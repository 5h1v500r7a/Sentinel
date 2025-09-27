# Building a syscall firewall from scratch (and the bug that ate my afternoon)

I wanted a systems security project for my portfolio that wasn't just
"here's a script that calls a library." Something where I actually had
to go read kernel documentation and get my hands dirty. This is the
write-up of what I ended up building: Sentinel Sandbox, a Linux process
sandbox that enforces a syscall allow-list using seccomp-bpf, with a
Rust layer on top and a C++ tool for making sense of the logs
afterward.

If you just want the code, it's in the repo alongside this post. This
is more about the process, the decisions, and the one bug that took me
way longer to figure out than I'd like to admit.

## Starting point: what's actually possible here

The core idea behind seccomp is one of those things that sounds almost
too simple once you get it. Every single thing a Linux program does
that touches the outside world (reading a file, opening a socket,
forking a child process) goes through a syscall. There's no other way
in. So if you can restrict which syscalls a process is allowed to
make, you've restricted everything that process can possibly do,
regardless of what code is actually running inside it. Doesn't matter
if there's a buffer overflow, doesn't matter if a dependency turns out
to be malicious. If the process physically can't call `connect()`,
it can't open a reverse shell. Full stop.

That's the property I wanted to demonstrate, not just talk about.

## Picking the stack

I decided on C for the actual enforcement code, Rust for the layer that
parses config and orchestrates things, C++ for a log analysis tool, and
Python to glue the whole thing into one CLI. That's partly because I
wanted a project that used all four languages credibly, but honestly
each one really does fit the job I gave it:

- C is where seccomp and ptrace actually live as APIs, and I wanted the
  part that's directly talking to the kernel to be small and easy to
  read line by line, not buried under abstraction.
- Rust took over anything involving parsing untrusted input (the TOML
  policy file) and building up argument arrays to hand to the C side.
  This is exactly the kind of code where a stray off-by-one in C turns
  into a security bug, and Rust just makes that category of mistake
  much harder to make by accident.
- C++ does the log analysis, aggregating a JSON-lines file of blocked
  syscalls and scoring them by severity. Nothing exotic, just
  `std::map` and a sort with a custom comparator, but it's a fine fit.
- Python ties the three binaries together into one `sentinel` command,
  because I didn't want to make anyone (including future me) remember
  four different tools' argument order.

## First attempt at the enforcement engine

The first version was, in hindsight, the "obvious" design: fork a
child, load a seccomp filter where anything not on the allow-list
raises `SIGSYS`, install a signal handler in that same process to catch
`SIGSYS` and log which syscall triggered it, then exec the real target
program.

I got the C compiling, wired up the Rust side, and ran my first test:
launching `/bin/ls` under a deliberately too-strict policy, expecting
to see a nice JSON line describing exactly which syscall got blocked.

Instead I got this:

```
[sentinel-launcher] policy="test-ls" default_action=log-and-kill ...
Bad system call
EXIT CODE: 159
```

No JSON. Empty log file. Just "Bad system call," which is the shell's
generic message for a process that died to an unhandled SIGSYS.

## Chasing the bug

My first assumption was that I'd messed up the signal handler itself,
maybe the async-signal-safety rules (you can't call `malloc` or
`printf` from inside a signal handler, only a small safe subset of
functions), or maybe I'd registered it for the wrong signal, or gotten
the `sigaction` flags wrong.

I stared at the handler for a while. It looked right. `SA_SIGINFO` was
set, I was pulling `si_syscall` out of `siginfo_t`, writing straight to
a file descriptor with `write()` instead of anything that allocates.
All the things you're supposed to get right for a signal handler, I'd
gotten right.

Then it clicked, and I felt a bit silly: the handler was installed in
my *launcher* process, but the launcher immediately calls `execve()` to
become `/bin/ls`. And `execve()` resets every custom signal handler
back to `SIG_DFL`. That's just how the syscall works, POSIX-mandated
behavior, nothing broken about it. My handler was gone the moment the
real target program started running. By the time `/bin/ls` tried a
blocked syscall, there was no handler left to catch it, just the
kernel's default response to SIGSYS, which is to kill the process with
no logging at all.

In hindsight this is exactly the kind of thing that's obvious once you
know it and invisible until you've been bitten by it. It's also, I
found out afterward, precisely why real sandboxing tools don't rely on
in-process signal handlers for this. They use ptrace, or on newer
kernels, `SECCOMP_RET_USER_NOTIF`, both of which involve a *separate*
process watching the sandboxed one, rather than a handler living inside
it.

## Version two: ptrace

The fix ended up being a bigger rewrite than I expected. Instead of
`SCMP_ACT_TRAP` (raise SIGSYS in-process), the filter's default action
became `SCMP_ACT_TRACE(0)`, and the parent process attaches as a
tracer before the child execs anything.

The flow now looks like this: child calls `ptrace(PTRACE_TRACEME)`
before loading the filter, then execs the target. Because it's traced,
that exec generates an automatic stop the parent picks up in a
`waitpid()` loop. From there the parent sets `PTRACE_O_TRACESECCOMP`
and continues the child. Any syscall outside the allow-list now causes
the kernel to pause the child and hand the parent a
`PTRACE_EVENT_SECCOMP` stop, before the syscall is allowed to run at
all. The parent reads the child's registers with `PTRACE_GETREGS`, on
x86_64 the syscall number sits in `orig_rax`, resolves that to a name,
writes a JSON line, and kills the child.

This worked. But it introduced a second bug almost immediately, which
was almost funny given the first one.

## Bug number two: forwarding a trap that wasn't meant for anyone

Once I had the ptrace loop working for the ptrace and socket demos, I
tried the "spawn a shell" scenario, and the child died with signal 5,
SIGTRAP, instead of running cleanly or getting caught by my seccomp
logic.

The loop's logic for "any stop that isn't a seccomp event" was to just
forward whatever signal caused the stop back to the child with
`PTRACE_CONT(child, sig)`. That's the normal thing to do for a real
signal, if the child gets sent a SIGINT while traced, you want to
actually deliver it once you're done inspecting things. But it turns
out ptrace also reports its own bookkeeping stops (like the automatic
stop on a successful execve) as SIGTRAP, and those aren't a real signal
meant for the traced program at all. I was forwarding that fake SIGTRAP
straight into `/bin/sh`, which has no handler for it, so it just died.

The fix was one line: if the stop signal is SIGTRAP and it's not a
seccomp event, continue with signal 0 instead of forwarding it. Only
forward anything that isn't SIGTRAP. Small fix, but I wouldn't have
known to look for it without actually hitting it.

## The limitation I decided not to paper over

Once both of those were fixed, I ran into something that isn't really
a bug, more an inherent property of the design, and I went back and
forth on whether to just quietly work around it or write it up
honestly.

The seccomp filter has to allow `execve` for the child to launch the
actual target program at all, since the filter loads before that exec
happens. But a plain syscall-name allow-list has no way to tell "the
one execve that launches my target" apart from "a later execve the
target decides to make on its own." They're the same syscall, same
name, no way to distinguish them without inspecting the actual argument
(the path being exec'd), which plain seccomp rules can't do for string
arguments.

Practically, this means a policy that allows `execve` (because the
target legitimately needs to shell out to something) can't stop that
same target from spawning an unrelated shell later. I built a small
demo binary that does exactly this under the most permissive bundled
policy, and sure enough: it spawns `/bin/sh`, prints `pwned`, and the
violation log is completely empty. Nothing caught it, because nothing
*could* catch it with this design.

I decided to keep that demo in the project instead of hiding it,
because I think being upfront about what a security tool can't do is
more useful, and more credible, than only showing the wins. The real
fix is a newer kernel mechanism, `SECCOMP_RET_USER_NOTIF`, where a
supervisor gets a file descriptor and can inspect the actual arguments
of a notified syscall before deciding what to do. That's on my list for
a follow-up version.

## Where it landed

What I ended up with: a C library doing the actual fork/seccomp/ptrace
work, a Rust binary that turns a human-editable TOML policy into the
arguments that library needs, a C++ tool that turns the resulting
JSON-lines violation log into a readable, severity-scored report, and
a Python CLI that ties all three together into one `sentinel` command.

Three bundled policies (a strict one for untrusted scripts, a moderate
one for network services, a permissive one for general CLI tools), a
handful of demo "attack" binaries that exercise ptrace, socket, and
shell-spawning behavior, and a "positive control" (a real tiny TCP
server, tested against a real `curl` request) to prove the strict
policies aren't just restrictive for the sake of it, they still let a
legitimate workload through cleanly.

If you want the technical deep-dive with all the actual commands and
output, that's the README in the repo. This was more the "here's what
actually happened while building it" version, bugs included.
