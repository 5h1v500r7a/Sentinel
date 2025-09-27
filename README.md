# Sentinel Sandbox

A policy-driven Linux syscall firewall, written in C, Rust, C++, and Python.

The idea is simple: you write a small config file listing exactly which
system calls a program is allowed to make. Run the program through
Sentinel, and if it ever tries anything not on that list, the kernel
stops it cold, Sentinel logs exactly what it tried to do, and the
process gets killed. That's basically the same trick Docker, Chrome,
and systemd use under the hood to sandbox processes (seccomp-bpf), plus
a bit of ptrace to get useful logs out of it.

This is the first of three portfolio projects I'm putting together:

1. **Sentinel Sandbox (this one)** — systems security / OS internals
2. A red-teaming project — next up
3. A blue-teaming project — after that

## Table of contents

- [Why I built this](#why-i-built-this)
- [What it does](#what-it-does)
- [Quick demo](#quick-demo)
- [Background, if you're new to this stuff](#background-if-youre-new-to-this-stuff)
- [Why four languages](#why-four-languages)
- [Repo layout](#repo-layout)
- [Prerequisites](#prerequisites)
- [Building it](#building-it)
- [Using the CLI](#using-the-cli)
- [Writing a policy](#writing-a-policy)
- [How the enforcement works](#how-the-enforcement-works)
- [A limitation I'm not going to hide](#a-limitation-im-not-going-to-hide)
- [What I actually tested](#what-i-actually-tested)
- [Where I'd take this next](#where-id-take-this-next)
- [Talking about this in an interview](#talking-about-this-in-an-interview)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Why I built this

Most "cybersecurity portfolio project" tutorials you'll find online are
a thin wrapper around a library that does all the actual work: import
`some_firewall_lib`, call `.block()`, ship it. Fine for learning the API,
but it doesn't really teach you anything about the underlying system,
and it's not that convincing to show a recruiter either, since there's
nothing under the hood.

I wanted to go the other way and talk to the kernel almost directly, so
this project uses `seccomp-bpf` and `ptrace` with basically no library
sitting between me and the syscalls. If you read through this repo you
should come away actually understanding how a container runtime like
`runc` restricts what a process inside a container can do, which felt
like a more useful thing to be able to explain in an interview than
"I used library X."

## What it does

1. You write a policy file (TOML) listing the exact syscalls a program
   is allowed to make. Everything else is denied by default.
2. You run `sentinel run --policy your-policy.toml -- /path/to/program`.
3. The program runs inside a kernel-enforced sandbox. Try a syscall
   that isn't allowed, and the kernel refuses to even run it. Sentinel
   catches the attempt, logs which syscall it was as JSON, and kills
   the process.
4. `sentinel report` turns that log into a readable, severity-scored
   summary.

## Quick demo

```bash
./build.sh
cd python
python3 -m sentinel_cli.cli demo
```

That builds everything and runs three scripted scenarios so you can
watch it work without setting anything up yourself:

| # | Scenario | Policy | What happens |
|---|----------|--------|------------------|
| 1 | Script tries to `ptrace()` (classic debugger/injection move) | `untrusted-script.toml` | Blocked |
| 2 | Script tries to open a network socket | `untrusted-script.toml` | Blocked |
| 3 | CLI tool spawns a shell | `cli-tool.toml` | Not blocked, and I explain exactly why below instead of pretending it doesn't happen |

Here's a real run from this repo (yours will have different PIDs/timestamps):

```
$ sentinel run --policy untrusted-script.toml -- evil_ptrace
[sentinel-launcher] policy="untrusted-script" default_action=log-and-kill allowed_syscalls=24 target=["evil_ptrace"]
[sentinel] BLOCKED syscall "ptrace" (nr=101) from pid 367
[sentinel-launcher] target was killed by signal 9

>>> Result: BLOCKED. Violation log:
{"ts":1790534390,"pid":367,"syscall_nr":101,"syscall_name":"ptrace","action":"blocked","policy":"untrusted-script"}
```

## Background, if you're new to this stuff

Skip this if you already know what a syscall is.

A running program can't touch hardware, other processes, the
filesystem, or the network directly. The CPU just doesn't allow
ordinary user-mode code to do that. Instead, a program asks the kernel
to do it on its behalf, through a fixed set of entry points called
system calls. `read`, `open`, `connect`, `fork`, `execve`, pretty much
everything a program does that has any effect outside its own memory
goes through one of a few hundred of these. Which means if you can
control which syscalls a program is allowed to make, you control
basically everything it's capable of doing, even if someone finds a
buffer overflow or a malicious dependency gets code execution inside
it. A process that literally cannot call `connect()` can't open a
reverse shell, full stop, no matter how good the exploit is.

**seccomp** is the Linux kernel feature that lets a process install
this kind of filter on itself: "from here on, only allow these
syscalls, and do X to anything else." Once it's loaded it can only get
stricter, never looser, for the rest of that process's life, which is
the whole point. Even a fully compromised process can't turn its own
sandbox back off.

**ptrace** is the mechanism debuggers use to pause a process and poke
at its memory and registers. I'm using it here for something much
narrower: getting notified the instant a sandboxed process tries a
blocked syscall, so I can log exactly what it tried before killing it.
There's a whole section below on why this ended up being necessary
instead of just slapping a signal handler on it (spoiler: I tried the
signal handler first, and it broke in a pretty instructive way).

## Why four languages

Not just resume-padding, I promise. Each layer is doing the job it's
actually suited for:

```
Python (python/sentinel_cli/)
  the friendly front door -- CLI, running the demo suite, calling the
  other two binaries and printing results. No sandboxing logic lives
  here on purpose.
        |                                    |
        v subprocess                         v subprocess
Rust (rust/)                          C++ (cpp/)
  sentinel-launcher: parses the         sentinel-log-analyzer: parses
  TOML policy, builds the C-shaped      violations.jsonl, aggregates +
  arguments, calls the engine via FFI   severity-scores it, renders Markdown
        |
        v extern "C"
C (c/seccomp_filter.c)
  the actual enforcement engine -- forks the target, applies rlimits,
  loads the seccomp-bpf filter, runs the ptrace supervisor loop.
  This is the only part of the project directly touching the kernel.
```

C is the enforcement core because seccomp and ptrace are C APIs at
heart, and this is exactly the spot where I want a small, reviewable
footprint instead of a framework in the way. Rust handles policy
parsing and orchestration, since parsing config files and gluing
pieces together is exactly where memory bugs tend to creep into C, and
Rust removes that risk while still giving me a clean unsafe/FFI
boundary for the one spot that actually needs raw C interop. C++ does
the log analysis because it's a natural fit for `std::map` +
`std::sort` + a comparator, nothing fancier needed there. And Python
ties it all together because nobody should have to remember four
different binaries' argument order just to use the thing.

## Repo layout

```
sentinel-sandbox/
├── README.md
├── build.sh                    builds everything, in the right order
├── c/
│   ├── seccomp_filter.h          API + the "why" behind the design
│   ├── seccomp_filter.c          fork + rlimits + seccomp + ptrace
│   └── Makefile
├── rust/
│   ├── Cargo.toml
│   ├── build.rs                  tells cargo where the C lib lives
│   └── src/
│       ├── main.rs               CLI parsing, entrypoint
│       ├── policy.rs             TOML -> Policy struct
│       ├── launcher.rs           safe wrapper around the FFI call
│       └── ffi.rs                extern "C" declarations
├── cpp/
│   ├── log_analyzer.hpp
│   ├── log_analyzer.cpp          JSONL parsing, aggregation, Markdown
│   └── Makefile
├── python/
│   ├── setup.py
│   ├── requirements.txt          empty on purpose, stdlib only
│   └── sentinel_cli/
│       ├── cli.py                the `sentinel` entrypoint
│       ├── runner.py             invokes sentinel-launcher
│       ├── report.py             invokes sentinel-log-analyzer
│       ├── demo.py               the scripted attack-suite demo
│       └── paths.py              finds binaries regardless of CWD
├── policies/
│   ├── untrusted-script.toml     strictest -- CPU/file-only workloads
│   ├── web-server.toml           moderate -- network server workloads
│   └── cli-tool.toml             most permissive -- trusted CLI tools
├── tests/
│   ├── good_server.c              a legit tiny server, the positive control
│   └── attack_syscalls/           demo "attack" binaries
│       ├── evil_ptrace.c
│       ├── evil_shell.c
│       └── evil_socket.c
├── logs/                          violations.jsonl lands here
└── docs/
    └── blog-post.md               a write-up of the whole build, bugs included
```

## Prerequisites

Built and tested on Ubuntu 24.04. Same package names on Debian.

```bash
sudo apt-get update
sudo apt-get install -y build-essential libseccomp-dev

# Rust -- either works
sudo apt-get install -y cargo rustc
# or, for a newer toolchain:
# curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Python 3.8+, which you probably already have. No `pip install` needed
to just run the CLI, it's stdlib only.

One honest caveat on portability: the C code reads raw CPU registers
(`orig_rax` on x86_64) to figure out which syscall got blocked, and the
seccomp syscall resolution is architecture-specific too. I built and
tested this on x86_64 Linux. Porting to ARM64 needs a one-line change
(different register name, noted in the code), and it won't run on
anything that isn't Linux since seccomp and ptrace are both Linux-only.
That's normal for this kind of tool, worth just saying up front instead
of getting caught out by it later.

## Building it

```bash
./build.sh
```

Builds the C library first, then Rust (which links against it), then
the C++ analyzer, then the demo binaries. Each piece also builds on its
own with its own Makefile / `cargo build`, if you only want to touch
one layer.

## Using the CLI

```bash
cd python

# see what's bundled and what each policy is for
python3 -m sentinel_cli.cli policies

# run any program under a policy
python3 -m sentinel_cli.cli run --policy web-server.toml -- ./my-server --port 8080

# run the full demo (do this first)
python3 -m sentinel_cli.cli demo

# turn a log into a readable report
python3 -m sentinel_cli.cli report ../logs/violations.jsonl
python3 -m sentinel_cli.cli report ../logs/violations.jsonl -o report.md
```

Or install it properly:

```bash
cd python && pip install -e . --break-system-packages
sentinel demo
```

## Writing a policy

```toml
name = "my-policy"

# what happens to anything NOT in allowed_syscalls:
#   "log-and-kill"  (recommended) block it, log exactly what it was, kill the process
#   "kill"          block it instantly, no log
#   "errno"         return an error instead of killing, useful while you're building the policy
default_action = "log-and-kill"

allowed_syscalls = [
  "read", "write", "openat", "close", "exit_group",
  # see policies/*.toml for real, working examples
]

[limits]
cpu_seconds = 5           # 0 = no limit
address_space_mb = 256
open_files = 16
```

How do you actually figure out which syscalls your program needs?
`strace` it first, unsandboxed:

```bash
strace -f -c ./my-program
```

`-c` prints a summary table. Start your allow-list from that, run it
through Sentinel with `default_action = "errno"` while you iterate (so
a missing syscall just errors instead of killing the process outright),
check `logs/violations.jsonl` for anything still getting denied, add
it, repeat. Once nothing shows up as denied during normal use, switch
to `log-and-kill` for real.

## How the enforcement works

This is the part worth being able to explain out loud. `sentinel_run_sandboxed()` in `c/seccomp_filter.c` does roughly this:

1. `fork()`, splitting into a parent (supervisor) and a child (soon to be sandboxed).
2. Child calls `setrlimit()` for whatever CPU/memory/fd caps the policy set.
3. Child calls `ptrace(PTRACE_TRACEME)`, "let my parent trace me." Has to happen before the filter loads, it's what makes step 6 work.
4. Child builds and loads the seccomp-bpf filter through libseccomp. Allow-list of syscalls, default action `SCMP_ACT_TRACE(0)` for everything else instead of an instant kill, so the parent gets a chance to step in.
5. Child `execve()`s the real target. Since it's traced, this exec generates an automatic `SIGTRAP` stop the parent will see.
6. Parent runs a `waitpid()` loop. After consuming that exec-stop it sets `PTRACE_O_TRACESECCOMP` and continues the child. From then on, any syscall outside the allow-list makes the kernel itself pause the child and hand a `PTRACE_EVENT_SECCOMP` stop to the parent, before the syscall is allowed to run.
7. On that stop, the parent reads the child's registers (`PTRACE_GETREGS`); on x86_64, `orig_rax` holds the syscall number about to run. It resolves the number to a name, writes it to the log, and kills the child.

**Why not just a signal handler in the sandboxed process instead of
all this ptrace stuff?** I actually built it that way first, and it's
worth knowing why it doesn't work, because it's a genuinely useful
gotcha to have run into.

My first version set the seccomp default action to `SCMP_ACT_TRAP`,
which raises `SIGSYS` inside the sandboxed process itself, and I put a
handler there to log the blocked syscall before exiting. Worked fine
for the launcher process. Except the launcher immediately calls
`execve()` to become the actual target program, and `execve()` resets
every custom signal handler back to default. So by the time the real
target was running, my handler was already gone, and a blocked syscall
just silently killed the process with a bare "Bad system call," no log
at all. I only noticed because a test run showed exit code 159 with an
empty violations file, which took a minute to track down. The ptrace
approach works because that relationship lives between two processes
instead of inside one process's signal table, so it survives
`execve()` fine. It's also basically why real container sandboxes use
ptrace, or the newer `SECCOMP_RET_USER_NOTIF`, instead of a plain
signal handler for this.

## A limitation I'm not going to hide

Worth reading before you demo this to anyone. It's the single most
important thing about how allow-list seccomp filters actually behave,
and being able to explain it clearly matters more in an interview than
pretending the tool has no edges.

The filter gets loaded in the child before it calls `execve()` to
launch your target, which means `execve` itself has to be on the
allow-list for the launch to work at all. But a plain, name-based
allow-list has no way to tell "the one execve that launches my target"
apart from "a later execve the target decides to make on its own." To
the kernel and to the filter, they're both just calls to the same
syscall with the same name.

You can see this yourself: `policies/cli-tool.toml` allows `execve`
because real CLI tools legitimately shell out to other programs, and
the bundled `evil_shell` demo exploits exactly that. Under that policy
it spawns `/bin/sh` and prints `pwned`, zero violations logged. That's
not something slipping through by accident, it's scenario 3 of
`sentinel demo`, included on purpose so you can see where the boundary
actually is.

The real fixes: argument-aware filtering (seccomp can filter on some
numeric arguments, though not on string contents like a file path),
installing the filter from inside the target's own first instructions
so no further execve is ever needed, or the newer
`SECCOMP_RET_USER_NOTIF` mechanism, where a supervisor process gets a
file descriptor it can use to inspect a notified syscall's actual
arguments before deciding to allow or deny it. That last one is a
natural next step if I keep building on this, see below.

## What I actually tested

I didn't want to just write claims in this README without checking
them, so here's what I actually ran against the compiled code:

| Test | Policy | Result |
|---|---|---|
| `/bin/ls` with a full syscall allow-list | ad hoc | ran clean, 0 violations |
| `/bin/ls` missing one syscall (`statx`) | ad hoc | blocked exactly on `statx` |
| `evil_ptrace` (calls `ptrace`) | `untrusted-script.toml` | blocked exactly on `ptrace` |
| `evil_socket` (calls `socket`) | `untrusted-script.toml` | blocked exactly on `socket` |
| `evil_shell` (execs `/bin/sh`) | `cli-tool.toml` | not blocked, on purpose, see above |
| `good_server` (real TCP server, real request via `curl`) | `web-server.toml` | served the request, 0 violations |
| C++ analyzer against a real log | -- | correctly parsed and scored the `ptrace` hit as HIGH |
| clean rebuild via `./build.sh` from scratch | -- | all four components built, no errors |

If you change anything, `python3 -m sentinel_cli.cli demo` re-runs the
three core scenarios and will tell you fast if you broke something.

## Where I'd take this next

Roughly easiest to hardest:

- More policy templates (a database process, a batch ML job, a Node
  server), tested the same way as the three here.
- Port the register-reading code to ARM64 (`regs.regs[8]` instead of
  `orig_rax`) with a runtime arch check.
- A "dry-run" mode that logs what would have been blocked without
  actually killing anything, so building a new policy from real
  traffic is less painful than reading raw strace output.
- The big one, and the actual fix for the limitation above: swap
  `SCMP_ACT_TRACE` + ptrace for `SECCOMP_RET_USER_NOTIF` +
  `SCMP_FILTER_FLAG_NEW_LISTENER`, so a supervisor can inspect a
  notified syscall's real argument values (like the path being passed
  to execve) before deciding anything, which means "allow execve, but
  only for stuff under /usr/bin/" becomes possible.
- Linux namespaces alongside seccomp (`unshare`/`clone` with
  `CLONE_NEWNET`/`CLONE_NEWPID`/etc.) for full container-style
  isolation instead of just syscall filtering.

## Talking about this in an interview

A few ways to describe this that I'd actually stand behind (make sure
you can answer a basic follow-up on anything you say here, interviewers
notice the difference between someone who built it and someone
reciting a summary):

- "I built a Linux process sandbox from the kernel primitives up, seccomp-bpf for the filter and ptrace for logging, with a Rust layer on top for policy parsing."
- "I hit a real bug where execve() resets signal handlers, which broke my first design. Fixed it by moving to a ptrace-based supervisor, which is what production sandboxes actually do for this exact reason."
- "I can point to a specific, real limitation in my own tool, a name-based allow-list can't tell a target's own launch-time execve apart from a later one, and describe what the actual fix looks like."

That last one especially. Being able to describe a weakness in your
own project, unprompted and accurately, reads a lot better to a
security-minded interviewer than insisting there isn't one.

## Troubleshooting

**`error while loading shared libraries: libsentinel_filter.so: cannot open shared object file`** -- the compiled C library isn't on the linker's search path. The Python CLI handles this for you automatically; if you're calling `sentinel-launcher` directly, export it yourself:
```bash
export LD_LIBRARY_PATH=$(pwd)/c/build:$LD_LIBRARY_PATH
```

**`unknown syscall name in policy: "..."`** -- typo, or a syscall that doesn't exist on this architecture/kernel. Check the spelling against `man 2 syscalls`.

**Everything dies immediately, even a totally normal program** -- almost always a missing syscall from C runtime startup or the dynamic linker (common culprits: `readlinkat`, `uname`, `access`, `faccessat2`). Switch to `default_action = "errno"` temporarily and check `logs/violations.jsonl` for what's actually being asked for. Statically-linked binaries need noticeably fewer startup syscalls, which is why the demo binaries in this repo are all built with `-static`.

**Rust build fails with `feature 'edition2024' is required`** -- some indirect dependency resolved to a version too new for an older cargo/rustc (this was built against the 1.75 that ships with Ubuntu 24.04's package manager). `rust/Cargo.toml` already pins `indexmap`/`hashbrown` for exactly this reason; if it happens again after adding a dependency, pin the offending one the same way, or just install a newer Rust via rustup.

## License

MIT. Use this however you want, including as a straight-up portfolio piece, you don't need to ask me.

```
MIT License

Copyright (c) 2026

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
```
