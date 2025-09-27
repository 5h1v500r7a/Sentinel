/*
 * seccomp_filter.h
 * ----------------
 * Public C API for Sentinel's syscall firewall core.
 *
 * Beginner note: "seccomp" (SECure COMPuting) is a Linux kernel feature
 * that lets a process say "from now on, only allow me to make THESE
 * syscalls, and do THIS to me if I try anything else". A syscall is the
 * only way a program can ask the kernel to do anything (open a file,
 * send a packet, spawn a process, etc.), so if you can control which
 * syscalls a program is allowed to make, you can dramatically shrink
 * what a compromised program is able to do, even with full code
 * execution inside it.
 *
 * IMPORTANT DESIGN NOTE (read this before you "improve" it):
 * An earlier version of this library tried to log blocked syscalls with
 * a SIGSYS signal handler installed in the sandboxed process itself
 * (via SCMP_ACT_TRAP). That does not work for real target programs:
 * execve() resets all custom signal handlers back to their default
 * disposition, so by the time the *actual* sandboxed program is running,
 * our handler is gone and the kernel just kills it with a bare,
 * unlogged SIGSYS ("Bad system call"). This is a well-known gotcha and
 * exactly the kind of thing worth understanding, not just avoiding.
 *
 * The fix used here is the same one real sandboxes use: a *separate,
 * still-alive supervisor process* watches the sandboxed child via
 * ptrace(2) and the SECCOMP_RET_TRACE action. Because ptrace is a
 * relationship between two processes (not a handler living inside the
 * traced process), it survives exec() cleanly. When the child attempts
 * a syscall outside the allow-list, the kernel stops it and notifies the
 * supervisor (this process) via PTRACE_EVENT_SECCOMP; we read which
 * syscall it was straight out of the child's CPU registers, log it, and
 * kill the child.
 */
#ifndef SENTINEL_SECCOMP_FILTER_H
#define SENTINEL_SECCOMP_FILTER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* What happens to a syscall that ISN'T in the allow-list. */
typedef enum {
    /* Kill the whole process instantly, no log. Cheapest, least visible. */
    SENTINEL_ACTION_KILL_PROCESS = 0,

    /* Recommended default: a supervisor process traces the sandbox,
     * logs the exact blocked syscall as JSON, then kills it. */
    SENTINEL_ACTION_LOG_AND_KILL = 1,

    /* Return -EPERM to the caller instead of killing it. Useful while
     * you are still building a policy, but noisier and lets a hostile
     * process keep running (it just sees failed syscalls). */
    SENTINEL_ACTION_ERRNO = 2
} sentinel_default_action_t;

/* Optional extra guard rails applied via setrlimit() before the seccomp
 * filter is loaded, independent of which syscalls are allowed. Zero
 * means "don't impose this particular limit". */
typedef struct {
    unsigned long cpu_seconds;      /* RLIMIT_CPU */
    unsigned long address_space_mb; /* RLIMIT_AS, in megabytes */
    unsigned long open_files;       /* RLIMIT_NOFILE */
} sentinel_limits_t;

/*
 * Fork, sandbox, and run `argv[0]` (a NULL-terminated argv array, same
 * shape as execve() expects) under the given policy. This call BLOCKS
 * until the sandboxed program exits (or is killed), the same way
 * system() would, and returns the child's exit status the way
 * waitpid()'s `status` out-parameter does -- use the standard
 * WIFEXITED()/WEXITSTATUS()/WIFSIGNALED()/WTERMSIG() macros from
 * <sys/wait.h> on the returned value.
 *
 * `allowed_syscalls`: NUL-terminated syscall names (as in `man 2
 * syscalls` / strace output), everything else gets `default_action`.
 * `log_path`: where JSON-lines violation records are appended. Ignored
 *             if `default_action != SENTINEL_ACTION_LOG_AND_KILL`.
 * `policy_label`: free-text tag copied into every violation record so
 *             logs from several policies can be told apart. May be NULL.
 * `limits`: may be NULL for "no extra limits".
 *
 * Returns:
 *   >= 0   a waitpid-style status describing how the sandboxed program
 *          ended (see above).
 *   -1     setup failed before the child ever ran (bad policy, fork
 *          failed, etc.) -- check stderr for a human-readable reason.
 */
int sentinel_run_sandboxed(const char *const *allowed_syscalls,
                            size_t count,
                            sentinel_default_action_t default_action,
                            const char *log_path,
                            const char *policy_label,
                            const sentinel_limits_t *limits,
                            char *const *argv);

#ifdef __cplusplus
}
#endif

#endif /* SENTINEL_SECCOMP_FILTER_H */
