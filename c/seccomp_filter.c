/*
 * seccomp_filter.c
 * ----------------
 * See seccomp_filter.h for the full design rationale (read it first,
 * especially the note on why we use ptrace instead of a signal handler).
 *
 * sentinel_run_sandboxed() has three phases:
 *   1. fork()
 *   2. CHILD: apply rlimits, optionally PTRACE_TRACEME, build+load the
 *      seccomp-bpf filter, execve() the real target.
 *   3. PARENT: if we're in log-and-kill mode, run a ptrace supervisor
 *      loop that watches for PTRACE_EVENT_SECCOMP stops, logs the
 *      blocked syscall, and kills the child. Otherwise just wait for
 *      the child to finish on its own (the kernel enforces the policy
 *      with no supervisor needed for KILL_PROCESS/ERRNO modes).
 */
#define _GNU_SOURCE
#include "seccomp_filter.h"

#include <seccomp.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/resource.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

/* ---- tiny helpers for building the JSON log line without malloc ---- */

static int u2a(unsigned long v, char *buf) {
    char tmp[24];
    int i = 0, n = 0;
    if (v == 0) { buf[0] = '0'; return 1; }
    while (v > 0 && i < (int)sizeof(tmp)) { tmp[i++] = (char)('0' + (v % 10)); v /= 10; }
    while (i > 0) buf[n++] = tmp[--i];
    return n;
}
static void append(char *buf, size_t *pos, const char *src) {
    while (*src) buf[(*pos)++] = *src++;
}
static void append_u(char *buf, size_t *pos, unsigned long v) {
    char tmp[24];
    int n = u2a(v, tmp);
    for (int i = 0; i < n; i++) buf[(*pos)++] = tmp[i];
}
static void append_json_escaped(char *buf, size_t *pos, const char *src) {
    if (!src) return;
    while (*src) {
        char c = *src++;
        if (c == '"' || c == '\\') { buf[(*pos)++] = '\\'; buf[(*pos)++] = c; }
        else if ((unsigned char)c < 0x20) { /* skip control chars */ }
        else buf[(*pos)++] = c;
    }
}

/* Appends one JSON-lines violation record to the (already-open) fd. */
static void log_violation(int log_fd, pid_t pid, int syscall_nr,
                           const char *policy_label) {
    const char *name = seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, syscall_nr);
    if (!name) name = "unknown";

    char buf[512];
    size_t pos = 0;
    append(buf, &pos, "{\"ts\":");
    append_u(buf, &pos, (unsigned long)time(NULL));
    append(buf, &pos, ",\"pid\":");
    append_u(buf, &pos, (unsigned long)pid);
    append(buf, &pos, ",\"syscall_nr\":");
    append_u(buf, &pos, (unsigned long)syscall_nr);
    append(buf, &pos, ",\"syscall_name\":\"");
    append_json_escaped(buf, &pos, name);
    append(buf, &pos, "\",\"action\":\"blocked\"");
    if (policy_label && policy_label[0]) {
        append(buf, &pos, ",\"policy\":\"");
        append_json_escaped(buf, &pos, policy_label);
        append(buf, &pos, "\"");
    }
    append(buf, &pos, "}\n");

    if (log_fd >= 0) {
        ssize_t written = write(log_fd, buf, pos);
        (void)written;
    }
    /* Also mirror to stderr so `sentinel run` is useful interactively
     * even before anyone looks at the log file. */
    fprintf(stderr, "[sentinel] BLOCKED syscall \"%s\" (nr=%d) from pid %d\n",
            name, syscall_nr, (int)pid);
}

static void apply_rlimits(const sentinel_limits_t *limits) {
    if (!limits) return;
    struct rlimit rl;
    if (limits->cpu_seconds > 0) {
        rl.rlim_cur = rl.rlim_max = limits->cpu_seconds;
        setrlimit(RLIMIT_CPU, &rl);
    }
    if (limits->address_space_mb > 0) {
        rl.rlim_cur = rl.rlim_max = limits->address_space_mb * 1024 * 1024;
        setrlimit(RLIMIT_AS, &rl);
    }
    if (limits->open_files > 0) {
        rl.rlim_cur = rl.rlim_max = limits->open_files;
        setrlimit(RLIMIT_NOFILE, &rl);
    }
}

/* Builds and loads the seccomp-bpf filter in the CURRENT (about to be
 * sandboxed) process. Must be called after any needed ptrace(PTRACE_TRACEME)
 * and before execve(). Returns 0 on success. */
static int load_filter(const char *const *allowed_syscalls, size_t count,
                        sentinel_default_action_t default_action) {
    uint32_t def_act;
    switch (default_action) {
        case SENTINEL_ACTION_KILL_PROCESS: def_act = SCMP_ACT_KILL_PROCESS; break;
        case SENTINEL_ACTION_LOG_AND_KILL: def_act = SCMP_ACT_TRACE(0);     break;
        case SENTINEL_ACTION_ERRNO:        def_act = SCMP_ACT_ERRNO(EPERM); break;
        default:
            fprintf(stderr, "[sentinel] unknown default_action %d\n", (int)default_action);
            return -1;
    }

    scmp_filter_ctx ctx = seccomp_init(def_act);
    if (!ctx) {
        fprintf(stderr, "[sentinel] seccomp_init failed\n");
        return -1;
    }

    for (size_t i = 0; i < count; i++) {
        int nr = seccomp_syscall_resolve_name(allowed_syscalls[i]);
        if (nr == __NR_SCMP_ERROR) {
            fprintf(stderr, "[sentinel] unknown syscall name in policy: \"%s\" "
                            "(typo? or not available on this architecture)\n",
                    allowed_syscalls[i]);
            seccomp_release(ctx);
            return -1;
        }
        int rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nr, 0);
        if (rc != 0) {
            fprintf(stderr, "[sentinel] failed to add rule for \"%s\": %s\n",
                    allowed_syscalls[i], strerror(-rc));
            seccomp_release(ctx);
            return -1;
        }
    }

    int rc = seccomp_load(ctx);
    seccomp_release(ctx);
    if (rc != 0) {
        fprintf(stderr, "[sentinel] seccomp_load failed: %s\n", strerror(-rc));
        return -1;
    }
    return 0;
}

/* The ptrace supervisor loop the PARENT runs when default_action is
 * SENTINEL_ACTION_LOG_AND_KILL. `child` has already called
 * PTRACE_TRACEME + loaded a filter whose default action is
 * SCMP_ACT_TRACE(0), and is about to (or already did) execve(). */
static int supervise(pid_t child, int log_fd, const char *policy_label) {
    int status;

    /* First stop: the automatic SIGTRAP a traced process receives right
     * after a successful execve(). We must consume this before we can
     * usefully set ptrace options. */
    if (waitpid(child, &status, 0) < 0) {
        fprintf(stderr, "[sentinel] waitpid (initial stop) failed: %s\n", strerror(errno));
        return -1;
    }
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        /* Target failed to even exec (e.g. binary not found); nothing
         * to supervise, just propagate. */
        return status;
    }

    if (ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESECCOMP) != 0) {
        fprintf(stderr, "[sentinel] PTRACE_SETOPTIONS failed: %s\n", strerror(errno));
        kill(child, SIGKILL);
        waitpid(child, &status, 0);
        return -1;
    }

    if (ptrace(PTRACE_CONT, child, 0, 0) != 0) {
        fprintf(stderr, "[sentinel] initial PTRACE_CONT failed: %s\n", strerror(errno));
        kill(child, SIGKILL);
        waitpid(child, &status, 0);
        return -1;
    }

    for (;;) {
        pid_t w = waitpid(child, &status, 0);
        if (w < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "[sentinel] waitpid failed: %s\n", strerror(errno));
            return -1;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            return status; /* target ended on its own (normal exit, or a
                               signal unrelated to us, e.g. it segfaulted) */
        }

        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);
            int event = status >> 16;

            if (sig == SIGTRAP && event == PTRACE_EVENT_SECCOMP) {
                struct user_regs_struct regs;
                if (ptrace(PTRACE_GETREGS, child, 0, &regs) == 0) {
                    /* x86_64 ABI: orig_rax holds the syscall number for
                     * the syscall currently being entered. (On other
                     * architectures the register name differs -- see
                     * README's "porting" note.) */
                    long syscall_nr = (long)regs.orig_rax;
                    log_violation(log_fd, child, (int)syscall_nr, policy_label);
                } else {
                    fprintf(stderr, "[sentinel] PTRACE_GETREGS failed: %s\n", strerror(errno));
                }
                kill(child, SIGKILL);
                waitpid(child, &status, 0);
                return status;
            }

            /* Some other stop. Most commonly this is ptrace's own
             * housekeeping trap (e.g. the SIGTRAP a traced process gets
             * on every execve(), or PTRACE_O_TRACECLONE-style events)
             * rather than a signal actually meant for the tracee -- if
             * we blindly forwarded that SIGTRAP, the child would receive
             * it as a real, uncaught signal and die from it, which is
             * not what we want (this bit us during testing: /bin/sh was
             * dying with "Trace/breakpoint trap" even though nothing
             * was actually blocked). Only forward a stop signal that
             * ISN'T seccomp's own SIGTRAP bookkeeping. */
            int forward_sig = (sig == SIGTRAP) ? 0 : sig;
            if (ptrace(PTRACE_CONT, child, 0, forward_sig) != 0) {
                if (errno == ESRCH) return status;
                fprintf(stderr, "[sentinel] PTRACE_CONT failed: %s\n", strerror(errno));
                return -1;
            }
        }
    }
}

int sentinel_run_sandboxed(const char *const *allowed_syscalls,
                            size_t count,
                            sentinel_default_action_t default_action,
                            const char *log_path,
                            const char *policy_label,
                            const sentinel_limits_t *limits,
                            char *const *argv) {
    if (!argv || !argv[0]) {
        fprintf(stderr, "[sentinel] empty argv\n");
        return -1;
    }

    int log_fd = -1;
    if (default_action == SENTINEL_ACTION_LOG_AND_KILL && log_path) {
        log_fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0640);
        if (log_fd < 0) {
            fprintf(stderr, "[sentinel] could not open log file \"%s\": %s\n",
                    log_path, strerror(errno));
            return -1;
        }
    }

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "[sentinel] fork failed: %s\n", strerror(errno));
        if (log_fd >= 0) close(log_fd);
        return -1;
    }

    if (pid == 0) {
        /* ---- child: about to become the sandboxed program ---- */
        apply_rlimits(limits);

        if (default_action == SENTINEL_ACTION_LOG_AND_KILL) {
            if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) {
                fprintf(stderr, "[sentinel] PTRACE_TRACEME failed: %s\n", strerror(errno));
                _exit(126);
            }
        }

        if (load_filter(allowed_syscalls, count, default_action) != 0) {
            _exit(126);
        }

        execvp(argv[0], argv);
        /* execvp only returns on failure */
        fprintf(stderr, "[sentinel] execvp(\"%s\") failed: %s\n", argv[0], strerror(errno));
        _exit(127);
    }

    /* ---- parent ---- */
    int status;
    if (default_action == SENTINEL_ACTION_LOG_AND_KILL) {
        status = supervise(pid, log_fd, policy_label);
    } else {
        if (waitpid(pid, &status, 0) < 0) {
            fprintf(stderr, "[sentinel] waitpid failed: %s\n", strerror(errno));
            status = -1;
        }
    }

    if (log_fd >= 0) close(log_fd);
    return status;
}
