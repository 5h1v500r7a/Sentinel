/*
 * evil_ptrace.c
 * -------------
 * Part of Sentinel's demo attack suite (`sentinel demo`). NOT malware:
 * it does nothing except call a single syscall that a compromised
 * process might use for anti-debugging evasion or process injection,
 * so you can watch the sandbox actually catch it. Safe to read, build,
 * and run -- it has no payload beyond the one syscall it demonstrates.
 *
 * Real-world relevance: ptrace() is how debuggers attach to processes,
 * but it's also how malware injects code into another running process
 * or detects that it's being analysed in a sandbox/debugger. A policy
 * that denies ptrace() to a program with no legitimate debugging need
 * (a web server, say) closes off that technique entirely.
 */
#include <sys/ptrace.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

int main(void) {
    printf("[evil_ptrace] attempting ptrace(PTRACE_TRACEME, ...)\n");
    long rc = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    if (rc == -1) {
        printf("[evil_ptrace] ptrace() failed with errno=%d (%s) -- "
               "if you see this, the sandbox used the 'errno' action, "
               "not 'log-and-kill'\n", errno, strerror(errno));
        return 1;
    }
    printf("[evil_ptrace] ptrace() succeeded -- sandbox did NOT block this!\n");
    return 0;
}
