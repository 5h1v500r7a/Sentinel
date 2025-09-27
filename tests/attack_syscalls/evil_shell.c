/*
 * evil_shell.c
 * ------------
 * Part of Sentinel's demo attack suite. Simulates what a successful
 * command-injection / RCE exploit typically does next: spawn a shell.
 * We use execve() directly (not system()) so the attempted syscall is
 * unambiguous. No shell is actually run if the sandbox is doing its job.
 */
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

int main(void) {
    printf("[evil_shell] attempting execve(\"/bin/sh\", ...)\n");
    char *argv[] = {"/bin/sh", "-c", "echo pwned", NULL};
    char *envp[] = {NULL};
    execve("/bin/sh", argv, envp);
    /* execve only returns on failure */
    printf("[evil_shell] execve() failed with errno=%d (%s) -- "
           "if you see this, the sandbox used the 'errno' action, "
           "not 'log-and-kill'\n", errno, strerror(errno));
    return 1;
}
