/*
 * evil_socket.c
 * -------------
 * Part of Sentinel's demo attack suite. Simulates data exfiltration /
 * command-and-control callback behaviour: opening a network socket. A
 * batch data-processing script or CLI tool that should have no reason
 * to talk to the network is exactly the kind of workload where denying
 * `socket`/`connect` outright closes off an entire attack category
 * (reverse shells, exfil, C2 beaconing) even if the program is fully
 * compromised.
 */
#include <sys/socket.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

int main(void) {
    printf("[evil_socket] attempting socket(AF_INET, SOCK_STREAM, 0)\n");
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("[evil_socket] socket() failed with errno=%d (%s) -- "
               "if you see this, the sandbox used the 'errno' action, "
               "not 'log-and-kill'\n", errno, strerror(errno));
        return 1;
    }
    printf("[evil_socket] socket() succeeded (fd=%d) -- sandbox did NOT block this!\n", fd);
    return 0;
}
