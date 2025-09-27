/*
 * good_server.c
 * -------------
 * NOT an attack demo -- this is the "positive control" for the
 * web-server.toml policy: a tiny, legitimate TCP server that does
 * exactly what a real (minimal) web server does -- socket, bind,
 * listen, accept, read, write, close -- and nothing else. Running this
 * under policies/web-server.toml with ZERO entries in
 * logs/violations.jsonl afterward is the proof that the policy is
 * usably permissive for its intended workload, not just restrictive.
 *
 * Usage: good_server <port>
 * Serves exactly one connection with a fixed HTTP response, then exits.
 * That's enough to exercise the full socket lifecycle without needing
 * an actual HTTP parser for a demo.
 */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

int main(int argc, char **argv) {
    int port = argc > 1 ? atoi(argv[1]) : 8765;

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }

    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((unsigned short)port);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind"); return 1;
    }
    if (listen(srv, 1) != 0) { perror("listen"); return 1; }

    fprintf(stderr, "[good_server] listening on 127.0.0.1:%d\n", port);

    int client = accept4(srv, NULL, NULL, 0);
    if (client < 0) { perror("accept4"); return 1; }

    char buf[512];
    ssize_t n = read(client, buf, sizeof(buf) - 1);
    if (n > 0) buf[n] = '\0';

    const char *resp =
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
    ssize_t written = write(client, resp, strlen(resp));
    (void)written;

    close(client);
    close(srv);
    fprintf(stderr, "[good_server] served one request, exiting cleanly\n");
    return 0;
}
