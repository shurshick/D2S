/* Local-only /resolve frontend for the existing d2o DNS engine.
 * The original DNS parser, allowlist, cache and query validation are reused.
 * Registration and relay credentials are not exposed by this frontend. */
#define main d2k_enrollment_unused_main
#include "upstream-main.c"
#undef main

#define LOCAL_CHILDREN 2

static void local_reply(int fd, int code, const char *body, size_t length) {
    char header[256];
    const char *reason = code == 200 ? "OK" : code == 400 ? "Bad Request" :
        code == 404 ? "Not Found" : code == 431 ? "Request Header Fields Too Large" :
        code == 503 ? "Service Unavailable" : "Internal Server Error";
    int n = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
        code, reason, length);
    if (n > 0 && (size_t)n < sizeof(header) &&
        socket_write_all(fd, header, (size_t)n) == 0 && length)
        (void)socket_write_all(fd, body, length);
}

static void local_client(int fd) {
    char headers[HEADER_LIMIT + 1], body[RESOLVE_BODY_LIMIT], reply_body[RESOLVE_REPLY_LIMIT];
    size_t used = 0, length = 0, reply_length = 0;
    int route = ROUTE_NONE;
    (void)signal(SIGALRM, SIG_DFL);
    alarm(HEADER_DEADLINE_SECONDS);
    while (used < HEADER_LIMIT) {
        ssize_t n = recv(fd, headers + used, 1, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return;
        used++;
        if (used >= 4 && memcmp(headers + used - 4, "\r\n\r\n", 4) == 0) break;
    }
    if (used == HEADER_LIMIT && memcmp(headers + used - 4, "\r\n\r\n", 4) != 0) {
        local_reply(fd, 431, "{}", 2); return;
    }
    if (memchr(headers, '\0', used)) { local_reply(fd, 400, "{}", 2); return; }
    headers[used] = '\0';
    int code = parse_headers(headers, &length, &route);
    if (route == ROUTE_HEALTH && code == 204) {
        static const char health[] = "{\"ok\":true,\"service\":\"d2s-local-resolver\"}";
        local_reply(fd, 200, health, sizeof(health)-1); return;
    }
    if (route == ROUTE_REGISTER) { local_reply(fd, 404, "{}", 2); return; }
    if (code != 200 || route != ROUTE_RESOLVE || !length || length > sizeof(body)) {
        local_reply(fd, code == 200 ? 400 : code, "{}", 2); return;
    }
    alarm(REQUEST_ALARM_SECONDS);
    used = 0;
    while (used < length) {
        ssize_t n = recv(fd, body + used, length - used, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return;
        used += (size_t)n;
    }
    code = handle_resolve(body, length, reply_body, sizeof(reply_body), &reply_length,
                          clock_now() + RESOLVE_DEADLINE_SECONDS);
    if (code == 200) local_reply(fd, 200, reply_body, reply_length);
    else local_reply(fd, code, "{}", 2);
    alarm(0);
}

int main(int argc, char **argv) {
    uint16_t port = 9083;
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        puts("d2s-local-resolver 0.1 base=a4a25d014a3a51191f188e0c9877ae864567d6fc loopback-only");
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "--port") == 0) {
        char *end = NULL;
        unsigned long value = strtoul(argv[2], &end, 10);
        if (!*argv[2] || *end || value < 1024 || value > 65535) return 2;
        port = (uint16_t)value;
    } else if (argc != 1) return 2;
    (void)setenv("RES_OPTIONS", RESOLVE_RES_OPTIONS, 0);
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = stop_server;
    (void)sigaction(SIGTERM, &action, NULL);
    (void)sigaction(SIGINT, &action, NULL);
    action.sa_handler = child_exited;
    (void)sigaction(SIGCHLD, &action, NULL);
    (void)signal(SIGPIPE, SIG_IGN);
    int listener = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    if (listener < 0) return 1;
    (void)setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in address = {.sin_family=AF_INET, .sin_port=htons(port),
                                  .sin_addr={.s_addr=htonl(INADDR_LOOPBACK)}};
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(listener, LOCAL_CHILDREN) != 0) { perror("local resolver"); close(listener); return 1; }
    answer_cache = answer_cache_create();
    if (!answer_cache) { close(listener); return 1; }
    pid_t children[LOCAL_CHILDREN] = {0};
    fprintf(stderr, "d2o local resolver listening on 127.0.0.1:%u\n", (unsigned)port);
    while (!stopping) {
        pid_t done;
        while ((done = waitpid(-1, NULL, WNOHANG)) > 0)
            for (size_t i=0; i<LOCAL_CHILDREN; i++) if (children[i]==done) children[i]=0;
        struct pollfd p = {.fd=listener, .events=POLLIN};
        int ready = poll(&p, 1, 500);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) break;
        if (!ready) continue;
        struct sockaddr_in peer;
        socklen_t peer_length = sizeof(peer);
        int fd = accept(listener, (struct sockaddr *)&peer, &peer_length);
        if (fd < 0) { if (errno==EINTR) continue; break; }
        if ((ntohl(peer.sin_addr.s_addr) >> 24) != 127) { close(fd); continue; }
        size_t slot = LOCAL_CHILDREN;
        for (size_t i=0; i<LOCAL_CHILDREN; i++) if (!children[i]) { slot=i; break; }
        if (slot == LOCAL_CHILDREN) {
            struct timeval timeout = {.tv_sec=1, .tv_usec=0};
            (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
            local_reply(fd, 503, "{}", 2); close(fd); continue;
        }
        pid_t child = fork();
        if (child == 0) {
            close(listener);
            (void)signal(SIGTERM, SIG_DFL); (void)signal(SIGINT, SIG_DFL);
            struct timeval timeout = {.tv_sec=4, .tv_usec=0};
            (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
            local_client(fd); close(fd); _exit(0);
        }
        close(fd);
        if (child > 0) children[slot] = child;
    }
    close(listener);
    for (size_t i=0; i<LOCAL_CHILDREN; i++) if (children[i]>0) (void)kill(children[i], SIGTERM);
    while (waitpid(-1, NULL, 0)>0 || errno==EINTR) {}
    (void)munmap(answer_cache, sizeof(*answer_cache));
    return 0;
}
