/* test_nfq_rcvbuf.c — real Linux NFQUEUE socket receive-buffer contract. */
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/netlink.h>

#include "d2s_nfq.h"

int main(void) {
    const int requested = 16 * 1024 * 1024;
    int probe_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    if (probe_fd < 0) {
        perror("SKIP: socket(NETLINK_NETFILTER)");
        return 0;
    }
    int probe = requested;
    if (setsockopt(probe_fd, SOL_SOCKET, SO_RCVBUFFORCE,
                   &probe, sizeof probe) != 0) {
        printf("SKIP: ядро не разрешило SO_RCVBUFFORCE в этой среде: %s\n",
               strerror(errno));
        close(probe_fd);
        return 0;
    }
    close(probe_fd);

    d2s_nfq_cfg cfg = {
        .queue = 61431,
        .copy_range = 1500,
        .maxlen = 32,
        .fail_open = 1,
        .rcvbuf = requested
    };
    char err[256] = {0};
    d2s_nfq *q = d2s_nfq_open(&cfg, err, sizeof err);
    if (!q) {
        fprintf(stderr, "ПРОВАЛ: открыть изолированную NFQUEUE: %s\n", err);
        return 1;
    }

    int actual = 0;
    socklen_t actual_len = sizeof actual;
    int got = getsockopt(d2s_nfq_fd(q), SOL_SOCKET, SO_RCVBUF,
                         &actual, &actual_len);
    d2s_nfq_close(q);
    if (got != 0) {
        perror("ПРОВАЛ: getsockopt(SO_RCVBUF)");
        return 1;
    }
    if (actual < requested) {
        fprintf(stderr,
                "ПРОВАЛ: NFQUEUE SO_RCVBUF=%d меньше запрошенных %d\n",
                actual, requested);
        return 1;
    }
    printf("NFQUEUE SO_RCVBUF=%d, запрошено %d: OK\n", actual, requested);
    return 0;
}
