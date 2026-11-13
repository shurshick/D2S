/* Real kernel segmentation and fail-safe preservation, isolated netns only. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "d2s_nfq.h"
#include "d2s_nl.h"

/* Baseline has no offload gate: allow the same test to expose that gap. */
#ifndef D2S_NFQA_SKB_GSO
#define d2s_nl_packet_offloaded(packet) 0
#endif

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif

static void run(int family, int force_gso) {
    char err[256] = {0};
    d2s_nfq_cfg cfg = { .queue = 61432, .copy_range = 65535, .maxlen = 64, .fail_open = 1 };
    d2s_nfq *q = d2s_nfq_open(&cfg, err, sizeof err);
    if (!q) { fprintf(stderr, "%s\n", err); exit(1); }
    if (force_gso) {
        uint8_t msg[128];
        size_t n = d2s_nl_cfg_params(msg, sizeof msg, cfg.queue, 999, cfg.copy_range,
            D2S_NFQNL_COPY_PACKET, cfg.maxlen,
            D2S_NFQA_CFG_F_FAIL_OPEN | D2S_NFQA_CFG_F_GSO,
            D2S_NFQA_CFG_F_FAIL_OPEN | D2S_NFQA_CFG_F_GSO);
        CHECK(send(d2s_nfq_fd(q), msg, n, 0) == (ssize_t)n);
        /* Consume and validate the actual kernel ACK. */
        struct pollfd p = { .fd = d2s_nfq_fd(q), .events = POLLIN };
        CHECK(poll(&p, 1, 3000) == 1);
        uint8_t reply[512];
        ssize_t r = d2s_nfq_recv(q, reply, sizeof reply, err, sizeof err);
        CHECK(r > 0);
        d2s_nl_iter it; d2s_nl_msg m; int32_t code = -1;
        d2s_nl_iter_init(&it, reply, (size_t)r);
        CHECK(d2s_nl_next(&it, &m) && d2s_nl_errno(&m, &code) == 0 && code == 0);
    }
    int sink = socket(family, SOCK_DGRAM, 0), source = socket(family, SOCK_DGRAM, 0);
    CHECK(sink >= 0 && source >= 0);
    struct sockaddr_storage ss = {0};
    socklen_t sl;
    if (family == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)&ss;
        a->sin_family = AF_INET; a->sin_port = htons(46132); a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sl = sizeof *a;
    } else {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
        a->sin6_family = AF_INET6; a->sin6_port = htons(46132); a->sin6_addr = in6addr_loopback;
        sl = sizeof *a;
    }
    CHECK(bind(sink, (struct sockaddr *)&ss, sl) == 0);
    int segment = 256;
    CHECK(setsockopt(source, IPPROTO_UDP, UDP_SEGMENT, &segment, sizeof segment) == 0);
    uint8_t payload[1024];
    for (size_t i = 0; i < sizeof payload; i++) payload[i] = (uint8_t)(i / 256 + 1);
    CHECK(sendto(source, payload, sizeof payload, 0, (struct sockaddr *)&ss, sl) == sizeof payload);
    int queued = 0, bypassed = 0;
    while (queued < (force_gso ? 1 : 4)) {
        struct pollfd p = { .fd = d2s_nfq_fd(q), .events = POLLIN };
        CHECK(poll(&p, 1, 3000) == 1);
        uint8_t buf[8192];
        ssize_t n = d2s_nfq_recv(q, buf, sizeof buf, err, sizeof err);
        CHECK(n > 0);
        d2s_nl_iter it; d2s_nl_msg m;
        d2s_nl_iter_init(&it, buf, (size_t)n);
        while (d2s_nl_next(&it, &m)) {
            if ((m.type & 255) != D2S_NFQNL_MSG_PACKET) continue;
            d2s_nl_pkt packet;
            CHECK(d2s_nl_packet(&m, &packet) == 0 && packet.have_hdr && !packet.truncated);
            CHECK(d2s_nl_packet_offloaded(&packet) == force_gso);
            if (d2s_nl_packet_offloaded(&packet)) bypassed++;
            else CHECK(packet.payload_len == (size_t)(family == AF_INET ? 284 : 304));
            CHECK(d2s_nfq_verdict(q, packet.id, D2S_NF_ACCEPT, err, sizeof err) == 0);
            queued++;
        }
    }
    for (int i = 0; i < 4; i++) {
        struct pollfd p = { .fd = sink, .events = POLLIN };
        CHECK(poll(&p, 1, 3000) == 1);
        uint8_t got[2048];
        CHECK(recv(sink, got, sizeof got, 0) == 256);
        for (int j = 0; j < 256; j++) CHECK(got[j] == i + 1);
    }
    struct pollfd p = { .fd = sink, .events = POLLIN };
    CHECK(poll(&p, 1, 50) == 0);
    CHECK(queued == (force_gso ? 1 : 4) && bypassed == force_gso);
    close(source); close(sink); d2s_nfq_close(q);
    printf("IPv%d GSO=%d: queue=%d, offload bypass=%d, four complete ordered datagrams PASS\n",
        family == AF_INET ? 4 : 6, force_gso, queued, bypassed);
}
int main(void) {
    run(AF_INET, 0); run(AF_INET6, 0);
    run(AF_INET, 1); run(AF_INET6, 1);
    return 0;
}
