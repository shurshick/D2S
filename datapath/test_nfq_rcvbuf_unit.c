/* test_nfq_rcvbuf_unit.c — buffer-limit and privileged override decisions. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

static int force_allowed;
static int forced_calls;
static int normal_calls;
static int observed_rcvbuf;
static int fails;

static int nfq_test_setsockopt(int fd, int level, int option,
                               const void *value, socklen_t len);
static int nfq_test_getsockopt(int fd, int level, int option,
                               void *value, socklen_t *len);

#define setsockopt nfq_test_setsockopt
#define getsockopt nfq_test_getsockopt
#include "nfq.c"
#undef getsockopt
#undef setsockopt

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "ПРОВАЛ: %s\n", msg); \
        fails++; \
    } \
} while (0)

static int nfq_test_setsockopt(int fd, int level, int option,
                               const void *value, socklen_t len) {
    (void)fd;
    if (level != SOL_SOCKET || len != sizeof(int)) {
        errno = EINVAL;
        return -1;
    }
    int requested = 0;
    memcpy(&requested, value, sizeof requested);
    if (option == SO_RCVBUFFORCE) {
        forced_calls++;
        if (!force_allowed) {
            errno = EPERM;
            return -1;
        }
        observed_rcvbuf = requested * 2;
        return 0;
    }
    if (option == SO_RCVBUF) {
        normal_calls++;
        observed_rcvbuf = 425984; /* doubled net.core.rmem_max = 212992 */
        return 0;
    }
    errno = ENOPROTOOPT;
    return -1;
}

static int nfq_test_getsockopt(int fd, int level, int option,
                               void *value, socklen_t *len) {
    (void)fd;
    if (level != SOL_SOCKET || option != SO_RCVBUF || *len < sizeof(int)) {
        errno = EINVAL;
        return -1;
    }
    memcpy(value, &observed_rcvbuf, sizeof observed_rcvbuf);
    *len = sizeof observed_rcvbuf;
    return 0;
}

int main(void) {
    const int requested = 4 * 1024 * 1024;
    int actual = 0;

    force_allowed = 1;
    forced_calls = normal_calls = 0;
    CHECK(set_rcvbuf(7, requested, &actual) == 0,
          "привилегированный сокет не принял запрошенный буфер");
    CHECK(actual == 2 * requested,
          "успешный SO_RCVBUFFORCE не подтвердился через getsockopt");
    CHECK(forced_calls == 1 && normal_calls == 0,
          "после успешного SO_RCVBUFFORCE вызван ограниченный SO_RCVBUF");

    force_allowed = 0;
    forced_calls = normal_calls = 0;
    CHECK(set_rcvbuf(7, requested, &actual) == 1,
          "ограниченный SO_RCVBUF не помечен как меньше запроса");
    CHECK(actual == 425984,
          "эффективный ограниченный размер не прочитан через getsockopt");
    CHECK(forced_calls == 1 && normal_calls == 1,
          "при отказе force не использован обычный SO_RCVBUF");

    if (fails) return 1;
    puts("NFQUEUE receive-buffer force/fallback: OK");
    return 0;
}
