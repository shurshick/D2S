/* Exercise the complete response decision with deterministic handshakes. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#include "d2s_detect.h"
static int fake_handshake(const char *, const char *, const char *, const d2s_opts *);
#define D2S_RESPONSE_HANDSHAKE fake_handshake
#include "response.c"

static int answers[2][3], calls[2], fails, delay_ms;
static int fake_handshake(const char *host, const char *port, const char *sni,
                          const d2s_opts *opt) {
    (void)host; (void)port; (void)opt;
    int side = strcmp(sni, "target.example") != 0;
    if (delay_ms) d2s_sleep_ms(delay_ms);
    int index = calls[side]++;
    if (index >= 3) { fails++; return -1; }
    return answers[side][index];
}
#define CHECK(c) do { if (!(c)) { printf("FAIL response repeats line %d\n", __LINE__); fails++; } } while (0)
int main(void) {
    d2s_opts opt = {0}; opt.repeats = 3;
    /* Every fully measured +/- sequence retains the previous verdict. */
    for (unsigned bits = 0; bits < 64; ++bits) {
        delay_ms = bits == 63 ? 8 : 0;
        int target = 0, control = 0, expected_control_calls = 3;
        for (int i = 0; i < 3; ++i) {
            answers[0][i] = (bits >> i) & 1u;
            answers[1][i] = (bits >> (i + 3)) & 1u;
            target += answers[0][i]; control += answers[1][i];
            if (answers[1][i] && expected_control_calls == 3)
                expected_control_calls = i + 1;
        }
        d2s_resp_result before = {0}, after = {0};
        d2s_resp_decide(target, control, 0, 3, &before);
        calls[0] = calls[1] = 0;
        d2s_probe_response("127.0.0.1", "443", "target.example", &opt, &after);
        CHECK(after.verdict == before.verdict);
        CHECK(after.target == before.target);
        CHECK(calls[0] == 3);
        CHECK(calls[1] == expected_control_calls);
        CHECK(after.control == (control > 0));
        CHECK(after.target_probes == calls[0] && after.control_probes == calls[1]);
        CHECK(after.probes == calls[0] + calls[1]);
        CHECK(after.target_ms >= 0 && after.control_ms >= 0);
        if (delay_ms) CHECK(after.target_ms >= 20 && after.control_ms >= 6);
    }
    /* A local failure actually observed before success must stay unknown. */
    for (int side = 0; side < 2; ++side) {
        delay_ms = 0;
        memset(answers, 0, sizeof answers); answers[1][2] = 1;
        answers[side][0] = -1;
        calls[0] = calls[1] = 0;
        d2s_resp_result r = {0};
        d2s_probe_response("127.0.0.1", "443", "target.example", &opt, &r);
        CHECK(r.verdict == D2S_RESP_NOT_APPLICABLE);
    }
    if (fails) return 1;
    puts("response repeats: 64 verdicts preserved, positive control stops early");
    return 0;
}
