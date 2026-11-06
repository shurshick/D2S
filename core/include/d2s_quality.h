#ifndef D2S_QUALITY_H
#define D2S_QUALITY_H
#include <stdint.h>
#include <limits.h>

/* Four supported shapes, independently for IPv4/IPv6. Unknown is not a
   context. Fixed semantic dimensions, not a budget on searches/evidence. */
#define D2S_QUALITY_CONTEXTS 8
typedef struct {
    uint32_t passed, failed, elapsed_ms;
    uint32_t nominal_fakes, nominal_delay_us;
    int cost_known;
    int64_t checked_at;
} d2s_plan_quality;
static inline int d2s_quality_index(unsigned family, unsigned shape) {
    int i = shape == 1 ? 0 : shape == 2 ? 1 : shape == 3 ? 2 : shape == 6 ? 3 : -1;
    return i < 0 || (family != 4 && family != 6) ? -1 : i + (family == 6 ? 4 : 0);
}
/* Idle-day decay is a ranking policy, not a claim about DPI lifetime.
   These are evidence weights, not all-time totals. Backward clocks add none. */
static inline void d2s_quality_decay(d2s_plan_quality *q, int64_t now) {
    if (!q || !q->checked_at || now <= q->checked_at) return;
    uint64_t days = (uint64_t)(now - q->checked_at) / 86400u;
    if (days > 31) days = 31;
    q->passed >>= days; q->failed >>= days;
}
static inline void d2s_quality_note(d2s_plan_quality *q, int passed,
                                   uint32_t elapsed, int64_t now) {
    if (!q || (passed != 0 && passed != 1)) return;
    d2s_quality_decay(q, now);
    /* Rescale only to keep arithmetic representable, not to reject work. */
    if ((uint64_t)q->passed + q->failed >= UINT32_MAX / 2u) {
        q->passed = (uint32_t)(((uint64_t)q->passed + 1u) / 2u);
        q->failed = (uint32_t)(((uint64_t)q->failed + 1u) / 2u);
    }
    if (passed) q->passed++; else q->failed++;
    q->elapsed_ms = !q->elapsed_ms ? elapsed :
        (uint32_t)(((uint64_t)q->elapsed_ms * 7u + elapsed) / 8u);
    q->checked_at = now;
}
/* Posterior mean with one success/failure of neutral prior: a tiny fresh
   sample does not outrank repeated reliable evidence by raw pass fraction. */
static inline int d2s_quality_compare(const d2s_plan_quality *a,
                                      const d2s_plan_quality *b) {
    uint64_t ap = a ? a->passed : 0, af = a ? a->failed : 0;
    uint64_t bp = b ? b->passed : 0, bf = b ? b->failed : 0;
    /* Loaded data is uint32; each factor at most 2^33, so use normalized
       halves for extreme imported counts before multiplying. */
    while (ap + af > UINT32_MAX / 2u) { ap = (ap + 1u) / 2u; af = (af + 1u) / 2u; }
    while (bp + bf > UINT32_MAX / 2u) { bp = (bp + 1u) / 2u; bf = (bf + 1u) / 2u; }
    uint64_t left = (ap + 1u) * (bp + bf + 2u);
    uint64_t right = (bp + 1u) * (ap + af + 2u);
    if (left != right) return left > right ? 1 : -1;
    if (a && b && a->cost_known && b->cost_known) {
        if (a->nominal_fakes != b->nominal_fakes)
            return a->nominal_fakes < b->nominal_fakes ? 1 : -1;
        if (a->nominal_delay_us != b->nominal_delay_us)
            return a->nominal_delay_us < b->nominal_delay_us ? 1 : -1;
    }
    if (a && b && a->elapsed_ms && b->elapsed_ms && a->elapsed_ms != b->elapsed_ms)
        return a->elapsed_ms < b->elapsed_ms ? 1 : -1;
    return 0;
}
static inline int d2s_quality_compare_at(const d2s_plan_quality *a,
                                         const d2s_plan_quality *b, int64_t now) {
    d2s_plan_quality qa = a ? *a : (d2s_plan_quality){0};
    d2s_plan_quality qb = b ? *b : (d2s_plan_quality){0};
    d2s_quality_decay(&qa, now); d2s_quality_decay(&qb, now);
    return d2s_quality_compare(&qa, &qb);
}
#endif
