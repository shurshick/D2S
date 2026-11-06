#ifndef D2S_LEARNING_H
#define D2S_LEARNING_H
#include "d2s_arm.h"
#include <stdint.h>

/* Method parameters only. No borrowed name/payload, endpoint, third-party
   pool, or assertion of a DPI property is part of a learned question. */
#define D2S_RECIPE_FIELDS(X) \
 X(seqovl,0,D2S_ARM_TRIGGER_MAX) X(seqovl_hello,0,1) X(badsum,0,1) \
 X(repeats,0,255) X(gap_ms,0,UINT32_MAX/1000u) X(disorder,0,1) \
 X(disorder_pos,0,D2S_ARM_TRIGGER_MAX) X(between,0,1) X(ttl,0,255) \
 X(autottl,0,1) X(autottl_delta,-128,127) X(autottl_min,0,255) X(autottl_max,0,255) \
 X(seq_out,0,1) X(decoy_hello,0,1) X(md5,0,1) X(tcpts,0,1) \
 X(tcpts_up,0,1) X(ipidzero,0,1) X(oob,0,1) X(split_pos,0,D2S_ARM_TRIGGER_MAX)

static inline int d2s_recipe_same(const d2s_arm *a, const d2s_arm *b) {
    if (!a || !b) return 0;
#define D2S_RECIPE_CMP(field,low,high) if (a->field != b->field) return 0;
    D2S_RECIPE_FIELDS(D2S_RECIPE_CMP)
#undef D2S_RECIPE_CMP
    return 1;
}
static inline int d2s_recipe_nonempty(const d2s_arm *a) {
    return a && (a->seqovl || a->seqovl_hello || a->disorder || a->split_pos ||
        a->badsum || a->md5 || a->tcpts || a->seq_out || a->repeats || a->oob);
}
#endif
