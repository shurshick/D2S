#ifndef D2S_DIAG_TRANSPORT_H
#define D2S_DIAG_TRANSPORT_H
#include "include/d2s_diagnostics.h"
#include "../runtime/d2s_diag_ipc.h"

typedef struct {
    d2s_diag_header header;
    int64_t monotonic_ms;
    d2s_diag_counts counts;
    d2s_diag_madvise madvise;
    d2s_diag_mem_site memory[D2S_DIAG_MEMORY_SITE_COUNT];
} d2s_diag_counts_message;

typedef struct {
    d2s_diag_header header;
    uint64_t id;
    int64_t elapsed_ms, queue_ms, probe_units;
    unsigned family, trigger, shape;
    char target[256], protocol[16], outcome[32], reason[256], ip[48], path[16], kind[8];
} d2s_diag_event_message;
#endif
