#ifndef D2S_DIAGNOSTICS_H
#define D2S_DIAGNOSTICS_H
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
/* Callback выполняется в потоке контроллера и не влияет на результаты поиска. */
typedef struct {
    uint64_t id;
    int64_t elapsed_ms, queue_ms, probe_units;
    int64_t classify_ms, contact_ms, verify_ms;
    unsigned family, trigger, shape;
    const char *target, *protocol, *outcome, *reason, *ip, *path, *kind;
} d2s_diag_event;
typedef void (*d2s_diag_observer)(void *, const d2s_diag_event *);
typedef struct {
    uint64_t boxes, bindings, plans, observations, active, queued, tasks, snapshots, http_records, http_queued;
} d2s_diag_counts;
typedef struct d2s_diag d2s_diag;
d2s_diag *d2s_diag_new(void);
void d2s_diag_free(d2s_diag *d);
size_t d2s_diag_bytes(const d2s_diag *d);
size_t d2s_diag_event_count(const d2s_diag *d);
size_t d2s_diag_sample_count(const d2s_diag *d);
void d2s_diag_record(d2s_diag *d,const d2s_diag_event *e);
void d2s_diag_sample(d2s_diag *d,int64_t mono_ms,const d2s_diag_counts *c,const char *proc,const char *run);
int d2s_diag_write(const d2s_diag *d,FILE *f);
#endif
