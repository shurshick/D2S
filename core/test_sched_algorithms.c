/* Scheduler algorithm lifecycle: real worker, isolated socketpair, no network. */
#define _POSIX_C_SOURCE 200809L
#include "sched.c"
#include <assert.h>

static int calls, early_seen;
static d2s_vres classify_seed(const char *ip, uint16_t port, d2s_hello tr,
    d2s_hello ctl, d2s_hello white, uint32_t mark, int repeats,
    uint32_t gap, uint32_t wait, const volatile sig_atomic_t *stop,
    const d2s_base_seed *seed) {
    (void)ip; (void)port; (void)tr; (void)ctl; (void)white; (void)mark;
    (void)repeats; (void)gap; (void)wait; (void)stop;
    calls++; early_seen = seed && seed->early_split;
    d2s_vres r = {0}; r.verdict = D2S_V_INCONCLUSIVE;
    return r;
}

int main(void) {
    d2s_catalog cat = {0};
    d2s_sched *s = d2s_sched_new(&cat, -1, 0);
    assert(s);
    d2s_sched_tcp_seeded_white_hook = classify_seed;
    task *t = &s->tasks[0];
    strcpy(t->name, "split.example"); strcpy(t->ip, "192.0.2.1");
    t->transport = 6; t->family = 4; t->port = 443;
    memset(t->trig, 0x42, 32); t->trig_len = 32;
    t->seed_use = t->seed.valid = 1;
    t->seed.repeats = 3; t->seed.fail = 3;
    t->seed_input = seed_input_of(t->trig, t->trig_len, t->ip, t->port);
    assert(start_worker(s, t, JOB_CLASSIFY) == 0);
    assert(join_worker(t) == 0 && calls == 1 && early_seen);
    d2s_vres measured = {.verdict=D2S_V_INCONCLUSIVE, .owns_search=1,
                        .split_measured=1, .split_pos=1, .split_gap_us=1000};
    verdict_to_plans(s, t, &measured);
    assert(t->split_pending && t->n_plans == 1 && !t->box_id[0]);
    assert(strstr(t->plans[0], "split payload_start +1\n"));
    t->state = T_PLANNING;
    t->exec_refused = 1; t->n_plans = t->next_plan = 1;
    assert(resume_split_detail(s, t, 1000) == 1);
    assert(t->state == T_ASKING && t->split_detailed && !t->split_pending);
    assert(!t->n_plans && !t->next_plan && !t->exec_refused);
    assert(join_worker(t) == 0 && calls == 2 && !early_seen);
    assert(!resume_split_detail(s, t, 1001) && calls == 2);
    d2s_sched_free(s); d2s_catalog_free(&cat);
    puts("algorithms: measured split resumes detailed search once");
    return 0;
}
