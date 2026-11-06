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

static void contextual_ranking(void) {
    d2s_catalog c = {0};
    c.boxes = calloc(1, sizeof *c.boxes); assert(c.boxes); c.n_boxes = 1;
    d2s_cat_box *b = c.boxes;
    b->plans = calloc(2, sizeof *b->plans); b->binds = calloc(2, sizeof *b->binds);
    assert(b->plans && b->binds); b->n_plans = b->n_binds = 2;
    for (int i = 0; i < 2; i++) {
        d2s_cat_plan *p = &b->plans[i]; d2s_cat_binding *bd = &b->binds[i];
        snprintf(p->id, sizeof p->id, "plan-%d", i); strcpy(p->proto, "tls");
        p->text = strdup(i ? "reliable" : "popular"); assert(p->text);
        p->enabled = 1; p->successes = i ? 10 : 100;
        p->quality[0].passed = (uint32_t)p->successes;
        p->quality[0].failed = i ? 0 : 900;
        strcpy(bd->kind, "name"); strcpy(bd->target, "old.example");
        strcpy(bd->plan_id, p->id); bd->level = 3; bd->enabled = 1;
        bd->transport = 6; bd->family = 4; bd->shape = 1;
    }
    d2s_sched *s = d2s_sched_new(&c, -1, 0); assert(s);
    task *t = &s->tasks[0]; strcpy(t->name, "new.example");
    t->transport = 6; t->family = 4;
    assert(own_first_plans(s, t, 1) == 2);
    assert(!strcmp(t->plans[0], "reliable"));
    /* IPv6 must not inherit IPv4 observations. */
    for (int i = 0; i < 2; i++) b->binds[i].family = 6;
    t->family = 6; t->n_own_seen = 0;
    assert(own_first_plans(s, t, 1) == 2);
    assert(!strcmp(t->plans[0], "popular"));
    /* Recording requires the actual trial's execution and excludes local
       limits, lost events and weaker handshake-only evidence. */
    char text[4096];
    assert(!d2s_tcp_split_plan(32, 1, 1000, 1500, text, sizeof text));
    free(b->plans[0].text); b->plans[0].text = strdup(text); assert(b->plans[0].text);
    strcpy(t->plans[0], text); t->next_plan = t->n_plans = 1; t->family = 4;
    t->ver.level = D2S_VER_APPLICATION; t->ver_ok = 1; t->last_verify_ms = 120;
    plan_quality_record(s, t, 1, 1000);
    d2s_plan_quality *q = &b->plans[0].quality[0];
    assert(q->passed == 101 && q->failed == 900 && q->elapsed_ms == 120 && q->cost_known);
    t->ver.local_limit = 1; plan_quality_record(s, t, 0, 1001);
    t->ver.local_limit = 0; t->ver_ok = 0; plan_quality_record(s, t, 0, 1002);
    t->ver_ok = 1; s->dropped_seen++; plan_quality_record(s, t, 0, 1003);
    s->dropped_seen--; t->ver.replay_proof = 1; plan_quality_record(s, t, 0, 1004);
    assert(q->failed == 900);
    t->ver.replay_proof = 0; plan_quality_record(s, t, 0, 1005);
    assert(q->failed == 901 && q->elapsed_ms == 120);
    /* Optional quality data survives restarts; absent legacy data is neutral. */
    char path[] = "/tmp/d2s-quality-XXXXXX", err[160];
    int fd = mkstemp(path); assert(fd >= 0); close(fd);
    assert(!d2s_catalog_save(&c, path, err, sizeof err));
    d2s_catalog loaded = {0}; assert(!d2s_catalog_load(path, &loaded, err, sizeof err));
    const d2s_plan_quality *restored = &loaded.boxes[0].plans[0].quality[0];
    assert(restored->passed == q->passed && restored->failed == q->failed &&
           restored->cost_known && restored->elapsed_ms == q->elapsed_ms);
    assert(!loaded.boxes[0].plans[0].quality[4].passed);
    d2s_catalog_free(&loaded);
    const char *bad[] = {
        "{\"family\":4,\"shape\":1,\"passed\":-1}",
        "{\"family\":4,\"shape\":1,\"failed\":4294967296}",
        "{\"family\":0,\"shape\":1,\"passed\":1}",
        "{\"family\":4,\"shape\":1},{\"family\":4,\"shape\":1}"
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        FILE *f = fopen(path, "w"); assert(f);
        fprintf(f, "{\"boxes\":[{\"plans\":[{\"quality\":[%s]}]}]}", bad[i]); fclose(f);
        assert(d2s_catalog_load(path, &loaded, err, sizeof err) != 0);
    }
    unlink(path);
    d2s_sched_free(s); d2s_catalog_free(&c);
}

int main(void) {
    d2s_plan_quality good = {.passed=100}, fresh = {.passed=2};
    assert(d2s_quality_compare(&good, &fresh) > 0);
    fresh.passed = 100; good.cost_known = fresh.cost_known = 1;
    good.nominal_fakes = 2; fresh.nominal_fakes = 8;
    assert(d2s_quality_compare(&good, &fresh) > 0);
    good.checked_at = 1; fresh.checked_at = 86401;
    assert(d2s_quality_compare_at(&good, &fresh, 86401) < 0);
    d2s_quality_note(&good, 1, 100, 86401); assert(good.passed == 51);
    uint32_t old = good.passed; d2s_quality_note(&good, -1, 100, 90000);
    assert(good.passed == old);
    d2s_plan_quality huge = {.passed=UINT32_MAX,.failed=UINT32_MAX};
    d2s_quality_note(&huge, 1, UINT32_MAX, 1);
    assert(huge.passed && huge.failed && d2s_quality_compare(&huge, NULL) >= 0);
    contextual_ranking();
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
    t->vol.rx_cut = 1; t->ver.level = D2S_VER_APPLICATION;
    t->ver.budget = D2S_BUDGET_CUT; t->ver.budget_packets = 10;
    budget_cut_reject(s, t, 999);
    assert(t->state == T_PLANNING && t->partial_valid && !cat.n_boxes);
    t->vol.rx_cut = 0;
    t->owned_fallback = 1; /* a data-stage cut may otherwise refill first */
    assert(install_next(s, t) == -1 && t->fb_next == 0);
    assert(resume_split_detail(s, t, 1000) == 1);
    assert(t->state == T_ASKING && t->split_detailed && !t->split_pending);
    assert(!t->n_plans && !t->next_plan && !t->exec_refused);
    assert(join_worker(t) == 0 && calls == 2 && !early_seen);
    assert(!resume_split_detail(s, t, 1001) && calls == 2);
    d2s_sched_free(s); d2s_catalog_free(&cat);
    puts("algorithms: split continuation, contextual quality, cost, restart and refusal guards PASS");
    return 0;
}
