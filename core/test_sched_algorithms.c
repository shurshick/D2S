/* Scheduler algorithm lifecycle: real worker, isolated socketpair, no network. */
#define _POSIX_C_SOURCE 200809L
#include "sched.c"
#include <assert.h>
#include "test_quic_pq.h"

static int calls, early_seen;
static size_t learned_seen;
static unsigned learned_repeats;
static int fail_spawn(void) { return -1; }
static d2s_vres classify_seed(const char *ip, uint16_t port, d2s_hello tr,
    d2s_hello ctl, d2s_hello white, uint32_t mark, int repeats,
    uint32_t gap, uint32_t wait, const volatile sig_atomic_t *stop,
    const d2s_base_seed *seed) {
    (void)ip; (void)port; (void)tr; (void)ctl; (void)white; (void)mark;
    (void)repeats; (void)gap; (void)wait; (void)stop;
    calls++; early_seen = seed && seed->early_split;
    learned_seen=seed ? seed->nlearned : 0;
    learned_repeats=learned_seen ? seed->learned[0].repeats : 0;
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
    t->plan_recipe_valid[0]=1;
    assert(own_first_plans(s, t, 1) == 2);
    assert(!strcmp(t->plans[0], "reliable") && !t->plan_recipe_valid[0]);
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
    t->plan_recipe_valid[0]=1;
    t->plan_recipes[0]=(d2s_arm){.badsum=1,.repeats=3,.gap_ms=80,.disorder=1};
    t->ver.local_limit=1; plan_quality_record(s,t,1,999);
    assert(!b->plans[0].recipe_valid); t->ver.local_limit=0;
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
    assert(loaded.boxes[0].plans[0].recipe_valid &&
           d2s_recipe_same(&loaded.boxes[0].plans[0].recipe,&b->plans[0].recipe));
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
    /* Promotion requires repeated completed evidence, same protocol family
       and shape, and a confirmed own binding. Copies own no catalog pointer. */
    b->plans[0].quality[0]=(d2s_plan_quality){.passed=1};
    for (int i=0;i<2;i++) { b->binds[i].family=4; b->binds[i].verified_by=D2S_VERBY_PROBE; }
    size_t n=0, bytes=0;
    d2s_arm *questions=learned_questions_for(s,t,&n,&bytes);
    assert(!questions && !n);
    b->plans[0].quality[0].passed=2;
    questions=learned_questions_for(s,t,&n,&bytes);
    assert(questions && n==1 && bytes>=sizeof *questions && !questions[0].name);
    b->plans[0].recipe.repeats=7;
    assert(questions[0].repeats==3); free(questions);
    t->family=6; questions=learned_questions_for(s,t,&n,&bytes);
    assert(!questions && !n);
    t->family=4; memset(t->trig,0x42,32); t->trig_len=32;
    t->seed_use=t->seed.valid=1; t->seed.repeats=3; t->seed.fail=3;
    t->seed_input=seed_input_of(t->trig,t->trig_len,t->ip,t->port);
    d2s_sched_tcp_seeded_white_hook=classify_seed;
    d2s_diag_memory_enable(1);
    d2s_diag_mem_site before[D2S_DIAG_MEMORY_SITE_COUNT],after[D2S_DIAG_MEMORY_SITE_COUNT];
    d2s_diag_memory_snapshot(before);
    assert(!start_worker(s,t,JOB_CLASSIFY));
    b->plans[0].recipe.repeats=13; /* after main-thread snapshot */
    assert(!join_worker(t) && learned_seen==1 && learned_repeats==7);
    d2s_diag_memory_snapshot(after);
    assert(after[0].live_bytes==before[0].live_bytes && after[0].created==before[0].created+2 &&
           after[0].destroyed==before[0].destroyed+2);
    d2s_sched_spawn_hook=fail_spawn;
    assert(start_worker(s,t,JOB_CLASSIFY)!=0);
    d2s_sched_spawn_hook=NULL;
    d2s_diag_memory_snapshot(after);
    assert(after[0].live_bytes==before[0].live_bytes && after[0].created==before[0].created+4 &&
           after[0].destroyed==before[0].destroyed+4);
    d2s_diag_memory_enable(0);
    assert(!d2s_hello_from_profile(D2S_SHAPE_MODERN,"fallback.example",t->trig,sizeof t->trig,&t->trig_len));
    t->search_owned=0; t->fb_next=0; t->n_tried=0;
    assert(refill_from_fallback(s,t)>0 && t->plan_recipe_valid[0] && t->plan_recipes[0].seqovl==1);
    d2s_sched_free(s); d2s_catalog_free(&c);
}

static void simplification(void) {
    const char *src = "d2s-plan 1 1\nid 12345678123456781234567812345678\n"
        "proto tcp tls\npayload 1 01020304\npoison 1 badsum\n"
        "fake payload=1 poison=1 repeats=3 gap_us=1000 place=before\n"
        "split payload_start +1\npace 100\n";
    char out[4096], err[160]; size_t next=0;
    assert(d2s_plan_simplify_next(src,0,out,sizeof out,&next,err,sizeof err)==1);
    assert(strstr(out,"repeats=2") && strstr(out,"gap_us=1000") &&
           strstr(out,"poison 1 badsum") && next==1);
    assert(strstr(out,"id 00000000000000000000000000000000"));
    assert(d2s_plan_simplify_next(src,next,out,sizeof out,&next,err,sizeof err)==1);
    assert(strstr(out,"repeats=3") && strstr(out,"gap_us=0"));
    assert(d2s_plan_simplify_next(src,next,out,sizeof out,&next,err,sizeof err)==1);
    assert(!strstr(out,"pace ") && strstr(out,"split payload_start +1"));
    assert(d2s_plan_simplify_next(src,next,out,sizeof out,&next,err,sizeof err)==0);
    assert(d2s_plan_simplify_next("invalid",0,out,sizeof out,&next,err,sizeof err)==-1);
    assert(d2s_plan_simplify_next(src,0,out,3,&next,err,sizeof err)==-1);
    uint8_t wire[D2S_PLAN_TLV_MAX];size_t wn=0;d2s_plan *p=NULL;
    assert(d2s_plan_simplify_next(src,0,out,sizeof out,&next,err,sizeof err)==1);
    assert(!d2s_plan_text_to_tlv(out,wire,sizeof wire,&wn,err,sizeof err));
    assert(!d2s_plan_load(wire,wn,&p,err,sizeof err));d2s_plan_free(p);
}

static void maintenance(void) {
    const char *src="d2s-plan 1 1\nid 00000000000000000000000000000000\n"
        "proto tcp tls\npayload 1 01020304\npoison 1 badsum\n"
        "fake payload=1 poison=1 repeats=3 gap_us=1000 place=before\n"
        "split payload_start +1\n";
    d2s_catalog c={0};c.boxes=calloc(1,sizeof *c.boxes);assert(c.boxes);c.n_boxes=1;
    d2s_cat_box *b=c.boxes;strcpy(b->id,"measured-box");
    b->plans=calloc(1,sizeof *b->plans);b->binds=calloc(1,sizeof *b->binds);
    assert(b->plans && b->binds);b->n_plans=b->n_binds=1;
    char id[40];uint8_t hash[D2S_PLAN_ID_LEN];plan_ident(src,id,sizeof id,hash);
    d2s_cat_plan *p=b->plans;strcpy(p->id,id);strcpy(p->proto,"tls");
    p->text=strdup(src);assert(p->text);p->enabled=1;p->successes=100;
    d2s_cat_binding *bd=b->binds;strcpy(bd->target,"min.example");strcpy(bd->kind,"name");
    strcpy(bd->plan_id,id);bd->enabled=1;bd->level=3;bd->confirmed=100;
    bd->successes=100;bd->transport=6;bd->family=4;bd->shape=1;
    bd->verified_by=D2S_VERBY_PROBE;bd->budget=D2S_CAT_BUDGET_PASSED;
    d2s_sched *s=d2s_sched_new(&c,-1,0);assert(s);task *t=&s->tasks[0];
    task_reset(s,t);
    strcpy(t->name,bd->target);strcpy(t->min_box,b->id);strcpy(t->min_source,id);
    t->transport=6;t->family=4;t->state=T_WATCHING;t->min_ready=1;
    assert(!d2s_hello_from_profile(D2S_SHAPE_MODERN,t->name,t->trig,sizeof t->trig,&t->trig_len));
    s->cpu_valid=s->mem_valid=1;s->cpu_free_u=900000;
    minimize_dispatch(s);assert(!t->min_active); /* observe/default-off */
    d2s_sched_optimize(s,1);s->tasks[1].state=T_QUEUED;
    minimize_dispatch(s);assert(!t->min_active); /* repair has priority */
    s->tasks[1].state=T_FREE;minimize_dispatch(s);assert(t->min_active);
    assert(!task_of(s,t->name,6,4)); /* new suspicion may start separately */
    assert(task_free_slot(s)!=t);
    char err[160];
    assert(d2s_plan_simplify_next(src,0,t->plans[0],sizeof t->plans[0],&t->min_next,err,sizeof err)==1);
    t->n_plans=t->next_plan=1;t->ver_ok=1;t->trial_installed=1;
    t->ver.level=D2S_VER_APPLICATION;t->ver.body_complete=1;t->ver.name_ok=1;
    t->ver.budget=D2S_BUDGET_PASSED;t->last_verify_ms=40;t->ver_plan_id[0]=1;
    t->ver.local_limit=1;assert(!minimize_proven(s,t,1000) && !t->min_passes);
    t->ver.local_limit=0;s->dropped_seen=1;assert(!minimize_proven(s,t,1000) && !t->min_passes);
    s->dropped_seen=0;t->ver.budget=D2S_BUDGET_CUT;
    assert(!minimize_proven(s,t,1000) && !t->min_passes);
    t->ver.budget=D2S_BUDGET_PASSED;t->ver_ok=0;
    assert(!minimize_proven(s,t,1000) && !t->min_passes); /* APP alone is insufficient */
    t->ver_ok=1;
    assert(!minimize_proven(s,t,1000) && t->min_passes==1);
    assert(!strcmp(b->binds[0].plan_id,id) && b->n_plans==1); /* first proof changes nothing */
    t->trial_installed=1;t->next_plan=1;
    assert(!minimize_proven(s,t,1001) && b->n_plans==1); /* duplicate receipt */
    t->ver_plan_id[0]=2;bd->successes++;
    assert(!minimize_proven(s,t,1001) && b->n_plans==1); /* concurrent repair generation */
    bd->successes--;t->last_verify_ms=60;
    assert(minimize_proven(s,t,1002)==1);
    assert(b->n_plans==2 && strcmp(b->binds[0].plan_id,id) && b->binds[0].successes==2);
    assert(b->plans[0].successes==100 && !strcmp(b->plans[0].text,src));
    assert(b->plans[1].quality[0].passed==2 && !b->plans[1].recipe_valid);
    assert(b->binds[0].budget==D2S_CAT_BUDGET_PASSED && t->min_cursor==0);
    assert(minimize_source(s,t,NULL));
    t->state=T_PLANNING;t->n_plans=t->next_plan=1;t->owned_fallback=1;
    assert(install_next(s,t)==-1 && !t->fb_next);
    s->tasks[1].state=T_QUEUED;assert(minimize_tick(s,t,2000)==1 && t->state==T_FREE);
    assert(b->n_binds==1 && b->binds[0].enabled); /* only the trial retired */
    s->tasks[1].state=T_FREE;d2s_sched_free(s);d2s_catalog_free(&c);
}

static void full_flight_applicability(void) {
    d2s_catalog c={0};d2s_sched *s=d2s_sched_new(&c,-1,0);assert(s);
    task *t=&s->tasks[0];task_reset(s,t);t->transport=17;t->family=4;
    strcpy(t->name,"pq.example");uint8_t a[1500],b[1500];size_t an=0,bn=0;
    assert(!d2s_test_pq_initials(t->name,a,&an,b,&bn));
    quic_note_multi(s,t->name,4);memcpy(t->trig,a,an);t->trig_len=an;
    assert(quic_split_unfit(s,t));
    const uint8_t *dg[]={a,b};size_t len[]={an,bn};
    t->trig_len=d2s_qsnap_pack(dg,len,2,t->trig,sizeof t->trig);assert(t->trig_len);
    assert(!quic_split_unfit(s,t));
    assert(!quic_split_text_unfit(s,t,"d2s-plan 1 14\nproto udp quic\nquicsplit 2\n"));
    assert(quic_split_text_unfit(s,t,"d2s-plan 1 10\nproto udp quic\nquicsplit 1\n"));
    c.boxes=calloc(1,sizeof *c.boxes);assert(c.boxes);c.n_boxes=1;
    d2s_cat_box *box=c.boxes;box->plans=calloc(2,sizeof *box->plans);box->binds=calloc(2,sizeof *box->binds);
    assert(box->plans && box->binds);box->n_plans=box->n_binds=2;
    for(int i=0;i<2;i++) {
        d2s_cat_plan *p=&box->plans[i];d2s_cat_binding *bd=&box->binds[i];
        snprintf(p->id,sizeof p->id,"form-%d",i+1);p->enabled=1;
        p->text=strdup(i?"d2s-plan 1 14\nproto udp quic\nquicsplit 2\n":"d2s-plan 1 10\nproto udp quic\nquicsplit 1\n");assert(p->text);
        strcpy(bd->target,t->name);strcpy(bd->kind,"name");strcpy(bd->plan_id,p->id);
        bd->transport=17;bd->family=4;bd->shape=D2S_LINK_SHAPE_QUIC;bd->enabled=1;
    }
    quic_note_multi(s,t->name,4);
    assert(box->binds[0].recheck_mono_ms && !box->binds[1].recheck_mono_ms);
    d2s_sched_free(s);d2s_catalog_free(&c);
}

int main(void) {
    full_flight_applicability();
    simplification();
    maintenance();
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
    calls=early_seen=0;
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
