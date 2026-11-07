/* Idle-only maintenance, included after the ordinary scheduler helpers.
 * Uses their exact-port installation, worker, executor and APPLIED receipts.
 * No ordinary repair/fallback/family-negative state machine is entered. */
#include <limits.h>
void d2s_sched_optimize(d2s_sched *s,int enabled) { if(s)s->optimize=!!enabled; }

static d2s_cat_binding *minimize_source(d2s_sched *s,const task *t,
                                       d2s_cat_box **owner) {
    if(!s->cat)return NULL;
    for(size_t bi=0;bi<s->cat->n_boxes;bi++) {
        d2s_cat_box *b=&s->cat->boxes[bi];
        if(strcmp(b->id,t->min_box))continue;
        const d2s_cat_plan *p=plan_by_id(b,t->min_source);
        if(!p || !p->enabled || !p->text)return NULL;
        for(size_t j=0;j<b->n_binds;j++) {
            d2s_cat_binding *bd=&b->binds[j];
            if(strcmp(bd->target,t->name) || strcmp(bd->kind,"name") ||
               strcmp(bd->plan_id,t->min_source) || bd->transport!=6 ||
               (bd->family?bd->family:4)!=t->family || bd->shape!=record_shape(t) ||
               bd->tcp_profile!=t->trigger_tcp_profile)continue;
            if(!bd->enabled || bd->level<3 || bd->recheck_since ||
               bd->verified_by!=D2S_VERBY_PROBE || bd->budget!=D2S_CAT_BUDGET_PASSED)return NULL;
            if(t->min_confirmed && (bd->confirmed!=t->min_confirmed ||
               bd->successes!=t->min_successes))return NULL;
            if(owner)*owner=b;
            return bd;
        }
    }
    return NULL;
}

static int minimize_idle(const d2s_sched *s,const task *self) {
    if(!s->optimize || !res_valid(s) || s->limiter || !s->meas_limit)return 0;
    for(size_t i=0;i<SCHED_MAX_TASKS;i++) {
        const task *t=&s->tasks[i];
        if(t==self || t->state==T_FREE || t->state==T_RESTING)continue;
        if(t->min_active || t->state!=T_WATCHING)return 0;
    }
    return 1;
}

static void minimize_dispatch(d2s_sched *s) {
    if(!minimize_idle(s,NULL))return;
    if(s->measure_start_seen && s->now_ms-s->last_measure_start_ms<SCHED_START_GAP_MS)return;
    for(size_t i=0;i<SCHED_MAX_TASKS;i++) {
        task *t=&s->tasks[i];
        if(t->state!=T_WATCHING || !t->min_ready)continue;
        t->min_ready=0;
        d2s_cat_binding *bd=minimize_source(s,t,NULL);
        if(!bd)continue;
        t->min_active=1;t->min_cursor=t->min_next=0;t->min_passes=0;
        t->min_confirmed=bd->confirmed;t->min_successes=bd->successes;
        /* A minimizer never creates fallbacks, transfers recipes or spends
           an unrelated repair's counters. Original binding stays installed. */
        t->own_first=t->family_fast=t->owned_fallback=t->split_pending=0;
        t->fb_queue=t->partial_valid=t->arm_hash=0;
        memset(t->plan_recipe_valid,0,sizeof t->plan_recipe_valid);
        say(s,"по %s в свободное время проверяю упрощение плана; рабочий сохранён",t->name);
        return;
    }
}

static int minimize_stop(d2s_sched *s,task *t) {
    if(t->th_live) {
        pthread_mutex_lock(&s->mu);
        int ready=t->res_ready;t->stop=1;
        pthread_mutex_unlock(&s->mu);
        if(!ready)return 0; /* never block event loop waiting for a network */
        if(join_worker(t))return 0;
    }
    trial_retire(s,t); task_done(s,t); return 1;
}

static int minimize_applied(task *t) {
    if(t->ver_ok)return 1;
    d2s_ev ev={0};ev.family=t->ver_flow.family;ev.transport=t->ver_flow.transport;
    memcpy(ev.low_ip,t->ver_flow.a_ip,sizeof ev.low_ip);
    memcpy(ev.high_ip,t->ver_flow.b_ip,sizeof ev.high_ip);
    ev.low_port=t->ver_flow.a_port;ev.high_port=t->ver_flow.b_port;
    for(size_t k=0;k<t->ver_seen;k++)if(ev_matches_flow(&ev,&t->ver_early[k]))return 1;
    return 0;
}

/* Returns 1 only for a new fully proven binding. First pass is local state;
   no catalog change, no success claim, no inheritance of the old plan's score. */
static int minimize_proven(d2s_sched *s,task *t,int64_t now_ms) {
    if(!t->trial_installed || !minimize_source(s,t,NULL) || !minimize_applied(t) ||
       t->exec_nak || t->ver_unsent_seen || t->ver.local_limit ||
       s->dropped_seen!=t->ver_dropped0 || t->ver.level!=D2S_VER_APPLICATION ||
       !t->ver.body_complete || t->ver.name_ok!=1 ||
       t->ver.unsupported || t->ver.cloudflare_challenge ||
       t->ver.http_outcome==D2S_HTTP_BLOCKED || t->ver.http_outcome==D2S_HTTP_LEGAL_DENIAL ||
       t->ver.replay_proof || t->ver.handshake_proof ||
       t->ver.budget!=D2S_BUDGET_PASSED)return 0;
    t->ver_ok=1;
    if(!t->min_passes) {
        t->min_passes=1;t->min_first_ms=t->last_verify_ms;
        memcpy(t->min_first_trial,t->ver_plan_id,sizeof t->min_first_trial);
        trial_retire(s,t);ver_close(t);t->next_plan=0;t->state=T_PLANNING;
        return 0;
    }
    if(!memcmp(t->min_first_trial,t->ver_plan_id,sizeof t->min_first_trial))return 0;
    char id[40];uint8_t wire[D2S_PLAN_ID_LEN];
    plan_ident(t->plans[0],id,sizeof id,wire);
    if(bind_confirmed(s->cat,t->min_box,id,t->plans[0],"tls",t->name,"name",
        6,t->family,record_shape(t),t->trigger_tcp_profile,D2S_VERBY_PROBE,
        t->trig_snapped?D2S_INPUT_CLIENT:D2S_INPUT_PROFILE,wall_s(s,now_ms),NULL))return 0;
    /* Re-fetch after reallocations; source identity/generation must now change. */
    snprintf(t->min_source,sizeof t->min_source,"%s",id);t->min_confirmed=0;
    d2s_cat_box *b=NULL;
    for(size_t bi=0;bi<s->cat->n_boxes;bi++)if(!strcmp(s->cat->boxes[bi].id,t->min_box))b=&s->cat->boxes[bi];
    if(b)for(size_t j=0;j<b->n_binds;j++) {
        d2s_cat_binding *bd=&b->binds[j];
        if(!strcmp(bd->target,t->name) && !strcmp(bd->plan_id,id) &&
           bd->transport==6 && bd->family==t->family && bd->shape==record_shape(t) &&
           bd->tcp_profile==t->trigger_tcp_profile) {
            bd->successes=2;bd->budget=D2S_CAT_BUDGET_PASSED;
            t->min_confirmed=bd->confirmed;t->min_successes=bd->successes;
        }
    }
    plan_quality_record(s,t,1,now_ms);
    int64_t second=t->last_verify_ms;t->last_verify_ms=t->min_first_ms;
    plan_quality_record(s,t,1,now_ms);t->last_verify_ms=second;
    if(b)for(size_t i=0;i<b->n_plans;i++)if(!strcmp(b->plans[i].id,id) && b->plans[i].successes<INT_MAX)b->plans[i].successes++;
    s->cat->revision++;s->sync_pending=1;
    say(s,"по %s упрощённый план %s прошёл два полных независимых испытания; старый оставлен в каталоге",t->name,id);
    trial_retire(s,t);ver_close(t);
    t->min_cursor=0;t->min_passes=0;t->state=T_WATCHING;
    return 1;
}

static int minimize_tick(d2s_sched *s,task *t,int64_t now_ms) {
    if(t->exec_nak || !minimize_idle(s,t) || !minimize_source(s,t,NULL))return minimize_stop(s,t);
    if(t->state==T_WATCHING) {
        d2s_cat_box *b=NULL;
        if(!minimize_source(s,t,&b))return minimize_stop(s,t);
        const d2s_cat_plan *p=plan_by_id(b,t->min_source);
        char err[160];
        int rc=d2s_plan_simplify_next(p->text,t->min_cursor,t->plans[0],sizeof t->plans[0],&t->min_next,err,sizeof err);
        if(rc!=1)return minimize_stop(s,t);
        snprintf(t->plan_boxes[0],sizeof t->plan_boxes[0],"%s",t->min_box);
        t->n_plans=1;t->next_plan=0;t->min_passes=0;t->state=T_PLANNING;
    }
    if(t->state==T_PLANNING) {
        if(s->measure_start_seen && now_ms-s->last_measure_start_ms<SCHED_START_GAP_MS)return 0;
        t->probes=0;
        if(install_next(s,t))return minimize_stop(s,t);
        t->ver_seen=t->ver_ok=t->ver_unsent_seen=0;
        ver_close(t);memset(&t->ver,0,sizeof t->ver);t->ver.fd=-1;
        t->ver_dropped0=s->dropped_seen;
        t->trial_acked=0;t->trial_until_ms=now_ms+SCHED_TRIAL_SETTLE_MS;t->state=T_TRIAL_SETTLE;
        s->last_measure_start_ms=now_ms;s->measure_start_seen=1;
        return 1;
    }
    if(t->state==T_TRIAL_SETTLE) {
        if(!t->trial_acked && now_ms<t->trial_until_ms)return 0;
        t->exec_probed++;t->state=T_VERIFY;
        if(start_worker(s,t,JOB_VERIFY))return minimize_stop(s,t);
        return 1;
    }
    if(t->state==T_VERIFY) {
        pthread_mutex_lock(&s->mu);int ready=t->res_ready;pthread_mutex_unlock(&s->mu);
        if(!ready)return 0;
        if(join_worker(t))return 0;
        t->ver_flow.family=t->family;t->ver_flow.transport=6;
        memcpy(t->ver_flow.a_ip,t->family==6?t->ver.local_addr:t->ver.local_ip4,t->family==6?16:4);
        t->ver_flow.a_port=t->ver.local_port;t->ver_flow.b_port=t->port;
        inet_pton(t->family==6?AF_INET6:AF_INET,t->ip,t->ver_flow.b_ip);
        claim_early_refusal(t);t->state=T_VERIFY_WAIT;t->ver_until_ms=now_ms+SCHED_VERIFY_STEP_MS;
    }
    if(t->state==T_VERIFY_WAIT) {
        if(!minimize_applied(t) && now_ms<t->ver_until_ms)return 0;
        if(t->ver.level==D2S_VER_APPLICATION && t->ver.budget==D2S_BUDGET_PASSED &&
           t->ver.body_complete && t->ver.name_ok==1 && !t->ver.local_limit &&
           !t->exec_nak && !t->ver_unsent_seen && s->dropped_seen==t->ver_dropped0 &&
           minimize_applied(t)) {
            int passes=t->min_passes;
            if(minimize_proven(s,t,now_ms) || t->min_passes!=passes)return 1;
        }
        /* Unknown/local error pauses maintenance, never votes against a
           working plan. An attributed network miss only advances this edit. */
        if(!minimize_applied(t) || t->ver.local_limit || t->exec_nak || t->ver_unsent_seen ||
           s->dropped_seen!=t->ver_dropped0 || t->ver.level<D2S_VER_TRANSPORT ||
           t->ver.level==D2S_VER_CHALLENGE || t->ver.level==D2S_VER_DENIED ||
           t->ver.cloudflare_challenge || t->ver.unsupported)return minimize_stop(s,t);
        trial_retire(s,t);ver_close(t);t->min_cursor=t->min_next;t->state=T_WATCHING;
        return 1;
    }
    return 0;
}
