/* Scheduler deadlines on a quiet controller: no network or wall-clock sleeps. */
#include "sched.c"

static int fails;
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"timer:%d: %s\n",__LINE__,#x); fails++; } } while (0)
int main(void) {
    d2s_catalog cat={0};
    d2s_sched *s=d2s_sched_new(&cat,-1,0x2d);
    CHECK(s!=NULL); if(!s)return 1;
    s->clock_seen=1; s->now_ms=1000; s->cpu_tried=1; s->cpu_try_ms=1000;
    s->meas_limit=2;
    CHECK(d2s_sched_wait_ms(s,1000,3000)==3000); /* idle does not busy-poll */
    task *t=&s->tasks[0];
    t->state=T_TRIAL_SETTLE; t->trial_until_ms=1050;
    CHECK(d2s_sched_wait_ms(s,1000,3000)==50);
    CHECK(d2s_sched_wait_ms(s,1050,3000)==0);
    t->trial_acked=1;
    CHECK(d2s_sched_wait_ms(s,1000,3000)==0);
    t->trial_acked=0; t->state=T_VERIFY_WAIT; t->ver_until_ms=1500;
    CHECK(d2s_sched_wait_ms(s,1000,3000)==500);
    t->state=T_QUEUED; s->measure_start_seen=1; s->last_measure_start_ms=1000;
    CHECK(d2s_sched_wait_ms(s,1000,3000)==250);
    CHECK(d2s_sched_wait_ms(s,1249,3000)==1);
    CHECK(d2s_sched_wait_ms(s,1250,3000)==0);
    /* Capacity must not be bypassed, nor an occupied queue cause a spin. */
    s->meas_limit=1; s->tasks[1].state=T_ASKING;
    CHECK(d2s_sched_wait_ms(s,1250,3000)==750);
    s->tasks[1].state=T_FREE; t->state=T_PLANNING; t->rx_retry_after_ms=1500;
    CHECK(d2s_sched_wait_ms(s,1000,3000)==500);
    t->rx_retry_after_ms=0;
    CHECK(d2s_sched_wait_ms(s,1000,3000)>0); /* allocation/send refusal cannot spin */
    t->state=T_FREE;
    CHECK(d2s_sched_wait_ms(s,5000,3000)==3000);
    CHECK(d2s_sched_wait_ms(s,5000,0)==0);
    d2s_sched_free(s); d2s_catalog_free(&cat);
    return fails?1:0;
}
