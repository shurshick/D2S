#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/d2s_groups.h"
#include "../runtime/d2s_protocol.h"
static int failed;
#define CHECK(c) do { if (!(c)) { fprintf(stderr,"groups:%d: %s\n",__LINE__,#c); failed++; } } while(0)
static d2s_group_key modern={6,4,1,"",""};
static void observe(d2s_group_state *s, const char *name, const char *plan,
                    unsigned evidence, d2s_group_key key) {
    d2s_group_observation o={0};
    snprintf(o.name,sizeof o.name,"%s",name);
    snprintf(o.plan_id,sizeof o.plan_id,"%s",plan);
    o.evidence=evidence; o.key=key; o.at=100;
    CHECK(d2s_group_learn(s,&o)>=0);
}
static int present(const d2s_group_state *s,const char *name) {
    for(size_t i=0;i<s->n_observations;i++)
        if(!strcmp(s->observations[i].name,name)) return 1;
    return 0;
}
int main(void) {
    d2s_group_key long_key;
    char path_a[512],path_b[512];
    memset(path_a,'a',sizeof path_a); path_a[0]='/'; path_a[300]=0;
    memcpy(path_b,path_a,sizeof path_b); path_b[299]='b';
    CHECK(d2s_group_key_make(&long_key,6,4,1,path_a,"")==-1);
    CHECK(d2s_group_key_make(&long_key,6,4,1,path_b,"")==-1);
    CHECK(d2s_group_key_make(&long_key,6,4,1,"/public/site.css","")==0 &&
          !strcmp(long_key.probe_path,"/public/site.css"));
    d2s_group_state *s=calloc(1,sizeof *s);
    CHECK(s!=NULL); if(!s) return 1;
    /* Counting requests rather than independent host evidence must fail. */
    for(int i=0;i<5;i++) observe(s,"meet.google.com","plan-a",1,modern);
    CHECK(s->n_groups==0 && s->n_observations==1);
    observe(s,"rr1.googlevideo.com","plan-a",1,modern);
    observe(s,"rr2.googlevideo.com","plan-a",1,modern);
    CHECK(!d2s_group_match(s,"rr-new.googlevideo.com",&modern));
    observe(s,"rr3.googlevideo.com","plan-a",1,modern);
    const d2s_domain_group *g=d2s_group_match(s,"rr-new.googlevideo.com",&modern);
    CHECK(g && !strcmp(g->suffix,"googlevideo.com") && !strcmp(g->plan_id,"plan-a"));
    CHECK(!d2s_group_match(s,"evilgooglevideo.com",&modern));
    CHECK(!d2s_group_match(s,"google.com",&modern));
    {
        d2s_group_key no_ts={6,4,D2S_TCP_SHAPE_MODERN_NO_TS,"",""};
        d2s_group_key with_ts={6,4,D2S_TCP_SHAPE_MODERN_TS,"",""};
        for(int i=0;i<3;i++) {
            char name[64];
            snprintf(name,sizeof name,"p%d.profile.example.com",i);
            observe(s,name,"profile-plan",D2S_GROUP_BLOCKED_CONFIRMED,no_ts);
            observe(s,name,"profile-plan",D2S_GROUP_BLOCKED_CONFIRMED,with_ts);
        }
        const d2s_domain_group *no_ts_group=d2s_group_match(s,"new.profile.example.com",&no_ts);
        const d2s_domain_group *with_ts_group=d2s_group_match(s,"new.profile.example.com",&with_ts);
        CHECK(no_ts_group && with_ts_group && no_ts_group->key.shape==no_ts.shape &&
              with_ts_group->key.shape==with_ts.shape);
        d2s_group_key unknown={6,4,1,"",""};
        CHECK(!d2s_group_match(s,"new.profile.example.com",&unknown));
    }
    {
        /* Поле 06.10: узел семейства, на котором не помог ни общий план, ни
           собственный поиск, — недоступен. Его отказы выкидываются целиком:
           домен снова под общим планом, голосов против плана нет. */
        d2s_group_state *d=calloc(1,sizeof *d);
        CHECK(d!=NULL);
        if(d) {
            observe(d,"rr1.googlevideo.com","plan-a",1,modern);
            observe(d,"rr2.googlevideo.com","plan-a",1,modern);
            observe(d,"rr3.googlevideo.com","plan-a",1,modern);
            observe(d,"rr4.googlevideo.com","plan-a",D2S_GROUP_PLAN_FAILED,modern);
            observe(d,"rr4.googlevideo.com","plan-b",D2S_GROUP_PLAN_FAILED,modern);
            CHECK(!d2s_group_match(d,"rr4.googlevideo.com",&modern));
            d2s_group_key quic={17,4,3,"",""};
            observe(d,"rr4.googlevideo.com","plan-q",D2S_GROUP_PLAN_FAILED,quic);
            CHECK(d2s_group_forget(d,"rr4.googlevideo.com",6,4)==2);
            CHECK(!present(d,"rr4.googlevideo.com") || d->n_observations==4);
            const d2s_domain_group *dg=d2s_group_match(d,"rr4.googlevideo.com",&modern);
            CHECK(dg && !strcmp(dg->plan_id,"plan-a"));
            CHECK(present(d,"rr1.googlevideo.com"));
            CHECK(d2s_group_forget(d,"rr4.googlevideo.com",6,4)==0);
            CHECK(d2s_group_forget(d,"rr1.googlevideo.com",6,4)==0);
            /* Отказ узла, который неделю больше не встречался, уходит сам:
               узлы googlevideo меняются, и на старый может больше не прийти
               никто. Подтверждения не стареют. */
            observe(d,"rr7.googlevideo.com","plan-a",D2S_GROUP_PLAN_FAILED,modern);
            observe(d,"rr8.googlevideo.com","plan-a",D2S_GROUP_PLAN_FAILED,modern);
            for(size_t i=0;i<d->n_observations;i++)
                if(!strcmp(d->observations[i].name,"rr8.googlevideo.com")) d->observations[i].at=100+6*86400;
            CHECK(!d2s_group_match(d,"rr7.googlevideo.com",&modern));
            CHECK(d2s_group_expire(d,100+7*86400,7*86400)==0);
            /* rr7 и оставшийся QUIC-отказ rr4 того же возраста; rr8 моложе. */
            CHECK(d2s_group_expire(d,101+7*86400,7*86400)==2);
            CHECK(!present(d,"rr7.googlevideo.com") && present(d,"rr8.googlevideo.com"));
            CHECK(present(d,"rr1.googlevideo.com"));
            CHECK(d2s_group_match(d,"rr7.googlevideo.com",&modern));
            free(d);
        }
    }
    size_t before=s->n_observations;
    for(int i=0;i<100;i++) CHECK(d2s_group_match(s,"a.b.new.googlevideo.com",&modern));
    CHECK(s->n_observations==before); /* Lookup does not enrol every CDN name. */
    d2s_group_key other=modern;
    other.family=6; CHECK(!d2s_group_match(s,"rr-new.googlevideo.com",&other));
    other=modern; other.shape=2; CHECK(!d2s_group_match(s,"rr-new.googlevideo.com",&other));
    other=modern; other.transport=17; other.shape=3;
    CHECK(!d2s_group_match(s,"rr-new.googlevideo.com",&other));
    other=modern; strcpy(other.probe_path,"/large.css");
    CHECK(!d2s_group_match(s,"rr-new.googlevideo.com",&other));
    other=modern; strcpy(other.ech_origin,"origin.example.com"); other.shape=6;
    CHECK(!d2s_group_match(s,"rr-new.googlevideo.com",&other));
    observe(s,"rr1.googlevideo.com","plan-a",8,modern);
    CHECK(d2s_group_match(s,"rr-new.googlevideo.com",&modern));
    observe(s,"rr1.googlevideo.com","plan-a",4,modern);
    CHECK(!d2s_group_match(s,"rr1.googlevideo.com",&modern));
    CHECK(d2s_group_match(s,"rr-new.googlevideo.com",&modern));
    /* A clean sibling prevents broadening, but allows the nested CDN branch. */
    observe(s,"www.example.com","",2,modern);
    observe(s,"a.cdn.example.com","plan-b",1,modern);
    observe(s,"b.cdn.example.com","plan-b",1,modern);
    observe(s,"c.cdn.example.com","plan-b",1,modern);
    g=d2s_group_match(s,"new.cdn.example.com",&modern);
    CHECK(g && !strcmp(g->suffix,"cdn.example.com"));
    CHECK(!d2s_group_match(s,"api.example.com",&modern));
    CHECK(!d2s_group_match(s,"www.example.com",&modern));
    /* Independent hosting tenants must never collapse at github.io. */
    observe(s,"a.github.io","plan-c",1,modern);
    observe(s,"b.github.io","plan-c",1,modern);
    observe(s,"c.github.io","plan-c",1,modern);
    CHECK(!d2s_group_match(s,"new.github.io",&modern));
    /* A different successful plan is not a vote for the elected candidate. */
    observe(s,"a.mixed.net","plan-a",1,modern);
    observe(s,"b.mixed.net","plan-b",1,modern);
    observe(s,"c.mixed.net","plan-c",1,modern);
    CHECK(!d2s_group_match(s,"new.mixed.net",&modern));
    /* A measured failure must outweigh a one-vote popularity advantage. */
    observe(s,"a.recovery.net","plan-a",1,modern);
    observe(s,"b.recovery.net","plan-a",1,modern);
    observe(s,"c.recovery.net","plan-a",1,modern);
    observe(s,"d.recovery.net","plan-a",1,modern);
    observe(s,"e.recovery.net","plan-b",1,modern);
    observe(s,"f.recovery.net","plan-b",1,modern);
    observe(s,"g.recovery.net","plan-b",1,modern);
    g=d2s_group_match(s,"new.recovery.net",&modern);
    CHECK(g && !strcmp(g->plan_id,"plan-a"));
    observe(s,"failed.recovery.net","plan-a",4,modern);
    g=d2s_group_match(s,"new.recovery.net",&modern);
    CHECK(g && !strcmp(g->plan_id,"plan-b"));
    CHECK(d2s_group_restore(s)==0);
    g=d2s_group_match(s,"new.recovery.net",&modern);
    CHECK(g && !strcmp(g->plan_id,"plan-b"));
    observe(s,"failed.recovery.net","plan-b",4,modern);
    unsigned failed_plans=0;
    for(size_t i=0;i<s->n_observations;i++)
        if(!strcmp(s->observations[i].name,"failed.recovery.net") &&
           (s->observations[i].evidence&D2S_GROUP_PLAN_FAILED)) failed_plans++;
    CHECK(failed_plans==2);
    CHECK(d2s_group_restore(s)==0);
    observe(s,"failed.recovery.net","plan-b",1,modern);
    CHECK(d2s_group_restore(s)==0);
    observe(s,"failed.recovery.net","plan-a",1,modern);
    CHECK(d2s_group_restore(s)==0);
    /* A proven clean member becomes an exception, not a family-wide outage. */
    observe(s,"clean.googlevideo.com","",2,modern);
    CHECK(d2s_group_match(s,"rr-new.googlevideo.com",&modern));
    CHECK(!d2s_group_match(s,"clean.googlevideo.com",&modern));
    observe(s,"clean.googlevideo.com","",2,modern);
    CHECK(d2s_group_match(s,"rr-new.googlevideo.com",&modern));
    observe(s,"clean.googlevideo.com","plan-a",1,modern);
    CHECK(d2s_group_match(s,"rr-new.googlevideo.com",&modern));
    d2s_group_observation invalid={0};
    strcpy(invalid.name,"a.example.com"); invalid.key=modern;
    invalid.evidence=1;
    CHECK(d2s_group_learn(s,&invalid)==-1); /* no authenticated plan */
    strcpy(invalid.plan_id,"plan-a");
    invalid.key.shape=255;
    CHECK(d2s_group_learn(s,&invalid)==-1);
    invalid.key=modern; invalid.key.transport=17;
    CHECK(d2s_group_learn(s,&invalid)==-1);
    invalid.key=modern;
    memset(invalid.name,'x',sizeof invalid.name);
    CHECK(d2s_group_learn(s,&invalid)==-1); /* no NUL */
    /* §3.7: an exception keeps the family only while live voters outnumber
       degraded ones; rr1 already failed, rr2/rr3 turn clear below. */
    observe(s,"rr4.googlevideo.com","plan-a",1,modern);
    observe(s,"rr5.googlevideo.com","plan-a",1,modern);
    observe(s,"rr6.googlevideo.com","plan-a",1,modern);
    /* Both quotas simultaneously full: no cross-journal eviction. */
    memset(s,0,sizeof *s);
    for(unsigned i=0;i<256;i++) {
        char n[128];snprintf(n,sizeof n,"clear.n%u.com",i);observe(s,n,"",2,modern);
        snprintf(n,sizeof n,"p%u.video.example.org",i);observe(s,n,"P",1,modern);
    }
    CHECK(s->n_observations==512);
    for(unsigned i=256;i<300;i++) {
        char n[128];snprintf(n,sizeof n,"p%u.video.example.org",i);observe(s,n,"P",1,modern);
        CHECK(present(s,n) && s->n_observations==512);
    }
    for(unsigned i=0;i<256;i++) {
        char n[128];snprintf(n,sizeof n,"clear.n%u.com",i);CHECK(present(s,n));
    }
    observe(s,"new.other.net","",2,modern);
    CHECK(!s->disabled && !s->frozen);
    for(unsigned i=0;i<256;i++) {
        char n[128];snprintf(n,sizeof n,"clear.n%u.com",i);CHECK(!d2s_group_match(s,n,&modern));
    }
    CHECK(d2s_group_match(s,"fresh.video.example.org",&modern));
    /* Independent budgets: negatives never consume positive admission. */
    memset(s,0,sizeof *s);
    for(unsigned i=0;i<2000;i++) {
        char name[128];snprintf(name,sizeof name,"clear%u.n%u.example.net",i,i);
        observe(s,name,"",2,modern);
        snprintf(name,sizeof name,"cdn%u.video.example.org",i);observe(s,name,"P",1,modern);
        size_t pos=0,neg=0;
        for(size_t j=0;j<s->n_observations;j++) {
            if(s->observations[j].evidence&(2|4|32))neg++;else pos++;
        }
        CHECK(pos<=D2S_GROUP_POSITIVE_MAX && neg<=D2S_GROUP_NEGATIVE_MAX);
        CHECK(present(s,name) && !s->frozen && !s->disabled);
        CHECK(!d2s_group_match(s,"clear0.n0.example.net",&modern));
        if(i%97==0)CHECK(d2s_group_restore(s)==0);
    }
    CHECK(d2s_group_match(s,"fresh.video.example.org",&modern));
    CHECK(d2s_group_restore(s)==0);
    /* A suffix barrier also prohibits parent groups and cannot be overwritten
       by a positive observation with the same text key. */
    observe(s,"example.net","P",1,modern);
    CHECK(!d2s_group_match(s,"clear0.n0.example.net",&modern));
    /* Independent key contexts remain independent after compaction. */
    d2s_group_key ipv6=modern;ipv6.family=6;
    observe(s,"a.other.example.net","P",1,ipv6);
    observe(s,"b.other.example.net","P",1,ipv6);
    observe(s,"c.other.example.net","P",1,ipv6);
    CHECK(d2s_group_match(s,"new.other.example.net",&ipv6));
    CHECK(!d2s_group_match(s,"new.other.example.net",&modern));
    /* No common suffix/context pair: coarse denial survives restore; positive
       evidence is still recorded without promoting the prohibited context. */
    memset(s,0,sizeof *s);
    for(unsigned i=0;i<300;i++) {
        d2s_group_observation ev={0};
        snprintf(ev.name,sizeof ev.name,"n%u.example.net",i);
        ev.key=modern;snprintf(ev.key.probe_path,sizeof ev.key.probe_path,"/p%u",i);
        ev.evidence=2;ev.at=i;CHECK(d2s_group_learn(s,&ev)>=0);
    }
    CHECK(s->blocked_contexts && !s->disabled && !s->frozen);
    observe(s,"new.video.example.org","P",1,modern);
    CHECK(present(s,"new.video.example.org"));
    CHECK(d2s_group_restore(s)==0 && s->blocked_contexts);
    CHECK(!d2s_group_match(s,"next.video.example.org",&modern));
    /* Long deterministic stream, many names and independent IPv4/IPv6,
       Timestamp and path contexts. Every historic negative remains excluded. */
    memset(s,0,sizeof *s);
    for(unsigned i=0;i<5000;i++) {
        d2s_group_observation ev={0};ev.key=modern;
        ev.key.family=(i&1)?4:6;ev.key.shape=(i&2)?D2S_TCP_SHAPE_MODERN_TS:1;
        strcpy(ev.key.probe_path,(i&4)?"/resource":"/");ev.at=10000+i;
        snprintf(ev.name,sizeof ev.name,"blocked.d%u.com",i);ev.evidence=2;
        CHECK(d2s_group_learn(s,&ev)>=0);
        snprintf(ev.name,sizeof ev.name,"cdn%u.video.example.org",i);ev.evidence=1;
        strcpy(ev.plan_id,"P");CHECK(d2s_group_learn(s,&ev)>0);
        CHECK(present(s,ev.name) && !s->frozen && !s->disabled);
        if(i%500==0)CHECK(d2s_group_restore(s)==0);
    }
    for(unsigned i=0;i<5000;i++) {
        char name[128];d2s_group_key k=modern;
        k.family=(i&1)?4:6;k.shape=(i&2)?D2S_TCP_SHAPE_MODERN_TS:1;
        strcpy(k.probe_path,(i&4)?"/resource":"/");
        snprintf(name,sizeof name,"blocked.d%u.com",i);
        CHECK(!d2s_group_match(s,name,&k));
        CHECK(d2s_group_match(s,"new.video.example.org",&k));
    }
    /* Reaching the area cap cannot stop evidence admission on restore. */
    memset(s,0,sizeof *s);
    for(unsigned i=0;i<100;i++)for(unsigned j=0;j<3;j++) {
        char name[128],plan[40];
        snprintf(name,sizeof name,"h%u.family%u.example.org",j,i);
        snprintf(plan,sizeof plan,"P%u",i);observe(s,name,plan,1,modern);
    }
    CHECK(s->n_groups<=D2S_GROUP_MAX && !s->frozen);
    CHECK(d2s_group_restore(s)==0 && !s->frozen);
    /* (c) property: random learn chains always pass restore. */
    srand(7);
    for(int round=0;round<2000;round++) {
        memset(s,0,sizeof *s);
        const char *names[]={"a.example.com","b.example.com","c.example.com","d.example.com"};
        const char *plans[]={"P","Q",""};
        static const unsigned ev[]={1,2,4,8};
        for(int k=0;k<12;k++) {
            unsigned e=ev[rand()%4]; const char *p=plans[rand()%3];
            if((e==1||e==4)&&!p[0]) p="P";
            observe(s,names[rand()%4],p,e,modern);
        }
        if(d2s_group_restore(s)!=0) { CHECK(0); break; }
    }
    free(s);
    if(!failed) puts("groups: passed");
    return failed?1:0;
}
