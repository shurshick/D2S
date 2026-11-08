#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "include/d2s_catalog.h"
#include "include/d2s_groups.h"
static int failed;
#define CHECK(c) do { if(!(c)) { fprintf(stderr,"group-catalog:%d: %s\n",__LINE__,#c); failed++; } } while(0)
int main(void) {
    char path[]="/tmp/d2s-groups-catalog-XXXXXX",err[256];
    int fd=mkstemp(path); CHECK(fd>=0); if(fd<0) return 1; close(fd);
    d2s_catalog a={0},b={0};
    a.groups=calloc(1,sizeof *a.groups);
    CHECK(a.groups!=NULL); if(!a.groups) { unlink(path); return 1; }
    a.boxes=calloc(1,sizeof *a.boxes); a.n_boxes=1;
    CHECK(a.boxes!=NULL); if(!a.boxes) { d2s_catalog_free(&a); unlink(path); return 1; }
    strcpy(a.boxes[0].id,"box-test");
    a.boxes[0].plans=calloc(1,sizeof *a.boxes[0].plans); a.boxes[0].n_plans=1;
    CHECK(a.boxes[0].plans!=NULL); if(!a.boxes[0].plans) { a.boxes[0].n_plans=0; d2s_catalog_free(&a); unlink(path); return 1; }
    strcpy(a.boxes[0].plans[0].id,"plan-test");
    strcpy(a.boxes[0].plans[0].proto,"tls");
    a.boxes[0].plans[0].text=strdup("opaque-test-plan");
    a.boxes[0].plans[0].enabled=1;
    d2s_group_key key={6,4,1,"",""};
    /* §3.7: five voters, so the two exceptions below (rr0 failed, rr1
       clear) stay a minority and the family legitimately survives. */
    for(int i=0;i<5;i++) {
        d2s_group_observation o={0};
        snprintf(o.name,sizeof o.name,"rr%d.googlevideo.com",i);
        strcpy(o.plan_id,"plan-test"); o.key=key; o.evidence=1; o.at=123;
        CHECK(d2s_group_learn(a.groups,&o)==1);
    }
    d2s_group_observation o=a.groups->observations[0]; o.evidence=4; o.at=124;
    CHECK(d2s_group_learn(a.groups,&o)==1);
    CHECK(d2s_catalog_save(&a,path,err,sizeof err)==0);
    CHECK(d2s_catalog_load(path,&b,err,sizeof err)==0);
    CHECK(b.groups && b.groups->n_observations==5 && b.groups->n_groups==1);
    CHECK(b.groups && d2s_group_match(b.groups,"new.googlevideo.com",&key));
    CHECK(b.groups && !d2s_group_match(b.groups,"rr0.googlevideo.com",&key));
    CHECK(b.n_boxes==1 && b.boxes[0].n_plans==1);
    d2s_catalog_free(&b);
    memset(&o,0,sizeof o); strcpy(o.name,"clean.googlevideo.com");
    o.key=key; o.evidence=2; o.at=125;
    CHECK(d2s_group_learn(a.groups,&o)==1);
    CHECK(d2s_catalog_save(&a,path,err,sizeof err)==0);
    CHECK(d2s_catalog_load(path,&b,err,sizeof err)==0);
    CHECK(b.groups && d2s_group_match(b.groups,"new.googlevideo.com",&key));
    CHECK(b.groups && !d2s_group_match(b.groups,"clean.googlevideo.com",&key));
    d2s_catalog_free(&b);
    o=a.groups->observations[1]; o.evidence=2; o.at=126;
    CHECK(d2s_group_learn(a.groups,&o)==1);
    CHECK(d2s_catalog_save(&a,path,err,sizeof err)==0);
    CHECK(d2s_catalog_load(path,&b,err,sizeof err)==0);
    CHECK(b.groups && d2s_group_match(b.groups,"new.googlevideo.com",&key));
    CHECK(b.groups && !d2s_group_match(b.groups,"rr1.googlevideo.com",&key));
    d2s_catalog_free(&b);
    a.groups->frozen=1;
    CHECK(d2s_catalog_save(&a,path,err,sizeof err)==0);
    CHECK(d2s_catalog_load(path,&b,err,sizeof err)==0 && b.groups && !b.groups->frozen);
    CHECK(b.groups && d2s_group_match(b.groups,"never-seen.googlevideo.com",&key));
    d2s_catalog_free(&b);
    /* §3.7: a third degraded voter makes them the majority → retired,
       also after save/load. */
    memset(&o,0,sizeof o); strcpy(o.name,"rr2.googlevideo.com");
    o.key=key; o.evidence=2; o.at=127;
    CHECK(d2s_group_learn(a.groups,&o)==1);
    CHECK(!d2s_group_match(a.groups,"new.googlevideo.com",&key));
    CHECK(d2s_catalog_save(&a,path,err,sizeof err)==0);
    CHECK(d2s_catalog_load(path,&b,err,sizeof err)==0);
    CHECK(b.groups && b.groups->n_groups==0 &&
          !d2s_group_match(b.groups,"new.googlevideo.com",&key));
    d2s_catalog_free(&b);
    /* Disabled without a stored moment (older catalogs) loads as 0. */
    a.groups->disabled=1;
    CHECK(d2s_catalog_save(&a,path,err,sizeof err)==0);
    CHECK(d2s_catalog_load(path,&b,err,sizeof err)==0);
    CHECK(b.groups && !b.groups->disabled && b.groups->blocked_contexts && b.groups->disabled_at==0);
    d2s_catalog_free(&b);
    a.groups->disabled_at=1700000000;
    CHECK(d2s_catalog_save(&a,path,err,sizeof err)==0);
    CHECK(d2s_catalog_load(path,&b,err,sizeof err)==0);
    CHECK(b.groups && b.groups->disabled_at==1700000000);
    CHECK(b.groups && !b.groups->disabled && b.groups->blocked_contexts && b.groups->n_groups==0);
    CHECK(b.n_boxes==1 && b.boxes[0].n_plans==1 && b.boxes[0].plans[0].enabled);
    d2s_catalog_free(&b);
    a.groups->disabled=0;
    a.boxes[0].plans[0].enabled=0;
    CHECK(d2s_catalog_save(&a,path,err,sizeof err)==0);
    CHECK(d2s_catalog_load(path,&b,err,sizeof err)==0);
    CHECK(b.groups && !d2s_group_match(b.groups,"new.googlevideo.com",&key));
    d2s_catalog_free(&b);
    /* A saved capacity stop is recoverable without wiping exact plans or
       any exclusions; new evidence stays learnable across another reload. */
    a.boxes[0].plans[0].enabled=1;
    memset(a.groups,0,sizeof *a.groups);
    a.groups->frozen=1;a.groups->n_observations=D2S_GROUP_NEGATIVE_MAX;
    for(size_t i=0;i<D2S_GROUP_NEGATIVE_MAX;i++) {
        d2s_group_observation *v=&a.groups->observations[i];
        snprintf(v->name,sizeof v->name,"old%zu.example.net",i);
        v->key=key;v->at=1;
        v->evidence=i<227?D2S_GROUP_DIRECT_CLEAR:D2S_GROUP_BLOCKED_CONFIRMED;
        if(i>=227)strcpy(v->plan_id,"plan-test");
    }
    CHECK(d2s_catalog_save(&a,path,err,sizeof err)==0);
    CHECK(d2s_catalog_load(path,&b,err,sizeof err)==0);
    CHECK(b.groups && !b.groups->frozen && b.groups->n_observations==D2S_GROUP_NEGATIVE_MAX);
    for(int i=0;i<3;i++) {
        d2s_group_observation fresh={0};
        snprintf(fresh.name,sizeof fresh.name,"cdn%d.video.example.org",i);
        strcpy(fresh.plan_id,"plan-test");fresh.key=key;fresh.at=200+i;
        fresh.evidence=D2S_GROUP_BLOCKED_CONFIRMED;
        CHECK(d2s_group_learn(b.groups,&fresh)>0);
    }
    CHECK(d2s_group_match(b.groups,"next.video.example.org",&key));
    CHECK(d2s_catalog_save(&b,path,err,sizeof err)==0);
    d2s_catalog_free(&b);
    CHECK(d2s_catalog_load(path,&b,err,sizeof err)==0);
    CHECK(b.groups && !b.groups->frozen && d2s_group_match(b.groups,"next.video.example.org",&key));
    CHECK(b.n_boxes==1 && b.boxes[0].n_plans==1 && b.boxes[0].plans[0].enabled);
    if(b.groups) {
        size_t clear=0;
        for(size_t i=0;i<b.groups->n_observations;i++)clear+=b.groups->observations[i].evidence==D2S_GROUP_DIRECT_CLEAR;
        CHECK(clear==227);
        for(int i=0;i<600;i++) {
            d2s_group_observation fresh={0};
            snprintf(fresh.name,sizeof fresh.name,"clear%d.scope%d.example.net",i,i);
            fresh.key=key;fresh.evidence=2;fresh.at=2000+i;
            CHECK(d2s_group_learn(b.groups,&fresh)>=0);
        }
        CHECK(d2s_catalog_save(&b,path,err,sizeof err)==0);
        uint64_t mask=b.groups->blocked_contexts;
        d2s_catalog_free(&b);
        CHECK(d2s_catalog_load(path,&b,err,sizeof err)==0);
        CHECK(b.groups && b.groups->blocked_contexts==mask && !b.groups->disabled);
        CHECK(!d2s_group_match(b.groups,"clear0.scope0.example.net",&key));
        CHECK(d2s_group_match(b.groups,"next.video.example.org",&key));
    }
    d2s_catalog_free(&a); d2s_catalog_free(&b);
    FILE *f=fopen(path,"w"); CHECK(f!=NULL);
    if(f) { fputs("{\"boxes\":[],\"domain_observations\":[{\"name\":\"a.example.com\",\"evidence\":255}]}",f); fclose(f); }
    CHECK(d2s_catalog_load(path,&b,err,sizeof err)!=0);
    d2s_catalog_free(&b);
    f=fopen(path,"w"); CHECK(f!=NULL);
    if(f) {
        fputs("{\"boxes\":[],\"domain_observations\":[",f);
        for(int i=0;i<=D2S_GROUP_OBSERVATION_MAX;i++) {
            if(i) fputc(',',f);
            fprintf(f,"{\"name\":\"h%d.example.com\",\"transport\":6,\"family\":4,\"shape\":1,\"evidence\":2}",i);
        }
        fputs("]}",f); fclose(f);
    }
    CHECK(d2s_catalog_load(path,&b,err,sizeof err)!=0);
    d2s_catalog_free(&b);
    f=fopen(path,"w"); CHECK(f!=NULL);
    if(f) { fputs("{\"boxes\":[],\"domain_groups\":[{\"suffix\":\"google.com\",\"plan_id\":\"forged\"}]}",f); fclose(f); }
    CHECK(d2s_catalog_load(path,&b,err,sizeof err)==0 && !b.groups);
    d2s_catalog_free(&b); /* derived snapshot cannot create an executable rule */
    f=fopen(path,"w"); CHECK(f!=NULL);
    if(f) { fputs("{\"boxes\":[]}",f); fclose(f); }
    CHECK(d2s_catalog_load(path,&b,err,sizeof err)==0 && !b.groups);
    d2s_catalog_free(&b); unlink(path);
    if(!failed) puts("group catalog: passed");
    return failed?1:0;
}
