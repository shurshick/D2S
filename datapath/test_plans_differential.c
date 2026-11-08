/* Deterministic production lookup trace. The driver compares old/new stdout.
 * Assertions cover priority/lifecycle directly; random traces compare IDs,
 * trial ownership, generation, shape misses and compact-table occupancy. */
#include <assert.h>
#include <stdio.h>
#ifndef D2S_BENCH_SOURCE
#define D2S_BENCH_SOURCE "plans.c"
#endif
#include D2S_BENCH_SOURCE
static d2s_plan *make_plan(void) {
    static const uint8_t data[]={'D','2','S','P',0,1,0,1,0,0,0,1,1,3,0,1,0};
    d2s_plan *p=NULL;char err[100];assert(!d2s_plan_load(data,sizeof data,&p,err,sizeof err));return p;
}
static d2s_plan *install(d2s_plantab *t,const char *n,uint8_t family,uint8_t shape,uint16_t port,uint64_t now) {
    d2s_plan *p=make_plan();assert(!d2s_plantab_set_name_family(t,(const uint8_t *)n,strlen(n),now,p,shape,port,family));return p;
}
static const d2s_plan *get(d2s_plantab *t,const char *n,uint8_t family,uint8_t shape,uint16_t port,uint64_t now) {
    return d2s_plantab_find_target(t,(const uint8_t *)n,n?strlen(n):0,NULL,family,now,shape,port);
}
static void checks(void) {
    d2s_plantab *t=d2s_plantab_new(32);assert(t);
    const char *a="c740766d21d73.test",*b="c0d5dbf0fc04e.test";
#ifdef D2S_PLANS_HAS_HASH
    assert(name_hash((const uint8_t *)a,strlen(a))==name_hash((const uint8_t *)b,strlen(b)));
#endif
    d2s_plan *pa=install(t,a,4,D2S_PLAN_SHAPE_MODERN,0,1);
    d2s_plan *pb=install(t,b,4,D2S_PLAN_SHAPE_MODERN,0,2);
    assert(get(t,a,4,D2S_PLAN_SHAPE_MODERN,0,3)==pa);
    assert(get(t,b,4,D2S_PLAN_SHAPE_MODERN,0,4)==pb);
    assert(get(t,"C740766D21D73.TEST",4,D2S_PLAN_SHAPE_MODERN,0,5)==pa);
    assert(!get(t,"c740766d21d74.test",4,D2S_PLAN_SHAPE_MODERN,0,6));
    d2s_plan *p6=install(t,a,6,D2S_PLAN_SHAPE_MODERN,0,7);
    assert(get(t,a,6,D2S_PLAN_SHAPE_MODERN,0,8)==p6);
    assert(get(t,a,4,D2S_PLAN_SHAPE_MODERN,0,9)==pa);
    d2s_plan *ts=install(t,"ts.test",4,D2S_PLAN_SHAPE_MODERN_TS,0,10);
    assert(get(t,"ts.test",4,D2S_PLAN_SHAPE_MODERN_TS,0,11)==ts);
    assert(!get(t,"ts.test",4,D2S_PLAN_SHAPE_MODERN_NO_TS,0,12));
    uint8_t token[16]={9};d2s_plan *trial=make_plan();
    assert(!d2s_plantab_set_name_trial(t,(const uint8_t *)a,strlen(a),13,trial,D2S_PLAN_SHAPE_MODERN,7001,4,token));
    assert(get(t,a,4,D2S_PLAN_SHAPE_MODERN,7001,14)==trial);
    assert(get(t,a,4,D2S_PLAN_SHAPE_MODERN,7002,15)==pa);
    d2s_plantab_clear_probes(t);assert(get(t,a,4,D2S_PLAN_SHAPE_MODERN,7001,16)==pa);
    assert(!d2s_plantab_set_suffix_family(t,(const uint8_t *)"test",4,17,make_plan(),D2S_PLAN_SHAPE_MODERN,4));
    assert(!d2s_plantab_set_bypass_family(t,(const uint8_t *)a,strlen(a),6,D2S_PLAN_SHAPE_MODERN,4));
    assert(get(t,a,4,D2S_PLAN_SHAPE_MODERN,0,18)==pa); /* exact beats bypass */
    assert(!d2s_plantab_set_bypass_family(t,(const uint8_t *)"excluded.test",13,6,D2S_PLAN_SHAPE_MODERN,4));
    assert(!get(t,"excluded.test",4,D2S_PLAN_SHAPE_MODERN,0,19));
    assert(get(t,"member.test",4,D2S_PLAN_SHAPE_MODERN,0,20));
    d2s_plantab_free(t);
    /* Compaction, LRU and replacement must preserve the per-name filter. */
    t=d2s_plantab_new(2);assert(t);
    pa=install(t,a,4,D2S_PLAN_SHAPE_MODERN,0,1);
    install(t,b,4,D2S_PLAN_SHAPE_MODERN,0,2);
    assert(get(t,a,4,D2S_PLAN_SHAPE_MODERN,0,3)==pa);
    install(t,"replacement.test",4,D2S_PLAN_SHAPE_MODERN,0,4);
    assert(!get(t,b,4,D2S_PLAN_SHAPE_MODERN,0,5));
    assert(get(t,a,4,D2S_PLAN_SHAPE_MODERN,0,6)==pa);
    uint64_t generation=pa->binding_generation;
    pa=install(t,a,4,D2S_PLAN_SHAPE_MODERN,0,7);
    assert(pa->binding_generation!=generation && get(t,a,4,D2S_PLAN_SHAPE_MODERN,0,8)==pa);
    assert(d2s_plantab_del_name_family(t,(const uint8_t *)a,strlen(a),4));
    assert(!get(t,a,4,D2S_PLAN_SHAPE_MODERN,0,9));
    d2s_plantab_free(t);
    /* Expiration belongs to flow probes, not confirmed permanent bindings. */
    t=d2s_plantab_new(4);assert(t);
    static const uint8_t udp[]={'D','2','S','P',0,1,0,11,0,0,0,2,0,2,0,2,17,2,1,16,0,1,1};
    d2s_addr_probe_flow flow={.family=4,.transport=17,.src_ip4={10,0,0,2},.dst_ip4={10,0,0,3},.src_port_be=1234,.dst_port_be=443};
    d2s_plan *p=NULL;char err[100];uint8_t out[16]={0};
    assert(!d2s_plan_load(udp,sizeof udp,&p,err,sizeof err));
    assert(!d2s_plantab_set_addr_probe(t,&flow,token,1,10,p));
    assert(d2s_plantab_find_addr_probe(t,&flow,9,out)==p && !memcmp(out,token,16));
    assert(!d2s_plantab_find_addr_probe(t,&flow,10,out));
    assert(!d2s_plan_load(udp,sizeof udp,&p,err,sizeof err));
    assert(!d2s_plantab_set_addr_probe(t,&flow,token,11,30,p));
    assert(d2s_plantab_del_addr_probe(t,&flow,token));
    assert(!d2s_plantab_find_addr_probe(t,&flow,12,out));
    d2s_plantab_free(t);
}
static uint32_t state=0x6d2b79f5;
static uint32_t random32(void) { state^=state<<13;state^=state>>17;state^=state<<5;return state; }
int main(void) {
    checks();
    uint8_t shapes[]={D2S_PLAN_SHAPE_MODERN,D2S_PLAN_SHAPE_LEGACY,D2S_PLAN_SHAPE_QUIC,
        D2S_PLAN_SHAPE_MODERN_TS,D2S_PLAN_SHAPE_MODERN_NO_TS,D2S_PLAN_SHAPE_ECH_TCP,
        D2S_PLAN_SHAPE_GRANDFATHER,D2S_PLAN_SHAPE_ANY};
    size_t capacities[]={32,128,256,512,1024,2048};
    for(size_t c=0;c<sizeof capacities/sizeof capacities[0];c++) {
        size_t cap=capacities[c];d2s_plantab *t=d2s_plantab_new(cap);assert(t);
        for(uint64_t step=1;step<=6000;step++) {
            uint32_t r=random32(),key=(r>>3)%3072;
            uint8_t family=r&1?4:6,shape=shapes[(r>>1)%7];
            uint16_t port=r%5?0:(uint16_t)(5000+key%7);
            char name[80];snprintf(name,sizeof name,"same-prefix-%04u.scope.test",key);
            uint8_t ip[16]={10,0,(uint8_t)(key>>8),(uint8_t)key};ip[15]=(uint8_t)key;
            switch(r%9) {
              case 0:case 1:case 2: install(t,name,family,shape,port,step);break;
              case 3:d2s_plantab_del_name_family(t,(const uint8_t *)name,strlen(name),family);break;
              case 4:assert(!d2s_plantab_set_addr_shaped(t,ip,family,step,make_plan(),shape));break;
              case 5:d2s_plantab_del_addr_shaped(t,ip,family,shape);break;
              case 6:if(step%17==0)d2s_plantab_clear_probes(t);break;
              case 7:assert(!d2s_plantab_set_suffix_family(t,(const uint8_t *)"scope.test",10,step,make_plan(),D2S_PLAN_SHAPE_MODERN,family));break;
              case 8:if(!shape_transport(shape))break;
                assert(!d2s_plantab_set_bypass_family(t,(const uint8_t *)name,strlen(name),shape_transport(shape),shape,family));
                /* Bypass storage is bounded: remove each temporary test exclusion. */
                assert(d2s_plantab_del_bypass_family(t,(const uint8_t *)name,strlen(name),shape_transport(shape),shape,family));break;
            }
            for(int variant=0;variant<4;variant++) {
                uint8_t seen=variant?shapes[random32()%8]:shape;
                const d2s_plan *p=d2s_plantab_find_target(t,variant==3?NULL:(const uint8_t *)name,
                    variant==3?0:strlen(name),ip,family,step+10000,seen,variant==2?(uint16_t)(port+1):port);
                uint8_t trial[16]={0};d2s_plantab_trial(t,p,trial);
                printf("%zu %llu %d %llu %u %u %u %u %u %zu %zu ",cap,(unsigned long long)step,variant,
                    p?(unsigned long long)p->binding_generation:0,p?p->binding_kind:0,p?p->binding_family:0,
                    p?p->binding_shape:0,p?p->binding_temporary:0,trial[0],t->used,t->shape_misses);
                const uint8_t *id=p?d2s_plan_id(p):NULL;
                for(size_t i=0;i<D2S_PLAN_ID_LEN;i++)printf("%02x",id?id[i]:0);
                putchar('\n');
            }
            assert(t->used<=cap);
        }
        d2s_plantab_free(t);
    }
    return 0;
}
