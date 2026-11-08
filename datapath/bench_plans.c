/* Production lookup benchmark. No packet path instrumentation or allocations.
 * Driver compiles unmodified plans.c separately for timing and counted copies
 * only for entry-visit accounting. Percentiles are 64-lookup batch means. */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#ifndef D2S_BENCH_SOURCE
#define D2S_BENCH_SOURCE "plans.c"
#endif
static unsigned long long bench_visits;
#ifdef D2S_BENCH_COUNT
#define D2S_BENCH_VISIT() (++bench_visits)
#else
#define D2S_BENCH_VISIT() ((void)0)
#endif
#include D2S_BENCH_SOURCE

static d2s_plan *program(void) {
    static const uint8_t data[]={'D','2','S','P',0,1,0,1,0,0,0,1,1,3,0,1,0};
    d2s_plan *p=NULL;char error[100];
    int rc=d2s_plan_load(data,sizeof data,&p,error,sizeof error);assert(!rc && p);return p;
}
static void put(d2s_plantab *t,const char *name,uint8_t shape,uint8_t family,uint16_t sport,uint64_t now) {
    int rc=d2s_plantab_set_name_family(t,(const uint8_t *)name,strlen(name),now,program(),shape,sport,family);
    assert(!rc);
}
static void address(uint8_t *ip,size_t i) {
    memset(ip,0,16);ip[0]=10;ip[1]=(uint8_t)(i>>16);ip[2]=(uint8_t)(i>>8);ip[3]=(uint8_t)i;
    ip[15]=(uint8_t)i;
}
static d2s_plantab *catalog(size_t n,int varied) {
    d2s_plantab *t=d2s_plantab_new(n);assert(t);
    put(t,"common-prefix-0000.example.test",D2S_PLAN_SHAPE_MODERN,4,0,1);
    put(t,"common-prefix-0000.example.test",D2S_PLAN_SHAPE_LEGACY,4,0,2);
    put(t,"common-prefix-0000.example.test",D2S_PLAN_SHAPE_MODERN,6,0,3);
    put(t,"timestamps.example.test",D2S_PLAN_SHAPE_MODERN_NO_TS,4,0,4);
    put(t,"timestamps.example.test",D2S_PLAN_SHAPE_MODERN_TS,4,0,5);
    put(t,"common-prefix-0000.example.test",D2S_PLAN_SHAPE_MODERN,4,5555,6);
    for(size_t i=6;i<n;i++) {
        uint8_t ip[16];address(ip,i);
        uint8_t family=i%4==3?6:4;
        if(i%4>=2) {
            int rc=d2s_plantab_set_addr_shaped(t,ip,family,i+1,program(),D2S_PLAN_SHAPE_MODERN);
            assert(!rc);
        } else {
            char name[80];
            if(varied)snprintf(name,sizeof name,"h%zu.cdn%zu.example.net",i,i%7);
            else snprintf(name,sizeof name,"common-prefix-%04zu.example.test",i);
            put(t,name,i%2?D2S_PLAN_SHAPE_LEGACY:D2S_PLAN_SHAPE_MODERN,family,0,i+1);
        }
    }
    int rc=d2s_plantab_set_suffix_family(t,(const uint8_t *)"scope.test",10,1,program(),D2S_PLAN_SHAPE_MODERN,4);
    assert(!rc);
    rc=d2s_plantab_set_bypass_family(t,(const uint8_t *)"excluded.scope.test",19,6,D2S_PLAN_SHAPE_MODERN,4);
    assert(!rc && t->used==n);return t;
}
typedef struct { const char *label,*name; uint8_t family,shape; uint16_t sport; uint8_t ip[16];int has_addr; } query;
static const d2s_plan *lookup(d2s_plantab *t,const query *q) {
    return d2s_plantab_find_target(t,(const uint8_t *)q->name,q->name?strlen(q->name):0,
        q->has_addr?q->ip:NULL,q->family,100000,q->shape,q->sport);
}
static double stamp(clockid_t clock) {
    struct timespec ts;int rc=clock_gettime(clock,&ts);assert(!rc);
    return ts.tv_sec*1e9+ts.tv_nsec;
}
static int order(const void *a,const void *b) { double x=*(const double *)a,y=*(const double *)b;return (x>y)-(x<y); }
static volatile uintptr_t sink;
int main(int argc,char **argv) {
    size_t sizes[]={32,128,256,512,1024,2048};
    int varied=argc>1;(void)argv;
    puts("size,case,mean_ns,median_ns,p95_ns,p99_ns,cpu_ns,visits,table_bytes,entry_bytes,plan_bytes,rss_kib,lookup_median_raw_ns,lookup_p95_raw_ns,lookup_p99_raw_ns");
    for(size_t z=0;z<sizeof sizes/sizeof sizes[0];z++) {
        size_t n=sizes[z];d2s_plantab *t=catalog(n,varied);
        query qs[]={
          {"exact4","common-prefix-0000.example.test",4,D2S_PLAN_SHAPE_MODERN,0,{0},0},
          {"name_miss","common-prefix-9999.example.test",4,D2S_PLAN_SHAPE_MODERN,0,{0},0},
          {"address4",NULL,4,D2S_PLAN_SHAPE_MODERN,0,{0},1},
          {"address_miss4",NULL,4,D2S_PLAN_SHAPE_MODERN,0,{0},1},
          {"exact6","common-prefix-0000.example.test",6,D2S_PLAN_SHAPE_MODERN,0,{0},0},
          {"address6",NULL,6,D2S_PLAN_SHAPE_MODERN,0,{0},1},
          {"address_miss6",NULL,6,D2S_PLAN_SHAPE_MODERN,0,{0},1},
          {"timestamp_match","timestamps.example.test",4,D2S_PLAN_SHAPE_MODERN_TS,0,{0},0},
          {"timestamp_mismatch","timestamps.example.test",4,D2S_PLAN_SHAPE_LEGACY_TS,0,{0},0},
          {"suffix","member.scope.test",4,D2S_PLAN_SHAPE_MODERN,0,{0},0},
          {"bypass","excluded.scope.test",4,D2S_PLAN_SHAPE_MODERN,0,{0},0},
          {"trial_hit","common-prefix-0000.example.test",4,D2S_PLAN_SHAPE_MODERN,5555,{0},0},
          {"trial_miss_permanent","common-prefix-0000.example.test",4,D2S_PLAN_SHAPE_MODERN,5556,{0},0},
          {"ech_fallback","common-prefix-0000.example.test",4,D2S_PLAN_SHAPE_ECH_TCP,0,{0},0},
        };
        address(qs[2].ip,n-2);address(qs[5].ip,n-1);
        address(qs[3].ip,99999);address(qs[6].ip,99999);
        for(size_t q=0;q<sizeof qs/sizeof qs[0];q++) {
            for(int i=0;i<128;i++)sink^=(uintptr_t)lookup(t,&qs[q]);
            double values[101],sum=0,cpu=stamp(CLOCK_PROCESS_CPUTIME_ID);
            bench_visits=0;
            for(int sample=0;sample<101;sample++) {
                double begin=stamp(CLOCK_MONOTONIC);
                for(int i=0;i<64;i++)sink^=(uintptr_t)lookup(t,&qs[q]);
                values[sample]=(stamp(CLOCK_MONOTONIC)-begin)/64;sum+=values[sample];
            }
            cpu=(stamp(CLOCK_PROCESS_CPUTIME_ID)-cpu)/(101*64);
            double visits=(double)bench_visits/(101*64);
            qsort(values,101,sizeof *values,order);
            double individual[1025];
            for(size_t sample=0;sample<1025;sample++) {
                double begin=stamp(CLOCK_MONOTONIC);sink^=(uintptr_t)lookup(t,&qs[q]);
                individual[sample]=stamp(CLOCK_MONOTONIC)-begin;
            }
            qsort(individual,1025,sizeof *individual,order);
            struct rusage ru;getrusage(RUSAGE_SELF,&ru);
            printf("%zu,%s,%.2f,%.2f,%.2f,%.2f,%.2f,%.0f,%zu,%zu,%zu,%ld,%.2f,%.2f,%.2f\n",n,qs[q].label,
                sum/101,values[50],values[95],values[99],cpu,visits,
                sizeof *t+n*(sizeof(entry)+sizeof(probe_entry)),sizeof(entry),
                (n+t->suffix_used)*sizeof(d2s_plan),ru.ru_maxrss,individual[512],individual[973],individual[1014]);
        }
        d2s_plantab_free(t);
    }
    return 0;
}
