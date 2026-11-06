#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#include "d2s_detect.h"
#include <pthread.h>
struct whole_trial;
static int fake_whole(struct whole_trial *);
int fake_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
#define D2S_BASELINE_PROBE fake_whole
#define D2S_BASELINE_CREATE fake_create
#include "classify.c"

static pthread_mutex_t mu=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv=PTHREAD_COND_INITIALIZER;
static int answers[9],calls[9],active,peak,barrier,released,create_calls,fail_at=-1,fails;
static int real_io,cancel_during,cancelled,observations;
static pthread_t owner;
static int fake_whole(whole_trial *trial) {
    if(real_io){char peer[INET6_ADDRSTRLEN]="";return once_probe(trial->host,trial->port,trial->trigger,trial->opt,NULL,0,0,trial->err,sizeof trial->err,peer,sizeof peer);}
    pthread_mutex_lock(&mu);
    if(cancel_during && trial->index==0)cancelled=1;
    calls[trial->index]++;active++;if(active>peak)peak=active;
    if(barrier){
        if(active==3){released=1;pthread_cond_broadcast(&cv);}
        struct timespec limit;clock_gettime(CLOCK_REALTIME,&limit);
        limit.tv_nsec+=100000000;if(limit.tv_nsec>=1000000000){limit.tv_sec++;limit.tv_nsec-=1000000000;}
        while(!released)if(pthread_cond_timedwait(&cv,&mu,&limit)==ETIMEDOUT)break;
    }
    pthread_mutex_unlock(&mu);
    d2s_sleep_ms((3-trial->index%3)*2);
    if(answers[trial->index]<0)snprintf(trial->err,sizeof trial->err,"error-%d",trial->index);
    pthread_mutex_lock(&mu);active--;pthread_mutex_unlock(&mu);
    return answers[trial->index];
}
int fake_create(pthread_t *thread,const pthread_attr_t *attr,void *(*fn)(void *),void *arg){
    int call=create_calls++;
    return call==fail_at?EAGAIN:pthread_create(thread,attr,fn,arg);
}
#define CHECK(c) do{if(!(c)){printf("FAIL parallel baseline line %d\n",__LINE__);fails++;}}while(0)
static void reset(void){memset(calls,0,sizeof calls);memset(answers,0,sizeof answers);active=peak=released=create_calls=barrier=0;real_io=cancel_during=cancelled=observations=0;fail_at=-1;}
static int stopped(void *ctx){(void)ctx;CHECK(pthread_equal(owner,pthread_self()));pthread_mutex_lock(&mu);int value=cancelled;pthread_mutex_unlock(&mu);return value;}
static void observed(void *ctx,const d2s_obs *obs){(void)ctx;(void)obs;CHECK(pthread_equal(owner,pthread_self()));observations++;}
static d2s_tally run(int n,d2s_result *res){
    d2s_opts opt={0};d2s_trigger tr={0};opt.repeats=n;opt.parallel_base=1;
    memset(res,0,sizeof *res);
    return measure("192.0.2.10","443",&tr,&opt,"whole",NULL,0,0,res,0);
}

typedef struct {int listener,reply,accepted;} server_arg;
static void *server(void *arg){
    server_arg *s=arg;int peers[3],count=0;
    for(int i=0;i<3;i++){
        struct pollfd p={.fd=s->listener,.events=POLLIN};
        if(poll(&p,1,3000)<=0)break;
        int fd=accept(s->listener,NULL,NULL);if(fd<0)break;
        struct timeval timeout={.tv_sec=3};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof timeout);
        uint8_t payload;
        if(recv(fd,&payload,1,0)!=1){close(fd);break;}
        peers[count++]=fd;
    }
    s->accepted=count;
    if(s->reply){for(int i=0;i<count;i++)(void)d2s_send_nosig(peers[i],"OK",2);}
    else d2s_sleep_ms(1200);
    for(int i=0;i<count;i++)close(peers[i]);
    return NULL;
}

static void test_socket_baseline(int family,int reply){
    int fd=socket(family,SOCK_STREAM,0),one=1;
    if(fd<0 && family==AF_INET6){puts("IPv6 loopback unavailable: socket case skipped");return;}
    CHECK(fd>=0);if(fd<0)return;
    setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    struct sockaddr_storage address={0};socklen_t length;
    const char *host=family==AF_INET?"127.0.0.1":"::1";
    if(family==AF_INET){struct sockaddr_in *a=(struct sockaddr_in *)&address;a->sin_family=AF_INET;a->sin_addr.s_addr=htonl(INADDR_LOOPBACK);length=sizeof *a;}
    else {struct sockaddr_in6 *a=(struct sockaddr_in6 *)&address;a->sin6_family=AF_INET6;a->sin6_addr=in6addr_loopback;length=sizeof *a;}
    int bound=bind(fd,(struct sockaddr *)&address,length);
    if(bound && family==AF_INET6){close(fd);puts("IPv6 loopback unavailable: bind case skipped");return;}
    CHECK(!bound && !listen(fd,3) && !getsockname(fd,(struct sockaddr *)&address,&length));
    char port[16];snprintf(port,sizeof port,"%u",ntohs(family==AF_INET?((struct sockaddr_in *)&address)->sin_port:((struct sockaddr_in6 *)&address)->sin6_port));
    server_arg state={fd,reply,0};pthread_t thread;CHECK(!pthread_create(&thread,NULL,server,&state));
    d2s_opts opt={0};d2s_trigger trigger={0};d2s_result result={0};
    opt.repeats=3;opt.timeout_ms=1000;opt.parallel_base=opt.allow_loopback=1;
    opt.on_obs=observed;opt.cancel.fn=stopped;trigger.payload[0]=1;trigger.len=1;
    reset();real_io=1;owner=pthread_self();
    d2s_tally tally=measure(host,port,&trigger,&opt,"whole",NULL,0,0,&result,0);
    pthread_join(thread,NULL);close(fd);real_io=0;
    CHECK(state.accepted==3 && result.probes==3 && observations==1 && !tally.has_err);
    CHECK(tally.pass==(reply?3:0) && tally.fail==(reply?0:3));
}
int main(void){
    d2s_result res;
    reset();barrier=1;d2s_tally tally=run(3,&res);
    CHECK(peak==3 && tally.fail==3 && res.probes==3 && active==0);
    /* Exhaust every success/silence/local-error sequence. First error is
       chosen by trial number, never by completion order. */
    for(int pattern=0;pattern<27;pattern++){
        reset();int bits=pattern,pass=0,first=-1;
        for(int i=0;i<3;i++){answers[i]=bits%3-1;bits/=3;if(answers[i]>0)pass++;if(answers[i]<0&&first<0)first=i;}
        tally=run(3,&res);
        CHECK(tally.pass==pass && tally.fail==3-pass && tally.has_err==(first>=0));
        CHECK(res.probes==3 && active==0);
        for(int i=0;i<3;i++)CHECK(calls[i]==1);
        if(first>=0){char expected[32];snprintf(expected,sizeof expected,"error-%d",first);CHECK(!strcmp(tally.err,expected));}
    }
    for(int failure=0;failure<2;failure++){
        reset();fail_at=failure;answers[0]=answers[1]=answers[2]=1;
        tally=run(3,&res);
        CHECK(create_calls>failure && tally.pass==3 && !tally.has_err && res.probes==3 && active==0);
        for(int i=0;i<3;i++)CHECK(calls[i]==1);
    }
    reset();tally=run(7,&res);CHECK(res.probes==7 && tally.fail==7 && active==0);
    for(int i=0;i<7;i++)CHECK(calls[i]==1);
    reset();
    d2s_opts opt={0};d2s_trigger tr={0};memset(&res,0,sizeof res);
    opt.repeats=opt.seed_repeats=opt.seed_fail=3;opt.seed_whole=opt.parallel_base=1;
    tally=measure("192.0.2.10","443",&tr,&opt,"whole",NULL,0,0,&res,0);
    CHECK(tally.fail==3 && res.probes==0 && create_calls==0 && res.trace[0].elapsed_ms==0);
    reset();cancel_during=1;owner=pthread_self();memset(&res,0,sizeof res);memset(&opt,0,sizeof opt);
    opt.repeats=7;opt.parallel_base=1;opt.cancel.fn=stopped;opt.on_obs=observed;
    tally=measure("192.0.2.10","443",&tr,&opt,"whole",NULL,0,0,&res,0);
    CHECK(active==0 && res.probes>=1 && res.probes<=3 && observations==1);
    int total=0;for(int i=0;i<9;i++)total+=calls[i];CHECK(total==res.probes);
    for(int i=3;i<9;i++)CHECK(calls[i]==0);
    test_socket_baseline(AF_INET,0);test_socket_baseline(AF_INET,1);
    test_socket_baseline(AF_INET6,0);test_socket_baseline(AF_INET6,1);
    if(fails)return 1;
    puts("Parallel baseline: 27 ordered verdict inputs, resource fallback, batches and reuse PASS");
    return 0;
}
