/* Production parser and budget loop; local controlled HTTP responses only. */
#include "verify.c"
#include <assert.h>
static int mode, reads;
static long packets(void *ctx) { (void)ctx; return mode == 3 ? 50 : 28; }
static int peer(void *ctx) { (void)ctx; return mode == 2; }
static int write_ok(void *ctx,const uint8_t *buf,size_t n,char *err,size_t cap) {
    (void)ctx;(void)buf;(void)n;(void)err;(void)cap;return 0;
}
static long reply(void *ctx,uint8_t *buf,size_t cap,int wait,char *err,size_t ec) {
    (void)ctx;(void)buf;(void)cap;(void)err;(void)ec;reads++;
    if(mode==1)return 0;
    struct timespec delay={wait/1000,(wait%1000)*1000000L};
    nanosleep(&delay,NULL); errno=ETIMEDOUT; return -1;
}
static int qrequest(void *ctx,uint64_t sid,char *err,size_t cap) {
    (void)ctx;(void)sid;(void)err;(void)cap;return 0;
}
static long qrecv(void *ctx,uint8_t *buf,size_t cap,char *err,size_t ec) {
    (void)ctx;(void)buf;(void)cap;(void)err;(void)ec;return -1;
}
static void progress(void *ctx,uint64_t *bytes,int *complete) {
    (void)ctx;*bytes=20;*complete=1;
}
int main(void) {
    for(mode=0;mode<4;mode++) {
        d2s_ver_result r={0}; r.level=D2S_VER_APPLICATION;r.status=404;r.body_complete=1;
        reads=0; budget_io io={packets,peer,NULL};
        budget_tcp(reply,write_ok,NULL,&io,"GET / HTTP/1.1\r\n\r\n",18,30,25,0,&r);
        assert(r.budget==(mode==3?D2S_BUDGET_PASSED:D2S_BUDGET_NOT_APPLICABLE));
        assert(r.status==404 && r.body_complete && r.level==D2S_VER_APPLICATION);
        if(mode==0)assert(strstr(r.budget_note,"причина не установлена"));
        if(mode==3)assert(reads==0);
    }
    mode=0;d2s_ver_result r={0};
    quic_budget_io io={qrequest,qrecv,progress,packets,NULL};
    budget_quic(&io,30,25,&r);
    assert(r.budget==D2S_BUDGET_NOT_APPLICABLE);
    return 0;
}
