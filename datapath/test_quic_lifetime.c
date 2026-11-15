/* Exercise the production sweep/expiry path after NFQUEUE's packet window. */
#include "session.c"
#include <assert.h>
static uint64_t orig_packets,reply_packets;
static int ct_available=1;
static int query(void *ctx,const d2s_ct_tuple *tuple,d2s_ct_info *out){
    (void)ctx;assert(tuple->proto==17);
    if(!ct_available)return -1;
    memset(out,0,sizeof *out);out->orig_pkts=orig_packets;out->reply_pkts=reply_packets;return 0;
}
int main(void){
    const uint64_t sec=1000000000ull;
    for(int family=4;family<=6;family+=2){
        d2s_session *s=d2s_session_new(64,64);assert(s);
        d2s_session_set_ct_query(s,query,NULL);
        d2s_key key={0};key.proto=17;key.family=(uint8_t)family;
        d2s_flow *f=d2s_track_get(s->uflows,&key,sec);assert(f);
        f->saw_initial=1;f->rev_after_hello=1;f->rev_pkts=8;f->quic_rtt_ns=10000000;
        ct_available=1;
        for(unsigned t=2;t<=300;t++){
            orig_packets=t*5;reply_packets=t*10;
            assert(!d2s_session_sweep(s,t*sec));
            assert(!d2s_session_expire(s,t*sec,120*sec));
            assert(d2s_session_flows(s)==1);
        }
        /* A seek/retry after five minutes is still attributed to this flow. */
        orig_packets+=3;
        assert(d2s_session_sweep(s,302*sec)==1);
        assert(!d2s_session_sweep(s,303*sec));
        assert(d2s_session_expire(s,421*sec,120*sec)==1);
        /* A quiet live entry is not progress and cannot pin memory. */
        f=d2s_track_get(s->uflows,&key,500*sec);assert(f);
        f->saw_initial=1;f->rev_after_hello=1;f->rev_pkts=8;
        orig_packets=4;reply_packets=8;
        d2s_session_sweep(s,501*sec);
        assert(d2s_session_expire(s,621*sec,120*sec)==1);
        d2s_session_free(s);
    }
    puts("QUIC: active video retained, late seek stall observed, quiet entries expired (IPv4/IPv6)");
    return 0;
}
