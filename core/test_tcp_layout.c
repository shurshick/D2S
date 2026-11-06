#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "d2s_compose.h"
#include "d2s_hello.h"
#include "d2s_plantlv.h"
#include "d2s_plan.h"
#include "d2s_wire.h"
#include <arpa/inet.h>

static void wire_stream(const d2s_actions *a,const d2s_pkt *input) {
    for(int family=4;family<=6;family+=2) {
        d2s_conn c={.family=(uint8_t)family,.ttl=64,.ack=1234,.window=32768};
        c.src_port=htons(50000);c.dst_port=htons(443);
        inet_pton(AF_INET,"192.0.2.1",&c.src_ip);inet_pton(AF_INET,"198.51.100.1",&c.dst_ip);
        inet_pton(AF_INET6,"2001:db8::1",c.src_ip6);inet_pton(AF_INET6,"2001:db8::2",c.dst_ip6);
        uint8_t restored[2048]={0},seen[2048]={0};size_t fakes=0;
        for(size_t i=0;i<a->n;i++) {
            uint8_t raw[4096];size_t n=d2s_wire_build(&c,&a->v[i],raw,sizeof raw);assert(n);
            if(!d2s_wire_tcp_checksum_ok(raw,n)) { assert(a->v[i].kind==D2S_EMIT_FAKE);fakes++;continue; }
            assert(a->v[i].kind==D2S_EMIT_PAYLOAD);
            size_t ip=family==6?40:(size_t)(raw[0]&15)*4;
            size_t body=ip+(size_t)(raw[ip+12]>>4)*4;
            uint32_t seq=(uint32_t)raw[ip+4]<<24 | (uint32_t)raw[ip+5]<<16 | (uint32_t)raw[ip+6]<<8 | raw[ip+7];
            size_t at=(uint32_t)(seq-input->seq);assert(at<input->payload_len && n-body<=input->payload_len-at);
            for(size_t j=0;j<n-body;j++) { assert(!seen[at+j]);seen[at+j]=1;restored[at+j]=raw[body+j]; }
        }
        assert(fakes && !memcmp(restored,input->payload,input->payload_len));
        for(size_t i=0;i<input->payload_len;i++)assert(seen[i]);
    }
}

static void layout(unsigned mode) {
    uint8_t hello[2048];size_t hn=0,off=0,len=0;
    assert(!d2s_hello_from_profile(D2S_SHAPE_MODERN,"blocked.example",hello,sizeof hello,&hn));
    assert(!d2s_hello_sni(hello,hn,&off,&len));
    d2s_arm_input in={.trigger_len=hn,.sni_off=off,.sni_len=len};
    assert(!d2s_hello_from_profile(D2S_SHAPE_MODERN,"control.example",in.decoy,sizeof in.decoy,&in.decoy_len));
    d2s_arm arm={.fake_layout=mode,.badsum=1,.repeats=1,.decoy_hello=1};
    char text[16384],err[160];uint8_t tlv[D2S_PLAN_TLV_MAX];size_t n=0;d2s_plan *p=NULL;
    assert(!d2s_arm_plan_measured(&arm,&in,text,sizeof text));
    assert(strstr(text,mode==1?"fakelayout 1\n":"fakelayout 2\n"));
    assert(!d2s_plan_text_to_tlv(text,tlv,sizeof tlv,&n,err,sizeof err));
    int loaded=d2s_plan_load(tlv,n,&p,err,sizeof err);
    if(loaded)fprintf(stderr,"layout%u load: %s\n",mode,err);
    assert(!loaded);
    tlv[7]=14;d2s_plan *old=NULL;assert(d2s_plan_load(tlv,n,&old,err,sizeof err)<0 && !old);tlv[7]=15;
    char unsafe[16384];strcpy(unsafe,text);char *poison=strstr(unsafe,"badsum");assert(poison);
    memcpy(poison,"ttl=64",6);
    assert(d2s_plan_text_to_tlv(unsafe,tlv,sizeof tlv,&n,err,sizeof err)<0);
    strcpy(unsafe,text);size_t used=strlen(unsafe);
    assert(used+14<sizeof unsafe);strcpy(unsafe+used,"fakelayout 1\n");
    assert(d2s_plan_text_to_tlv(unsafe,tlv,sizeof tlv,&n,err,sizeof err)<0);
    char simplified[16384];size_t next=0;
    assert(!d2s_plan_simplify_next(text,0,simplified,sizeof simplified,&next,err,sizeof err));
    d2s_pkt packet={.payload=hello,.payload_len=hn,.seq=0xffffff00u,
        .have_sni=1,.is_tls13=1,.sni_off=off,.sni_len=len};
    d2s_actions a={0};assert(!d2s_plan_apply(p,NULL,&packet,&a));
    assert(a.fate==D2S_ORIG_DROP);wire_stream(&a,&packet);
    uint8_t restored[2048]={0},seen[2048]={0};size_t reals=0,fakes=0;
    for(size_t i=0;i<a.n;i++) {
        d2s_emit *e=&a.v[i];size_t at=(uint32_t)(e->seq-packet.seq);
        assert(at<hn && e->len && e->len<=hn-at);
        if(e->kind==D2S_EMIT_FAKE) {
            assert(e->poison&D2S_POISON_BADSUM);fakes++;
            if(mode==2)assert(at==off && e->len==len);
        } else {
            assert(e->kind==D2S_EMIT_PAYLOAD);reals++;
            for(size_t j=0;j<e->len;j++) { assert(!seen[at+j]);seen[at+j]=1;restored[at+j]=e->bytes[j]; }
        }
    }
    assert(!memcmp(restored,hello,hn));for(size_t i=0;i<hn;i++)assert(seen[i]);
    if(mode==1) {
        assert(fakes==2 && reals==2 && a.n==4);
        assert(a.v[0].kind==D2S_EMIT_FAKE && a.v[1].kind==D2S_EMIT_PAYLOAD &&
            a.v[0].seq==a.v[1].seq && (uint32_t)(a.v[1].seq-packet.seq)>0 &&
            a.v[2].kind==D2S_EMIT_FAKE && a.v[3].seq==packet.seq);
    } else assert(fakes==2 && reals==4 && a.n==6);
    d2s_actions_free(&a);packet.segment_cap=96;
    assert(!d2s_plan_apply(p,NULL,&packet,&a));wire_stream(&a,&packet);d2s_actions_free(&a);
    packet.segment_cap=0;packet.payload_len--;
    assert(d2s_plan_apply(p,NULL,&packet,&a)<0 && !a.n);packet.payload_len++;
    packet.have_sni=0;
    assert(d2s_plan_apply(p,NULL,&packet,&a)<0 && !a.n);
    d2s_plan_free(p);
    arm.badsum=0;assert(d2s_arm_plan_measured(&arm,&in,text,sizeof text)<0);
    arm.badsum=1;arm.ttl=3;assert(d2s_arm_plan_measured(&arm,&in,text,sizeof text)<0);
    arm.ttl=0;arm.fake_layout=3;assert(d2s_arm_plan_measured(&arm,&in,text,sizeof text)<0);
    arm.fake_layout=mode;
    assert(d2s_arm_plan(&arm,D2S_SHAPE_MODERN,"control.example",0,text,sizeof text)<0);
}
int main(void) {
    layout(1);layout(2);puts("TCP fake layouts: exact order, sequence and unmodified real stream PASS");return 0;
}
