#define D2O_WATCH_TEST
#include "dns-media-watch.c"
#include <assert.h>
static size_t query(uint8_t *packet,const char *name,uint16_t type) {
    memset(packet,0,512);packet[0]=0x45;packet[9]=17;
    packet[22]=0;packet[23]=53;packet[32]=0;packet[33]=1;
    size_t at=40;const char *p=name;
    while(*p) {
        const char *end=strchr(p,'.');size_t n=end?(size_t)(end-p):strlen(p);
        packet[at++]=(uint8_t)n;memcpy(packet+at,p,n);at+=n;
        if(!end) break;
        p=end+1;
    }
    packet[at++]=0;packet[at++]=(uint8_t)(type>>8);packet[at++]=(uint8_t)type;packet[at++]=0;packet[at++]=1;
    packet[2]=(uint8_t)(at>>8);packet[3]=(uint8_t)at;
    packet[24]=(uint8_t)((at-20)>>8);packet[25]=(uint8_t)(at-20);
    return at;
}
int main(void) {
    uint8_t p[512];char name[NAME_CAP];size_t n;
    for(unsigned i=0;i<3;i++) {
        uint16_t types[]={1,28,65};n=query(p,"media-arn2-1.cdn.whatsapp.net",types[i]);
        assert(packet_name(p,n,name));assert(!strcmp(name,"media-arn2-1.cdn.whatsapp.net"));
    }
    n=query(p,"MEDIA-ARN2-1.CDN.WHATSAPP.NET",1);assert(packet_name(p,n,name));assert(!strcmp(name,"media-arn2-1.cdn.whatsapp.net"));
    const char *bad[]={"example.com","media-x.cdn.whatsapp.net.evil.com","media-x.y.cdn.whatsapp.net","media-.cdn.whatsapp.net"};
    for(size_t i=0;i<sizeof(bad)/sizeof(bad[0]);i++){n=query(p,bad[i],1);assert(!packet_name(p,n,name));}
    n=query(p,"media-a.cdn.whatsapp.net",1);p[30]=0x80;assert(!packet_name(p,n,name));
    n=query(p,"media-a.cdn.whatsapp.net",1);p[6]=0x20;assert(!packet_name(p,n,name));
    n=query(p,"media-a.cdn.whatsapp.net",1);p[9]=6;assert(!packet_name(p,n,name));
    n=query(p,"media-a.cdn.whatsapp.net",1);p[23]=54;assert(!packet_name(p,n,name));
    n=query(p,"media-a.cdn.whatsapp.net",1);p[33]=2;assert(!packet_name(p,n,name));
    n=query(p,"media-a.cdn.whatsapp.net",1);p[40]=0xc0;assert(!packet_name(p,n,name));
    n=query(p,"media-a.cdn.whatsapp.net",1);assert(!packet_name(p,n-2,name));
    n=query(p,"media-a.cdn.whatsapp.net",15);assert(!packet_name(p,n,name));
    puts("DNS observer parser PASS: query types, lowercase, media suffix, hostile/truncated/fragmented packets");return 0;
}
