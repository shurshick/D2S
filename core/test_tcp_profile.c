#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "include/d2s_compose_internal.h"
#include <arpa/inet.h>
#include <assert.h>
#ifdef __linux__
#include <linux/tcp.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef __linux__
static int mask_peer_timestamp,masked_info_reads;
#endif
static int profile_getsockopt(int,int,int,void *,socklen_t *);
#define getsockopt profile_getsockopt
#include "compose.c"
#undef getsockopt
static int profile_getsockopt(int fd,int level,int option,void *value,socklen_t *len) {
    int rc=getsockopt(fd,level,option,value,len);
#ifdef __linux__
    if(!rc && mask_peer_timestamp && level==IPPROTO_TCP && option==TCP_INFO) {
        ((struct tcp_info *)value)->tcpi_options &= (uint8_t)~TCPI_OPT_TIMESTAMPS;
        masked_info_reads++;
    }
#endif
    return rc;
}

#ifdef __linux__
static int timestamp_setting(void) {
    FILE *f=fopen("/proc/sys/net/ipv4/tcp_timestamps","r");
    if(!f)return -1;
    int value=-1;assert(fscanf(f,"%d",&value)==1);fclose(f);return value;
}
#endif
int main(void) {
#ifdef __linux__
    int initial=timestamp_setting();assert(initial>=0);
    int seen[2]={0},refused[2]={0};
    for(int pass=0;pass<9;pass++) {
        mask_peer_timestamp=pass==8;
        int wanted=mask_peer_timestamp?1:pass%2;
        int listener=socket(AF_INET,SOCK_STREAM,0);assert(listener>=0);
        struct sockaddr_in addr={0};addr.sin_family=AF_INET;
        addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        assert(!bind(listener,(struct sockaddr *)&addr,sizeof addr));
        assert(!listen(listener,1));socklen_t size=sizeof addr;
        assert(!getsockname(listener,(struct sockaddr *)&addr,&size));
        int client=-1;uint8_t local[16]={0};uint16_t port=0;
        int rc=d2s_props_contact_on_family_tcp_profile(-1,"127.0.0.1",ntohs(addr.sin_port),
            (d2s_hello){0},4,wanted,local,&port,&client);
        assert(timestamp_setting()==initial);
        if(mask_peer_timestamp) { assert(rc==-3 && client<0);close(listener);continue; }
        if(initial==0 && wanted==1)assert(rc==-3 && client<0);
        if(rc==-3) { refused[wanted]++;close(listener);continue; }
        assert(!rc && client>=0);
        struct tcp_info info;memset(&info,0,sizeof info);size=sizeof info;
        assert(!getsockopt(client,IPPROTO_TCP,TCP_INFO,&info,&size));
        assert(!!(info.tcpi_options & TCPI_OPT_TIMESTAMPS)==wanted);
        seen[wanted]++;close(client);close(listener);
    }
    mask_peer_timestamp=0;
    if(initial!=0)assert(masked_info_reads==1);
    if(getenv("D2S_REQUIRE_TCP_PROFILE")) {
        assert(seen[0]);
        if(initial==0)assert(refused[1]==4 && !seen[1]);
        else assert(seen[1]);
    }
    printf("TCP profile: original=%d absent=%d present=%d refused=%d/%d; original sysctl restored after every connect\n",initial,seen[0],seen[1],refused[0],refused[1]);
#else
    puts("TCP profile: Linux-only wire test");
#endif
    return 0;
}
