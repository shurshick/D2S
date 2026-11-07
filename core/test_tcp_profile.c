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
static int timestamp_setting(void) {
    FILE *f=fopen("/proc/sys/net/ipv4/tcp_timestamps","r");
    if(!f)return -1;
    int value=-1;assert(fscanf(f,"%d",&value)==1);fclose(f);return value;
}
#endif
int main(void) {
#ifdef __linux__
    int initial=timestamp_setting();assert(initial>=0);
    int seen[2]={0};
    for(int pass=0;pass<8;pass++) {
        int wanted=pass%2;
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
        if(rc==-3) { close(listener);continue; }
        assert(!rc && client>=0);
        struct tcp_info info;memset(&info,0,sizeof info);size=sizeof info;
        assert(!getsockopt(client,IPPROTO_TCP,TCP_INFO,&info,&size));
        assert(!!(info.tcpi_options & TCPI_OPT_TIMESTAMPS)==wanted);
        seen[wanted]++;close(client);close(listener);
    }
    if(getenv("D2S_REQUIRE_TCP_PROFILE"))assert(seen[0] && seen[1]);
    printf("TCP profile: absent=%d present=%d; original sysctl restored after every connect; unavailable profiles remain local refusals\n",seen[0],seen[1]);
#else
    puts("TCP profile: Linux-only wire test");
#endif
    return 0;
}
