#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <unistd.h>

#define HOST_CAP 128
#define NAME_CAP 256
static uint16_t be16(const uint8_t *p) { return (uint16_t)((unsigned)p[0]*256u+p[1]); }
static int media_name(const char *name) {
    static const char suffix[]=".cdn.whatsapp.net";
    size_t n=strlen(name),s=sizeof(suffix)-1;
    if(n<=s+6 || n>63+s || strncmp(name,"media-",6) || strcmp(name+n-s,suffix)) return 0;
    for(size_t i=6;i<n-s;i++)
        if(!((name[i]>='a'&&name[i]<='z')||(name[i]>='0'&&name[i]<='9')||name[i]=='-')) return 0;
    return name[n-s-1]!='-';
}

static int packet_name(const uint8_t *p,size_t n,char name[NAME_CAP]) {
    if(n<20 || p[0]>>4!=4 || (p[0]&15)<5 || p[9]!=17 || (be16(p+6)&0x3fff)) return 0;
    size_t ip=(size_t)(p[0]&15)*4;
    if(n<ip+20 || be16(p+ip+2)!=53 || be16(p+ip+4)<20) return 0;
    size_t end=ip+be16(p+ip+4);
    if(end>n || end>be16(p+2)) return 0;
    const uint8_t *d=p+ip+8;
    if((be16(d+2)&0xf800) || be16(d+4)!=1) return 0;
    size_t at=ip+20,used=0;
    for(;;) {
        if(at>=end) return 0;
        unsigned count=p[at++];
        if(!count) break;
        if(count>63 || at+count>end || used+count+1>=NAME_CAP) return 0;
        if(used) name[used++]='.';
        for(unsigned i=0;i<count;i++) {
            unsigned char c=p[at++];
            if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-')) return 0;
            name[used++]=(char)tolower(c);
        }
    }
    name[used]=0;
    if(at+4>end || be16(p+at+2)!=1) return 0;
    uint16_t type=be16(p+at);
    return (type==1 || type==28 || type==65) && media_name(name);
}

#ifndef D2O_WATCH_TEST
static volatile sig_atomic_t stopping;
static void stop_watch(int sig) { (void)sig;stopping=1; }
static int save_names(const char *path,char hosts[HOST_CAP][NAME_CAP],size_t count) {
    char temp[4096];
    if(snprintf(temp,sizeof(temp),"%s.new",path)>=(int)sizeof(temp)) return -1;
    int fd=open(temp,O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW,0600);
    if(fd<0) return -1;
    FILE *f=fdopen(fd,"w");
    if(!f) {close(fd);return -1;}
    int bad=0;
    for(size_t i=0;i<count;i++) if(fprintf(f,"%s\n",hosts[i])<0) bad=1;
    if(fclose(f)!=0) bad=1;
    if(bad || rename(temp,path)!=0) {unlink(temp);return -1;}
    return 0;
}
int main(int argc,char **argv) {
    if(argc==2 && strcmp(argv[1],"--version")==0) {
        puts("d2o-dns-watch 0.1 LAN-query-only media-whatsapp-only");return 0;
    }
    if(argc!=5 || strcmp(argv[1],"--interfaces") || strcmp(argv[3],"--output") || argv[4][0]!='/') return 2;
    char interfaces[1024];
    if(strlen(argv[2])>=sizeof(interfaces)) return 2;
    strcpy(interfaces,argv[2]);
    unsigned indexes[16];size_t interface_count=0;
    char *save=NULL;
    for(char *i=strtok_r(interfaces,",",&save);i;i=strtok_r(NULL,",",&save)) {
        unsigned index=if_nametoindex(i);
        if(!index || interface_count==16) return 2;
        indexes[interface_count++]=index;
    }
    if(!interface_count) return 2;
    char lock_path[4096];
    if(snprintf(lock_path,sizeof(lock_path),"%s.lock",argv[4])>=(int)sizeof(lock_path)) return 2;
    int lock=open(lock_path,O_RDWR|O_CREAT|O_NOFOLLOW,0600);
    if(lock<0 || flock(lock,LOCK_EX|LOCK_NB)!=0) return 1;
    int fd=socket(AF_PACKET,SOCK_DGRAM,htons(ETH_P_IP));
    if(fd<0) {perror("DNS watch socket");return 1;}
    struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_B|BPF_ABS,9),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,17,0,6),
        BPF_STMT(BPF_LD|BPF_H|BPF_ABS,6),
        BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,0x3fff,4,0),
        BPF_STMT(BPF_LDX|BPF_B|BPF_MSH,0),
        BPF_STMT(BPF_LD|BPF_H|BPF_IND,2),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,53,0,1),
        BPF_STMT(BPF_RET|BPF_K,1500),
        BPF_STMT(BPF_RET|BPF_K,0)
    };
    struct sock_fprog filter={.len=(unsigned short)(sizeof(code)/sizeof(code[0])),.filter=code};
    if(setsockopt(fd,SOL_SOCKET,SO_ATTACH_FILTER,&filter,sizeof(filter))!=0) {perror("DNS watch filter");return 1;}
    char hosts[HOST_CAP][NAME_CAP];size_t count=0;
    FILE *old=fopen(argv[4],"r");
    if(old) {
        char line[NAME_CAP];
        while(count<HOST_CAP && fgets(line,sizeof(line),old)) {
            line[strcspn(line,"\r\n")]=0;
            if(media_name(line)) strcpy(hosts[count++],line);
        }
        fclose(old);
    }
    struct sigaction action;memset(&action,0,sizeof(action));action.sa_handler=stop_watch;
    (void)sigaction(SIGTERM,&action,NULL);(void)sigaction(SIGINT,&action,NULL);
    fprintf(stderr,"DNS media observer ready on %zu configured LAN interfaces\n",interface_count);
    while(!stopping) {
        struct pollfd event={.fd=fd,.events=POLLIN};
        int ready=poll(&event,1,1000);
        if(ready<0 && errno==EINTR) continue;
        if(ready<0) break;
        if(!ready) continue;
        uint8_t packet[1500];struct sockaddr_ll address;socklen_t length=sizeof(address);
        ssize_t n=recvfrom(fd,packet,sizeof(packet),0,(struct sockaddr *)&address,&length);
        if(n<=0) continue;
        int selected=0;
        for(size_t i=0;i<interface_count;i++) if(indexes[i]==(unsigned)address.sll_ifindex) selected=1;
        if(!selected || address.sll_pkttype==PACKET_OUTGOING) continue;
        char name[NAME_CAP];if(!packet_name(packet,(size_t)n,name)) continue;
        int seen=0;for(size_t i=0;i<count;i++) if(!strcmp(hosts[i],name)) seen=1;
        if(seen) continue;
        if(count==HOST_CAP) {memmove(hosts,hosts+1,(HOST_CAP-1)*NAME_CAP);count--;}
        strcpy(hosts[count++],name);
        if(save_names(argv[4],hosts,count)!=0) {perror("DNS watch state");break;}
    }
    close(fd);close(lock);return 0;
}
#endif
