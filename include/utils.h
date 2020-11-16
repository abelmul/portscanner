#ifndef UTILS_PSC_H
#define UTILS_PSC_H

#include "pthread.h"
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>


#define RED "\033[38;2;200;100;100m"
#define GREEN "\033[38;2;100;200;100m"
#define RST "\033[0m"

typedef struct iphdr iphdr_t;
typedef struct tcphdr tcphdr_t;
typedef struct sockaddr_in sockaddr_in_t;
typedef void (*scanner)(sockaddr_in_t *);

enum scan_type { TCP_SCAN, UDP_SCAN, SYN_SCAN, FIN_SCAN};

struct pseudo_header
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;

    struct tcphdr tcp;
};

/**
 * Get the public ip of this host
 */
void get_local_ip ( char * buffer) {
    int sock = socket ( AF_INET, SOCK_DGRAM, 0);

    const char* kGoogleDnsIp = "8.8.8.8";
    int dns_port = 53;

    struct sockaddr_in serv;

    memset( &serv, 0, sizeof(serv) );
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
    serv.sin_port = htons( dns_port );

    int err = connect( sock , (const struct sockaddr*) &serv , sizeof(serv) );

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    err = getsockname(sock, (struct sockaddr*) &name, &namelen);

    const char *p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);

    close(sock);
}


/**
 * Checksums - IP and TCP
*/
unsigned short csum(unsigned short *ptr,int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}

typedef struct 
{
    uint8_t done;
    int sd;
    int period;
    void* (*stopListening)(void*);
}Interrupter;

/**
 * Shutdown a listening socket.
 */
void* stopListening(void* p){
    Interrupter* self = (Interrupter*)p;
    sleep(self->period);
    self->done = 1;
    shutdown(self->sd,SHUT_RDWR);
}

void initInt(Interrupter* intr,int sd, int period){
    intr->sd = sd;
    intr->stopListening = stopListening;
    intr->done = 0;
    intr->period = period;
}

void set_iphdr(iphdr_t* iph,char (*source_ip)[20],sockaddr_in_t* servaddr){
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = 0;
    iph->id = 0;
    iph->frag_off = htons(16384);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = inet_addr (*source_ip);
    iph->daddr = servaddr->sin_addr.s_addr;
}

void set_tcphdr(tcphdr_t* tcph,u_int16_t source_port,uint8_t syn){
    tcph->source = htons (source_port);
    tcph->seq = htonl(1105024978);
    tcph->ack_seq = 0;
    tcph->doff = sizeof(struct tcphdr) / 4;		//Size of tcp header
    tcph->fin=1-syn;
    tcph->syn=syn;
    tcph->rst=0;
    tcph->psh=0;
    tcph->ack=0;
    tcph->urg=0;
    tcph->window = htons ( 14600 );
    tcph->check = 0;
    tcph->urg_ptr = 0;
}

void print_err(char* msg){
    printf(RED"[Error] %s%s%s", msg,RST,"\n");
    fflush(stdout);
}
void print_err2(char* msg1,char* msg2){
    printf(RED"[Error] %s%s%s%s", msg1,msg2,RST,"\n");
    fflush(stdout);
}
void print_status(int port,char* status){
    static int first=1;
    if( first ){
        printf("%17s\n","Port status");
        printf("%17s\n","-----------");
        printf(" %-15s%7s\n","port", "status");
        first = 0;
    }
    printf(GREEN"%-15d%6s%s%s", port, status,RST,"\n");
    fflush(stdout);
}
void print_msg(char* msg){
    printf(GREEN"[PortScanner]"RST);
    printf(" %s\n",msg);
    fflush(stdout);
}
void print_usage(){
    print_msg("Usage: ./prtsc [options] [target_ip]");
    printf("\noptions: -sT|-sU|-sS|-sF\n");
    printf("\t -sT : Do a TCP connect scan.\n");
    printf("\t -sU : Do a UDP connect scan.\n");
    printf("\t -sS : Do a SYN scan.\n");
    printf("\t -sF : Do a FIN scan.\n");
    printf("[target_ip] is the ip address of the target machine to carry out the scan on.\n");
}

enum scan_type get_type(char* opt){
    if( !strcmp(opt, "-sT") )
        return TCP_SCAN;
    
    else if (!strcmp(opt, "-sU"))
        return UDP_SCAN;

    else if(!strcmp(opt, "-sS"))
        return SYN_SCAN;

    else if( !strcmp(opt, "-sF"))
        return FIN_SCAN;

    else{
        print_err2("Unrecognized option ",opt);
        print_usage();
        exit(-1);
    }
}

Interrupter intterupter;
#endif
