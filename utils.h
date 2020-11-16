#ifndef UTILS_PSC_H
#define UTILS_PSC_H

#include "pthread.h"
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <sys/types.h>


#define RED "\033[38;2;200;100;100m "
#define GREEN "\033[38;2;100;200;100m "
#define RST "\033[0m"

typedef struct iphdr iphdr_t;
typedef struct tcphdr tcphdr_t;
typedef struct sockaddr_in sockaddr_in_t;
typedef struct 
{
    uint8_t done;
    int sd;
    int period;
    void* (*stopListening)(void*);
}Interrupter;

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
        printf("%18s\n","Port statuses");
        printf("%18s\n","-------------");
        printf(" %-15s%7s\n","port", "status");
        first = 0;
    }
    printf(GREEN"%-15d%6s%s%s", port, status,RST,"\n");
    fflush(stdout);
}
Interrupter intterupter;
#endif
