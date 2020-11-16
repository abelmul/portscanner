#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include "utils.h"

struct syn_ack_args
{
    struct sockaddr_in* addr;
    int sd;
};

struct pseudo_header
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;

    struct tcphdr tcp;
};

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

/*
   Checksums - IP and TCP
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

void * receive_ack( void *ptr ) {
    struct syn_ack_args* args = (struct syn_ack_args*) ptr;

    struct sockaddr_in* servaddr = args->addr;
    struct iphdr *iph_r;
    struct tcphdr *tcph_r;

    struct sockaddr saddr;
    struct sockaddr_in source;

    unsigned char* buffer = (unsigned char*)malloc(65536);
    int data_size, saddr_size = sizeof(saddr);
    int sock_raw = args->sd;

    if (sock_raw < 0) {
        print_err2("socket creation failed. ", strerror(errno));
        goto FREE_MALLOC;
    }

    while(!intterupter.done) {
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
        if( intterupter.done ) break;
        if(data_size < 0 )
        {
            print_err("Recvfrom error , failed to get packets.");
            break;
        }

        iph_r = (struct iphdr*)buffer;

        if (iph_r->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph_r=(struct tcphdr*)(buffer + iph_r->ihl * 4);

            memset(&source, 0, sizeof(source));
            source.sin_addr.s_addr = iph_r->saddr;

            if(tcph_r->syn == 1 && tcph_r->ack == 1 && source.sin_addr.s_addr == servaddr->sin_addr.s_addr )
            {
                print_status(ntohs(tcph_r->source),"open");
            }
        }
    }



    close(sock_raw);
FREE_MALLOC:
    free(buffer);
}

void* receive_rst(void* ptr) {
    struct sockaddr_in* servaddr = (struct sockaddr_in*)ptr;
    struct iphdr *iph_r;
    struct tcphdr *tcph_r;

    struct sockaddr saddr;
    struct sockaddr_in source;

    unsigned char* buffer = (unsigned char*)malloc(65536);
    int data_size, saddr_size = sizeof(saddr);
    int sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if (sock_raw < 0) {
        print_err2("socket creation failed", strerror(errno));
        goto FREE_MALLOC;
    }

    while(1) {
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);

        if(data_size < 0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            break;
        }

        iph_r = (struct iphdr*)buffer;

        if (iph_r->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph_r=(struct tcphdr*)(buffer + iph_r->ihl * 4);

            memset(&source, 0, sizeof(source));
            source.sin_addr.s_addr = iph_r->saddr;

            /*printf("Received from socket %d, %d\n", tcph_r->syn, tcph_r->rst);*/

            if(tcph_r->fin == 1 && !(tcph_r->rst == 1) && source.sin_addr.s_addr == servaddr->sin_addr.s_addr )
            {
                print_status(ntohs(tcph_r->source),"open");
            }
        }
    }

    close(sock_raw);
FREE_MALLOC:
    free(buffer);
}

int syn_ack_scan(struct sockaddr_in* servaddr) {
    int source_port = 43591;
    char source_ip[20];
    char datagram[4096];
    struct iphdr *iph = (struct iphdr *) datagram;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
    struct pseudo_header psh;
    pthread_t receiver_thread,int_thread;
    struct  syn_ack_args args;

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd == -1) {
        printf(RED"[Error] tcp socket creation failed... for port %d, %s\n", ntohs(servaddr->sin_port), strerror(errno));
        return 0;
    }

    get_local_ip(source_ip);

    memset(datagram, 0, 4096);
    //Set the miscellaneous ip header fields.
    set_iphdr(iph,&source_ip,servaddr);

    //Set the miscellaneous tcp header fields
    set_tcphdr(tcph, source_port,1);

    {
        int one = 1;
        const int *val = &one;

        if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
        {
            print_err2("Fatal error setting IP_HDRINCL ", strerror(errno));
            exit(1);
        }
    }

    {
        args.addr =  servaddr;
        int sd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        args.sd = sd;
        initInt(&intterupter,sd,5);
        if(pthread_create(&receiver_thread, NULL, receive_ack, (void*)&args) < 0) {
            print_err2("Fatal can't create reciever thread" , strerror(errno));
            exit(1);
        }
        if( pthread_create(&int_thread, NULL, intterupter.stopListening,(void*)&intterupter) < 0 ){
            print_err2("Fatal can't create intterupting thread " , strerror(errno));
            exit(1);
        }
        pthread_detach(int_thread);
    }

    for(int i = 0;i < 65536; ++i) {
        tcph->dest = htons(i);
        tcph->check = 0;

        psh.source_address = iph->saddr;
        psh.dest_address = servaddr->sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons( sizeof(struct tcphdr) );

        memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));

        tcph->check = csum( (unsigned short*) &psh , sizeof (struct pseudo_header));

        if ( sendto (sockfd, datagram , sizeof(struct iphdr) + sizeof(struct tcphdr) , 0 , (struct sockaddr *)servaddr, sizeof(*servaddr)) < 0)
        {
            print_err2("error sending syn packet " , strerror(errno));
            continue;
        }
    }

    close(sockfd);


    pthread_join(receiver_thread , NULL);

    return 1;
}

int fin_scan(struct sockaddr_in* servaddr) {
    int source_port = 43591;
    char source_ip[20];
    char datagram[4096];
    struct iphdr *iph = (struct iphdr *) datagram;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
    struct pseudo_header psh;

    pthread_t receiver_thread;

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd == -1) {
        printf(RED"[Error] tcp socket creation failed... for port %d, %s\n", ntohs(servaddr->sin_port), strerror(errno));
        return 0;
    }

    get_local_ip(source_ip);

    memset(datagram, 0, 4096);

    //Set the miscellaneous ip header fields.
    set_iphdr(iph,&source_ip,servaddr);

    //Set the miscellaneous tcp header fields
    set_tcphdr(tcph, source_port,0);

    {
        int one = 1;
        const int *val = &one;

        if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
        {
            print_err2("Fatal error setting IP_HDRINCL, " , strerror(errno));
            exit(1);
        }
    }

    {
        if(pthread_create(&receiver_thread, NULL, receive_rst, (void*)servaddr) < 0) {
            print_err2("Fatal can't create reciever thread, " , strerror(errno));
        }
    }

    for(int i = 0;i < 65536; ++i) {
        tcph->dest = htons(i);
        tcph->check = 0;

        psh.source_address = iph->saddr;
        psh.dest_address = servaddr->sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons( sizeof(struct tcphdr) );

        memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));

        tcph->check = csum( (unsigned short*) &psh , sizeof (struct pseudo_header));

        if ( sendto (sockfd, datagram , sizeof(struct iphdr) + sizeof(struct tcphdr) , 0 , (struct sockaddr *)servaddr, sizeof(*servaddr)) < 0)
        {
            print_err2("error sending syn packet " , strerror(errno));
            continue;
        }
    }

    close(sockfd);


    pthread_join(receiver_thread , NULL);

    return 1;
}

int is_tcp_port_open(struct sockaddr_in* servaddr) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd == -1) {
        printf(RED"[Error] tcp socket creation failed... for port %d, %s\n", ntohs(servaddr->sin_port), strerror(errno));
        return 0;
    }

    struct linger sl;
    sl.l_onoff = 1;
    sl.l_linger = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));

    if (connect(sockfd, (struct sockaddr*)servaddr, sizeof(*servaddr)) != 0) {
        return 0;
    }

    if (shutdown(sockfd, SHUT_RDWR) != 0)
        perror("shutdown");

    close(sockfd);

    return 1;
}

int is_udp_port_open(struct sockaddr_in* servaddr) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (sockfd == -1) {
        printf(RED"[Error] udp socket creation failed... for port %d, %s\n", ntohs(servaddr->sin_port), strerror(errno));
        return 0;
    }

    if (connect(sockfd, (struct sockaddr*)servaddr, sizeof(*servaddr)) != 0) {
        return 1;
    }

    close(sockfd);

    return 0;
}

int main(int argc, char** args) {
    struct sockaddr_in servaddr;
    struct addrinfo hints, *res;

    if (argc < 2) {
        printf("Usage: %s [target_ip]\n", args[0]);
        return -1;
    }

    memset(&servaddr, 0, sizeof(servaddr));

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;

    if (inet_addr(args[1]) != -1) {
        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = inet_addr(args[1]);
    }
    else if (getaddrinfo (args[1], NULL, &hints, &res) == 0) {
        servaddr = *(struct sockaddr_in*)res->ai_addr;
    }
    else {
        print_err("Provided ip or hostname is invalid.");
        return 1;
    }

    syn_ack_scan(&servaddr);

    /*for(int i = 1; i < 65536; ++i) {
      servaddr.sin_port   = htons(i);

      if (is_tcp_port_open(&servaddr)) {
      printf("Port %d is open\n", i);
      }

      if(is_udp_port_open(&servaddr))  {
      printf("Port %d is open\n", i);
      }
      }*/

    return 0;
}

