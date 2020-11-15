#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <pthread.h>

struct pseudo_header
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;

    struct tcphdr tcp;
};

int get_local_ip ( char * buffer)
{
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
unsigned short csum(unsigned short *ptr,int nbytes) 
{
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

int syn_ack_scan(struct sockaddr_in* servaddr) {
    int source_port = 43591;
    char source_ip[20];
    char datagram[4096];
    struct iphdr *iph = (struct iphdr *) datagram;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
    struct pseudo_header psh;

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd == -1) { 
        printf("tcp socket creation failed... for port %d, %s\n", ntohs(servaddr->sin_port), strerror(errno)); 
        return 0;
    }

    get_local_ip(source_ip);

    memset(datagram, 0, 4096);

    {
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
        iph->id = htons (54321);
        iph->frag_off = htons(16384);
        iph->ttl = 64;
        iph->protocol = IPPROTO_TCP;
        iph->check = 0;	
        iph->saddr = inet_addr (source_ip);
        iph->daddr = servaddr->sin_addr.s_addr;
    }

    {
        tcph->dest = htons (80);
        tcph->seq = htonl(1105024978);
        tcph->ack_seq = 0;
        tcph->doff = sizeof(struct tcphdr) / 4;		//Size of tcp header
        tcph->fin=0;
        tcph->syn=1;
        tcph->rst=0;
        tcph->psh=0;
        tcph->ack=0;
        tcph->urg=0;
        tcph->window = htons ( 14600 );
        tcph->check = 0;
        tcph->urg_ptr = 0;
    }

    {
        int one = 1;
        const int *val = &one;

        if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
        {
            printf ("Fatal error setting IP_HDRINCL,%s \n", strerror(errno));
            exit(1);
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
            printf("error sending syn packet, %s \n",  strerror(errno));
            continue;
        }

        struct iphdr *iph_r;
        struct tcphdr *tcph_r;

        struct sockaddr saddr; 
        struct sockaddr_in source;
        unsigned char* buffer = (unsigned char*)malloc(65536);
        int data_sie, saddr_size = sizeof(saddr);
        int sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

        if (sock_raw < 0) {
            printf("socket creation failed, %s\n", strerror(errno));
            goto FREE_MALLOC;
        }
        int data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);

        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            goto CLOSE_SOCKET;
        }

        iph_r = (struct iphdr*)buffer;

        if (iph_r->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph_r=(struct tcphdr*)(buffer + iph_r->ihl * 4);

            memset(&source, 0, sizeof(source));
            source.sin_addr.s_addr = iph_r->saddr;

            if(tcph_r->syn == 1 && tcph_r->ack == 1 && source.sin_addr.s_addr == servaddr->sin_addr.s_addr )
            {
                printf("Port %d open \n" , ntohs(tcph->source));
                fflush(stdout);
            }
        }



CLOSE_SOCKET:
        close(sock_raw);
FREE_MALLOC:
        free(buffer);
    }

    close(sockfd);

    return 1;
}

int is_tcp_port_open(struct sockaddr_in* servaddr) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd == -1) { 
        printf("tcp socket creation failed... for port %d, %s\n", ntohs(servaddr->sin_port), strerror(errno)); 
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
        printf("udp socket creation failed... for port %d, %s\n", ntohs(servaddr->sin_port), strerror(errno)); 
        return 0;
    }

    if (connect(sockfd, (struct sockaddr*)servaddr, sizeof(*servaddr)) != 0) {
        return 1;
    }

    close(sockfd);

    return 0;
}

int main(int argv, char** args) {
    struct sockaddr_in servaddr;
    struct addrinfo hints, *res;

    if (argv < 2) {
        printf("Please pass the ip to be port scanned\n");
        return 1;
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
        printf("Provided ip or hostname is invalid\n");
        return 1;
    }

    syn_ack_scan(&servaddr);

    /*for(int i = 1; i < 65536; ++i) {*/
        /*servaddr.sin_port   = htons(i);*/

        /*[>if (is_tcp_port_open(&servaddr)) {<]*/
        /*[>printf("Port %d is open\n", i);<]*/
        /*[>}<]*/

        /*if(is_udp_port_open(&servaddr))  {*/
            /*printf("Port %d is open\n", i);*/
        /*}*/
    /*}*/

    return 0;
}

