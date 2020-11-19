#ifndef UDP_CONNECT_H
#define UDP_CONNECT_H
#include <netinet/ip_icmp.h> 
#include "utils.h"

struct udp_args {
    int recvfd;
    int port;
    struct sockaddr_in* servaddr;
    Interrupter* intr;

    unsigned char rcvd_msg;
};

void* recieve_icmp(void* ptr);
void* recieve_udp(void* ptr);

/**
 * Do a UDP port scan.
 */
void udp_cnct_scan(struct sockaddr_in* servaddr, int port) {
    print_msg("Doing a UPD Connect Scan.");

    if( port == -1 ){
        print_err("Please specify the udp port to scan.");
        print_usage();
        exit(-1);
    }

    char msg[] = "\xff\xffport scanner\x5f\x5f";
    Interrupter intr,intr2;
    struct udp_args args, args2;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY; 
    addr.sin_port = htons( 43593 ); 

    args2.servaddr = args.servaddr = servaddr;
    args.intr  = &intr;
    args.intr = &intr2;


    pthread_t th, th2;
    servaddr->sin_port   = htons(port);

    int opt = 1;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    int recvfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    int recvfd2 = socket(AF_INET, SOCK_DGRAM, 0);

    if (sockfd == -1) {
        printf(RED"[Error] udp socket creation failed... for port %d, %s\n", ntohs(servaddr->sin_port), strerror(errno));
        exit(-1);
    }

    if (recvfd == -1) {
        printf(RED"[Error] icmp socket creation failed... for port %d, %s\n", ntohs(servaddr->sin_port), strerror(errno));
        exit(-1);
    }

    if (recvfd2 == -1) {
        printf(RED"[Error] udp socket creation failed... for port %d, %s\n", ntohs(servaddr->sin_port), strerror(errno));
        exit(-1);
    }


    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(recvfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(recvfd2, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if ( bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) ||  bind(recvfd, (struct sockaddr *)&addr, sizeof(addr)) || bind(recvfd2, (struct sockaddr *)&addr, sizeof(addr))) {
        print_err2("Bind failed!", strerror(errno));
        close(recvfd);
        close(sockfd);
        return;
    }

    args.recvfd = recvfd;
    args2.recvfd = recvfd2;
    args2.port = args.port = port;

    if (pthread_create(&th, NULL, recieve_icmp, (void*)&args) != 0) {
        print_err2("Failed to create reciever thread, ", strerror(errno));
        exit(-1);
    }

    if (pthread_create(&th2, NULL, recieve_udp, (void*)&args2) != 0) {
        print_err2("Failed to create reciever thread, ", strerror(errno));
        exit(-1);
    }

    // send three times
    if(sendto(sockfd, msg, sizeof(msg), 0, (struct sockaddr*)servaddr, sizeof(*servaddr))  < 0) {
        print_err2("Send failed ", strerror(errno));
        close(recvfd);
        close(sockfd);
        return;
    }
    sendto(sockfd, msg, sizeof(msg), 0, (struct sockaddr*)servaddr, sizeof(*servaddr));
    sendto(sockfd, msg, sizeof(msg), 0, (struct sockaddr*)servaddr, sizeof(*servaddr));


    pthread_join(th, NULL);
    pthread_join(th2, NULL);

    if (args.rcvd_msg == 0 && args2.rcvd_msg == 0) {
        print_status(port, "open|filtered");
    }

    close(recvfd);
    close(sockfd);
}

void* recieve_icmp(void* ptr) {
    char* msg2 = (char*)malloc(4096);
    socklen_t servlen = sizeof(struct sockaddr_in);

    struct udp_args* args = (struct udp_args*)ptr;
    pthread_t th;

    Interrupter* intr = args->intr;
    initInt(intr,args->recvfd,500);

    if(pthread_create(&th, NULL, intr->stopListening, (void*)intr) != 0) {
        print_err2("Failed to create intre thread, ", strerror(errno));
        exit(-1);
    }
    pthread_detach(th);

    if (recvfrom(args->recvfd, msg2, sizeof(msg2), 0, (struct sockaddr*) args->servaddr, &servlen) > 0) {
        // look at the icmp header here.
        struct icmphdr* icmph = (struct icmphdr*)(msg2 + sizeof(struct iphdr));

        if (icmph->type == ICMP_UNREACH) {
            switch(icmph->code) {
                case ICMP_UNREACH_PORT:
                    // port is closed
                    break;
                case ICMP_UNREACH_HOST:
                case ICMP_UNREACH_PROTOCOL:
                case ICMP_UNREACH_NET_PROHIB:
                case ICMP_UNREACH_HOST_PROHIB:
                case ICMP_UNREACH_FILTER_PROHIB:
                    print_status(args->port, "filtered");
            }
        }
        args->rcvd_msg = 1;
    }
    else {
        args->rcvd_msg = 0;
    }

    free(msg2);
}

void* recieve_udp(void* ptr) {
    char* msg2 = (char*)malloc(4096);
    socklen_t servlen = sizeof(struct sockaddr_in);

    struct udp_args* args = (struct udp_args*)ptr;
    pthread_t th;

    Interrupter* intr = args->intr;
    initInt(intr,args->recvfd,500);

    if(pthread_create(&th, NULL, intr->stopListening, (void*)intr) != 0) {
        print_err2("Failed to create intre thread, ", strerror(errno));
        exit(-1);
    }
    pthread_detach(th);

    if (recvfrom(args->recvfd, msg2, sizeof(msg2), 0, (struct sockaddr*) args->servaddr, &servlen) > 0) {
        // look at the icmp header here.
        print_status(args->port, "open");
        args->rcvd_msg = 1;
    }
    else {
        args->rcvd_msg = 0;
    }

    free(msg2);
}

#endif
