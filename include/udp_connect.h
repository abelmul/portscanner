#ifndef UDP_CONNECT_H
#define UDP_CONNECT_H
#include <netinet/ip_icmp.h> 
#include "utils.h"

struct udp_args {
    int recvfd;
    int port;
    struct sockaddr_in* servaddr;
};

void* recieve_icmp(void* ptr);

/**
 * Do a UDP port scan.
 */
void udp_cnct_scan(struct sockaddr_in* servaddr) {
    print_msg("Doing a UPD Connect Scan.");
    char msg[] = "\xff\xffport scanner\x5f\x5f";

    struct udp_args args;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY; 
    addr.sin_port = htons( 43593 ); 

    args.servaddr = servaddr;


    for(int i = 1; i < 65536; ++i){
        pthread_t th;
        servaddr->sin_port   = htons(i);

        int opt = 1;
        int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        int recvfd   = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

        if (sockfd == -1) {
            printf(RED"[Error] udp socket creation failed... for port %d, %s\n", ntohs(servaddr->sin_port), strerror(errno));
            exit(-1);
        }

        if (recvfd == -1) {
            printf(RED"[Error] icmp socket creation failed... for port %d, %s\n", ntohs(servaddr->sin_port), strerror(errno));
            exit(-1);
        }


        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        setsockopt(recvfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        if ( bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) ||  bind(recvfd, (struct sockaddr *)&addr, sizeof(addr)) ) {
            print_err2("Bind failed!", strerror(errno));
            close(recvfd);
            close(sockfd);
            continue;
        }

        args.recvfd = recvfd;
        args.port = i;

        if (pthread_create(&th, NULL, recieve_icmp, (void*)&args) != 0) {
            print_err2("Failed to create reciever thread, ", strerror(errno));
            exit(-1);
        }

        // send three times
        if(sendto(sockfd, msg, sizeof(msg), 0, (struct sockaddr*)servaddr, sizeof(*servaddr))  < 0) {
            print_err2("Send failed ", strerror(errno));
            close(recvfd);
            close(sockfd);
            continue;
        }
        sendto(sockfd, msg, sizeof(msg), 0, (struct sockaddr*)servaddr, sizeof(*servaddr));
        sendto(sockfd, msg, sizeof(msg), 0, (struct sockaddr*)servaddr, sizeof(*servaddr));


        pthread_join(th, NULL);

        close(recvfd);
        close(sockfd);
    }
}

void* recieve_icmp(void* ptr) {
    char* msg2 = (char*)malloc(4096);
    socklen_t servlen = sizeof(struct sockaddr_in);

    struct udp_args* args = (struct udp_args*)ptr;
    pthread_t th;

    Interrupter intr;
    initInt(&intr,args->recvfd,500);

    if(pthread_create(&th, NULL, intr.stopListening, (void*)&intr) != 0) {
        print_err2("Failed to create intre thread, ", strerror(errno));
        exit(-1);
    }
    pthread_detach(th);

    if (recvfrom(args->recvfd, msg2, sizeof(msg2), 0, (struct sockaddr*) args->servaddr, &servlen) == 0) {
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
    }

    free(msg2);
}

#endif
