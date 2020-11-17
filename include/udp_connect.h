#ifndef UDP_CONNECT_H
#define UDP_CONNECT_H
#include "utils.h"
/**
 * Do a UDP port scan.
 */
void udp_cnct_scan(struct sockaddr_in* servaddr) {
    print_msg("Doing a UPD Connect Scan.");
    char msg[] = "\xff\xffport scanner\x5f\x5f";
    char msg2[4096];

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY; 
    addr.sin_port = htons( 43593 ); 

    for(int i = 1; i < 65536; ++i){
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

        Interrupter intr;
        initInt &intr, recvfd, 3000);

        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        setsockopt(recvfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        if ( bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) ||  bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) ) {
            print_err2("Bind failed!", strerror(errno));
            close(recvfd);
            close(sockfd);
            continue;
        }

        if(sendto(sockfd, msg, sizeof(msg), 0, (struct sockaddr*)servaddr, sizeof(*servaddr))  < 0) {
            print_err2("Send failed ", strerror(errno));
            close(recvfd);
            close(sockfd);
            continue;
        }

        pthread_t th;
        if(pthread_create(&th, NULL, intr.stopListening, (void*)&intr) != 0) {
            print_err2("Failed to create intre thread, ", strerror(errno));
            exit(-1);
        }

        if (recvfrom(recvfd, msg2, sizeof(msg2), 0, (struct sockaddr*) servaddr, sizeof(*servaddr)) == 0) {
        }


        close(recvfd);
        close(sockfd);
    }
}
#endif
