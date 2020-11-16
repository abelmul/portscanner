#ifndef UDP_CONNECT_H
#define UDP_CONNECT_H
#include "utils.h"
/**
 * Do a UDP port scan.
 */
int udp_cnct_scan(struct sockaddr_in* servaddr) {
    print_msg("Doing a UPD Connect Scan.");
    for(int i = 1; i < 65536; ++i){
        servaddr->sin_port   = htons(i);
        int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd == -1) {
            printf(RED"[Error] udp socket creation failed... for port %d, %s\n", ntohs(servaddr->sin_port), strerror(errno));
            return 0;
        }

        if (connect(sockfd, (struct sockaddr*)servaddr, sizeof(*servaddr)) != 0) 
            print_status(i, "open");
        

        close(sockfd);
    }
    return 0;
}
#endif