#ifndef TCP_CONNECT_H
#define TCP_CONNECT_H
#include "utils.h"
/**
 * Try to initiate a full TCP connection .
 */
int tcp_cnct_scan(struct sockaddr_in* servaddr) {
    print_msg("Doing a TCP Connect Scan.");
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

#endif