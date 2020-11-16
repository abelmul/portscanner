#ifndef TCP_CONNECT_H
#define TCP_CONNECT_H
#include "utils.h"
/**
 * Try to initiate a full TCP connection .
 */
void tcp_cnct_scan(struct sockaddr_in* servaddr) {
    print_msg("Doing a TCP Connect Scan.");
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY; 
    addr.sin_port = htons( 43592 ); 
    int opt=1;
    for(int i = 1; i < 65536; ++i){
        servaddr->sin_port   = htons(i);
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        struct linger sl;
        sl.l_onoff = 1;
        sl.l_linger = 0;
        setsockopt(sockfd, SOL_SOCKET, SO_LINGER | SO_REUSEADDR, &sl, sizeof(sl));

        if( bind( sockfd, (struct sockaddr *)&addr,sizeof(addr)) ){
            close(sockfd);
            print_err2("Bind failed!",strerror(errno));
            continue;
        }
        if (sockfd == -1) {
            printf(RED"[Error] tcp socket creation failed... for port %d, %s\n", ntohs(servaddr->sin_port), strerror(errno));
            exit(-1);
        }

        Interrupter intr;
        initInt(&intr, sockfd, 100);
        pthread_t th;
        if(pthread_create(&th, NULL, intr.stopListening, (void*)&intr) != 0) {
            print_err2("Failed to create intre thread, ", strerror(errno));
            exit(-1);
        }

        if (connect(sockfd, (struct sockaddr*)servaddr, sizeof(*servaddr)) == 0){
            print_status(i,"open");
            if (shutdown(sockfd, SHUT_RDWR) != 0)
                perror("shutdown");
        }
        close(sockfd);
    }
}

#endif
