#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>

int is_tcp_port_open(struct sockaddr_in* servaddr) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd == -1) { 
        printf("tcp socket creation failed... for port %d, %s\n", ntohs(servaddr->sin_port), strerror(errno)); 
        return 0;
    }

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

    if (argv < 2) {
        printf("Please pass the ip to be port scanned\n");
        return 1;
    }

    memset(&servaddr, 0, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(args[1]);

    for(int i = 1; i < 65536; ++i) {
        servaddr.sin_port   = htons(i);

        if (is_tcp_port_open(&servaddr)) {
            printf("Port %d is open\n", i);
        }

        else if(is_udp_port_open(&servaddr))  {
            printf("Port %d is open\n", i);
        }
    }

    return 0;
}

