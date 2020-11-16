#include "utils.h"
#include "fin_scan.h"
#include "syn_scan.h"
#include "tcp_connect.h"
#include "udp_connect.h"

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

    tcp_cnct_scan(&servaddr);
    // syn_ack_scan(&servaddr);
    // fin_scan(&servaddr);
    return 0;
}

