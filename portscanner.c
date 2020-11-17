#include "utils.h"
#include "fin_scan.h"
#include "syn_scan.h"
#include "tcp_connect.h"
#include "udp_connect.h"

int main(int argc, char** args) {
    scanner scanners[4] = {tcp_cnct_scan, udp_cnct_scan,syn_ack_scan,fin_scan};
    struct sockaddr_in servaddr;
    struct addrinfo hints, *res;

    if (argc != 3) {
        print_usage();
        return -1;
    }

    memset(&servaddr, 0, sizeof(servaddr));

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;

    if (inet_addr(args[2]) != -1) {
        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = inet_addr(args[2]);
    }
    else if (getaddrinfo (args[2], NULL, &hints, &res) == 0) {
        servaddr = *(struct sockaddr_in*)res->ai_addr;
        printf("Resolved %s to %s\n", args[2], inet_ntoa(servaddr.sin_addr));
    }
    else {
        print_err("Provided ip or hostname is invalid.");
        return 1;
    }

    //Call the corresponding scanner.
    scanners[ get_type(args[1]) ](&servaddr);

    return 0;
}
