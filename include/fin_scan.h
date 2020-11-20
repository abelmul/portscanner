#ifndef FIN_SCAN_H
#define FIN_SCAN_H
#include "utils.h"

void* receive_rst(void* ptr);

typedef struct fin_args
{
    struct sockaddr_in* addr;
    int* port_status;
    int this_port;
}fin_args;

void fin_scan(struct sockaddr_in* servaddr, int port) {
    print_msg("Doing a FIN scan.");
    int source_port = 43591;
    char source_ip[20];
    char datagram[4096];
    struct iphdr *iph = (struct iphdr *) datagram;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
    struct pseudo_header psh;

    pthread_t receiver_thread;

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd == -1) {
        printf(RED"[Error] tcp socket creation failed... for port %d, %s\n", ntohs(servaddr->sin_port), strerror(errno));
        exit(-1);
    }

    get_local_ip(source_ip);

    memset(datagram, 0, 4096);

    //Set the miscellaneous ip header fields.
    set_iphdr(iph,&source_ip,servaddr);

    //Set the miscellaneous tcp header fields
    set_tcphdr(tcph, source_port,0);

    {
        int one = 1;
        const int *val = &one;

        if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
        {
            print_err2("Fatal error setting IP_HDRINCL, " , strerror(errno));
            exit(1);
        }
    }

    fin_args args;
    args.addr = servaddr;
    args.port_status = calloc(65536,sizeof(int));
    args.this_port = source_port;
    if(pthread_create(&receiver_thread, NULL, receive_rst, (void*)&args) < 0) {
        print_err2("Fatal can't create reciever thread, " , strerror(errno));
    }
    int start = port == -1 ? 0 : port;
    int end = port == -1 ? 65536 : port+1;
    for (size_t k = 0; k < 5000;k++)
    {
        for(int i = start;i < end; ++i) {
            if( args.port_status[i] ) continue;
            for (size_t j = 0; j <5; j++)
            {
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
                    print_err2("error sending fin packet " , strerror(errno));
                    continue;
                }
            }   
        }
        if( k % 1000 == 0 ) sleep(1);
    }
    close(sockfd);
    pthread_join(receiver_thread , NULL);
    for (size_t i = start; i < end; i++)
    {
        if( args.port_status[i] == 0 )
            print_status(i, "open|filtered");
    }
    free( args.port_status);
}
/**
 * wait for a RST message.
 */
void* receive_rst(void* ptr) {
    fin_args* args = (fin_args*)ptr;
    struct sockaddr_in* servaddr = args->addr;
    struct iphdr *iph_r;
    struct tcphdr *tcph_r;

    struct sockaddr saddr;
    struct sockaddr_in source;

    unsigned char* buffer = (unsigned char*)malloc(65536);
    int data_size, saddr_size = sizeof(saddr);
    int sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if (sock_raw < 0) {
        print_err2("socket creation failed", strerror(errno));
        goto FREE_MALLOC;
    }
    
    Interrupter intr;
    initInt(&intr,sock_raw,20000);
    pthread_t th;
    if( pthread_create( &th, NULL, intr.stopListening, (void*)&intr) != 0){
        print_err2("Failed to create intre thread, ", strerror(errno));
        exit(-1);
    }
    pthread_detach(th);
    while(!intr.done) {
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
        if( intr.done) break;
        if(data_size < 0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            break;
        }

        iph_r = (struct iphdr*)buffer;

        if (iph_r->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph_r=(struct tcphdr*)(buffer + iph_r->ihl * 4);

            memset(&source, 0, sizeof(source));
            source.sin_addr.s_addr = iph_r->saddr;

            int dest_port = ntohs(tcph_r->dest);
            if(tcph_r->rst == 1 && source.sin_addr.s_addr == servaddr->sin_addr.s_addr && dest_port == args->this_port)
            {
                int port  = ntohs(tcph_r->source);
                args->port_status[port] = 1;
            }
        }
    }

    close(sock_raw);
FREE_MALLOC:
    free(buffer);
}

#endif
