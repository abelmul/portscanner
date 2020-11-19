#ifndef SYN_SCAN_H
#define SYN_SCAN_H

struct syn_ack_args
{
    struct sockaddr_in* addr;
    int sd;
    Interrupter* intterupter;
};

void * receive_ack( void *ptr );

void syn_ack_scan(struct sockaddr_in* servaddr, int port) {
    print_msg("Doing a SYN scan.");
    
    Interrupter intterupter;
    int source_port = 43591;
    char source_ip[20];
    char datagram[4096];
    struct iphdr *iph = (struct iphdr *) datagram;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
    struct pseudo_header psh;
    pthread_t receiver_thread,int_thread;
    struct  syn_ack_args args;

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd == -1) {
        printf(RED"[Error] tcp socket creation failed... for port %d, %s\n", ntohs(servaddr->sin_port), strerror(errno));
        exit(-1);
    }

    get_local_ip(source_ip);

    memset(datagram, 0, 4096);
    //Set the miscellaneous ip header fields.
    set_iphdr(iph,&source_ip,servaddr);

    //Set the miscellaneous tcp header fields
    set_tcphdr(tcph, source_port,1);

    {
        int one = 1;
        const int *val = &one;

        if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
        {
            print_err2("Fatal error setting IP_HDRINCL ", strerror(errno));
            exit(1);
        }
    }

    {
        args.addr =  servaddr;
        int sd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        args.sd = sd;
        args.intterupter = &intterupter;
        initInt(&intterupter,sd,2000);
        if(pthread_create(&receiver_thread, NULL, receive_ack, (void*)&args) < 0) {
            print_err2("Fatal can't create reciever thread" , strerror(errno));
            exit(1);
        }
        if( pthread_create(&int_thread, NULL, intterupter.stopListening,(void*)&intterupter) < 0 ){
            print_err2("Fatal can't create intterupting thread " , strerror(errno));
            exit(1);
        }
        pthread_detach(int_thread);
    }

    for(int i = 0;i < 65536; ++i) {
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
            print_err2("error sending syn packet " , strerror(errno));
            continue;
        }
    }

    close(sockfd);
    pthread_join(receiver_thread , NULL);
}

/**
 * Start a listening server and wait for an ACK if any is sent.
 */
void * receive_ack( void *ptr ) {
    struct syn_ack_args* args = (struct syn_ack_args*) ptr;

    struct sockaddr_in* servaddr = args->addr;
    struct iphdr *iph_r;
    struct tcphdr *tcph_r;

    struct sockaddr saddr;
    struct sockaddr_in source;

    struct set port_set = new_set();

    unsigned char* buffer = (unsigned char*)malloc(65536);
    int data_size, saddr_size = sizeof(saddr);
    int sock_raw = args->sd;

    if (sock_raw < 0) {
        print_err2("socket creation failed. ", strerror(errno));
        goto FREE_MALLOC;
    }

    while(!args->intterupter->done) {
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
        if( args->intterupter->done ) break;
        if(data_size < 0 )
        {
            print_err("Recvfrom error , failed to get packets.");
            break;
        }

        iph_r = (struct iphdr*)buffer;

        if (iph_r->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph_r=(struct tcphdr*)(buffer + iph_r->ihl * 4);

            memset(&source, 0, sizeof(source));
            source.sin_addr.s_addr = iph_r->saddr;

            if(tcph_r->syn == 1 && tcph_r->ack == 1 && source.sin_addr.s_addr == servaddr->sin_addr.s_addr )
            {
                store(&port_set, ntohs(tcph_r->source));
            }
        }
    }

    for(int i = 1; i < 65536; ++i) {
        if (port_set.array[i] == 1)
            print_status(i,"open");
    }


    close(sock_raw);
FREE_MALLOC:
    destroy(&port_set);
    free(buffer);
}
#endif
