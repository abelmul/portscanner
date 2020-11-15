#ifndef UTILS_PSC_H
#define UTILS_PSC_H

#include "pthread.h"
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>


typedef struct 
{
    uint8_t done;
    int sd;
    int period;
    void* (*stopListening)(void*);
}Interrupter;

void* stopListening(void* p){
    Interrupter* self = (Interrupter*)p;
    sleep(self->period);
    printf("Done scanning, Exiting...\n");
    self->done = 1;
    shutdown(self->sd,SHUT_RDWR);
}

void initInt(Interrupter* intr,int sd, int period){
    intr->sd = sd;
    intr->stopListening = stopListening;
    intr->done = 0;
    intr->period = period;
}
Interrupter intterupter;
#endif
