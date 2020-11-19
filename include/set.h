#ifndef SET_H
#define SET_H
#include <stdlib.h>

struct set {
    char* array;
};

struct set new_set() {
    struct set s;
    s.array = (char*)calloc(65536, sizeof(char));

    return s;
}

void store(struct set* s, int port) {
    if (port < 65536)
        s->array[port] = 1;
}

void destroy(struct set* s) {
    free(s->array);
}

#endif
