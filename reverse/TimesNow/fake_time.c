// fake_time.c
#define _GNU_SOURCE
#include <time.h>
#include <stdio.h>

time_t time(time_t *tloc) {
    time_t fake_time = 1751634980;  

    if (tloc) {
        *tloc = fake_time;
    }

    printf("[LD_PRELOAD] time() called, returning 0x%lx\n", fake_time);
    return fake_time;
}