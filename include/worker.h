#ifndef WORKER_H
#define WORKER_H

#include "platform.h"
#include "newcamd.h"

typedef struct {
    nc_params_t params;
    volatile int stop;
} worker_ctx_t;

THREAD_RET worker_thread(THREAD_ARG arg);

#endif
