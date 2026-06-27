#ifndef WORKER_H
#define WORKER_H

#include "platform.h"
#include "newcamd.h"

typedef struct {
    nc_params_t  params;
    volatile int stop;
} worker_ctx_t;

THREAD_RET worker_thread(THREAD_ARG arg);

void     rand_bytes(uint8_t *buf, size_t n);
void     get_timestamp(char *buf, size_t sz);
long     get_ms_diff(struct timeval *t0, struct timeval *t1);
void     get_time_now(struct timeval *tv);
bool     parse_hex(const char *s, uint8_t *out, int n);
void     bytes_to_hex(char *dst, const uint8_t *src, int len);
void     secure_zero(void *ptr, size_t len);
int      recv_all(sock_t fd, void *buf, int len);
int      send_all(sock_t fd, const void *buf, int len);
sock_t   connect_server(const char *host, int port);
void     tvcas4_to_v3(const uint8_t *key4, uint8_t *key3, size_t len);

#endif
