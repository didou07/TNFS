#ifndef UTIL_H
#define UTIL_H

#include "platform.h"

void     rand_bytes(uint8_t *buf, size_t n);
void     get_timestamp(char *buf, size_t sz);
long     get_ms_diff(struct timeval *t0, struct timeval *t1);
void     get_time_now(struct timeval *tv);
bool     parse_hex(const char *s, uint8_t *out, int n);
void     bytes_to_hex(char *dst, const uint8_t *src, int len);
int      recv_all(sock_t fd, void *buf, int len);
int      send_all(sock_t fd, const void *buf, int len);
sock_t   connect_server(const char *host, int port);

#endif
