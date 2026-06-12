#include "util.h"

void rand_bytes(uint8_t *buf, size_t n) {
#ifdef _WIN32
    HCRYPTPROV hProv;
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(hProv, (DWORD)n, buf);
        CryptReleaseContext(hProv, 0);
    } else {
        for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)(rand() & 0xFF);
    }
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        if (fread(buf, 1, n, f) != n)
            for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)(rand() & 0xFF);
        fclose(f);
    } else {
        for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)(rand() & 0xFF);
    }
#endif
}

void get_timestamp(char *buf, size_t sz) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(buf, sz, "%Y/%m/%d %H:%M:%S", t);
}

long get_ms_diff(struct timeval *t0, struct timeval *t1) {
    return (t1->tv_sec  - t0->tv_sec)  * 1000L
         + (t1->tv_usec - t0->tv_usec) / 1000L;
}

void get_time_now(struct timeval *tv) {
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    unsigned __int64 tmp = ((unsigned __int64)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    tmp /= 10;
    tmp -= 11644473600000000ULL;
    tv->tv_sec  = (long)(tmp / 1000000ULL);
    tv->tv_usec = (long)(tmp % 1000000ULL);
#else
    gettimeofday(tv, NULL);
#endif
}

bool parse_hex(const char *s, uint8_t *out, int n) {
    if ((int)strlen(s) != n * 2) return false;
    for (int i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(s + i*2, "%02x", &v) != 1) return false;
        out[i] = (uint8_t)v;
    }
    return true;
}

void bytes_to_hex(char *dst, const uint8_t *src, int len) {
    for (int i = 0; i < len; i++) snprintf(dst + i*2, 3, "%02X", src[i]);
    dst[len*2] = '\0';
}

int recv_all(sock_t fd, void *buf, int len) {
    uint8_t *p = (uint8_t *)buf;
    int total = 0;
    while (total < len) {
        int n = (int)recv(fd, (char *)p + total, len - total, 0);
        if (n <= 0) return -1;
        total += n;
    }
    return total;
}

int send_all(sock_t fd, const void *buf, int len) {
    const uint8_t *p = (const uint8_t *)buf;
    int total = 0;
    while (total < len) {
        int n = (int)send(fd, (const char *)p + total, len - total, 0);
        if (n <= 0) return -1;
        total += n;
    }
    return total;
}

sock_t connect_server(const char *host, int port) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return SOCK_INVALID;
    sock_t fd = socket(res->ai_family, SOCK_STREAM, 0);
    if (fd == SOCK_INVALID) { freeaddrinfo(res); return SOCK_INVALID; }
#ifdef _WIN32
    int tv = 10000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv));
#else
    struct timeval tv = {10, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
    if (connect(fd, res->ai_addr, (int)res->ai_addrlen) != 0) {
        sock_close(fd); freeaddrinfo(res); return SOCK_INVALID;
    }
    freeaddrinfo(res);
    return fd;
}
