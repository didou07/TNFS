#include "platform.h"
#include "newcamd.h"
#include "crypto.h"
#include "config.h"
#include "log.h"
#include "worker.h"

/* ── TVCAS key transform ── */

static const uint8_t TVCAS_CT[256] = {
    0xDA,0x26,0xE8,0x72,0x11,0x52,0x3E,0x46,0x32,0xFF,0x8C,0x1E,0xA7,0xBE,0x2C,0x29,
    0x5F,0x86,0x7E,0x75,0x0A,0x08,0xA5,0x21,0x61,0xFB,0x7A,0x58,0x60,0xF7,0x81,0x4F,
    0xE4,0xFC,0xDF,0xB1,0xBB,0x6A,0x02,0xB3,0x0B,0x6E,0x5D,0x5C,0xD5,0xCF,0xCA,0x2A,
    0x14,0xB7,0x90,0xF3,0xD9,0x37,0x3A,0x59,0x44,0x69,0xC9,0x78,0x30,0x16,0x39,0x9A,
    0x0D,0x05,0x1F,0x8B,0x5E,0xEE,0x1B,0xC4,0x76,0x43,0xBD,0xEB,0x42,0xEF,0xF9,0xD0,
    0x4D,0xE3,0xF4,0x57,0x56,0xA3,0x0F,0xA6,0x50,0xFD,0xDE,0xD2,0x80,0x4C,0xD3,0xCB,
    0xF8,0x49,0x8F,0x22,0x71,0x84,0x33,0xE0,0x47,0xC2,0x93,0xBC,0x7C,0x3B,0x9C,0x7D,
    0xEC,0xC3,0xF1,0x89,0xCE,0x98,0xA2,0xE1,0xC1,0xF2,0x27,0x12,0x01,0xEA,0xE5,0x9B,
    0x25,0x87,0x96,0x7B,0x34,0x45,0xAD,0xD1,0xB5,0xDB,0x83,0x55,0xB0,0x9E,0x19,0xD7,
    0x17,0xC6,0x35,0xD8,0xF0,0xAE,0xD4,0x2B,0x1D,0xA0,0x99,0x8A,0x15,0x00,0xAF,0x2D,
    0x09,0xA8,0xF5,0x6C,0xA1,0x63,0x67,0x51,0x3C,0xB2,0xC0,0xED,0x94,0x03,0x6F,0xBA,
    0x3F,0x4E,0x62,0x92,0x85,0xDD,0xAB,0xFE,0x10,0x2E,0x68,0x65,0xE7,0x04,0xF6,0x0C,
    0x20,0x1C,0xA9,0x53,0x40,0x77,0x2F,0xA4,0xFA,0x6D,0x73,0x28,0xE2,0xCD,0x79,0xC8,
    0x97,0x66,0x8E,0x82,0x74,0x06,0xC7,0x88,0x1A,0x4A,0x6B,0xCC,0x41,0xE9,0x9D,0xB8,
    0x23,0x9F,0x3D,0xBF,0x8D,0x95,0xC5,0x13,0xB9,0x24,0x5A,0xDC,0x64,0x18,0x38,0x91,
    0x7F,0x5B,0x70,0x54,0x07,0xB6,0x4B,0x0E,0x36,0xAC,0x31,0xE6,0xD6,0x48,0xAA,0xB4
};

static void tvcas_key_transform(uint8_t key[8], bool to_v4) {
    uint8_t bk[8] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
    if (to_v4) {
        for (int i1 = 7; i1 >= 0; i1--) {
            uint8_t carry = (bk[0] & 0x01) ? 0x80 : 0x00;
            for (int k = 0; k < 8; k++) {
                uint8_t next = (bk[k] & 0x01) ? 0x80 : 0x00;
                bk[k] = (bk[k] >> 1) | carry;
                carry = next;
            }
            for (int i2 = 7; i2 >= 0; i2--) {
                uint8_t t1 = TVCAS_CT[key[7] ^ bk[i2] ^ (uint8_t)i1];
                uint8_t t2 = key[0];
                for (int j = 0; j < 7; j++) key[j] = key[j+1];
                key[5] ^= t1;
                key[7] = t1 ^ t2;
            }
        }
    } else {
        for (int i1 = 0; i1 < 8; i1++) {
            for (int i2 = 0; i2 < 8; i2++) {
                uint8_t t1 = TVCAS_CT[key[7] ^ bk[i2] ^ (uint8_t)i1];
                uint8_t t2 = key[0];
                for (int j = 0; j < 7; j++) key[j] = key[j+1];
                key[5] ^= t1;
                key[7] = t1 ^ t2;
            }
            uint8_t carry = (bk[7] & 0x80) ? 0x01 : 0x00;
            for (int k = 0; k < 8; k++) {
                uint8_t next = (bk[k] & 0x80) ? 0x01 : 0x00;
                bk[k] = (bk[k] << 1) | carry;
                carry = next;
            }
        }
    }
}

void tvcas4_to_v3(const uint8_t *key4, uint8_t *key3, size_t len) {
    memcpy(key3, key4, len);
    for (size_t i = 0; i < len; i += 8)
        tvcas_key_transform(key3 + i, false);
}

/* ── Utilities ── */
#ifndef _WIN32
#endif

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

void secure_zero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
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
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof(one));
    freeaddrinfo(res);
    return fd;
}

/* ── ECM build ── */

void ecm_build(uint8_t *ecm_buf, int *ecm_len,
               const uint8_t *cw_even8,
               const uint8_t *cw_odd8,
               uint8_t table_id,
               const uint8_t *master_key32)
{
    uint8_t plain[48];
    memset(plain, 0, 48);
    uint32_t ts = (uint32_t)time(NULL);
    plain[0] = (ts >> 24) & 0xFF;
    plain[1] = (ts >> 16) & 0xFF;
    plain[2] = (ts >>  8) & 0xFF;
    plain[3] =  ts        & 0xFF;
    memcpy(plain +  4, cw_odd8,  8);
    memcpy(plain + 12, cw_even8, 8);
    uint8_t ck = 0;
    for (int i = 0; i < 47; i++) ck += plain[i];
    plain[47] = ck;
    uint8_t key16[16];
    uint8_t key_idx = table_id & 3;
    memcpy(key16, master_key32 + key_idx * 16, 16);
    uint8_t enc[48];
    memcpy(enc, plain, 48);
    ede2_ecb_enc(key16, enc, 48);
    secure_zero(key16, 16);
    ecm_buf[0] = table_id;
    ecm_buf[1] = 0x70;
    ecm_buf[2] = 2 + 2 + 48;
    ecm_buf[3] = 0x70;
    ecm_buf[4] = 2 + 48;
    ecm_buf[5] = 0x64;
    ecm_buf[6] = 0x21;
    memcpy(ecm_buf + 7, enc, 48);
    *ecm_len = 7 + 48;
}

/* ── Worker thread ── */

THREAD_RET worker_thread(THREAD_ARG arg) {
    worker_ctx_t *ctx = (worker_ctx_t *)arg;
    nc_params_t  *p   = &ctx->params;

    uint16_t caid   = 0;
    uint16_t sid    = 0;
    uint32_t provid = 0;
    uint8_t  master_key[32];

    nc_client_t *cl = nc_connect(p, &caid, &sid, &provid, master_key);
    if (!cl) {
        free(ctx);
#ifdef _WIN32
        return 1;
#else
        return NULL;
#endif
    }

    int interval = (p->ecm_interval_sec > 0) ? p->ecm_interval_sec : 10;
    int cw_ok    = 0;
    int cw_fail  = 0;
    int ecm_num  = 0;
    uint8_t table_state = MSG_ECM_0;
    uint8_t prev_cw[8]  = {0};

    {
        uint8_t ncw[8], cw_e[8], cw_o[8], ep[128], wr[NC_MSG_MAX];
        int el = 0; uint16_t ws, wm, wc;
        rand_bytes(ncw, 8);
        memcpy(cw_e, ncw, 8); memset(cw_o, 0, 8);
        ecm_build(ep, &el, cw_e, cw_o, MSG_ECM_0, master_key);
        if (nc_send(cl, ep, el, sid, caid, provid) >= 0) {
            cl->mid++;
            nc_recv(cl, wr, &ws, &wm, &wc);
            memcpy(prev_cw, ncw, 8);
            table_state = MSG_ECM_1;
        }
        memset(ncw, 0, 8); memset(cw_e, 0, 8);
    }

    for (;;) {
        if (ctx->stop) break;

        ecm_num++;
        uint8_t new_cw[8];
        rand_bytes(new_cw, 8);

        uint8_t cw_even[8], cw_odd[8];
        if (table_state == MSG_ECM_0) {
            memcpy(cw_even, new_cw,  8);
            memcpy(cw_odd,  prev_cw, 8);
        } else {
            memcpy(cw_even, prev_cw, 8);
            memcpy(cw_odd,  new_cw,  8);
        }
        memcpy(prev_cw, new_cw, 8);

        char hex_even[17], hex_odd[17];
        bytes_to_hex(hex_even, cw_even, 8);
        bytes_to_hex(hex_odd,  cw_odd,  8);

        uint8_t ecm_payload[128];
        int     ecm_len = 0;
        ecm_build(ecm_payload, &ecm_len, cw_even, cw_odd, table_state, master_key);
        secure_zero(cw_even, 8); secure_zero(cw_odd, 8); secure_zero(new_cw, 8);

        struct timeval t0, t1;
        get_time_now(&t0);

        if (nc_send(cl, ecm_payload, ecm_len, sid, caid, provid) < 0) {
            log_append("[!] Send failed");
            break;
        }
        cl->mid++;

        uint8_t  resp[NC_MSG_MAX];
        uint16_t r_sid, r_mid, r_caid;
        int rlen = nc_recv(cl, resp, &r_sid, &r_mid, &r_caid);
        get_time_now(&t1);
        long ms = get_ms_diff(&t0, &t1);

        if (rlen < 0) {
            log_append("[!] Connection lost");
            break;
        }

        if (rlen >= 3 && (resp[0] == MSG_ECM_0 || resp[0] == MSG_ECM_1)) {
            if (rlen >= (int)(3 + CW_LEN) && resp[2] == CW_LEN) {
                log_append("(cw) [hit]  %04X:%04X:%02X  [%02X]  %s %s  %ldms  %s",
                    caid, sid, table_state, ecm_len,
                    hex_even, hex_odd, ms, p->user);
                cw_ok++;
            } else {
                log_append("(cw) [nok]  %04X:%04X:%02X  [%02X]  resp=%02X%02X  %ldms",
                    caid, sid, table_state, ecm_len, resp[1], resp[2], ms);
                cw_fail++;
            }
        } else {
            log_append("(cw) [err]  %04X:%04X:%02X  [%02X]  cmd=0x%02X  rlen=%d  %ldms",
                caid, sid, table_state, ecm_len,
                rlen > 0 ? resp[0] : 0, rlen, ms);
            cw_fail++;
        }

        table_state = (table_state == MSG_ECM_0) ? MSG_ECM_1 : MSG_ECM_0;

        for (int s = 0; s < interval * 10; s++) {
            if (ctx->stop) break;
            Sleep(100);
        }
    }

    log_append("--- Stop ---");
    log_append("  Total: %d OK  |  %d NOK  |  (%d sent)", cw_ok, cw_fail, ecm_num);
    if (cw_ok > 0)
        log_append("server is decrypting ECM correctly");
    else
        log_append("server not providing CW -- check CAID/ProvID/keys");

    nc_disconnect(cl);
    secure_zero(master_key, 32);
    free(ctx);

#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}
