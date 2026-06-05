#ifdef _WIN32
  #ifndef _WIN32_WINNT
  #define _WIN32_WINNT 0x0600
  #endif
  #include <winsock2.h>
  #include <windows.h>
  #include <ws2tcpip.h>
  #include <wincrypt.h>
  #pragma comment(lib, "ws2_32.lib")
  #pragma comment(lib, "advapi32.lib")
  typedef SOCKET sock_t;
  #define SOCK_INVALID INVALID_SOCKET
  #define sock_close   closesocket
  #define THREAD_RET   DWORD WINAPI
  #define THREAD_ARG   LPVOID
#else
  #include <sys/socket.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <pthread.h>
  #include <sys/time.h>
  #include <gtk/gtk.h>
  typedef int sock_t;
  #define SOCK_INVALID (-1)
  #define sock_close   close
  #define THREAD_RET   void *
  #define THREAD_ARG   void *
  #define Sleep(ms)    usleep((ms)*1000)
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <stdarg.h>

#define NC_MSG_MAX       1024
#define NC_HDR_LEN_524   8
#define CW_LEN           16


#define MSG_CLIENT_LOGIN     0xe0
#define MSG_CLIENT_LOGIN_ACK 0xe1
#define MSG_CLIENT_LOGIN_NAK 0xe2
#define MSG_CARD_DATA_REQ    0xe3
#define MSG_CARD_DATA        0xe4
#define MSG_KEEPALIVE        0x8d
#define MSG_ECM_0            0x80
#define MSG_ECM_1            0x81

#define CONF_FILE "tnfs.conf"

static const int IP[64]  = {58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7};
static const int FP[64]  = {40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25};
static const int  E[48]  = {32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1};
static const int  P[32]  = {16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25};
static const int PC1[56] = {57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4};
static const int PC2[48] = {14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32};
static const int SH[16]  = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
static const int SB[8][64] = {
    {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13},
    {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9},
    {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12},
    {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14},
    {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3},
    {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13},
    {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12},
    {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
};

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

static void tvcas_key_transform(uint8_t key[8], bool to_v4)
{
    uint8_t bk[8] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};

    if (to_v4) {
        for (int i1 = 7; i1 >= 0; i1--) {
            uint8_t carry = bk[0];
            for (int k = 7; k >= 0; k--) {
                uint8_t next = bk[k];
                bk[k] = (uint8_t)((bk[k] >> 1) | (carry << 7));
                carry  = next;
            }

            for (int i2 = 7; i2 >= 0; i2--) {
                uint8_t old_k7 = key[6];
                uint8_t t1     = TVCAS_CT[(uint8_t)(old_k7 ^ bk[i2] ^ (uint8_t)i1)];
                uint8_t old_k0 = key[7] ^ t1;
                uint8_t old_k6 = key[5] ^ t1;
                key[7] = old_k7;
                key[6] = old_k6;
                for (int j = 5; j >= 1; j--) key[j] = key[j - 1];
                key[0] = old_k0;
            }
        }
    } else {
        for (int i1 = 0; i1 < 8; i1++) {
            for (int i2 = 0; i2 < 8; i2++) {
                uint8_t t1 = TVCAS_CT[(uint8_t)(key[7] ^ bk[i2] ^ (uint8_t)i1)];
                uint8_t t2 = key[0];
                for (int j = 0; j < 6; j++) key[j] = key[j + 1];
                key[5] ^= t1;
                key[6]  = key[7];
                key[7]  = t1 ^ t2;
            }
            uint8_t carry = bk[7];
            for (int k = 0; k < 8; k++) {
                uint8_t next = bk[k];
                bk[k] = (uint8_t)((bk[k] << 1) | (carry >> 7));
                carry  = next;
            }
        }
    }
}

static void tvcas4_to_v3(const uint8_t *key4, uint8_t *key3, size_t len)
{
    memcpy(key3, key4, len);
    for (size_t i = 0; i < len; i += 8)
        tvcas_key_transform(key3 + i, false);
}

static uint64_t des_p64(uint64_t in, const int *t, int n) {
    uint64_t out = 0;
    for (int i = 0; i < n; i++)
        if (in & (1ULL << (64 - t[i]))) out |= (1ULL << (n-1-i));
    return out;
}
static uint32_t des_p32(uint32_t in, const int *t, int n) {
    uint32_t out = 0;
    for (int i = 0; i < n; i++)
        if (in & (1U << (32 - t[i]))) out |= (1U << (n-1-i));
    return out;
}
static void des_subkeys(const uint8_t *key, uint64_t sk[16]) {
    uint64_t k64 = 0;
    for (int i = 0; i < 8; i++) k64 |= ((uint64_t)key[i] << (56-i*8));
    uint64_t perm = 0;
    for (int i = 0; i < 56; i++)
        if (k64 & (1ULL << (64-PC1[i]))) perm |= (1ULL << (55-i));
    uint32_t c = (uint32_t)((perm >> 28) & 0x0FFFFFFF);
    uint32_t d = (uint32_t)(perm & 0x0FFFFFFF);
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < SH[i]; j++) {
            c = ((c << 1) | (c >> 27)) & 0x0FFFFFFF;
            d = ((d << 1) | (d >> 27)) & 0x0FFFFFFF;
        }
        uint64_t cd = ((uint64_t)c << 28) | d, s2 = 0;
        for (int j = 0; j < 48; j++)
            if (cd & (1ULL << (56-PC2[j]))) s2 |= (1ULL << (47-j));
        sk[i] = s2;
    }
}
static uint32_t des_f(uint32_t r, uint64_t sk) {
    uint64_t exp = 0;
    for (int i = 0; i < 48; i++)
        if (r & (1U << (32-E[i]))) exp |= (1ULL << (47-i));
    exp ^= sk;
    uint32_t out = 0;
    for (int i = 0; i < 8; i++) {
        int bi  = (int)((exp >> (42-i*6)) & 0x3F);
        int row = ((bi & 0x20) >> 4) | (bi & 1);
        int col = (bi >> 1) & 0x0F;
        out |= (uint32_t)(SB[i][row*16+col] << (28-i*4));
    }
    return des_p32(out, P, 32);
}
static void des_block(const uint8_t *in, uint8_t *out, const uint8_t *key, bool dec) {
    uint64_t sk[16];
    des_subkeys(key, sk);
    uint64_t blk = 0;
    for (int i = 0; i < 8; i++) blk |= ((uint64_t)in[i] << (56-i*8));
    blk = des_p64(blk, IP, 64);
    uint32_t l = (uint32_t)(blk >> 32), r = (uint32_t)(blk & 0xFFFFFFFF);
    for (int i = 0; i < 16; i++) {
        uint32_t tmp = r;
        r = l ^ des_f(r, dec ? sk[15-i] : sk[i]);
        l = tmp;
    }
    blk = ((uint64_t)r << 32) | l;
    blk = des_p64(blk, FP, 64);
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)((blk >> (56-i*8)) & 0xFF);
    memset(sk, 0, sizeof(sk));
}
static void des_enc(const uint8_t *k, const uint8_t *in, uint8_t *out) { des_block(in, out, k, false); }
static void des_dec(const uint8_t *k, const uint8_t *in, uint8_t *out) { des_block(in, out, k, true);  }

static void ede2_cbc_enc(const uint8_t *k16, const uint8_t *iv, const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t ivec[8];
    memcpy(ivec, iv, 8);
    for (size_t i = 0; i < len; i += 8) {
        for (int j = 0; j < 8; j++) out[i+j] = in[i+j] ^ ivec[j];
        des_enc(k16,   out+i, out+i);
        des_dec(k16+8, out+i, out+i);
        des_enc(k16,   out+i, out+i);
        memcpy(ivec, out+i, 8);
    }
    memset(ivec, 0, 8);
}
static void ede2_cbc_dec(const uint8_t *k16, const uint8_t *iv, const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t ivec[8], tmp[8];
    memcpy(ivec, iv, 8);
    for (size_t i = 0; i < len; i += 8) {
        memcpy(tmp, in+i, 8);
        des_dec(k16,   in+i, out+i);
        des_enc(k16+8, out+i, out+i);
        des_dec(k16,   out+i, out+i);
        for (int j = 0; j < 8; j++) out[i+j] ^= ivec[j];
        memcpy(ivec, tmp, 8);
    }
    memset(ivec, 0, 8);
}
static void ede2_ecb_enc(const uint8_t *k16, uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i += 8) {
        des_enc(k16,   data+i, data+i);
        des_dec(k16+8, data+i, data+i);
        des_enc(k16,   data+i, data+i);
    }
}

static void key_spread(const uint8_t *k14, uint8_t *s) {
    s[0]  =  k14[0] & 0xfe;
    s[1]  = ((k14[0]  << 7) | (k14[1]  >> 1)) & 0xfe;
    s[2]  = ((k14[1]  << 6) | (k14[2]  >> 2)) & 0xfe;
    s[3]  = ((k14[2]  << 5) | (k14[3]  >> 3)) & 0xfe;
    s[4]  = ((k14[3]  << 4) | (k14[4]  >> 4)) & 0xfe;
    s[5]  = ((k14[4]  << 3) | (k14[5]  >> 5)) & 0xfe;
    s[6]  = ((k14[5]  << 2) | (k14[6]  >> 6)) & 0xfe;
    s[7]  =   k14[6]  << 1;
    s[8]  =  k14[7]  & 0xfe;
    s[9]  = ((k14[7]  << 7) | (k14[8]  >> 1)) & 0xfe;
    s[10] = ((k14[8]  << 6) | (k14[9]  >> 2)) & 0xfe;
    s[11] = ((k14[9]  << 5) | (k14[10] >> 3)) & 0xfe;
    s[12] = ((k14[10] << 4) | (k14[11] >> 4)) & 0xfe;
    s[13] = ((k14[11] << 3) | (k14[12] >> 5)) & 0xfe;
    s[14] = ((k14[12] << 2) | (k14[13] >> 6)) & 0xfe;
    s[15] =   k14[13] << 1;
    for (int i = 0; i < 16; i++) {
        int par = 0;
        for (int j = 1; j < 8; j++) par ^= (s[i] >> j) & 1;
        s[i] = (s[i] & 0xFE) | (par ^ 1);
    }
}

#define RD_LE32(p) (((uint32_t)(p)[0])|((uint32_t)(p)[1]<<8)|((uint32_t)(p)[2]<<16)|((uint32_t)(p)[3]<<24))
#define ROL(x,n)   (((x)<<(n))|((x)>>(32-(n))))
#define MF(x,y,z)  (((x)&(y))|(~(x)&(z)))
#define MG(x,y,z)  (((x)&(z))|((y)&~(z)))
#define MH(x,y,z)  ((x)^(y)^(z))
#define MI(x,y,z)  ((y)^((x)|~(z)))

static const uint32_t T64[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};
static void md5_transform(uint32_t st[4], const uint8_t blk[64]) {
    uint32_t a=st[0],b=st[1],c=st[2],d=st[3],x[16];
    for(int i=0;i<16;i++) x[i]=RD_LE32(blk+i*4);
#define OP(f,a,b,c,d,k,s,idx) a=b+ROL(a+f(b,c,d)+x[k]+T64[idx],s)
    OP(MF,a,b,c,d,0,7,0);  OP(MF,d,a,b,c,1,12,1);  OP(MF,c,d,a,b,2,17,2);  OP(MF,b,c,d,a,3,22,3);
    OP(MF,a,b,c,d,4,7,4);  OP(MF,d,a,b,c,5,12,5);  OP(MF,c,d,a,b,6,17,6);  OP(MF,b,c,d,a,7,22,7);
    OP(MF,a,b,c,d,8,7,8);  OP(MF,d,a,b,c,9,12,9);  OP(MF,c,d,a,b,10,17,10);OP(MF,b,c,d,a,11,22,11);
    OP(MF,a,b,c,d,12,7,12);OP(MF,d,a,b,c,13,12,13);OP(MF,c,d,a,b,14,17,14);OP(MF,b,c,d,a,15,22,15);
    OP(MG,a,b,c,d,1,5,16); OP(MG,d,a,b,c,6,9,17);  OP(MG,c,d,a,b,11,14,18);OP(MG,b,c,d,a,0,20,19);
    OP(MG,a,b,c,d,5,5,20); OP(MG,d,a,b,c,10,9,21); OP(MG,c,d,a,b,15,14,22);OP(MG,b,c,d,a,4,20,23);
    OP(MG,a,b,c,d,9,5,24); OP(MG,d,a,b,c,14,9,25); OP(MG,c,d,a,b,3,14,26); OP(MG,b,c,d,a,8,20,27);
    OP(MG,a,b,c,d,13,5,28);OP(MG,d,a,b,c,2,9,29);  OP(MG,c,d,a,b,7,14,30); OP(MG,b,c,d,a,12,20,31);
    OP(MH,a,b,c,d,5,4,32); OP(MH,d,a,b,c,8,11,33); OP(MH,c,d,a,b,11,16,34);OP(MH,b,c,d,a,14,23,35);
    OP(MH,a,b,c,d,1,4,36); OP(MH,d,a,b,c,4,11,37); OP(MH,c,d,a,b,7,16,38); OP(MH,b,c,d,a,10,23,39);
    OP(MH,a,b,c,d,13,4,40);OP(MH,d,a,b,c,0,11,41); OP(MH,c,d,a,b,3,16,42); OP(MH,b,c,d,a,6,23,43);
    OP(MH,a,b,c,d,9,4,44); OP(MH,d,a,b,c,12,11,45);OP(MH,c,d,a,b,15,16,46);OP(MH,b,c,d,a,2,23,47);
    OP(MI,a,b,c,d,0,6,48); OP(MI,d,a,b,c,7,10,49); OP(MI,c,d,a,b,14,15,50);OP(MI,b,c,d,a,5,21,51);
    OP(MI,a,b,c,d,12,6,52);OP(MI,d,a,b,c,3,10,53); OP(MI,c,d,a,b,10,15,54);OP(MI,b,c,d,a,1,21,55);
    OP(MI,a,b,c,d,8,6,56); OP(MI,d,a,b,c,15,10,57);OP(MI,c,d,a,b,6,15,58); OP(MI,b,c,d,a,13,21,59);
    OP(MI,a,b,c,d,4,6,60); OP(MI,d,a,b,c,11,10,61);OP(MI,c,d,a,b,2,15,62); OP(MI,b,c,d,a,9,21,63);
#undef OP
    st[0]+=a; st[1]+=b; st[2]+=c; st[3]+=d;
}
static void md5_hash(const uint8_t *data, size_t len, uint8_t out[16]) {
    uint32_t st[4] = {0x67452301,0xefcdab89,0x98badcfe,0x10325476};
    uint8_t buf[64];
    size_t i=0, rem;
    while (i+64 <= len) { md5_transform(st, data+i); i+=64; }
    rem = len-i;
    memcpy(buf, data+i, rem);
    buf[rem] = 0x80;
    memset(buf+rem+1, 0, 64-rem-1);
    if (rem >= 56) { md5_transform(st, buf); memset(buf, 0, 64); }
    uint64_t bits = (uint64_t)len*8;
    for (int j=0; j<8; j++) buf[56+j] = (uint8_t)((bits >> (j*8)) & 0xFF);
    md5_transform(st, buf);
    for (int j=0; j<4; j++) {
        out[j*4+0] = st[j] & 0xFF;
        out[j*4+1] = (st[j] >>  8) & 0xFF;
        out[j*4+2] = (st[j] >> 16) & 0xFF;
        out[j*4+3] = (st[j] >> 24) & 0xFF;
    }
}
static const char MD5B64[] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
static void to64(uint32_t v, int n, char *dst, int *pos) {
    for (int i=0; i<n; i++) { dst[(*pos)++] = MD5B64[v & 0x3f]; v >>= 6; }
}
static bool md5_crypt(const char *pw, const char *salt_str, char *out, size_t outsz) {
    static const char MAGIC[] = "$1$";
    char salt[9];
    const char *sp = salt_str + 3;
    size_t sl = 0;
    while (sp[sl] && sp[sl] != '$' && sl < 8) { salt[sl] = sp[sl]; sl++; }
    salt[sl] = '\0';
    size_t pw_len = strlen(pw);
    uint8_t *tmp  = (uint8_t *)malloc(pw_len*2+128);
    uint8_t *atmp = (uint8_t *)malloc(pw_len*2+32);
    if (!tmp || !atmp) { free(tmp); free(atmp); return false; }
    uint8_t alt[16], fh[16];
    size_t pos=0, apos=0;
    memcpy(tmp+pos,  pw,    pw_len); pos  += pw_len;
    memcpy(tmp+pos,  MAGIC, 3);      pos  += 3;
    memcpy(tmp+pos,  salt,  sl);     pos  += sl;
    memcpy(atmp+apos,pw,    pw_len); apos += pw_len;
    memcpy(atmp+apos,salt,  sl);     apos += sl;
    memcpy(atmp+apos,pw,    pw_len); apos += pw_len;
    md5_hash(atmp, apos, alt);
    for (int pl=(int)pw_len; pl>0; pl-=16) {
        int take = pl>16 ? 16 : pl;
        memcpy(tmp+pos, alt, take); pos += take;
    }
    memset(alt, 0, 16);
    for (int i=(int)pw_len; i; i>>=1) tmp[pos++] = (i & 1) ? 0 : pw[0];
    md5_hash(tmp, pos, fh);
    for (int i=0; i<1000; i++) {
        pos = 0;
        if (i & 1)  { memcpy(tmp+pos, pw,   pw_len); pos += pw_len; }
        else        { memcpy(tmp+pos, fh,   16);      pos += 16;     }
        if (i % 3)  { memcpy(tmp+pos, salt, sl);      pos += sl;     }
        if (i % 7)  { memcpy(tmp+pos, pw,   pw_len); pos += pw_len; }
        if (i & 1)  { memcpy(tmp+pos, fh,   16);      pos += 16;     }
        else        { memcpy(tmp+pos, pw,   pw_len); pos += pw_len; }
        md5_hash(tmp, pos, fh);
    }
    int opos = 0;
    char result[64] = {0};
    opos += snprintf(result+opos, sizeof(result)-opos, "%s", MAGIC);
    for (int i=0; i<(int)sl; i++) result[opos++] = salt[i];
    result[opos++] = '$';
#define EM(a,b,c,n) do { uint32_t v=((uint32_t)fh[a]<<16)|((uint32_t)fh[b]<<8)|fh[c]; to64(v,n,result,&opos); } while(0)
    EM(0,6,12,4); EM(1,7,13,4); EM(2,8,14,4); EM(3,9,15,4); EM(4,10,5,4);
#undef EM
    to64(fh[11], 2, result, &opos);
    result[opos] = '\0';
    memset(fh, 0, 16);
    free(tmp); free(atmp);
    if ((size_t)opos >= outsz) return false;
    memcpy(out, result, opos+1);
    return true;
}

static uint8_t nc_xor(const uint8_t *buf, int len) {
    uint8_t x = 0;
    for (int i=0; i<len; i++) x ^= buf[i];
    return x;
}

#ifdef _WIN32
static void rand_bytes(uint8_t *buf, size_t n) {
    HCRYPTPROV hProv;
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(hProv, (DWORD)n, buf);
        CryptReleaseContext(hProv, 0);
    } else {
        for (size_t i=0; i<n; i++) buf[i] = (uint8_t)(rand() & 0xFF);
    }
}
#else
static void rand_bytes(uint8_t *buf, size_t n) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) { if (fread(buf, 1, n, f) != n) { for (size_t i=0; i<n; i++) buf[i]=(uint8_t)(rand()&0xFF); } fclose(f); }
    else { for (size_t i=0; i<n; i++) buf[i] = (uint8_t)(rand() & 0xFF); }
}
#endif

static void get_timestamp(char *buf, size_t sz) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buf, sz, "%Y/%m/%d %H:%M:%S", tm_info);
}

static long get_ms_diff(struct timeval *t0, struct timeval *t1) {
    return (t1->tv_sec  - t0->tv_sec)  * 1000L
         + (t1->tv_usec - t0->tv_usec) / 1000L;
}

#ifdef _WIN32
static void get_time_now(struct timeval *tv) {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    unsigned __int64 tmp = ((unsigned __int64)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    tmp /= 10;
    tmp -= 11644473600000000ULL;
    tv->tv_sec  = (long)(tmp / 1000000ULL);
    tv->tv_usec = (long)(tmp % 1000000ULL);
}
#else
static void get_time_now(struct timeval *tv) {
    gettimeofday(tv, NULL);
}
#endif

static int recv_all(sock_t fd, void *buf, int len) {
    uint8_t *p = (uint8_t *)buf;
    int total = 0;
    while (total < len) {
        int n = (int)recv(fd, (char *)p+total, len-total, 0);
        if (n <= 0) return -1;
        total += n;
    }
    return total;
}
static int send_all(sock_t fd, const void *buf, int len) {
    const uint8_t *p = (const uint8_t *)buf;
    int total = 0;
    while (total < len) {
        int n = (int)send(fd, (const char *)p+total, len-total, 0);
        if (n <= 0) return -1;
        total += n;
    }
    return total;
}

static bool parse_hex(const char *s, uint8_t *out, int n) {
    if ((int)strlen(s) != n*2) return false;
    for (int i=0; i<n; i++) {
        unsigned v;
        if (sscanf(s+i*2, "%02x", &v) != 1) return false;
        out[i] = (uint8_t)v;
    }
    return true;
}

static void bytes_to_hex(char *dst, const uint8_t *src, int len) {
    for (int i=0; i<len; i++) snprintf(dst+i*2, 3, "%02X", src[i]);
    dst[len*2] = '\0';
}

static void build_ecm(uint8_t *ecm_buf, int *ecm_len,
                      const uint8_t *cw_even8, const uint8_t *cw_odd8,
                      uint8_t table_id, const uint8_t *master_key32)
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
    for (int i=0; i<47; i++) ck += plain[i];
    plain[47] = ck;
    uint8_t key16[16];
    uint8_t key_idx = table_id & 3;
    memcpy(key16, master_key32+key_idx*16, 16);
    uint8_t enc[48];
    memcpy(enc, plain, 48);
    ede2_ecb_enc(key16, enc, 48);
    memset(key16, 0, 16);
    ecm_buf[0] = table_id;
    ecm_buf[1] = 0x70;
    ecm_buf[2] = 2+2+48;
    ecm_buf[3] = 0x70;
    ecm_buf[4] = 2+48;
    ecm_buf[5] = 0x64;
    ecm_buf[6] = 0x21;
    memcpy(ecm_buf+7, enc, 48);
    *ecm_len = 7+48;
}

typedef struct {
    sock_t   fd;
    uint8_t  key1[8], key2[8];
    uint8_t  session_key[14];
    uint8_t  send_buf[NC_MSG_MAX+64];
    uint8_t  recv_buf[NC_MSG_MAX];
    uint16_t mid;
} NC_CLIENT;

static int nc_send(NC_CLIENT *cl, const uint8_t *data, int dlen,
                   uint16_t sid, uint16_t caid, uint32_t provid)
{
    uint8_t *buf = cl->send_buf;
    memset(buf, 0, 12);
    buf[2]  = (uint8_t)(cl->mid >> 8);
    buf[3]  = (uint8_t)(cl->mid & 0xFF);
    buf[4]  = (uint8_t)(sid    >> 8);
    buf[5]  = (uint8_t)(sid    & 0xFF);
    buf[6]  = (uint8_t)(caid   >> 8);
    buf[7]  = (uint8_t)(caid   & 0xFF);
    buf[8]  = (uint8_t)(provid >> 16);
    buf[9]  = (uint8_t)(provid >>  8);
    buf[10] = (uint8_t)(provid       );
    buf[11] = (uint8_t)(provid >> 24);

    memcpy(buf+12, data, dlen);
    buf[13] = (data[1] & 0xF0) | (((dlen-3) >> 8) & 0x0F);
    buf[14] = (dlen-3) & 0xFF;

    uint32_t blen = (uint32_t)dlen + 12;
    uint8_t pad[8];
    rand_bytes(pad, 8);
    uint32_t plen = (8-((blen-1) % 8)) % 8;
    memcpy(buf+blen, pad, plen);
    blen += plen;
    buf[blen] = nc_xor(buf+2, (int)(blen-2));
    blen++;
    uint8_t iv[8];
    rand_bytes(iv, 8);
    memcpy(buf+blen, iv, 8);
    uint8_t key16[16];
    memcpy(key16,   cl->key1, 8);
    memcpy(key16+8, cl->key2, 8);
    ede2_cbc_enc(key16, iv, buf+2, buf+2, blen-2);
    memset(key16, 0, 16);
    blen += 8;
    buf[0] = (uint8_t)((blen-2) >> 8);
    buf[1] = (uint8_t)((blen-2) & 0xFF);
    return send_all(cl->fd, buf, (int)blen);
}

static int nc_recv(NC_CLIENT *cl, uint8_t *data,
                   uint16_t *sid, uint16_t *mid, uint16_t *caid)
{
    for (int _try = 0; _try < 32; _try++) {
        uint8_t lenbuf[2], *buf = cl->recv_buf;
        if (recv_all(cl->fd, lenbuf, 2) != 2) return -1;
        uint16_t total_len = (uint16_t)((lenbuf[0] << 8) | lenbuf[1]);
        if (!total_len || total_len > NC_MSG_MAX) return -1;
        if (recv_all(cl->fd, buf, total_len) != (int)total_len) return -1;
        if (total_len < 8) return -1;
        uint16_t payload_len = total_len-8;
        uint8_t iv[8], key16[16];
        memcpy(iv, buf+payload_len, 8);
        memcpy(key16,     cl->key1, 8);
        memcpy(key16+8,   cl->key2, 8);
        ede2_cbc_dec(key16, iv, buf, buf, payload_len);
        memset(key16, 0, 16);
        if (nc_xor(buf, payload_len)) return -1;
        *mid  = (uint16_t)((buf[0] << 8) | buf[1]);
        *sid  = (uint16_t)((buf[2] << 8) | buf[3]);
        *caid = (uint16_t)((buf[4] << 8) | buf[5]);
        if (payload_len < (uint16_t)(NC_HDR_LEN_524+5)) return -1;
        uint32_t rlen = (uint32_t)((((buf[3+NC_HDR_LEN_524] & 0x0F) << 8) |
                                      buf[4+NC_HDR_LEN_524]) + 3);
        if (rlen+2+NC_HDR_LEN_524 > (uint32_t)payload_len) return -1;
        memcpy(data, buf+2+NC_HDR_LEN_524, rlen);
        if (rlen >= 1 && (data[0] == 0xD3 || data[0] == 0xD6))
            continue;
        return (int)rlen;
    }
    return -1;
}

static sock_t connect_server(const char *host, int port) {
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

typedef struct {
    char host[256];
    int  port;
    char user[64];
    char pass[64];
    char deskey[64];
    char caid[16];
    char sid[16];
    char provid[16];
    char masterkey[128];
    int  ecm_interval_sec;
    bool is_tvcas4;
} THREAD_PARAM;

typedef struct {
    char host[256];
    int  port;
    char user[64];
    char pass[64];
    char deskey[64];
    char caid[16];
    char sid[16];
    char provid[16];
    char masterkey[128];
    int  interval;
} CONF;

static void conf_load(CONF *c) {
    FILE *f = fopen(CONF_FILE, "r");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char key[64], val[448];
        if (sscanf(line, " %63[^= ] = %447[^\r\n]", key, val) != 2) continue;
        if (strcmp(key, "host")      == 0) { strncpy(c->host,      val, sizeof(c->host)-1);      c->host[sizeof(c->host)-1]=0; }
        else if (strcmp(key, "port")      == 0) c->port     = atoi(val);
        else if (strcmp(key, "user")      == 0) { strncpy(c->user,      val, sizeof(c->user)-1);      c->user[sizeof(c->user)-1]=0; }
        else if (strcmp(key, "pass")      == 0) { strncpy(c->pass,      val, sizeof(c->pass)-1);      c->pass[sizeof(c->pass)-1]=0; }
        else if (strcmp(key, "deskey")    == 0) { strncpy(c->deskey,    val, sizeof(c->deskey)-1);    c->deskey[sizeof(c->deskey)-1]=0; }
        else if (strcmp(key, "caid")      == 0) { strncpy(c->caid,      val, sizeof(c->caid)-1);      c->caid[sizeof(c->caid)-1]=0; }
        else if (strcmp(key, "sid")       == 0) { strncpy(c->sid,       val, sizeof(c->sid)-1);       c->sid[sizeof(c->sid)-1]=0; }
        else if (strcmp(key, "provid")    == 0) { strncpy(c->provid,    val, sizeof(c->provid)-1);    c->provid[sizeof(c->provid)-1]=0; }
        else if (strcmp(key, "masterkey") == 0) { strncpy(c->masterkey, val, sizeof(c->masterkey)-1); c->masterkey[sizeof(c->masterkey)-1]=0; }
        else if (strcmp(key, "interval")  == 0) c->interval = atoi(val);
    }
    fclose(f);
}

static void conf_save(const CONF *c) {
    FILE *f = fopen(CONF_FILE, "w");
    if (!f) return;
    fprintf(f, "host      = %s\n", c->host);
    fprintf(f, "port      = %d\n", c->port);
    fprintf(f, "user      = %s\n", c->user);
    fprintf(f, "pass      = %s\n", c->pass);
    fprintf(f, "deskey    = %s\n", c->deskey);
    fprintf(f, "caid      = %s\n", c->caid);
    fprintf(f, "sid       = %s\n", c->sid);
    fprintf(f, "provid    = %s\n", c->provid);
    fprintf(f, "masterkey = %s\n", c->masterkey);
    fprintf(f, "interval  = %d\n", c->interval);
    fclose(f);
}

#ifdef _WIN32

#define IDC_EDIT_HOST      101
#define IDC_EDIT_PORT      102
#define IDC_EDIT_USER      103
#define IDC_EDIT_PASS      104
#define IDC_EDIT_DESKEY    105
#define IDC_EDIT_CAID      106
#define IDC_EDIT_SID       107
#define IDC_EDIT_PROVID    108
#define IDC_EDIT_MASTERKEY 109
#define IDC_EDIT_INTERVAL  110
#define IDC_BTN_RUN        111
#define IDC_BTN_STOP       112
#define IDC_BTN_CLEAR      113
#define IDC_EDIT_LOG       114
#define IDC_CHK_TVCAS4     115

static HINSTANCE     g_hInst;
static HWND          g_hWnd;
static HWND          g_hLog;
static HWND          g_hwnd_chk_tvcas4;
static volatile LONG g_stop_flag  = 0;
static HANDLE        g_thread     = NULL;
static NC_CLIENT    *g_nc_client  = NULL;
static uint8_t       g_master_key[32];
static uint16_t      g_sid_val    = 0x0001;
static uint16_t      g_caid_val   = 0x0B00;
static uint32_t      g_provid_val = 0x000000;
static bool          g_connected  = false;

static void AppendLogRaw(const char *text) {
    if (!g_hLog) return;
    int len = GetWindowTextLengthA(g_hLog);
    SendMessageA(g_hLog, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessageA(g_hLog, EM_REPLACESEL, 0, (LPARAM)text);
}
static void AppendLog(const char *fmt, ...) {
    char ts[32], buf[1200];
    get_timestamp(ts, sizeof(ts));
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    snprintf(buf, sizeof(buf), "%s %s\r\n", ts, msg);
    AppendLogRaw(buf);
}

#else

static GtkWidget    *g_window;
static GtkWidget    *g_log_view;
static GtkTextBuffer*g_log_buf;
static GtkWidget    *g_entry_host, *g_entry_port, *g_entry_user, *g_entry_pass;
static GtkWidget    *g_entry_deskey, *g_entry_caid, *g_entry_sid;
static GtkWidget    *g_entry_provid, *g_entry_masterkey, *g_entry_interval;
static GtkWidget    *g_btn_run, *g_btn_stop;
static GtkWidget    *g_chk_tvcas4;
static volatile int  g_stop_flag  = 0;
static pthread_t     g_thread;
static bool          g_thread_running = false;
static NC_CLIENT    *g_nc_client  = NULL;
static uint8_t       g_master_key[32];
static uint16_t      g_sid_val    = 0x0001;
static uint16_t      g_caid_val   = 0x0B00;
static uint32_t      g_provid_val = 0x000000;
static bool          g_connected  = false;
static GtkTextMark  *g_log_end_mark = NULL;

typedef struct { char *text; } LogMsg;

static gboolean append_log_idle(gpointer data) {
    LogMsg *lm = (LogMsg *)data;
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(g_log_buf, &end);
    gtk_text_buffer_insert(g_log_buf, &end, lm->text, -1);
    gtk_text_view_scroll_mark_onscreen(GTK_TEXT_VIEW(g_log_view), g_log_end_mark);
    free(lm->text);
    free(lm);
    return FALSE;
}
static void AppendLog(const char *fmt, ...) {
    char ts[32], msg[1024], full[1200];
    get_timestamp(ts, sizeof(ts));
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    snprintf(full, sizeof(full), "%s %s\n", ts, msg);
    LogMsg *lm = (LogMsg *)malloc(sizeof(LogMsg));
    if (!lm) return;
    lm->text = strdup(full);
    if (!lm->text) { free(lm); return; }
    g_idle_add(append_log_idle, lm);
}
#endif

static THREAD_RET NetworkThread(THREAD_ARG lpParam) {
    THREAD_PARAM *tp = (THREAD_PARAM *)lpParam;
#ifdef _WIN32
    InterlockedExchange(&g_stop_flag, 0);
#else
    g_stop_flag = 0;
#endif

    uint8_t des_key14[14];
    if (!parse_hex(tp->deskey, des_key14, 14)) {
        AppendLog("[!] DES key parse error (need 28 hex chars)");
        free(tp);
#ifdef _WIN32
        g_thread = NULL;
        return 1;
#else
        g_thread_running = false;
        return NULL;
#endif
    }

    uint16_t caid   = 0x0B00;
    uint16_t sid    = 0x0001;
    uint32_t provid = 0x000000;
    if (strlen(tp->caid)   > 0) sscanf(tp->caid,   "%hx", &caid);
    if (strlen(tp->sid)    > 0) sscanf(tp->sid,    "%hx", &sid);
    if (strlen(tp->provid) > 0) sscanf(tp->provid, "%x",  &provid);

    if (caid == 0x0900) {
        AppendLog("[*] TVCAS4 CAID detected (0900) -> remapping to TVCAS3 (0B00)");
        caid = 0x0B00;
    }

    const char *mk_str = tp->masterkey;
    if (strlen(mk_str) == 0)
        mk_str = "9F3C17A2B5D0481E6A7B92F4C8E05D13A1B9E4F276C3058D4ACF19B08273DE5F";

    bool is_v4_key = tp->is_tvcas4;
    if (strlen(mk_str) != 64) {
        AppendLog("[!] Master key must be 64 hex chars (32 bytes)");
        free(tp);
#ifdef _WIN32
        g_thread = NULL; return 1;
#else
        g_thread_running = false; return NULL;
#endif
    }

    uint8_t master_key_raw[32];
    for (int i=0; i<32; i++) {
        unsigned v; sscanf(mk_str+i*2, "%02x", &v);
        master_key_raw[i] = (uint8_t)v;
    }

    uint8_t master_key[32];
    if (is_v4_key) {
        AppendLog("[*] Converting TVCAS4 master key -> TVCAS3");
        tvcas4_to_v3(master_key_raw, master_key, 32);
    } else {
        memcpy(master_key, master_key_raw, 32);
    }

    memcpy(g_master_key, master_key, 32);
    g_sid_val    = sid;
    g_caid_val   = caid;
    g_provid_val = provid;

    int interval = (tp->ecm_interval_sec > 0) ? tp->ecm_interval_sec : 10;

    AppendLog("(newcamd) %s connecting ....", tp->host);

    sock_t fd = connect_server(tp->host, tp->port);
    if (fd == SOCK_INVALID) {
        AppendLog("[!] Connection failed");
        free(tp);
#ifdef _WIN32
        g_thread = NULL; return 1;
#else
        g_thread_running = false; return NULL;
#endif
    }

    NC_CLIENT *cl = (NC_CLIENT *)calloc(1, sizeof(NC_CLIENT));
    cl->fd  = fd;
    cl->mid = 1;
    g_nc_client = cl;

    uint8_t srv_rnd[14];
    if (recv_all(fd, srv_rnd, 14) != 14) {
        AppendLog("[!] Server nonce not received");
        sock_close(fd); free(cl); free(tp); g_nc_client = NULL;
#ifdef _WIN32
        g_thread = NULL; return 1;
#else
        g_thread_running = false; return NULL;
#endif
    }
    uint8_t xored[14], spread[16];
    for (int i=0; i<14; i++) xored[i] = srv_rnd[i] ^ des_key14[i];
    key_spread(xored, spread);
    memcpy(cl->key1, spread,     8);
    memcpy(cl->key2, spread+8,   8);
    memcpy(cl->session_key, des_key14, 14);
    memset(xored,  0, 14);
    memset(spread, 0, 16);

    char hash[64];
    if (!md5_crypt(tp->pass, "$1$abcdefgh$", hash, sizeof(hash))) {
        AppendLog("[!] Failed to generate MD5 hash");
        sock_close(fd); free(cl); free(tp); g_nc_client = NULL;
#ifdef _WIN32
        g_thread = NULL; return 1;
#else
        g_thread_running = false; return NULL;
#endif
    }

    uint8_t login_buf[256];
    int lpos = 0;
    size_t ulen = strlen(tp->user);
    size_t hlen = strlen(hash);
    login_buf[lpos++] = MSG_CLIENT_LOGIN;
    login_buf[lpos++] = 0x00;
    login_buf[lpos++] = (uint8_t)((ulen + 1) + (hlen + 1));
    memcpy(login_buf+lpos, tp->user, ulen+1); lpos += (int)ulen+1;
    memcpy(login_buf+lpos, hash, hlen+1); lpos += (int)hlen+1;

    if (nc_send(cl, login_buf, lpos, 0x0000, 0x0000, 0) < 0) {
        AppendLog("[!] Failed to send LOGIN");
        sock_close(fd); free(cl); free(tp); g_nc_client = NULL;
#ifdef _WIN32
        g_thread = NULL; return 1;
#else
        g_thread_running = false; return NULL;
#endif
    }

    uint8_t  resp[NC_MSG_MAX];
    uint16_t r_sid, r_mid, r_caid;
    int rlen = nc_recv(cl, resp, &r_sid, &r_mid, &r_caid);
    if (rlen < 1 || resp[0] != MSG_CLIENT_LOGIN_ACK) {
        AppendLog("[!] Login rejected (cmd=0x%02X)", rlen>0 ? resp[0] : 0);
        sock_close(fd); free(cl); free(tp); g_nc_client = NULL;
#ifdef _WIN32
        g_thread = NULL; return 1;
#else
        g_thread_running = false; return NULL;
#endif
    }

    for (int i=0; i<(int)hlen; i++)
        cl->session_key[i % 14] ^= (uint8_t)hash[i];
    key_spread(cl->session_key, spread);
    memcpy(cl->key1, spread,     8);
    memcpy(cl->key2, spread+8,   8);
    memset(spread, 0, 16);
    cl->mid++;

    uint8_t card_req[3] = {MSG_CARD_DATA_REQ, 0, 0};
    if (nc_send(cl, card_req, 3, sid, caid, provid) < 0) {
        AppendLog("[!] Failed to send CARD_DATA_REQ");
        sock_close(fd); free(cl); free(tp); g_nc_client = NULL;
#ifdef _WIN32
        g_thread = NULL; return 1;
#else
        g_thread_running = false; return NULL;
#endif
    }
    cl->mid++;
    rlen = nc_recv(cl, resp, &r_sid, &r_mid, &r_caid);
    if (rlen >= 6 && resp[0] == MSG_CARD_DATA) {
        uint16_t got_caid = (uint16_t)((resp[4] << 8) | resp[5]);
        AppendLog("[card] CAID from server: %04X", got_caid);
    }

    g_connected = true;

    int cw_ok   = 0;
    int cw_fail = 0;
    int ecm_num = 0;
    uint8_t table_state = MSG_ECM_0;
    uint8_t prev_cw[8] = {0};

    {
        uint8_t ncw[8], cw_e[8], cw_o[8], ep[128], wr[NC_MSG_MAX];
        int el = 0; uint16_t ws, wm, wc;
        rand_bytes(ncw, 8);
        memcpy(cw_e, ncw, 8); memset(cw_o, 0, 8);
        build_ecm(ep, &el, cw_e, cw_o, MSG_ECM_0, master_key);
        if (nc_send(cl, ep, el, sid, caid, provid) >= 0) {
            cl->mid++;
            nc_recv(cl, wr, &ws, &wm, &wc);
            memcpy(prev_cw, ncw, 8);
            table_state = MSG_ECM_1;
        }
        memset(ncw, 0, 8); memset(cw_e, 0, 8);
    }

    for (;;) {
#ifdef _WIN32
        if (InterlockedOr(&g_stop_flag, 0)) break;
#else
        if (g_stop_flag) break;
#endif

        ecm_num++;

        uint8_t new_cw[8];
        rand_bytes(new_cw, 8);

        uint8_t cw_even[8], cw_odd[8];
        if (table_state == MSG_ECM_0) {
            memcpy(cw_even, new_cw,   8);
            memcpy(cw_odd,  prev_cw,  8);
        } else {
            memcpy(cw_even, prev_cw,  8);
            memcpy(cw_odd,  new_cw,   8);
        }
        memcpy(prev_cw, new_cw, 8);

        char hex_cw_even[17], hex_cw_odd[17];
        bytes_to_hex(hex_cw_even, cw_even, 8);
        bytes_to_hex(hex_cw_odd,  cw_odd,  8);

        uint8_t ecm_payload[128];
        int     ecm_len = 0;
        build_ecm(ecm_payload, &ecm_len, cw_even, cw_odd, table_state, master_key);
        memset(cw_even, 0, 8); memset(cw_odd, 0, 8); memset(new_cw, 0, 8);

        struct timeval t0, t1;
        get_time_now(&t0);

        if (nc_send(cl, ecm_payload, ecm_len, sid, caid, provid) < 0) {
            AppendLog("[!] Send failed");
            break;
        }
        cl->mid++;

        rlen = nc_recv(cl, resp, &r_sid, &r_mid, &r_caid);
        get_time_now(&t1);
        long ms = get_ms_diff(&t0, &t1);

        if (rlen < 0) {
            AppendLog("[!] Connection lost");
            break;
        }

        if (rlen >= 3 && (resp[0] == MSG_ECM_0 || resp[0] == MSG_ECM_1)) {
            if (rlen >= (int)(3 + CW_LEN) && resp[2] == CW_LEN) {
                AppendLog("(cw) [hit]  %04X:%04X:%02X  [%02X]  %s %s  %ldms  %s",
                    caid, sid, table_state, ecm_len,
                    hex_cw_even, hex_cw_odd, ms, tp->user);
                cw_ok++;
            } else {
                AppendLog("(cw) [nok]  %04X:%04X:%02X  [%02X]  resp=%02X%02X  %ldms",
                          caid, sid, table_state, ecm_len, resp[1], resp[2], ms);
                cw_fail++;
            }
        } else {
            AppendLog("(cw) [err]  %04X:%04X:%02X  [%02X]  cmd=0x%02X  rlen=%d  %ldms",
                      caid, sid, table_state, ecm_len,
                      rlen>0 ? resp[0] : 0, rlen, ms);
            cw_fail++;
        }

        table_state = (table_state == MSG_ECM_0) ? MSG_ECM_1 : MSG_ECM_0;

        for (int s=0; s < interval*10; s++) {
#ifdef _WIN32
            if (InterlockedOr(&g_stop_flag, 0)) break;
#else
            if (g_stop_flag) break;
#endif
            Sleep(100);
        }
    }

    AppendLog("--- Stop ---");
    AppendLog("  Total: %d OK  |  %d NOK  |  (%d sent)", cw_ok, cw_fail, ecm_num);
    if (cw_ok > 0)
        AppendLog("server is decrypting ECM correctly");
    else
        AppendLog("server not providing CW -- check CAID/ProvID/keys");

    sock_close(fd);
    memset(master_key, 0, 32);
    memset(g_master_key, 0, 32);
    g_connected = false;
    g_nc_client = NULL;
    free(cl);
    free(tp);

#ifdef _WIN32
    g_thread = NULL;
    return 0;
#else
    g_thread_running = false;
    return NULL;
#endif
}

#ifdef _WIN32

static HWND CreateLabel(HWND hWnd, const char *text, int x, int y, int w, int h) {
    return CreateWindowA("STATIC", text, WS_VISIBLE|WS_CHILD|SS_LEFT,
                         x, y, w, h, hWnd, NULL, g_hInst, NULL);
}
static HWND CreateEdit(HWND hWnd, int id, const char *def, int x, int y, int w, int h, DWORD xstyle) {
    HWND he = CreateWindowA("EDIT", def,
                            WS_VISIBLE|WS_CHILD|WS_BORDER|ES_AUTOHSCROLL|xstyle,
                            x, y, w, h, hWnd, (HMENU)(UINT_PTR)id, g_hInst, NULL);
    SendMessageA(he, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
    return he;
}
static HWND CreateBtn(HWND hWnd, int id, const char *text, int x, int y, int w, int h) {
    HWND hb = CreateWindowA("BUTTON", text, WS_VISIBLE|WS_CHILD|BS_PUSHBUTTON,
                            x, y, w, h, hWnd, (HMENU)(UINT_PTR)id, g_hInst, NULL);
    SendMessageA(hb, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
    return hb;
}

static void gui_load_conf(HWND hWnd) {
    CONF c;
    memset(&c, 0, sizeof(c));
    strncpy(c.host,      "127.0.0.1",  sizeof(c.host)-1);
    c.port = 15050;
    strncpy(c.user,      "tvcas",      sizeof(c.user)-1);
    strncpy(c.pass,      "1234",       sizeof(c.pass)-1);
    strncpy(c.deskey,    "0102030405060708091011121314", sizeof(c.deskey)-1);
    strncpy(c.caid,      "0B00",       sizeof(c.caid)-1);
    strncpy(c.sid,       "0001",       sizeof(c.sid)-1);
    strncpy(c.provid,    "000000",     sizeof(c.provid)-1);
    strncpy(c.masterkey, "9F3C17A2B5D0481E6A7B92F4C8E05D13A1B9E4F276C3058D4ACF19B08273DE5F", sizeof(c.masterkey)-1);
    c.interval = 10;
    conf_load(&c);
    char portbuf[16], ivbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%d", c.port);
    snprintf(ivbuf,   sizeof(ivbuf),   "%d", c.interval);
    SetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_HOST),      c.host);
    SetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_PORT),      portbuf);
    SetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_USER),      c.user);
    SetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_PASS),      c.pass);
    SetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_DESKEY),    c.deskey);
    SetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_CAID),      c.caid);
    SetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_SID),       c.sid);
    SetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_PROVID),    c.provid);
    SetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_MASTERKEY), c.masterkey);
    SetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_INTERVAL),  ivbuf);
}

static void gui_save_conf(HWND hWnd) {
    CONF c;
    memset(&c, 0, sizeof(c));
    char portbuf[16], ivbuf[16];
    GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_HOST),      c.host,      sizeof(c.host));
    GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_PORT),      portbuf,     sizeof(portbuf));
    GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_USER),      c.user,      sizeof(c.user));
    GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_PASS),      c.pass,      sizeof(c.pass));
    GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_DESKEY),    c.deskey,    sizeof(c.deskey));
    GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_CAID),      c.caid,      sizeof(c.caid));
    GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_SID),       c.sid,       sizeof(c.sid));
    GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_PROVID),    c.provid,    sizeof(c.provid));
    GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_MASTERKEY), c.masterkey, sizeof(c.masterkey));
    GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_INTERVAL),  ivbuf,       sizeof(ivbuf));
    c.port     = atoi(portbuf);
    c.interval = atoi(ivbuf);
    conf_save(&c);
}

static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        int lw = 72;
        int fw = 290;
        int sw = 90;
        int nw = 72;
        int x0 = 8;
        int rh = 24;
        int rs = 26;
        int y  = 10;

        int xL1 = x0;
        int xF1 = xL1 + lw + 4;
        int xL2 = xF1 + fw + 8;
        int xF2 = xL2 + sw + 4;
        int xL3 = xF2 + sw + 8;
        int xF3 = xL3 + nw + 4;

        CreateLabel(hWnd, "HOST",    xL1, y+4, lw, 16);
        CreateEdit (hWnd, IDC_EDIT_HOST,  "127.0.0.1", xF1, y, fw, rh, 0);
        CreateLabel(hWnd, "PORT",    xL2, y+4, sw, 16);
        CreateEdit (hWnd, IDC_EDIT_PORT,  "15050",     xF2, y, sw, rh, 0);
        CreateLabel(hWnd, "CAID",    xL3, y+4, nw, 16);
        CreateEdit (hWnd, IDC_EDIT_CAID,  "0B00",      xF3, y, nw, rh, 0);
        y += rs;

        CreateLabel(hWnd, "USER",    xL1, y+4, lw, 16);
        CreateEdit (hWnd, IDC_EDIT_USER,  "tvcas",     xF1, y, fw, rh, 0);
        CreateLabel(hWnd, "PASS",    xL2, y+4, sw, 16);
        CreateEdit (hWnd, IDC_EDIT_PASS,  "1234",      xF2, y, sw, rh, 0);
        CreateLabel(hWnd, "SID",     xL3, y+4, nw, 16);
        CreateEdit (hWnd, IDC_EDIT_SID,   "0001",      xF3, y, nw, rh, 0);
        y += rs;

        CreateLabel(hWnd, "DES KEY", xL1, y+4, lw, 16);
        CreateEdit (hWnd, IDC_EDIT_DESKEY,"0102030405060708091011121314", xF1, y, fw, rh, 0);
        g_hwnd_chk_tvcas4 = CreateWindowA("BUTTON", "TVCAS4",
                   WS_VISIBLE|WS_CHILD|BS_AUTOCHECKBOX,
                   xL2, y+4, sw + 4 + sw, 16,
                   hWnd, (HMENU)(UINT_PTR)IDC_CHK_TVCAS4, g_hInst, NULL);
        SendMessageA(g_hwnd_chk_tvcas4, WM_SETFONT,
                     (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
        CreateLabel(hWnd, "PROVID",  xL3, y+4, nw, 16);
        CreateEdit (hWnd, IDC_EDIT_PROVID,"000000",    xF3, y, nw, rh, 0);
        y += rs;

        int mk_w = xF2 + sw - xF1;
        CreateLabel(hWnd, "MASTER KEY", xL1, y+4, lw, 16);
        CreateEdit (hWnd, IDC_EDIT_MASTERKEY,
                    "9F3C17A2B5D0481E6A7B92F4C8E05D13A1B9E4F276C3058D4ACF19B08273DE5F",
                    xF1, y, mk_w, rh, 0);
        CreateLabel(hWnd, "INTERVAL", xL3, y+4, nw, 16);
        CreateEdit (hWnd, IDC_EDIT_INTERVAL, "10",     xF3, y, nw, rh, 0);

        y += rs + 6;

        CreateBtn(hWnd, IDC_BTN_RUN,   "Run Test",  x0,      y, 90, 26);
        CreateBtn(hWnd, IDC_BTN_STOP,  "Stop",      x0+98,   y, 72, 26);
        CreateBtn(hWnd, IDC_BTN_CLEAR, "Clear Log", x0+178,  y, 82, 26);
        y += 34;

        g_hLog = CreateWindowA("EDIT", "",
                               WS_VISIBLE|WS_CHILD|WS_BORDER|WS_VSCROLL|WS_HSCROLL|
                               ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY,
                               8, y, 1, 1, hWnd,
                               (HMENU)(UINT_PTR)IDC_EDIT_LOG, g_hInst, NULL);
        SendMessageA(g_hLog, WM_SETFONT,
                     (WPARAM)CreateFontA(14,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,
                                        OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,DEFAULT_QUALITY,
                                        FIXED_PITCH|FF_MODERN,"Consolas"), TRUE);
        gui_load_conf(hWnd);
        AppendLog("Ready -- fill fields and click Run Test.");
        break;
    }
    case WM_SIZE: {
        RECT rc;
        GetClientRect(hWnd, &rc);
        int log_y = 140;
        int w = rc.right - 16;
        int h = rc.bottom - log_y - 8;
        if (g_hLog && h > 40)
            SetWindowPos(g_hLog, NULL, 8, log_y, w, h, SWP_NOZORDER);
        break;
    }
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_BTN_RUN:
            if (g_thread) { AppendLog("[!] Already running -- click Stop first."); break; }
            {
                gui_save_conf(hWnd);
                THREAD_PARAM *tp = (THREAD_PARAM *)calloc(1, sizeof(THREAD_PARAM));
                char portbuf[16], itv[16];
                GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_HOST),      tp->host,      sizeof(tp->host));
                GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_PORT),      portbuf,       sizeof(portbuf));
                GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_USER),      tp->user,      sizeof(tp->user));
                GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_PASS),      tp->pass,      sizeof(tp->pass));
                GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_DESKEY),    tp->deskey,    sizeof(tp->deskey));
                GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_CAID),      tp->caid,      sizeof(tp->caid));
                GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_SID),       tp->sid,       sizeof(tp->sid));
                GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_PROVID),    tp->provid,    sizeof(tp->provid));
                GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_MASTERKEY), tp->masterkey, sizeof(tp->masterkey));
                GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_INTERVAL),  itv,           sizeof(itv));
                tp->port             = atoi(portbuf);
                tp->ecm_interval_sec = atoi(itv);
                tp->is_tvcas4 = (SendMessageA(g_hwnd_chk_tvcas4, BM_GETCHECK, 0, 0) == BST_CHECKED);
                g_thread = CreateThread(NULL, 0, NetworkThread, tp, 0, NULL);
            }
            break;
        case IDC_BTN_STOP:
            InterlockedExchange(&g_stop_flag, 1);
            break;
        case IDC_BTN_CLEAR:
            SetWindowTextA(g_hLog, "");
            break;
        }
        break;
    case WM_DESTROY:
        gui_save_conf(hWnd);
        InterlockedExchange(&g_stop_flag, 1);
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProcA(hWnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    (void)hPrevInstance; (void)lpCmdLine;
    g_hInst = hInstance;
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    srand((unsigned)time(NULL));

    WNDCLASSEXA wc = {0};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.hIcon         = LoadIcon(NULL, IDI_APPLICATION);
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE+1);
    wc.lpszClassName = "TNFSClass";
    RegisterClassExA(&wc);

    g_hWnd = CreateWindowExA(0, "TNFSClass",
                              "TVCAS Newcamd Fake Stream (TNFS)",
                              WS_OVERLAPPEDWINDOW,
                              CW_USEDEFAULT, CW_USEDEFAULT, 760, 560,
                              NULL, NULL, hInstance, NULL);
    ShowWindow(g_hWnd, nCmdShow);
    UpdateWindow(g_hWnd);

    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    WSACleanup();
    return (int)msg.wParam;
}

#else

static void gtk_save_conf(void) {
    CONF c;
    memset(&c, 0, sizeof(c));
    strncpy(c.host,      gtk_entry_get_text(GTK_ENTRY(g_entry_host)),      sizeof(c.host)-1);
    c.port = atoi(gtk_entry_get_text(GTK_ENTRY(g_entry_port)));
    strncpy(c.user,      gtk_entry_get_text(GTK_ENTRY(g_entry_user)),      sizeof(c.user)-1);
    strncpy(c.pass,      gtk_entry_get_text(GTK_ENTRY(g_entry_pass)),      sizeof(c.pass)-1);
    strncpy(c.deskey,    gtk_entry_get_text(GTK_ENTRY(g_entry_deskey)),    sizeof(c.deskey)-1);
    strncpy(c.caid,      gtk_entry_get_text(GTK_ENTRY(g_entry_caid)),      sizeof(c.caid)-1);
    strncpy(c.sid,       gtk_entry_get_text(GTK_ENTRY(g_entry_sid)),       sizeof(c.sid)-1);
    strncpy(c.provid,    gtk_entry_get_text(GTK_ENTRY(g_entry_provid)),    sizeof(c.provid)-1);
    strncpy(c.masterkey, gtk_entry_get_text(GTK_ENTRY(g_entry_masterkey)), sizeof(c.masterkey)-1);
    c.interval = atoi(gtk_entry_get_text(GTK_ENTRY(g_entry_interval)));
    conf_save(&c);
}

static void on_run_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (g_thread_running) {
        AppendLog("[!] Already running -- click Stop first.");
        return;
    }
    gtk_save_conf();
    THREAD_PARAM *tp = (THREAD_PARAM *)calloc(1, sizeof(THREAD_PARAM));
    strncpy(tp->host,      gtk_entry_get_text(GTK_ENTRY(g_entry_host)),      sizeof(tp->host)-1);
    tp->port = atoi(gtk_entry_get_text(GTK_ENTRY(g_entry_port)));
    strncpy(tp->user,      gtk_entry_get_text(GTK_ENTRY(g_entry_user)),      sizeof(tp->user)-1);
    strncpy(tp->pass,      gtk_entry_get_text(GTK_ENTRY(g_entry_pass)),      sizeof(tp->pass)-1);
    strncpy(tp->deskey,    gtk_entry_get_text(GTK_ENTRY(g_entry_deskey)),    sizeof(tp->deskey)-1);
    strncpy(tp->caid,      gtk_entry_get_text(GTK_ENTRY(g_entry_caid)),      sizeof(tp->caid)-1);
    strncpy(tp->sid,       gtk_entry_get_text(GTK_ENTRY(g_entry_sid)),       sizeof(tp->sid)-1);
    strncpy(tp->provid,    gtk_entry_get_text(GTK_ENTRY(g_entry_provid)),    sizeof(tp->provid)-1);
    strncpy(tp->masterkey, gtk_entry_get_text(GTK_ENTRY(g_entry_masterkey)), sizeof(tp->masterkey)-1);
    tp->ecm_interval_sec = atoi(gtk_entry_get_text(GTK_ENTRY(g_entry_interval)));
    tp->is_tvcas4 = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(g_chk_tvcas4));
    g_thread_running = true;
    pthread_create(&g_thread, NULL, NetworkThread, tp);
    pthread_detach(g_thread);
}

static void on_stop_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    g_stop_flag = 1;
}

static void on_clear_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    gtk_text_buffer_set_text(g_log_buf, "", 0);
}

static gboolean on_delete_event(GtkWidget *widget, GdkEvent *event, gpointer data)
{
    (void)widget; (void)event; (void)data;
    g_stop_flag = 1;
    gtk_save_conf();
    return FALSE;
}

static GtkWidget *make_entry(const char *def, int chars) {
    GtkWidget *e = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(e), def);
    gtk_entry_set_width_chars(GTK_ENTRY(e), chars);
    return e;
}

static GtkWidget *make_label(const char *text) {
    GtkWidget *l = gtk_label_new(text);
    gtk_widget_set_halign(l, GTK_ALIGN_END);
    return l;
}

static void gtk_load_conf(void) {
    CONF c;
    memset(&c, 0, sizeof(c));
    strncpy(c.host,      "127.0.0.1",  sizeof(c.host)-1);
    c.port = 15050;
    strncpy(c.user,      "tvcas",      sizeof(c.user)-1);
    strncpy(c.pass,      "1234",       sizeof(c.pass)-1);
    strncpy(c.deskey,    "0102030405060708091011121314", sizeof(c.deskey)-1);
    strncpy(c.caid,      "0B00",       sizeof(c.caid)-1);
    strncpy(c.sid,       "0001",       sizeof(c.sid)-1);
    strncpy(c.provid,    "000000",     sizeof(c.provid)-1);
    strncpy(c.masterkey, "9F3C17A2B5D0481E6A7B92F4C8E05D13A1B9E4F276C3058D4ACF19B08273DE5F", sizeof(c.masterkey)-1);
    c.interval = 10;
    conf_load(&c);
    char portbuf[16], ivbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%d", c.port);
    snprintf(ivbuf,   sizeof(ivbuf),   "%d", c.interval);
    gtk_entry_set_text(GTK_ENTRY(g_entry_host),      c.host);
    gtk_entry_set_text(GTK_ENTRY(g_entry_port),      portbuf);
    gtk_entry_set_text(GTK_ENTRY(g_entry_user),      c.user);
    gtk_entry_set_text(GTK_ENTRY(g_entry_pass),      c.pass);
    gtk_entry_set_text(GTK_ENTRY(g_entry_deskey),    c.deskey);
    gtk_entry_set_text(GTK_ENTRY(g_entry_caid),      c.caid);
    gtk_entry_set_text(GTK_ENTRY(g_entry_sid),       c.sid);
    gtk_entry_set_text(GTK_ENTRY(g_entry_provid),    c.provid);
    gtk_entry_set_text(GTK_ENTRY(g_entry_masterkey), c.masterkey);
    gtk_entry_set_text(GTK_ENTRY(g_entry_interval),  ivbuf);
}

int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);
    srand((unsigned)time(NULL));

    g_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(g_window), "TVCAS Newcamd Fake Stream (TNFS)");
    gtk_window_set_default_size(GTK_WINDOW(g_window), 860, 520);
    gtk_window_set_resizable(GTK_WINDOW(g_window), TRUE);
    g_signal_connect(g_window, "destroy",      G_CALLBACK(gtk_main_quit),    NULL);
    g_signal_connect(g_window, "delete-event", G_CALLBACK(on_delete_event),  NULL);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 8);
    gtk_container_add(GTK_CONTAINER(g_window), vbox);

    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_column_spacing(GTK_GRID(grid), 6);
    gtk_grid_set_row_spacing(GTK_GRID(grid), 4);
    gtk_box_pack_start(GTK_BOX(vbox), grid, FALSE, FALSE, 0);

    g_entry_host     = make_entry("127.0.0.1", 30);
    g_entry_port     = make_entry("15050",     12);
    g_entry_user     = make_entry("tvcas",     30);
    g_entry_pass     = make_entry("1234",      12);
    g_entry_interval = make_entry("10",         6);
    g_entry_deskey   = make_entry("0102030405060708091011121314", 30);
    g_entry_caid     = make_entry("0B00",   7);
    g_entry_sid      = make_entry("0001",   7);
    g_entry_provid   = make_entry("000000", 7);

    gtk_widget_set_hexpand(g_entry_host,   TRUE);
    gtk_widget_set_hexpand(g_entry_user,   TRUE);
    gtk_widget_set_hexpand(g_entry_deskey, TRUE);

    gtk_grid_attach(GTK_GRID(grid), make_label("HOST"),  0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), g_entry_host,        1, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), make_label("PORT"),  2, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), g_entry_port,        3, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), make_label("CAID"),  4, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), g_entry_caid,        5, 0, 1, 1);

    gtk_grid_attach(GTK_GRID(grid), make_label("USER"),  0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), g_entry_user,        1, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), make_label("PASS"),  2, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), g_entry_pass,        3, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), make_label("SID"),   4, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), g_entry_sid,         5, 1, 1, 1);

    gtk_grid_attach(GTK_GRID(grid), make_label("DES KEY"), 0, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), g_entry_deskey,        1, 2, 1, 1);
    g_chk_tvcas4 = gtk_check_button_new_with_label("TVCAS4 key");
    gtk_grid_attach(GTK_GRID(grid), g_chk_tvcas4,          2, 2, 2, 1);
    gtk_grid_attach(GTK_GRID(grid), make_label("PROVID"),  4, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), g_entry_provid,        5, 2, 1, 1);

    g_entry_masterkey = make_entry(
        "9F3C17A2B5D0481E6A7B92F4C8E05D13A1B9E4F276C3058D4ACF19B08273DE5F", 46);
    gtk_widget_set_hexpand(g_entry_masterkey, TRUE);
    gtk_grid_attach(GTK_GRID(grid), make_label("MASTER KEY"), 0, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), g_entry_masterkey,        1, 3, 3, 1);
    gtk_grid_attach(GTK_GRID(grid), make_label("INTERVAL"),   4, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), g_entry_interval,         5, 3, 1, 1);

    gtk_load_conf();

    GtkWidget *btnbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_pack_start(GTK_BOX(vbox), btnbox, FALSE, FALSE, 2);

    g_btn_run  = gtk_button_new_with_label("Run Test");
    g_btn_stop = gtk_button_new_with_label("Stop");
    GtkWidget *btn_clear = gtk_button_new_with_label("Clear Log");

    g_signal_connect(g_btn_run,  "clicked", G_CALLBACK(on_run_clicked),  NULL);
    g_signal_connect(g_btn_stop, "clicked", G_CALLBACK(on_stop_clicked), NULL);
    g_signal_connect(btn_clear,  "clicked", G_CALLBACK(on_clear_clicked),NULL);

    gtk_box_pack_start(GTK_BOX(btnbox), g_btn_run,  FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btnbox), g_btn_stop, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btnbox), btn_clear,  FALSE, FALSE, 0);

    GtkWidget *sep = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_box_pack_start(GTK_BOX(vbox), sep, FALSE, FALSE, 0);

    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);
    g_log_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(g_log_view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(g_log_view), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(g_log_view), TRUE);
    g_log_buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(g_log_view));
    GtkTextIter end_iter;
    gtk_text_buffer_get_end_iter(g_log_buf, &end_iter);
    g_log_end_mark = gtk_text_buffer_create_mark(g_log_buf, "end", &end_iter, FALSE);
    gtk_container_add(GTK_CONTAINER(scroll), g_log_view);
    gtk_widget_set_size_request(scroll, -1, 300);
    gtk_box_pack_start(GTK_BOX(vbox), scroll, TRUE, TRUE, 0);

    gtk_widget_show_all(g_window);
    AppendLog("Ready. Fill fields and click Run Test.");
    gtk_main();
    return 0;
}

#endif
