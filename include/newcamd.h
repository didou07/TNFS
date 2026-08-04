#ifndef NEWCAMD_H
#define NEWCAMD_H

#include "platform.h"

#define NC_MSG_MAX       1024
#define NC_HDR_LEN       8
#define CW_LEN           16

#define MSG_CLIENT_LOGIN     0xe0
#define MSG_CLIENT_LOGIN_ACK 0xe1
#define MSG_CLIENT_LOGIN_NAK 0xe2
#define MSG_CARD_DATA_REQ    0xe3
#define MSG_CARD_DATA        0xe4
#define MSG_KEEPALIVE        0x8d
#define MSG_ECM_0            0x80
#define MSG_ECM_1            0x81

typedef struct {
    sock_t   fd;
    uint8_t  key1[8];
    uint8_t  key2[8];
    uint8_t  session_key[14];
    uint8_t  send_buf[NC_MSG_MAX + 64];
    uint8_t  recv_buf[NC_MSG_MAX];
    uint16_t mid;
} nc_client_t;

typedef struct {
    char     host[256];
    int      port;
    char     user[64];
    char     pass[64];
    char     deskey[64];
    char     caid[16];
    char     sid[16];
    char     provid[16];
    char     masterkey[128];
    int      ecm_interval_sec;
    bool     is_tvcas4;
    char     timestamp[24];
    char     access_criteria[64];
} nc_params_t;

nc_client_t *nc_connect(const nc_params_t *p,
                        uint16_t *caid_out,
                        uint16_t *sid_out,
                        uint32_t *provid_out,
                        uint8_t   master_key_out[32]);

void nc_disconnect(nc_client_t *cl);

int  nc_send(nc_client_t *cl, const uint8_t *data, int dlen,
             uint16_t sid, uint16_t caid, uint32_t provid);

int  nc_recv(nc_client_t *cl, uint8_t *data,
             uint16_t *sid, uint16_t *mid, uint16_t *caid);

#endif
