#include "newcamd.h"
#include "crypto.h"
#include "util.h"
#include "tvcas.h"
#include "log.h"

static uint8_t nc_xor(const uint8_t *buf, int len) {
    uint8_t x = 0;
    for (int i = 0; i < len; i++) x ^= buf[i];
    return x;
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

int nc_send(nc_client_t *cl, const uint8_t *data, int dlen,
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
    memcpy(buf + 12, data, dlen);
    buf[13] = (data[1] & 0xF0) | (((dlen-3) >> 8) & 0x0F);
    buf[14] = (dlen-3) & 0xFF;
    uint32_t blen = (uint32_t)dlen + 12;
    uint8_t pad[8];
    rand_bytes(pad, 8);
    uint32_t plen = (8 - ((blen-1) % 8)) % 8;
    memcpy(buf + blen, pad, plen);
    blen += plen;
    buf[blen] = nc_xor(buf + 2, (int)(blen - 2));
    blen++;
    uint8_t iv[8];
    rand_bytes(iv, 8);
    memcpy(buf + blen, iv, 8);
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

int nc_recv(nc_client_t *cl, uint8_t *data,
            uint16_t *sid, uint16_t *mid, uint16_t *caid)
{
    for (int _try = 0; _try < 32; _try++) {
        uint8_t lenbuf[2], *buf = cl->recv_buf;
        if (recv_all(cl->fd, lenbuf, 2) != 2) return -1;
        uint16_t total_len = (uint16_t)((lenbuf[0] << 8) | lenbuf[1]);
        if (!total_len || total_len > NC_MSG_MAX) return -1;
        if (recv_all(cl->fd, buf, total_len) != (int)total_len) return -1;
        if (total_len < 8) return -1;
        uint16_t payload_len = total_len - 8;
        uint8_t iv[8], key16[16];
        memcpy(iv, buf + payload_len, 8);
        memcpy(key16,   cl->key1, 8);
        memcpy(key16+8, cl->key2, 8);
        ede2_cbc_dec(key16, iv, buf, buf, payload_len);
        memset(key16, 0, 16);
        if (nc_xor(buf, payload_len)) return -1;
        *mid  = (uint16_t)((buf[0] << 8) | buf[1]);
        *sid  = (uint16_t)((buf[2] << 8) | buf[3]);
        *caid = (uint16_t)((buf[4] << 8) | buf[5]);
        if (payload_len < (uint16_t)(NC_HDR_LEN + 5)) return -1;
        uint32_t rlen = (uint32_t)((((buf[3+NC_HDR_LEN] & 0x0F) << 8) |
                                      buf[4+NC_HDR_LEN]) + 3);
        if (rlen + 2 + NC_HDR_LEN > (uint32_t)payload_len) return -1;
        memcpy(data, buf + 2 + NC_HDR_LEN, rlen);
        if (rlen >= 1 && (data[0] == 0xD3 || data[0] == 0xD6)) continue;
        return (int)rlen;
    }
    return -1;
}

nc_client_t *nc_connect(const nc_params_t *p,
                        uint16_t *caid_out,
                        uint16_t *sid_out,
                        uint32_t *provid_out,
                        uint8_t   master_key_out[32])
{
    uint8_t des_key14[14];
    if (!parse_hex(p->deskey, des_key14, 14)) {
        log_append("[!] DES key parse error (need 28 hex chars)");
        return NULL;
    }

    uint16_t caid   = 0x0B00;
    uint16_t sid    = 0x0001;
    uint32_t provid = 0x000000;
    if (strlen(p->caid)   > 0) sscanf(p->caid,   "%hx", &caid);
    if (strlen(p->sid)    > 0) sscanf(p->sid,    "%hx", &sid);
    if (strlen(p->provid) > 0) sscanf(p->provid, "%x",  &provid);

    if (caid == 0x0900) {
        log_append("[*] TVCAS4 CAID 0900 -> remapping to 0B00");
        caid = 0x0B00;
    }

    const char *mk_str = (strlen(p->masterkey) > 0)
        ? p->masterkey
        : "9F3C17A2B5D0481E6A7B92F4C8E05D13A1B9E4F276C3058D4ACF19B08273DE5F";

    if (strlen(mk_str) != 64) {
        log_append("[!] Master key must be 64 hex chars (32 bytes)");
        return NULL;
    }

    uint8_t master_raw[32];
    for (int i = 0; i < 32; i++) {
        unsigned v; sscanf(mk_str + i*2, "%02x", &v);
        master_raw[i] = (uint8_t)v;
    }

    uint8_t master_key[32];
    if (p->is_tvcas4) {
        log_append("[*] Converting TVCAS4 master key to TVCAS3");
        tvcas4_to_v3(master_raw, master_key, 32);
    } else {
        memcpy(master_key, master_raw, 32);
    }

    log_append("(newcamd) %s connecting ....", p->host);

    sock_t fd = connect_server(p->host, p->port);
    if (fd == SOCK_INVALID) {
        log_append("[!] Connection failed");
        return NULL;
    }

    nc_client_t *cl = (nc_client_t *)calloc(1, sizeof(nc_client_t));
    cl->fd  = fd;
    cl->mid = 1;

    uint8_t srv_rnd[14];
    if (recv_all(fd, srv_rnd, 14) != 14) {
        log_append("[!] Server nonce not received");
        sock_close(fd); free(cl);
        return NULL;
    }
    uint8_t xored[14], spread[16];
    for (int i = 0; i < 14; i++) xored[i] = srv_rnd[i] ^ des_key14[i];
    key_spread(xored, spread);
    memcpy(cl->key1, spread,   8);
    memcpy(cl->key2, spread+8, 8);
    memcpy(cl->session_key, des_key14, 14);
    memset(xored,  0, 14);
    memset(spread, 0, 16);

    char hash[64];
    if (!md5_crypt(p->pass, "$1$abcdefgh$", hash, sizeof(hash))) {
        log_append("[!] Failed to generate MD5 hash");
        sock_close(fd); free(cl);
        return NULL;
    }

    uint8_t login_buf[256];
    int lpos = 0;
    size_t ulen = strlen(p->user);
    size_t hlen = strlen(hash);
    login_buf[lpos++] = MSG_CLIENT_LOGIN;
    login_buf[lpos++] = 0x00;
    login_buf[lpos++] = (uint8_t)((ulen+1) + (hlen+1));
    memcpy(login_buf + lpos, p->user, ulen+1); lpos += (int)ulen+1;
    memcpy(login_buf + lpos, hash,    hlen+1); lpos += (int)hlen+1;

    if (nc_send(cl, login_buf, lpos, 0x0000, 0x0000, 0) < 0) {
        log_append("[!] Failed to send LOGIN");
        sock_close(fd); free(cl);
        return NULL;
    }

    uint8_t  resp[NC_MSG_MAX];
    uint16_t r_sid, r_mid, r_caid;
    int rlen = nc_recv(cl, resp, &r_sid, &r_mid, &r_caid);
    if (rlen < 1 || resp[0] != MSG_CLIENT_LOGIN_ACK) {
        log_append("[!] Login rejected (cmd=0x%02X)", rlen > 0 ? resp[0] : 0);
        sock_close(fd); free(cl);
        return NULL;
    }

    for (int i = 0; i < (int)hlen; i++)
        cl->session_key[i % 14] ^= (uint8_t)hash[i];
    key_spread(cl->session_key, spread);
    memcpy(cl->key1, spread,   8);
    memcpy(cl->key2, spread+8, 8);
    memset(spread, 0, 16);
    cl->mid++;

    uint8_t card_req[3] = {MSG_CARD_DATA_REQ, 0, 0};
    if (nc_send(cl, card_req, 3, sid, caid, provid) < 0) {
        log_append("[!] Failed to send CARD_DATA_REQ");
        sock_close(fd); free(cl);
        return NULL;
    }
    cl->mid++;
    rlen = nc_recv(cl, resp, &r_sid, &r_mid, &r_caid);
    if (rlen >= 6 && resp[0] == MSG_CARD_DATA) {
        uint16_t got_caid = (uint16_t)((resp[4] << 8) | resp[5]);
        log_append("[card] CAID from server: %04X", got_caid);
    }

    *caid_out   = caid;
    *sid_out    = sid;
    *provid_out = provid;
    memcpy(master_key_out, master_key, 32);
    memset(master_key, 0, 32);

    return cl;
}

void nc_disconnect(nc_client_t *cl) {
    if (!cl) return;
    sock_close(cl->fd);
    free(cl);
}
