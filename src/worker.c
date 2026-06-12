#include "worker.h"
#include "newcamd.h"
#include "ecm.h"
#include "util.h"
#include "log.h"

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
        memset(cw_even, 0, 8); memset(cw_odd, 0, 8); memset(new_cw, 0, 8);

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
    memset(master_key, 0, 32);
    free(ctx);

#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}
