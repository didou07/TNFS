#include "ecm.h"
#include "crypto.h"

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
    memset(key16, 0, 16);
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
