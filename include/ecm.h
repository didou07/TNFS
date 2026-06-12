#ifndef ECM_H
#define ECM_H

#include "platform.h"

void ecm_build(uint8_t *ecm_buf, int *ecm_len,
               const uint8_t *cw_even8,
               const uint8_t *cw_odd8,
               uint8_t table_id,
               const uint8_t *master_key32);

#endif
