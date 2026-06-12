#ifndef CRYPTO_H
#define CRYPTO_H

#include "platform.h"

void des_enc(const uint8_t *key, const uint8_t *in, uint8_t *out);
void des_dec(const uint8_t *key, const uint8_t *in, uint8_t *out);

void ede2_ecb_enc(const uint8_t *k16, uint8_t *data, size_t len);
void ede2_cbc_enc(const uint8_t *k16, const uint8_t *iv, const uint8_t *in, uint8_t *out, size_t len);
void ede2_cbc_dec(const uint8_t *k16, const uint8_t *iv, const uint8_t *in, uint8_t *out, size_t len);

void md5_hash(const uint8_t *data, size_t len, uint8_t out[16]);
bool md5_crypt(const char *pw, const char *salt_str, char *out, size_t outsz);

#endif
