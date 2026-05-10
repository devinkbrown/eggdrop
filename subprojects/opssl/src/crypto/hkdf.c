/*
 * opssl/crypto/hkdf.c — HKDF (RFC 5869) and TLS 1.3 key schedule.
 *
 * HKDF-Extract and HKDF-Expand are the building blocks of the
 * TLS 1.3 key schedule. HKDF-Expand-Label implements the TLS 1.3
 * specific derivation (RFC 8446 §7.1).
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/crypto.h>
#include <opssl/platform.h>
#include <opssl/cbs.h>
#include <string.h>
#include "sha_internal.h"

int
opssl_hkdf_extract(opssl_hmac_algo_t algo,
                   const uint8_t *salt, size_t salt_len,
                   const uint8_t *ikm, size_t ikm_len,
                   uint8_t *prk, size_t *prk_len)
{
    /* If no salt, use a hash-length string of zeros */
    uint8_t zero_salt[OPSSL_SHA512_DIGEST_LEN];
    if (salt == NULL || salt_len == 0) {
        size_t hash_len;
        switch (algo) {
        case OPSSL_HMAC_SHA256: hash_len = OPSSL_SHA256_DIGEST_LEN; break;
        case OPSSL_HMAC_SHA384: hash_len = OPSSL_SHA384_DIGEST_LEN; break;
        case OPSSL_HMAC_SHA512: hash_len = OPSSL_SHA512_DIGEST_LEN; break;
        default: return 0;
        }
        memset(zero_salt, 0, hash_len);
        salt = zero_salt;
        salt_len = hash_len;
    }

    /* PRK = HMAC-Hash(salt, IKM) */
    int ret = opssl_hmac(algo, salt, salt_len, ikm, ikm_len, prk, prk_len);
    opssl_memzero(zero_salt, sizeof(zero_salt));
    return ret;
}

int
opssl_hkdf_expand(opssl_hmac_algo_t algo,
                  const uint8_t *prk, size_t prk_len,
                  const uint8_t *info, size_t info_len,
                  uint8_t *okm, size_t okm_len)
{
    size_t hash_len;
    switch (algo) {
    case OPSSL_HMAC_SHA256: hash_len = OPSSL_SHA256_DIGEST_LEN; break;
    case OPSSL_HMAC_SHA384: hash_len = OPSSL_SHA384_DIGEST_LEN; break;
    case OPSSL_HMAC_SHA512: hash_len = OPSSL_SHA512_DIGEST_LEN; break;
    default: return 0;
    }

    size_t n = (okm_len + hash_len - 1) / hash_len;
    if (n > 255)
        return 0;

    uint8_t T[OPSSL_SHA512_DIGEST_LEN];
    size_t T_len = 0;
    size_t offset = 0;

    for (uint8_t i = 1; i <= (uint8_t)n; i++) {
        opssl_hmac_ctx_t ctx;
        opssl_hmac_init(&ctx, algo, prk, prk_len);

        if (T_len > 0)
            opssl_hmac_update(&ctx, T, T_len);
        if (info_len > 0)
            opssl_hmac_update(&ctx, info, info_len);
        opssl_hmac_update(&ctx, &i, 1);

        opssl_hmac_final(&ctx, T, &T_len);
        opssl_hmac_cleanup(&ctx);

        size_t copy = okm_len - offset;
        if (copy > hash_len)
            copy = hash_len;
        memcpy(okm + offset, T, copy);
        offset += copy;
    }

    opssl_memzero(T, sizeof(T));
    return 1;
}

int
opssl_hkdf_expand_label(opssl_hmac_algo_t algo,
                        const uint8_t *secret, size_t secret_len,
                        const char *label,
                        const uint8_t *context, size_t context_len,
                        uint8_t *out, size_t out_len)
{
    /*
     * HkdfLabel (RFC 8446 §7.1):
     *   uint16 length = Length;
     *   opaque label<7..255> = "tls13 " + Label;
     *   opaque context<0..255> = Context;
     */
    uint8_t info[512];
    opssl_cbb_t cbb;
    opssl_cbb_init_fixed(&cbb, info, sizeof(info));

    opssl_cbb_add_u16(&cbb, (uint16_t)out_len);

    /* Label: "tls13 " + label */
    size_t label_len = strlen(label);
    opssl_cbb_add_u8(&cbb, (uint8_t)(6 + label_len));
    opssl_cbb_add_bytes(&cbb, (const uint8_t *)"tls13 ", 6);
    opssl_cbb_add_bytes(&cbb, (const uint8_t *)label, label_len);

    /* Context */
    opssl_cbb_add_u8(&cbb, (uint8_t)context_len);
    if (context_len > 0)
        opssl_cbb_add_bytes(&cbb, context, context_len);

    size_t info_len = opssl_cbb_len(&cbb);

    int ret = opssl_hkdf_expand(algo, secret, secret_len,
                                info, info_len, out, out_len);

    opssl_memzero(info, sizeof(info));
    return ret;
}
