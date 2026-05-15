/*
 * opssl/crypto/totp.c — Time-based One-Time Password (RFC 6238).
 *
 * Implements TOTP using HMAC-SHA1 (default).
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/crypto.h>
#include <opssl/platform.h>
#include <string.h>

int
opssl_totp_generate(const uint8_t *secret, size_t secret_len,
                    uint64_t timestamp, uint32_t digits, uint32_t *out)
{
    if (!secret || secret_len == 0 || digits < 6 || digits > 8 || !out)
        return 0;

    /* T = (Current Time - T0) / X */
    /* Default: T0 = 0, X = 30 seconds */
    uint64_t steps = timestamp / 30;
    uint8_t msg[8];
    opssl_put_be64(msg, steps);

    /* HMAC-SHA1(secret, steps) */
    uint8_t hash[OPSSL_SHA1_DIGEST_LEN];
    size_t hash_len;
    if (!opssl_hmac(OPSSL_HMAC_SHA1, secret, secret_len, msg, 8, hash, &hash_len))
        return 0;

    /* Dynamic truncation (RFC 4226 section 5.4) */
    uint8_t offset = hash[19] & 0x0f;
    uint32_t binary = ((uint32_t)(hash[offset] & 0x7f) << 24) |
                      ((uint32_t)(hash[offset + 1] & 0xff) << 16) |
                      ((uint32_t)(hash[offset + 2] & 0xff) << 8) |
                      ((uint32_t)(hash[offset + 3] & 0xff));

    /* Extract digits */
    uint32_t div = 1;
    for (uint32_t i = 0; i < digits; i++)
        div *= 10;

    *out = binary % div;

    opssl_memzero(hash, sizeof(hash));
    return 1;
}
