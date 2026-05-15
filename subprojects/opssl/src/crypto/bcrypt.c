/*
 * opssl/crypto/bcrypt.c — bcrypt password hashing (OpenBSD).
 *
 * Implements EksBlowfish-based password hashing per OpenBSD specs.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/crypto.h>
#include <opssl/platform.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "bcrypt_tables.h"

typedef struct {
    uint32_t P[18];
    uint32_t S[4][256];
} bf_ctx_t;

static void
bf_encrypt(const bf_ctx_t *ctx, uint32_t *xl, uint32_t *xr)
{
    uint32_t L = *xl;
    uint32_t R = *xr;

    for (int i = 0; i < 16; i++) {
        L ^= ctx->P[i];
        uint32_t f = ((ctx->S[0][(L >> 24) & 0xff] + ctx->S[1][(L >> 16) & 0xff]) ^
                      ctx->S[2][(L >> 8) & 0xff]) + ctx->S[3][L & 0xff];
        R ^= f;
        uint32_t tmp = L; L = R; R = tmp;
    }

    uint32_t tmp = L; L = R; R = tmp;
    R ^= ctx->P[16];
    L ^= ctx->P[17];
    *xl = L;
    *xr = R;
}

static void
bf_expand(bf_ctx_t *ctx, const uint8_t *data, size_t len, const uint8_t *key, size_t key_len)
{
    uint32_t L = 0, R = 0;
    int k_idx = 0;

    for (int i = 0; i < 18; i++) {
        uint32_t val = 0;
        for (int j = 0; j < 4; j++) {
            val = (val << 8) | key[k_idx];
            k_idx = (k_idx + 1) % key_len;
        }
        ctx->P[i] ^= val;
    }

    int d_idx = 0;
    for (int i = 0; i < 18; i += 2) {
        if (len > 0) {
            uint32_t l_val = 0, r_val = 0;
            for (int j = 0; j < 4; j++) {
                l_val = (l_val << 8) | data[d_idx];
                d_idx = (d_idx + 1) % len;
            }
            for (int j = 0; j < 4; j++) {
                r_val = (r_val << 8) | data[d_idx];
                d_idx = (d_idx + 1) % len;
            }
            L ^= l_val;
            R ^= r_val;
        }
        bf_encrypt(ctx, &L, &R);
        ctx->P[i] = L;
        ctx->P[i+1] = R;
    }

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 256; j += 2) {
            if (len > 0) {
                uint32_t l_val = 0, r_val = 0;
                for (int k = 0; k < 4; k++) {
                    l_val = (l_val << 8) | data[d_idx];
                    d_idx = (d_idx + 1) % len;
                }
                for (int k = 0; k < 4; k++) {
                    r_val = (r_val << 8) | data[d_idx];
                    d_idx = (d_idx + 1) % len;
                }
                L ^= l_val;
                R ^= r_val;
            }
            bf_encrypt(ctx, &L, &R);
            ctx->S[i][j] = L;
            ctx->S[i][j+1] = R;
        }
    }
}

static void
eks_bf_setup(bf_ctx_t *ctx, uint32_t cost, const uint8_t *salt, size_t salt_len, const uint8_t *key, size_t key_len)
{
    memcpy(ctx->P, bf_init_p, sizeof(ctx->P));
    memcpy(ctx->S, bf_init_s, sizeof(ctx->S));

    bf_expand(ctx, salt, salt_len, key, key_len);

    for (uint32_t i = 0; i < (1U << cost); i++) {
        bf_expand(ctx, NULL, 0, key, key_len);
        bf_expand(ctx, NULL, 0, salt, salt_len);
    }
}

static const char bcrypt_b64_table[] =
    "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

static void
bcrypt_b64_encode(char *s, const uint8_t *data, size_t len)
{
    int i = 0, j = 0;
    uint32_t c1, c2;

    while (i < (int)len) {
        c1 = data[i++];
        s[j++] = bcrypt_b64_table[(c1 >> 2) & 0x3f];
        c1 = (c1 & 0x03) << 4;
        if (i >= (int)len) {
            s[j++] = bcrypt_b64_table[c1 & 0x3f];
            break;
        }
        c2 = data[i++];
        c1 |= (c2 >> 4) & 0x0f;
        s[j++] = bcrypt_b64_table[c1 & 0x3f];
        c1 = (c2 & 0x0f) << 2;
        if (i >= (int)len) {
            s[j++] = bcrypt_b64_table[c1 & 0x3f];
            break;
        }
        c2 = data[i++];
        c1 |= (c2 >> 6) & 0x03;
        s[j++] = bcrypt_b64_table[c1 & 0x3f];
        s[j++] = bcrypt_b64_table[c2 & 0x3f];
    }
    s[j] = '\0';
}

static int
bcrypt_b64_decode(uint8_t *data, size_t max_len, const char *s)
{
    /* Minimal decoder for salt verification */
    static int8_t map[256];
    static bool map_inited = false;
    if (!map_inited) {
        memset(map, -1, 256);
        for (int i = 0; i < 64; i++) map[(uint8_t)bcrypt_b64_table[i]] = i;
        map_inited = true;
    }

    int i = 0, j = 0;
    while (s[i] && j < (int)max_len) {
        uint32_t c1 = map[(uint8_t)s[i++]];
        uint32_t c2 = map[(uint8_t)s[i++]];
        data[j++] = (c1 << 2) | ((c2 >> 4) & 0x03);
        if (!s[i] || j >= (int)max_len) break;
        uint32_t c3 = map[(uint8_t)s[i++]];
        data[j++] = ((c2 & 0x0f) << 4) | ((c3 >> 2) & 0x0f);
        if (!s[i] || j >= (int)max_len) break;
        uint32_t c4 = map[(uint8_t)s[i++]];
        data[j++] = ((c3 & 0x03) << 6) | c4;
    }
    return j;
}

int
opssl_bcrypt_hash(const char *password, const char *salt_str, char *out)
{
    if (!password || !salt_str || !out) return 0;

    /* Parse salt: $2[ab]$COST$22CHARS */
    if (salt_str[0] != '$' || salt_str[1] != '2') return 0;
    char minor = salt_str[2];
    if (minor != 'a' && minor != 'b' && minor != 'y') return 0;
    if (salt_str[3] != '$') return 0;
    int cost = atoi(salt_str + 4);
    if (cost < 4 || cost > 31) return 0;
    const char *b64_salt = salt_str + 7;

    uint8_t salt[16];
    if (bcrypt_b64_decode(salt, 16, b64_salt) < 16) return 0;

    bf_ctx_t ctx;
    size_t pw_len = strlen(password);
    /* bcrypt uses password + NULL, max 72 chars */
    uint8_t pw[73];
    memset(pw, 0, 73);
    memcpy(pw, password, pw_len > 72 ? 72 : pw_len);
    if (pw_len < 72) pw_len++; else pw_len = 72;

    eks_bf_setup(&ctx, cost, salt, 16, pw, pw_len);

    /* Encrypt "OrpheanBeholderScryDoubt" 64 times */
    uint32_t cdata[6] = {
        0x4f727068, 0x65616e42, 0x65686f6c, 0x64657253, 0x63727944, 0x6f756274
    };

    for (int i = 0; i < 64; i++) {
        for (int j = 0; j < 6; j += 2) {
            bf_encrypt(&ctx, &cdata[j], &cdata[j+1]);
        }
    }

    uint8_t result[24];
    for (int i = 0; i < 6; i++) {
        opssl_put_be32(result + i*4, cdata[i]);
    }

    /* Format output: $2b$COST$SALT(22)HASH(31) */
    sprintf(out, "$2%c$%02d$", minor, cost);
    memcpy(out + 7, b64_salt, 22);
    bcrypt_b64_encode(out + 29, result, 23);

    opssl_memzero(&ctx, sizeof(ctx));
    opssl_memzero(pw, sizeof(pw));
    return 1;
}

int
opssl_bcrypt_verify(const char *password, const char *hash)
{
    char new_hash[64];
    if (!opssl_bcrypt_hash(password, hash, new_hash)) return 0;
    return strcmp(new_hash, hash) == 0;
}

int
opssl_bcrypt_gensalt(int work_factor, char *out)
{
    uint8_t rnd[16];
    if (!opssl_random_bytes(rnd, 16)) return 0;
    sprintf(out, "$2b$%02d$", work_factor);
    bcrypt_b64_encode(out + 7, rnd, 16);
    return 1;
}
