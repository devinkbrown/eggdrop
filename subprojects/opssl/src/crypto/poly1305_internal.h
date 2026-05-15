/*
 * poly1305_internal.h — internal Poly1305 streaming API.
 *
 * Shared between poly1305.c and chacha20_poly1305.c (which needs to
 * stream the AEAD construction without heap-allocating the concatenated
 * input buffer).
 *
 * The poly1305_state_t is stack-allocated by callers; the three functions
 * collectively form an init/update/final streaming interface identical in
 * shape to the SHA contexts in sha_internal.h.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef OPSSL_POLY1305_INTERNAL_H
#define OPSSL_POLY1305_INTERNAL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct {
    uint32_t r[5];     /* clamped key */
    uint32_t h[5];     /* accumulator */
    uint32_t pad[4];   /* final pad (s) */
    uint8_t  buf[16];
    size_t   buf_used;
    bool     finalized;
} poly1305_state_t;

void poly1305_init(poly1305_state_t *st, const uint8_t key[32]);
void poly1305_update(poly1305_state_t *st, const uint8_t *data, size_t len);
void poly1305_final(poly1305_state_t *st, uint8_t tag[16]);

#endif /* OPSSL_POLY1305_INTERNAL_H */
