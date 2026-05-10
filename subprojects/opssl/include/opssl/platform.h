/*
 * opssl/platform.h — platform layer built on libop.
 *
 * opssl is part of the libop ecosystem. All general allocation, strings,
 * and data structures come from libop. This file adds only what TLS
 * specifically needs on top: secure key memory, constant-time ops, entropy.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef OPSSL_PLATFORM_H
#define OPSSL_PLATFORM_H

#include <sys/socket.h>
#include <op_lib.h>
#include <op_memory.h>
#include <op_strbuf.h>

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ─── Secure Key Memory ──────────────────────────────────────────────── */

/*
 * For key material ONLY. These add mlock + guaranteed zeroing on free.
 * General allocations use op_malloc/op_free from libop.
 */
void *opssl_key_alloc(size_t size);
void *opssl_key_realloc(void *ptr, size_t old_size, size_t new_size);
void  opssl_key_free(void *ptr, size_t size);

/* ─── Secure Erasure ─────────────────────────────────────────────────── */

/*
 * Guaranteed not to be optimized away. Uses explicit_bzero, memset_s,
 * or volatile write barrier depending on platform.
 */
void opssl_memzero(void *ptr, size_t len);

/* ─── Constant-Time Operations ───────────────────────────────────────── */

int    opssl_ct_eq(const void *a, const void *b, size_t len);
int    opssl_ct_is_zero(const void *buf, size_t len);
void   opssl_ct_select(void *dst, const void *a, const void *b, size_t len, int select_a);
size_t opssl_ct_min(size_t a, size_t b);

/* ─── Entropy / CSPRNG ───────────────────────────────────────────────── */

int  opssl_random_bytes(void *buf, size_t len);
int  opssl_random_uniform(uint32_t upper_bound, uint32_t *out);
int  opssl_random_init(void);
void opssl_random_cleanup(void);

/* ─── Endian / Byte Manipulation ─────────────────────────────────────── */

static inline uint16_t opssl_be16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] << 8 | (uint16_t)p[1]);
}

static inline uint32_t opssl_be32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8  | (uint32_t)p[3];
}

static inline uint64_t opssl_be64(const uint8_t *p)
{
    return (uint64_t)opssl_be32(p) << 32 | (uint64_t)opssl_be32(p + 4);
}

static inline void opssl_put_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v);
}

static inline void opssl_put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

static inline void opssl_put_be64(uint8_t *p, uint64_t v)
{
    opssl_put_be32(p, (uint32_t)(v >> 32));
    opssl_put_be32(p + 4, (uint32_t)(v));
}

/* ─── Hardware Feature Detection ─────────────────────────────────────────── */

/*
 * Runtime CPU feature detection for hardware acceleration dispatch.
 * These check CPUID on x86_64 and return false on other architectures.
 */
bool opssl_has_aesni(void);
bool opssl_has_pclmul(void);

#endif /* OPSSL_PLATFORM_H */
