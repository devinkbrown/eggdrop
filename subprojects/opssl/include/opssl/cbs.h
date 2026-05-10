/*
 * opssl/cbs.h — Crypto Byte String parser and builder.
 *
 * Inspired by BoringSSL's CBS/CBB. Provides safe, bounds-checked parsing
 * and building of TLS wire format messages without manual pointer arithmetic.
 *
 * CBS: read-only view into a byte buffer (parse direction)
 * CBB: growable byte buffer builder (build direction)
 *
 * All operations return 1 on success, 0 on failure.
 * On failure the CBS/CBB is left in an error state and all subsequent
 * operations also return 0 (fail-closed).
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef OPSSL_CBS_H
#define OPSSL_CBS_H

#include <stdint.h>
#include <stddef.h>

/* ─── CBS: Crypto Byte String (Parser) ───────────────────────────────── */

typedef struct {
    const uint8_t *data;
    size_t len;
} opssl_cbs_t;

/* Initialize a CBS from a buffer */
static inline void opssl_cbs_init(opssl_cbs_t *cbs, const uint8_t *data, size_t len)
{
    cbs->data = data;
    cbs->len = len;
}

/* Remaining bytes */
static inline size_t opssl_cbs_len(const opssl_cbs_t *cbs)
{
    return cbs->len;
}

static inline const uint8_t *opssl_cbs_data(const opssl_cbs_t *cbs)
{
    return cbs->data;
}

/* Read fixed-size integers (network byte order) */
int opssl_cbs_get_u8(opssl_cbs_t *cbs, uint8_t *out);
int opssl_cbs_get_u16(opssl_cbs_t *cbs, uint16_t *out);
int opssl_cbs_get_u24(opssl_cbs_t *cbs, uint32_t *out);
int opssl_cbs_get_u32(opssl_cbs_t *cbs, uint32_t *out);

/* Read raw bytes */
int opssl_cbs_get_bytes(opssl_cbs_t *cbs, opssl_cbs_t *out, size_t len);
int opssl_cbs_skip(opssl_cbs_t *cbs, size_t len);

/* Read length-prefixed fields (TLS encoding) */
int opssl_cbs_get_u8_length_prefixed(opssl_cbs_t *cbs, opssl_cbs_t *out);
int opssl_cbs_get_u16_length_prefixed(opssl_cbs_t *cbs, opssl_cbs_t *out);
int opssl_cbs_get_u24_length_prefixed(opssl_cbs_t *cbs, opssl_cbs_t *out);

/* Peek without consuming */
int opssl_cbs_peek_u8(const opssl_cbs_t *cbs, uint8_t *out);

/* Copy out raw bytes into caller buffer */
int opssl_cbs_copy_bytes(opssl_cbs_t *cbs, uint8_t *out, size_t len);

/* Check if empty */
static inline int opssl_cbs_is_empty(const opssl_cbs_t *cbs)
{
    return cbs->len == 0;
}

/* ─── CBB: Crypto Byte Builder ───────────────────────────────────────── */

typedef struct opssl_cbb opssl_cbb_t;

struct opssl_cbb {
    uint8_t *buf;
    size_t   len;
    size_t   cap;
    size_t   offset;      /* for length-prefix fixup */
    opssl_cbb_t *parent;  /* parent CBB for nested builders */
    opssl_cbb_t *child;   /* pending child builder (auto-flushed) */
    uint8_t  prefix_len;  /* 1, 2, or 3 byte length prefix */
    uint8_t  error;       /* sticky error flag */
    uint8_t  is_child;    /* true if this is a child builder */
};

/* Initialize with preallocated or dynamic buffer */
int  opssl_cbb_init(opssl_cbb_t *cbb, size_t initial_cap);
int  opssl_cbb_init_fixed(opssl_cbb_t *cbb, uint8_t *buf, size_t len);
void opssl_cbb_cleanup(opssl_cbb_t *cbb);

/* Finalize: get the built buffer. Caller owns the memory. */
int opssl_cbb_finish(opssl_cbb_t *cbb, uint8_t **out, size_t *out_len);

/* Write fixed-size integers (network byte order) */
int opssl_cbb_add_u8(opssl_cbb_t *cbb, uint8_t val);
int opssl_cbb_add_u16(opssl_cbb_t *cbb, uint16_t val);
int opssl_cbb_add_u24(opssl_cbb_t *cbb, uint32_t val);
int opssl_cbb_add_u32(opssl_cbb_t *cbb, uint32_t val);

/* Write raw bytes */
int opssl_cbb_add_bytes(opssl_cbb_t *cbb, const uint8_t *data, size_t len);

/* Length-prefixed child builders (auto-fixup on flush) */
int opssl_cbb_add_u8_length_prefixed(opssl_cbb_t *cbb, opssl_cbb_t *child);
int opssl_cbb_add_u16_length_prefixed(opssl_cbb_t *cbb, opssl_cbb_t *child);
int opssl_cbb_add_u24_length_prefixed(opssl_cbb_t *cbb, opssl_cbb_t *child);

/* Flush child back to parent (writes length prefix) */
int opssl_cbb_flush(opssl_cbb_t *cbb);

/* Reserve space for caller to write directly */
int opssl_cbb_reserve(opssl_cbb_t *cbb, uint8_t **out, size_t len);
int opssl_cbb_did_write(opssl_cbb_t *cbb, size_t len);

/* Current length of built data */
static inline size_t opssl_cbb_len(const opssl_cbb_t *cbb)
{
    return cbb->len;
}

/* Pointer to built data */
static inline const uint8_t *opssl_cbb_data(const opssl_cbb_t *cbb)
{
    return cbb->buf;
}

/* Short Aliases
 * Internal source files use the shorter CBS_* / CBB_* names (BoringSSL style).
 * These map directly to the opssl_cbs_* / opssl_cbb_* functions above.
 */

#define CBS_init       opssl_cbs_init
#define CBS_len        opssl_cbs_len
#define CBS_data       opssl_cbs_data
#define CBS_get_u8     opssl_cbs_get_u8
#define CBS_get_u16    opssl_cbs_get_u16
#define CBS_get_u24    opssl_cbs_get_u24
#define CBS_get_u32    opssl_cbs_get_u32
#define CBS_get_bytes  opssl_cbs_get_bytes
#define CBS_skip       opssl_cbs_skip
#define CBS_get_u8_length_prefixed   opssl_cbs_get_u8_length_prefixed
#define CBS_get_u16_length_prefixed  opssl_cbs_get_u16_length_prefixed
#define CBS_get_u24_length_prefixed  opssl_cbs_get_u24_length_prefixed
#define CBS_peek_u8    opssl_cbs_peek_u8
#define CBS_copy_bytes opssl_cbs_copy_bytes
#define CBS_is_empty   opssl_cbs_is_empty

#define CBB_init       opssl_cbb_init
#define CBB_init_fixed opssl_cbb_init_fixed
#define CBB_cleanup    opssl_cbb_cleanup
#define CBB_finish     opssl_cbb_finish
#define CBB_add_u8     opssl_cbb_add_u8
#define CBB_add_u16    opssl_cbb_add_u16
#define CBB_add_u24    opssl_cbb_add_u24
#define CBB_add_u32    opssl_cbb_add_u32
#define CBB_add_bytes  opssl_cbb_add_bytes
#define CBB_add_u8_length_prefixed   opssl_cbb_add_u8_length_prefixed
#define CBB_add_u16_length_prefixed  opssl_cbb_add_u16_length_prefixed
#define CBB_add_u24_length_prefixed  opssl_cbb_add_u24_length_prefixed
#define CBB_flush      opssl_cbb_flush
#define CBB_reserve    opssl_cbb_reserve
#define CBB_did_write  opssl_cbb_did_write
#define CBB_len        opssl_cbb_len
#define CBB_data       opssl_cbb_data

/* Type aliases for BoringSSL-compatible code */
typedef opssl_cbs_t CBS;
typedef opssl_cbb_t CBB;

#endif /* OPSSL_CBS_H */
