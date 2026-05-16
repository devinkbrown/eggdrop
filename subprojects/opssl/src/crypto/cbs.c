/*
 * opssl/crypto/cbs.c — Crypto Byte String parser and builder.
 *
 * Safe, bounds-checked TLS wire format parsing. Inspired by BoringSSL.
 * All failures are sticky — once a CBS/CBB errors, all subsequent ops fail.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/cbs.h>
#include <opssl/platform.h>
#include <string.h>

/* ─── CBS: Parser ──────────────────────────────────────────��─────────── */

int
opssl_cbs_get_u8(opssl_cbs_t *cbs, uint8_t *out)
{
    if (cbs->len < 1)
        return 0;
    *out = cbs->data[0];
    cbs->data++;
    cbs->len--;
    return 1;
}

int
opssl_cbs_get_u16(opssl_cbs_t *cbs, uint16_t *out)
{
    if (cbs->len < 2)
        return 0;
    *out = opssl_be16(cbs->data);
    cbs->data += 2;
    cbs->len -= 2;
    return 1;
}

int
opssl_cbs_get_u24(opssl_cbs_t *cbs, uint32_t *out)
{
    if (cbs->len < 3)
        return 0;
    *out = ((uint32_t)cbs->data[0] << 16) |
           ((uint32_t)cbs->data[1] << 8) |
           ((uint32_t)cbs->data[2]);
    cbs->data += 3;
    cbs->len -= 3;
    return 1;
}

int
opssl_cbs_get_u32(opssl_cbs_t *cbs, uint32_t *out)
{
    if (cbs->len < 4)
        return 0;
    *out = opssl_be32(cbs->data);
    cbs->data += 4;
    cbs->len -= 4;
    return 1;
}

int
opssl_cbs_get_bytes(opssl_cbs_t *cbs, opssl_cbs_t *out, size_t len)
{
    if (cbs->len < len)
        return 0;
    out->data = cbs->data;
    out->len = len;
    cbs->data += len;
    cbs->len -= len;
    return 1;
}

int
opssl_cbs_skip(opssl_cbs_t *cbs, size_t len)
{
    if (cbs->len < len)
        return 0;
    cbs->data += len;
    cbs->len -= len;
    return 1;
}

int
opssl_cbs_get_u8_length_prefixed(opssl_cbs_t *cbs, opssl_cbs_t *out)
{
    uint8_t len;
    if (!opssl_cbs_get_u8(cbs, &len))
        return 0;
    return opssl_cbs_get_bytes(cbs, out, len);
}

int
opssl_cbs_get_u16_length_prefixed(opssl_cbs_t *cbs, opssl_cbs_t *out)
{
    uint16_t len;
    if (!opssl_cbs_get_u16(cbs, &len))
        return 0;
    return opssl_cbs_get_bytes(cbs, out, len);
}

int
opssl_cbs_get_u24_length_prefixed(opssl_cbs_t *cbs, opssl_cbs_t *out)
{
    uint32_t len;
    if (!opssl_cbs_get_u24(cbs, &len))
        return 0;
    return opssl_cbs_get_bytes(cbs, out, len);
}

int
opssl_cbs_peek_u8(const opssl_cbs_t *cbs, uint8_t *out)
{
    if (cbs->len < 1)
        return 0;
    if (out)
        *out = cbs->data[0];
    return 1;
}

int
opssl_cbs_copy_bytes(opssl_cbs_t *cbs, uint8_t *out, size_t len)
{
    if (cbs->len < len)
        return 0;
    memcpy(out, cbs->data, len);
    cbs->data += len;
    cbs->len -= len;
    return 1;
}

/* ─── CBB: Builder ────────────────────────────────────────────���──────── */

int
opssl_cbb_init(opssl_cbb_t *cbb, size_t initial_cap)
{
    memset(cbb, 0, sizeof(*cbb));
    if (initial_cap == 0)
        initial_cap = 256;
    cbb->buf = op_malloc(initial_cap);
    cbb->cap = initial_cap;
    return 1;
}

int
opssl_cbb_init_fixed(opssl_cbb_t *cbb, uint8_t *buf, size_t len)
{
    memset(cbb, 0, sizeof(*cbb));
    cbb->buf = buf;
    cbb->cap = len;
    return 1;
}

void
opssl_cbb_cleanup(opssl_cbb_t *cbb)
{
    if (!cbb->is_child && cbb->buf)
        free(cbb->buf);
    memset(cbb, 0, sizeof(*cbb));
}

static int
cbb_grow(opssl_cbb_t *cbb, size_t need)
{
    if (cbb->error)
        return 0;

    if (cbb->child) {
        if (!opssl_cbb_flush(cbb->child))
            return 0;
        cbb->child = NULL;
    }

    size_t required = cbb->len + need;
    if (required < cbb->len) {
        cbb->error = 1;
        return 0;
    }
    if (required <= cbb->cap)
        return 1;

    /* Children delegate growth to the root CBB, then update their pointers */
    if (cbb->is_child) {
        opssl_cbb_t *root = cbb->parent;
        while (root && root->is_child)
            root = root->parent;
        if (!root) {
            cbb->error = 1;
            return 0;
        }

        size_t new_cap = root->cap ? root->cap : 64;
        while (new_cap < required) {
            size_t doubled = new_cap * 2;
            if (doubled <= new_cap) {
                cbb->error = 1;
                return 0;
            }
            new_cap = doubled;
        }

        uint8_t *new_buf = op_realloc(root->buf, new_cap);
        root->buf = new_buf;
        root->cap = new_cap;

        /* Update buf/cap for all children in the parent chain */
        opssl_cbb_t *p = cbb;
        while (p && p->is_child) {
            p->buf = new_buf;
            p->cap = new_cap;
            p = p->parent;
        }
        return 1;
    }

    size_t new_cap = cbb->cap ? cbb->cap : 64;
    while (new_cap < required) {
        size_t doubled = new_cap * 2;
        if (doubled <= new_cap) {
            cbb->error = 1;
            return 0;
        }
        new_cap = doubled;
    }

    uint8_t *new_buf = op_realloc(cbb->buf, new_cap);
    cbb->buf = new_buf;
    cbb->cap = new_cap;
    return 1;
}

int
opssl_cbb_finish(opssl_cbb_t *cbb, uint8_t **out, size_t *out_len)
{
    if (cbb->error || cbb->is_child)
        return 0;

    if (cbb->child) {
        if (!opssl_cbb_flush(cbb->child))
            return 0;
        cbb->child = NULL;
    }

    *out = cbb->buf;
    *out_len = cbb->len;
    cbb->buf = NULL;
    cbb->len = 0;
    cbb->cap = 0;
    return 1;
}

int
opssl_cbb_add_u8(opssl_cbb_t *cbb, uint8_t val)
{
    if (!cbb_grow(cbb, 1))
        return 0;
    cbb->buf[cbb->len++] = val;
    return 1;
}

int
opssl_cbb_add_u16(opssl_cbb_t *cbb, uint16_t val)
{
    if (!cbb_grow(cbb, 2))
        return 0;
    opssl_put_be16(cbb->buf + cbb->len, val);
    cbb->len += 2;
    return 1;
}

int
opssl_cbb_add_u24(opssl_cbb_t *cbb, uint32_t val)
{
    if (!cbb_grow(cbb, 3))
        return 0;
    cbb->buf[cbb->len]     = (uint8_t)(val >> 16);
    cbb->buf[cbb->len + 1] = (uint8_t)(val >> 8);
    cbb->buf[cbb->len + 2] = (uint8_t)(val);
    cbb->len += 3;
    return 1;
}

int
opssl_cbb_add_u32(opssl_cbb_t *cbb, uint32_t val)
{
    if (!cbb_grow(cbb, 4))
        return 0;
    opssl_put_be32(cbb->buf + cbb->len, val);
    cbb->len += 4;
    return 1;
}

int
opssl_cbb_add_bytes(opssl_cbb_t *cbb, const uint8_t *data, size_t len)
{
    if (!cbb_grow(cbb, len))
        return 0;
    memcpy(cbb->buf + cbb->len, data, len);
    cbb->len += len;
    return 1;
}

int
opssl_cbb_add_u8_length_prefixed(opssl_cbb_t *cbb, opssl_cbb_t *child)
{
    if (!cbb_grow(cbb, 1))
        return 0;

    memset(child, 0, sizeof(*child));
    child->parent = cbb;
    child->buf = cbb->buf;
    child->cap = cbb->cap;
    child->offset = cbb->len;
    child->prefix_len = 1;
    child->is_child = 1;

    cbb->buf[cbb->len] = 0;
    cbb->len++;
    child->buf = cbb->buf;
    child->len = cbb->len;
    child->cap = cbb->cap;
    cbb->child = child;
    return 1;
}

int
opssl_cbb_add_u16_length_prefixed(opssl_cbb_t *cbb, opssl_cbb_t *child)
{
    if (!cbb_grow(cbb, 2))
        return 0;

    memset(child, 0, sizeof(*child));
    child->parent = cbb;
    child->buf = cbb->buf;
    child->cap = cbb->cap;
    child->offset = cbb->len;
    child->prefix_len = 2;
    child->is_child = 1;

    cbb->buf[cbb->len] = 0;
    cbb->buf[cbb->len + 1] = 0;
    cbb->len += 2;
    child->buf = cbb->buf;
    child->len = cbb->len;
    child->cap = cbb->cap;
    cbb->child = child;
    return 1;
}

int
opssl_cbb_add_u24_length_prefixed(opssl_cbb_t *cbb, opssl_cbb_t *child)
{
    if (!cbb_grow(cbb, 3))
        return 0;

    memset(child, 0, sizeof(*child));
    child->parent = cbb;
    child->buf = cbb->buf;
    child->cap = cbb->cap;
    child->offset = cbb->len;
    child->prefix_len = 3;
    child->is_child = 1;

    cbb->buf[cbb->len] = 0;
    cbb->buf[cbb->len + 1] = 0;
    cbb->buf[cbb->len + 2] = 0;
    cbb->len += 3;
    child->buf = cbb->buf;
    child->len = cbb->len;
    child->cap = cbb->cap;
    cbb->child = child;
    return 1;
}

int
opssl_cbb_flush(opssl_cbb_t *cbb)
{
    if (cbb->child) {
        if (!opssl_cbb_flush(cbb->child))
            return 0;
        cbb->child = NULL;
    }

    if (!cbb->is_child || !cbb->parent)
        return 1;

    opssl_cbb_t *parent = cbb->parent;
    if (cbb->len < cbb->offset + cbb->prefix_len) {
        cbb->error = 1;
        return 0;
    }
    size_t child_len = cbb->len - (cbb->offset + cbb->prefix_len);

    if (cbb->prefix_len == 1) {
        if (child_len > 0xFF) {
            cbb->error = 1;
            return 0;
        }
        cbb->buf[cbb->offset] = (uint8_t)child_len;
    } else if (cbb->prefix_len == 2) {
        if (child_len > 0xFFFF) {
            cbb->error = 1;
            return 0;
        }
        opssl_put_be16(cbb->buf + cbb->offset, (uint16_t)child_len);
    } else if (cbb->prefix_len == 3) {
        if (child_len > 0xFFFFFF) {
            cbb->error = 1;
            return 0;
        }
        cbb->buf[cbb->offset]     = (uint8_t)(child_len >> 16);
        cbb->buf[cbb->offset + 1] = (uint8_t)(child_len >> 8);
        cbb->buf[cbb->offset + 2] = (uint8_t)(child_len);
    }

    parent->len = cbb->len;
    parent->child = NULL;
    cbb->is_child = 0;
    cbb->parent = NULL;
    return 1;
}

int
opssl_cbb_reserve(opssl_cbb_t *cbb, uint8_t **out, size_t len)
{
    if (!cbb_grow(cbb, len))
        return 0;
    *out = cbb->buf + cbb->len;
    return 1;
}

int
opssl_cbb_did_write(opssl_cbb_t *cbb, size_t len)
{
    if (cbb->len + len > cbb->cap) {
        cbb->error = 1;
        return 0;
    }
    cbb->len += len;
    return 1;
}
