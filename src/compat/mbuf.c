/*
 * mbuf.c -- message buffer (ring buffer) implementation.
 *
 * Ported from ophion's op_mbuf to eggdrop.
 *
 * A fixed-capacity circular byte buffer.  The ring buffer avoids any data
 * movement on append or consume: the write pointer advances on append and
 * the read pointer advances on consume.  Both pointers wrap modulo
 * capacity.
 *
 *   Append:   O(1) -- two memcpy at most (wrap-around split)
 *   Consume:  O(1) -- pointer arithmetic
 *   Peek:     O(1) -- pointer arithmetic
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define COMPILING_MEM

#include "main.h"
#include "../eggdrop.h"
#include "mbuf.h"

#include <string.h>
#include <stdlib.h>

/* -------------------------------------------------------------------------
 * Internal structure
 * ---------------------------------------------------------------------- */

struct egg_mbuf {
    char   *buf;      /* backing store, capacity bytes         */
    size_t  cap;      /* total capacity                        */
    size_t  len;      /* bytes currently buffered              */
    size_t  rpos;     /* read position (index into buf)        */
    size_t  wpos;     /* write position (index into buf)       */
};

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

egg_mbuf_t *egg_mbuf_alloc(size_t capacity)
{
    egg_mbuf_t *mb;

    if (capacity == 0)
        return NULL;

    mb = nmalloc(sizeof(*mb));
    if (mb == NULL)
        return NULL;

    mb->buf = nmalloc(capacity);
    if (mb->buf == NULL) {
        nfree(mb);
        return NULL;
    }

    mb->cap  = capacity;
    mb->len  = 0;
    mb->rpos = 0;
    mb->wpos = 0;

    return mb;
}

void egg_mbuf_free(egg_mbuf_t *mb)
{
    if (mb == NULL)
        return;
    nfree(mb->buf);
    nfree(mb);
}

size_t egg_mbuf_append(egg_mbuf_t *mb, const char *data, size_t len)
{
    size_t free_space;
    size_t to_write;
    size_t first_chunk;
    size_t second_chunk;

    if (mb == NULL || data == NULL || len == 0)
        return 0;

    free_space = mb->cap - mb->len;
    to_write   = (len < free_space) ? len : free_space;

    if (to_write == 0)
        return 0;

    /* How many bytes fit before we hit the end of the backing array? */
    first_chunk = mb->cap - mb->wpos;
    if (first_chunk > to_write)
        first_chunk = to_write;

    memcpy(mb->buf + mb->wpos, data, first_chunk);
    mb->wpos = (mb->wpos + first_chunk) % mb->cap;

    second_chunk = to_write - first_chunk;
    if (second_chunk > 0) {
        memcpy(mb->buf, data + first_chunk, second_chunk);
        mb->wpos = second_chunk;
    }

    mb->len += to_write;
    return to_write;
}

size_t egg_mbuf_peek(egg_mbuf_t *mb, char **data, size_t *len)
{
    size_t contiguous;

    if (mb == NULL || data == NULL || len == 0)
        return 0;

    if (mb->len == 0) {
        *data = NULL;
        *len  = 0;
        return 0;
    }

    /* Number of contiguous bytes available before the array wraps. */
    contiguous = mb->cap - mb->rpos;
    if (contiguous > mb->len)
        contiguous = mb->len;

    *data = mb->buf + mb->rpos;
    *len  = contiguous;

    return mb->len;
}

void egg_mbuf_consume(egg_mbuf_t *mb, size_t len)
{
    if (mb == NULL || len == 0)
        return;

    /* Caller must not consume more than is buffered. */
    if (len > mb->len)
        len = mb->len;

    mb->rpos = (mb->rpos + len) % mb->cap;
    mb->len -= len;

    /* Reset pointers when buffer is empty to keep future appends
     * contiguous as long as possible. */
    if (mb->len == 0) {
        mb->rpos = 0;
        mb->wpos = 0;
    }
}

size_t egg_mbuf_len(const egg_mbuf_t *mb)
{
    return (mb != NULL) ? mb->len : 0;
}

size_t egg_mbuf_capacity(const egg_mbuf_t *mb)
{
    return (mb != NULL) ? mb->cap : 0;
}

void egg_mbuf_peek2(egg_mbuf_t *mb,
                    char **data1, size_t *len1,
                    char **data2, size_t *len2)
{
    size_t c1;

    if (mb == NULL || mb->len == 0) {
        *data1 = NULL; *len1 = 0;
        *data2 = NULL; *len2 = 0;
        return;
    }

    /* First contiguous segment from rpos to end of backing store */
    c1 = mb->cap - mb->rpos;
    if (c1 > mb->len)
        c1 = mb->len;

    *data1 = mb->buf + mb->rpos;
    *len1  = c1;

    /* Second segment wraps around to the start of backing store */
    if (mb->len > c1) {
        *data2 = mb->buf;
        *len2  = mb->len - c1;
    } else {
        *data2 = NULL;
        *len2  = 0;
    }
}

int egg_mbuf_grow(egg_mbuf_t *mb, size_t new_cap)
{
    char *new_buf;
    size_t first, rest;

    if (mb == NULL)
        return -1;
    if (new_cap <= mb->cap)
        return 0;

    new_buf = nmalloc(new_cap);
    if (new_buf == NULL)
        return -1;

    /* Linearise ring-buffer data into new_buf[0..len-1]. */
    if (mb->len > 0) {
        first = mb->cap - mb->rpos;
        if (first > mb->len)
            first = mb->len;
        memcpy(new_buf, mb->buf + mb->rpos, first);
        rest = mb->len - first;
        if (rest > 0)
            memcpy(new_buf + first, mb->buf, rest);
    }

    nfree(mb->buf);
    mb->buf  = new_buf;
    mb->cap  = new_cap;
    mb->rpos = 0;
    mb->wpos = mb->len;
    return 0;
}

size_t egg_mbuf_append_grow(egg_mbuf_t *mb, const char *data, size_t len)
{
    size_t new_cap;

    if (mb == NULL || data == NULL || len == 0)
        return 0;

    if (mb->cap - mb->len < len) {
        new_cap = mb->cap ? mb->cap : 512;
        while (new_cap < mb->len + len)
            new_cap *= 2;
        if (egg_mbuf_grow(mb, new_cap) < 0)
            return 0;
    }

    return egg_mbuf_append(mb, data, len);
}
