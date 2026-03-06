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
