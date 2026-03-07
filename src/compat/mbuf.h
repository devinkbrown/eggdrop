/*
 * mbuf.h -- message buffer (ring buffer) interface.
 *
 * Ported from ophion's op_mbuf to eggdrop.
 *
 * Provides a fixed-capacity ring buffer of bytes suitable for queuing
 * outgoing IRC data before it is written to a socket.
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef EGG_COMPAT_MBUF_H
#define EGG_COMPAT_MBUF_H

#include <stddef.h>

/*
 * egg_mbuf_t -- opaque message buffer handle.
 *
 * Internally this is a circular byte buffer of fixed capacity.  Writers
 * call egg_mbuf_append(); readers call egg_mbuf_peek() to get a pointer
 * to contiguous data and egg_mbuf_consume() to advance the read pointer
 * once they have processed bytes.
 */
typedef struct egg_mbuf egg_mbuf_t;

/*
 * egg_mbuf_alloc -- allocate a new message buffer with the given capacity.
 *
 * Returns NULL on allocation failure.
 */
egg_mbuf_t *egg_mbuf_alloc(size_t capacity);

/*
 * egg_mbuf_free -- release all memory associated with an mbuf.
 *
 * The pointer must not be used after this call.
 */
void egg_mbuf_free(egg_mbuf_t *mb);

/*
 * egg_mbuf_append -- copy len bytes from data into the ring buffer.
 *
 * Returns the number of bytes actually written (may be less than len if
 * the buffer does not have enough free space).
 */
size_t egg_mbuf_append(egg_mbuf_t *mb, const char *data, size_t len);

/*
 * egg_mbuf_peek -- expose a contiguous view of buffered data.
 *
 * Sets *data to point at the start of readable bytes and *len to the
 * number of contiguous bytes available at that pointer.  Because the
 * buffer is circular, a second call after consuming the first chunk may
 * return additional bytes that wrapped around.
 *
 * Returns the total number of buffered bytes (same as egg_mbuf_len).
 */
size_t egg_mbuf_peek(egg_mbuf_t *mb, char **data, size_t *len);

/*
 * egg_mbuf_consume -- mark len bytes as consumed (advance read pointer).
 *
 * len must not exceed egg_mbuf_len(mb).
 */
void egg_mbuf_consume(egg_mbuf_t *mb, size_t len);

/*
 * egg_mbuf_len -- return the number of bytes currently buffered.
 */
size_t egg_mbuf_len(const egg_mbuf_t *mb);

/*
 * egg_mbuf_capacity -- return the total capacity of the buffer.
 */
size_t egg_mbuf_capacity(const egg_mbuf_t *mb);

/*
 * egg_mbuf_grow -- ensure the buffer has at least new_cap bytes of capacity.
 *
 * Linearises buffered data into a newly allocated backing store.
 * Returns 0 on success, -1 on allocation failure.
 */
int egg_mbuf_grow(egg_mbuf_t *mb, size_t new_cap);

/*
 * egg_mbuf_append_grow -- append data, growing the buffer if needed.
 *
 * Uses doubling strategy to amortise reallocation cost.
 * Returns the number of bytes written (always len unless allocation fails).
 */
size_t egg_mbuf_append_grow(egg_mbuf_t *mb, const char *data, size_t len);

#endif /* EGG_COMPAT_MBUF_H */
