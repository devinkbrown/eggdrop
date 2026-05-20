/*
 * async_recv.h -- parallel socket read-ahead via the op_async thread pool.
 *
 * Submits recv() calls for all epoll-ready sockets simultaneously so that
 * kernel round-trips overlap.  Done callbacks push raw bytes into each
 * socket's op_linebuf_t on the main thread; sockgets() then drains the
 * pre-filled buffers without any blocking recv().
 *
 * Copyright (C) 2026 Eggheads Development Team
 */

#ifndef _EGG_ASYNC_RECV_H
#define _EGG_ASYNC_RECV_H

#include <stdint.h>

/* Submit non-blocking recv() calls for every ready, eligible socket.
 * Returns the number of recv operations submitted. */
int async_recv_submit_all(void);

/* Fill *inflight_out, *total_out, *hwm_out with recv stats.
 * Any pointer may be NULL. */
void async_recv_stats(int *inflight_out, uint64_t *total_out, int *hwm_out);

#endif /* _EGG_ASYNC_RECV_H */
