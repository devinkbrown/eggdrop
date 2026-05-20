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

/* Snapshot of async-recv performance counters. */
typedef struct {
    int      inflight;       /* currently in-flight recv() ops */
    int      hwm;            /* all-time peak concurrent inflight */
    uint64_t total_calls;    /* total completed recv() calls */
    uint64_t total_bytes;    /* total bytes delivered to linebufs */
    double   calls_per_sec;  /* 10 s windowed call rate */
    double   bytes_per_sec;  /* 10 s windowed byte rate */
} async_recv_stats_t;

/* Submit non-blocking recv() calls for every ready, eligible socket.
 * Returns the number of recv operations submitted. */
int async_recv_submit_all(void);

/* Fill *out with a snapshot of recv stats. */
void async_recv_stats(async_recv_stats_t *out);

#endif /* _EGG_ASYNC_RECV_H */
