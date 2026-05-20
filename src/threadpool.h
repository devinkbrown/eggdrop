/*
 * threadpool.h -- DCC parallel dispatch via the unified op_async worker pool.
 *
 * This module routes DCT_PARALLEL DCC activity handlers through op_async_submit()
 * so that DCC work, file I/O, and DNS all share one worker pool.  No second
 * thread pool is created.
 *
 * Contract for DCT_PARALLEL activity handlers
 * -------------------------------------------
 *  - The activity function runs on a worker thread.
 *  - It MUST NOT call lostdcc(), modify dcc[], or call any event-loop API.
 *  - To signal that a connection should be closed, set a flag in the slot's
 *    private data; the main loop will see it and call lostdcc() on the next tick.
 *
 * Lifecycle
 * ---------
 *  threadpool_init()     called after op_async_init(); registers DCC dispatch.
 *  threadpool_shutdown() marks DCC dispatch disabled; op_async_shutdown()
 *                        handles actual thread teardown.
 *  threadpool_drain()    pumps op_async_drain() until all in-flight DCC items
 *                        are complete and their done_fn callbacks have run.
 *
 * Copyright (C) 2026 Eggheads Development Team
 */

#ifndef _EGG_THREADPOOL_H
#define _EGG_THREADPOOL_H

#include <stddef.h>
#include <stdint.h>

/* Work item callback signature: void fn(int idx, char *buf, int len) */
typedef void (*pool_work_fn)(int idx, char *buf, int len);

/* Register DCC parallel dispatch against the running op_async pool.
 * Must be called after op_async_init().  nthreads is ignored (the pool
 * was already sized by op_async_init).  Returns 0 on success, -1 if the
 * async pool is not active.
 */
int threadpool_init(int nthreads);

/* Submit a DCT_PARALLEL DCC activity to the shared worker pool.
 * The buffer is copied internally.
 * Returns 0 on success, -1 if the pool is not active (caller runs inline).
 */
int threadpool_submit(pool_work_fn fn, int idx, const char *buf, int len);

/* Drain all in-flight DCC work by pumping op_async_drain() until the
 * in-flight count reaches zero.  Called before bot restart or shutdown.
 */
void threadpool_drain(void);

/* Disable DCC parallel dispatch.  Does not stop worker threads — that
 * happens in op_async_shutdown().
 */
void threadpool_shutdown(void);

/* Returns non-zero if DCC parallel dispatch is active. */
int threadpool_active(void);

/* Number of DCC items currently in the worker pool (approximate). */
int threadpool_pending(void);

/* Number of worker threads (same as op_async_nthreads). */
int threadpool_size(void);

/* Cumulative shim statistics since threadpool_init(). */
typedef struct {
  uint64_t submitted;   /* work items ever submitted via threadpool_submit */
  uint64_t completed;   /* work items ever completed (dcc_done callback run) */
  uint64_t dropped;     /* items silently dropped due to per-slot queue overflow */
  int      hwm;         /* all-time max queue depth seen across all slots */
} threadpool_stats_t;

void threadpool_get_stats(threadpool_stats_t *out);

/* Shim lifecycle — called from dccutil.c slot management */
void dcc_shim_slot_open(int idx);
void dcc_shim_slot_close(int idx);
void dcc_shim_slot_move(int from, int to);  /* removedcc moves last slot to idx */
void dcc_shim_grow(int new_max);            /* called after increase_socks_max */
int  dcc_shim_queue_depth(int idx);         /* for .threads stats */

#endif /* _EGG_THREADPOOL_H */
