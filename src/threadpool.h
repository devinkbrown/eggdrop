/*
 * threadpool.h -- worker thread pool for parallel I/O dispatch
 *
 * Provides a fixed-size pool of worker threads that can execute DCC
 * activity handlers in parallel when the DCC type is marked safe for
 * concurrent dispatch (DCT_PARALLEL).
 *
 * Copyright (C) 2026 Eggheads Development Team
 */

#ifndef _EGG_THREADPOOL_H
#define _EGG_THREADPOOL_H

#include <stddef.h>

/* Work item callback signature: void fn(int idx, char *buf, int len) */
typedef void (*pool_work_fn)(int idx, char *buf, int len);

/* Initialize the thread pool with nthreads workers.
 * Call once from main() before entering the event loop.
 * nthreads=0 means auto-detect (ncpus - 1, min 1, max 8).
 * Returns 0 on success, -1 on failure.
 */
int threadpool_init(int nthreads);

/* Submit work to the pool. The buffer is copied internally.
 * Returns 0 on success, -1 if the queue is full (caller should
 * execute inline as fallback).
 */
int threadpool_submit(pool_work_fn fn, int idx, const char *buf, int len);

/* Drain all pending work and wait for workers to finish current tasks.
 * Called before bot shutdown or restart.
 */
void threadpool_drain(void);

/* Shut down the pool and join all threads.
 * After this call, threadpool_submit() returns -1.
 */
void threadpool_shutdown(void);

/* Query whether the pool is active and accepting work. */
int threadpool_active(void);

/* Number of pending items in the queue (approximate). */
int threadpool_pending(void);

/* Number of worker threads. */
int threadpool_size(void);

#endif /* _EGG_THREADPOOL_H */
