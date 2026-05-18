/*
 * comqueue.h -- MPMC completion queue for worker→main thread callbacks.
 *
 * Workers running in the thread pool post completion items here.
 * The main thread drains the queue once per event-loop tick, executing
 * each callback serially on the main thread — safe for all Tcl and
 * global-state access.
 *
 * Backed by op_mpmc_t (Vyukov bounded MPMC queue, lock-free CAS).
 *
 * Copyright (C) 2026 Eggheads Development Team
 */

#ifndef _EGG_COMQUEUE_H
#define _EGG_COMQUEUE_H

#include <stddef.h>

/* Callback executed on the main thread after worker completion. */
typedef void (*comqueue_fn)(void *arg);

/* Initialise the global completion queue. capacity must be a power of two. */
void comqueue_init(size_t capacity);

/* Destroy the queue (call after all workers are done). */
void comqueue_destroy(void);

/* Post a completion callback from any thread.
 * fn(arg) will be called on the main thread during the next drain.
 * Returns 0 on success, -1 if the queue is full (caller must handle inline). */
int comqueue_post(comqueue_fn fn, void *arg);

/* Drain all pending completions on the main thread.
 * Call once per event-loop tick, before dcc_remove_lost(). */
void comqueue_drain(void);

/* Number of pending completions (approximate). */
int comqueue_pending(void);

#endif /* _EGG_COMQUEUE_H */
