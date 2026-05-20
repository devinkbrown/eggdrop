/*
 * threadpool.c -- DCC parallel dispatch adapter over op_async.
 *
 * Design: one unified worker pool for all async work in eggdrop.
 *
 * Previously threadpool.c owned its own op_tpool, running in parallel with
 * the op_async pool used by async_fileio and async_dns — two independent
 * work-stealing pools burning threads for idle work.
 *
 * Now threadpool_submit() routes DCC activity through op_async_submit()
 * alongside file I/O and DNS work.  Benefits:
 *
 *   Single pool   — workers are shared; idle workers pick up any pending work
 *                   regardless of type.  Fewer threads, less contention.
 *
 *   Single drain  — op_async_drain() in the event loop delivers all
 *                   completions: DCC, fileio, DNS.  No second drain path.
 *
 *   Main-thread   — dcc_done() runs on the main thread via op_async_drain(),
 *   in_flight       so in_flight decrements are serialized with lostdcc().
 *   safety          No cross-thread dcc[] access from worker threads.
 *
 * Lifecycle:
 *   threadpool_init()     — called after op_async_init(); marks DCC dispatch
 *                           enabled.  nthreads param is advisory/ignored
 *                           (op_async_init already chose the count).
 *   threadpool_shutdown() — disables new submissions; actual thread teardown
 *                           happens in op_async_shutdown().
 *   threadpool_drain()    — pumps op_async_drain() until DCC inflight==0.
 *
 * Copyright (C) 2026 Eggheads Development Team
 */

#define _GNU_SOURCE
#define COMPILING_MEM
#include "main.h"
#include "threadpool.h"

#include <op_async.h>

#include <stdatomic.h>
#include <string.h>

extern struct dcc_t *dcc;
extern int dcc_total;

#define MAX_WORK_BUF  2048

/* ---- Work item ---------------------------------------------------------- */

typedef struct {
  pool_work_fn  fn;
  int           idx;
  int           len;
  char          buf[MAX_WORK_BUF];
} dcc_work_t;

/* ---- Pool state --------------------------------------------------------- */

static bool      pool_enabled;          /* true after threadpool_init() */
static _Atomic int pool_inflight;       /* DCC items in flight          */

/* ---- Worker / completion ------------------------------------------------ */

/* Runs on a worker thread — may block, must not touch event-loop state. */
static void dcc_worker(void *arg)
{
  dcc_work_t *w = (dcc_work_t *)arg;
  w->fn(w->idx, w->buf, w->len);
}

/* Runs on the main thread via op_async_drain() — safe to access dcc[]. */
static void dcc_done(void *arg)
{
  dcc_work_t *w = (dcc_work_t *)arg;
  if (w->idx >= 0 && w->idx < dcc_total)
    atomic_fetch_sub_explicit(&dcc[w->idx].in_flight, 1, memory_order_release);
  atomic_fetch_sub_explicit(&pool_inflight, 1, memory_order_release);
  op_free(w);
}

/* ---- Public API --------------------------------------------------------- */

int threadpool_init(int nthreads)
{
  (void)nthreads;   /* op_async_init() already chose worker count */
  if (!op_async_active())
    return -1;
  pool_enabled = true;
  atomic_store_explicit(&pool_inflight, 0, memory_order_relaxed);
  return 0;
}

int threadpool_submit(pool_work_fn fn, int idx, const char *buf, int len)
{
  if (!pool_enabled || !op_async_active())
    return -1;

  dcc_work_t *w = (dcc_work_t *)op_malloc(sizeof *w);
  if (!w)
    return -1;

  w->fn  = fn;
  w->idx = idx;

  if (len > 0 && buf) {
    int n = len < MAX_WORK_BUF ? len : MAX_WORK_BUF - 1;
    memcpy(w->buf, buf, (size_t)n);
    w->buf[n] = '\0';
    w->len = n;
  } else {
    w->buf[0] = '\0';
    w->len = 0;
  }

  /* Increment per-slot in_flight before submitting so lostdcc() sees it. */
  if (idx >= 0 && idx < dcc_total)
    atomic_fetch_add_explicit(&dcc[idx].in_flight, 1, memory_order_relaxed);
  atomic_fetch_add_explicit(&pool_inflight, 1, memory_order_relaxed);

  op_async_submit(dcc_worker, dcc_done, w);
  return 0;
}

void threadpool_drain(void)
{
  /* Pump completions until all DCC work is acknowledged on the main thread.
   * File I/O and DNS completions are delivered as a side effect — that is
   * correct: we want a clean state before restart/shutdown anyway. */
  while (atomic_load_explicit(&pool_inflight, memory_order_acquire) > 0)
    op_async_drain();
}

void threadpool_shutdown(void)
{
  /* Mark disabled so new submissions are rejected.  The actual thread pool
   * teardown happens in op_async_shutdown(). */
  pool_enabled = false;
  atomic_store_explicit(&pool_inflight, 0, memory_order_relaxed);
}

int threadpool_active(void)
{
  return pool_enabled && op_async_active();
}

int threadpool_pending(void)
{
  return (int)atomic_load_explicit(&pool_inflight, memory_order_relaxed);
}

int threadpool_size(void)
{
  return op_async_nthreads();
}
