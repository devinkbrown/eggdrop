/*
 * threadpool.c -- worker thread pool using libop's work-stealing op_tpool.
 *
 * Replaces the hand-rolled mutex+condvar queue with op_thread_pool_t:
 *   - Lock-free MPSC inbox per worker (Treiber stack, single CAS)
 *   - Chase-Lev work-stealing deque — idle workers steal from peers
 *   - eventfd/pipe wakeup — no busy-wait, no condvar overhead
 *   - Per-worker stats available via op_tpool_get_stats()
 *
 * Thread safety for dcc slot removal:
 *   pool_inflight tracks items in flight.  lostdcc() waits until
 *   in_flight reaches 0 before zeroing the slot, preventing use-after-free.
 *
 * Copyright (C) 2026 Eggheads Development Team
 */

#define _GNU_SOURCE
#define COMPILING_MEM
#include "main.h"
#include "threadpool.h"

#include "libop/include/op_thread_pool.h"

#include <stdatomic.h>
#include <string.h>
#include <sched.h>

extern struct dcc_t *dcc;
extern int dcc_total;

/* Maximum buffer size per work item */
#define MAX_WORK_BUF  2048

/* ---- Work item ---------------------------------------------------------- */

typedef struct {
  pool_work_fn  fn;
  int           idx;
  int           len;
  char          buf[MAX_WORK_BUF];
} work_item_t;

/* ---- Pool state --------------------------------------------------------- */

static op_thread_pool_t *pool;
static _Atomic int       pool_inflight;

/* ---- Worker dispatch ---------------------------------------------------- */

static void worker_dispatch(void *arg)
{
  work_item_t *w = (work_item_t *)arg;
  w->fn(w->idx, w->buf, w->len);
  /* Release per-slot in_flight ref so lostdcc() can safely zero the slot */
  if (w->idx >= 0 && w->idx < dcc_total)
    atomic_fetch_sub_explicit(&dcc[w->idx].in_flight, 1, memory_order_release);
  atomic_fetch_sub_explicit(&pool_inflight, 1, memory_order_release);
  op_free(w);
}

/* ---- Public API --------------------------------------------------------- */

int threadpool_init(int nthreads)
{
  if (pool)
    return 0;

  /* op_tpool_create aborts on failure — always succeeds or terminates */
  pool = op_tpool_create(nthreads);
  atomic_store_explicit(&pool_inflight, 0, memory_order_relaxed);
  return 0;
}

int threadpool_submit(pool_work_fn fn, int idx, const char *buf, int len)
{
  if (!pool)
    return -1;

  work_item_t *w = (work_item_t *)op_malloc(sizeof *w);
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

  /* Increment per-slot in_flight before submit so lostdcc() can wait */
  if (idx >= 0 && idx < dcc_total)
    atomic_fetch_add_explicit(&dcc[idx].in_flight, 1, memory_order_relaxed);
  atomic_fetch_add_explicit(&pool_inflight, 1, memory_order_relaxed);
  op_tpool_submit(pool, worker_dispatch, w);
  return 0;
}

void threadpool_drain(void)
{
  if (!pool)
    return;
  /* Spin until all submitted items complete — only called at shutdown/restart */
  while (atomic_load_explicit(&pool_inflight, memory_order_acquire) > 0)
    sched_yield();
}

void threadpool_shutdown(void)
{
  if (!pool)
    return;
  /* op_tpool_shutdown drains pending items and joins all workers */
  op_tpool_shutdown(pool);
  pool = nullptr;
  atomic_store_explicit(&pool_inflight, 0, memory_order_relaxed);
}

int threadpool_active(void)
{
  return pool != nullptr;
}

int threadpool_pending(void)
{
  if (!pool)
    return 0;
  return (int)atomic_load_explicit(&pool_inflight, memory_order_relaxed);
}

int threadpool_size(void)
{
  return pool ? op_tpool_nthreads(pool) : 0;
}
