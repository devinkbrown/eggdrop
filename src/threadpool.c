/*
 * threadpool.c -- DCC parallel dispatch shim over op_async.
 *
 * The shim provides per-slot serialized dispatch: at most one worker runs
 * per DCC slot at a time.  When a new activity event arrives for a slot
 * that is already in-flight, the work is queued locally (up to
 * SHIM_QUEUE_MAX items; oldest dropped if exceeded).  When the worker
 * completes, dcc_done() automatically submits the next queued item.
 *
 * Generation counter: dcc_t.generation is incremented each time a slot
 * is opened (new_dcc).  Work items snapshot the generation at submit
 * time.  In dcc_done(), a mismatch means the slot was reused -- queued
 * items for the old connection are drained.
 *
 * Flexible buffer: work items allocate exactly sizeof(dcc_work_t)+len
 * bytes so there is no arbitrary size cap on the activity payload.
 *
 * All slot_queues operations happen on the main thread only.
 * op_async_submit/dcc_worker run on worker threads.
 * dcc_done runs on the main thread via op_async_drain().
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
extern int max_dcc;

#define SHIM_QUEUE_MAX  32   /* max queued items per slot before drop-oldest */

/* ---- Work item ---------------------------------------------------------- */

typedef struct dcc_work_t {
  pool_work_fn        fn;
  int                 idx;
  uint32_t            gen;
  int                 len;
  struct dcc_work_t  *next;
  char                buf[];   /* flexible: exactly len bytes allocated */
} dcc_work_t;

/* ---- Per-slot queue ----------------------------------------------------- */

typedef struct {
  dcc_work_t *head;
  dcc_work_t *tail;
  int         depth;
} slot_queue_t;

static slot_queue_t *slot_queues;    /* parallel array to dcc[], main-thread only */
static int           slot_queue_max; /* current allocation size */

/* ---- Pool state --------------------------------------------------------- */

static bool        pool_enabled;
static _Atomic int pool_inflight;

/* ---- Forward declarations ----------------------------------------------- */

static void dcc_worker(void *arg);
static void dcc_done(void *arg);

/* ---- Internal helpers --------------------------------------------------- */

static dcc_work_t *alloc_work(pool_work_fn fn, int idx, uint32_t gen,
                               const char *buf, int len)
{
  dcc_work_t *w = (dcc_work_t *)op_malloc(sizeof(dcc_work_t) + (size_t)len + 1);
  w->fn   = fn;
  w->idx  = idx;
  w->gen  = gen;
  w->len  = len;
  w->next = nullptr;
  if (len > 0 && buf)
    memcpy(w->buf, buf, (size_t)len);
  w->buf[len] = '\0';
  return w;
}

static void enqueue_work(int idx, dcc_work_t *w)
{
  slot_queue_t *q = &slot_queues[idx];

  if (q->depth >= SHIM_QUEUE_MAX) {
    /* Drop oldest item to make room */
    dcc_work_t *old = q->head;
    q->head = old->next;
    if (!q->head)
      q->tail = nullptr;
    q->depth--;
    op_free(old);
  }

  if (q->tail)
    q->tail->next = w;
  else
    q->head = w;
  q->tail = w;
  q->depth++;
}

static dcc_work_t *dequeue_work(int idx)
{
  slot_queue_t *q = &slot_queues[idx];
  dcc_work_t *w = q->head;

  if (!w)
    return nullptr;
  q->head = w->next;
  if (!q->head)
    q->tail = nullptr;
  q->depth--;
  w->next = nullptr;
  return w;
}

static void drain_slot_queue(int idx)
{
  if (!slot_queues || idx < 0 || idx >= slot_queue_max)
    return;
  slot_queue_t *q = &slot_queues[idx];
  dcc_work_t *w = q->head;
  while (w) {
    dcc_work_t *next = w->next;
    op_free(w);
    w = next;
  }
  q->head  = nullptr;
  q->tail  = nullptr;
  q->depth = 0;
}

static void submit_work(dcc_work_t *w)
{
  if (w->idx >= 0 && w->idx < dcc_total)
    atomic_fetch_add_explicit(&dcc[w->idx].in_flight, 1, memory_order_relaxed);
  atomic_fetch_add_explicit(&pool_inflight, 1, memory_order_relaxed);
  op_async_submit(dcc_worker, dcc_done, w);
}

/* ---- Worker / completion ------------------------------------------------ */

/* Runs on a worker thread -- may block, must not touch event-loop state. */
static void dcc_worker(void *arg)
{
  dcc_work_t *w = (dcc_work_t *)arg;
  w->fn(w->idx, w->buf, w->len);
}

/* Runs on the main thread via op_async_drain() -- safe to access dcc[]. */
static void dcc_done(void *arg)
{
  dcc_work_t *w = (dcc_work_t *)arg;
  int      idx  = w->idx;
  op_free(w);

  /* Decrement counters */
  if (idx >= 0 && idx < dcc_total)
    atomic_fetch_sub_explicit(&dcc[idx].in_flight, 1, memory_order_release);
  atomic_fetch_sub_explicit(&pool_inflight, 1, memory_order_release);

  /* Check slot still valid before dequeuing */
  if (idx < 0 || idx >= dcc_total || !slot_queues)
    return;

  /* Dequeue next item */
  dcc_work_t *next = dequeue_work(idx);
  if (!next)
    return;

  /* Generation check: discard stale queue if slot was reused */
  uint32_t cur_gen = atomic_load_explicit(&dcc[idx].generation, memory_order_acquire);
  if (next->gen != cur_gen) {
    op_free(next);
    drain_slot_queue(idx);
    return;
  }

  /* Submit next in-order item */
  submit_work(next);
}

/* ---- Public API --------------------------------------------------------- */

int threadpool_init(int nthreads)
{
  (void)nthreads;   /* op_async_init() already chose worker count */
  if (!op_async_active())
    return -1;
  pool_enabled = true;
  atomic_store_explicit(&pool_inflight, 0, memory_order_relaxed);
  dcc_shim_grow(max_dcc > 0 ? max_dcc : 1);
  return 0;
}

int threadpool_submit(pool_work_fn fn, int idx, const char *buf, int len)
{
  if (!pool_enabled || !op_async_active())
    return -1;

  /* Grow slot_queues if needed */
  if (idx >= slot_queue_max)
    dcc_shim_grow(max_dcc);

  uint32_t gen = (idx >= 0 && idx < dcc_total)
    ? atomic_load_explicit(&dcc[idx].generation, memory_order_acquire)
    : 0;

  dcc_work_t *w = alloc_work(fn, idx, gen, buf, len);

  if (idx >= 0 && idx < dcc_total &&
      atomic_load_explicit(&dcc[idx].in_flight, memory_order_acquire) == 0) {
    submit_work(w);
  } else {
    enqueue_work(idx, w);
  }
  return 0;
}

void threadpool_drain(void)
{
  /* Pump completions until all DCC work is acknowledged on the main thread.
   * File I/O and DNS completions are delivered as a side effect -- that is
   * correct: we want a clean state before restart/shutdown anyway. */
  while (atomic_load_explicit(&pool_inflight, memory_order_acquire) > 0)
    op_async_drain();
}

void threadpool_shutdown(void)
{
  /* Drain all per-slot queues before marking disabled */
  if (slot_queues) {
    for (int i = 0; i < slot_queue_max; i++)
      drain_slot_queue(i);
    op_free(slot_queues);
    slot_queues    = nullptr;
    slot_queue_max = 0;
  }
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

/* ---- Shim lifecycle ----------------------------------------------------- */

void dcc_shim_slot_open(int idx)
{
  if (slot_queues && idx >= 0 && idx < slot_queue_max)
    slot_queues[idx] = (slot_queue_t){};
  /* generation is set to 1 by new_dcc() via atomic_store after op_memzero */
}

void dcc_shim_slot_close(int idx)
{
  if (slot_queues && idx >= 0 && idx < slot_queue_max)
    drain_slot_queue(idx);
  if (idx >= 0 && idx < dcc_total)
    atomic_fetch_add_explicit(&dcc[idx].generation, 1, memory_order_release);
}

void dcc_shim_slot_move(int from, int to)
{
  if (!slot_queues || from < 0 || from >= slot_queue_max ||
      to < 0 || to >= slot_queue_max)
    return;
  drain_slot_queue(to);
  slot_queues[to]   = slot_queues[from];
  slot_queues[from] = (slot_queue_t){};
}

void dcc_shim_grow(int new_max)
{
  if (new_max <= slot_queue_max)
    return;
  slot_queue_t *nq = (slot_queue_t *)op_realloc(slot_queues,
                                                  sizeof(slot_queue_t) * (size_t)new_max);
  memset(nq + slot_queue_max, 0,
         sizeof(slot_queue_t) * (size_t)(new_max - slot_queue_max));
  slot_queues    = nq;
  slot_queue_max = new_max;
}

int dcc_shim_queue_depth(int idx)
{
  if (!slot_queues || idx < 0 || idx >= slot_queue_max)
    return 0;
  return slot_queues[idx].depth;
}
