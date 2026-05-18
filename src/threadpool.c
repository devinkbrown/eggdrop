/*
 * threadpool.c -- worker thread pool for parallel I/O dispatch
 *
 * Fixed-size pool with a bounded MPSC queue. Workers dequeue items
 * and execute the callback. The queue uses a mutex + condition variable
 * for simplicity and correctness (no lock-free tricks needed at this
 * throughput level — we're dispatching IRC events, not millions of ops).
 *
 * Copyright (C) 2026 Eggheads Development Team
 */

#define _GNU_SOURCE
#define COMPILING_MEM
#include "main.h"
#include "threadpool.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Maximum pending work items before submit() returns -1 (backpressure) */
#define QUEUE_CAP  4096

/* Maximum buffer size per work item */
#define MAX_WORK_BUF  2048

/* ---- Work item ---------------------------------------------------------- */

typedef struct {
  pool_work_fn fn;
  int          idx;
  int          len;
  char         buf[MAX_WORK_BUF];
} work_item_t;

/* ---- Bounded ring queue ------------------------------------------------- */

typedef struct {
  work_item_t   items[QUEUE_CAP];
  unsigned int  head;    /* next write position */
  unsigned int  tail;    /* next read position */
  unsigned int  count;
  pthread_mutex_t lock;
  pthread_cond_t  not_empty;
  pthread_cond_t  not_full;
  int             shutdown;
} work_queue_t;

/* ---- Pool state --------------------------------------------------------- */

#define MAX_THREADS 16

static work_queue_t  pool_queue;
static pthread_t     pool_threads[MAX_THREADS];
static int           pool_nthreads;
static int           pool_running;

/* ---- Queue operations --------------------------------------------------- */

static void queue_init(work_queue_t *q)
{
  q->head = 0;
  q->tail = 0;
  q->count = 0;
  q->shutdown = 0;
  pthread_mutex_init(&q->lock, nullptr);
  pthread_cond_init(&q->not_empty, nullptr);
  pthread_cond_init(&q->not_full, nullptr);
}

static void queue_destroy(work_queue_t *q)
{
  pthread_mutex_destroy(&q->lock);
  pthread_cond_destroy(&q->not_empty);
  pthread_cond_destroy(&q->not_full);
}

/* Non-blocking push. Returns 0 on success, -1 if full. */
static int queue_push(work_queue_t *q, const work_item_t *item)
{
  pthread_mutex_lock(&q->lock);
  if (q->count >= QUEUE_CAP) {
    pthread_mutex_unlock(&q->lock);
    return -1;
  }
  q->items[q->head & (QUEUE_CAP - 1)] = *item;
  q->head++;
  q->count++;
  pthread_cond_signal(&q->not_empty);
  pthread_mutex_unlock(&q->lock);
  return 0;
}

/* Blocking pop. Returns 0 on success, -1 on shutdown. */
static int queue_pop(work_queue_t *q, work_item_t *out)
{
  pthread_mutex_lock(&q->lock);
  while (q->count == 0 && !q->shutdown)
    pthread_cond_wait(&q->not_empty, &q->lock);

  if (q->shutdown && q->count == 0) {
    pthread_mutex_unlock(&q->lock);
    return -1;
  }

  *out = q->items[q->tail & (QUEUE_CAP - 1)];
  q->tail++;
  q->count--;
  pthread_cond_signal(&q->not_full);
  pthread_mutex_unlock(&q->lock);
  return 0;
}

/* ---- Worker thread ------------------------------------------------------ */

static void *worker_fn(void *arg)
{
  (void)arg;
  work_item_t item;

  while (queue_pop(&pool_queue, &item) == 0)
    item.fn(item.idx, item.buf, item.len);

  return nullptr;
}

/* ---- Public API --------------------------------------------------------- */

int threadpool_init(int nthreads)
{
  if (pool_running)
    return 0;

  if (nthreads <= 0) {
    long ncpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpus < 2) ncpus = 2;
    nthreads = (int)(ncpus - 1);
    if (nthreads > 8) nthreads = 8;
    if (nthreads < 1) nthreads = 1;
  }
  if (nthreads > MAX_THREADS)
    nthreads = MAX_THREADS;

  queue_init(&pool_queue);
  pool_nthreads = nthreads;

  for (int i = 0; i < nthreads; i++) {
    int rc = pthread_create(&pool_threads[i], nullptr, worker_fn, nullptr);
    if (rc != 0) {
      fprintf(stderr, "threadpool: pthread_create[%d]: %s\n", i, strerror(rc));
      pool_nthreads = i;
      break;
    }
  }

  if (pool_nthreads == 0) {
    queue_destroy(&pool_queue);
    return -1;
  }

  pool_running = 1;
  return 0;
}

int threadpool_submit(pool_work_fn fn, int idx, const char *buf, int len)
{
  if (!pool_running)
    return -1;

  work_item_t item;
  item.fn  = fn;
  item.idx = idx;
  item.len = len;

  if (len > 0 && buf != nullptr) {
    int copy_len = len < MAX_WORK_BUF ? len : MAX_WORK_BUF - 1;
    memcpy(item.buf, buf, (size_t)copy_len);
    item.buf[copy_len] = '\0';
    item.len = copy_len;
  } else {
    item.buf[0] = '\0';
    item.len = 0;
  }

  return queue_push(&pool_queue, &item);
}

void threadpool_drain(void)
{
  if (!pool_running)
    return;

  /* Spin until queue is empty (workers finish their current items) */
  pthread_mutex_lock(&pool_queue.lock);
  while (pool_queue.count > 0) {
    pthread_mutex_unlock(&pool_queue.lock);
    usleep(1000);
    pthread_mutex_lock(&pool_queue.lock);
  }
  pthread_mutex_unlock(&pool_queue.lock);
}

void threadpool_shutdown(void)
{
  if (!pool_running)
    return;

  /* Signal shutdown and wake all workers */
  pthread_mutex_lock(&pool_queue.lock);
  pool_queue.shutdown = 1;
  pthread_cond_broadcast(&pool_queue.not_empty);
  pthread_mutex_unlock(&pool_queue.lock);

  /* Join all threads */
  for (int i = 0; i < pool_nthreads; i++)
    pthread_join(pool_threads[i], nullptr);

  queue_destroy(&pool_queue);
  pool_nthreads = 0;
  pool_running = 0;
}

int threadpool_active(void)
{
  return pool_running;
}

int threadpool_pending(void)
{
  if (!pool_running)
    return 0;
  pthread_mutex_lock(&pool_queue.lock);
  int n = (int)pool_queue.count;
  pthread_mutex_unlock(&pool_queue.lock);
  return n;
}

int threadpool_size(void)
{
  return pool_nthreads;
}
