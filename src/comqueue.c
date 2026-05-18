/*
 * comqueue.c -- MPMC completion queue implementation.
 *
 * Each completion item is a heap-allocated (comqueue_item_t) carrying
 * a function pointer and opaque argument.  Workers post via comqueue_post();
 * the main thread drains via comqueue_drain().
 *
 * Copyright (C) 2026 Eggheads Development Team
 */

#define _GNU_SOURCE
#define COMPILING_MEM
#include "main.h"
#include "comqueue.h"

#include "libop/include/op_mpmc.h"

/* ---- Item --------------------------------------------------------------- */

typedef struct {
  comqueue_fn fn;
  void       *arg;
} comqueue_item_t;

/* ---- State -------------------------------------------------------------- */

static op_mpmc_t cq;
static int       cq_active;

/* ---- Public API --------------------------------------------------------- */

void comqueue_init(size_t capacity)
{
  if (cq_active)
    return;
  if (op_mpmc_init(&cq, (uint64_t)capacity) != 0)
    fatal("comqueue_init: op_mpmc_init failed", 0);
  cq_active = 1;
}

void comqueue_destroy(void)
{
  if (!cq_active)
    return;
  op_mpmc_destroy(&cq);
  cq_active = 0;
}

int comqueue_post(comqueue_fn fn, void *arg)
{
  if (!cq_active)
    return -1;

  comqueue_item_t *item = (comqueue_item_t *)op_malloc(sizeof *item);
  if (!item)
    return -1;

  item->fn  = fn;
  item->arg = arg;

  if (!op_mpmc_push(&cq, item)) {
    op_free(item);
    return -1;
  }
  return 0;
}

void comqueue_drain(void)
{
  if (!cq_active)
    return;

  comqueue_item_t *item;
  while ((item = (comqueue_item_t *)op_mpmc_pop(&cq)) != NULL) {
    item->fn(item->arg);
    op_free(item);
  }
}

int comqueue_pending(void)
{
  if (!cq_active)
    return 0;
  return (int)op_mpmc_size(&cq);
}
