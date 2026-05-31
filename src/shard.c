/*
 * shard.c -- Eggdrop libop I/O shard worker runtime
 *
 * This wires Eggdrop into libop's per-event-context backend machinery.
 * Shard 0 remains the main Eggdrop state owner; worker shards are available
 * for shard-owned I/O as subsystems are migrated.
 */

#include <config.h>
#include "main.h"
#include "shard.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <op_lib.h>

typedef enum {
  EGG_SHARD_INIT = 0,
  EGG_SHARD_RUNNING,
  EGG_SHARD_STOPPING,
  EGG_SHARD_STOPPED,
} egg_shard_state_t;

typedef struct egg_io_shard {
  int shard_id;
  pthread_t thread_id;
  bool thread_started;
  _Atomic int state;
  op_event_ctx_t *ctx;
  pthread_mutex_t shutdown_mu;
  pthread_cond_t  shutdown_cv;
} egg_io_shard_t;

static egg_io_shard_t egg_shards[EGG_IO_SHARDS_MAX];
static int egg_shard_count = 1;
static _Atomic int egg_shard_running = 0;

static void *egg_shard_thread(void *arg)
{
  egg_io_shard_t *s = arg;

#if defined(__linux__) && defined(_GNU_SOURCE)
  char name[16];
  snprintf(name, sizeof name, "egg-io-%d", s->shard_id);
  pthread_setname_np(pthread_self(), name);
#endif

  op_event_ctx_set_current(s->ctx);
  int expected = EGG_SHARD_INIT;
  if (!atomic_compare_exchange_strong_explicit(&s->state, &expected,
                                               EGG_SHARD_RUNNING,
                                               memory_order_acq_rel,
                                               memory_order_acquire)) {
    op_event_ctx_set_current(NULL);
    atomic_store_explicit(&s->state, EGG_SHARD_STOPPED, memory_order_release);
    return NULL;
  }
  atomic_fetch_add_explicit(&egg_shard_running, 1, memory_order_release);

  /* Wait for shutdown signal.  The per-shard io_uring CQ poll thread
   * (started by op_uring_ctx_init) handles kernel-side waiting; the main
   * thread dispatches all shard rings via op_select_uring.  This thread
   * holds the libop TLS context (t_ev_ctx = s->ctx) and sleeps until
   * egg_shards_shutdown() signals the condvar. */
  pthread_mutex_lock(&s->shutdown_mu);
  while (atomic_load_explicit(&s->state, memory_order_acquire) ==
         EGG_SHARD_RUNNING)
    pthread_cond_wait(&s->shutdown_cv, &s->shutdown_mu);
  pthread_mutex_unlock(&s->shutdown_mu);

  op_event_ctx_set_current(NULL);
  atomic_fetch_sub_explicit(&egg_shard_running, 1, memory_order_release);
  atomic_store_explicit(&s->state, EGG_SHARD_STOPPED, memory_order_release);
  return NULL;
}

int egg_shards_resolve_count(int configured)
{
  if (configured > 0) {
    if (configured > EGG_IO_SHARDS_MAX)
      return EGG_IO_SHARDS_MAX;
    return configured;
  }

  long nproc = 1;
#ifdef _SC_NPROCESSORS_ONLN
  nproc = sysconf(_SC_NPROCESSORS_ONLN);
  if (nproc < 1)
    nproc = 1;
#endif
  if (nproc > 8)
    nproc = 8;
  if (nproc > EGG_IO_SHARDS_MAX)
    nproc = EGG_IO_SHARDS_MAX;
  return (int)nproc;
}

static void egg_shards_destroy_contexts(void)
{
  for (int i = 1; i < egg_shard_count; i++) {
    if (egg_shards[i].ctx) {
      op_event_ctx_destroy(egg_shards[i].ctx);
      egg_shards[i].ctx = NULL;
    }
    atomic_store_explicit(&egg_shards[i].state, EGG_SHARD_STOPPED,
                          memory_order_release);
  }
}

int egg_shards_start(int count)
{
  if (count < 1)
    count = 1;
  if (count > EGG_IO_SHARDS_MAX)
    count = EGG_IO_SHARDS_MAX;

  egg_shard_count = count;
  atomic_store_explicit(&egg_shard_running, 0, memory_order_release);

  if (count == 1)
    return 0;

  for (int i = 1; i < count; i++) {
    egg_io_shard_t *s = &egg_shards[i];
    memset(s, 0, sizeof *s);
    s->shard_id = i;
    atomic_store_explicit(&s->state, EGG_SHARD_INIT, memory_order_relaxed);
    pthread_mutex_init(&s->shutdown_mu, NULL);
    pthread_cond_init(&s->shutdown_cv, NULL);

    char name[32];
    snprintf(name, sizeof name, "eggdrop-io-%d", i);
    s->ctx = op_event_ctx_create(name);
    if (!s->ctx) {
      putlog(LOG_MISC, "*",
             "I/O shard %d: failed to create event context; capping at %d shard%s",
             i, i, i == 1 ? "" : "s");
      count = i;
      egg_shard_count = count;
      break;
    }
  }

  for (int i = 1; i < count; i++) {
    egg_io_shard_t *s = &egg_shards[i];
    int rc = pthread_create(&s->thread_id, NULL, egg_shard_thread, s);
    if (rc != 0) {
      putlog(LOG_MISC, "*", "I/O shard %d: pthread_create failed: %s",
             i, strerror(rc));
      egg_shards_shutdown();
      return -1;
    }
    s->thread_started = true;
  }

  putlog(LOG_MISC, "*",
         "I/O shards: %d total (%d worker shard%s; Eggdrop state on shard 0)",
         count, count - 1, count == 2 ? "" : "s");
  return 0;
}

void egg_shards_shutdown(void)
{
  for (int i = 1; i < egg_shard_count; i++) {
    egg_io_shard_t *s = &egg_shards[i];
    int state = atomic_load_explicit(&s->state, memory_order_acquire);
    if (state != EGG_SHARD_STOPPED) {
      pthread_mutex_lock(&s->shutdown_mu);
      atomic_store_explicit(&s->state, EGG_SHARD_STOPPING,
                            memory_order_release);
      pthread_cond_signal(&s->shutdown_cv);
      pthread_mutex_unlock(&s->shutdown_mu);
    }
  }

  for (int i = 1; i < egg_shard_count; i++) {
    egg_io_shard_t *s = &egg_shards[i];
    if (s->thread_started) {
      pthread_join(s->thread_id, NULL);
      s->thread_started = false;
      pthread_cond_destroy(&s->shutdown_cv);
      pthread_mutex_destroy(&s->shutdown_mu);
    }
  }

  egg_shards_destroy_contexts();
  egg_shard_count = 1;
}

int egg_shards_count(void)
{
  return egg_shard_count;
}

int egg_shards_running(void)
{
  return atomic_load_explicit(&egg_shard_running, memory_order_acquire);
}
