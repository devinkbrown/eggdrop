/*
 * async_log.c -- dedicated async log-file writer thread.
 *
 * Architecture
 * ============
 *   Main thread:   formats log lines, enqueues commands (lock-free push to
 *                  a singly-linked list); signals a condvar to wake the writer.
 *   Writer thread: wakes, atomically swaps the list head to NULL, reverses the
 *                  list to restore FIFO order, then executes each command
 *                  (fopen / fwrite / fclose).
 *
 * The writer thread owns all FILE * handles.  The main thread never calls
 * fwrite or fclose directly when async mode is active.
 *
 * Thread safety
 * =============
 *   - Push (main thread only): CAS on list head, then signal condvar.
 *   - Pop  (writer thread only): atomic exchange of list head with NULL.
 *   - No lock needed on the hot write path.
 *
 * Copyright (C) 2026 Eggheads Development Team
 */

#define _GNU_SOURCE
#define COMPILING_MEM
#include "main.h"
#include "async_log.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---- command types ------------------------------------------------------- */

typedef enum {
  ALOG_WRITE,  /* open-if-needed + fwrite a line */
  ALOG_CLOSE,  /* fclose a slot's file             */
  ALOG_STOP,   /* sentinel: drain and exit writer  */
  ALOG_FLUSH,  /* writer signals flush_done when processed */
} alog_cmd_type;

typedef struct alog_cmd {
  alog_cmd_type    type;
  int              slot;   /* log slot index (WRITE / CLOSE) */
  char            *path;   /* heap copy of file path (WRITE, may be NULL) */
  char            *line;   /* heap copy of formatted line (WRITE) */
  struct alog_cmd *next;   /* intrusive Treiber stack link */
} alog_cmd_t;

/* ---- state --------------------------------------------------------------- */

#define ALOG_MAX_SLOTS 64

static _Atomic(alog_cmd_t *) stack_head;  /* lock-free Treiber stack (LIFO) */

static pthread_t       writer_tid;
static pthread_mutex_t wake_mutex  = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  wake_cond   = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t flush_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  flush_cond  = PTHREAD_COND_INITIALIZER;
static _Atomic int     flush_seq;   /* incremented by writer after each FLUSH */

static _Atomic bool     writer_running;
static int              alog_nslots;  /* set once at init, read-only after */

/* Cumulative write stats — updated by writer thread, read by main thread. */
static _Atomic uint64_t alog_lines_written;
static _Atomic uint64_t alog_bytes_written;

/* Writer-private file handles */
static FILE           *slot_files[ALOG_MAX_SLOTS];

/* Main-thread view: true when a non-null path has been sent for this slot
 * and async_log_close() has not yet been called.  Lets the main thread
 * know not to pass a path on subsequent writes. */
static bool            slot_told_open[ALOG_MAX_SLOTS];

/* ---- heap helpers -------------------------------------------------------- */

static alog_cmd_t *cmd_alloc(void)
{
  /* Use system malloc so we don't need COMPILING_MEM gymnastics for every
   * caller; the writer frees with free() via cmd_free(). */
  alog_cmd_t *c = (alog_cmd_t *)malloc(sizeof *c);
  if (!c)
    return nullptr;
  memset(c, 0, sizeof *c);
  return c;
}

static void cmd_free(alog_cmd_t *c)
{
  if (!c) return;
  free(c->path);
  free(c->line);
  free(c);
}

/* ---- Treiber stack push ------------------------------------------------- */

static void stack_push(alog_cmd_t *cmd)
{
  alog_cmd_t *old = atomic_load_explicit(&stack_head, memory_order_relaxed);
  do {
    cmd->next = old;
  } while (!atomic_compare_exchange_weak_explicit(
      &stack_head, &old, cmd,
      memory_order_release, memory_order_relaxed));
}

/* Atomically drain the entire stack, reverse it to restore submission order,
 * and return the head of the FIFO chain. */
static alog_cmd_t *stack_drain(void)
{
  alog_cmd_t *lifo = atomic_exchange_explicit(&stack_head, nullptr,
                                               memory_order_acquire);
  /* Reverse: LIFO → FIFO */
  alog_cmd_t *fifo = nullptr;
  while (lifo) {
    alog_cmd_t *nxt = lifo->next;
    lifo->next = fifo;
    fifo = lifo;
    lifo = nxt;
  }
  return fifo;
}

/* ---- writer thread ------------------------------------------------------- */

static void writer_open(int slot, const char *path)
{
  if (slot < 0 || slot >= alog_nslots || !path) return;
  if (slot_files[slot]) return;  /* already open */

  slot_files[slot] = fopen(path, "a");
  if (slot_files[slot])
    setvbuf(slot_files[slot], nullptr, _IOFBF, 65536);  /* 64 KB block buffer */
}

static void writer_write(int slot, const char *path, const char *line)
{
  if (slot < 0 || slot >= alog_nslots) return;
  if (!slot_files[slot])
    writer_open(slot, path);
  if (!slot_files[slot]) return;  /* open failed */
  fputs(line, slot_files[slot]);
  atomic_fetch_add_explicit(&alog_lines_written, 1, memory_order_relaxed);
  atomic_fetch_add_explicit(&alog_bytes_written, strlen(line),
                            memory_order_relaxed);
}

static void writer_close(int slot)
{
  if (slot < 0 || slot >= alog_nslots) return;
  if (!slot_files[slot]) return;
  fflush(slot_files[slot]);
  fclose(slot_files[slot]);
  slot_files[slot] = nullptr;
}

static void *writer_main(void *arg)
{
  (void)arg;

  while (1) {
    /* Wait for commands */
    pthread_mutex_lock(&wake_mutex);
    while (!atomic_load_explicit(&stack_head, memory_order_acquire))
      pthread_cond_wait(&wake_cond, &wake_mutex);
    pthread_mutex_unlock(&wake_mutex);

    alog_cmd_t *chain = stack_drain();
    bool stop = false;

    for (alog_cmd_t *c = chain; c; c = c->next) {
      switch (c->type) {
      case ALOG_WRITE:
        writer_write(c->slot, c->path, c->line);
        break;
      case ALOG_CLOSE:
        writer_close(c->slot);
        break;
      case ALOG_FLUSH:
        /* Flush all open files, then signal flush completion */
        for (int i = 0; i < alog_nslots; i++)
          if (slot_files[i]) fflush(slot_files[i]);
        pthread_mutex_lock(&flush_mutex);
        atomic_fetch_add_explicit(&flush_seq, 1, memory_order_release);
        pthread_cond_broadcast(&flush_cond);
        pthread_mutex_unlock(&flush_mutex);
        break;
      case ALOG_STOP:
        stop = true;
        break;
      }
    }

    /* Free all processed commands */
    alog_cmd_t *c = chain;
    while (c) {
      alog_cmd_t *nxt = c->next;
      cmd_free(c);
      c = nxt;
    }

    if (stop)
      break;
  }

  /* Drain + close all files on exit */
  for (int i = 0; i < alog_nslots; i++)
    writer_close(i);

  return nullptr;
}

/* ---- public API ---------------------------------------------------------- */

void async_log_init(int max_slots)
{
  if (atomic_load_explicit(&writer_running, memory_order_acquire))
    return;

  alog_nslots = max_slots > 0 && max_slots <= ALOG_MAX_SLOTS
                ? max_slots : ALOG_MAX_SLOTS;
  memset(slot_files,     0, sizeof slot_files);
  memset(slot_told_open, 0, sizeof slot_told_open);
  atomic_store_explicit(&stack_head, nullptr, memory_order_relaxed);
  atomic_store_explicit(&flush_seq, 0, memory_order_relaxed);

  if (pthread_create(&writer_tid, nullptr, writer_main, nullptr) != 0) {
    /* Fall back to sync mode — caller checks async_log_active() */
    return;
  }
  atomic_store_explicit(&writer_running, true, memory_order_release);
}

static void enqueue(alog_cmd_t *cmd)
{
  stack_push(cmd);
  pthread_mutex_lock(&wake_mutex);
  pthread_cond_signal(&wake_cond);
  pthread_mutex_unlock(&wake_mutex);
}

void async_log_write(int slot_idx, const char *path, const char *line)
{
  if (!atomic_load_explicit(&writer_running, memory_order_acquire)) {
    /* Sync fallback: not initialized or failed to start */
    return;
  }

  alog_cmd_t *cmd = cmd_alloc();
  if (!cmd) return;

  cmd->type  = ALOG_WRITE;
  cmd->slot  = slot_idx;
  cmd->path  = path ? strdup(path) : nullptr;
  cmd->line  = line ? strdup(line) : nullptr;
  if (path && slot_idx >= 0 && slot_idx < alog_nslots)
    slot_told_open[slot_idx] = true;
  enqueue(cmd);
}

void async_log_close(int slot_idx)
{
  if (!atomic_load_explicit(&writer_running, memory_order_acquire)) return;

  alog_cmd_t *cmd = cmd_alloc();
  if (!cmd) return;

  cmd->type = ALOG_CLOSE;
  cmd->slot = slot_idx;
  if (slot_idx >= 0 && slot_idx < alog_nslots)
    slot_told_open[slot_idx] = false;
  enqueue(cmd);
}

void async_log_flush(void)
{
  if (!atomic_load_explicit(&writer_running, memory_order_acquire)) return;

  int before = atomic_load_explicit(&flush_seq, memory_order_acquire);

  alog_cmd_t *cmd = cmd_alloc();
  if (!cmd) return;

  cmd->type = ALOG_FLUSH;
  enqueue(cmd);

  /* Block until the writer acknowledges the flush */
  pthread_mutex_lock(&flush_mutex);
  while (atomic_load_explicit(&flush_seq, memory_order_acquire) == before)
    pthread_cond_wait(&flush_cond, &flush_mutex);
  pthread_mutex_unlock(&flush_mutex);
}

void async_log_destroy(void)
{
  if (!atomic_load_explicit(&writer_running, memory_order_acquire)) return;

  /* First flush so nothing is lost */
  async_log_flush();

  /* Then send the stop sentinel */
  alog_cmd_t *cmd = cmd_alloc();
  if (cmd) {
    cmd->type = ALOG_STOP;
    enqueue(cmd);
  }

  pthread_join(writer_tid, nullptr);
  atomic_store_explicit(&writer_running, false, memory_order_release);
}

bool async_log_active(void)
{
  return atomic_load_explicit(&writer_running, memory_order_acquire);
}

bool async_log_slot_open(int slot_idx)
{
  if (!async_log_active()) return false;
  if (slot_idx < 0 || slot_idx >= alog_nslots) return false;
  return slot_told_open[slot_idx];
}

void async_log_stats(uint64_t *lines_out, uint64_t *bytes_out)
{
  if (lines_out)
    *lines_out = atomic_load_explicit(&alog_lines_written, memory_order_relaxed);
  if (bytes_out)
    *bytes_out = atomic_load_explicit(&alog_bytes_written, memory_order_relaxed);
}

void async_log_restart(void)
{
  /* Called in the child process after fork().  The writer thread from the
   * parent does not exist here.  Close inherited file handles, reinitialise
   * all synchronisation primitives to a clean unlocked state, drain any
   * stale queued commands, and start a fresh writer thread. */
  for (int i = 0; i < alog_nslots; i++) {
    if (slot_files[i]) {
      fclose(slot_files[i]);
      slot_files[i] = nullptr;
    }
  }
  memset(slot_told_open, 0, sizeof slot_told_open);

  /* Reinitialise mutexes — the inherited copies may be locked. */
  pthread_mutex_init(&wake_mutex,  nullptr);
  pthread_mutex_init(&flush_mutex, nullptr);
  pthread_cond_init(&wake_cond,   nullptr);
  pthread_cond_init(&flush_cond,  nullptr);

  /* Drain any commands that were queued in the parent but never processed. */
  alog_cmd_t *cmd = atomic_exchange_explicit(&stack_head, nullptr,
                                              memory_order_acquire);
  while (cmd) {
    alog_cmd_t *nxt = cmd->next;
    cmd_free(cmd);
    cmd = nxt;
  }
  atomic_store_explicit(&flush_seq,       0,     memory_order_relaxed);
  atomic_store_explicit(&alog_lines_written, 0,  memory_order_relaxed);
  atomic_store_explicit(&alog_bytes_written, 0,  memory_order_relaxed);
  atomic_store_explicit(&writer_running,  false, memory_order_release);

  /* Start a fresh writer thread with the same slot count. */
  async_log_init(alog_nslots);
}
