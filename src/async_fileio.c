/*
 * async_fileio.c — async file I/O via the op_async thread pool.
 *
 * Offloads blocking file operations (copy, write+rename) to worker
 * threads so they never stall the main event loop.
 *
 * Copyright (C) 2026 Eggheads Development Team
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "main.h"
#include "async_fileio.h"
#include "async_log.h"
#include "misc_file.h"
#include <op_async.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ======================================================================
 * Async copyfile
 * ==================================================================== */

typedef struct {
  char *src;
  char *dst;
  int   result;
} acopy_ctx_t;

static op_bh *acopy_bh   = nullptr;
static op_bh *awrite_bh  = nullptr;

static void acopy_work(void *arg)
{
  acopy_ctx_t *c = arg;
  c->result = copyfile(c->src, c->dst);
}

static void acopy_done(void *arg)
{
  acopy_ctx_t *c = arg;
  if (c->result != 0)
    putlog(LOG_MISC, "*", "async_fileio: backup failed (%s): error %d",
           c->dst, c->result);
  op_free(c->src);
  op_free(c->dst);
  op_bh_free(acopy_bh, c);
}

void async_copyfile(const char *src, const char *dst)
{
  if (!op_async_active()) {
    copyfile(src, dst);
    return;
  }

  if (!acopy_bh) acopy_bh = op_bh_create(sizeof(acopy_ctx_t), 8, "acopy_ctx");
  acopy_ctx_t *c = (acopy_ctx_t *)op_bh_alloc(acopy_bh);
  c->src = op_strdup(src);
  c->dst = op_strdup(dst);
  c->result = 0;
  op_async_submit(acopy_work, acopy_done, c);
}

/* ======================================================================
 * Async movefile  (unlink dst + rename/copy src→dst off the main thread)
 * ==================================================================== */

typedef struct {
  char *src;
  char *dst;
  int   result;
} amove_ctx_t;

static op_bh *amove_bh = nullptr;

static void amove_work(void *arg)
{
  amove_ctx_t *c = arg;
  c->result = movefile(c->src, c->dst);
}

static void amove_done(void *arg)
{
  amove_ctx_t *c = arg;
  if (c->result != 0)
    putlog(LOG_MISC, "*", "async_fileio: move failed (%s → %s): error %d",
           c->src, c->dst, c->result);
  op_free(c->src);
  op_free(c->dst);
  op_bh_free(amove_bh, c);
}

void async_movefile(const char *src, const char *dst)
{
  if (!op_async_active()) {
    movefile(src, dst);
    return;
  }

  if (!amove_bh) amove_bh = op_bh_create(sizeof(amove_ctx_t), 8, "amove_ctx");
  amove_ctx_t *c = (amove_ctx_t *)op_bh_alloc(amove_bh);
  c->src    = op_strdup(src);
  c->dst    = op_strdup(dst);
  c->result = 0;
  op_async_submit(amove_work, amove_done, c);
}

/* ======================================================================
 * Async writebuf  (write buffer → tmpfile → fsync → rename)
 *
 * Write coalescing: at most one write per path is in-flight at a time.
 * If async_writebuf() is called while a write is already in-flight,
 * the new buffer is stored as "pending".  When the in-flight write
 * completes, the pending buffer is immediately submitted as the next
 * write.  Only the latest pending buffer is retained — intermediate
 * ones are discarded — so rapid callers (e.g. write_userfile on every
 * join) produce at most two disk writes: the one already in-flight plus
 * one final write of the most-recent state.
 * ==================================================================== */

/* Per-path coalescing state (main-thread only — done_fn runs on main) */
typedef struct coalesce_slot {
  char   *path;
  char   *pending_buf;   /* newest buffer waiting to be written, or NULL */
  size_t  pending_len;
  int     pending_perm;
  int     in_flight;     /* 1 while a write for this path is queued/running */
  struct coalesce_slot *next;
} coalesce_slot_t;

static coalesce_slot_t *coalesce_head = nullptr;  /* main-thread only */

/* Find or create the coalescing slot for a path. */
static coalesce_slot_t *coalesce_get(const char *path)
{
  for (coalesce_slot_t *s = coalesce_head; s; s = s->next)
    if (!strcmp(s->path, path)) return s;
  coalesce_slot_t *s = (coalesce_slot_t *)op_malloc(sizeof *s);
  s->path         = op_strdup(path);
  s->pending_buf  = nullptr;
  s->pending_len  = 0;
  s->pending_perm = 0;
  s->in_flight    = 0;
  s->next         = coalesce_head;
  coalesce_head   = s;
  return s;
}

typedef struct {
  char   *finalpath;
  char   *tmppath;
  char   *buf;
  size_t  len;
  int     perm;
  int     result;
} awrite_ctx_t;

static void awrite_work(void *arg)
{
  awrite_ctx_t *c = arg;

  int fd = open(c->tmppath, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, c->perm);
  if (fd < 0) {
    c->result = -1;
    return;
  }

  size_t written = 0;
  while (written < c->len) {
    ssize_t w = write(fd, c->buf + written, c->len - written);
    if (w < 0) {
      if (errno == EINTR)
        continue;
      close(fd);
      unlink(c->tmppath);
      c->result = -2;
      return;
    }
    written += (size_t)w;
  }

  fsync(fd);
  close(fd);

  if (rename(c->tmppath, c->finalpath) < 0) {
    unlink(c->tmppath);
    c->result = -3;
    return;
  }

  c->result = 0;
}

static void awrite_done(void *arg)
{
  awrite_ctx_t *c = arg;
  if (c->result != 0)
    putlog(LOG_MISC, "*", "async_fileio: write failed (%s): error %d",
           c->finalpath, c->result);

  /* Coalescing: mark slot idle; submit pending write if one accumulated. */
  coalesce_slot_t *cs = coalesce_get(c->finalpath);
  cs->in_flight = 0;
  if (cs->pending_buf) {
    char  *pbuf  = cs->pending_buf;
    size_t plen  = cs->pending_len;
    int    pperm = cs->pending_perm;
    cs->pending_buf = nullptr;
    /* async_writebuf will find cs->in_flight==0 and submit immediately */
    async_writebuf(c->finalpath, pbuf, plen, pperm);
  }

  op_free(c->finalpath);
  op_free(c->tmppath);
  op_free(c->buf);
  op_bh_free(awrite_bh, c);
}

static void awrite_sync(const char *finalpath, const char *tmppath,
                         char *buf, size_t len, int perm)
{
  int fd = open(tmppath, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, perm);
  if (fd < 0) {
    putlog(LOG_MISC, "*", "async_fileio: sync write open failed (%s)", tmppath);
    op_free(buf);
    return;
  }

  size_t written = 0;
  while (written < len) {
    ssize_t w = write(fd, buf + written, len - written);
    if (w < 0) {
      if (errno == EINTR)
        continue;
      close(fd);
      unlink(tmppath);
      op_free(buf);
      return;
    }
    written += (size_t)w;
  }

  fsync(fd);
  close(fd);
  rename(tmppath, finalpath);
  op_free(buf);
}

static _Atomic unsigned int awrite_seq = 0;

void async_writebuf(const char *finalpath, char *buf, size_t len, int perm)
{
  if (!op_async_active()) {
    op_strbuf_t tmp = {};
    op_strbuf_init(&tmp);
    op_strbuf_appendf(&tmp, "%s~new.%u", finalpath,
                      atomic_fetch_add_explicit(&awrite_seq, 1,
                                                memory_order_relaxed));
    awrite_sync(finalpath, op_strbuf_str(&tmp), buf, len, perm);
    op_strbuf_free(&tmp);
    return;
  }

  /* Coalescing: if a write is already in-flight for this path, store the
   * new buffer as pending (dropping any previous pending buffer) so the
   * latest state is always written exactly once after the current write
   * completes.  This bounds disk writes to two per burst regardless of how
   * many write_userfile() calls the main loop issues. */
  coalesce_slot_t *cs = coalesce_get(finalpath);
  if (cs->in_flight) {
    op_free(cs->pending_buf);
    cs->pending_buf  = buf;
    cs->pending_len  = len;
    cs->pending_perm = perm;
    return;  /* awrite_done will submit this buffer when in-flight completes */
  }
  cs->in_flight = 1;

  unsigned int seq = atomic_fetch_add_explicit(&awrite_seq, 1,
                                               memory_order_relaxed);
  op_strbuf_t tmp = {};
  op_strbuf_init(&tmp);
  op_strbuf_appendf(&tmp, "%s~new.%u", finalpath, seq);

  if (!awrite_bh) awrite_bh = op_bh_create(sizeof(awrite_ctx_t), 8, "awrite_ctx");
  awrite_ctx_t *c = (awrite_ctx_t *)op_bh_alloc(awrite_bh);
  c->finalpath = op_strdup(finalpath);
  c->tmppath   = op_strbuf_steal(&tmp);
  c->buf       = buf;
  c->len       = len;
  c->perm      = perm;
  c->result    = 0;
  op_async_submit(awrite_work, awrite_done, c);
}

/* ======================================================================
 * Async log-size check
 *
 * Submits stat() calls for each active log file on a worker thread.
 * The done_fn runs on the main thread and performs the same truncation
 * logic as the synchronous check_logsize() in misc.c, but without
 * blocking the event loop on potentially slow filesystem stat() calls.
 * ==================================================================== */

extern log_t *logs;
extern int    max_logs, max_logsize, keep_all_logs;

typedef struct {
  int   log_idx;
  char *filename;   /* snapshot of logs[i].filename at submit time */
  off_t size;
  int   ok;
} alogstat_ctx_t;

static op_bh *alogstat_bh = nullptr;

static void alogstat_work(void *arg)
{
  alogstat_ctx_t *c = arg;
  struct stat ss;
  if (stat(c->filename, &ss) == 0) {
    c->size = ss.st_size;
    c->ok   = 1;
  } else {
    c->ok = 0;
  }
}

static void alogstat_done(void *arg)
{
  alogstat_ctx_t *c = arg;
  int i = c->log_idx;

  /* Verify the slot still refers to the same file we stat'd */
  if (c->ok && logs[i].filename && !strcmp(logs[i].filename, c->filename) &&
      (c->size >> 10) > (off_t)max_logsize) {
    putlog(LOG_MISC, "*", MISC_CLOGS, c->filename, (long long)c->size);

    if (async_log_active() && async_log_slot_open(i))
      async_log_close(i);
    else if (logs[i].f) {
      fclose(logs[i].f);
      logs[i].f = nullptr;
    }

    op_strbuf_t yesterday = {};
    op_strbuf_init(&yesterday);
    op_strbuf_appendf(&yesterday, "%s.yesterday", c->filename);
    unlink(op_strbuf_str(&yesterday));  /* remove old backup synchronously */
    async_movefile(c->filename, op_strbuf_str(&yesterday));  /* rename off main thread */
    op_strbuf_free(&yesterday);
  }

  op_free(c->filename);
  op_bh_free(alogstat_bh, c);
}

void async_check_logsize(void)
{
  if (!op_async_active() || keep_all_logs || max_logsize <= 0)
    return;

  if (!alogstat_bh)
    alogstat_bh = op_bh_create(sizeof(alogstat_ctx_t), 16, "alogstat_ctx");

  for (int i = 0; i < max_logs; i++) {
    if (!logs[i].filename)
      continue;
    alogstat_ctx_t *c = (alogstat_ctx_t *)op_bh_alloc(alogstat_bh);
    c->log_idx  = i;
    c->filename = op_strdup(logs[i].filename);
    c->size     = 0;
    c->ok       = 0;
    op_async_submit(alogstat_work, alogstat_done, c);
  }
}

/* ======================================================================
 * Stats
 * ==================================================================== */

void async_fileio_stats(int *inflight_out, int *pending_out)
{
  int inflight = 0, pending = 0;
  for (coalesce_slot_t *s = coalesce_head; s; s = s->next) {
    if (s->in_flight)  inflight++;
    if (s->pending_buf) pending++;
  }
  if (inflight_out) *inflight_out = inflight;
  if (pending_out)  *pending_out  = pending;
}
