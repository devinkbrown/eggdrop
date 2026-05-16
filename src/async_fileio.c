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
#include <op_async.h>

#include <errno.h>
#include <fcntl.h>
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
  op_free(c);
}

void async_copyfile(const char *src, const char *dst)
{
  if (!op_async_active()) {
    copyfile(src, dst);
    return;
  }

  acopy_ctx_t *c = op_malloc(sizeof(*c));
  c->src = op_strdup(src);
  c->dst = op_strdup(dst);
  c->result = 0;
  op_async_submit(acopy_work, acopy_done, c);
}

/* ======================================================================
 * Async writebuf  (write buffer → tmpfile → fsync → rename)
 * ==================================================================== */

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
  op_free(c->finalpath);
  op_free(c->tmppath);
  op_free(c->buf);
  op_free(c);
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
  unsigned int seq = atomic_fetch_add_explicit(&awrite_seq, 1,
                                               memory_order_relaxed);
  op_strbuf_t tmp = {};
  op_strbuf_init(&tmp);
  op_strbuf_appendf(&tmp, "%s~new.%u", finalpath, seq);

  if (!op_async_active()) {
    awrite_sync(finalpath, op_strbuf_str(&tmp), buf, len, perm);
    op_strbuf_free(&tmp);
    return;
  }

  awrite_ctx_t *c = op_malloc(sizeof(*c));
  c->finalpath = op_strdup(finalpath);
  c->tmppath = op_strbuf_steal(&tmp);
  c->buf = buf;
  c->len = len;
  c->perm = perm;
  c->result = 0;
  op_async_submit(awrite_work, awrite_done, c);
}
