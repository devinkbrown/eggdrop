/*
 * async_fileio.h — async file I/O via the op_async thread pool.
 *
 * Copyright (C) 2026 Eggheads Development Team
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _EGG_ASYNC_FILEIO_H
#define _EGG_ASYNC_FILEIO_H

#include <stddef.h>

/* Copy a file asynchronously on a worker thread.  Falls back to synchronous
 * copyfile() if the async pool is not active. */
void async_copyfile(const char *src, const char *dst);

/* Move (rename, or copy+delete across filesystems) a file on a worker thread.
 * Falls back to synchronous movefile() if the async pool is not active. */
void async_movefile(const char *src, const char *dst);

/* Write a memory buffer to disk atomically: worker thread writes to a
 * temp file, fsyncs, then renames to finalpath.
 *
 * Takes ownership of buf — it will be freed (with the system allocator)
 * after the write completes.  buf MUST have been allocated with system
 * malloc (e.g. from open_memstream).
 *
 * Falls back to synchronous write if the async pool is not active. */
void async_writebuf(const char *finalpath, char *buf, size_t len, int perm);

/* Submit a stat() for every active log file on a worker thread.  The
 * completion runs on the main thread and rotates files that exceed
 * max_logsize, mirroring the synchronous check_logsize() in misc.c.
 * No-op if async is not active, keep_all_logs is set, or max_logsize <= 0. */
void async_check_logsize(void);

/* Return write-coalescing slot counts.  Either pointer may be NULL.
 * inflight_out: paths with a write currently queued or running.
 * pending_out:  paths with a newer buffer waiting behind the inflight write.
 * Must be called from the main thread. */
void async_fileio_stats(int *inflight_out, int *pending_out);

#endif /* _EGG_ASYNC_FILEIO_H */
