/*
 * async_log.h -- dedicated async log-file writer thread.
 *
 * Moves all log file I/O off the main event loop.  The main thread formats
 * lines and enqueues write commands via a lock-free push; a dedicated writer
 * thread wakes on a condvar, drains the queue, and performs all fopen /
 * fwrite / fclose calls.
 *
 * Copyright (C) 2026 Eggheads Development Team
 */

#ifndef _EGG_ASYNC_LOG_H
#define _EGG_ASYNC_LOG_H

#include <stdbool.h>
#include <stdint.h>

/* Initialize the async log writer for up to max_slots log slots.
 * Starts the writer thread.  Must be called from the main thread after
 * op_async_init().  Calling more than once is a no-op. */
void async_log_init(int max_slots);

/* Write a formatted line (including trailing newline) to log slot slot_idx.
 * path is the filesystem path to open if the slot is not yet open (may be
 * NULL if the slot is already open from a previous write).  Ownership of
 * line and path is NOT transferred — they are copied internally. */
void async_log_write(int slot_idx, const char *path, const char *line);

/* Close the file for slot slot_idx.  Subsequent writes will re-open it. */
void async_log_close(int slot_idx);

/* Block until the writer thread has processed all queued commands.
 * Use before log rotation or shutdown so no lines are dropped. */
void async_log_flush(void);

/* Flush and stop the writer thread.  Must be called from the main thread
 * before op_async_shutdown(). */
void async_log_destroy(void);

/* Returns true if the writer thread is running. */
bool async_log_active(void);

/* Returns true if the writer has been asked to open slot_idx and has not
 * yet been asked to close it.  Used by the main thread to decide whether
 * to pass an open path with the next write to that slot. */
bool async_log_slot_open(int slot_idx);

/* Fill *lines_out and *bytes_out with cumulative write counters.
 * Either pointer may be NULL.  Counters are updated relaxed from the writer
 * thread and are best-effort (no synchronization guarantee vs in-flight
 * writes). */
void async_log_stats(uint64_t *lines_out, uint64_t *bytes_out);

#endif /* _EGG_ASYNC_LOG_H */
