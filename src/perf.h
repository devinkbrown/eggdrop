/*
 * perf.h — Per-tick performance monitoring with seqlock-protected metrics.
 *
 * Tracks timing, memory, and I/O metrics per main-loop iteration.
 * All counters use monotonic clock_gettime(CLOCK_MONOTONIC) for nanosecond
 * precision.
 *
 * Seqlock guarantees tear-free reads from any thread without locks:
 *   Writer increments sequence to odd (write in progress), updates data,
 *   increments to even (write complete).  Reader retries if sequence
 *   changed or was odd.
 *
 * Tick latency histogram provides distribution insight:
 *   bucket[0]: < 10 µs     (idle tick)
 *   bucket[1]: < 100 µs    (light load)
 *   bucket[2]: < 1 ms      (normal)
 *   bucket[3]: < 10 ms     (busy)
 *   bucket[4]: >= 10 ms    (overloaded)
 */

#ifndef _EGG_PERF_H
#define _EGG_PERF_H

#include <stdint.h>
#include <stdatomic.h>
#include <stdalign.h>
#include <time.h>
#include "egg_perf_types.h"

#define EGG_PERF_HIST_BUCKETS 5

struct egg_perf_metrics {
  /* Tick timing */
  uint64_t tick_count;
  uint64_t tick_ns_last;
  uint64_t tick_ns_max;
  uint64_t tick_ns_total;
  uint64_t idle_ticks;

  /* Tick latency histogram */
  uint64_t tick_hist[EGG_PERF_HIST_BUCKETS];

  /* Arena allocator */
  uint64_t arena_allocs;
  uint64_t arena_bytes;
  uint64_t arena_peak_bytes;
  uint64_t arena_overflows;

  /* I/O thread */
  uint64_t io_drain_count;
  uint64_t io_drain_results;
  uint64_t io_drain_max_batch;

  /* Bind dispatch */
  uint64_t bind_dispatches;
  uint64_t bind_exact_hits;
  uint64_t bind_scan_hits;

  /* Traffic rate (bytes in last second) */
  uint64_t traffic_in_last_sec;
  uint64_t traffic_out_last_sec;
};

/* Seqlock-protected metrics snapshot */
void egg_perf_tick_begin(void);
void egg_perf_tick_end(int was_idle);
void egg_perf_io_drain(int results);
void egg_perf_bind_dispatch(int was_exact);
void egg_perf_traffic_tick(uint64_t bytes_in, uint64_t bytes_out);
struct egg_perf_metrics egg_perf_snapshot(void);
void egg_perf_reset(void);

/* Daily traffic counter rollover (accumulate today → total, reset today) */
void egg_perf_reset_traffic(void);

static inline uint64_t egg_perf_now_ns(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

#endif /* _EGG_PERF_H */
