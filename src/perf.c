/*
 * perf.c — Per-tick performance monitoring for eggdrop.
 *
 * Seqlock protocol:
 *   Writer (main thread only) brackets updates with odd/even sequence bumps.
 *   Reader (any thread) retries until it sees two identical even sequences,
 *   guaranteeing a consistent snapshot without locks.
 *
 * Tick latency histogram thresholds:
 *   [0] < 10 µs   [1] < 100 µs   [2] < 1 ms   [3] < 10 ms   [4] >= 10 ms
 */

#include "main.h"
#include "perf.h"
#include "traffic.h"
#include <sys/resource.h>

/* Seqlock sequence counter — even = idle, odd = write in progress */
static _Atomic(uint32_t) pm_seq = 0;
static struct egg_perf_metrics pm;
static uint64_t tick_start_ns;

static inline void pm_write_begin(void)
{
  uint32_t s = atomic_load_explicit(&pm_seq, memory_order_relaxed);
  atomic_store_explicit(&pm_seq, s + 1, memory_order_release);
  atomic_thread_fence(memory_order_release);
}

static inline void pm_write_end(void)
{
  atomic_thread_fence(memory_order_release);
  uint32_t s = atomic_load_explicit(&pm_seq, memory_order_relaxed);
  atomic_store_explicit(&pm_seq, s + 1, memory_order_release);
}

void egg_perf_tick_begin(void)
{
  tick_start_ns = egg_perf_now_ns();
}

void egg_perf_tick_end(int was_idle)
{
  uint64_t elapsed = egg_perf_now_ns() - tick_start_ns;

  pm_write_begin();

  pm.tick_count++;
  pm.tick_ns_last = elapsed;
  pm.tick_ns_total += elapsed;
  if (elapsed > pm.tick_ns_max)
    pm.tick_ns_max = elapsed;
  if (was_idle)
    pm.idle_ticks++;

  /* Histogram: classify tick into latency bucket */
  int bucket;
  if (elapsed < 10000ULL)         bucket = 0;  /* < 10 µs */
  else if (elapsed < 100000ULL)   bucket = 1;  /* < 100 µs */
  else if (elapsed < 1000000ULL)  bucket = 2;  /* < 1 ms */
  else if (elapsed < 10000000ULL) bucket = 3;  /* < 10 ms */
  else                            bucket = 4;  /* >= 10 ms */
  pm.tick_hist[bucket]++;

  /* Arena stats from this tick */
  op_arena_t *a = op_event_arena();
  pm.arena_allocs += a->alloc_count;
  uint64_t used = a->used;
  pm.arena_bytes += used;
  if (used > pm.arena_peak_bytes)
    pm.arena_peak_bytes = used;
  pm.arena_overflows += (a->overflow ? 1 : 0);

  pm_write_end();
}

void egg_perf_io_drain(int results)
{
  pm_write_begin();
  pm.io_drain_count++;
  pm.io_drain_results += (uint64_t)results;
  if ((uint64_t)results > pm.io_drain_max_batch)
    pm.io_drain_max_batch = (uint64_t)results;
  pm_write_end();
}

void egg_perf_bind_dispatch(int was_exact)
{
  pm_write_begin();
  pm.bind_dispatches++;
  if (was_exact)
    pm.bind_exact_hits++;
  else
    pm.bind_scan_hits++;
  pm_write_end();
}

void egg_perf_traffic_tick(uint64_t bytes_in, uint64_t bytes_out)
{
  pm_write_begin();
  pm.traffic_in_last_sec = bytes_in;
  pm.traffic_out_last_sec = bytes_out;
  pm_write_end();
}

struct egg_perf_metrics egg_perf_snapshot(void)
{
  struct egg_perf_metrics snap;
  uint32_t s1, s2;
  do {
    s1 = atomic_load_explicit(&pm_seq, memory_order_acquire);
    if (s1 & 1) continue;  /* write in progress */
    __builtin_memcpy(&snap, &pm, sizeof snap);
    atomic_thread_fence(memory_order_acquire);
    s2 = atomic_load_explicit(&pm_seq, memory_order_relaxed);
  } while (s1 != s2);
  return snap;
}

void egg_perf_reset(void)
{
  pm_write_begin();
  memset(&pm, 0, sizeof pm);
  pm_write_end();
}

float getcputime(void)
{
  struct rusage ru;

  getrusage(RUSAGE_SELF, &ru);
  float utime = ru.ru_utime.tv_sec + (ru.ru_utime.tv_usec / 1000000.00);
  float stime = ru.ru_stime.tv_sec + (ru.ru_stime.tv_usec / 1000000.00);
  return utime + stime;
}

void egg_traffic_get_snap(struct egg_traffic_snap *in,
                          struct egg_traffic_snap *out)
{
#define TSNAP(d, f) \
  atomic_load_explicit(&d##traffic.total.f, memory_order_relaxed) + \
  atomic_load_explicit(&d##traffic.today.f, memory_order_relaxed)

  in->irc  = TSNAP(i, irc);      out->irc  = TSNAP(o, irc);
  in->bn   = TSNAP(i, bn);       out->bn   = TSNAP(o, bn);
  in->partyline = TSNAP(i, partyline); out->partyline = TSNAP(o, partyline);
  in->trans = TSNAP(i, trans);    out->trans = TSNAP(o, trans);
  in->unknown = TSNAP(i, unknown); out->unknown = TSNAP(o, unknown);
  in->filesys = TSNAP(i, filesys); out->filesys = TSNAP(o, filesys);

#undef TSNAP
}

void egg_perf_reset_traffic(void)
{
  egg_traffic_accumulate(&otraffic);
  egg_traffic_accumulate(&itraffic);
  egg_traffic_reset_today(&otraffic);
  egg_traffic_reset_today(&itraffic);
}
