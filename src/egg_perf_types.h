/*
 * egg_perf_types.h — Shared performance/threading definitions.
 *
 * This header provides constants and plain-data types that are safe
 * to include from any translation unit, including those that cannot
 * pull in <stdatomic.h> (e.g. the Python module, where Python.h
 * redefines atomic primitives).
 */

#ifndef _EGG_PERF_TYPES_H
#define _EGG_PERF_TYPES_H

#include <stdint.h>
#include <sys/resource.h>

/* L1D cache line size — used for alignas() on hot shared data to prevent
 * false sharing between cores.  64 bytes is standard on x86-64 and most
 * ARMv8 cores (Cortex-A53 through Neoverse-V2, Apple M-series).
 * Apple M1/M2 performance cores use 128-byte lines; over-aligning to 128
 * wastes 64 bytes per struct but never causes correctness issues, while
 * under-aligning causes measurable contention.
 */
#if defined(__APPLE__) && defined(__aarch64__)
#  define EGG_CACHELINE 128
#else
#  define EGG_CACHELINE 64
#endif

struct egg_traffic_snap {
  uint64_t irc, bn, partyline, trans, unknown, filesys;
};

float getcputime(void);
void egg_traffic_get_snap(struct egg_traffic_snap *in,
                          struct egg_traffic_snap *out);

/* Format a duration (seconds) into "N years N weeks ... N seconds" */
void egg_format_duration(uint64_t sec, char *out, size_t outlen);

/* Format uptime as "N days, HH:MM" compact string */
void egg_format_uptime(time_t seconds, char *out, size_t outlen);

/* RSS memory in kilobytes (getrusage ru_maxrss) */
static inline long egg_get_rss_kb(void)
{
  struct rusage ru;
  if (getrusage(RUSAGE_SELF, &ru))
    return -1;
  return ru.ru_maxrss;
}

/* getrusage timing helpers — wrap before/after pairs */
struct egg_rusage_timer {
  struct rusage ru1;
  int ok;
};

static inline void egg_timer_start(struct egg_rusage_timer *t)
{
  t->ok = !getrusage(RUSAGE_SELF, &t->ru1);
}

static inline int egg_timer_stop(struct egg_rusage_timer *t,
                                 double *user_ms, double *sys_ms)
{
  struct rusage ru2;
  if (!t->ok || getrusage(RUSAGE_SELF, &ru2))
    return 0;
  *user_ms = (double)(ru2.ru_utime.tv_usec - t->ru1.ru_utime.tv_usec) / 1000
           + (double)(ru2.ru_utime.tv_sec  - t->ru1.ru_utime.tv_sec)  * 1000;
  *sys_ms  = (double)(ru2.ru_stime.tv_usec - t->ru1.ru_stime.tv_usec) / 1000
           + (double)(ru2.ru_stime.tv_sec  - t->ru1.ru_stime.tv_sec)  * 1000;
  return 1;
}

#endif /* _EGG_PERF_TYPES_H */
