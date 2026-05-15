/*
 * traffic.h — Cache-line padded atomic traffic counters.
 *
 * Traffic counters are grouped by direction (inbound/outbound) and placed
 * on separate cache lines (alignas(64)) so concurrent atomic updates from
 * different threads never cause false sharing.
 *
 * Within each group, the "today" counters (hot-path, incremented per
 * message) are adjacent for spatial locality.  The all-time accumulators
 * (cold, touched once per day) follow on the next cache line.
 */

#ifndef _EGG_TRAFFIC_H
#define _EGG_TRAFFIC_H

#include <stdatomic.h>
#include <stdalign.h>
#include "egg_perf_types.h"

struct egg_traffic_today {
  _Atomic uint64_t irc;
  _Atomic uint64_t bn;
  _Atomic uint64_t partyline;
  _Atomic uint64_t trans;
  _Atomic uint64_t unknown;
  _Atomic uint64_t filesys;
};

struct egg_traffic_alltime {
  _Atomic uint64_t irc;
  _Atomic uint64_t bn;
  _Atomic uint64_t partyline;
  _Atomic uint64_t trans;
  _Atomic uint64_t unknown;
  _Atomic uint64_t filesys;
};

struct egg_traffic {
  alignas(EGG_CACHELINE) struct egg_traffic_today  today;
  alignas(EGG_CACHELINE) struct egg_traffic_alltime total;
};

extern struct egg_traffic itraffic;
extern struct egg_traffic otraffic;

#define itraffic_irc_today     itraffic.today.irc
#define itraffic_bn_today      itraffic.today.bn
#define itraffic_dcc_today     itraffic.today.partyline
#define itraffic_trans_today   itraffic.today.trans
#define itraffic_unknown_today itraffic.today.unknown
#define itraffic_filesys_today itraffic.today.filesys

#define itraffic_irc           itraffic.total.irc
#define itraffic_bn            itraffic.total.bn
#define itraffic_dcc           itraffic.total.partyline
#define itraffic_trans         itraffic.total.trans
#define itraffic_unknown       itraffic.total.unknown
#define itraffic_filesys       itraffic.total.filesys

#define otraffic_irc_today     otraffic.today.irc
#define otraffic_bn_today      otraffic.today.bn
#define otraffic_dcc_today     otraffic.today.partyline
#define otraffic_trans_today   otraffic.today.trans
#define otraffic_unknown_today otraffic.today.unknown
#define otraffic_filesys_today otraffic.today.filesys

#define otraffic_irc           otraffic.total.irc
#define otraffic_bn            otraffic.total.bn
#define otraffic_dcc           otraffic.total.partyline
#define otraffic_trans         otraffic.total.trans
#define otraffic_unknown       otraffic.total.unknown
#define otraffic_filesys       otraffic.total.filesys

static inline void egg_traffic_reset_today(struct egg_traffic *t)
{
  atomic_store_explicit(&t->today.irc,     0, memory_order_relaxed);
  atomic_store_explicit(&t->today.bn,      0, memory_order_relaxed);
  atomic_store_explicit(&t->today.partyline, 0, memory_order_relaxed);
  atomic_store_explicit(&t->today.trans,   0, memory_order_relaxed);
  atomic_store_explicit(&t->today.unknown, 0, memory_order_relaxed);
  atomic_store_explicit(&t->today.filesys, 0, memory_order_relaxed);
}

static inline void egg_traffic_accumulate(struct egg_traffic *t)
{
  atomic_fetch_add_explicit(&t->total.irc,     atomic_load_explicit(&t->today.irc,     memory_order_relaxed), memory_order_relaxed);
  atomic_fetch_add_explicit(&t->total.bn,      atomic_load_explicit(&t->today.bn,      memory_order_relaxed), memory_order_relaxed);
  atomic_fetch_add_explicit(&t->total.partyline, atomic_load_explicit(&t->today.partyline, memory_order_relaxed), memory_order_relaxed);
  atomic_fetch_add_explicit(&t->total.trans,   atomic_load_explicit(&t->today.trans,   memory_order_relaxed), memory_order_relaxed);
  atomic_fetch_add_explicit(&t->total.unknown, atomic_load_explicit(&t->today.unknown, memory_order_relaxed), memory_order_relaxed);
  atomic_fetch_add_explicit(&t->total.filesys, atomic_load_explicit(&t->today.filesys, memory_order_relaxed), memory_order_relaxed);
}

#endif /* _EGG_TRAFFIC_H */
