/*
 * async_dns.h — non-blocking DNS resolution via the op_async thread pool.
 *
 * Replaces the blocking core_dns_hostbyip() / core_dns_ipbyhost() fallbacks.
 * DNS work runs on a worker thread; results are delivered on the main thread
 * through the existing call_hostbyip() / call_ipbyhost() event system.
 *
 * Copyright (C) 2026 Eggheads Development Team
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _EGG_ASYNC_DNS_H
#define _EGG_ASYNC_DNS_H

#include "eggdrop.h"

void async_dns_hostbyip(sockname_t *addr);
void async_dns_ipbyhost(char *host);

/* Flush the DNS cache.  Called on rehash so stale mappings don't linger. */
void async_dns_cache_flush(void);

/* Return current cache entry count (IP→host and host→IP combined). */
int  async_dns_cache_size(void);

/* Fill hit/miss counters (all main-thread-only, cumulative since startup).
 * Any pointer may be NULL if that counter is not needed. */
void async_dns_cache_stats(uint64_t *hip_hits_out,   uint64_t *hip_misses_out,
                            uint64_t *ibh_hits_out,   uint64_t *ibh_misses_out);

#endif /* _EGG_ASYNC_DNS_H */
