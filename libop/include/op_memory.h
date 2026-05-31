/*
 *  libop: ophion support library.
 *  op_memory.h: Memory allocation wrappers (always-succeeds: OOM calls op_outofmemory()).
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2005 ircd-ratbox development team
 *  Copyright (C) 2025-2026 ophion development team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
 *  USA
 *
 */

#ifndef LIBOP_LIB_H
#error "Do not include op_memory.h directly; include op_lib.h"
#endif

#ifndef LIBOP_MEMORY_H
#define LIBOP_MEMORY_H



OP_NORETURN void op_outofmemory(void);


#pragma GCC diagnostic push
#ifdef __GNUC__
#ifndef __clang__
#pragma GCC diagnostic ignored "-Wclobbered"
#endif
#endif
OP_NODISCARD OP_RETURNS_NONNULL static inline void *
op_calloc(size_t nmemb, size_t size)
{
	void *ret = calloc(nmemb, size);
	if (op_unlikely(ret == NULL))
		op_outofmemory();
	return (ret);
}

OP_NODISCARD OP_RETURNS_NONNULL static inline void *
op_malloc(size_t size)
{
	void *volatile ret = calloc(1, size);
	if (op_unlikely(ret == NULL))
		op_outofmemory();
	return (ret);
}

OP_NODISCARD OP_RETURNS_NONNULL static inline void *
op_realloc(void *x, size_t y)
{
	void *ret = realloc(x, y);

	if (op_unlikely(ret == NULL))
		op_outofmemory();
	return (ret);
}

OP_NODISCARD OP_RETURNS_NONNULL OP_NONNULL(1) static inline char *
op_strndup(const char *x, size_t y)
{
	char *ret = malloc(y);
	if (op_unlikely(ret == NULL))
		op_outofmemory();
	op_strlcpy(ret, x, y);
	return (ret);
}

OP_NODISCARD OP_RETURNS_NONNULL OP_NONNULL(1) static inline char *
op_strdup(const char *x)
{
	char *ret = malloc(strlen(x) + 1);
	if (op_unlikely(ret == NULL))
		op_outofmemory();
	memcpy(ret, x, strlen(x) + 1);
	return (ret);
}


static inline void
op_free(void *ptr)
{
	if (op_likely(ptr != NULL))
		free(ptr);
}

OP_NODISCARD OP_RETURNS_NONNULL
static inline void *
op_calloc_checked(size_t nmemb, size_t size)
{
	size_t total;
	if (op_ckd_mul(&total, nmemb, size))
		op_outofmemory();
	return op_calloc(1, total);
}
#pragma GCC diagnostic pop

/* -------------------------------------------------------------------------
 * Per-thread slab cache — low-latency allocation for small, short-lived
 * objects (16/32/64/128/256 byte size classes).  Each thread maintains a
 * lock-free magazine of recently-freed slabs; on miss/overflow, requests
 * fall through to a global mutex-protected freelist, and ultimately to
 * op_malloc().  Reduces malloc/free contention on hot paths (parser,
 * dlink_node, small string allocations).
 *
 * Constraints:
 *   - The same size value used at alloc time must be supplied at free time.
 *   - Allocations larger than OP_SLAB_MAX_SIZE (256) silently fall through
 *     to op_malloc/op_free; this is invisible to callers.
 *   - Memory is zeroed on return (calloc semantics) to match op_malloc.
 *   - Threads must call op_slab_thread_flush() before exit to return their
 *     magazine to the global pool.  The thread_pool already does this; bare
 *     pthread_create users must do it themselves.
 * ---------------------------------------------------------------------- */

#define OP_SLAB_MAX_SIZE 256

OP_NODISCARD OP_RETURNS_NONNULL void *op_slab_alloc(size_t size);
void                                  op_slab_free(void *ptr, size_t size);
void                                  op_slab_thread_flush(void);

/* -------------------------------------------------------------------------
 * NUMA-local allocation
 *
 * op_alloc_numa_local() returns memory bound to the given NUMA node (or to
 * the node of the calling thread when node_hint < 0).  When libnuma was not
 * available at build time, or NUMA is unavailable at runtime, this aliases
 * to op_calloc(1, size).  Memory must be freed with op_free_numa().
 * ---------------------------------------------------------------------- */

OP_NODISCARD OP_RETURNS_NONNULL void *op_alloc_numa_local(size_t size, int node_hint);
void                                  op_free_numa(void *ptr, size_t size);

/* -------------------------------------------------------------------------
 * op_memzero_explicit — constant-time, dead-store-resistant memory clear.
 * Use for clearing key material, plaintext after encrypt, and any other
 * data the optimiser must not be permitted to elide.  Prefer the C11/POSIX
 * memset_explicit / explicit_bzero when available; otherwise we fall back
 * to a memory-barrier-fenced memset that the optimiser cannot remove.
 * ---------------------------------------------------------------------- */

void op_memzero_explicit(void *ptr, size_t len);

#endif /* LIBOP_MEMORY_H */
