/*
 *  Ophion IRC Daemon
 *  libop/src/op_memory_ext.c: Per-thread slab cache, NUMA-local allocation,
 *  and constant-time memzero.
 *
 *  Copyright (C) 2024-2026 Ophion IRC Daemon contributors
 *
 *  Licensed under the GNU General Public License v2 or any later version.
 *  See COPYING in the source distribution for full terms.
 */

#include <libop_config.h>
#include <op_lib.h>

#include <pthread.h>
#include <stdatomic.h>
#include <string.h>

#if defined(HAVE_LIBNUMA)
#  include <numa.h>
#  include <sched.h>           /* sched_getcpu — Linux-only */
#endif

/* -------------------------------------------------------------------------
 * Per-thread slab cache
 * ----------------------------------------------------------------------
 *
 * Size classes are powers of two from 16 to 256 bytes inclusive.
 * Every block returned to the cache is treated as an intrusive freelist
 * cell whose first sizeof(void *) bytes hold the next pointer.  Because
 * the smallest class is 16 bytes and sizeof(void *) <= 8 on every
 * supported platform, that always fits.
 *
 * All blocks are aligned to OP_SLAB_ALIGN so callers can safely place
 * structs of any standard type inside them.
 */

#define OP_SLAB_NCLASSES        5
#define OP_SLAB_MAGAZINE_DEPTH  32      /* per-class, per-thread cap */
#define OP_SLAB_REFILL_BATCH    8       /* moved between global and tl */
#define OP_SLAB_ALIGN           16      /* matches max_align_t on common ABIs */

/* Compile-time size of each class.  Index 0 = 16, 1 = 32, ... 4 = 256. */
static const size_t op_slab_sizes[OP_SLAB_NCLASSES] = { 16, 32, 64, 128, 256 };

/*
 * Map a request size to a class index.  Returns -1 for sizes that exceed
 * OP_SLAB_MAX_SIZE; the caller falls through to op_malloc() in that case.
 *
 * Branchless on most compilers — five comparisons and a saturating select.
 */
static inline int
op_slab_class_index(size_t size)
{
	if (size <= 16)  return 0;
	if (size <= 32)  return 1;
	if (size <= 64)  return 2;
	if (size <= 128) return 3;
	if (size <= 256) return 4;
	return -1;
}

struct op_slab_cell {
	struct op_slab_cell *next;
};

/* ------------------------------------------------------------------- */
/* Global pool — last-resort backing store for every thread.            */
/* ------------------------------------------------------------------- */

struct op_slab_global {
	pthread_mutex_t        lock;
	struct op_slab_cell   *head;
	size_t                 count;
};

static struct op_slab_global op_slab_global[OP_SLAB_NCLASSES] = {
	{ PTHREAD_MUTEX_INITIALIZER, NULL, 0 },
	{ PTHREAD_MUTEX_INITIALIZER, NULL, 0 },
	{ PTHREAD_MUTEX_INITIALIZER, NULL, 0 },
	{ PTHREAD_MUTEX_INITIALIZER, NULL, 0 },
	{ PTHREAD_MUTEX_INITIALIZER, NULL, 0 },
};

/* ------------------------------------------------------------------- */
/* Per-thread magazine.                                                 */
/* ------------------------------------------------------------------- */

struct op_slab_magazine {
	struct op_slab_cell *head;
	size_t               count;
};

static _Thread_local struct op_slab_magazine op_slab_tl[OP_SLAB_NCLASSES];
static _Thread_local bool                    op_slab_tl_registered;

/* TLS destructor key — installed lazily; flushes magazine on thread exit. */
static pthread_key_t  op_slab_tl_key;
static pthread_once_t op_slab_tl_key_once = PTHREAD_ONCE_INIT;

static void op_slab_tl_destructor(void *unused);

static void
op_slab_tl_key_init(void)
{
	/*
	 * pthread_key_create can fail only on EAGAIN (out of keys) or ENOMEM.
	 * Both are fatal; we cannot run without the per-thread flush hook
	 * because magazines would leak on thread exit.
	 */
	if (pthread_key_create(&op_slab_tl_key, op_slab_tl_destructor) != 0)
		op_outofmemory();
}

/*
 * Move count cells from src to global pool.  Caller owns no lock.
 * The src list head is updated to point past the donated cells.
 */
static void
op_slab_push_global(int cls, struct op_slab_cell *list, size_t n)
{
	if (n == 0 || list == NULL)
		return;

	struct op_slab_cell *tail = list;
	for (size_t i = 1; i < n; i++)
		tail = tail->next;

	pthread_mutex_lock(&op_slab_global[cls].lock);
	tail->next = op_slab_global[cls].head;
	op_slab_global[cls].head = list;
	op_slab_global[cls].count += n;
	pthread_mutex_unlock(&op_slab_global[cls].lock);
}

/*
 * Pull up to want cells off the global pool.  Returns the list head and
 * writes the actual count to *got.  May return NULL with *got == 0 when
 * the global pool is empty; the caller then mallocs fresh memory.
 */
static struct op_slab_cell *
op_slab_pop_global(int cls, size_t want, size_t *got)
{
	struct op_slab_cell *head = NULL;
	size_t              taken = 0;

	pthread_mutex_lock(&op_slab_global[cls].lock);
	head = op_slab_global[cls].head;
	if (head != NULL) {
		struct op_slab_cell *tail = head;
		taken = 1;
		while (taken < want && tail->next != NULL) {
			tail = tail->next;
			taken++;
		}
		op_slab_global[cls].head = tail->next;
		op_slab_global[cls].count -= taken;
		tail->next = NULL;
	}
	pthread_mutex_unlock(&op_slab_global[cls].lock);

	*got = taken;
	return head;
}

/*
 * Flush this thread's magazine for one class to the global pool.
 */
static void
op_slab_flush_class(int cls)
{
	struct op_slab_magazine *mag = &op_slab_tl[cls];
	if (mag->head == NULL)
		return;
	op_slab_push_global(cls, mag->head, mag->count);
	mag->head = NULL;
	mag->count = 0;
}

static void
op_slab_tl_destructor(void *unused)
{
	(void) unused;
	op_slab_thread_flush();
}

static void
op_slab_tl_register(void)
{
	pthread_once(&op_slab_tl_key_once, op_slab_tl_key_init);
	/*
	 * Set a non-NULL TLS value so glibc will invoke the destructor on
	 * thread exit.  The actual pointer value is unused.
	 */
	(void) pthread_setspecific(op_slab_tl_key, (void *) (uintptr_t) 1);
	op_slab_tl_registered = true;
}

/*
 * Public: take one block.  Always returns a zeroed buffer of at least
 * op_slab_sizes[class] bytes.  Falls through to op_malloc for oversized
 * requests so callers do not need to special-case big allocations.
 */
void *
op_slab_alloc(size_t size)
{
	int cls = op_slab_class_index(size);
	if (cls < 0)
		return op_malloc(size);

	if (op_unlikely(!op_slab_tl_registered))
		op_slab_tl_register();

	struct op_slab_magazine *mag = &op_slab_tl[cls];
	struct op_slab_cell     *cell = mag->head;

	if (cell == NULL) {
		size_t got = 0;
		cell = op_slab_pop_global(cls, OP_SLAB_REFILL_BATCH, &got);
		if (cell != NULL) {
			mag->head  = cell->next;
			mag->count = got - 1;
		} else {
			/*
			 * Global empty — allocate one fresh block.  We do not
			 * pre-fill the magazine here; pure-alloc workloads
			 * never benefit from prefetching unused blocks.
			 *
			 * aligned_alloc requires size to be a multiple of the
			 * alignment; all our class sizes already are.
			 */
			void *raw = aligned_alloc(OP_SLAB_ALIGN, op_slab_sizes[cls]);
			if (op_unlikely(raw == NULL))
				op_outofmemory();
			memset(raw, 0, op_slab_sizes[cls]);
			return raw;
		}
	} else {
		mag->head = cell->next;
		mag->count--;
	}

	memset(cell, 0, op_slab_sizes[cls]);
	return cell;
}

/*
 * Public: return a block.  Size must match the original allocation request
 * (or any size that maps to the same class).  Oversized blocks were
 * malloc'd directly and are passed back to free().
 */
void
op_slab_free(void *ptr, size_t size)
{
	if (ptr == NULL)
		return;

	int cls = op_slab_class_index(size);
	if (cls < 0) {
		free(ptr);
		return;
	}

	if (op_unlikely(!op_slab_tl_registered))
		op_slab_tl_register();

	struct op_slab_magazine *mag = &op_slab_tl[cls];

	/*
	 * Magazine full?  Donate half of it to the global pool to keep the
	 * tl cache hot without unbounded growth.
	 */
	if (mag->count >= OP_SLAB_MAGAZINE_DEPTH) {
		size_t              donate = OP_SLAB_MAGAZINE_DEPTH / 2;
		struct op_slab_cell *cut = mag->head;
		for (size_t i = 1; i < donate; i++)
			cut = cut->next;
		struct op_slab_cell *donated = cut->next;
		cut->next = NULL;
		op_slab_push_global(cls, donated, mag->count - donate);
		mag->count = donate;
	}

	struct op_slab_cell *cell = (struct op_slab_cell *) ptr;
	cell->next = mag->head;
	mag->head  = cell;
	mag->count++;
}

void
op_slab_thread_flush(void)
{
	for (int i = 0; i < OP_SLAB_NCLASSES; i++)
		op_slab_flush_class(i);
}

/* -------------------------------------------------------------------------
 * NUMA-local allocation
 * ---------------------------------------------------------------------- */

void *
op_alloc_numa_local(size_t size, int node_hint)
{
#if defined(HAVE_LIBNUMA)
	if (size == 0)
		size = 1;

	/*
	 * numa_available() returns -1 when the kernel lacks NUMA support
	 * (eg single-socket virtual machine).  Skip the libnuma path in
	 * that case and let the kernel pick the page.
	 */
	if (numa_available() < 0)
		return op_calloc(1, size);

	int node = (node_hint < 0) ? numa_node_of_cpu(sched_getcpu()) : node_hint;
	if (node < 0)
		return op_calloc(1, size);

	void *ptr = numa_alloc_onnode(size, node);
	if (op_unlikely(ptr == NULL))
		op_outofmemory();
	memset(ptr, 0, size);
	return ptr;
#else
	(void) node_hint;
	return op_calloc(1, size);
#endif
}

void
op_free_numa(void *ptr, size_t size)
{
	if (ptr == NULL)
		return;
#if defined(HAVE_LIBNUMA)
	if (numa_available() >= 0) {
		numa_free(ptr, size == 0 ? 1 : size);
		return;
	}
#else
	(void) size;
#endif
	free(ptr);
}

/* -------------------------------------------------------------------------
 * op_memzero_explicit — secure memory wipe
 *
 * The C compiler is allowed to elide stores to memory that is provably
 * dead.  For cryptographic key material we MUST defeat that optimisation.
 * We prefer platform primitives where available, and otherwise emit a
 * full memory clobber barrier after the memset so the optimiser cannot
 * see that the stored bytes are unused.
 * ---------------------------------------------------------------------- */

void
op_memzero_explicit(void *ptr, size_t len)
{
	if (ptr == NULL || len == 0)
		return;

#if defined(__STDC_LIB_EXT1__) && defined(__STDC_WANT_LIB_EXT1__)
	memset_s(ptr, len, 0, len);
#elif defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
      (defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25)))
	explicit_bzero(ptr, len);
#elif defined(_WIN32)
	SecureZeroMemory(ptr, len);
#else
	/*
	 * Portable fallback: memset followed by an inline-assembly memory
	 * clobber.  The clobber forces the compiler to treat every byte of
	 * memory as potentially observed by external code, which prevents
	 * dead-store elimination.  This is the same trick used by libsodium's
	 * sodium_memzero() on platforms without explicit_bzero.
	 */
	volatile unsigned char *p = (volatile unsigned char *) ptr;
	while (len--)
		*p++ = 0;
#  if defined(__GNUC__) || defined(__clang__)
	__asm__ __volatile__("" : : "r"(ptr) : "memory");
#  endif
#endif
}
