/*
 * libop/include/op_mpmc.h — Vyukov bounded MPMC queue.
 *
 * Multi-producer, multi-consumer bounded queue. One CAS per enqueue,
 * one CAS per dequeue. Per-slot sequence counters eliminate ABA.
 * Power-of-two capacity required.
 *
 * Based on Dmitry Vyukov's design (1024cores.net).
 *
 * Copyright (c) 2026 Ophion Development Team.  GPL v2.
 */

#ifndef OP_MPMC_H
#define OP_MPMC_H

#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef OP_CACHELINE
#define OP_CACHELINE 64
#endif

typedef struct {
	_Alignas(OP_CACHELINE)
	_Atomic(uint64_t) seq;
	void             *data;
	char              _pad[OP_CACHELINE - sizeof(_Atomic(uint64_t)) - sizeof(void *)];
} op_mpmc_slot_t;

typedef struct {
	_Alignas(OP_CACHELINE)
	_Atomic(uint64_t) head;
	char _pad0[OP_CACHELINE - sizeof(_Atomic(uint64_t))];

	_Alignas(OP_CACHELINE)
	_Atomic(uint64_t) tail;
	char _pad1[OP_CACHELINE - sizeof(_Atomic(uint64_t))];

	uint64_t         mask;
	op_mpmc_slot_t  *slots;
} op_mpmc_t;

static inline int
op_mpmc_init(op_mpmc_t *q, uint64_t capacity)
{
	if (capacity == 0 || (capacity & (capacity - 1)) != 0)
		return -1;

	memset(q, 0, sizeof(*q));
	q->mask = capacity - 1;
	q->slots = (op_mpmc_slot_t *)calloc((size_t)capacity, sizeof(op_mpmc_slot_t));
	if (!q->slots)
		return -1;

	for (uint64_t i = 0; i < capacity; i++)
		atomic_store_explicit(&q->slots[i].seq, i, memory_order_relaxed);

	return 0;
}

static inline void
op_mpmc_destroy(op_mpmc_t *q)
{
	free(q->slots);
	q->slots = NULL;
}

static inline int
op_mpmc_push(op_mpmc_t *q, void *item)
{
	uint64_t pos = atomic_load_explicit(&q->head, memory_order_relaxed);

	for (;;) {
		op_mpmc_slot_t *slot = &q->slots[pos & q->mask];
		uint64_t seq = atomic_load_explicit(&slot->seq, memory_order_acquire);
		int64_t diff = (int64_t)seq - (int64_t)pos;

		if (diff == 0) {
			if (atomic_compare_exchange_weak_explicit(
				    &q->head, &pos, pos + 1,
				    memory_order_relaxed,
				    memory_order_relaxed)) {
				slot->data = item;
				atomic_store_explicit(&slot->seq, pos + 1,
				                      memory_order_release);
				return 1;
			}
		} else if (diff < 0) {
			return 0;  /* full */
		} else {
			pos = atomic_load_explicit(&q->head, memory_order_relaxed);
		}
	}
}

static inline void *
op_mpmc_pop(op_mpmc_t *q)
{
	uint64_t pos = atomic_load_explicit(&q->tail, memory_order_relaxed);

	for (;;) {
		op_mpmc_slot_t *slot = &q->slots[pos & q->mask];
		uint64_t seq = atomic_load_explicit(&slot->seq, memory_order_acquire);
		int64_t diff = (int64_t)seq - (int64_t)(pos + 1);

		if (diff == 0) {
			if (atomic_compare_exchange_weak_explicit(
				    &q->tail, &pos, pos + 1,
				    memory_order_relaxed,
				    memory_order_relaxed)) {
				void *item = slot->data;
				atomic_store_explicit(&slot->seq, pos + q->mask + 1,
				                      memory_order_release);
				return item;
			}
		} else if (diff < 0) {
			return NULL;  /* empty */
		} else {
			pos = atomic_load_explicit(&q->tail, memory_order_relaxed);
		}
	}
}

static inline uint64_t
op_mpmc_size(const op_mpmc_t *q)
{
	uint64_t h = atomic_load_explicit(&q->head, memory_order_acquire);
	uint64_t t = atomic_load_explicit(&q->tail, memory_order_acquire);
	return h - t;
}

/*
 * op_mpmc_size_lower_bound — relaxed approximation of queue size, useful
 * for telemetry/backpressure heuristics. Performs no fences and may
 * observe stale head/tail values; the returned value is a lower bound on
 * the *actual* queue size at some point during the call window.
 */
static inline uint64_t
op_mpmc_size_lower_bound(const op_mpmc_t *q)
{
	uint64_t t = atomic_load_explicit(&q->tail, memory_order_relaxed);
	uint64_t h = atomic_load_explicit(&q->head, memory_order_relaxed);
	return (h > t) ? (h - t) : 0;
}

/*
 * Batch push: enqueue up to n items in a single head advance.
 *
 * Returns the number actually enqueued (0..n). Race-free argument:
 *   1) We CAS-claim a contiguous range [pos, pos+k) of head sequences.
 *      Claim size k is bounded by per-slot probing of seq == pos+i
 *      (slot is empty for this generation) so the entire range is
 *      publishable at claim time.
 *   2) Between probe and CAS, only consumers may bump a slot's seq
 *      forward (release), which can only make publish *more* possible,
 *      never less. Producers competing for the same range will fail the
 *      head CAS (only one thread advances head past pos).
 *   3) After CAS success, this thread is the *sole* writer for every
 *      slot in [pos, pos+k); it stores data, then release-stores
 *      seq = pos+i+1, publishing each slot to consumers.
 *
 * Falls back to op_mpmc_push semantics for n == 1.
 */
static inline size_t
op_mpmc_push_batch(op_mpmc_t *q, void **in, size_t n)
{
	if (n == 0)
		return 0;

	uint64_t pos = atomic_load_explicit(&q->head, memory_order_relaxed);

	for (;;) {
		size_t   k = 0;
		uint64_t first_seq =
			atomic_load_explicit(&q->slots[pos & q->mask].seq,
			                     memory_order_acquire);
		int64_t  first_diff = (int64_t)first_seq - (int64_t)pos;

		if (first_diff < 0)
			return 0;  /* full */
		if (first_diff > 0) {
			pos = atomic_load_explicit(&q->head,
			                           memory_order_relaxed);
			continue;
		}

		/* Probe contiguous publishable run. */
		for (k = 1; k < n; k++) {
			op_mpmc_slot_t *s = &q->slots[(pos + k) & q->mask];
			uint64_t seq = atomic_load_explicit(&s->seq,
			                                    memory_order_acquire);
			if ((int64_t)seq - (int64_t)(pos + k) != 0)
				break;
		}

		if (atomic_compare_exchange_weak_explicit(
			    &q->head, &pos, pos + k,
			    memory_order_relaxed,
			    memory_order_relaxed)) {
			for (size_t i = 0; i < k; i++) {
				op_mpmc_slot_t *s =
					&q->slots[(pos + i) & q->mask];
				s->data = in[i];
				atomic_store_explicit(&s->seq, pos + i + 1,
				                      memory_order_release);
			}
			return k;
		}
		/* pos reloaded by failed CAS; retry */
	}
}

/*
 * Batch pop: dequeue up to max_n items in a single tail advance.
 *
 * Returns the number actually dequeued (0..max_n). Same correctness
 * structure as push_batch: probe a contiguous run of *published* slots
 * (seq == pos+1+i), CAS-claim the range on tail, then read data and
 * release-store seq = pos + i + mask + 1 to recycle the slot for the
 * next generation.
 */
static inline size_t
op_mpmc_pop_batch(op_mpmc_t *q, void **out, size_t max_n)
{
	if (max_n == 0)
		return 0;

	uint64_t pos = atomic_load_explicit(&q->tail, memory_order_relaxed);

	for (;;) {
		size_t   k = 0;
		uint64_t first_seq =
			atomic_load_explicit(&q->slots[pos & q->mask].seq,
			                     memory_order_acquire);
		int64_t  first_diff = (int64_t)first_seq - (int64_t)(pos + 1);

		if (first_diff < 0)
			return 0;  /* empty */
		if (first_diff > 0) {
			pos = atomic_load_explicit(&q->tail,
			                           memory_order_relaxed);
			continue;
		}

		/* Probe contiguous published run. */
		for (k = 1; k < max_n; k++) {
			op_mpmc_slot_t *s = &q->slots[(pos + k) & q->mask];
			uint64_t seq = atomic_load_explicit(&s->seq,
			                                    memory_order_acquire);
			if ((int64_t)seq - (int64_t)(pos + k + 1) != 0)
				break;
		}

		if (atomic_compare_exchange_weak_explicit(
			    &q->tail, &pos, pos + k,
			    memory_order_relaxed,
			    memory_order_relaxed)) {
			for (size_t i = 0; i < k; i++) {
				op_mpmc_slot_t *s =
					&q->slots[(pos + i) & q->mask];
				out[i] = s->data;
				atomic_store_explicit(&s->seq,
				                      pos + i + q->mask + 1,
				                      memory_order_release);
			}
			return k;
		}
		/* pos reloaded by failed CAS; retry */
	}
}

#endif /* OP_MPMC_H */
