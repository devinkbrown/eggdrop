/*
 * libop/src/shm_ring.c — SPSC shared-memory lock-free ring buffer.
 *
 * See libop/include/op_shm_ring.h for the design, wire format and
 * cross-process ordering contract.
 *
 * Copyright (C) 2026 ophion development team
 * Licence: same as libop (GPL-2+).
 */

#include <libop_config.h>
#include <op_lib.h>
#include <op_shm_ring.h>

#include <string.h>
#include <op_atomic.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef _WIN32
# include <sys/stat.h>
#endif

/* Compile-time invariants — guarantee a slot is exactly one page (4096 B)
 * and that the header layout matches what the wire-format contract promises.
 * If any of these fire, both producer and consumer must be rebuilt; mixing
 * old and new mappings would silently corrupt memory. */
_Static_assert(sizeof(struct op_shm_slot) == 4096,
               "op_shm_slot must be exactly one page (4096 B)");
_Static_assert(OP_SHM_SLOT_PAYLOAD <= UINT32_MAX,
               "OP_SHM_SLOT_PAYLOAD must fit in uint32_t");

/* ── memfd / shm_open backend ─────────────────────────────────────────── */

#if defined(__linux__) && defined(__NR_memfd_create)
# include <sys/syscall.h>
# ifndef MFD_CLOEXEC
#  define MFD_CLOEXEC 1U
# endif
static int
_shm_fd_create(size_t sz)
{
	int fd = (int)syscall(__NR_memfd_create, "op_shm_ring",
	                      (unsigned int)MFD_CLOEXEC);
	if (fd < 0)
		return -1;
	if (ftruncate(fd, (off_t)sz) < 0)
	{
		int saved = errno;
		close(fd);
		errno = saved;
		return -1;
	}
	return fd;
}
#elif !defined(_WIN32)
/* POSIX shm_open fallback (macOS, BSDs, older Linux). */
# include <sys/mman.h>
static int
_shm_fd_create(size_t sz)
{
	/* Retry with a random suffix so two siblings of the same pid (after
	 * exec-loops or container PID reuse) cannot collide on O_EXCL. */
	for (int attempt = 0; attempt < 16; attempt++)
	{
		char    name[64];
		unsigned r = (unsigned)random();
		snprintf(name, sizeof(name), "/op_shm_%d_%08x",
		         (int)getpid(), r);
		int fd = shm_open(name, O_CREAT | O_RDWR | O_EXCL, 0600);
		if (fd < 0)
		{
			if (errno == EEXIST)
				continue;
			return -1;
		}
		/* Unlink immediately: the fd keeps the segment alive and no
		 * other process can re-open by name. */
		(void)shm_unlink(name);
		if (ftruncate(fd, (off_t)sz) < 0)
		{
			int saved = errno;
			close(fd);
			errno = saved;
			return -1;
		}
		/* shm_open does NOT set CLOEXEC; set it explicitly so the
		 * parent controls inheritance. */
		if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
		{
			int saved = errno;
			close(fd);
			errno = saved;
			return -1;
		}
		return fd;
	}
	errno = EEXIST;
	return -1;
}
#else  /* Windows — not yet implemented */
static int
_shm_fd_create(size_t sz)
{
	(void)sz;
	errno = ENOSYS;
	return -1;
}
#endif

/* True iff `n` is a non-zero power of two. */
static inline bool
_is_pow2(uint32_t n)
{
	return n != 0 && (n & (n - 1)) == 0;
}

/* ── public API ─────────────────────────────────────────────────────────── */

size_t
op_shm_ring_map_size(uint32_t slot_count)
{
	return sizeof(op_shm_ring_t)
	       + (size_t)slot_count * sizeof(struct op_shm_slot);
}

int
op_shm_ring_create(uint32_t slot_count)
{
	if (!_is_pow2(slot_count))
	{
		errno = EINVAL;
		return -1;
	}
	return _shm_fd_create(op_shm_ring_map_size(slot_count));
}

op_shm_ring_t *
op_shm_ring_map(int fd, uint32_t slot_count, bool init)
{
	if (!_is_pow2(slot_count))
	{
		errno = EINVAL;
		return NULL;
	}
#ifdef _WIN32
	(void)fd; (void)init;
	errno = ENOSYS;
	return NULL;
#else
	size_t sz = op_shm_ring_map_size(slot_count);
	void *p = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED)
		return NULL;

	op_shm_ring_t *ring = (op_shm_ring_t *)p;
	if (init)
	{
		memset(ring, 0, sz);
		ring->hdr.magic      = OP_SHM_RING_MAGIC;
		ring->hdr.slot_count = slot_count;
		/* These are the very first stores; relaxed is sufficient because
		 * the child process has not yet been forked/execed and there is
		 * no other observer.  The exec/fork synchronisation (fork barrier
		 * or environment-variable setup followed by execve) provides the
		 * happens-before edge that publishes these to the child. */
		atomic_store_explicit(&ring->hdr.prod_pos, 0,
		                      memory_order_relaxed);
		atomic_store_explicit(&ring->hdr.cons_pos, 0,
		                      memory_order_relaxed);
	}
	else
	{
		/* Sanity-check the mapping the peer handed us.  A mismatched
		 * magic or slot_count indicates an ABI break or a hostile fd;
		 * either way we must refuse the mapping rather than silently
		 * corrupt the ring. */
		if (ring->hdr.magic != OP_SHM_RING_MAGIC
		    || ring->hdr.slot_count != slot_count)
		{
			munmap(p, sz);
			errno = EPROTO;
			return NULL;
		}
	}
	return ring;
#endif
}

void
op_shm_ring_unmap(op_shm_ring_t *ring, uint32_t slot_count)
{
#ifndef _WIN32
	if (ring != NULL)
		munmap(ring, op_shm_ring_map_size(slot_count));
#else
	(void)ring; (void)slot_count;
#endif
}

bool
op_shm_ring_readable(const op_shm_ring_t *ring)
{
	/* Producer publishes prod_pos with release after writing slot->len;
	 * acquiring prod_pos here gives us happens-before on slot writes. */
	uint64_t prod = atomic_load_explicit(&ring->hdr.prod_pos,
	                                     memory_order_acquire);
	/* The consumer owns cons_pos, so a relaxed load is safe when called
	 * by the consumer.  When called by another thread of the consumer
	 * process, the caller is expected to provide its own ordering. */
	uint64_t cons = atomic_load_explicit(&ring->hdr.cons_pos,
	                                     memory_order_relaxed);
	if (prod == cons)
		return false;
	/* Producer may have bumped prod_pos before the slot's len store
	 * becomes visible (extremely tight window).  Confirm via len. */
	const struct op_shm_slot *slot =
		&ring->slots[cons & (ring->hdr.slot_count - 1)];
	return atomic_load_explicit(&slot->len, memory_order_acquire) != 0;
}

int
op_shm_ring_push(op_shm_ring_t *ring, uint64_t conn_id,
                 const void *buf, uint32_t len)
{
	if (len == 0)
		return 0;
	if (buf == NULL)
	{
		errno = EINVAL;
		return -1;
	}

	const uint8_t *src      = (const uint8_t *)buf;
	uint32_t       capacity = ring->hdr.slot_count;

	/* Number of slots this message will occupy. */
	uint32_t slots_needed = (len + OP_SHM_SLOT_PAYLOAD - 1)
	                        / OP_SHM_SLOT_PAYLOAD;
	if (slots_needed > capacity)
	{
		/* Message larger than the entire ring would deadlock against
		 * itself; the caller must fragment at a higher layer. */
		errno = EMSGSIZE;
		return -1;
	}

	uint64_t prod = atomic_load_explicit(&ring->hdr.prod_pos,
	                                     memory_order_relaxed);
	uint64_t cons = atomic_load_explicit(&ring->hdr.cons_pos,
	                                     memory_order_acquire);

	/* Reserve the full chain up-front.  Without this, a partial publish
	 * during a multi-slot push would leave the consumer reading a chain
	 * that begins with FLAG_FIRST but never receives its FLAG_MORE
	 * continuation — a torn message. */
	if ((uint64_t)(prod - cons) + slots_needed > capacity)
		return -1;  /* ring full */

	uint32_t remaining = len;
	bool     first     = true;

	while (remaining > 0)
	{
		struct op_shm_slot *slot = &ring->slots[prod & (capacity - 1)];

		/* SPSC invariant: if we passed the capacity check above, the
		 * consumer must have already cleared this slot's len.  Assert
		 * defensively — a stale len here means a second producer is
		 * scribbling on our ring, which we cannot recover from. */
		if (atomic_load_explicit(&slot->len, memory_order_acquire) != 0)
		{
			errno = EBUSY;
			return -1;
		}

		uint32_t chunk = (remaining < OP_SHM_SLOT_PAYLOAD)
		                 ? remaining : (uint32_t)OP_SHM_SLOT_PAYLOAD;

		uint16_t flags = 0;
		if (first)             flags |= OP_SHM_FLAG_FIRST;
		if (chunk < remaining) flags |= OP_SHM_FLAG_MORE;

		slot->conn_id = conn_id;
		slot->flags   = flags;
		memcpy(slot->data, src, chunk);

		/* Publish: store length LAST with release.  Once the consumer
		 * observes len != 0 via an acquire load, all of the preceding
		 * writes (conn_id, flags, data) are guaranteed to be visible. */
		atomic_store_explicit(&slot->len, chunk, memory_order_release);

		/* Advance producer sequence — release pairs with the consumer's
		 * acquire load of prod_pos. */
		atomic_store_explicit(&ring->hdr.prod_pos, prod + 1,
		                      memory_order_release);

		src       += chunk;
		remaining -= chunk;
		prod++;
		first = false;
	}
	return 0;
}

int
op_shm_ring_pop(op_shm_ring_t *ring, uint64_t *conn_id_out,
                void *out_buf, uint16_t *flags_out)
{
	if (conn_id_out == NULL || out_buf == NULL || flags_out == NULL)
	{
		errno = EINVAL;
		return -1;
	}

	/* Consumer owns cons_pos; relaxed load is safe. */
	uint64_t cons     = atomic_load_explicit(&ring->hdr.cons_pos,
	                                         memory_order_relaxed);
	/* Acquire pairs with producer's release on prod_pos. */
	uint64_t prod     = atomic_load_explicit(&ring->hdr.prod_pos,
	                                         memory_order_acquire);
	uint32_t capacity = ring->hdr.slot_count;

	if (cons == prod)
		return 0;  /* empty */

	struct op_shm_slot *slot = &ring->slots[cons & (capacity - 1)];

	/* Acquire on len pairs with producer's release-store of the chunk
	 * length, giving us happens-before on conn_id / flags / data. */
	uint32_t plen = atomic_load_explicit(&slot->len, memory_order_acquire);
	if (plen == 0)
		return 0;  /* prod_pos bumped but len not yet visible — retry */

	/* Defence in depth: cap plen against the slot payload.  A corrupted
	 * producer (or one built against a mismatched header) cannot trick
	 * us into overrunning out_buf, which the API contract requires to be
	 * at least OP_SHM_SLOT_PAYLOAD bytes. */
	if (plen > OP_SHM_SLOT_PAYLOAD)
		plen = OP_SHM_SLOT_PAYLOAD;

	*conn_id_out = slot->conn_id;
	*flags_out   = slot->flags;
	memcpy(out_buf, slot->data, plen);

	/* Release the slot back to the producer.  The release store on len
	 * publishes the consumer's reads (so the producer's next push into
	 * this slot is correctly ordered after we are done with it). */
	atomic_store_explicit(&slot->len, 0, memory_order_release);
	atomic_store_explicit(&ring->hdr.cons_pos, cons + 1,
	                      memory_order_release);

	return (int)plen;
}
