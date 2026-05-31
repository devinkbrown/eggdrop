/*
 * libop/include/op_shm_ring.h — SPSC shared-memory lock-free ring buffer.
 *
 * Zero-copy inter-process IPC: producer (ssld) writes directly into shared
 * memory; consumer (ircd) reads from the same mapping.  No kernel copy.
 *
 * Design (SPSC — Single Producer, Single Consumer):
 *
 *   • Each slot carries a fixed-size payload plus a conn_id tag so a single
 *     ring serves all connections of one ssld instance.
 *   • Synchronisation is via a single _Atomic(uint32_t) len field per slot:
 *       Producer: writes conn_id/flags/data, then
 *                 atomic_store_explicit(&slot->len, n, memory_order_release)
 *                 atomic_store_explicit(&hdr->prod_pos, p+1, release)
 *       Consumer: atomic_load_explicit(&hdr->prod_pos, acquire)
 *                 atomic_load_explicit(&slot->len, acquire) != 0 → data ready
 *                 reads data, then atomic_store(slot->len, 0, release)
 *                 atomic_store(&hdr->cons_pos, c+1, release)
 *   • prod_pos / cons_pos in the header are also atomic so each side can
 *     detect full / empty without spinning on every slot.
 *   • Cache-line padding (64 B) on prod_pos and cons_pos prevents false
 *     sharing between the two processes.
 *
 * Cross-process ordering contract:
 *   The release/acquire chain on slot->len is what makes this safe across
 *   processes that share a MAP_SHARED mapping.  C11 atomics with memory_order
 *   release/acquire emit the same CPU fences regardless of whether the peer
 *   is another thread or another process — the synchronisation is a property
 *   of the memory operation, not the address-space.  As long as both peers
 *   are built against the same op_shm_slot layout (enforced by a static
 *   assertion in shm_ring.c) and the same atomic ABI, the producer's writes
 *   are guaranteed visible to the consumer once it has observed len != 0.
 *
 * Wire format:
 *   The mapping begins with op_shm_ring_hdr (192 B = three 64-B cache
 *   lines) followed by slot_count * op_shm_slot (4096 B each).
 *   slot_count MUST be a power of two so masking can replace modulo.
 *   prod_pos / cons_pos are unbounded 64-bit sequence numbers; the slot
 *   index is `pos & (slot_count - 1)`.  Sequence wrap at 2^64 is treated
 *   as impossible (it would take centuries at line rate).
 *
 * Multi-slot messages and torn-write safety:
 *   Messages larger than OP_SHM_SLOT_PAYLOAD are split across consecutive
 *   slots with the FLAG_MORE chain.  op_shm_ring_push() reserves the whole
 *   chain up-front via the (prod - cons + needed > capacity) check, so the
 *   ring either accepts the entire message or none of it.  This guarantees
 *   the consumer never sees a FIRST slot without its trailing continuations.
 *
 * Crash safety:
 *   The protocol is SPSC.  If the producer dies mid-write (before the
 *   release-store of slot->len), the slot stays len == 0 and the consumer
 *   simply blocks on an empty ring — it never reads partial data.  Detection
 *   of producer death is therefore an out-of-band concern (e.g. SIGCHLD or
 *   socketpair EOF in ircd's case), not the ring's responsibility.
 *   If the consumer dies, the producer eventually sees the ring fill and
 *   gets -1 from push(); again, out-of-band death detection is the caller's
 *   job.
 *
 * Bootstrap (Linux):
 *   Parent (ircd): fd = op_shm_ring_create(256);  ring = op_shm_ring_map(fd,256,true);
 *   Before exec:   clear FD_CLOEXEC on fd; set env SHM_DATA_FD=<fd>
 *   Child (ssld):  fd = atoi(getenv("SHM_DATA_FD")); ring = op_shm_ring_map(fd,256,false);
 *
 * Copyright (C) 2026 ophion development team
 * Licence: same as libop (GPL-2+).
 */
#ifndef LIBOP_LIB_H
# error "Do not include op_shm_ring.h directly; include op_lib.h"
#endif

#ifndef OP_SHM_RING_H
#define OP_SHM_RING_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <op_atomic.h>

/* ── Constants ─────────────────────────────────────────────────────────── */

#define OP_SHM_RING_MAGIC    UINT32_C(0x4F505352)  /* "OPSR" */

/*
 * Payload bytes per slot.  4080 + 16 bytes of header = 4096 (one page).
 * Large enough for any IRC message including IRCv3 message tags (≤ 8191 B)
 * split across consecutive slots via OP_SHM_FLAG_MORE chaining.
 */
#define OP_SHM_SLOT_PAYLOAD  4080

/* Default ring depth — power-of-2, fits in one huge-page boundary (2 MB). */
#define OP_SHM_DEFAULT_SLOTS 512

/* Flags embedded in op_shm_slot.flags */
#define OP_SHM_FLAG_FIRST  UINT16_C(0x0001)  /* first (or only) chunk     */
#define OP_SHM_FLAG_MORE   UINT16_C(0x0002)  /* more chunks follow        */

/* ── Data structures ────────────────────────────────────────────────────── */

/*
 * op_shm_slot — one ring entry (exactly 4096 bytes = one memory page).
 *
 * Synchronisation contract:
 *   Producer writes conn_id / flags / data BEFORE publishing via len.
 *   Consumer sees a consistent slot once it observes len != 0.
 *   Consumer clears len to 0 to return the slot to the producer.
 */
struct op_shm_slot
{
    _Atomic(uint32_t)  len;                    /* 0=empty; >0=payload bytes  */
    uint16_t           flags;                  /* OP_SHM_FLAG_* bitmask      */
    uint16_t           _pad;
    uint64_t           conn_id;               /* originating connection id   */
    uint8_t            data[OP_SHM_SLOT_PAYLOAD];
    /* Total: 4+2+2+8+4080 = 4096 bytes */
};

/*
 * op_shm_ring_hdr — ring control header (192 bytes, 3 cache lines).
 *
 * prod_pos / cons_pos are sequence numbers (not masked indices).
 * Slot index = pos & (slot_count - 1).
 * Each is written ONLY by its respective owner; both are read by either side.
 * Separate cache lines prevent false sharing.
 */
struct op_shm_ring_hdr
{
    uint32_t           magic;       /* OP_SHM_RING_MAGIC                     */
    uint32_t           slot_count;  /* capacity (power-of-2)                 */
    uint8_t            _pad0[56];   /* ── pad header to 64 B ─────────────── */

    _Alignas(64) _Atomic(uint64_t) prod_pos; /* next slot to write (producer) */
    uint8_t            _pad1[56];

    _Alignas(64) _Atomic(uint64_t) cons_pos; /* next slot to read (consumer)  */
    uint8_t            _pad2[56];
};

/* Full ring: header immediately followed by the slot array. */
typedef struct {
    struct op_shm_ring_hdr hdr;
    struct op_shm_slot     slots[];  /* slot_count entries                   */
} op_shm_ring_t;

/* ── API ─────────────────────────────────────────────────────────────────── */

/*
 * op_shm_ring_map_size — total mmap size for `slot_count` slots.
 */
size_t op_shm_ring_map_size(uint32_t slot_count);

/*
 * op_shm_ring_create — allocate anonymous shared memory (memfd_create on
 * Linux, shm_open on POSIX) sized for `slot_count` slots.
 * Returns an open file descriptor, or -1 on error.
 * The returned fd has FD_CLOEXEC set; clear it before exec if the child
 * needs to inherit it.
 */
int op_shm_ring_create(uint32_t slot_count);

/*
 * op_shm_ring_map — mmap an existing shm fd.
 * Pass init=true once (in the creating process) to zero and initialise the
 * header.  The child passes init=false.
 * Returns the mapped ring pointer, or NULL on error.
 */
op_shm_ring_t *op_shm_ring_map(int fd, uint32_t slot_count, bool init);

/* op_shm_ring_unmap — munmap the ring.  Does not close the fd. */
void op_shm_ring_unmap(op_shm_ring_t *ring, uint32_t slot_count);

/*
 * op_shm_ring_push — producer: write up to `len` bytes from `buf` into the
 * ring, tagged with `conn_id`.  Payloads > OP_SHM_SLOT_PAYLOAD are split
 * across consecutive slots using the OP_SHM_FLAG_MORE chain; the entire
 * chain is reserved atomically so the consumer never observes a partial
 * message.
 * Returns 0 on success, -1 on failure with errno set:
 *   ENOSPC/0 → ring full (caller should fall back to the socket path)
 *   EMSGSIZE → message larger than the entire ring
 *   EINVAL   → buf == NULL
 *   EBUSY    → SPSC invariant violated (multiple producers detected)
 */
int op_shm_ring_push(op_shm_ring_t *ring, uint64_t conn_id,
                     const void *buf, uint32_t len);

/*
 * op_shm_ring_pop — consumer: read the next ready slot.
 * `out_buf` MUST hold at least OP_SHM_SLOT_PAYLOAD bytes; the consumer is
 * expected to reassemble multi-slot messages by looping while the previous
 * slot carried OP_SHM_FLAG_MORE.
 * Sets *conn_id_out and *flags_out, returns payload length (1..PAYLOAD).
 * Returns 0 if the ring is empty (or a slot is not yet fully published —
 * the caller should retry), -1 with errno set on argument error.
 */
int op_shm_ring_pop(op_shm_ring_t *ring, uint64_t *conn_id_out,
                    void *out_buf, uint16_t *flags_out);

/* Returns true if the ring has at least one ready slot. */
bool op_shm_ring_readable(const op_shm_ring_t *ring);

#endif /* OP_SHM_RING_H */
