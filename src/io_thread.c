/*
 * io_thread.c — dedicated I/O reader thread for eggdrop.
 *
 * Architecture:
 *
 *   io_thread runs its own epoll watching non-TLS, non-TCL sockets.
 *   When a socket becomes readable, io_thread does recv() and pushes
 *   the result onto a lockfree MPSC Treiber stack.  A wakeup eventfd
 *   registered with commio triggers io_thread_drain() on the main
 *   thread, which feeds the data into the socket's linebuf (recvbuf).
 *   sockgets() then extracts complete lines as usual.
 *
 *   Data path:
 *     kernel → recv (io_thread) → MPSC stack → drain (main thread)
 *            → op_linebuf_parse → recvbuf → sockgets → handler
 *
 *   Thread safety:
 *     - io_thread never touches socklist or linebufs
 *     - The MPSC stack is the only shared state (atomic CAS)
 *     - Socket fd comes from epoll data (stored at add_sock time)
 *     - iot_managed[] is per-slot atomic; del_sock clears before close
 *
 * Linux-only (epoll + eventfd).  Non-Linux: all functions are no-ops.
 *
 * Copyright (C) 2026 Eggheads Development Team
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

/* op_thread.h before main.h: eggdrop.h poisons malloc/free, but
 * op_thread.h needs the real allocators for pthread adapter structs. */
#include <op_thread.h>

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "main.h"
#include "io_thread.h"
#include "perf.h"
#include <op_commio.h>

#include <stdatomic.h>
#include <errno.h>
#include <unistd.h>

/* =========================================================================
 * Platform gate — full implementation on Linux, stubs elsewhere.
 * ====================================================================== */

#if defined(__linux__)
#  include <sys/epoll.h>
#  include <sys/eventfd.h>
#  define IOT_SUPPORTED 1
#endif

#ifdef IOT_SUPPORTED

/* =========================================================================
 * SPSC ring buffer — lock-free, zero-contention result queue.
 *
 * Replaces the Treiber stack.  Advantages:
 *   - No CAS retry loops (single producer, single consumer)
 *   - Native FIFO order (no O(n) LIFO→FIFO reversal)
 *   - Cache-line padded indices prevent false sharing
 *   - Simple acquire/release ordering on index loads/stores
 * ====================================================================== */

typedef struct iot_result {
  int    slist_idx;
  int    sock;
  int    len;       /* >0 = data bytes, 0 = EOF, -1 = error           */
  char   data[];    /* flexible array member, allocated to actual size */
} iot_result_t;

#include "egg_perf_types.h"

#define IOT_RING_CAP    4096u
#define IOT_RING_MASK   (IOT_RING_CAP - 1u)

static iot_result_t *iot_ring[IOT_RING_CAP];
static alignas(EGG_CACHELINE) _Atomic(uint32_t) iot_ring_prod = 0;
static alignas(EGG_CACHELINE) _Atomic(uint32_t) iot_ring_cons = 0;

static int iot_ring_push(iot_result_t *r)
{
  uint32_t p = atomic_load_explicit(&iot_ring_prod, memory_order_relaxed);
  uint32_t c = atomic_load_explicit(&iot_ring_cons, memory_order_acquire);
  if (op_unlikely(p - c >= IOT_RING_CAP))
    return -1;
  iot_ring[p & IOT_RING_MASK] = r;
  atomic_store_explicit(&iot_ring_prod, p + 1, memory_order_release);
  return 0;
}

static iot_result_t *iot_ring_pop(void)
{
  uint32_t c = atomic_load_explicit(&iot_ring_cons, memory_order_relaxed);
  uint32_t p = atomic_load_explicit(&iot_ring_prod, memory_order_acquire);
  if (op_unlikely(c == p))
    return nullptr;
  iot_result_t *r = iot_ring[c & IOT_RING_MASK];
  atomic_store_explicit(&iot_ring_cons, c + 1, memory_order_release);
  return r;
}

static uint32_t iot_ring_pending(void)
{
  uint32_t p = atomic_load_explicit(&iot_ring_prod, memory_order_acquire);
  uint32_t c = atomic_load_explicit(&iot_ring_cons, memory_order_relaxed);
  return p - c;
}

/* =========================================================================
 * State
 * ====================================================================== */

#define IOT_MAX_SLOTS   4096
#define IOT_MAX_EVENTS  64

static _Atomic int iot_managed[IOT_MAX_SLOTS];

static int         iot_epfd       = -1;
static int         iot_stop_fd    = -1;
static int         iot_wakeup_fd  = -1;
static op_fde_t   *iot_wakeup_fde = nullptr;
static op_thrd_t   iot_thread;
static _Atomic int iot_running    = 0;

extern sock_list  *socklist;

/* =========================================================================
 * epoll data encoding
 *
 * Each epoll event carries:
 *   data.u64 = (uint64_t)(unsigned)sock << 32 | (unsigned)slist_idx
 *
 * The stop fd uses UINT64_MAX as a sentinel (no valid socket has
 * both fd and index at 0xFFFFFFFF).
 * ====================================================================== */

#define IOT_STOP_SENTINEL  UINT64_MAX

static inline uint64_t iot_encode(int sock, int slist_idx)
{
  return ((uint64_t)(unsigned)sock << 32) | (unsigned)slist_idx;
}

static inline void iot_decode(uint64_t d, int *sock, int *slist_idx)
{
  *sock      = (int)(uint32_t)(d >> 32);
  *slist_idx = (int)(uint32_t)d;
}

/* =========================================================================
 * Commio wakeup handler — fires on the main thread when io_thread has
 * posted results.  Drains the eventfd and feeds results into linebufs.
 * ====================================================================== */

static void iot_wakeup_handler(op_fde_t *F, [[maybe_unused]] void *data)
{
  uint64_t val;
  ssize_t rc;
  do { rc = read(iot_wakeup_fd, &val, sizeof val); }
  while (rc < 0 && errno == EINTR);

  io_thread_drain();

  op_setselect(F, OP_SELECT_READ, iot_wakeup_handler, nullptr);
}

/* =========================================================================
 * CPU affinity — pin the I/O thread to a core to improve cache locality
 * and reduce context-switch jitter.  -1 means no pinning (OS default).
 * ====================================================================== */

static int iot_cpu_affinity = -1;

#if defined(__linux__) && defined(CPU_SET)
#include <sched.h>
static void iot_pin_cpu(int core)
{
  if (core < 0)
    return;
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(core, &cpuset);
  if (sched_setaffinity(0, sizeof cpuset, &cpuset) == 0)
    putlog(LOG_MISC, "*", "io_thread: pinned to CPU %d", core);
}
#else
static void iot_pin_cpu([[maybe_unused]] int core) {}
#endif

/* =========================================================================
 * I/O thread function
 *
 * Adaptive timeout:  Under load (events received), epoll_wait uses a
 * short timeout (1ms) for low latency.  After consecutive idle rounds,
 * the timeout ramps to 500ms to save CPU.  This provides sub-millisecond
 * response under traffic while burning ~0% CPU when idle.
 * ====================================================================== */

#define IOT_TIMEOUT_HOT   1     /* ms — under active I/O */
#define IOT_TIMEOUT_WARM  50    /* ms — recent activity */
#define IOT_TIMEOUT_COLD  500   /* ms — fully idle */
#define IOT_IDLE_WARM     5     /* idle rounds before warm→cold */

static int iot_thread_fn([[maybe_unused]] void *arg)
{
  char rbuf[READMAX + 2];
  struct epoll_event events[IOT_MAX_EVENTS];
  int idle_rounds = 0;

  iot_pin_cpu(iot_cpu_affinity);

  while (op_likely(atomic_load_explicit(&iot_running, memory_order_acquire))) {
    int timeout = (idle_rounds == 0)   ? IOT_TIMEOUT_HOT
                : (idle_rounds < IOT_IDLE_WARM) ? IOT_TIMEOUT_WARM
                : IOT_TIMEOUT_COLD;

    int n = epoll_wait(iot_epfd, events, IOT_MAX_EVENTS, timeout);

    if (op_unlikely(n < 0)) {
      if (errno == EINTR)
        continue;
      break;
    }

    if (n == 0) {
      if (idle_rounds < IOT_IDLE_WARM + 1)
        idle_rounds++;
      continue;
    }

    idle_rounds = 0;
    int signaled = 0;

    for (int i = 0; i < n; i++) {
      uint64_t d = events[i].data.u64;

      if (op_unlikely(d == IOT_STOP_SENTINEL)) {
        uint64_t v;
        ssize_t _r = read(iot_stop_fd, &v, sizeof v);
        (void)_r;
        atomic_store_explicit(&iot_running, 0, memory_order_release);
        goto done;
      }

      int sock, slist_idx;
      iot_decode(d, &sock, &slist_idx);

      if (op_unlikely(slist_idx < 0 || slist_idx >= IOT_MAX_SLOTS))
        continue;
      if (op_unlikely(!atomic_load_explicit(&iot_managed[slist_idx],
                                             memory_order_acquire)))
        continue;

      ssize_t ret = recv(sock, rbuf, READMAX, 0);

      iot_result_t *r;
      if (op_likely(ret > 0)) {
        r = op_malloc(sizeof(*r) + (size_t)ret);
        r->slist_idx = slist_idx;
        r->sock = sock;
        r->len = (int)ret;
        memcpy(r->data, rbuf, (size_t)ret);
      } else if (ret == 0) {
        r = op_malloc(sizeof(*r));
        r->slist_idx = slist_idx;
        r->sock = sock;
        r->len = 0;
      } else {
        if (op_likely(errno == EAGAIN || errno == EWOULDBLOCK))
          continue;
        r = op_malloc(sizeof(*r));
        r->slist_idx = slist_idx;
        r->sock = sock;
        r->len = -1;
      }

      if (op_unlikely(iot_ring_push(r) < 0)) {
        op_free(r);
        continue;
      }
      signaled = 1;
    }

    if (signaled) {
      uint64_t one = 1;
      ssize_t rc;
      do { rc = write(iot_wakeup_fd, &one, sizeof one); }
      while (rc < 0 && errno == EINTR);
    }
  }

done:
  return 0;
}

/* =========================================================================
 * Public API
 * ====================================================================== */

int io_thread_start(void)
{
  if (atomic_load_explicit(&iot_running, memory_order_acquire))
    return 0;

  memset((void *)iot_managed, 0, sizeof iot_managed);
  memset(iot_ring, 0, sizeof iot_ring);
  atomic_store_explicit(&iot_ring_prod, 0, memory_order_relaxed);
  atomic_store_explicit(&iot_ring_cons, 0, memory_order_relaxed);

  /* Create epoll instance. */
  iot_epfd = epoll_create1(EPOLL_CLOEXEC);
  if (iot_epfd < 0)
    return -1;

  /* Stop signal eventfd. */
  iot_stop_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
  if (iot_stop_fd < 0)
    goto fail;

  {
    struct epoll_event ev = {
      .events   = EPOLLIN,
      .data.u64 = IOT_STOP_SENTINEL,
    };
    if (epoll_ctl(iot_epfd, EPOLL_CTL_ADD, iot_stop_fd, &ev) < 0)
      goto fail;
  }

  /* Wakeup eventfd — registered with commio so op_select() picks up
   * io_thread results and fires iot_wakeup_handler. */
  iot_wakeup_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
  if (iot_wakeup_fd < 0)
    goto fail;

  iot_wakeup_fde = op_open(iot_wakeup_fd, OP_FD_UNKNOWN, "iot-wakeup");
  if (!iot_wakeup_fde)
    goto fail;
  op_setselect(iot_wakeup_fde, OP_SELECT_READ, iot_wakeup_handler, nullptr);

  /* Spawn the thread. */
  atomic_store_explicit(&iot_running, 1, memory_order_release);
  if (op_thrd_create(&iot_thread, iot_thread_fn, nullptr) != OP_THRD_SUCCESS) {
    atomic_store_explicit(&iot_running, 0, memory_order_release);
    goto fail;
  }

  putlog(LOG_MISC, "*", "io_thread: started (epoll=%d, ring=%u/%u)",
         iot_epfd, iot_ring_pending(), IOT_RING_CAP);
  return 0;

fail:
  if (iot_wakeup_fde) { op_close(iot_wakeup_fde); iot_wakeup_fde = nullptr; }
  if (iot_wakeup_fd >= 0)  { close(iot_wakeup_fd);  iot_wakeup_fd  = -1; }
  if (iot_stop_fd >= 0)    { close(iot_stop_fd);     iot_stop_fd    = -1; }
  if (iot_epfd >= 0)       { close(iot_epfd);        iot_epfd       = -1; }
  return -1;
}

void io_thread_stop(void)
{
  if (!atomic_load_explicit(&iot_running, memory_order_acquire))
    goto cleanup;

  /* Signal the io_thread to exit. */
  if (iot_stop_fd >= 0) {
    uint64_t one = 1;
    ssize_t rc;
    do { rc = write(iot_stop_fd, &one, sizeof one); }
    while (rc < 0 && errno == EINTR);
  }

  op_thrd_join(iot_thread, nullptr);
  atomic_store_explicit(&iot_running, 0, memory_order_release);

  /* Drain any remaining results. */
  io_thread_drain();

cleanup:
  if (iot_wakeup_fde) { op_close(iot_wakeup_fde); iot_wakeup_fde = nullptr; }
  if (iot_wakeup_fd >= 0) { close(iot_wakeup_fd); iot_wakeup_fd = -1; }
  if (iot_stop_fd >= 0)   { close(iot_stop_fd);   iot_stop_fd   = -1; }
  if (iot_epfd >= 0)      { close(iot_epfd);       iot_epfd      = -1; }
}

int io_thread_active(void)
{
  return atomic_load_explicit(&iot_running, memory_order_acquire);
}

void io_thread_add_sock(int sock, int slist_idx)
{
  if (!io_thread_active())
    return;
  if (slist_idx < 0 || slist_idx >= IOT_MAX_SLOTS)
    return;

  atomic_store_explicit(&iot_managed[slist_idx], 1, memory_order_release);

  struct epoll_event ev = {
    .events   = EPOLLIN,
    .data.u64 = iot_encode(sock, slist_idx),
  };
  epoll_ctl(iot_epfd, EPOLL_CTL_ADD, sock, &ev);
}

void io_thread_del_sock([[maybe_unused]] int sock, int slist_idx)
{
  if (slist_idx < 0 || slist_idx >= IOT_MAX_SLOTS)
    return;

  atomic_store_explicit(&iot_managed[slist_idx], 0, memory_order_release);

  if (iot_epfd >= 0 && sock >= 0)
    epoll_ctl(iot_epfd, EPOLL_CTL_DEL, sock, nullptr);
}

int io_thread_drain(void)
{
  int count = 0;
  iot_result_t *r;

  while ((r = iot_ring_pop()) != nullptr) {
    int idx = r->slist_idx;

    if (op_likely(idx >= 0 && !(socklist[idx].flags & SOCK_UNUSED) &&
                  socklist[idx].sock == r->sock)) {

      if (op_likely(r->len > 0)) {
        int mode = (socklist[idx].flags & (SOCK_BINARY | SOCK_BUFFER))
                   ? LINEBUF_RAW : LINEBUF_PARSED;
        op_linebuf_parse(&socklist[idx].handler.sock.recvbuf,
                         r->data, (ssize_t)r->len, mode);
      } else {
        socklist[idx].flags |= SOCK_EOFD;
      }
      count++;
    }

    op_free(r);
  }

  if (op_likely(count > 0))
    egg_perf_io_drain(count);
  return count;
}

int io_thread_manages(int slist_idx)
{
  if (slist_idx < 0 || slist_idx >= IOT_MAX_SLOTS)
    return 0;
  return atomic_load_explicit(&iot_managed[slist_idx], memory_order_acquire);
}

void io_thread_set_affinity(int core)
{
  iot_cpu_affinity = core;
}

int io_thread_get_affinity(void)
{
  return iot_cpu_affinity;
}

/* =========================================================================
 * CPU topology detection — find best core for I/O thread.
 *
 * Strategy: find the main thread's current CPU, read its L2 cache siblings
 * from /sys/devices/system/cpu, then pick a core NOT sharing L2 with it.
 * This maximizes cache independence between the main thread and I/O thread.
 * ====================================================================== */

#if defined(__linux__)
#include <sched.h>
#include <stdio.h>

int io_thread_detect_best_core(void)
{
  int main_cpu = sched_getcpu();
  if (main_cpu < 0)
    return -1;

  long nproc = sysconf(_SC_NPROCESSORS_ONLN);
  if (nproc <= 1)
    return -1;

  /* Read L2 shared_cpu_list for the main thread's current CPU.
   * Format: "0-1" or "0,1" or "0" etc. */
  op_strbuf_t path;
  op_strbuf_init(&path);
  op_strbuf_appendf(&path,
           "/sys/devices/system/cpu/cpu%d/cache/index2/shared_cpu_list",
           main_cpu);

  FILE *f = fopen(op_strbuf_str(&path), "r");
  if (!f) {
    /* No L2 info — fall back to any core != main_cpu */
    op_strbuf_free(&path);
    return (main_cpu + 1) % (int)nproc;
  }

  /* Parse shared_cpu_list into a bitmask */
  char line[256];
  uint64_t siblings = 0;
  if (fgets(line, sizeof line, f)) {
    char *p = line;
    while (*p) {
      int lo = (int)strtol(p, &p, 10);
      int hi = lo;
      if (*p == '-') {
        p++;
        hi = (int)strtol(p, &p, 10);
      }
      for (int c = lo; c <= hi && c < 64; c++)
        siblings |= (1ULL << c);
      if (*p == ',') p++;
    }
  }
  fclose(f);

  /* Pick the first online core NOT in the L2 sibling set */
  for (int c = 0; c < (int)nproc && c < 64; c++) {
    if (!(siblings & (1ULL << c))) {
      /* Verify this core is online */
      op_strbuf_clear(&path);
      op_strbuf_appendf(&path,
               "/sys/devices/system/cpu/cpu%d/online", c);
      f = fopen(op_strbuf_str(&path), "r");
      if (f) {
        int online = fgetc(f) == '1';
        fclose(f);
        if (!online)
          continue;
      }
      putlog(LOG_MISC, "*",
             "io_thread: topology: main on cpu%d, io_thread → cpu%d (separate L2)",
             main_cpu, c);
      op_strbuf_free(&path);
      return c;
    }
  }

  /* All cores share L2 — pick one on a different physical core (SMT sibling).
   * Reading thread_siblings_list would refine this further, but for most
   * topologies any non-self core is fine. */
  int alt = (main_cpu + (int)nproc / 2) % (int)nproc;
  if (alt == main_cpu)
    alt = (main_cpu + 1) % (int)nproc;
  putlog(LOG_MISC, "*",
         "io_thread: topology: main on cpu%d, io_thread → cpu%d (shared L2, different core)",
         main_cpu, alt);
  op_strbuf_free(&path);
  return alt;
}

#else /* !__linux__ */

int io_thread_detect_best_core(void)
{
  return -1;
}

#endif /* __linux__ */

/* =========================================================================
 * Non-Linux stubs
 * ====================================================================== */
#else /* !IOT_SUPPORTED */

int  io_thread_start(void)  { return -1; }
void io_thread_stop(void)   {}
int  io_thread_active(void) { return 0; }

void io_thread_add_sock([[maybe_unused]] int sock,
                        [[maybe_unused]] int slist_idx) {}
void io_thread_del_sock([[maybe_unused]] int sock,
                        [[maybe_unused]] int slist_idx) {}
int  io_thread_drain(void)    { return 0; }
int  io_thread_manages([[maybe_unused]] int slist_idx) { return 0; }
void io_thread_set_affinity([[maybe_unused]] int core) {}
int  io_thread_get_affinity(void) { return -1; }
int  io_thread_detect_best_core(void) { return -1; }

#endif /* IOT_SUPPORTED */
