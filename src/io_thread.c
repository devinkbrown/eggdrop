/*
 * io_thread.c — dedicated I/O reader thread for eggdrop.
 *
 * See io_thread.h for the design overview.
 *
 * Copyright (C) 2026 Eggheads Development Team
 * SPDX-License-Identifier: GPL-2.0-only
 */

/* Enable GNU extensions: eventfd, EPOLL_CLOEXEC, accept4, etc. */
#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

/* op_thread.h must be included before main.h.  main.h → eggdrop.h redefines
 * malloc/free to dont_use_old_malloc/dont_use_old_free to catch accidental
 * direct allocation in eggdrop code.  op_thread.h is a libop library header
 * that legitimately uses the real malloc for its pthreads adapter structs;
 * it must see the real allocators. */
#include <op_thread.h>

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "main.h"
#include "io_thread.h"
#include "tclhash.h"   /* struct threaddata, threaddata() */

#include <stdatomic.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef TLS
#  include "egg_tls.h"
#endif

/* Global socklist from net.c */
extern sock_list *socklist;

/* =========================================================================
 * Platform-specific I/O notification backend
 *
 * Two notification fds are needed:
 *   io_wakeup_fd  — io_thread → main thread: "data is ready"
 *   io_stop_fd   — main thread → io_thread: "please stop"
 *
 * Use eventfd on Linux; fall back to a pipe pair on other POSIX systems.
 * ====================================================================== */

#ifdef __linux__
#  include <sys/eventfd.h>
#  define HAVE_EVENTFD 1
#endif

#if defined(HAVE_EPOLL) || defined(EGG_EPOLL) || defined(__linux__)
#  include <sys/epoll.h>
#  define IOT_HAVE_EPOLL 1
#endif

/* =========================================================================
 * State
 * ====================================================================== */

/* io_thread's own epoll fd — watches non-TCL, non-TLS sockets for EPOLLIN */
static int iot_epoll_fd = -1;

/* Wakeup notification: io_thread signals main when inbuf has new data */
#ifdef HAVE_EVENTFD
static int iot_wakeup_fd = -1;        /* eventfd */
#else
static int iot_wakeup_pipe[2] = { -1, -1 };
#  define iot_wakeup_fd iot_wakeup_pipe[0]
#endif

/* Stop signal: main signals io_thread to exit */
#ifdef HAVE_EVENTFD
static int iot_stop_fd = -1;          /* eventfd */
#else
static int iot_stop_pipe[2] = { -1, -1 };
#  define iot_stop_fd iot_stop_pipe[0]
#endif

static op_thrd_t iot_thread;
static _Atomic int iot_running = 0;   /* 1 while io_thread is alive */

/* Maximum epoll events per wait call */
constexpr int IOT_MAX_EVENTS = 64;

/* Recv staging buffer size (READMAX + 2 for CRLF detection) */
constexpr int IOT_RBUF_SIZE = READMAX + 2;

/* =========================================================================
 * Helper: open an eventfd or pipe pair
 * ====================================================================== */

static int iot_open_notify(int *write_end_out)
{
#ifdef HAVE_EVENTFD
  int fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
  if (fd < 0)
    return -1;
  if (write_end_out)
    *write_end_out = fd;   /* eventfd: same fd for read and write */
  return fd;
#else
  int fds[2];
  if (pipe(fds) < 0)
    return -1;
  fcntl(fds[0], F_SETFL, O_NONBLOCK);
  fcntl(fds[1], F_SETFL, O_NONBLOCK);
  if (write_end_out)
    *write_end_out = fds[1];
  return fds[0];
#endif
}

/* =========================================================================
 * Inbuf append helper (called from io_thread, under inbuf_lock)
 * ====================================================================== */

static void iot_append_inbuf(struct sock_handler *h, const char *data, int len)
{
  size_t newlen = h->inbuflen + (size_t)len;
  char *newbuf = nrealloc(h->inbuf, newlen + 1);
  if (!newbuf)
    return;   /* OOM: silently drop; main thread will see no progress */
  memcpy(newbuf + h->inbuflen, data, (size_t)len);
  newbuf[newlen] = '\0';
  h->inbuf    = newbuf;
  h->inbuflen = newlen;
}

/* =========================================================================
 * I/O thread function
 * ====================================================================== */

static int iot_thread_fn([[maybe_unused]] void *arg)
{

  /* threaddata() from the io_thread returns td_main (via the
   * mainloopfunc==NULL fallback in the Tcl build, or the global td_static
   * in the no-Tcl build).  Used for MAXSOCKS bounds-checking. */
  struct threaddata *td = threaddata();

  char rbuf[IOT_RBUF_SIZE];

#ifdef IOT_HAVE_EPOLL
  struct epoll_event events[IOT_MAX_EVENTS];
  int n;

  while (atomic_load_explicit(&iot_running, memory_order_acquire)) {
    /* Wait for readability on any registered socket, or for the stop fd. */
    n = epoll_wait(iot_epoll_fd, events, IOT_MAX_EVENTS, 200 /* ms timeout */);

    if (n < 0) {
      if (errno == EINTR)
        continue;
      break;
    }

    for (int i = 0; i < n; i++) {
      uint64_t data64 = events[i].data.u64;
      int is_control   = (int)(data64 >> 32);
      int slot_or_fd   = (int)(uint32_t)data64;

      if (is_control) {
        /* Stop fd became readable — exit. */
        atomic_store_explicit(&iot_running, 0, memory_order_release);
        break;
      }

      int slist_idx = slot_or_fd;
      if (slist_idx < 0 || slist_idx >= td->MAXSOCKS)
        continue;

      sock_list *sl = &socklist[slist_idx];

      /* Skip slots that have been freed or are TCL/virtual/TLS sockets.
       * We check flags before taking the lock; a concurrent killsock() will
       * set SOCK_UNUSED first and then destroy the lock.  The race window is
       * harmless: if we see SOCK_UNUSED we skip; if we lock first, killsock()
       * will wait on the lock before destroying it. */
      if (sl->flags & (SOCK_UNUSED | SOCK_TCL | SOCK_VIRTUAL))
        continue;

#ifdef TLS
      /* Leave TLS sockets for the main thread. */
      if (sl->ssl)
        continue;
#endif

      int fd = sl->sock;
      if (fd < 0)
        continue;

      /* Read data from the kernel socket buffer. */
      ssize_t ret = recv(fd, rbuf, sizeof rbuf - 1, 0);

      if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
          continue;
        /* Real error: mark the socket so sockgets() triggers EOF handling. */
        egg_spin_lock(&sl->handler.sock.inbuf_lock);
        if (!(sl->flags & SOCK_UNUSED))
          sl->flags |= SOCK_EOFD;
        egg_spin_unlock(&sl->handler.sock.inbuf_lock);
      } else if (ret == 0) {
        /* EOF: mark for sockgets() to report. */
        egg_spin_lock(&sl->handler.sock.inbuf_lock);
        if (!(sl->flags & SOCK_UNUSED))
          sl->flags |= SOCK_EOFD;
        egg_spin_unlock(&sl->handler.sock.inbuf_lock);
      } else {
        /* Append received bytes to inbuf under the per-socket lock. */
        egg_spin_lock(&sl->handler.sock.inbuf_lock);
        if (!(sl->flags & SOCK_UNUSED))
          iot_append_inbuf(&sl->handler.sock, rbuf, (int)ret);
        egg_spin_unlock(&sl->handler.sock.inbuf_lock);
      }

      /* Wake the main thread regardless of ret — it needs to process
       * EOF flags and/or newly buffered data. */
#ifdef HAVE_EVENTFD
      {
        uint64_t one = 1;
        ssize_t rc;
        do { rc = write(iot_wakeup_fd, &one, sizeof one); }
        while (rc < 0 && errno == EINTR);
      }
#else
      {
        char one = 1;
        ssize_t rc;
        do { rc = write(iot_wakeup_pipe[1], &one, 1); }
        while (rc < 0 && errno == EINTR);
      }
#endif
    }
  }

#else  /* !IOT_HAVE_EPOLL — select() fallback */

  fd_set fdr;
  struct timeval tv;
  int maxfd, ret_s;

  while (atomic_load_explicit(&iot_running, memory_order_acquire)) {
    FD_ZERO(&fdr);
    maxfd = -1;

    /* Add stop fd */
    FD_SET(iot_stop_fd, &fdr);
    if (iot_stop_fd > maxfd)
      maxfd = iot_stop_fd;

    /* Add all eligible sockets */
    for (int i = 0; i < td->MAXSOCKS; i++) {
      sock_list *sl = &socklist[i];
      if (sl->flags & (SOCK_UNUSED | SOCK_TCL | SOCK_VIRTUAL))
        continue;
#ifdef TLS
      if (sl->ssl)
        continue;
#endif
      int fd = sl->sock;
      if (fd < 0)
        continue;
      FD_SET(fd, &fdr);
      if (fd > maxfd)
        maxfd = fd;
    }

    if (maxfd < 0) {
      /* No sockets — sleep briefly and retry. */
      tv.tv_sec = 0;
      tv.tv_usec = 200000;
      select(0, NULL, NULL, NULL, &tv);
      continue;
    }

    tv.tv_sec = 0;
    tv.tv_usec = 200000;
    ret_s = select(maxfd + 1, &fdr, NULL, NULL, &tv);

    if (ret_s < 0) {
      if (errno == EINTR)
        continue;
      break;
    }

    /* Check stop fd */
    if (FD_ISSET(iot_stop_fd, &fdr)) {
      atomic_store_explicit(&iot_running, 0, memory_order_release);
      break;
    }

    for (int i = 0; i < td->MAXSOCKS; i++) {
      sock_list *sl = &socklist[i];
      if (sl->flags & (SOCK_UNUSED | SOCK_TCL | SOCK_VIRTUAL))
        continue;
#ifdef TLS
      if (sl->ssl)
        continue;
#endif
      int fd = sl->sock;
      if (fd < 0 || !FD_ISSET(fd, &fdr))
        continue;

      ssize_t ret = recv(fd, rbuf, sizeof rbuf - 1, 0);

      if (ret <= 0) {
        egg_spin_lock(&sl->handler.sock.inbuf_lock);
        if (!(sl->flags & SOCK_UNUSED))
          sl->flags |= SOCK_EOFD;
        egg_spin_unlock(&sl->handler.sock.inbuf_lock);
      } else {
        egg_spin_lock(&sl->handler.sock.inbuf_lock);
        if (!(sl->flags & SOCK_UNUSED))
          iot_append_inbuf(&sl->handler.sock, rbuf, (int)ret);
        egg_spin_unlock(&sl->handler.sock.inbuf_lock);
      }

#ifdef HAVE_EVENTFD
      {
        uint64_t one = 1;
        ssize_t rc;
        do { rc = write(iot_wakeup_fd, &one, sizeof one); }
        while (rc < 0 && errno == EINTR);
      }
#else
      {
        char one = 1;
        ssize_t rc;
        do { rc = write(iot_wakeup_pipe[1], &one, 1); }
        while (rc < 0 && errno == EINTR);
      }
#endif
    }
  }

#endif /* IOT_HAVE_EPOLL */

  return 0;
}

/* =========================================================================
 * Public API
 * ====================================================================== */

int io_thread_start(void)
{
  if (atomic_load_explicit(&iot_running, memory_order_acquire))
    return 0;  /* already running */

#ifdef IOT_HAVE_EPOLL
  iot_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  if (iot_epoll_fd < 0)
    return -1;

  /* Register the stop fd on our epoll using the high bit of data.u64 as a
   * "control" flag so the io_thread can distinguish it from socket events. */
  {
    struct epoll_event ev = {
      .events  = EPOLLIN,
      .data.u64 = (uint64_t)1 << 32  /* is_control=1, slot=0 */
    };
#ifdef HAVE_EVENTFD
    iot_stop_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (iot_stop_fd < 0) {
      close(iot_epoll_fd);
      iot_epoll_fd = -1;
      return -1;
    }
#else
    {
      int fds[2];
      if (pipe(fds) < 0) {
        close(iot_epoll_fd);
        iot_epoll_fd = -1;
        return -1;
      }
      fcntl(fds[0], F_SETFL, O_NONBLOCK);
      iot_stop_pipe[0] = fds[0];
      iot_stop_pipe[1] = fds[1];
    }
#endif
    if (epoll_ctl(iot_epoll_fd, EPOLL_CTL_ADD, iot_stop_fd, &ev) < 0) {
      close(iot_stop_fd);
      close(iot_epoll_fd);
      iot_stop_fd = -1;
      iot_epoll_fd = -1;
      return -1;
    }
  }
#else
  /* select() path: open stop pipe */
  {
    int fds[2];
    if (pipe(fds) < 0)
      return -1;
    fcntl(fds[0], F_SETFL, O_NONBLOCK);
    iot_stop_pipe[0] = fds[0];
    iot_stop_pipe[1] = fds[1];
  }
#endif

  /* Open the wakeup notification fd (main thread reads this). */
#ifdef HAVE_EVENTFD
  iot_wakeup_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
  if (iot_wakeup_fd < 0) {
    io_thread_stop();
    return -1;
  }
#else
  {
    int fds[2];
    if (pipe(fds) < 0) {
      io_thread_stop();
      return -1;
    }
    fcntl(fds[0], F_SETFL, O_NONBLOCK);
    fcntl(fds[1], F_SETFL, O_NONBLOCK);
    iot_wakeup_pipe[0] = fds[0];
    iot_wakeup_pipe[1] = fds[1];
  }
#endif

  atomic_store_explicit(&iot_running, 1, memory_order_release);

  if (op_thrd_create(&iot_thread, iot_thread_fn, NULL) != OP_THRD_SUCCESS) {
    atomic_store_explicit(&iot_running, 0, memory_order_release);
    io_thread_stop();
    return -1;
  }

  putlog(LOG_MISC, "*", "io_thread: started (epoll=%d, wakeup_fd=%d)",
         iot_epoll_fd, iot_wakeup_fd);
  return 0;
}

void io_thread_stop(void)
{
  if (!atomic_load_explicit(&iot_running, memory_order_acquire))
    goto cleanup_fds;

  /* Signal the io_thread to stop. */
#ifdef HAVE_EVENTFD
  if (iot_stop_fd >= 0) {
    uint64_t one = 1;
    ssize_t rc;
    do { rc = write(iot_stop_fd, &one, sizeof one); }
    while (rc < 0 && errno == EINTR);
  }
#else
  if (iot_stop_pipe[1] >= 0) {
    char one = 1;
    ssize_t rc;
    do { rc = write(iot_stop_pipe[1], &one, 1); }
    while (rc < 0 && errno == EINTR);
  }
#endif

  op_thrd_join(iot_thread, NULL);
  atomic_store_explicit(&iot_running, 0, memory_order_release);

cleanup_fds:
#ifdef IOT_HAVE_EPOLL
  if (iot_epoll_fd >= 0) {
    close(iot_epoll_fd);
    iot_epoll_fd = -1;
  }
#endif

#ifdef HAVE_EVENTFD
  if (iot_stop_fd >= 0) {
    close(iot_stop_fd);
    iot_stop_fd = -1;
  }
  if (iot_wakeup_fd >= 0) {
    close(iot_wakeup_fd);
    iot_wakeup_fd = -1;
  }
#else
  for (int k = 0; k < 2; k++) {
    if (iot_stop_pipe[k] >= 0) {
      close(iot_stop_pipe[k]);
      iot_stop_pipe[k] = -1;
    }
    if (iot_wakeup_pipe[k] >= 0) {
      close(iot_wakeup_pipe[k]);
      iot_wakeup_pipe[k] = -1;
    }
  }
#endif
}

void io_thread_add_sock([[maybe_unused]] int sock, [[maybe_unused]] int slist_idx)
{
#ifdef IOT_HAVE_EPOLL
  if (iot_epoll_fd < 0)
    return;
  struct epoll_event ev = {
    .events   = EPOLLIN | EPOLLET,     /* edge-triggered to reduce wake storms */
    .data.u64 = (uint64_t)(uint32_t)slist_idx   /* is_control=0 */
  };
  epoll_ctl(iot_epoll_fd, EPOLL_CTL_ADD, sock, &ev);
#endif
}

void io_thread_del_sock([[maybe_unused]] int sock)
{
#ifdef IOT_HAVE_EPOLL
  if (iot_epoll_fd < 0)
    return;
  epoll_ctl(iot_epoll_fd, EPOLL_CTL_DEL, sock, NULL);
#endif
}

int io_thread_wait(int timeout_ms)
{
  if (iot_wakeup_fd < 0)
    return -1;

#ifdef HAVE_EVENTFD
  /* Block until the io_thread writes to the eventfd, or timeout. */
  fd_set fdr;
  struct timeval tv;
  FD_ZERO(&fdr);
  FD_SET(iot_wakeup_fd, &fdr);
  if (timeout_ms >= 0) {
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
  }
  int r = select(iot_wakeup_fd + 1, &fdr, NULL, NULL,
                 timeout_ms >= 0 ? &tv : NULL);
  if (r > 0) {
    /* Drain the counter so the fd doesn't stay readable. */
    uint64_t val;
    ssize_t rc;
    do { rc = read(iot_wakeup_fd, &val, sizeof val); }
    while (rc < 0 && errno == EINTR);
    return 1;
  }
  return r;  /* 0 = timeout, -1 = error */
#else
  fd_set fdr;
  struct timeval tv;
  FD_ZERO(&fdr);
  FD_SET(iot_wakeup_pipe[0], &fdr);
  if (timeout_ms >= 0) {
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
  }
  int r = select(iot_wakeup_pipe[0] + 1, &fdr, NULL, NULL,
                 timeout_ms >= 0 ? &tv : NULL);
  if (r > 0) {
    /* Drain the pipe. */
    char buf[64];
    ssize_t rc;
    do { rc = read(iot_wakeup_pipe[0], buf, sizeof buf); }
    while (rc > 0 || (rc < 0 && errno == EINTR));
    return 1;
  }
  return r;
#endif
}

int io_thread_active(void)
{
  return atomic_load_explicit(&iot_running, memory_order_acquire);
}
