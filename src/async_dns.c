/*
 * async_dns.c — non-blocking DNS resolution via the op_async thread pool.
 *
 * Submits getnameinfo() / getaddrinfo() calls to the worker pool so they
 * never block the main event loop.  Results are delivered on the main thread
 * through call_hostbyip() / call_ipbyhost().
 *
 * Copyright (C) 2026 Eggheads Development Team
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "main.h"
#include "dns.h"
#include "async_dns.h"
#include <op_async.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>

/* ---- host-by-IP --------------------------------------------------------- */

typedef struct {
  sockname_t addr;
  char       host[256];
  int        ok;
} dns_hip_ctx_t;

static op_bh *dns_hip_bh = nullptr;

static void dns_hip_work(void *arg)
{
  dns_hip_ctx_t *c = arg;
  int rc;

  c->host[0] = '\0';
  c->ok = 0;

  if (c->addr.family == AF_INET) {
    rc = getnameinfo((const struct sockaddr *)&c->addr.addr.s4,
                     sizeof(struct sockaddr_in),
                     c->host, sizeof c->host, nullptr, 0, 0);
    if (rc) {
      inet_ntop(AF_INET, &c->addr.addr.s4.sin_addr, c->host, sizeof c->host);
    } else {
      c->ok = 1;
    }
#ifdef IPV6
  } else if (c->addr.family == AF_INET6) {
    rc = getnameinfo((const struct sockaddr *)&c->addr.addr.s6,
                     sizeof(struct sockaddr_in6),
                     c->host, sizeof c->host, nullptr, 0, 0);
    if (rc) {
      inet_ntop(AF_INET6, &c->addr.addr.s6.sin6_addr, c->host, sizeof c->host);
    } else {
      c->ok = 1;
    }
#endif
  } else {
    op_strlcpy(c->host, "unknown", sizeof c->host);
  }
}

static void dns_hip_done(void *arg)
{
  dns_hip_ctx_t *c = arg;
  call_hostbyip(&c->addr, c->host, c->ok);
  op_bh_free(dns_hip_bh, c);
}

void async_dns_hostbyip(sockname_t *addr)
{
  if (!op_async_active()) {
    core_dns_hostbyip(addr);
    return;
  }

  if (!dns_hip_bh) dns_hip_bh = op_bh_create(sizeof(dns_hip_ctx_t), 16, "dns_hip_ctx");
  dns_hip_ctx_t *c = (dns_hip_ctx_t *)op_bh_alloc(dns_hip_bh);
  memcpy(&c->addr, addr, sizeof(sockname_t));
  op_async_submit(dns_hip_work, dns_hip_done, c);
}

/* ---- IP-by-host --------------------------------------------------------- */

typedef struct {
  char       host[256];
  sockname_t name;
  int        ok;
} dns_ibh_ctx_t;

static op_bh *dns_ibh_bh = nullptr;

static void dns_ibh_work(void *arg)
{
  dns_ibh_ctx_t *c = arg;
  struct addrinfo hints = {}, *res;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  c->ok = 0;
  memset(&c->name, 0, sizeof c->name);

  int rc = getaddrinfo(c->host, nullptr, &hints, &res);
  if (rc == 0 && res) {
    if (res->ai_family == AF_INET) {
      memcpy(&c->name.addr.s4, res->ai_addr, sizeof(struct sockaddr_in));
      c->name.family = AF_INET;
      c->ok = 1;
#ifdef IPV6
    } else if (res->ai_family == AF_INET6) {
      memcpy(&c->name.addr.s6, res->ai_addr, sizeof(struct sockaddr_in6));
      c->name.family = AF_INET6;
      c->ok = 1;
#endif
    }
    freeaddrinfo(res);
  }
}

static void dns_ibh_done(void *arg)
{
  dns_ibh_ctx_t *c = arg;
  call_ipbyhost(c->host, &c->name, c->ok);
  op_bh_free(dns_ibh_bh, c);
}

void async_dns_ipbyhost(char *host)
{
  if (!op_async_active()) {
    core_dns_ipbyhost(host);
    return;
  }

  if (!dns_ibh_bh) dns_ibh_bh = op_bh_create(sizeof(dns_ibh_ctx_t), 16, "dns_ibh_ctx");
  dns_ibh_ctx_t *c = (dns_ibh_ctx_t *)op_bh_alloc(dns_ibh_bh);
  op_strlcpy(c->host, host, sizeof c->host);
  op_async_submit(dns_ibh_work, dns_ibh_done, c);
}
