/*
 * async_dns.c — non-blocking DNS resolution via the op_async thread pool.
 *
 * Submits getnameinfo() / getaddrinfo() calls to the worker pool so they
 * never block the main event loop.  Results are delivered on the main thread
 * through call_hostbyip() / call_ipbyhost().
 *
 * DNS cache
 * =========
 * Resolved IP→host and host→IP mappings are cached for DNS_CACHE_TTL seconds
 * (main thread only — all accesses happen in the done callbacks and in the
 * lookup functions which are called from the main event loop).
 *
 * Cache entries are stored in two op_htab tables keyed by IP-string and
 * hostname respectively.  A simple sweep-on-lookup eviction avoids a
 * background timer: expired entries are discarded at hit time.
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

#define DNS_CACHE_TTL  300  /* seconds */

/* ---- Shared cache types ------------------------------------------------- */

typedef struct {
  char   key[256];   /* IP string (hip) or hostname (ibh) */
  char   val[256];   /* hostname (hip) or IP string (ibh) */
  time_t expires;
  int    ok;         /* 1 = resolved successfully */
} dns_cache_entry_t;

static op_htab *dns_hip_cache = nullptr;  /* IP  → hostname */
static op_htab *dns_ibh_cache = nullptr;  /* host → IP      */

extern time_t now;  /* main.c global seconds counter */

static void dns_cache_free_entry(void *key, void *val, void *ud)
{
  (void)key; (void)ud;
  op_free(val);
}

void async_dns_cache_flush(void)
{
  if (dns_hip_cache) {
    op_htab_destroy(dns_hip_cache, dns_cache_free_entry, nullptr);
    dns_hip_cache = nullptr;
  }
  if (dns_ibh_cache) {
    op_htab_destroy(dns_ibh_cache, dns_cache_free_entry, nullptr);
    dns_ibh_cache = nullptr;
  }
}

int async_dns_cache_size(void)
{
  int n = 0;
  if (dns_hip_cache) n += (int)op_htab_size(dns_hip_cache);
  if (dns_ibh_cache) n += (int)op_htab_size(dns_ibh_cache);
  return n;
}

static const dns_cache_entry_t *dns_hip_cache_get(const char *ip)
{
  if (!dns_hip_cache) return nullptr;
  dns_cache_entry_t *e = (dns_cache_entry_t *)op_htab_get(dns_hip_cache, ip);
  if (!e) return nullptr;
  if (e->expires <= now) {
    op_htab_del(dns_hip_cache, ip);
    op_free(e);
    return nullptr;
  }
  return e;
}

static void dns_hip_cache_set(const char *ip, const char *host, int ok)
{
  if (!dns_hip_cache)
    dns_hip_cache = op_htab_create_str("dns_hip", 64);
  dns_cache_entry_t *old = (dns_cache_entry_t *)op_htab_get(dns_hip_cache, ip);
  op_free(old);
  dns_cache_entry_t *e = (dns_cache_entry_t *)op_malloc(sizeof *e);
  op_strlcpy(e->key, ip,   sizeof e->key);
  op_strlcpy(e->val, host, sizeof e->val);
  e->expires = now + DNS_CACHE_TTL;
  e->ok = ok;
  op_htab_set(dns_hip_cache, e->key, e, nullptr);
}

static const dns_cache_entry_t *dns_ibh_cache_get(const char *host)
{
  if (!dns_ibh_cache) return nullptr;
  dns_cache_entry_t *e = (dns_cache_entry_t *)op_htab_get(dns_ibh_cache, host);
  if (!e) return nullptr;
  if (e->expires <= now) {
    op_htab_del(dns_ibh_cache, host);
    op_free(e);
    return nullptr;
  }
  return e;
}

static void dns_ibh_cache_set(const char *host, const char *ip, int ok)
{
  if (!dns_ibh_cache)
    dns_ibh_cache = op_htab_create_str("dns_ibh", 64);
  dns_cache_entry_t *old = (dns_cache_entry_t *)op_htab_get(dns_ibh_cache, host);
  op_free(old);
  dns_cache_entry_t *e = (dns_cache_entry_t *)op_malloc(sizeof *e);
  op_strlcpy(e->key, host, sizeof e->key);
  op_strlcpy(e->val, ip,   sizeof e->val);
  e->expires = now + DNS_CACHE_TTL;
  e->ok = ok;
  op_htab_set(dns_ibh_cache, e->key, e, nullptr);
}

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

  /* Cache the result (keyed by IP string) before delivering. */
  char ipstr[INET6_ADDRSTRLEN] = {};
  if (c->addr.family == AF_INET)
    inet_ntop(AF_INET,  &c->addr.addr.s4.sin_addr,  ipstr, sizeof ipstr);
#ifdef IPV6
  else if (c->addr.family == AF_INET6)
    inet_ntop(AF_INET6, &c->addr.addr.s6.sin6_addr, ipstr, sizeof ipstr);
#endif
  if (ipstr[0])
    dns_hip_cache_set(ipstr, c->host, c->ok);

  call_hostbyip(&c->addr, c->host, c->ok);
  op_bh_free(dns_hip_bh, c);
}

void async_dns_hostbyip(sockname_t *addr)
{
  /* Check cache first (main thread only). */
  char ipstr[INET6_ADDRSTRLEN] = {};
  if (addr->family == AF_INET)
    inet_ntop(AF_INET,  &addr->addr.s4.sin_addr,  ipstr, sizeof ipstr);
#ifdef IPV6
  else if (addr->family == AF_INET6)
    inet_ntop(AF_INET6, &addr->addr.s6.sin6_addr, ipstr, sizeof ipstr);
#endif
  if (ipstr[0]) {
    const dns_cache_entry_t *hit = dns_hip_cache_get(ipstr);
    if (hit) {
      call_hostbyip(addr, hit->val, hit->ok);
      return;
    }
  }

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
      c->name.addrlen = sizeof(struct sockaddr_in);
      c->ok = 1;
#ifdef IPV6
    } else if (res->ai_family == AF_INET6) {
      memcpy(&c->name.addr.s6, res->ai_addr, sizeof(struct sockaddr_in6));
      c->name.family = AF_INET6;
      c->name.addrlen = sizeof(struct sockaddr_in6);
      c->ok = 1;
#endif
    }
    freeaddrinfo(res);
  }
}

static void dns_ibh_done(void *arg)
{
  dns_ibh_ctx_t *c = arg;

  /* Cache the result (keyed by hostname). */
  if (c->ok) {
    char ipstr[INET6_ADDRSTRLEN] = {};
    if (c->name.family == AF_INET)
      inet_ntop(AF_INET,  &c->name.addr.s4.sin_addr,  ipstr, sizeof ipstr);
#ifdef IPV6
    else if (c->name.family == AF_INET6)
      inet_ntop(AF_INET6, &c->name.addr.s6.sin6_addr, ipstr, sizeof ipstr);
#endif
    if (ipstr[0])
      dns_ibh_cache_set(c->host, ipstr, 1);
  } else {
    dns_ibh_cache_set(c->host, "", 0);
  }

  call_ipbyhost(c->host, &c->name, c->ok);
  op_bh_free(dns_ibh_bh, c);
}

void async_dns_ipbyhost(char *host)
{
  /* Check cache first (main thread only). */
  const dns_cache_entry_t *hit = dns_ibh_cache_get(host);
  if (hit) {
    sockname_t name = {};
    if (hit->ok && hit->val[0]) {
      if (inet_pton(AF_INET, hit->val, &name.addr.s4.sin_addr) == 1) {
        name.family  = AF_INET;
        name.addrlen = sizeof(struct sockaddr_in);
        name.addr.s4.sin_family = AF_INET;
#ifdef IPV6
      } else if (inet_pton(AF_INET6, hit->val, &name.addr.s6.sin6_addr) == 1) {
        name.family  = AF_INET6;
        name.addrlen = sizeof(struct sockaddr_in6);
        name.addr.s6.sin6_family = AF_INET6;
#endif
      }
    }
    call_ipbyhost(host, &name, hit->ok);
    return;
  }

  if (!op_async_active()) {
    core_dns_ipbyhost(host);
    return;
  }

  if (!dns_ibh_bh) dns_ibh_bh = op_bh_create(sizeof(dns_ibh_ctx_t), 16, "dns_ibh_ctx");
  dns_ibh_ctx_t *c = (dns_ibh_ctx_t *)op_bh_alloc(dns_ibh_bh);
  op_strlcpy(c->host, host, sizeof c->host);
  op_async_submit(dns_ibh_work, dns_ibh_done, c);
}
