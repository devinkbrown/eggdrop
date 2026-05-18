/*
 * res.c -- part of dns.mod
 *   Lightweight async DNS resolver for eggdrop, adapted from ophion's res.c.
 *
 *   Replaces the legacy coredns.c (1985 BSD libresolv heritage) with a
 *   clean, self-contained implementation.  The public API exposed to
 *   dns.mod/dns.c (dns_lookup, dns_forward, dns_check_expires, dns_ack,
 *   init_dns_network, expireresolves, resfd, myres) is preserved via
 *   compatibility wrappers so that dns.mod/dns.c requires no changes.
 *
 * Design:
 *   - Single non-blocking UDP socket for plain DNS queries.
 *   - Optional DNS-over-TLS (DoT, RFC 7858) path, guarded by #ifdef EGG_TLS.
 *   - Each in-flight query is a dns_req on a doubly-linked list.
 *   - A secondly hook drives timeout / retry logic.
 *   - FCrDNS: PTR reply triggers A/AAAA forward lookup; hostname accepted
 *     only if the forward result matches the original IP.
 *   - /etc/resolv.conf is parsed at startup and on restart_resolver().
 *
 * Original: Copyright (C) 2024-2026 Ophion IRC development team
 * Adapted for eggdrop by the Eggheads Development Team
 */
/*
 * Copyright (C) 1999 - 2025 Eggheads Development Team
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#define _GNU_SOURCE 1
#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif
#ifdef TLS
#include <opssl/conn.h>
#include <opssl/types.h>
#endif
/* Include main.h (which in turn includes eggdrop.h and, when NOT
 * MAKING_MODS, proto.h as well) so that res.c compiles as a standalone
 * translation unit.  When compiled inside the dns module unity build
 * (dns.c #includes res.c after #including module.h), the include guards
 * in main.h make this a no-op and the global[] dispatch macros from
 * module.h are already in scope.  main.h has include guards so
 * double-inclusion is safe. */
#include "../../main.h"
#include "dns.h"
#include "res.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <resolv.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

/* Map EGG_TLS onto the eggdrop-wide TLS flag.
 * Must be done before any #ifdef EGG_TLS guards in this file. */
#ifdef TLS
# ifndef EGG_TLS
#  define EGG_TLS 1
# endif
#endif

/* =========================================================================
 * Eggdrop global externs needed by this file.
 *
 * When res.c is compiled as part of the dns module unity build (dns.c
 * #includes res.c), these are satisfied by the dns.c translation unit.
 * When compiled standalone (e.g. libeggres or use-res-dns), we declare
 * them explicitly.  The definitions live in main.c and net.c.
 * ====================================================================== */
/* In module context (MAKING_MODS), now/pref_af come from module.h macros;
 * the extern declarations would conflict with those macro definitions. */
#ifndef MAKING_MODS
extern time_t now;         /* updated every main-loop tick (main.c)      */
extern int pref_af;        /* 0 = prefer IPv4, 1 = prefer IPv6  (net.c) */
extern sock_list *socklist; /* TLS-aware socket list           (net.c)   */
#endif

/* =========================================================================
 * Eggdrop portability shims
 * ====================================================================== */

/* op_dlink_{node,list}, op_dlinkAdd, op_dlinkDelete, OP_DLINK_FOREACH*,
 * op_malloc, op_free, op_strcasecmp, op_strlcpy — all provided by
 * op_lib.h (pulled in via main.h above).  No local reimplementation needed. */

#define op_sockaddr_storage sockaddr_storage

/* Logging */
#define iwarn(fmt, ...)      putlog(LOG_MISC, "*", "DNS: " fmt, ##__VA_ARGS__)
#define ilog(lvl, fmt, ...)  putlog(LOG_MISC, "*", "DNS: " fmt, ##__VA_ARGS__)
#define idebug(fmt, ...)     /* debug only */

/* Socket helpers */
[[maybe_unused]] static inline
int res_inet_pton_sock(const char *addr,
                       struct sockaddr_storage *ss)
{
  memset(ss, 0, sizeof(*ss));
  if (inet_pton(AF_INET, addr,
                &((struct sockaddr_in *)ss)->sin_addr) == 1) {
    ((struct sockaddr_in *)ss)->sin_family = AF_INET;
    return 1;
  }
#ifdef IPV6
  if (inet_pton(AF_INET6, addr,
                &((struct sockaddr_in6 *)ss)->sin6_addr) == 1) {
    ((struct sockaddr_in6 *)ss)->sin6_family = AF_INET6;
    return 1;
  }
#endif
  return 0;
}
#define op_inet_pton_sock(addr, ss)  res_inet_pton_sock(addr, ss)

[[maybe_unused]] static inline
const char *res_inet_ntop_sock(const struct sockaddr *sa,
                               char *buf, size_t len)
{
  if (sa->sa_family == AF_INET)
    return inet_ntop(AF_INET,
                     &((const struct sockaddr_in *)sa)->sin_addr,
                     buf, len);
#ifdef IPV6
  else if (sa->sa_family == AF_INET6)
    return inet_ntop(AF_INET6,
                     &((const struct sockaddr_in6 *)sa)->sin6_addr,
                     buf, len);
#endif
  if (len > 0) buf[0] = '\0';
  return buf;
}
#define op_inet_ntop_sock(sa, buf, len) \
  res_inet_ntop_sock((const struct sockaddr *)(sa), buf, len)

#undef GET_SS_FAMILY
#define GET_SS_FAMILY(ss)  (((const struct sockaddr *)(ss))->sa_family)

/* SS_LEN: portable sockaddr length */
static inline socklen_t res_ss_len(const struct sockaddr_storage *ss) {
  if (GET_SS_FAMILY(ss) == AF_INET)  return sizeof(struct sockaddr_in);
#ifdef IPV6
  if (GET_SS_FAMILY(ss) == AF_INET6) return sizeof(struct sockaddr_in6);
#endif
  return sizeof(struct sockaddr_storage);
}
#undef GET_SS_LEN
#define GET_SS_LEN(ss)      res_ss_len(ss)
#undef SET_SS_LEN
#define SET_SS_LEN(ss, l)   /* length is implicit in family */

/* Random ID generation — uses getrandom(2) (Linux ≥ 3.17) with a
 * /dev/urandom fallback so query IDs are unpredictable and resist
 * off-path DNS cache poisoning (Kaminsky-style attacks). */
static inline void res_get_random(void *buf, size_t len) {
#if defined(SYS_getrandom)
  /* getrandom() never blocks for urandom-quality entropy and has no fd. */
  ssize_t got = syscall(SYS_getrandom, buf, len, 0);
  if (got == (ssize_t)len)
    return;
#endif
  /* Fallback: /dev/urandom */
  {
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
      ssize_t nread = read(fd, buf, len);
      close(fd);
      if (nread == (ssize_t)len)
        return;
    }
  }
  /* Last resort: time+pid XOR mix (weak, but better than nothing) */
  {
    static uint32_t seed = 0;
    if (!seed) seed = (uint32_t)(time(nullptr) ^ getpid());
    uint8_t *p = (uint8_t *)buf;
    for (size_t i = 0; i < len; i++) {
      seed = seed * 1664525u + 1013904223u;
      p[i] = (uint8_t)(seed >> 16);
    }
  }
}

#define op_current_time()   ((time_t)now)

/* =========================================================================
 * Simple timer shim replacing op_event_*
 *
 * res_secondly_check() is called every second via HOOK_SECONDLY from
 * dns.mod/dns.c.  It drives both the query-timeout loop and the optional
 * DoT reconnect countdown.
 * ====================================================================== */

static int res_timer_seconds    = 0;
#ifdef EGG_TLS
static int dot_reconnect_seconds = -1;  /* -1 = not scheduled */
#endif

/* =========================================================================
 * DNS wire-format constants
 * ====================================================================== */

constexpr int DNS_HDR_SIZE     = 12;
constexpr int DNS_MAXPKT       = 4096;  /* EDNS0 max UDP payload (RFC 6891) */
constexpr int DNS_MAXLABEL     = 63;
constexpr int DNS_PTR_HI       = 0xC0;
constexpr int DNS_CLASS_IN     = 1;

constexpr int DNS_TYPE_A       = 1;
constexpr int DNS_TYPE_CNAME   = 5;
constexpr int DNS_TYPE_OPT     = 41;    /* EDNS0 pseudo-RR (RFC 6891) */
constexpr int DNS_TYPE_PTR     = 12;
constexpr int DNS_TYPE_AAAA    = 28;

/* EDNS0 OPT record constants (RFC 6891) */
constexpr int DNS_EDNS0_PAYLOAD = 4096; /* advertised UDP payload size */
constexpr int DNS_OPT_RDLEN     = 0;    /* no option data */

/* TC (Truncation) bit in DNS flags word (bit 9) */
constexpr int DNS_FLAG_TC      = 0x0200;

constexpr int DNS_RC_NOERR     = 0;
constexpr int DNS_RC_SERVFAIL  = 2;
constexpr int DNS_RC_NXDOMAIN  = 3;
constexpr int DNS_RC_NOTIMP    = 4;
constexpr int DNS_RC_REFUSED   = 5;

constexpr int DNS_INITIAL_TIMEOUT = 4;
constexpr int DNS_MAX_RETRIES     = 3;
constexpr int DNS_TIMER_INTERVAL  = 1;
constexpr int DNS_MAX_CNAME_DEPTH = 8; /* RFC 1034 §3.6.2 recommends ≤ a few hops */

/* High bit of dns_req.type marks a forward-confirmation query */
constexpr int DNS_FLAG_FCRDNS  = 0x8000;

/* Cap on answer RRs to guard against malformed packets (tight-loop DoS) */
constexpr int DNS_MAX_ANCOUNT  = 64;

/* =========================================================================
 * DNS header field accessors (byte-level; safe on all arches)
 * ====================================================================== */

static inline uint16_t hdr_u16(const unsigned char *p) {
  return ((uint16_t)p[0] << 8) | p[1];
}
static inline void hdr_put_u16(unsigned char *p, uint16_t v) {
  p[0] = (unsigned char)(v >> 8);
  p[1] = (unsigned char)v;
}

#define HDR_ID(pkt)      hdr_u16((const unsigned char *)(pkt))
#define HDR_FLAGS(pkt)   hdr_u16((const unsigned char *)(pkt) + 2)
#define HDR_QDCOUNT(pkt) hdr_u16((const unsigned char *)(pkt) + 4)
#define HDR_ANCOUNT(pkt) hdr_u16((const unsigned char *)(pkt) + 6)
#define HDR_QR(pkt)      (HDR_FLAGS(pkt) >> 15)
#define HDR_OPCODE(pkt)  ((HDR_FLAGS(pkt) >> 11) & 0xf)
#define HDR_RCODE(pkt)   (HDR_FLAGS(pkt) & 0xf)

/* =========================================================================
 * Global resolver state (exported via res.h)
 * ====================================================================== */

struct sockaddr_storage irc_nsaddr_list[IRCD_MAXNS];
int irc_nscount = 0;

static char irc_domain[IRCD_RES_HOSTLEN + 1];

/* =========================================================================
 * Compatibility variables expected by dns.mod/dns.c
 *
 * dns.mod/dns.c includes coredns.c (now replaced by this file via the
 * Makefile), and references several names that live here:
 *   resfd            — the raw UDP socket fd
 *   expireresolves   — used by dns_free_cache() / dns_cache_expmem()
 *   myres            — used by dns_change() TCL trace and dns_report()
 *
 * We provide thin compatibility shims so dns.mod/dns.c compiles unchanged.
 * ====================================================================== */

/* resfd: the UDP socket file descriptor used by dns.mod/dns.c for
 * DCC_DNS registration and eof_dns_socket recovery.
 * resfd_family: the address family (AF_INET or AF_INET6) of resfd.
 * Nameservers whose family doesn't match resfd_family are skipped when
 * sending UDP queries, preventing silent EAFNOSUPPORT failures in mixed
 * IPv4/IPv6 resolver configurations. */
static int resfd        = -1;
static int resfd_family = AF_INET;

/* expireresolves: kept nullptr; dns_free_cache() / dns_cache_expmem() in
 * dns.mod/dns.c iterate this list, but with the new resolver all
 * memory is managed internally per-query.  The cache concept from the
 * old coredns.c no longer applies; we return 0 / nullptr safely. */
static struct resolve *expireresolves [[maybe_unused]] = nullptr;

/* myres: struct __res_state used by dns_change() and dns_report() in
 * dns.mod/dns.c to get/set nameserver addresses via TCL "dns-servers"
 * and to display them in .status.  We populate myres.nsaddr_list[] and
 * myres.nscount to mirror irc_nsaddr_list[]/irc_nscount. */
#ifdef res_ninit
#define MY_RES_INIT() res_ninit(&myres)
struct __res_state myres;
#else
#define MY_RES_INIT() res_init()
#define myres _res
#endif

/* Sync myres nameserver list from irc_nsaddr_list */
static void sync_myres_from_irc(void) {
  myres.nscount = 0;
  for (int i = 0; i < irc_nscount && i < MAXNS; i++) {
    if (GET_SS_FAMILY(&irc_nsaddr_list[i]) == AF_INET) {
      memcpy(&myres.nsaddr_list[myres.nscount],
             &irc_nsaddr_list[i],
             sizeof(struct sockaddr_in));
      myres.nscount++;
    }
  }
}

/* Sync irc_nsaddr_list from myres (called after dns_change() TCL write) */
[[maybe_unused]] static void sync_irc_from_myres(void) {
  irc_nscount = 0;
  for (int i = 0; i < myres.nscount && i < IRCD_MAXNS; i++) {
    memset(&irc_nsaddr_list[irc_nscount], 0,
           sizeof(irc_nsaddr_list[irc_nscount]));
    memcpy(&irc_nsaddr_list[irc_nscount],
           &myres.nsaddr_list[i],
           sizeof(struct sockaddr_in));
    irc_nscount++;
  }
}

/* =========================================================================
 * DNS name codec
 * ====================================================================== */

static int dns_name_encode(unsigned char *dst, size_t dstlen, const char *name)
{
  unsigned char *p   = dst;
  unsigned char *end = dst + dstlen;
  const char    *src = name;

  while (*src) {
    const char *dot = src;
    while (*dot && *dot != '.')
      dot++;

    size_t lablen = (size_t)(dot - src);

    if (lablen == 0) {
      src = dot + (*dot == '.' ? 1 : 0);
      continue;
    }
    if (lablen > DNS_MAXLABEL)
      return -1;
    if (p + 1 + lablen >= end)
      return -1;

    *p++ = (unsigned char)lablen;
    memcpy(p, src, lablen);
    p  += lablen;
    src = dot + (*dot == '.' ? 1 : 0);
  }

  if (p >= end)
    return -1;
  *p++ = 0;
  return (int)(p - dst);
}

static int dns_name_decode(const unsigned char *msg, size_t msglen,
                           size_t off, char *dst, size_t dstlen)
{
  const unsigned char *p        = msg + off;
  const unsigned char *msg_end  = msg + msglen;
  char                *d        = dst;
  char                *d_end    = dst + dstlen;
  int                  jumped   = 0;
  size_t               consumed = 0;
  int                  hops     = 0;

  while (p < msg_end) {
    unsigned int n = (unsigned int)*p;

    if ((n & DNS_PTR_HI) == DNS_PTR_HI) {
      if (p + 1 >= msg_end)
        return -1;
      if (!jumped)
        consumed = (size_t)(p - (msg + off)) + 2;
      size_t new_off = ((n & 0x3F) << 8) | (unsigned int)p[1];
      if (new_off >= msglen)
        return -1;
      p      = msg + new_off;
      jumped = 1;
      if (++hops > 16)
        return -1;

    } else if ((n & DNS_PTR_HI) == 0) {
      p++;
      if (n == 0)
        break;
      if (p + n > msg_end)
        return -1;
      if (d != dst) {
        if (d >= d_end - 1)
          return -1;
        *d++ = '.';
      }
      if ((size_t)(d_end - d) <= n)
        return -1;
      {
        unsigned int i;
        for (i = 0; i < n; i++)
          *d++ = (char)tolower((unsigned char)*p++);
      }
    } else {
      return -1;
    }
  }

  if (d >= d_end)
    return -1;
  *d = '\0';

  if (!jumped)
    consumed = (size_t)(p - (msg + off));
  return (int)consumed;
}

static int dns_name_skip(const unsigned char *msg, size_t msglen, size_t off)
{
  const unsigned char *p     = msg + off;
  const unsigned char *end   = msg + msglen;
  const unsigned char *start = p;

  while (p < end) {
    unsigned int n = (unsigned int)*p;
    if ((n & DNS_PTR_HI) == DNS_PTR_HI) {
      if (p + 1 >= end)
        return -1;
      return (int)((p - start) + 2);
    } else if ((n & DNS_PTR_HI) == 0) {
      p++;
      if (n == 0)
        return (int)(p - start);
      if (p + n > end)
        return -1;
      p += n;
    } else {
      return -1;
    }
  }
  return -1;
}

/* =========================================================================
 * DNS query packet builder
 * ====================================================================== */

/* dns_build_query — build a DNS query packet.
 *
 * When use_edns is non-zero, appends an EDNS0 OPT pseudo-RR (RFC 6891)
 * that advertises DNS_EDNS0_PAYLOAD bytes of UDP receive capacity.  This
 * allows the resolver to return responses larger than the legacy 512-byte
 * limit, avoiding truncation for common record types (AAAA, many A
 * records, TXT, etc.).
 *
 * DoT callers pass use_edns=0: DoT uses TCP framing so there is no UDP
 * payload limit, and the OPT record adds unnecessary overhead.
 *
 * Returns the packet length on success, -1 on error.
 */
static int dns_build_query(unsigned char *buf, size_t buflen,
                           uint16_t id, uint16_t qtype, const char *name,
                           int use_edns)
{
  int off, n;
  /* OPT record: 1-byte root name + 2 type + 2 class + 4 TTL + 2 rdlen = 11 */
  const size_t opt_size = 11;
  size_t       min_size = DNS_HDR_SIZE + 4 + (use_edns ? opt_size : 0);

  if (buflen < min_size)
    return -1;

  memset(buf, 0, DNS_HDR_SIZE);
  hdr_put_u16(buf + 0, id);
  hdr_put_u16(buf + 2, 0x0100);              /* QR=0, RD=1 */
  hdr_put_u16(buf + 4, 1);                   /* QDCOUNT=1 */
  hdr_put_u16(buf + 10, use_edns ? 1 : 0);  /* ARCOUNT=1 for OPT */

  off = DNS_HDR_SIZE;
  n   = dns_name_encode(buf + off, buflen - (size_t)off - 4
                        - (use_edns ? opt_size : 0), name);
  if (n < 0)
    return -1;
  off += n;

  if ((size_t)off + 4 + (use_edns ? opt_size : 0) > buflen)
    return -1;

  hdr_put_u16(buf + off,     qtype);
  hdr_put_u16(buf + off + 2, DNS_CLASS_IN);
  off += 4;

  if (use_edns) {
    /* OPT RR (RFC 6891 §6.1.2):
     *   NAME:   0x00  (root / empty name)
     *   TYPE:   41    (OPT)
     *   CLASS:  UDP payload size
     *   TTL:    0     (extended RCODE=0, version=0, flags=0)
     *   RDLEN:  0     (no option data)
     */
    buf[off++] = 0x00;                            /* root name */
    hdr_put_u16(buf + off, DNS_TYPE_OPT);  off += 2;
    hdr_put_u16(buf + off, DNS_EDNS0_PAYLOAD); off += 2;
    buf[off++] = 0; buf[off++] = 0;              /* ext-RCODE, version */
    buf[off++] = 0; buf[off++] = 0;              /* DNSSEC flags (DO=0) */
    hdr_put_u16(buf + off, DNS_OPT_RDLEN); off += 2;  /* RDLEN=0 */
  }

  return off;
}

/* =========================================================================
 * resolv.conf parser
 * ====================================================================== */

static void add_nameserver(const char *addr_str)
{
  struct addrinfo hints = {}, *res;

  if (irc_nscount >= IRCD_MAXNS)
    return;
  hints.ai_family   = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags    = AI_NUMERICHOST;

  if (getaddrinfo(addr_str, "53", &hints, &res) != 0 || res == nullptr)
    return;
  if (res->ai_addrlen <= (socklen_t)sizeof irc_nsaddr_list[0]) {
    memcpy(&irc_nsaddr_list[irc_nscount], res->ai_addr, res->ai_addrlen);
    irc_nscount++;
  }
  freeaddrinfo(res);
}

static void parse_resolv_conf(void)
{
  FILE *f = fopen("/etc/resolv.conf", "r");
  char  line[256];
  char *p, *kw, *val, *ve, *nl;

  if (f == nullptr) {
    add_nameserver("127.0.0.1");
    return;
  }

  while (fgets(line, sizeof line, f)) {
    nl = strpbrk(line, "\r\n");
    if (nl) *nl = '\0';

    p = line;
    while (isspace((unsigned char)*p))
      p++;
    if (*p == '#' || *p == ';' || *p == '\0')
      continue;

    kw = p;
    while (*p && !isspace((unsigned char)*p))
      p++;
    if (!*p)
      continue;
    *p++ = '\0';

    while (isspace((unsigned char)*p))
      p++;
    val = p;
    ve  = val + strlen(val);
    while (ve > val && isspace((unsigned char)ve[-1]))
      ve--;
    *ve = '\0';

    if (op_strcasecmp(kw, "nameserver") == 0) {
      add_nameserver(val);
    } else if (op_strcasecmp(kw, "domain") == 0 ||
               op_strcasecmp(kw, "search") == 0) {
      if (irc_domain[0] == '\0') {
        char *sp = val;
        while (*sp && !isspace((unsigned char)*sp))
          sp++;
        *sp = '\0';
        op_strlcpy(irc_domain, val, sizeof irc_domain);
      }
    }
  }
  fclose(f);

  if (irc_nscount == 0)
    add_nameserver("127.0.0.1");
}

/* =========================================================================
 * In-flight query tracking
 * ====================================================================== */

struct dns_req {
  uint16_t                    id;
  int                         type;
  int                         retries;
  time_t                      sent_at;
  int                         timeout;
  int                         last_ns;
  int                         cname_depth;  /* CNAME hops followed so far */
  char                        qname[IRCD_RES_HOSTLEN + 1];
  struct sockaddr_storage     orig_addr;
  char                        hostname[IRCD_RES_HOSTLEN + 1];
  struct DNSQuery            *query;
};

static op_vec_t  req_vec;
static op_bh    *dns_req_bh = nullptr;   /* block allocator for dns_req */
static int            ns_failures[IRCD_MAXNS];

/* =========================================================================
 * DoT (DNS over TLS) — state
 *
 * Guarded by the eggdrop-wide TLS compile flag (#ifdef TLS), which is
 * set by the build system when OpenSSL support is present.  We alias
 * EGG_TLS -> TLS so that the guard names used throughout this file stay
 * consistent with the original design.
 *
 * Architecture (RFC 7858):
 *   dot_fd:     eggdrop socket fd of the persistent TLS/TCP connection
 *               to the DoT resolver.  -1 when not connected.
 *   dot_active: 1 when the TLS handshake has completed and the channel
 *               is ready for queries.
 *   dot_host:   DoT server hostname, used for SNI in ssl_handshake().
 *
 * Send path (send_dns_query, #ifdef EGG_TLS):
 *   When dot_active, prefix the DNS wire packet with a 2-byte big-endian
 *   length field and write it via tputs(dot_fd, ...).  tputs() routes
 *   through the socklist SSL pointer set up by ssl_handshake(), so TLS
 *   framing is transparent.
 *
 * Receive path (res_read_dns, renamed from res_read_udp):
 *   When dot_active, call SSL_read() directly to receive the 2-byte
 *   length prefix then the payload, then hand the packet to
 *   process_answer() as usual.  Falls through to UDP recvfrom() when
 *   dot_active == 0.
 *
 * Connection setup (res_enable_dot):
 *   1. getsock(AF, SOCK_STREAM) allocates a TCP fd in eggdrop's socklist.
 *   2. connect() is called directly (avoids open_telnet_raw which assumes
 *      a dcc[] entry exists for the socket).
 *   3. ssl_handshake(dot_fd, TLS_CONNECT, verify_flags, LOG_MISC, dot_host, nullptr)
 *      wraps the fd in an OpenSSL session.  When dot_verify != 0 (default),
 *      TLS_VERIFYPEER is passed so eggdrop's ssl_verify() callback enforces
 *      full chain validation and CN/SAN hostname matching (RFC 7858 §3.2).
 *      Pass verify=0 only for private/self-signed resolvers.
 *   4. On success dot_active = 1; on failure killsock(dot_fd) and
 *      dot_fd = -1.
 * ====================================================================== */


constexpr int DOT_RECONNECT_DELAY = 30; /* seconds between reconnect attempts */

#ifdef EGG_TLS
static int  dot_active = 0;
static int  dot_fd     = -1;                    /* TLS/TCP fd, -1 = closed */
static int  dot_verify = 1;                     /* 1 = verify server cert (default) */
static char dot_host[IRCD_RES_HOSTLEN + 1];     /* hostname for SNI        */

/* Saved DoT server address and port for automatic reconnects */
static struct sockaddr_storage dot_sa_saved;
static uint16_t                dot_port_saved = 0;
static int                     dot_sa_valid   = 0; /* 1 when saved addr is set */

/* DoT receive reassembly buffer.
 *
 * RFC 7858 §3.3: each DNS message is framed with a 2-byte big-endian length
 * prefix.  SSL_read() may legally return fewer bytes than requested (partial
 * TLS records).  Without buffering, a partial read of the 2-byte length
 * prefix desynchronises the stream permanently.
 *
 * State machine:
 *   dot_rx_phase == 0: accumulating the 2-byte length prefix in dot_rxbuf[0..1]
 *   dot_rx_phase == 1: accumulating the DNS payload in dot_rxbuf[2..2+msglen-1]
 *
 * dot_rxoff  = bytes valid in dot_rxbuf so far for the current phase
 * dot_rxneed = total bytes needed for the current phase
 */
#define DOT_RXBUF_SIZE (2 + DNS_HDR_SIZE + DNS_MAXPKT)
static unsigned char dot_rxbuf[DOT_RXBUF_SIZE];
static int           dot_rxoff   = 0;  /* bytes accumulated */
static int           dot_rxneed  = 2;  /* bytes needed to finish current phase */
static int           dot_rx_phase = 0; /* 0 = length prefix, 1 = payload */
/* Reset reassembly state — call whenever the DoT connection is torn down */
#define DOT_RX_RESET() do { dot_rxoff = 0; dot_rxneed = 2; dot_rx_phase = 0; } while(0)
#endif

/* =========================================================================
 * Query list helpers
 * ====================================================================== */

static struct dns_req *find_req_by_id(uint16_t id)
{
  for (size_t i = 0; i < req_vec.size; i++) {
    struct dns_req *r = (struct dns_req *)op_vec_get(&req_vec, i);
    if (r->id == id)
      return r;
  }
  return nullptr;
}

static uint16_t next_query_id(void)
{
  uint16_t id;
  do {
    res_get_random(&id, sizeof id);
  } while (id == 0 || find_req_by_id(id));
  return id;
}

static void send_dns_query(struct dns_req *req);

static struct dns_req *make_req(struct DNSQuery *query, int type)
{
  struct dns_req *req = op_bh_alloc(dns_req_bh); /* zeroed by op_bh_alloc */
  req->id      = next_query_id();
  req->type    = type;
  req->retries = DNS_MAX_RETRIES;
  req->sent_at = op_current_time();
  req->timeout = DNS_INITIAL_TIMEOUT;
  req->last_ns = -1;
  req->query   = query;
  op_vec_push(&req_vec, req);
  return req;
}

static void free_req(struct dns_req *req)
{
  op_vec_remove_ptr(&req_vec, req);
  op_bh_free(dns_req_bh, req);
}

/* =========================================================================
 * Nameserver selection
 * ====================================================================== */

static int choose_ns(int attempt)
{
  int i, ns;

  if (irc_nscount == 0)
    return -1;

  for (i = 0; i < irc_nscount; i++) {
    ns = (i + attempt) % irc_nscount;
    if (ns_failures[ns] == 0)
      return ns;
  }
  return attempt % irc_nscount;
}

static void send_dns_query(struct dns_req *req)
{
  unsigned char buf[DNS_MAXPKT];
  uint16_t      qtype;
  int           pktlen, attempt, ns;
  const struct sockaddr_storage *sa;
  ssize_t       sent;

#ifdef EGG_TLS
  if (dot_active && dot_fd >= 0) {
    /* DoT send path (RFC 7858):
     * Prefix the DNS wire packet with a 2-byte big-endian message
     * length field, then write the framed packet via tputs().
     * tputs() routes through the socklist ssl pointer established by
     * ssl_handshake(), so TLS encryption is transparent.
     */
    unsigned char framed[2 + DNS_MAXPKT];
    qtype  = (uint16_t)(req->type & ~DNS_FLAG_FCRDNS);
    pktlen = dns_build_query(framed + 2, sizeof framed - 2,
                             req->id, qtype, req->qname, 0 /* no EDNS0 over TCP */);
    if (pktlen < 0) {
      idebug("res: DoT dns_build_query failed for %s", req->qname);
      return;
    }
    framed[0] = (unsigned char)((unsigned)pktlen >> 8);
    framed[1] = (unsigned char)((unsigned)pktlen & 0xff);
    tputs(dot_fd, (char *)framed, (unsigned int)(pktlen + 2));
    /* DoT uses a single long-lived TCP connection; there is no
     * per-server index to track, so leave req->last_ns at -1. */
    return;
  }
#endif

  if (resfd < 0)
    return;

  qtype  = (uint16_t)(req->type & ~DNS_FLAG_FCRDNS);
  pktlen = dns_build_query(buf, sizeof buf, req->id, qtype, req->qname,
                           1 /* EDNS0: advertise 4096-byte UDP payload */);
  if (pktlen < 0) {
    idebug("res: dns_build_query failed for %s", req->qname);
    return;
  }

  attempt = DNS_MAX_RETRIES - req->retries;
  ns      = choose_ns(attempt);
  if (ns < 0 || ns >= irc_nscount)
    return;

  /* Skip nameservers whose address family doesn't match the UDP socket.
   * A mixed IPv4/IPv6 resolv.conf would otherwise cause sendto() to fail
   * with EAFNOSUPPORT, silently dropping the query until it times out. */
  {
    for (int i = 0; i < irc_nscount; i++) {
      int try_ns = (ns + i) % irc_nscount;
      if ((int)GET_SS_FAMILY(&irc_nsaddr_list[try_ns]) == resfd_family) {
        ns = try_ns;
        break;
      }
    }
    if ((int)GET_SS_FAMILY(&irc_nsaddr_list[ns]) != resfd_family) {
      idebug("res: no nameserver matches UDP socket family (af=%d)", resfd_family);
      return;
    }
  }

  sa   = &irc_nsaddr_list[ns];
  sent = sendto(resfd, buf, (size_t)pktlen, 0,
                (const struct sockaddr *)sa, GET_SS_LEN(sa));
  if (sent == (ssize_t)pktlen)
    req->last_ns = ns;
}

/* =========================================================================
 * Response parser
 * ====================================================================== */

static void handle_req_done(struct dns_req *req, struct DNSReply *reply);
static void start_fcrdns_check(struct dns_req *ptr_req);

static int process_answer(struct dns_req *req,
                          const unsigned char *pkt, size_t pktlen)
{
  size_t   off;
  uint16_t ancount, ai;
  int      base_type, rcode;

  if (pktlen < DNS_HDR_SIZE)
    return 0;
  if (HDR_ID(pkt) != req->id)
    return 0;
  if (HDR_QR(pkt) != 1)
    return 0;
  /* Must be a standard QUERY response (OPCODE 0).
   * Responses with OPCODE 2 (STATUS), 4 (NOTIFY), 5 (UPDATE), etc.
   * are not answers to our queries and must be discarded. */
  if (HDR_OPCODE(pkt) != 0)
    return 0;
  /* QDCOUNT should echo the single question we sent.
   * A value != 1 indicates a malformed or mismatched response. */
  if (HDR_QDCOUNT(pkt) != 1)
    return 0;

  rcode = HDR_RCODE(pkt);

  /* TC (Truncation) bit: UDP response was truncated at the wire level.
   * With EDNS0 in queries this should be rare (resolvers can send up to
   * DNS_EDNS0_PAYLOAD bytes).  Treat as a transient failure so the
   * timeout/retry loop retries the query.  If DoT is available the
   * retry will use TCP framing and avoid truncation entirely. */
  if (HDR_FLAGS(pkt) & DNS_FLAG_TC) {
    putlog(LOG_MISC, "*",
           "DNS: truncated response for %s — retrying (enable DoT to avoid)",
           req->qname);
    if (req->last_ns >= 0 && req->last_ns < IRCD_MAXNS)
      ns_failures[req->last_ns]++;
    return 1;
  }

  if (rcode == DNS_RC_SERVFAIL || rcode == DNS_RC_NOTIMP ||
      rcode == DNS_RC_REFUSED) {
    if (req->last_ns >= 0 && req->last_ns < IRCD_MAXNS)
      ns_failures[req->last_ns]++;
    return 1;
  }
  if (rcode == DNS_RC_NXDOMAIN) {
    if (req->last_ns >= 0 && req->last_ns < IRCD_MAXNS)
      ns_failures[req->last_ns] /= 4;
    handle_req_done(req, nullptr);
    return 1;
  }
  if (rcode != DNS_RC_NOERR || HDR_ANCOUNT(pkt) == 0) {
    handle_req_done(req, nullptr);
    return 1;
  }

  /* Skip question section — QDCOUNT is validated as 1 above, so exactly
   * one question name + QTYPE/QCLASS (4 bytes) follows the header. */
  {
    int n;
    off = DNS_HDR_SIZE;
    n   = dns_name_skip(pkt, pktlen, off);
    if (n < 0)
      return 0;
    off += (size_t)n;
    if (off + 4 > pktlen)
      return 0;
    off += 4;
  }

  /* Process answer RRs.  Cap ANCOUNT to avoid tight loops on malformed
   * responses with absurdly large wire counts (e.g. 65535 with a 200-byte
   * packet).  The loop already breaks on out-of-bounds access, but the
   * cap makes the worst case explicit and cheap. */
  ancount   = HDR_ANCOUNT(pkt);
  if (ancount > DNS_MAX_ANCOUNT)
    ancount = DNS_MAX_ANCOUNT;
  base_type = req->type & ~DNS_FLAG_FCRDNS;

  /* CNAME chain: if all answers are CNAMEs (no matching A/AAAA/PTR), we
   * follow the chain by issuing a fresh query for the canonical name. */
  char cname_target[IRCD_RES_HOSTLEN + 1];
  cname_target[0] = '\0';

  for (ai = 0; ai < ancount; ai++) {
    uint16_t rrtype, rdlen;
    int n = dns_name_skip(pkt, pktlen, off);
    if (n < 0)
      break;
    off += (size_t)n;

    if (off + 10 > pktlen)
      break;

    rrtype = hdr_u16(pkt + off);
    rdlen  = hdr_u16(pkt + off + 8);
    off   += 10;

    if (off + rdlen > pktlen)
      break;

    if (rrtype == DNS_TYPE_CNAME) {
      /* Decode the canonical name so we can follow the chain if needed */
      char cname_buf[IRCD_RES_HOSTLEN + 1];
      int nc = dns_name_decode(pkt, pktlen, off, cname_buf, sizeof cname_buf);
      if (nc > 0 && cname_buf[0] != '\0')
        op_strlcpy(cname_target, cname_buf, sizeof cname_target);
      off += rdlen;
      continue;
    }

    if (rrtype == DNS_TYPE_A && base_type == DNS_TYPE_A) {
      if (rdlen != 4) { off += rdlen; continue; }

      struct DNSReply reply = {};
      struct sockaddr_in *v4;
      v4 = (struct sockaddr_in *)&reply.addr;
      v4->sin_family = AF_INET;
      memcpy(&v4->sin_addr, pkt + off, 4);

      if (req->last_ns >= 0 && req->last_ns < IRCD_MAXNS)
        ns_failures[req->last_ns] /= 4;
      handle_req_done(req, &reply);
      return 1;
    }

#ifdef IPV6
    if (rrtype == DNS_TYPE_AAAA && base_type == DNS_TYPE_AAAA) {
      if (rdlen != 16) { off += rdlen; continue; }

      struct DNSReply reply = {};
      struct sockaddr_in6 *v6;
      v6 = (struct sockaddr_in6 *)&reply.addr;
      v6->sin6_family = AF_INET6;
      memcpy(&v6->sin6_addr, pkt + off, 16);

      if (req->last_ns >= 0 && req->last_ns < IRCD_MAXNS)
        ns_failures[req->last_ns] /= 4;
      handle_req_done(req, &reply);
      return 1;
    }
#endif

    if (rrtype == DNS_TYPE_PTR && base_type == DNS_TYPE_PTR) {
      char hostname[IRCD_RES_HOSTLEN + 1];
      int nc = dns_name_decode(pkt, pktlen, off,
                               hostname, sizeof hostname);
      if (nc < 0 || hostname[0] == '\0') {
        off += rdlen;
        continue;
      }
      op_strlcpy(req->hostname, hostname, sizeof req->hostname);

      if (req->last_ns >= 0 && req->last_ns < IRCD_MAXNS)
        ns_failures[req->last_ns] /= 4;
      start_fcrdns_check(req);
      return 1;
    }

    off += rdlen;
  }

  /* No matching RR found.  If we decoded a CNAME target and haven't hit
   * the depth limit, follow the chain by issuing a new query. */
  if (cname_target[0] != '\0' && req->cname_depth < DNS_MAX_CNAME_DEPTH) {
    struct dns_req *cname_req = make_req(req->query,
                                         req->type & ~DNS_FLAG_FCRDNS);
    cname_req->cname_depth = req->cname_depth + 1;
    op_strlcpy(cname_req->qname, cname_target, sizeof cname_req->qname);
    memcpy(&cname_req->orig_addr, &req->orig_addr, sizeof cname_req->orig_addr);
    if (req->type & DNS_FLAG_FCRDNS) {
      cname_req->type |= DNS_FLAG_FCRDNS;
      op_strlcpy(cname_req->hostname, req->hostname, sizeof cname_req->hostname);
    }
    free_req(req);
    send_dns_query(cname_req);
    return 1;
  }

  handle_req_done(req, nullptr);
  return 1;
}

static void start_fcrdns_check(struct dns_req *ptr_req)
{
  int fwd_type;
  struct dns_req *fwd;

#ifdef IPV6
  fwd_type = (GET_SS_FAMILY(&ptr_req->orig_addr) == AF_INET6)
             ? DNS_TYPE_AAAA : DNS_TYPE_A;
#else
  fwd_type = DNS_TYPE_A;
#endif

  fwd = make_req(ptr_req->query, fwd_type | DNS_FLAG_FCRDNS);
  op_strlcpy(fwd->qname,    ptr_req->hostname, sizeof fwd->qname);
  op_strlcpy(fwd->hostname, ptr_req->hostname, sizeof fwd->hostname);
  memcpy(&fwd->orig_addr, &ptr_req->orig_addr, sizeof fwd->orig_addr);

  free_req(ptr_req);
  send_dns_query(fwd);
}

static void handle_req_done(struct dns_req *req, struct DNSReply *reply)
{
  if ((req->type & DNS_FLAG_FCRDNS) && reply != nullptr)
    reply->h_name = req->hostname;

  (*req->query->callback)(req->query, reply);
  free_req(req);
}

/* =========================================================================
 * DNS read — called from DCC_DNS activity handler (dns_ack wrapper).
 *
 * Handles both paths:
 *   - DoT (TLS/TCP): when dot_active, read the RFC 7858 2-byte length
 *     prefix via SSL_read(), then the payload, and process it.
 *   - Plain UDP: the original recvfrom() loop.
 * ====================================================================== */

void res_read_dns(void)
{
  unsigned char              buf[DNS_HDR_SIZE + DNS_MAXPKT];
  uint16_t                   id;
  struct dns_req            *req;

#ifdef EGG_TLS
  if (dot_active && dot_fd >= 0) {
    /* DoT receive path (RFC 7858):
     * Drive the two-phase reassembly state machine (dot_rx_phase /
     * dot_rxbuf) until SSL_read() returns WANT_READ (no more data this
     * tick) or an error.  The state machine survives partial reads across
     * calls, so a short SSL_read() of the 2-byte length prefix or payload
     * simply leaves dot_rxoff < dot_rxneed and resumes next event.
     */
    int idx = findsock(dot_fd);
    if (idx < 0 || !socklist[idx].ssl) {
      /* SSL session gone — disable DoT and schedule reconnect */
      putlog(LOG_MISC, "*",
             "DNS: DoT connection lost (no SSL session); reconnecting in %ds",
             DOT_RECONNECT_DELAY);
      DOT_RX_RESET();
      dot_active = 0;
      killsock(dot_fd);
      dot_fd = -1;
      if (dot_sa_valid)
        dot_reconnect_seconds = DOT_RECONNECT_DELAY;
      return;
    }

    /* Reassembly loop.  opssl_read() may return fewer bytes than requested
     * (partial TLS records).  We drive a two-phase state machine:
     *   phase 0: fill dot_rxbuf[0..1] with the RFC 7858 2-byte length prefix.
     *   phase 1: fill dot_rxbuf[2..2+msglen-1] with the DNS payload.
     * Partial reads simply leave dot_rxoff < dot_rxneed and we return,
     * resuming where we left off on the next readable event. */
    for (;;) {
      ssize_t got = opssl_read(socklist[idx].ssl,
                               dot_rxbuf + dot_rxoff,
                               dot_rxneed - dot_rxoff);
      if (got <= 0) {
        if (got == OPSSL_WANT_READ || got == OPSSL_WANT_WRITE)
          break; /* no more data this tick */
        /* Connection error — reset reassembly state, schedule reconnect */
        dot_rxoff = 0; dot_rxneed = 2; dot_rx_phase = 0;
        putlog(LOG_MISC, "*",
               "DNS: DoT read error (%zd); reconnecting in %ds",
               got, DOT_RECONNECT_DELAY);
        dot_active = 0;
        killsock(dot_fd);
        dot_fd = -1;
        if (dot_sa_valid)
          dot_reconnect_seconds = DOT_RECONNECT_DELAY;
        return;
      }
      dot_rxoff += got;

      if (dot_rxoff < dot_rxneed)
        break; /* still accumulating — wait for more data */

      if (dot_rx_phase == 0) {
        /* Completed the 2-byte length prefix */
        uint16_t msglen = ((uint16_t)dot_rxbuf[0] << 8) | dot_rxbuf[1];
        if (msglen == 0 || msglen > (uint16_t)(DNS_HDR_SIZE + DNS_MAXPKT)) {
          /* Malformed frame — reset and reconnect to recover stream sync */
          dot_rxoff = 0; dot_rxneed = 2; dot_rx_phase = 0;
          putlog(LOG_MISC, "*",
                 "DNS: DoT malformed frame (len=%u); reconnecting", msglen);
          dot_active = 0;
          killsock(dot_fd);
          dot_fd = -1;
          if (dot_sa_valid)
            dot_reconnect_seconds = DOT_RECONNECT_DELAY;
          return;
        }
        /* Transition to payload phase */
        dot_rx_phase = 1;
        dot_rxoff    = 0;
        dot_rxneed   = (int)msglen;
      } else {
        /* Completed the DNS payload — process it */
        uint16_t    msglen = (uint16_t)dot_rxneed;
        if ((size_t)msglen > DNS_HDR_SIZE) {
          id  = HDR_ID(dot_rxbuf);
          req = find_req_by_id(id);
          if (req != nullptr)
            process_answer(req, dot_rxbuf, (size_t)msglen);
        }
        /* Reset to read next message */
        dot_rxoff    = 0;
        dot_rxneed   = 2;
        dot_rx_phase = 0;
      }
    }
    return; /* DoT path handled; skip UDP */
  }
#endif /* EGG_TLS */

  /* Plain UDP receive path */
  {
    struct sockaddr_storage    from;
    socklen_t                  fromlen = sizeof from;
    ssize_t                    rc;

    if (resfd < 0)
      return;

    for (;;) {
      rc = recvfrom(resfd, buf, sizeof buf, 0,
                    (struct sockaddr *)&from, &fromlen);
      if (rc <= 0)
        break;
      if ((size_t)rc <= DNS_HDR_SIZE)
        continue;

      /* Accept only replies from configured nameservers */
      {
        int trusted = 0, i;
        for (i = 0; i < irc_nscount && !trusted; i++) {
          const struct sockaddr_storage *ns = &irc_nsaddr_list[i];
          if (GET_SS_FAMILY(ns) != GET_SS_FAMILY(&from))
            continue;
          if (GET_SS_FAMILY(ns) == AF_INET) {
            const struct sockaddr_in *a = (const struct sockaddr_in *)ns;
            const struct sockaddr_in *b = (const struct sockaddr_in *)&from;
            trusted = (a->sin_addr.s_addr == b->sin_addr.s_addr
                       && a->sin_port == b->sin_port);
          }
#ifdef IPV6
          else if (GET_SS_FAMILY(ns) == AF_INET6) {
            const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)ns;
            const struct sockaddr_in6 *b = (const struct sockaddr_in6 *)&from;
            trusted = (memcmp(&a->sin6_addr, &b->sin6_addr,
                              sizeof a->sin6_addr) == 0
                       && a->sin6_port == b->sin6_port);
          }
#endif
        }
        if (!trusted)
          continue;
      }

      id  = HDR_ID(buf);
      req = find_req_by_id(id);
      if (req == nullptr)
        continue;

      process_answer(req, buf, (size_t)rc);
    }
  }
}

/* Backward-compat alias: dns.c calls res_read_udp() in dns_ack(). */
void res_read_udp(void) { res_read_dns(); }

/* =========================================================================
 * Timeout / retry — driven by res_secondly_check() via HOOK_SECONDLY
 * ====================================================================== */

static void timeout_resolver([[maybe_unused]] void *unused)
{
  time_t t = op_current_time();
  /* Iterate backwards so free_req's op_vec_remove_ptr doesn't skip elements */
  for (size_t i = req_vec.size; i-- > 0; ) {
    struct dns_req *req = (struct dns_req *)op_vec_get(&req_vec, i);

    if (t < req->sent_at + req->timeout)
      continue;

    if (req->last_ns >= 0 && req->last_ns < IRCD_MAXNS)
      ns_failures[req->last_ns]++;

    if (--req->retries <= 0) {
      (*req->query->callback)(req->query, nullptr);
      free_req(req);
      continue;
    }

    req->timeout *= 2;
    req->sent_at  = t;
    send_dns_query(req);
  }
}

/* Called every second from HOOK_SECONDLY (registered in dns.mod/dns.c
 * as dns_check_expires, which maps to this function). */
void res_secondly_check(void)
{
  if (++res_timer_seconds >= DNS_TIMER_INTERVAL) {
    res_timer_seconds = 0;
    timeout_resolver(nullptr);
  }

#ifdef EGG_TLS
  if (dot_reconnect_seconds > 0 && --dot_reconnect_seconds == 0) {
    dot_reconnect_seconds = -1;
    if (dot_sa_valid && !dot_active) {
      putlog(LOG_MISC, "*", "DNS: attempting DoT reconnect to saved server");
      res_enable_dot(&dot_sa_saved, dot_host, dot_port_saved, dot_verify);
    }
  }
#endif
}

/* =========================================================================
 * Network initialisation
 * ====================================================================== */

static void dns_commio_read_cb(op_fde_t *F, void *data)
{
  (void)F;
  (void)data;
  res_read_dns();
}

static int init_dns_network(void)
{
  int family, flags;

  family = (irc_nscount > 0 && GET_SS_FAMILY(&irc_nsaddr_list[0]) == AF_INET6)
           ? AF_INET6 : AF_INET;

  resfd = socket(family, SOCK_DGRAM, 0);
  resfd_family = family;
  if (resfd < 0) {
    putlog(LOG_MISC, "*",
           "DNS: Unable to allocate UDP socket: %s", strerror(errno));
    return 0;
  }

  flags = fcntl(resfd, F_GETFL, 0);
  if (flags < 0 || fcntl(resfd, F_SETFL, flags | O_NONBLOCK) < 0) {
    putlog(LOG_MISC, "*",
           "DNS: Unable to set UDP socket non-blocking: %s", strerror(errno));
    close(resfd);
    resfd = -1;
    return 0;
  }

  if (allocsock(resfd, SOCK_PASS) == -1) {
    putlog(LOG_MISC, "*",
           "DNS: Unable to allocate socket in socklist");
    close(resfd);
    resfd = -1;
    return 0;
  }

  {
    op_fde_t *F = op_get_fde(resfd);
    if (F)
      op_setselect(F, OP_SELECT_READ, dns_commio_read_cb, nullptr);
  }

  return 1;
}

/* =========================================================================
 * Public API — init / restart
 * ====================================================================== */

static void start_resolver(void)
{
  irc_nscount   = 0;
  irc_domain[0] = '\0';
  memset(ns_failures, 0, sizeof ns_failures);
  parse_resolv_conf();
  sync_myres_from_irc();

  if (resfd < 0) {
    if (!init_dns_network())
      putlog(LOG_MISC, "*",
             "DNS: Warning — could not create DNS UDP socket");
  }

  res_timer_seconds = 0;
}

void init_resolver(void)
{
  MY_RES_INIT();
  start_resolver();
}

void restart_resolver(void)
{
  /* Cancel all pending queries */
  for (size_t i = req_vec.size; i-- > 0; ) {
    struct dns_req *req = (struct dns_req *)op_vec_get(&req_vec, i);
    (*req->query->callback)(req->query, nullptr);
    free_req(req);
  }

  if (resfd >= 0) {
    killsock(resfd);
    resfd = -1;
  }

#ifdef EGG_TLS
  DOT_RX_RESET();
  dot_active = 0;
  dot_reconnect_seconds = -1;
  dot_sa_valid = 0;
  if (dot_fd >= 0) {
    killsock(dot_fd);
    dot_fd = -1;
  }
#endif

  start_resolver();
}

/* =========================================================================
 * Public API — forward / reverse lookups
 * ====================================================================== */

void gethost_byname_type(const char *name, struct DNSQuery *query, int type)
{
  struct dns_req *req;
  char fqdn[IRCD_RES_HOSTLEN + 1];

  if (!name || !query)
    return;

  req = make_req(query, type);

  op_strlcpy(fqdn, name, sizeof fqdn);
  if (irc_domain[0] && strchr(fqdn, '.') == nullptr) {
    size_t nl = strlen(fqdn);
    if (nl + 1 + strlen(irc_domain) < sizeof fqdn) {
      fqdn[nl++] = '.';
      op_strlcpy(fqdn + nl, irc_domain, sizeof fqdn - nl);
    }
  }

  op_strlcpy(req->qname, fqdn, sizeof req->qname);
  send_dns_query(req);
}

void gethost_byaddr(const struct sockaddr_storage *addr,
                    struct DNSQuery *query)
{
  struct dns_req *req;

  if (!addr || !query)
    return;

  req = make_req(query, DNS_TYPE_PTR);
  memcpy(&req->orig_addr, addr, sizeof req->orig_addr);
  build_rdns(req->qname, sizeof req->qname, addr, nullptr);
  send_dns_query(req);
}

/* =========================================================================
 * DoT — enable / disable
 * ====================================================================== */

#ifdef EGG_TLS
/*
 * res_enable_dot() — open a TLS/TCP connection to the DoT server.
 *
 * Steps:
 *   1. Discard any existing DoT connection.
 *   2. Allocate a TCP socket via getsock() (registers it in eggdrop's
 *      socklist so tputs / killsock work correctly).
 *   3. Connect directly to the DoT server address/port.
 *   4. Perform the TLS handshake via ssl_handshake().
 *   5. On success set dot_active = 1.
 *
 * Note: we use a direct connect() rather than open_telnet_raw() because
 * open_telnet_raw() assumes the socket has a matching dcc[] entry, which
 * DoT connections do not have.
 */
void res_enable_dot(const struct sockaddr_storage *sa,
                    const char *addr_str, uint16_t port, int verify)
{
  int   fd, af;
  struct sockaddr_storage target;
  socklen_t               targetlen;

  if (!sa || !addr_str)
    return;

  dot_verify = verify;

  /* Save address for automatic reconnect */
  memcpy(&dot_sa_saved, sa, sizeof dot_sa_saved);
  dot_port_saved = port;
  dot_sa_valid   = 1;

  /* Tear down any existing DoT connection first */
  if (dot_fd >= 0) {
    DOT_RX_RESET();
    dot_active = 0;
    killsock(dot_fd);
    dot_fd = -1;
  }
  dot_reconnect_seconds = -1;

  /* Save the hostname for SNI */
  op_strlcpy(dot_host, addr_str, sizeof dot_host);

  /* Build the target address with the requested port */
  memcpy(&target, sa, sizeof target);
  af = GET_SS_FAMILY(&target);
  if (af == AF_INET) {
    ((struct sockaddr_in *)&target)->sin_port = htons(port ? port : 853);
    targetlen = sizeof(struct sockaddr_in);
  }
#ifdef IPV6
  else if (af == AF_INET6) {
    ((struct sockaddr_in6 *)&target)->sin6_port = htons(port ? port : 853);
    targetlen = sizeof(struct sockaddr_in6);
  }
#endif
  else {
    iwarn("DoT: unsupported address family %d", af);
    return;
  }

  /* Allocate a TCP socket registered in eggdrop's socklist */
  fd = getsock(af, 0);
  if (fd < 0) {
    putlog(LOG_MISC, "*", "DNS: DoT: getsock() failed: %s", strerror(errno));
    return;
  }

  /* Direct TCP connect (non-blocking; EINPROGRESS is OK) */
  if (connect(fd, (const struct sockaddr *)&target, targetlen) < 0 &&
      errno != EINPROGRESS) {
    putlog(LOG_MISC, "*", "DNS: DoT: connect() to %s:%u failed: %s",
           addr_str, (unsigned)port, strerror(errno));
    killsock(fd);
    return;
  }

  dot_fd = fd;

  /* Start TLS handshake.  ssl_handshake() is non-blocking on success;
   * it sets up the SSL * on socklist[i].ssl so tputs() / SSL_read()
   * will use TLS automatically.
   */
  if (ssl_handshake(dot_fd, TLS_CONNECT,
                    dot_verify ? TLS_VERIFYPEER : 0,
                    LOG_MISC, dot_host, nullptr) != 0) {
    putlog(LOG_MISC, "*",
           "DNS: DoT: TLS handshake with %s failed; disabling DoT", addr_str);
    killsock(dot_fd);
    dot_fd = -1;
    return;
  }

  dot_active = 1;
  putlog(LOG_MISC, "*", "DNS: DoT active — using TLS resolver %s port %u",
         addr_str, (unsigned)(port ? port : 853));
}

void res_disable_dot(void)
{
  DOT_RX_RESET();
  dot_active = 0;
  dot_reconnect_seconds = -1;
  dot_sa_valid = 0;
  if (dot_fd >= 0) {
    killsock(dot_fd);
    dot_fd = -1;
  }
  putlog(LOG_MISC, "*", "DNS: DoT disabled");
}

#else /* !EGG_TLS */

void res_enable_dot([[maybe_unused]] const struct sockaddr_storage *sa,
                    [[maybe_unused]] const char *addr_str,
                    [[maybe_unused]] uint16_t port,
                    [[maybe_unused]] int verify)
{
  iwarn("DoT: TLS not compiled in — secure_dns ignored");
}

void res_disable_dot(void)
{
  /* nothing to do when TLS is not compiled in */
}
#endif /* EGG_TLS */

/* =========================================================================
 * build_rdns — build reverse-DNS query string (PTR / DNSBL suffix)
 * ====================================================================== */

void build_rdns(char *buf, size_t size,
                const struct sockaddr_storage *addr, const char *suffix)
{
  const unsigned char *cp;

  if (GET_SS_FAMILY(addr) == AF_INET) {
    const struct sockaddr_in *v4 = (const struct sockaddr_in *)addr;
    cp = (const unsigned char *)&v4->sin_addr.s_addr;
    {
      op_strbuf_t _b = {};
      op_strbuf_init(&_b);
      op_strbuf_appendf(&_b, "%u.%u.%u.%u.%s",
                       (unsigned)cp[3], (unsigned)cp[2],
                       (unsigned)cp[1], (unsigned)cp[0],
                       suffix ? suffix : "in-addr.arpa");
      op_strlcpy(buf, op_strbuf_str(&_b), size);
      op_strbuf_free(&_b);
    }

#ifdef IPV6
  } else if (GET_SS_FAMILY(addr) == AF_INET6) {
    const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)addr;
    cp = (const unsigned char *)&v6->sin6_addr.s6_addr;
    {
      op_strbuf_t _b = {};
      op_strbuf_init(&_b);
      op_strbuf_appendf(&_b,
          "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x."
          "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%s",
          cp[15] & 0xf, cp[15] >> 4,  cp[14] & 0xf, cp[14] >> 4,
          cp[13] & 0xf, cp[13] >> 4,  cp[12] & 0xf, cp[12] >> 4,
          cp[11] & 0xf, cp[11] >> 4,  cp[10] & 0xf, cp[10] >> 4,
          cp[9]  & 0xf, cp[9]  >> 4,  cp[8]  & 0xf, cp[8]  >> 4,
          cp[7]  & 0xf, cp[7]  >> 4,  cp[6]  & 0xf, cp[6]  >> 4,
          cp[5]  & 0xf, cp[5]  >> 4,  cp[4]  & 0xf, cp[4]  >> 4,
          cp[3]  & 0xf, cp[3]  >> 4,  cp[2]  & 0xf, cp[2]  >> 4,
          cp[1]  & 0xf, cp[1]  >> 4,  cp[0]  & 0xf, cp[0]  >> 4,
          suffix ? suffix : "ip6.arpa");
      op_strlcpy(buf, op_strbuf_str(&_b), size);
      op_strbuf_free(&_b);
    }
#endif

  } else {
    if (size > 0) buf[0] = '\0';
  }
}

/* =========================================================================
 * Compatibility API for dns.mod/dns.c
 *
 * dns.mod/dns.c includes coredns.c (now res.c) and calls:
 *   dns_lookup(sockname_t *)     — registered on HOOK_DNS_HOSTBYIP
 *   dns_forward(char *)          — registered on HOOK_DNS_IPBYHOST
 *   dns_check_expires()          — registered on HOOK_SECONDLY
 *   dns_ack()                    — called from DCC_DNS activity handler
 *   init_dns_network()           — called from dns_start() and eof_dns_socket()
 *   init_dns_core()              — called from dns_start()
 *
 * These functions bridge the eggdrop sockname_t / callback convention to
 * the DNSQuery/DNSReply convention used by res.c.
 * ====================================================================== */

/* Per-query callback context: maps a DNSQuery callback to eggdrop events */
struct egg_dns_ctx {
  int     is_reverse;   /* 1 = PTR query, 0 = A/AAAA query */
  int     aftype;       /* AF_INET or AF_INET6 */
  struct  sockaddr_storage orig_addr;  /* for reverse lookups */
  char    hostn[IRCD_RES_HOSTLEN + 1]; /* for forward lookups */
};

static op_bh *egg_dns_ctx_bh = nullptr;
static op_bh *dns_query_bh   = nullptr;

static void egg_forward_cb(void *ptr, struct DNSReply *reply)
{
  struct DNSQuery    *q   = (struct DNSQuery *)ptr;
  struct egg_dns_ctx *ctx = (struct egg_dns_ctx *)q->ptr;
  sockname_t          sn = {};

  if (reply != nullptr) {
    int fam = GET_SS_FAMILY(&reply->addr);
    if (fam == AF_INET) {
      const struct sockaddr_in *v4 = (const struct sockaddr_in *)&reply->addr;
      sn.family  = AF_INET;
      sn.addrlen = sizeof(struct sockaddr_in);
      memcpy(&sn.addr.s4, v4, sizeof(struct sockaddr_in));
      call_ipbyhost(ctx->hostn, &sn, 1);
    }
#ifdef IPV6
    else if (fam == AF_INET6) {
      const struct sockaddr_in6 *v6 =
          (const struct sockaddr_in6 *)&reply->addr;
      sn.family  = AF_INET6;
      sn.addrlen = sizeof(struct sockaddr_in6);
      memcpy(&sn.addr.s6, v6, sizeof(struct sockaddr_in6));
      call_ipbyhost(ctx->hostn, &sn, 1);
    }
#endif
    else {
      call_ipbyhost(ctx->hostn, &sn, 0);
    }
  } else {
    call_ipbyhost(ctx->hostn, &sn, 0);
  }

  op_bh_free(egg_dns_ctx_bh, ctx);
  op_bh_free(dns_query_bh, q);
}

static void egg_reverse_cb(void *ptr, struct DNSReply *reply)
{
  struct DNSQuery    *q   = (struct DNSQuery *)ptr;
  struct egg_dns_ctx *ctx = (struct egg_dns_ctx *)q->ptr;
  sockname_t          sn = {};
  const char         *hostname = nullptr;
  int                 ok = 0;

  /* Reconstruct the sockname_t from the original address */
  if (GET_SS_FAMILY(&ctx->orig_addr) == AF_INET) {
    const struct sockaddr_in *v4 =
        (const struct sockaddr_in *)&ctx->orig_addr;
    sn.family  = AF_INET;
    sn.addrlen = sizeof(struct sockaddr_in);
    memcpy(&sn.addr.s4, v4, sizeof(struct sockaddr_in));
  }
#ifdef IPV6
  else if (GET_SS_FAMILY(&ctx->orig_addr) == AF_INET6) {
    const struct sockaddr_in6 *v6 =
        (const struct sockaddr_in6 *)&ctx->orig_addr;
    sn.family  = AF_INET6;
    sn.addrlen = sizeof(struct sockaddr_in6);
    memcpy(&sn.addr.s6, v6, sizeof(struct sockaddr_in6));
  }
#endif

  if (reply != nullptr && reply->h_name != nullptr && reply->h_name[0] != '\0') {
    /*
     * FCrDNS verification: reply->addr is the forward-confirmed address.
     * Compare it against ctx->orig_addr.
     */
    int orig_af = GET_SS_FAMILY(&ctx->orig_addr);
    int match   = 0;

    if (orig_af == AF_INET && GET_SS_FAMILY(&reply->addr) == AF_INET) {
      const struct sockaddr_in *orig =
          (const struct sockaddr_in *)&ctx->orig_addr;
      const struct sockaddr_in *fwd  =
          (const struct sockaddr_in *)&reply->addr;
      match = (orig->sin_addr.s_addr == fwd->sin_addr.s_addr);
    }
#ifdef IPV6
    else if (orig_af == AF_INET6 &&
             GET_SS_FAMILY(&reply->addr) == AF_INET6) {
      const struct sockaddr_in6 *orig =
          (const struct sockaddr_in6 *)&ctx->orig_addr;
      const struct sockaddr_in6 *fwd  =
          (const struct sockaddr_in6 *)&reply->addr;
      match = (memcmp(&orig->sin6_addr, &fwd->sin6_addr,
                      sizeof(struct in6_addr)) == 0);
    }
#endif

    if (match) {
      hostname = reply->h_name;
      ok = 1;
    }
  }

  if (!hostname)
    hostname = iptostr(&sn.addr.sa);

  call_hostbyip(&sn, (char *)hostname, ok);

  op_bh_free(egg_dns_ctx_bh, ctx);
  op_bh_free(dns_query_bh, q);
}

/*
 * dns_lookup — reverse lookup (IP -> hostname).
 * Registered on HOOK_DNS_HOSTBYIP; receives a sockname_t *.
 */
[[maybe_unused]] static void dns_lookup(sockname_t *addr)
{
  struct egg_dns_ctx *ctx;
  struct DNSQuery    *q;

  if (!addr)
    return;

  if (!egg_dns_ctx_bh) egg_dns_ctx_bh = op_bh_create(sizeof(struct egg_dns_ctx), 16, "egg_dns_ctx");
  if (!dns_query_bh)   dns_query_bh   = op_bh_create(sizeof(struct DNSQuery),    16, "dns_query");
  ctx = (struct egg_dns_ctx *)op_bh_alloc(egg_dns_ctx_bh);
  ctx->is_reverse = 1;
  ctx->aftype     = addr->family;

  if (addr->family == AF_INET) {
    memcpy(&ctx->orig_addr, &addr->addr.s4, sizeof(struct sockaddr_in));
    ((struct sockaddr_in *)&ctx->orig_addr)->sin_family = AF_INET;
  }
#ifdef IPV6
  else if (addr->family == AF_INET6) {
    memcpy(&ctx->orig_addr, &addr->addr.s6, sizeof(struct sockaddr_in6));
    ((struct sockaddr_in6 *)&ctx->orig_addr)->sin6_family = AF_INET6;
  }
#endif
  else {
    op_bh_free(egg_dns_ctx_bh, ctx);
    return;
  }

  q = (struct DNSQuery *)op_bh_alloc(dns_query_bh);
  q->ptr      = ctx;
  q->callback = egg_reverse_cb;

  gethost_byaddr(&ctx->orig_addr, q);
}

/*
 * dns_forward — forward lookup (hostname -> IP).
 * Registered on HOOK_DNS_IPBYHOST; receives a char *.
 */
[[maybe_unused]] static void dns_forward(char *hostn)
{
  struct egg_dns_ctx *ctx;
  struct DNSQuery    *q;
  sockname_t          name;
  int                 g_type;

  if (!hostn || !*hostn)
    return;

  /* If it's already a numeric address, resolve immediately */
  if (setsockname(&name, hostn, 0, 0) != AF_UNSPEC) {
    call_ipbyhost(hostn, &name, 1);
    return;
  }

  if (!egg_dns_ctx_bh) egg_dns_ctx_bh = op_bh_create(sizeof(struct egg_dns_ctx), 16, "egg_dns_ctx");
  if (!dns_query_bh)   dns_query_bh   = op_bh_create(sizeof(struct DNSQuery),    16, "dns_query");
  ctx = (struct egg_dns_ctx *)op_bh_alloc(egg_dns_ctx_bh);
  ctx->is_reverse = 0;
  ctx->aftype     = AF_INET;
  op_strlcpy(ctx->hostn, hostn, sizeof ctx->hostn);

#ifdef IPV6
  g_type = pref_af ? DNS_TYPE_AAAA : DNS_TYPE_A;
#else
  g_type = DNS_TYPE_A;
#endif

  q = (struct DNSQuery *)op_bh_alloc(dns_query_bh);
  q->ptr      = ctx;
  q->callback = egg_forward_cb;

  gethost_byname_type(hostn, q, g_type);
}

/*
 * dns_check_expires — called every second via HOOK_SECONDLY.
 * Delegates to res_secondly_check().
 */
[[maybe_unused]] static void dns_check_expires(void)
{
  res_secondly_check();
}

/*
 * dns_ack — called from DCC_DNS activity handler.
 * Reads pending UDP replies.
 */
[[maybe_unused]] static void dns_ack(void)
{
  res_read_udp();
}

/*
 * init_dns_core — initialise the resolver; returns 1 on success, 0 on error.
 * Called from dns_start() in dns.mod/dns.c.
 */
[[maybe_unused]] static int init_dns_core(void)
{
  if (!dns_req_bh) {
    dns_req_bh = op_bh_create(sizeof(struct dns_req), 64, "dns_req");
    op_vec_init(&req_vec, 64);
  }
  init_resolver();

  if (resfd < 0) {
    putlog(LOG_MISC, "*", "DNS: No nameservers found or socket open failed.");
    return 0;
  }
  if (!myres.nscount) {
    putlog(LOG_MISC, "*", "DNS: No nameservers defined.");
    return 0;
  }
  return 1;
}

void dns_req_cleanup(void)
{
  for (size_t i = req_vec.size; i-- > 0; ) {
    struct dns_req *req = (struct dns_req *)op_vec_get(&req_vec, i);
    (*req->query->callback)(req->query, nullptr);
    op_bh_free(dns_req_bh, req);
  }
  op_vec_fini(&req_vec, nullptr, nullptr);
  if (dns_req_bh) {
    op_bh_destroy(dns_req_bh);
    dns_req_bh = nullptr;
  }
}

/* Provide myres to callers that need it for nameserver management */
#ifndef res_ninit
/* myres is _res from <resolv.h> via the #define above */
#endif
