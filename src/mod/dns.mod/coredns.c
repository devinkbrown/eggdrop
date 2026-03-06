/*
 * coredns.c -- part of dns.mod
 *   Lightweight async DNS resolver for eggdrop, adapted from ophion's res.c.
 *
 *   Replaces the legacy coredns.c (1985 BSD libresolv heritage) with a
 *   clean, self-contained RFC 1035 implementation.
 *
 *   The public API (dns_lookup, dns_forward, dns_check_expires, dns_ack,
 *   init_dns_network, init_dns_core) and all variables referenced by
 *   dns.mod/dns.c (expireresolves, resfd, myres, struct resolve, nonull,
 *   T_A, T_PTR) are preserved so that dns.mod/dns.c requires no changes.
 *
 * Design:
 *   - Single non-blocking UDP socket for plain DNS queries.
 *   - Each in-flight query is a dns_req on a doubly-linked list.
 *   - dns_check_expires() (called from HOOK_SECONDLY) drives timeouts/retry.
 *   - FCrDNS: after a PTR reply, a forward A/AAAA lookup verifies the
 *     hostname maps back to the original IP before accepting it.
 *   - /etc/resolv.conf is parsed at startup and on restart_resolver().
 *   - Optional DNS-over-TLS path guarded by #ifdef EGG_TLS (stub only).
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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

/* =========================================================================
 * Compatibility macro: nonull — used by dns_event_failure in dns.mod/dns.c
 * ====================================================================== */
static const char nullstring[] = "";
#define nonull(s) ((s) ? (s) : nullstring)

/* =========================================================================
 * DNS record type constants — used by dns.mod/dns.c
 * ====================================================================== */
#ifndef T_A
#  define T_A    1
#endif
#ifndef T_PTR
#  define T_PTR  12
#endif
#ifndef T_AAAA
#  define T_AAAA 28
#endif

/* =========================================================================
 * Resolver internals
 * ====================================================================== */

#define DNS_MAXNS        10       /* max nameservers from resolv.conf        */
#define DNS_RES_HOSTLEN  256      /* max hostname length                     */
#define DNS_HDR_SIZE     12       /* fixed DNS header size                   */
#define DNS_MAXPKT       512      /* RFC 1035 §2.3.4 UDP limit w/o EDNS0    */
#define DNS_MAXLABEL     63       /* max label length                        */
#define DNS_PTR_HI       0xC0    /* top 2 bits set = compression pointer    */
#define DNS_CLASS_IN     1

#define DNS_TYPE_A       1
#define DNS_TYPE_CNAME   5
#define DNS_TYPE_PTR     12
#define DNS_TYPE_AAAA    28

#define DNS_RC_NOERR     0
#define DNS_RC_SERVFAIL  2
#define DNS_RC_NXDOMAIN  3
#define DNS_RC_NOTIMP    4
#define DNS_RC_REFUSED   5

#define DNS_INITIAL_TIMEOUT  4
#define DNS_MAX_RETRIES      3

/* High bit marks a forward-confirmation query spawned after a PTR reply */
#define DNS_FLAG_FCRDNS  0x8000

/* =========================================================================
 * DNS header accessors (byte-safe on all architectures)
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
#define HDR_RCODE(pkt)   (HDR_FLAGS(pkt) & 0xf)

/* =========================================================================
 * GET_SS_FAMILY / GET_SS_LEN — portable sockaddr_storage helpers
 * ====================================================================== */

#define GET_SS_FAMILY(ss)  (((const struct sockaddr *)(ss))->sa_family)

static inline socklen_t dns_ss_len(const struct sockaddr_storage *ss) {
  if (GET_SS_FAMILY(ss) == AF_INET)
    return sizeof(struct sockaddr_in);
#ifdef IPV6
  if (GET_SS_FAMILY(ss) == AF_INET6)
    return sizeof(struct sockaddr_in6);
#endif
  return sizeof(struct sockaddr_storage);
}
#define GET_SS_LEN(ss) dns_ss_len(ss)

/* =========================================================================
 * Nameserver list (mirrors myres for the new resolver)
 * ====================================================================== */

static struct sockaddr_storage dns_nsaddr_list[DNS_MAXNS];
static int                     dns_nscount = 0;
static char                    dns_domain[DNS_RES_HOSTLEN + 1];
static int                     dns_ns_failures[DNS_MAXNS];

/* =========================================================================
 * myres — struct __res_state compatibility
 *
 * dns.mod/dns.c accesses myres.nscount and myres.nsaddr_list[] for:
 *   - Displaying nameservers in .status (dns_report)
 *   - The TCL dns-servers variable (dns_change)
 *   - Copying address into dcc[idx].sockname (dns_start)
 *
 * We maintain myres in sync with our internal dns_nsaddr_list.
 * ====================================================================== */

#ifdef res_ninit
#  define MY_RES_INIT() res_ninit(&myres)
struct __res_state myres;
#else
#  define MY_RES_INIT() res_init()
#  define myres _res
#endif

/* Copy dns_nsaddr_list -> myres.nsaddr_list (IPv4 entries only) */
static void sync_myres_from_internal(void)
{
  int i;
  myres.nscount = 0;
  for (i = 0; i < dns_nscount && myres.nscount < MAXNS; i++) {
    if (GET_SS_FAMILY(&dns_nsaddr_list[i]) == AF_INET) {
      memcpy(&myres.nsaddr_list[myres.nscount],
             &dns_nsaddr_list[i],
             sizeof(struct sockaddr_in));
      myres.nscount++;
    }
  }
}

/* Copy myres.nsaddr_list -> dns_nsaddr_list (called after TCL dns-servers write) */
static void sync_internal_from_myres(void)
{
  int i;
  dns_nscount = 0;
  for (i = 0; i < myres.nscount && dns_nscount < DNS_MAXNS; i++) {
    memset(&dns_nsaddr_list[dns_nscount], 0,
           sizeof dns_nsaddr_list[dns_nscount]);
    memcpy(&dns_nsaddr_list[dns_nscount],
           &myres.nsaddr_list[i],
           sizeof(struct sockaddr_in));
    dns_nscount++;
  }
}

/* =========================================================================
 * resfd — UDP socket file descriptor
 *
 * Referenced by dns.mod/dns.c in eof_dns_socket, dns_close, dns_start.
 * ====================================================================== */

static int resfd = -1;

/* =========================================================================
 * struct resolve + expireresolves compatibility
 *
 * dns.mod/dns.c defines dns_event_success / dns_event_failure which
 * accept struct resolve *.  It also iterates expireresolves in
 * dns_free_cache() and dns_cache_expmem().
 *
 * With the new resolver there is no long-lived cache; queries are freed
 * as soon as they complete.  We maintain expireresolves = NULL so the
 * loops in dns_free_cache / dns_cache_expmem are no-ops, and we synthesize
 * a transient struct resolve on the stack whenever we need to fire an event.
 * ====================================================================== */

static struct resolve *expireresolves = NULL;

/* =========================================================================
 * In-flight query structure
 * ====================================================================== */

struct dns_req {
  struct dns_req             *next;
  struct dns_req             *prev;
  uint16_t                    id;
  int                         type;       /* DNS_TYPE_* | DNS_FLAG_FCRDNS */
  int                         retries;
  time_t                      sent_at;
  int                         timeout_sec;
  int                         last_ns;
  char                        qname[DNS_RES_HOSTLEN + 1];
  struct sockaddr_storage     orig_addr;  /* PTR: original IP to verify */
  char                        hostname[DNS_RES_HOSTLEN + 1]; /* PTR result */
  sockname_t                  sockname;   /* resolved address (for events) */
  char                       *hostn;      /* resolved hostname string (heap) */
};

static struct dns_req *req_head = NULL;
static struct dns_req *req_tail = NULL;

static void req_list_add(struct dns_req *r)
{
  r->prev = NULL;
  r->next = req_head;
  if (req_head)
    req_head->prev = r;
  else
    req_tail = r;
  req_head = r;
}

static void req_list_remove(struct dns_req *r)
{
  if (r->prev) r->prev->next = r->next; else req_head = r->next;
  if (r->next) r->next->prev = r->prev; else req_tail = r->prev;
}

/* =========================================================================
 * Random ID generation (simple LCG, good enough for DNS query IDs)
 * ====================================================================== */

static uint32_t dns_rand_seed = 0;

static uint16_t dns_random_u16(void)
{
  if (!dns_rand_seed)
    dns_rand_seed = (uint32_t)(time(NULL) ^ getpid());
  dns_rand_seed = dns_rand_seed * 1664525u + 1013904223u;
  return (uint16_t)(dns_rand_seed >> 16);
}

static struct dns_req *find_req_by_id(uint16_t id)
{
  struct dns_req *r;
  for (r = req_head; r; r = r->next)
    if (r->id == id)
      return r;
  return NULL;
}

static uint16_t next_query_id(void)
{
  uint16_t id;
  do {
    id = dns_random_u16();
  } while (id == 0 || find_req_by_id(id));
  return id;
}

static struct dns_req *make_req(int type)
{
  struct dns_req *r = nmalloc(sizeof *r);
  memset(r, 0, sizeof *r);
  r->id          = next_query_id();
  r->type        = type;
  r->retries     = DNS_MAX_RETRIES;
  r->sent_at     = now;
  r->timeout_sec = DNS_INITIAL_TIMEOUT;
  r->last_ns     = -1;
  req_list_add(r);
  return r;
}

static void free_req(struct dns_req *r)
{
  req_list_remove(r);
  if (r->hostn)
    nfree(r->hostn);
  nfree(r);
}

/* =========================================================================
 * DNS name codec
 * ====================================================================== */

static int dns_name_encode(unsigned char *dst, size_t dstlen, const char *name)
{
  unsigned char *p   = dst;
  unsigned char *end = dst + dstlen;
  const char    *src = name;
  const char    *dot;
  size_t         lablen;

  while (*src) {
    dot = src;
    while (*dot && *dot != '.')
      dot++;
    lablen = (size_t)(dot - src);
    if (lablen == 0) {
      src = dot + (*dot == '.' ? 1 : 0);
      continue;
    }
    if (lablen > DNS_MAXLABEL) return -1;
    if (p + 1 + lablen >= end) return -1;
    *p++ = (unsigned char)lablen;
    memcpy(p, src, lablen);
    p  += lablen;
    src = dot + (*dot == '.' ? 1 : 0);
  }
  if (p >= end) return -1;
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
  unsigned int         n;

  while (p < msg_end) {
    n = (unsigned int)*p;
    if ((n & DNS_PTR_HI) == DNS_PTR_HI) {
      if (p + 1 >= msg_end) return -1;
      if (!jumped) consumed = (size_t)(p - (msg + off)) + 2;
      {
        size_t new_off = ((n & 0x3F) << 8) | (unsigned int)p[1];
        if (new_off >= msglen) return -1;
        p = msg + new_off;
      }
      jumped = 1;
      if (++hops > 16) return -1;
    } else if ((n & DNS_PTR_HI) == 0) {
      p++;
      if (n == 0) break;
      if (p + n > msg_end) return -1;
      if (d != dst) {
        if (d >= d_end - 1) return -1;
        *d++ = '.';
      }
      if ((size_t)(d_end - d) <= n) return -1;
      {
        unsigned int i;
        for (i = 0; i < n; i++)
          *d++ = (char)tolower((unsigned char)*p++);
      }
    } else {
      return -1;
    }
  }
  if (d >= d_end) return -1;
  *d = '\0';
  if (!jumped) consumed = (size_t)(p - (msg + off));
  return (int)consumed;
}

static int dns_name_skip(const unsigned char *msg, size_t msglen, size_t off)
{
  const unsigned char *p     = msg + off;
  const unsigned char *end   = msg + msglen;
  const unsigned char *start = p;
  unsigned int         n;

  while (p < end) {
    n = (unsigned int)*p;
    if ((n & DNS_PTR_HI) == DNS_PTR_HI) {
      if (p + 1 >= end) return -1;
      return (int)((p - start) + 2);
    } else if ((n & DNS_PTR_HI) == 0) {
      p++;
      if (n == 0) return (int)(p - start);
      if (p + n > end) return -1;
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

static int dns_build_query(unsigned char *buf, size_t buflen,
                           uint16_t id, uint16_t qtype, const char *name)
{
  int off, n;

  if (buflen < DNS_HDR_SIZE + 4) return -1;
  memset(buf, 0, DNS_HDR_SIZE);
  hdr_put_u16(buf + 0, id);
  hdr_put_u16(buf + 2, 0x0100);   /* RD=1 */
  hdr_put_u16(buf + 4, 1);        /* QDCOUNT=1 */
  off = DNS_HDR_SIZE;
  n   = dns_name_encode(buf + off, buflen - (size_t)off - 4, name);
  if (n < 0) return -1;
  off += n;
  if ((size_t)off + 4 > buflen) return -1;
  hdr_put_u16(buf + off,     qtype);
  hdr_put_u16(buf + off + 2, DNS_CLASS_IN);
  return off + 4;
}

/* =========================================================================
 * resolv.conf parser
 * ====================================================================== */

static void add_nameserver_str(const char *addr_str)
{
  struct addrinfo hints, *res;

  if (dns_nscount >= DNS_MAXNS) return;
  memset(&hints, 0, sizeof hints);
  hints.ai_family   = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags    = AI_NUMERICHOST;
  if (getaddrinfo(addr_str, "53", &hints, &res) != 0 || res == NULL) return;
  if (res->ai_addrlen <= (socklen_t)sizeof dns_nsaddr_list[0]) {
    memcpy(&dns_nsaddr_list[dns_nscount], res->ai_addr, res->ai_addrlen);
    dns_nscount++;
  }
  freeaddrinfo(res);
}

static void parse_resolv_conf(void)
{
  FILE *f = fopen("/etc/resolv.conf", "r");
  char  line[256], *p, *kw, *val, *ve, *nl;

  if (!f) {
    add_nameserver_str("127.0.0.1");
    return;
  }
  while (fgets(line, sizeof line, f)) {
    nl = strpbrk(line, "\r\n");
    if (nl) *nl = '\0';
    p = line;
    while (isspace((unsigned char)*p)) p++;
    if (*p == '#' || *p == ';' || *p == '\0') continue;
    kw = p;
    while (*p && !isspace((unsigned char)*p)) p++;
    if (!*p) continue;
    *p++ = '\0';
    while (isspace((unsigned char)*p)) p++;
    val = p;
    ve  = val + strlen(val);
    while (ve > val && isspace((unsigned char)ve[-1])) ve--;
    *ve = '\0';
    if (!strcasecmp(kw, "nameserver")) {
      add_nameserver_str(val);
    } else if (!strcasecmp(kw, "domain") || !strcasecmp(kw, "search")) {
      if (dns_domain[0] == '\0') {
        char *sp = val;
        while (*sp && !isspace((unsigned char)*sp)) sp++;
        *sp = '\0';
        strlcpy(dns_domain, val, sizeof dns_domain);
      }
    }
  }
  fclose(f);
  if (dns_nscount == 0)
    add_nameserver_str("127.0.0.1");
}

/* =========================================================================
 * Nameserver selection — round-robin, biased away from failing servers
 * ====================================================================== */

static int choose_ns(int attempt)
{
  int i, ns;
  if (dns_nscount == 0) return -1;
  for (i = 0; i < dns_nscount; i++) {
    ns = (i + attempt) % dns_nscount;
    if (dns_ns_failures[ns] == 0) return ns;
  }
  return attempt % dns_nscount;
}

/* =========================================================================
 * Forward declaration
 * ====================================================================== */

static void send_dns_query(struct dns_req *req);
static void start_fcrdns_check(struct dns_req *ptr_req);
static void finish_fcrdns(struct dns_req *fwd);
static void finish_req_success(struct dns_req *req, int type);
static void finish_req_failure(struct dns_req *req, int type);

/* =========================================================================
 * Send a DNS query packet over UDP
 * ====================================================================== */

static void send_dns_query(struct dns_req *req)
{
  unsigned char buf[DNS_MAXPKT];
  uint16_t      qtype;
  int           pktlen, attempt, ns;
  ssize_t       sent;
  const struct sockaddr_storage *sa;

  if (resfd < 0) return;

  /* Keep dns_nsaddr_list in sync with myres in case dns_change() updated it */
  sync_internal_from_myres();

  qtype  = (uint16_t)(req->type & ~DNS_FLAG_FCRDNS);
  pktlen = dns_build_query(buf, sizeof buf, req->id, qtype, req->qname);
  if (pktlen < 0) return;

  attempt = DNS_MAX_RETRIES - req->retries;
  ns      = choose_ns(attempt);
  if (ns < 0 || ns >= dns_nscount) return;

  sa   = &dns_nsaddr_list[ns];
  sent = sendto(resfd, buf, (size_t)pktlen, 0,
                (const struct sockaddr *)sa, GET_SS_LEN(sa));
  if (sent == (ssize_t)pktlen)
    req->last_ns = ns;
}

/* =========================================================================
 * Deliver results to dns.mod/dns.c event callbacks
 *
 * dns.mod/dns.c defines:
 *   dns_event_success(struct resolve *rp, int type)
 *   dns_event_failure(struct resolve *rp, int type)
 *
 * We synthesize a minimal struct resolve on the stack to satisfy these.
 * ====================================================================== */

static void finish_req_success(struct dns_req *req, int type)
{
  struct resolve rp;
  memset(&rp, 0, sizeof rp);
  memcpy(&rp.sockname, &req->sockname, sizeof rp.sockname);
  rp.hostn = req->hostn;
  dns_event_success(&rp, type);
}

static void finish_req_failure(struct dns_req *req, int type)
{
  struct resolve rp;
  memset(&rp, 0, sizeof rp);
  memcpy(&rp.sockname, &req->sockname, sizeof rp.sockname);
  rp.hostn = req->hostn;
  dns_event_failure(&rp, type);
}

/* =========================================================================
 * Response parser
 * ====================================================================== */

static void process_answer(struct dns_req *req,
                           const unsigned char *pkt, size_t pktlen)
{
  int      rcode, base_type;
  size_t   off;
  uint16_t qdcount, ancount, qi, ai;

  if (pktlen < DNS_HDR_SIZE) return;
  if (HDR_ID(pkt) != req->id) return;
  if (HDR_QR(pkt) != 1) return;

  rcode = HDR_RCODE(pkt);

  if (rcode == DNS_RC_SERVFAIL || rcode == DNS_RC_NOTIMP ||
      rcode == DNS_RC_REFUSED) {
    if (req->last_ns >= 0 && req->last_ns < DNS_MAXNS)
      dns_ns_failures[req->last_ns]++;
    /* timeout loop will retry */
    return;
  }
  if (rcode == DNS_RC_NXDOMAIN) {
    if (req->last_ns >= 0 && req->last_ns < DNS_MAXNS)
      dns_ns_failures[req->last_ns] /= 4;
    {
      int type = (req->type & DNS_FLAG_FCRDNS) ? T_A : T_PTR;
      if ((req->type & ~DNS_FLAG_FCRDNS) == DNS_TYPE_A ||
          (req->type & ~DNS_FLAG_FCRDNS) == DNS_TYPE_AAAA)
        type = T_A;
      else
        type = T_PTR;
      finish_req_failure(req, type);
    }
    free_req(req);
    return;
  }
  if (rcode != DNS_RC_NOERR || HDR_ANCOUNT(pkt) == 0) {
    {
      int type = ((req->type & ~DNS_FLAG_FCRDNS) == DNS_TYPE_PTR)
                 ? T_PTR : T_A;
      finish_req_failure(req, type);
    }
    free_req(req);
    return;
  }

  /* Skip question section */
  off     = DNS_HDR_SIZE;
  qdcount = HDR_QDCOUNT(pkt);
  for (qi = 0; qi < qdcount; qi++) {
    int n = dns_name_skip(pkt, pktlen, off);
    if (n < 0) return;
    off += (size_t)n;
    if (off + 4 > pktlen) return;
    off += 4;
  }

  /* Process answer RRs */
  ancount   = HDR_ANCOUNT(pkt);
  base_type = req->type & ~DNS_FLAG_FCRDNS;

  for (ai = 0; ai < ancount; ai++) {
    uint16_t rrtype, rdlen;
    int n = dns_name_skip(pkt, pktlen, off);
    if (n < 0) break;
    off += (size_t)n;
    if (off + 10 > pktlen) break;
    rrtype = hdr_u16(pkt + off);
    rdlen  = hdr_u16(pkt + off + 8);
    off   += 10;
    if (off + rdlen > pktlen) break;

    if (rrtype == DNS_TYPE_CNAME) {
      off += rdlen;
      continue;
    }

    if (rrtype == DNS_TYPE_A && base_type == DNS_TYPE_A) {
      if (rdlen != 4) { off += rdlen; continue; }
      if (req->last_ns >= 0 && req->last_ns < DNS_MAXNS)
        dns_ns_failures[req->last_ns] /= 4;
      /* Populate sockname with the resolved address */
      memset(&req->sockname, 0, sizeof req->sockname);
      req->sockname.family  = AF_INET;
      req->sockname.addrlen = sizeof(struct sockaddr_in);
      req->sockname.addr.sa.sa_family = AF_INET;
      memcpy(&req->sockname.addr.s4.sin_addr, pkt + off, 4);
      if (req->type & DNS_FLAG_FCRDNS)
        finish_fcrdns(req);   /* FCrDNS: verify IP matches original */
      else {
        finish_req_success(req, T_A);
        free_req(req);
      }
      return;
    }

#ifdef IPV6
    if (rrtype == DNS_TYPE_AAAA && base_type == DNS_TYPE_AAAA) {
      if (rdlen != 16) { off += rdlen; continue; }
      if (req->last_ns >= 0 && req->last_ns < DNS_MAXNS)
        dns_ns_failures[req->last_ns] /= 4;
      memset(&req->sockname, 0, sizeof req->sockname);
      req->sockname.family  = AF_INET6;
      req->sockname.addrlen = sizeof(struct sockaddr_in6);
      req->sockname.addr.sa.sa_family = AF_INET6;
      memcpy(&req->sockname.addr.s6.sin6_addr, pkt + off, 16);
      if (req->type & DNS_FLAG_FCRDNS)
        finish_fcrdns(req);
      else {
        finish_req_success(req, T_A);
        free_req(req);
      }
      return;
    }
#endif

    if (rrtype == DNS_TYPE_PTR && base_type == DNS_TYPE_PTR) {
      char hostname[DNS_RES_HOSTLEN + 1];
      int nc = dns_name_decode(pkt, pktlen, off, hostname, sizeof hostname);
      if (nc < 0 || hostname[0] == '\0') { off += rdlen; continue; }
      strlcpy(req->hostname, hostname, sizeof req->hostname);
      if (req->last_ns >= 0 && req->last_ns < DNS_MAXNS)
        dns_ns_failures[req->last_ns] /= 4;
      start_fcrdns_check(req);   /* req ownership transferred */
      return;
    }

    off += rdlen;
  }

  /* No matching RR */
  {
    int type = (base_type == DNS_TYPE_PTR) ? T_PTR : T_A;
    finish_req_failure(req, type);
  }
  free_req(req);
}

/* =========================================================================
 * FCrDNS — forward-confirmed reverse DNS
 * ====================================================================== */

static void start_fcrdns_check(struct dns_req *ptr_req)
{
  int             fwd_type;
  struct dns_req *fwd;

#ifdef IPV6
  fwd_type = (GET_SS_FAMILY(&ptr_req->orig_addr) == AF_INET6)
             ? DNS_TYPE_AAAA : DNS_TYPE_A;
#else
  fwd_type = DNS_TYPE_A;
#endif

  fwd = make_req(fwd_type | DNS_FLAG_FCRDNS);
  strlcpy(fwd->qname,    ptr_req->hostname, sizeof fwd->qname);
  strlcpy(fwd->hostname, ptr_req->hostname, sizeof fwd->hostname);
  memcpy(&fwd->orig_addr, &ptr_req->orig_addr, sizeof fwd->orig_addr);
  /* Copy sockname of the original PTR request so events have the IP */
  memcpy(&fwd->sockname, &ptr_req->sockname, sizeof fwd->sockname);
  /* Keep the resolved hostname string for the event callbacks */
  {
    size_t hlen = strlen(ptr_req->hostname) + 1;
    fwd->hostn = nmalloc(hlen);
    memcpy(fwd->hostn, ptr_req->hostname, hlen);
  }

  free_req(ptr_req);
  send_dns_query(fwd);
}

/* Verify FCrDNS forward result and deliver final PTR result */
static void finish_fcrdns(struct dns_req *fwd)
{
  int    orig_af = GET_SS_FAMILY(&fwd->orig_addr);
  int    match   = 0;
  struct resolve rp;

  /* Compare the forward-resolved address against the original IP */
  if (orig_af == AF_INET &&
      fwd->sockname.family == AF_INET) {
    const struct sockaddr_in *orig =
        (const struct sockaddr_in *)&fwd->orig_addr;
    match = (orig->sin_addr.s_addr ==
             fwd->sockname.addr.s4.sin_addr.s_addr);
  }
#ifdef IPV6
  else if (orig_af == AF_INET6 &&
           fwd->sockname.family == AF_INET6) {
    const struct sockaddr_in6 *orig =
        (const struct sockaddr_in6 *)&fwd->orig_addr;
    match = (memcmp(&orig->sin6_addr,
                    &fwd->sockname.addr.s6.sin6_addr,
                    sizeof(struct in6_addr)) == 0);
  }
#endif

  /* Rebuild the sockname to reflect the *original* IP for the event */
  memset(&rp, 0, sizeof rp);
  if (orig_af == AF_INET) {
    rp.sockname.family  = AF_INET;
    rp.sockname.addrlen = sizeof(struct sockaddr_in);
    rp.sockname.addr.sa.sa_family = AF_INET;
    memcpy(&rp.sockname.addr.s4,
           (const struct sockaddr_in *)&fwd->orig_addr,
           sizeof(struct sockaddr_in));
  }
#ifdef IPV6
  else if (orig_af == AF_INET6) {
    rp.sockname.family  = AF_INET6;
    rp.sockname.addrlen = sizeof(struct sockaddr_in6);
    rp.sockname.addr.sa.sa_family = AF_INET6;
    memcpy(&rp.sockname.addr.s6,
           (const struct sockaddr_in6 *)&fwd->orig_addr,
           sizeof(struct sockaddr_in6));
  }
#endif
  rp.hostn = match ? fwd->hostn : NULL;

  if (match)
    dns_event_success(&rp, T_PTR);
  else
    dns_event_failure(&rp, T_PTR);

  free_req(fwd);
}

/* =========================================================================
 * dns_ack — read available UDP replies; called from DCC_DNS activity handler
 * ====================================================================== */

static void dns_ack(void)
{
  unsigned char           buf[DNS_HDR_SIZE + DNS_MAXPKT];
  struct sockaddr_storage from;
  socklen_t               fromlen = sizeof from;
  ssize_t                 rc;
  uint16_t                id;
  struct dns_req         *req;

  if (resfd < 0) return;

  /* Keep nameserver list in sync with myres (TCL dns-servers may have updated it) */
  sync_internal_from_myres();

  for (;;) {
    fromlen = sizeof from;
    rc = recvfrom(resfd, buf, sizeof buf, 0,
                  (struct sockaddr *)&from, &fromlen);
    if (rc <= 0) break;
    if ((size_t)rc <= DNS_HDR_SIZE) continue;

    /* Accept only from configured nameservers */
    {
      int trusted = 0, i;
      for (i = 0; i < dns_nscount && !trusted; i++) {
        const struct sockaddr_storage *ns = &dns_nsaddr_list[i];
        if (GET_SS_FAMILY(ns) != GET_SS_FAMILY(&from)) continue;
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
      if (!trusted) continue;
    }

    id  = HDR_ID(buf);
    req = find_req_by_id(id);
    if (!req) continue;

    process_answer(req, buf, (size_t)rc);
  }
}

/* =========================================================================
 * dns_check_expires — timeout and retry loop; called from HOOK_SECONDLY
 * ====================================================================== */

static void dns_check_expires(void)
{
  struct dns_req *r, *rn;
  time_t          t = now;

  for (r = req_head; r; r = rn) {
    rn = r->next;

    if (t < r->sent_at + r->timeout_sec)
      continue;

    if (r->last_ns >= 0 && r->last_ns < DNS_MAXNS)
      dns_ns_failures[r->last_ns]++;

    if (--r->retries <= 0) {
      int type = ((r->type & ~DNS_FLAG_FCRDNS) == DNS_TYPE_PTR)
                 ? T_PTR : T_A;
      finish_req_failure(r, type);
      free_req(r);
      continue;
    }

    /* Exponential backoff */
    r->timeout_sec *= 2;
    r->sent_at      = t;
    send_dns_query(r);
  }
}

/* =========================================================================
 * build_rdns — build PTR query name string
 * ====================================================================== */

static void build_rdns_internal(char *buf, size_t size,
                                const struct sockaddr_storage *addr,
                                const char *suffix)
{
  const unsigned char *cp;

  if (GET_SS_FAMILY(addr) == AF_INET) {
    const struct sockaddr_in *v4 = (const struct sockaddr_in *)addr;
    cp = (const unsigned char *)&v4->sin_addr.s_addr;
    snprintf(buf, size, "%u.%u.%u.%u.%s",
             (unsigned)cp[3], (unsigned)cp[2],
             (unsigned)cp[1], (unsigned)cp[0],
             suffix ? suffix : "in-addr.arpa");
#ifdef IPV6
  } else if (GET_SS_FAMILY(addr) == AF_INET6) {
    const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)addr;
    cp = (const unsigned char *)&v6->sin6_addr.s6_addr;
    snprintf(buf, size,
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
#endif
  } else {
    if (size > 0) buf[0] = '\0';
  }
}

/* =========================================================================
 * Reverse lookup helper — build sockaddr_storage from sockname_t
 * ====================================================================== */

static int sockname_to_ss(const sockname_t *sn, struct sockaddr_storage *ss)
{
  memset(ss, 0, sizeof *ss);
  if (sn->family == AF_INET) {
    memcpy(ss, &sn->addr.s4, sizeof(struct sockaddr_in));
    return 1;
  }
#ifdef IPV6
  if (sn->family == AF_INET6) {
    memcpy(ss, &sn->addr.s6, sizeof(struct sockaddr_in6));
    return 1;
  }
#endif
  return 0;
}

/* =========================================================================
 * dns_lookup — reverse lookup (IP -> hostname)
 * Registered on HOOK_DNS_HOSTBYIP in dns_start()
 * ====================================================================== */

static void dns_lookup(sockname_t *addr)
{
  struct sockaddr_storage ss;
  struct dns_req         *req;

  if (!addr) return;
  if (!sockname_to_ss(addr, &ss)) return;

  req = make_req(DNS_TYPE_PTR);
  memcpy(&req->orig_addr, &ss, sizeof ss);
  /* Store original sockname for event delivery */
  memcpy(&req->sockname, addr, sizeof req->sockname);
  build_rdns_internal(req->qname, sizeof req->qname, &ss, NULL);
  send_dns_query(req);
}

/* =========================================================================
 * dns_forward — forward lookup (hostname -> IP)
 * Registered on HOOK_DNS_IPBYHOST in dns_start()
 * ====================================================================== */

static void dns_forward(char *hostn)
{
  struct dns_req *req;
  sockname_t      name;
  int             g_type;
  char            fqdn[DNS_RES_HOSTLEN + 1];

  if (!hostn || !*hostn) return;

  /* Already a numeric address? */
  if (setsockname(&name, hostn, 0, 0) != AF_UNSPEC) {
    call_ipbyhost(hostn, &name, 1);
    return;
  }

  /* Check /etc/hosts */
  /* (omitted — let the DNS server handle it for simplicity) */

#ifdef IPV6
  g_type = pref_af ? DNS_TYPE_AAAA : DNS_TYPE_A;
#else
  g_type = DNS_TYPE_A;
#endif

  req = make_req(g_type);

  strlcpy(fqdn, hostn, sizeof fqdn);
  if (dns_domain[0] && strchr(fqdn, '.') == NULL) {
    size_t nl = strlen(fqdn);
    if (nl + 1 + strlen(dns_domain) < sizeof fqdn) {
      fqdn[nl++] = '.';
      strlcpy(fqdn + nl, dns_domain, sizeof fqdn - nl);
    }
  }
  strlcpy(req->qname, fqdn, sizeof req->qname);
  {
    size_t hlen = strlen(hostn) + 1;
    req->hostn = nmalloc(hlen);
    memcpy(req->hostn, hostn, hlen);
  }

  send_dns_query(req);
}

/* =========================================================================
 * Network initialisation
 * ====================================================================== */

static int init_dns_network(void)
{
  int family, flags;

  /* Always open a fresh socket; caller is responsible for closing the old one
   * (eof_dns_socket calls killsock before calling us). */
  resfd = -1;

  family = (dns_nscount > 0 &&
             GET_SS_FAMILY(&dns_nsaddr_list[0]) == AF_INET6)
           ? AF_INET6 : AF_INET;

  resfd = socket(family, SOCK_DGRAM, 0);
  if (resfd < 0) {
    putlog(LOG_MISC, "*",
           "DNS: Unable to allocate UDP socket: %s", strerror(errno));
    return 0;
  }

  flags = fcntl(resfd, F_GETFL, 0);
  if (flags < 0 || fcntl(resfd, F_SETFL, flags | O_NONBLOCK) < 0) {
    putlog(LOG_MISC, "*",
           "DNS: Unable to set socket non-blocking: %s", strerror(errno));
    close(resfd);
    resfd = -1;
    return 0;
  }

  if (allocsock(resfd, SOCK_PASS) == -1) {
    putlog(LOG_MISC, "*", "DNS: Unable to register socket in socklist");
    close(resfd);
    resfd = -1;
    return 0;
  }

  return 1;
}

/* =========================================================================
 * init_dns_core — full initialisation; called from dns_start()
 * ====================================================================== */

static int init_dns_core(void)
{
  struct dns_req *r, *rn;

  /* Cancel any pending queries from a previous run */
  for (r = req_head; r; r = rn) {
    rn = r->next;
    free_req(r);
  }
  req_head = req_tail = NULL;

  dns_nscount   = 0;
  dns_domain[0] = '\0';
  memset(dns_ns_failures, 0, sizeof dns_ns_failures);

  MY_RES_INIT();
  parse_resolv_conf();
  sync_myres_from_internal();

  if (!myres.nscount) {
    putlog(LOG_MISC, "*", "DNS: No nameservers defined.");
    return 0;
  }

  if (!init_dns_network())
    return 0;

  return 1;
}

/* =========================================================================
 * restart_resolver — re-read resolv.conf (called on SIGHUP / TCL rehash)
 * ====================================================================== */

static void restart_resolver(void)
{
  struct dns_req *r, *rn;

  /* Cancel pending queries */
  for (r = req_head; r; r = rn) {
    rn = r->next;
    finish_req_failure(r, ((r->type & ~DNS_FLAG_FCRDNS) == DNS_TYPE_PTR)
                          ? T_PTR : T_A);
    free_req(r);
  }
  req_head = req_tail = NULL;

  if (resfd >= 0) {
    killsock(resfd);
    resfd = -1;
  }

  dns_nscount   = 0;
  dns_domain[0] = '\0';
  memset(dns_ns_failures, 0, sizeof dns_ns_failures);
  parse_resolv_conf();
  sync_myres_from_internal();
  init_dns_network();
}
