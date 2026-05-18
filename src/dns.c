/*
 * dns.c -- handles:
 *   DNS resolve calls and events
 *   provides the code used by the bot if the DNS module is not loaded
 *   DNS Tcl commands
 */
/*
 * Written by Fabian Knittel <fknittel@gmx.de>
 *
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

#include "main.h"
#include <netdb.h>
#include <arpa/inet.h>
#include "dns.h"
#include "script.h"
#include <setjmp.h>

extern struct dcc_t *dcc;
extern int dcc_total;
extern time_t now;
extern Tcl_Interp *interp;
extern int resolve_timeout;
extern sigjmp_buf alarmret;

static op_vec_t dns_events;

/* Slab allocators for DNS event nodes — lazy-initialised on first DNS call. */
static op_bh *devent_bh  = nullptr;
static op_bh *tclinfo_bh = nullptr;
static op_bh *sockname_bh = nullptr;

static int ipaddr_equal(const sockname_t *ip, const sockname_t *ip2)
{
  if (!ip || !ip2) {
    return 0;
  }
#ifdef IPV6
  if (ip->family == AF_INET6 && ip2->family == AF_INET6) {
    return IN6_ARE_ADDR_EQUAL(&ip->addr.s6.sin6_addr, &ip2->addr.s6.sin6_addr);
  }
#endif
  if (ip->family == AF_INET && ip2->family == AF_INET) {
    return ip->addr.s4.sin_addr.s_addr == ip2->addr.s4.sin_addr.s_addr;
  }
  return 0;
}


/*
 *   DCC functions
 */

static void dcc_dnswait(int idx, char *buf, int len)
{
  /* Ignore anything now. */
}

static void eof_dcc_dnswait(int idx)
{
  putlog(LOG_MISC, "*", "Lost connection while resolving hostname [%s/%d]",
         iptostr(&dcc[idx].sockname.addr.sa), dcc[idx].port);
  killsock(dcc[idx].sock);
  lostdcc(idx);
}

static void display_dcc_dnswait(int idx, op_strbuf_t *buf)
{
  op_strbuf_appendf(buf, "dns   waited %" PRId64 "s", (int64_t) (now - dcc[idx].timeval));
}

static int expmem_dcc_dnswait(void *x)
{
  struct dns_info *p = (struct dns_info *) x;
  int size = 0;

  if (p) {
    size = sizeof(struct dns_info);
    if (p->host)
      size += strlen(p->host) + 1;
    if (p->cbuf)
      size += strlen(p->cbuf) + 1;
  }
  return size;
}

static void kill_dcc_dnswait(int idx, void *x)
{
  struct dns_info *p = (struct dns_info *) x;

  if (p) {
    if (p->host)
      op_free(p->host);
    if (p->cbuf)
      op_free(p->cbuf);
    op_free(p);
  }
}

struct dcc_table DCC_DNSWAIT = {
  "DNSWAIT",
  DCT_VALIDIDX,
  eof_dcc_dnswait,
  dcc_dnswait,
  0,
  0,
  display_dcc_dnswait,
  expmem_dcc_dnswait,
  kill_dcc_dnswait,
  0,
  nullptr
};


/*
 *   DCC events
 */

/* Walk through every dcc entry and look for waiting DNS requests
 * of RES_HOSTBYIP for our IP address.
 */
static void dns_dcchostbyip(sockname_t *ip, char *hostn, int ok, void *other)
{
  int idx;

  for (idx = 0; idx < dcc_total; idx++) {
    if ((dcc[idx].type == &DCC_DNSWAIT) &&
        (dcc[idx].u.dns->dns_type == RES_HOSTBYIP) && (
#ifdef IPV6
        (ip->family == AF_INET6 &&
          IN6_ARE_ADDR_EQUAL(&dcc[idx].sockname.addr.s6.sin6_addr,
                             &ip->addr.s6.sin6_addr)) ||
        (ip->family == AF_INET &&
#endif
          (dcc[idx].sockname.addr.s4.sin_addr.s_addr ==
                              ip->addr.s4.sin_addr.s_addr)))
#ifdef IPV6
       )
#endif
    {
      if (dcc[idx].u.dns->host)
        op_free(dcc[idx].u.dns->host);
      size_t _len = strlen(hostn) + 1;
      dcc[idx].u.dns->host = get_data_ptr(_len);
      op_strlcpy(dcc[idx].u.dns->host, hostn, _len);
      if (ok)
        dcc[idx].u.dns->dns_success(idx);
      else
        dcc[idx].u.dns->dns_failure(idx);
    }
  }
}

/* Walk through every dcc entry and look for waiting DNS requests
 * of RES_IPBYHOST for our hostname.
 */
static void dns_dccipbyhost(sockname_t *ip, char *hostn, int ok, void *other)
{
  int idx;

  for (idx = 0; idx < dcc_total; idx++) {
    if ((dcc[idx].type == &DCC_DNSWAIT) &&
        (dcc[idx].u.dns->dns_type == RES_IPBYHOST) &&
        !op_strcasecmp(dcc[idx].u.dns->host, hostn)) {
      if (ok) {
        memcpy(&dcc[idx].sockname, ip, sizeof(sockname_t));
        dcc[idx].u.dns->dns_success(idx);
      } else
        dcc[idx].u.dns->dns_failure(idx);
    }
  }
}

static int dns_dccexpmem(void *other)
{
  return 0;
}

devent_type DNS_DCCEVENT_HOSTBYIP = {
  "DCCEVENT_HOSTBYIP",
  dns_dccexpmem,
  dns_dcchostbyip
};

devent_type DNS_DCCEVENT_IPBYHOST = {
  "DCCEVENT_IPBYHOST",
  dns_dccexpmem,
  dns_dccipbyhost
};

void dcc_dnsipbyhost(char *hostn)
{
  for (size_t i = 0; i < dns_events.size; i++) {
    devent_t *de = (devent_t *)op_vec_get(&dns_events, i);
    if (de->type && (de->type == &DNS_DCCEVENT_IPBYHOST) &&
        (de->lookup == RES_IPBYHOST) && de->res_data.hostname &&
        !op_strcasecmp(de->res_data.hostname, hostn))
      return;
  }
  if (!devent_bh)
    devent_bh = op_bh_create(sizeof(devent_t), 16, "dns_devent");
  devent_t *de = (devent_t *)op_bh_alloc(devent_bh);
  de->type = &DNS_DCCEVENT_IPBYHOST;
  de->lookup = RES_IPBYHOST;
  de->res_data.hostname = op_strdup(hostn);
  op_vec_push(&dns_events, de);
  dns_ipbyhost(hostn);
}

void dcc_dnshostbyip(sockname_t *ip)
{
  for (size_t i = 0; i < dns_events.size; i++) {
    devent_t *de = (devent_t *)op_vec_get(&dns_events, i);
    if (de->type && (de->type == &DNS_DCCEVENT_HOSTBYIP) &&
        (de->lookup == RES_HOSTBYIP) && ipaddr_equal(ip, de->res_data.ip_addr))
      return;
  }
  if (!devent_bh)
    devent_bh = op_bh_create(sizeof(devent_t), 16, "dns_devent");
  devent_t *de = (devent_t *)op_bh_alloc(devent_bh);
  de->type = &DNS_DCCEVENT_HOSTBYIP;
  de->lookup = RES_HOSTBYIP;
  if (!sockname_bh)
    sockname_bh = op_bh_create(sizeof(sockname_t), 16, "dns_sockname");
  de->res_data.ip_addr = (sockname_t *)op_bh_alloc(sockname_bh);
  memcpy(de->res_data.ip_addr, ip, sizeof *ip);
  op_vec_push(&dns_events, de);
  dns_hostbyip(ip);
}


/*
 *   Tcl events
 */

static void dns_tcl_iporhostres(sockname_t *ip, char *hostn, int ok, void *other)
{
  devent_tclinfo_t *tclinfo = (devent_tclinfo_t *) other;
  op_strbuf_t sb = {};
  op_strbuf_init(&sb);

  /* Build the command: proc ip host ok ?paras? */
  op_strbuf_appendf(&sb, "%s {%s} {%s} %s",
                   tclinfo->proc,
                   iptostr(&ip->addr.sa),
                   hostn,
                   ok ? "1" : "0");
  if (tclinfo->paras)
    op_strbuf_appendf(&sb, " %s", tclinfo->paras);

  egg_eval_log(tclinfo->proc, op_strbuf_str(&sb));
  op_strbuf_free(&sb);

  op_free(tclinfo->proc);
  if (tclinfo->paras)
    op_free(tclinfo->paras);
  op_bh_free(tclinfo_bh, tclinfo);
}

static int dns_tclexpmem(void *other)
{
  devent_tclinfo_t *tclinfo = (devent_tclinfo_t *) other;
  int l = 0;

  if (tclinfo) {
    l = sizeof(devent_tclinfo_t);
    if (tclinfo->proc)
      l += strlen(tclinfo->proc) + 1;
    if (tclinfo->paras)
      l += strlen(tclinfo->paras) + 1;
  }
  return l;
}

devent_type DNS_TCLEVENT_HOSTBYIP = {
  "TCLEVENT_HOSTBYIP",
  dns_tclexpmem,
  dns_tcl_iporhostres
};

devent_type DNS_TCLEVENT_IPBYHOST = {
  "TCLEVENT_IPBYHOST",
  dns_tclexpmem,
  dns_tcl_iporhostres
};

/* Tcl command handlers. In non-Tcl builds these compile as dead code
 * (lush.h stubs all Tcl API calls; add_tcl_commands is a no-op).
 */
static void tcl_dnsipbyhost(char *hostn, char *proc, char *paras)
{
  if (!devent_bh)
    devent_bh = op_bh_create(sizeof(devent_t), 16, "dns_devent");
  devent_t *de = (devent_t *)op_bh_alloc(devent_bh);
  de->type = &DNS_TCLEVENT_IPBYHOST;
  de->lookup = RES_IPBYHOST;
  de->res_data.hostname = op_strdup(hostn);
  if (!tclinfo_bh)
    tclinfo_bh = op_bh_create(sizeof(devent_tclinfo_t), 8, "dns_tclinfo");
  devent_tclinfo_t *tclinfo = (devent_tclinfo_t *)op_bh_alloc(tclinfo_bh);
  tclinfo->proc = op_strdup(proc);
  tclinfo->paras = paras ? op_strdup(paras) : nullptr;
  de->other = tclinfo;
  op_vec_push(&dns_events, de);
  dns_ipbyhost(hostn);
}

static void tcl_dnshostbyip(sockname_t *ip, char *proc, char *paras)
{
  if (!devent_bh)
    devent_bh = op_bh_create(sizeof(devent_t), 16, "dns_devent");
  devent_t *de = (devent_t *)op_bh_alloc(devent_bh);
  de->type = &DNS_TCLEVENT_HOSTBYIP;
  de->lookup = RES_HOSTBYIP;
  if (!sockname_bh)
    sockname_bh = op_bh_create(sizeof(sockname_t), 16, "dns_sockname");
  de->res_data.ip_addr = (sockname_t *)op_bh_alloc(sockname_bh);
  memcpy(de->res_data.ip_addr, ip, sizeof *ip);

  if (!tclinfo_bh)
    tclinfo_bh = op_bh_create(sizeof(devent_tclinfo_t), 8, "dns_tclinfo");
  devent_tclinfo_t *tclinfo = (devent_tclinfo_t *)op_bh_alloc(tclinfo_bh);
  tclinfo->proc = op_strdup(proc);
  tclinfo->paras = paras ? op_strdup(paras) : nullptr;
  de->other = tclinfo;
  op_vec_push(&dns_events, de);
  dns_hostbyip(ip);
}


/*
 *    Event functions
 */

[[maybe_unused]] static int dnsevent_expmem(void)
{
  int tot = 0;
  for (size_t i = 0; i < dns_events.size; i++) {
    devent_t *de = (devent_t *)op_vec_get(&dns_events, i);
    tot += (int)sizeof(devent_t);
    if ((de->lookup == RES_IPBYHOST) && de->res_data.hostname)
      tot += (int)strlen(de->res_data.hostname) + 1;
    if (de->type && de->type->expmem)
      tot += de->type->expmem(de->other);
  }
  return tot;
}

void call_hostbyip(sockname_t *ip, char *hostn, int ok)
{
  /* Iterate backward so removal by index is safe; new entries appended by
   * event handlers land beyond [i] and are not fired in this pass. */
  for (size_t i = dns_events.size; i-- > 0; ) {
    devent_t *de = (devent_t *)op_vec_get(&dns_events, i);
    if ((de->lookup == RES_HOSTBYIP) && ipaddr_equal(ip, de->res_data.ip_addr)) {
      op_vec_remove_fast(&dns_events, i);
      if (de->type && de->type->event)
        de->type->event(ip, hostn, ok, de->other);
      else
        putlog(LOG_MISC, "*", "(!) Unknown DNS event type found: %s",
               (de->type && de->type->name) ? de->type->name : "<empty>");
      if (de->res_data.ip_addr)
        op_bh_free(sockname_bh, de->res_data.ip_addr);
      op_bh_free(devent_bh, de);
    }
  }
}

void call_ipbyhost(char *hostn, sockname_t *ip, int ok)
{
  for (size_t i = dns_events.size; i-- > 0; ) {
    devent_t *de = (devent_t *)op_vec_get(&dns_events, i);
    if ((de->lookup == RES_IPBYHOST) && (!de->res_data.hostname ||
        !op_strcasecmp(de->res_data.hostname, hostn))) {
      op_vec_remove_fast(&dns_events, i);
      if (de->type && de->type->event)
        de->type->event(ip, hostn, ok, de->other);
      else
        putlog(LOG_MISC, "*", "(!) Unknown DNS event type found: %s",
               (de->type && de->type->name) ? de->type->name : "<empty>");
      if (de->res_data.hostname)
        op_free(de->res_data.hostname);
      op_bh_free(devent_bh, de);
    }
  }
}


/*
 *    Async DNS emulation functions (fallback when dns module is not loaded)
 */

void core_dns_hostbyip(sockname_t *addr)
{
  char host[256] = "";
  volatile int i = 1;

  if (addr->family == AF_INET) {
    if (!sigsetjmp(alarmret, 1)) {
      alarm(resolve_timeout);
      i = getnameinfo((const struct sockaddr *) &addr->addr.s4,
                      sizeof (struct sockaddr_in), host, sizeof host, nullptr, 0, 0);
      alarm(0);
      if (i)
        debug1("dns: core_dns_hostbyip(): getnameinfo(): error = %s", gai_strerror(i));
    }
    if (i)
      inet_ntop(AF_INET, &addr->addr.s4.sin_addr.s_addr, host, sizeof host);
#ifdef IPV6
  } else {
    if (!sigsetjmp(alarmret, 1)) {
      alarm(resolve_timeout);
      i = getnameinfo((const struct sockaddr *) &addr->addr.s6,
                      sizeof (struct sockaddr_in6), host, sizeof host, nullptr, 0, 0);
      alarm(0);
      if (i)
        debug1("dns: core_dns_hostbyip(): getnameinfo(): error = %s", gai_strerror(i));
    }
    if (i)
      inet_ntop(AF_INET6, &addr->addr.s6.sin6_addr, host, sizeof host);
  }
#else
  }
#endif
  call_hostbyip(addr, host, !i);
}

void core_dns_ipbyhost(char *host)
{
  sockname_t name;

  if (setsockname(&name, host, 0, 1) == AF_UNSPEC)
    call_ipbyhost(host, &name, 0);
  else
    call_ipbyhost(host, &name, 1);
}

/*
 *   Misc functions
 */


/* dnslookup <ip-address> <proc> */
static int tcl_dnslookup STDVAR
{
  sockname_t addr;
  Tcl_DString paras;

  if (argc < 3) {
    Tcl_AppendResult(irp, "wrong # args: should be \"", argv[0],
                     " ip-address/hostname proc ?args...?\"", nullptr);
    return TCL_ERROR;
  }

  Tcl_DStringInit(&paras);
  if (argc > 3) {
    int p;

    for (p = 3; p < argc; p++)
      Tcl_DStringAppendElement(&paras, argv[p]);
  }

  if (setsockname(&addr, argv[1], 0, 0) != AF_UNSPEC)
    tcl_dnshostbyip(&addr, argv[2], Tcl_DStringValue(&paras));
  else {
    if (strlen(argv[1]) > 255) {
      Tcl_SetResult(irp, "hostname too long. max 255 chars.", TCL_STATIC);
      return TCL_ERROR;
    }
    tcl_dnsipbyhost(argv[1], argv[2], Tcl_DStringValue(&paras));
  }

  Tcl_DStringFree(&paras);
  return TCL_OK;
}

tcl_cmds tcldns_cmds[] = {
  {"dnslookup", (IntFunc) tcl_dnslookup},
  {nullptr,                          nullptr}
};
