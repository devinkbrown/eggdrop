/*
 * dns.c -- part of dns.mod
 *   domain lookup glue code for eggdrop
 *
 * Written by Fabian Knittel <fknittel@gmx.de>
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

#include "src/mod/module.h"

#define MODULE_NAME "dns"

#include "dns.h"

static Function *global = NULL;

static int dns_maxsends = 4;
static int dns_retrydelay = 3;
static int dns_cache = 86400;
static int dns_negcache = 600;

static char dns_servers[144] = "";

#include "res.c"


/*
 *    DNS event related code
 */
/* dns_event_success / dns_event_failure: legacy callbacks no longer called
 * directly; res.c calls call_hostbyip/call_ipbyhost at each resolution site.
 * Kept as dead code to avoid changing the dns.c API surface. */


/*
 *    DNS Socket related code
 */

static void eof_dns_socket(int idx)
{
  putlog(LOG_MISC, "*", "DNS Error: socket closed.");
  killsock(dcc[idx].sock);
  /* Try to reopen socket */
  if (init_dns_network()) {
    putlog(LOG_MISC, "*", "DNS socket successfully reopened!");
    dcc[idx].sock = resfd;
    dcc[idx].timeval = now;
  } else
    lostdcc(idx);
}

static void dns_socket(int idx, char *buf, int len)
{
  dns_ack();
}

static void display_dns_socket(int idx, char *buf)
{
  /* buf is the 160-byte display buffer from dccutil.c / tcldcc.c */
  snprintf(buf, 160, "dns   (ready)");
}

static struct dcc_table DCC_DNS = {
  "DNS",
  DCT_LISTEN,
  eof_dns_socket,
  dns_socket,
  NULL,
  NULL,
  display_dns_socket,
  NULL,
  NULL,
  NULL,
  NULL
};

static tcl_ints dnsints[] = {
  {"dns-maxsends",   &dns_maxsends,   0},
  {"dns-retrydelay", &dns_retrydelay, 0},
  {"dns-cache",      &dns_cache,      0},
  {"dns-negcache",   &dns_negcache,   0},
  {NULL,             NULL,            0}
};

static tcl_strings dnsstrings[] = {
  {"dns-servers", dns_servers, 143,           0},
  {NULL,          NULL,          0,           0}
};

#ifdef HAVE_TCL
static char *dns_change(ClientData cdata, Tcl_Interp *irp,
                           EGG_CONST char *name1,
                           EGG_CONST char *name2, int flags)
{
  char buf[sizeof dns_servers], *p;
  unsigned short port;
  Tcl_Size i, lc;
  int code;
  EGG_CONST char **list, *slist;

  if (flags & (TCL_TRACE_READS | TCL_TRACE_UNSETS)) {
    Tcl_DString ds;

    Tcl_DStringInit(&ds);
    for (i = 0; i < myres.nscount; i++) {
      egg_snprintf(buf, sizeof buf, "%s:%d", iptostr((struct sockaddr *)
               &myres.nsaddr_list[i]), ntohs(myres.nsaddr_list[i].sin_port));
      Tcl_DStringAppendElement(&ds, buf);
    }
    slist = Tcl_DStringValue(&ds);
    Tcl_SetVar2(interp, name1, name2, slist, TCL_GLOBAL_ONLY);
    Tcl_DStringFree(&ds);
  } else { /* TCL_TRACE_WRITES */
    slist = Tcl_GetVar2(interp, name1, name2, TCL_GLOBAL_ONLY);
    code = Tcl_SplitList(interp, slist, &lc, &list);
    if (code == TCL_ERROR)
      return "variable must be a list";
    /* reinitialize the list */
    myres.nscount = 0;
    for (i = 0; i < lc; i++) {
      if (myres.nscount >= MAXNS) {
        putlog(LOG_MISC, "*", "DNS: WARNING: %" TCL_SIZE_MODIFIER "i dns-servers configured but "
               "kernel-defined limit is %i, ignoring extra servers\n", lc,
               MAXNS);
        break;
      }
      if ((p = strchr(list[i], ':'))) {
        *p++ = 0;
        /* allow non-standard ports */
        port = atoi(p);
      } else
        port = NAMESERVER_PORT; /* port 53 */
      /* Ignore invalid addresses */
      if (egg_inet_aton(list[i], &myres.nsaddr_list[myres.nscount].sin_addr)) {
        myres.nsaddr_list[myres.nscount].sin_port = htons(port);
        myres.nsaddr_list[myres.nscount].sin_family = AF_INET;
        myres.nscount++;
        debug1("DNS: Valid dns-server %s", list[i]);
      }
      else
        putlog(LOG_MISC, "*", "DNS: WARNING: Invalid dns-server %s", list[i]);
    }
    Tcl_Free((char *) list);
  }
  return NULL;
}
#endif /* HAVE_TCL */


/*
 *    DNS module related code
 */

static void dns_free_cache(void)
{
  struct resolve *rp, *rpnext;

  for (rp = expireresolves; rp; rp = rpnext) {
    rpnext = rp->next;
    if (rp->hostn)
      nfree(rp->hostn);
    nfree(rp);
  }
  expireresolves = NULL;
}

static int dns_cache_expmem(void)
{
  struct resolve *rp;
  int size = 0;

  for (rp = expireresolves; rp; rp = rp->next) {
    size += sizeof(struct resolve);
    if (rp->hostn)
      size += strlen(rp->hostn) + 1;
  }
  return size;
}

static int dns_expmem(void)
{
  return dns_cache_expmem();
}

static int dns_report(int idx, int details)
{
  if (details) {
    int i, size = dns_expmem();

    dprintf(idx, "    Async DNS resolver is active.\n");
    dprintf(idx, "    DNS server list:");
    for (i = 0; i < myres.nscount; i++)
      dprintf(idx, " %s:%d", iptostr((struct sockaddr *) &myres.nsaddr_list[i]),
              ntohs(myres.nsaddr_list[i].sin_port));
    if (!myres.nscount)
      dprintf(idx, " NO DNS SERVERS FOUND!\n");
    dprintf(idx, "\n");
    dprintf(idx, "    Using %d byte%s of memory\n", size,
            (size != 1) ? "s" : "");
  }
  return 0;
}

static int dns_check_servercount(void)
{
  static int oldcount = -1;
  /* dns_nscount includes IPv6 servers that myres (IPv4-only) omits.
   * Warn only when both are zero — i.e., genuinely no nameservers at all. */
  int total = myres.nscount > 0 ? myres.nscount : irc_nscount;
  if (oldcount != total && !total) {
    putlog(LOG_MISC, "*", "WARNING: No nameservers found. Please set the dns-servers config variable.");
  }
  oldcount = total;
  return 0;
}

/* =========================================================================
 * Tcl command: dnsdot ?on server ?port? ?-noverify?? | off
 *
 * Examples:
 *   dnsdot on 1.1.1.1           — enable DoT to 1.1.1.1 port 853, verify cert
 *   dnsdot on 1.1.1.1 853       — same, explicit port
 *   dnsdot on ::1 853 -noverify — allow self-signed cert
 *   dnsdot off                  — disable DoT, revert to plain UDP
 *   dnsdot                      — report current DoT status
 * ====================================================================== */
static int tcl_dnsdot(ClientData cd, Tcl_Interp *irp, int argc,
                      EGG_CONST char *argv[])
{
  (void)cd;

  if (argc < 2) {
#ifdef EGG_TLS
    if (dot_active || dot_sa_valid) {
      char portbuf[8];
      snprintf(portbuf, sizeof portbuf, "%u", dot_port_saved ? dot_port_saved : 853);
      Tcl_AppendResult(irp, dot_active ? "on " : "connecting ", dot_host, ":", portbuf, NULL);
    } else {
      Tcl_AppendResult(irp, "off", NULL);
    }
#else
    Tcl_AppendResult(irp, "unavailable (TLS not compiled in)", NULL);
#endif
    return TCL_OK;
  }

  if (!strcasecmp(argv[1], "off")) {
    res_disable_dot();
    return TCL_OK;
  }

  if (!strcasecmp(argv[1], "on")) {
    struct sockaddr_storage sa;
    const char *addr;
    uint16_t    port    = 853;
    int         verify  = 1;
    int         i;

    if (argc < 3) {
      Tcl_AppendResult(irp, "Usage: dnsdot on <server> [port] [-noverify]",
                       NULL);
      return TCL_ERROR;
    }
    addr = argv[2];

    for (i = 3; i < argc; i++) {
      if (!strcasecmp(argv[i], "-noverify"))
        verify = 0;
      else
        port = (uint16_t)atoi(argv[i]);
    }

    memset(&sa, 0, sizeof sa);
    if (inet_pton(AF_INET, addr,
                  &((struct sockaddr_in *)&sa)->sin_addr) == 1) {
      ((struct sockaddr_in *)&sa)->sin_family = AF_INET;
    }
#ifdef IPV6
    else if (inet_pton(AF_INET6, addr,
                       &((struct sockaddr_in6 *)&sa)->sin6_addr) == 1) {
      ((struct sockaddr_in6 *)&sa)->sin6_family = AF_INET6;
    }
#endif
    else {
      Tcl_AppendResult(irp, "Invalid server address (must be numeric IP)",
                       NULL);
      return TCL_ERROR;
    }

    res_enable_dot(&sa, addr, port, verify);
    return TCL_OK;
  }

  Tcl_AppendResult(irp, "Usage: dnsdot [on <server> [port] [-noverify] | off]",
                   NULL);
  return TCL_ERROR;
}

static tcl_cmds dnscmds[] = {
  {"dnsdot", tcl_dnsdot},
  {NULL,     NULL}
};

static char *dns_close(void)
{
  int i;

  del_hook(HOOK_DNS_HOSTBYIP, (Function) dns_lookup);
  del_hook(HOOK_DNS_IPBYHOST, (Function) dns_forward);
  del_hook(HOOK_SECONDLY, (Function) dns_check_expires);
  del_hook(HOOK_REHASH, (Function) dns_check_servercount);
  rem_tcl_ints(dnsints);
  rem_tcl_strings(dnsstrings);
  rem_tcl_commands(dnscmds);
  Tcl_UntraceVar(interp, "dns-servers",
                 TCL_TRACE_READS | TCL_TRACE_WRITES | TCL_TRACE_UNSETS,
                 dns_change, NULL);

  for (i = 0; i < dcc_total; i++) {
    if (dcc[i].type == &DCC_DNS && dcc[i].sock == resfd) {
      killsock(dcc[i].sock);
      lostdcc(i);
      break;
    }
  }

  dns_free_cache();
  module_undepend(MODULE_NAME);
  return NULL;
}

char *dns_start(Function *global_funcs);

static Function dns_table[] = {
  /* 0 - 3 */
  (Function) dns_start,
  (Function) dns_close,
  (Function) dns_expmem,
  (Function) dns_report,
  /* 4 - 7 */
};

EXPORT_SCOPE char *dns_start(Function *global_funcs);

char *dns_start(Function *global_funcs)
{
  int idx;

  global = global_funcs;

  module_register(MODULE_NAME, dns_table, 1, 2);
  if (!module_depend(MODULE_NAME, "eggdrop", 108, 0)) {
    module_undepend(MODULE_NAME);
    return "This module requires Eggdrop 1.8.0 or later.";
  }

  idx = new_dcc(&DCC_DNS, 0);
  if (idx < 0)
    return "NO MORE DCC CONNECTIONS -- Can't create DNS socket.";
  if (!init_dns_core()) {
    lostdcc(idx);
    return "DNS initialisation failed.";
  }
  dcc[idx].sock = resfd;
  dcc[idx].timeval = now;
  strlcpy(dcc[idx].nick, "(dns)", sizeof(dcc[idx].nick));
  /* myres only holds IPv4 servers; guard against IPv6-only configs where
   * myres.nscount may be 0 even though dns_nscount > 0. */
  if (myres.nscount > 0) {
    memcpy(&dcc[idx].sockname.addr.sa, &myres.nsaddr_list[0],
               sizeof(myres.nsaddr_list[0]));
    dcc[idx].sockname.addrlen = sizeof(myres.nsaddr_list[0]);
  }

  Tcl_TraceVar(interp, "dns-servers",
               TCL_TRACE_READS | TCL_TRACE_WRITES | TCL_TRACE_UNSETS,
               dns_change, NULL);
  add_hook(HOOK_SECONDLY, (Function) dns_check_expires);
  add_hook(HOOK_DNS_HOSTBYIP, (Function) dns_lookup);
  add_hook(HOOK_DNS_IPBYHOST, (Function) dns_forward);
  add_hook(HOOK_REHASH, (Function) dns_check_servercount);
  add_tcl_ints(dnsints);
  add_tcl_strings(dnsstrings);
  add_tcl_commands(dnscmds);
  return NULL;
}
