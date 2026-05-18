/*
 * res.h -- part of dns.mod
 *   Async DNS resolver public interface, adapted from ophion's res.h
 *   for use in eggdrop's dns module.
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

#ifndef _EGG_MOD_DNS_RES_H
#define _EGG_MOD_DNS_RES_H

#include <sys/socket.h>
#include <netinet/in.h>

/* Maximum number of nameservers read from /etc/resolv.conf */
#define IRCD_MAXNS      10

/* Maximum hostname length used internally by the resolver */
#define IRCD_RES_HOSTLEN 256

/* DNS record types */
#define T_A     1
#define T_AAAA  28
#define T_PTR   12

/* ---- resolver callback types ------------------------------------------- */

struct DNSReply {
  char                    *h_name;  /* hostname (PTR result, or nullptr) */
  struct sockaddr_storage  addr;    /* resolved address               */
};

struct DNSQuery {
  void  *ptr;
  void (*callback)(void *ptr, struct DNSReply *reply);
};

/* ---- nameserver list (exported for module reporting) ------------------- */

extern struct sockaddr_storage irc_nsaddr_list[IRCD_MAXNS];
extern int irc_nscount;

/* ---- public resolver API ----------------------------------------------- */

void init_resolver(void);
void restart_resolver(void);
void dns_req_cleanup(void);

/* DNS over TLS (RFC 7858) — stubbed unless EGG_TLS is defined.
 * sa must have the address family set; port is applied separately.
 * verify != 0 (recommended default) enables full TLS certificate chain
 * validation and hostname matching (TLS_VERIFYPEER).  Pass verify=0
 * only for private/self-signed resolvers.
 * When TLS is not compiled in, res_enable_dot() logs a warning. */
void res_enable_dot(const struct sockaddr_storage *sa,
                    const char *addr_str, uint16_t port, int verify);
void res_disable_dot(void);

/* Forward lookup (hostname -> address).  type must be T_A or T_AAAA. */
void gethost_byname_type(const char *name, struct DNSQuery *query, int type);

/* Reverse lookup (address -> hostname).  Performs fcrdns verification. */
void gethost_byaddr(const struct sockaddr_storage *addr,
                    struct DNSQuery *query);

/* Build a reverse-DNS query name (PTR / DNSBL suffix). */
void build_rdns(char *buf, size_t size,
                const struct sockaddr_storage *addr, const char *suffix);

/* Called from HOOK_SECONDLY (via dns.mod/dns.c) to drive timeouts */
void res_secondly_check(void);

/* Called when the UDP socket fd is readable (via DCC_DNS activity handler) */
void res_read_udp(void);

#endif /* _EGG_MOD_DNS_RES_H */
