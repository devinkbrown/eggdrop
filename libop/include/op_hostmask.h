/*
 * libop/include/op_hostmask.h — IP / hostmask parsing and matching.
 *
 * Ported from ophion ircd/hostmask.c.  Provides optimised bitwise
 * IPv4 and IPv6 prefix comparison and netmask string parsing.
 * ConfItem / AddressRec server-specific parts are not included.
 */

#ifndef OP_HOSTMASK_H
#define OP_HOSTMASK_H

#include <stddef.h>
#include <sys/socket.h>

struct op_sockaddr_storage;

/* ── Parse-result discriminant ──────────────────────────────────────── */

enum op_hm_type {
	OP_HM_ERROR = 0,   /* invalid / unparseable                    */
	OP_HM_HOST  = 1,   /* wildcard or plain hostname               */
	OP_HM_IPV4  = 2,   /* dotted-quad IPv4, possibly with /prefix  */
	OP_HM_IPV6  = 3,   /* colon-hex IPv6, possibly with /prefix    */
};

/* ── Netmask parsing ─────────────────────────────────────────────────── */

/*
 * op_parse_netmask — parse an IP address with optional /prefix into
 * binary form.
 *
 *   text   input string, e.g. "192.168.1.0/24" or "::1/128"
 *   addr   receives the binary address (may be NULL to probe type only)
 *   bits   receives the prefix length (may be NULL)
 *
 * Returns OP_HM_IPV4, OP_HM_IPV6, OP_HM_HOST, or OP_HM_ERROR.
 * Out-of-range prefix lengths are clamped to the address-family maximum.
 */
int op_parse_netmask(const char *text,
                     struct op_sockaddr_storage *addr, int *bits);

/*
 * op_parse_netmask_strict — like op_parse_netmask but returns OP_HM_ERROR
 * for out-of-range prefix lengths instead of clamping.
 */
int op_parse_netmask_strict(const char *text,
                             struct op_sockaddr_storage *addr, int *bits);

/* ── Bitwise address comparison ─────────────────────────────────────── */

/*
 * op_match_ipv4 — compare two IPv4 sockaddrs under a /bits prefix.
 * Returns 1 if the first `bits` bits are equal, 0 otherwise.
 * bits ≤ 0 → always 1 (match-all); bits ≥ 32 → full 32-bit compare.
 */
int op_match_ipv4(struct sockaddr *addr, struct sockaddr *mask, int bits);

/*
 * op_match_ipv6 — compare two IPv6 sockaddrs under a /bits prefix.
 * Returns 1 if the first `bits` bits are equal, 0 otherwise.
 * bits ≤ 0 → always 1; bits ≥ 128 → full 128-bit compare.
 */
int op_match_ipv6(struct sockaddr *addr, struct sockaddr *mask, int bits);

#endif /* OP_HOSTMASK_H */
