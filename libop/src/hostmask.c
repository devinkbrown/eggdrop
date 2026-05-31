/*
 * libop/src/hostmask.c — IP / hostmask parsing and bitwise matching.
 *
 * Ported from ophion ircd/hostmask.c (charybdis / ircd-ratbox lineage).
 * Server-specific code (ConfItem, AddressRec, atable, find_conf_by_address,
 * etc.) is not included.
 *
 * Provides:
 *   op_match_ipv4 / op_match_ipv6  — optimised prefix comparison
 *   op_parse_netmask               — "addr[/bits]" string → binary
 */

#include <libop_config.h>
#include <op_lib.h>
#include <op_hostmask.h>

#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ── Bitwise address comparison ─────────────────────────────────────── */

static inline bool __attribute__((hot))
match_ipv4_bits(const struct sockaddr_in *restrict a,
                const struct sockaddr_in *restrict b,
                int bits)
{
	if (__builtin_expect(bits <= 0, 0))
		return true;
	uint32_t mask = bits >= 32 ? 0xFFFFFFFFu : ~((1u << (32 - bits)) - 1u);
	uint32_t av   = ntohl(a->sin_addr.s_addr);
	uint32_t bv   = ntohl(b->sin_addr.s_addr);
	return (av & mask) == (bv & mask);
}

static inline bool __attribute__((hot))
match_ipv6_bits(const struct sockaddr_in6 *restrict a,
                const struct sockaddr_in6 *restrict b,
                int bits)
{
	if (__builtin_expect(bits <= 0, 0))
		return true;

	const uint32_t *aw = (const uint32_t *)(const void *)&a->sin6_addr;
	const uint32_t *bw = (const uint32_t *)(const void *)&b->sin6_addr;

	int remaining = bits;
	for (int w = 0; w < 4; w++) {
		if (remaining >= 32) {
			if (ntohl(aw[w]) != ntohl(bw[w]))
				return false;
			remaining -= 32;
		} else if (remaining > 0) {
			uint32_t mask = ~((1u << (32 - remaining)) - 1u);
			return (ntohl(aw[w]) & mask) == (ntohl(bw[w]) & mask);
		} else {
			return true;
		}
	}
	return true;
}

int __attribute__((hot))
op_match_ipv4(struct sockaddr *addr, struct sockaddr *mask, int bits)
{
	return match_ipv4_bits((struct sockaddr_in *)(void *)addr,
	                       (struct sockaddr_in *)(void *)mask,
	                       bits) ? 1 : 0;
}

int __attribute__((hot))
op_match_ipv6(struct sockaddr *addr, struct sockaddr *mask, int bits)
{
	return match_ipv6_bits((struct sockaddr_in6 *)(void *)addr,
	                       (struct sockaddr_in6 *)(void *)mask,
	                       bits) ? 1 : 0;
}

/* ── Netmask parser ─────────────────────────────────────────────────── */

static int __attribute__((cold))
parse_netmask_impl(const char *restrict text,
                   struct op_sockaddr_storage *restrict naddr,
                   int *restrict nb,
                   bool strict)
{
	/* Copy to mutable stack buffer so we can NUL-terminate at '/'. */
	char ip[256];
	op_strlcpy(ip, text, sizeof ip);

	struct op_sockaddr_storage xaddr;
	int xb;
	struct op_sockaddr_storage *addr = naddr ? naddr : &xaddr;
	int                        *b    = nb    ? nb    : &xb;

	/* Wildcard patterns are host masks — no IP parsing. */
	if (__builtin_expect(strpbrk(ip, "*?") != NULL, 0))
		return OP_HM_HOST;

	/* IPv6: contains ':' */
	if (strchr(ip, ':')) {
		char *ptr = strchr(ip, '/');
		if (ptr) {
			*ptr++ = '\0';
			char *endp;
			long n = strtol(ptr, &endp, 10);
			if (endp == ptr || n < 0)
				return OP_HM_HOST;
			if (n > 128 || *endp != '\0') {
				if (strict)
					return OP_HM_ERROR;
				n = 128;
			}
			*b = (int)n;
		} else {
			*b = 128;
		}
		return op_inet_pton_sock(ip, addr) > 0 ? OP_HM_IPV6 : OP_HM_HOST;
	}

	/* IPv4: contains '.' */
	if (strchr(text, '.')) {
		char *ptr = strchr(ip, '/');
		if (ptr) {
			*ptr++ = '\0';
			char *endp;
			long n = strtol(ptr, &endp, 10);
			if (endp == ptr || n < 0)
				return OP_HM_HOST;
			if (n > 32 || *endp != '\0') {
				if (strict)
					return OP_HM_ERROR;
				n = 32;
			}
			*b = (int)n;
		} else {
			*b = 32;
		}
		return op_inet_pton_sock(ip, addr) > 0 ? OP_HM_IPV4 : OP_HM_HOST;
	}

	return OP_HM_HOST;
}

int
op_parse_netmask(const char *text,
                 struct op_sockaddr_storage *addr, int *bits)
{
	return parse_netmask_impl(text, addr, bits, false);
}

int
op_parse_netmask_strict(const char *text,
                         struct op_sockaddr_storage *addr, int *bits)
{
	return parse_netmask_impl(text, addr, bits, true);
}
