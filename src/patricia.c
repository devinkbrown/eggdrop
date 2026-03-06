/* Adapted from devinkbrown/ophion (GPL v2) */
/*
 * Yanked out of Net::Patricia by Aaron Sethman <androsyn@ratbox.org>
 *
 * This was then yanked out of the ratbox/devel/src tree and stuffed into
 * libop and had function names changed, but otherwise not really altered.
 *
 * Dave Plonka <plonka@doit.wisc.edu>
 *
 * This product includes software developed by the University of Michigan,
 * Merit Network, Inc., and their contributors.
 *
 * This file had been called "radix.c" in the MRT sources.
 *
 * I renamed it to "patricia.c" since it's not an implementation of a general
 * radix trie.  Also I pulled in various requirements from "prefix.c" and
 * "demo.c" so that it could be used as a standalone API.
 *
 * This product includes software developed by the University of Michigan, Merit
 * Network, Inc., and their contributors.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "main.h"
#include "eggdrop.h"
#include "patricia.h"

/* Enable both of these to debug patricia.c
 * #define NOTYET 1
 * #define PATRICIA_DEBUG 1
 */

__attribute__((cold))
void
egg_init_patricia(void)
{
	return;
}

/* -------------------------------------------------------------------------
 * Internal prefix helpers
 * ---------------------------------------------------------------------- */

/*
 * prefix_tochar
 *
 * Return a read-only byte pointer into the address portion of a prefix.
 */
static inline const uint8_t *
prefix_tochar(const egg_prefix_t *restrict prefix)
{
	if (__builtin_expect(prefix == NULL, 0))
		return NULL;
	return (const uint8_t *)&prefix->add.sin;
}

/*
 * comp_with_mask
 *
 * Return 1 if the first 'mask' bits of addr and dest are identical.
 * Uses a combined byte-compare + single-bit-residue check to avoid
 * bit-by-bit loops on the common path.
 */
static __attribute__((hot)) int
comp_with_mask(const void *restrict addr, const void *restrict dest,
               unsigned int mask)
{
	/* Full-byte comparison first */
	if (memcmp(addr, dest, mask >> 3) == 0)
	{
		unsigned int remainder = mask & 7u;
		if (remainder == 0)
			return 1;
		unsigned int n = mask >> 3;
		uint8_t m = (uint8_t)(0xFF << (8u - remainder));
		if ((((const uint8_t *)addr)[n] & m) ==
		    (((const uint8_t *)dest)[n] & m))
			return 1;
	}
	return 0;
}

/*
 * New_Prefix2
 *
 * Allocate (or reuse) an egg_prefix_t and fill it from the raw address bytes.
 */
static __attribute__((cold)) egg_prefix_t *
New_Prefix2(int family, const void *restrict dest, int bitlen, egg_prefix_t *prefix)
{
	bool dynamic_allocated = false;
	int default_bitlen = 128;

	if (family == AF_INET6)
	{
		default_bitlen = 128;
		if (prefix == NULL)
		{
			prefix = nmalloc(sizeof(egg_prefix_t));
			dynamic_allocated = true;
		}
		memcpy(&prefix->add.sin6, dest, 16);
	}
	else if (family == AF_INET)
	{
		if (prefix == NULL)
		{
			prefix = nmalloc(sizeof(egg_prefix_t));
			dynamic_allocated = true;
		}
		memcpy(&prefix->add.sin, dest, 4);
	}
	else
	{
		return NULL;
	}

	prefix->bitlen   = (unsigned short)((bitlen >= 0) ? bitlen : default_bitlen);
	prefix->family   = (unsigned short)family;
	prefix->ref_count = 0;
	if (dynamic_allocated)
		prefix->ref_count++;

	return prefix;
}

static __attribute__((cold)) egg_prefix_t *
New_Prefix(int family, const void *restrict dest, int bitlen)
{
	return New_Prefix2(family, dest, bitlen, NULL);
}

/*
 * ascii2prefix
 *
 * Parse a CIDR string (e.g. "192.0.2.0/24") into an egg_prefix_t.
 */
static __attribute__((cold)) egg_prefix_t *
ascii2prefix(int family, const char *restrict string)
{
	long bitlen, maxbitlen = 0;
	char *cp;
	struct in_addr  sinaddr;
	struct in6_addr sinaddr6;
	int result;
	char save[MAXLINE];

	if (__builtin_expect(string == NULL, 0))
		return NULL;

	/* Auto-detect family from presence of ':' */
	if (family == 0)
	{
		family = AF_INET;
		if (strchr(string, ':'))
			family = AF_INET6;
	}

	if (family == AF_INET)
		maxbitlen = 32;
	else if (family == AF_INET6)
		maxbitlen = 128;

	if ((cp = strchr(string, '/')) != NULL)
	{
		bitlen = atol(cp + 1);
		assert(cp - string < MAXLINE);
		memcpy(save, string, (size_t)(cp - string));
		save[cp - string] = '\0';
		string = save;
		if (bitlen < 0 || bitlen > maxbitlen)
			bitlen = maxbitlen;
	}
	else
	{
		bitlen = maxbitlen;
	}

	if (family == AF_INET)
	{
		if ((result = inet_pton(AF_INET, string, &sinaddr)) <= 0)
			return NULL;
		return New_Prefix(AF_INET, &sinaddr, (int)bitlen);
	}
	else if (family == AF_INET6)
	{
		if ((result = inet_pton(AF_INET6, string, &sinaddr6)) <= 0)
			return NULL;
		return New_Prefix(AF_INET6, &sinaddr6, (int)bitlen);
	}
	return NULL;
}

static __attribute__((cold)) egg_prefix_t *
Ref_Prefix(egg_prefix_t *restrict prefix)
{
	if (__builtin_expect(prefix == NULL, 0))
		return NULL;
	if (prefix->ref_count == 0)
		return New_Prefix2(prefix->family, &prefix->add, prefix->bitlen, NULL);
	prefix->ref_count++;
	return prefix;
}

static __attribute__((cold)) void
Deref_Prefix(egg_prefix_t *restrict prefix)
{
	if (__builtin_expect(prefix == NULL, 0))
		return;
	assert(prefix->ref_count > 0);
	prefix->ref_count--;
	assert(prefix->ref_count >= 0);
	if (prefix->ref_count <= 0)
		nfree(prefix);
}

static int num_active_patricia = 0;

/* -------------------------------------------------------------------------
 * Tree lifecycle
 * ---------------------------------------------------------------------- */

__attribute__((cold))
egg_patricia_tree_t *
egg_new_patricia(int maxbits)
{
	egg_patricia_tree_t *patricia = nmalloc(sizeof(egg_patricia_tree_t));

	patricia->maxbits        = (unsigned int)maxbits;
	patricia->head           = NULL;
	patricia->num_active_node = 0;
	assert(maxbits <= EGG_PATRICIA_MAXBITS);
	num_active_patricia++;
	return patricia;
}

/*
 * egg_clear_patricia
 *
 * Iterative (non-recursive) post-order traversal to free all nodes.
 * Uses an explicit stack to avoid deep call-chains on large tries.
 */
__attribute__((cold))
void
egg_clear_patricia(egg_patricia_tree_t *restrict patricia, void (*func)(void *))
{
	assert(patricia);

	if (patricia->head)
	{
		egg_patricia_node_t *Xstack[EGG_PATRICIA_MAXBITS + 1];
		egg_patricia_node_t **Xsp  = Xstack;
		egg_patricia_node_t *Xrn   = patricia->head;

		while (Xrn)
		{
			egg_patricia_node_t *l = Xrn->l;
			egg_patricia_node_t *r = Xrn->r;

			if (Xrn->prefix)
			{
				Deref_Prefix(Xrn->prefix);
				if (Xrn->data && func)
					func(Xrn->data);
			}
			else
			{
				assert(Xrn->data == NULL);
			}
			nfree(Xrn);
			patricia->num_active_node--;

			if (l)
			{
				if (r)
					*Xsp++ = r;
				Xrn = l;
			}
			else if (r)
			{
				Xrn = r;
			}
			else if (Xsp != Xstack)
			{
				Xrn = *(--Xsp);
			}
			else
			{
				Xrn = NULL;
			}
		}
	}
	assert(patricia->num_active_node == 0);
	nfree(patricia);
}

__attribute__((cold))
void
egg_destroy_patricia(egg_patricia_tree_t *restrict patricia, void (*func)(void *))
{
	egg_clear_patricia(patricia, func);
	num_active_patricia--;
}

/*
 * egg_patricia_process
 *
 * Walk the trie in order, calling func(prefix, data) for every node that
 * carries a prefix.
 */
__attribute__((cold))
void
egg_patricia_process(egg_patricia_tree_t *restrict patricia,
                    void (*func)(egg_prefix_t *, void *))
{
	egg_patricia_node_t *node;
	assert(func);

	EGG_PATRICIA_WALK(patricia->head, node)
	{
		func(node->prefix, node->data);
	}
	EGG_PATRICIA_WALK_END;
}

/* -------------------------------------------------------------------------
 * Lookup / search
 * ---------------------------------------------------------------------- */

/*
 * egg_patricia_search_exact
 *
 * Search for an exact match of prefix in the trie.
 * Returns NULL if not found.
 *
 * Prefetches the next candidate node before branching to hide memory
 * latency on the common path.
 */
__attribute__((hot))
egg_patricia_node_t *
egg_patricia_search_exact(egg_patricia_tree_t *restrict patricia,
                         egg_prefix_t *restrict prefix)
{
	egg_patricia_node_t *node;
	const uint8_t *addr;
	unsigned int bitlen;

	assert(patricia);
	assert(prefix);
	assert(prefix->bitlen <= patricia->maxbits);

	if (__builtin_expect(patricia->head == NULL, 0))
		return NULL;

	node   = patricia->head;
	addr   = egg_prefix_touchar(prefix);
	bitlen = prefix->bitlen;

	while (node->bit < bitlen)
	{
		egg_patricia_node_t *next;
		if (BIT_TEST(addr[node->bit >> 3], 0x80 >> (node->bit & 0x07)))
			next = node->r;
		else
			next = node->l;

		if (__builtin_expect(next == NULL, 0))
			return NULL;

		/* Prefetch the next-next node to overlap memory access with
		 * the branch decision above. */
		__builtin_prefetch(next, 0, 1);
		node = next;
	}

	if (node->bit > bitlen || node->prefix == NULL)
		return NULL;

	assert(node->bit == bitlen);
	assert(node->bit == node->prefix->bitlen);

	if (comp_with_mask(prefix_tochar(node->prefix), prefix_tochar(prefix), bitlen))
		return node;

	return NULL;
}

/*
 * egg_patricia_search_best2
 *
 * Longest-prefix match: walk down the trie saving each node that carries a
 * prefix, then scan back up for the deepest match.
 *
 * 'inclusive' controls whether the prefix itself is eligible.
 */
__attribute__((hot))
egg_patricia_node_t *
egg_patricia_search_best2(egg_patricia_tree_t *restrict patricia,
                         egg_prefix_t *restrict prefix, int inclusive)
{
	egg_patricia_node_t *node;
	egg_patricia_node_t *stack[EGG_PATRICIA_MAXBITS + 1];
	const uint8_t *addr;
	unsigned int bitlen;
	int cnt = 0;

	assert(patricia);
	assert(prefix);
	assert(prefix->bitlen <= patricia->maxbits);

	if (__builtin_expect(patricia->head == NULL, 0))
		return NULL;

	node   = patricia->head;
	addr   = egg_prefix_touchar(prefix);
	bitlen = prefix->bitlen;

	while (node->bit < bitlen)
	{
		if (node->prefix)
			stack[cnt++] = node;

		egg_patricia_node_t *next;
		if (BIT_TEST(addr[node->bit >> 3], 0x80 >> (node->bit & 0x07)))
			next = node->r;
		else
			next = node->l;

		if (__builtin_expect(next == NULL, 0))
			break;

		__builtin_prefetch(next, 0, 1);
		node = next;
	}

	if (inclusive && node && node->prefix)
		stack[cnt++] = node;

	if (__builtin_expect(cnt <= 0, 0))
		return NULL;

	/* Scan from deepest candidate upward */
	while (--cnt >= 0)
	{
		node = stack[cnt];
		if (comp_with_mask(prefix_tochar(node->prefix),
		                   prefix_tochar(prefix),
		                   node->prefix->bitlen))
			return node;
	}
	return NULL;
}

__attribute__((hot))
egg_patricia_node_t *
egg_patricia_search_best(egg_patricia_tree_t *restrict patricia,
                        egg_prefix_t *restrict prefix)
{
	return egg_patricia_search_best2(patricia, prefix, 1);
}

/*
 * egg_patricia_lookup
 *
 * Insert or find a node for prefix.  If the node already exists (exact
 * match) return it.  Otherwise insert new nodes as required, splitting
 * glue nodes where the trie diverges.
 *
 * Uses __builtin_clz to find the first differing bit without a byte-by-byte
 * inner loop.
 */
__attribute__((hot))
egg_patricia_node_t *
egg_patricia_lookup(egg_patricia_tree_t *restrict patricia,
                   egg_prefix_t *restrict prefix)
{
	egg_patricia_node_t *node, *new_node, *parent, *glue;
	const uint8_t *addr, *test_addr;
	unsigned int bitlen, check_bit, differ_bit;
	unsigned int i, j, r;

	assert(patricia);
	assert(prefix);
	assert(prefix->bitlen <= patricia->maxbits);

	if (__builtin_expect(patricia->head == NULL, 0))
	{
		node            = nmalloc(sizeof(egg_patricia_node_t));
		node->bit       = prefix->bitlen;
		node->prefix    = Ref_Prefix(prefix);
		node->parent    = NULL;
		node->l = node->r = NULL;
		node->data      = NULL;
		patricia->head  = node;
		patricia->num_active_node++;
		return node;
	}

	addr   = egg_prefix_touchar(prefix);
	bitlen = prefix->bitlen;
	node   = patricia->head;

	while (node->bit < bitlen || node->prefix == NULL)
	{
		if (node->bit < patricia->maxbits &&
		    BIT_TEST(addr[node->bit >> 3], 0x80 >> (node->bit & 0x07)))
		{
			if (node->r == NULL)
				break;
			__builtin_prefetch(node->r, 0, 1);
			node = node->r;
		}
		else
		{
			if (node->l == NULL)
				break;
			__builtin_prefetch(node->l, 0, 1);
			node = node->l;
		}
		assert(node);
	}

	assert(node->prefix);

	test_addr  = egg_prefix_touchar(node->prefix);
	check_bit  = (node->bit < bitlen) ? node->bit : bitlen;
	differ_bit = 0;

	for (i = 0; i * 8 < check_bit; i++)
	{
		r = (unsigned int)(addr[i] ^ test_addr[i]);
		if (r == 0)
		{
			differ_bit = (i + 1) * 8;
			continue;
		}
		/*
		 * __builtin_clz gives the number of leading zero bits in r,
		 * so the first differing bit is at position i*8 + clz(r).
		 * (r is non-zero, so clz is safe.)
		 */
		j = (unsigned int)__builtin_clz(r) - (8u * (sizeof(unsigned int) - 1u));
		differ_bit = i * 8 + j;
		break;
	}
	if (differ_bit > check_bit)
		differ_bit = check_bit;

	parent = node->parent;
	while (parent && parent->bit >= differ_bit)
	{
		node   = parent;
		parent = node->parent;
	}

	if (differ_bit == bitlen && node->bit == bitlen)
	{
		if (node->prefix)
			return node;
		node->prefix = Ref_Prefix(prefix);
		assert(node->data == NULL);
		return node;
	}

	new_node         = nmalloc(sizeof(egg_patricia_node_t));
	new_node->bit    = prefix->bitlen;
	new_node->prefix = Ref_Prefix(prefix);
	new_node->parent = NULL;
	new_node->l = new_node->r = NULL;
	new_node->data = NULL;
	patricia->num_active_node++;

	if (node->bit == differ_bit)
	{
		new_node->parent = node;
		if (node->bit < patricia->maxbits &&
		    BIT_TEST(addr[node->bit >> 3], 0x80 >> (node->bit & 0x07)))
		{
			assert(node->r == NULL);
			node->r = new_node;
		}
		else
		{
			assert(node->l == NULL);
			node->l = new_node;
		}
		return new_node;
	}

	if (bitlen == differ_bit)
	{
		test_addr = egg_prefix_touchar(node->prefix);
		if (bitlen < patricia->maxbits &&
		    BIT_TEST(test_addr[bitlen >> 3], 0x80 >> (bitlen & 0x07)))
			new_node->r = node;
		else
			new_node->l = node;

		new_node->parent = node->parent;

		if (node->parent == NULL)
		{
			assert(patricia->head == node);
			patricia->head = new_node;
		}
		else if (node->parent->r == node)
		{
			node->parent->r = new_node;
		}
		else
		{
			node->parent->l = new_node;
		}
		node->parent = new_node;
	}
	else
	{
		glue          = nmalloc(sizeof(egg_patricia_node_t));
		glue->bit     = differ_bit;
		glue->prefix  = NULL;
		glue->parent  = node->parent;
		glue->data    = NULL;
		patricia->num_active_node++;

		if (differ_bit < patricia->maxbits &&
		    BIT_TEST(addr[differ_bit >> 3], 0x80 >> (differ_bit & 0x07)))
		{
			glue->r = new_node;
			glue->l = node;
		}
		else
		{
			glue->r = node;
			glue->l = new_node;
		}
		new_node->parent = glue;

		if (node->parent == NULL)
		{
			assert(patricia->head == node);
			patricia->head = glue;
		}
		else if (node->parent->r == node)
		{
			node->parent->r = glue;
		}
		else
		{
			node->parent->l = glue;
		}
		node->parent = glue;
	}
	return new_node;
}

/* -------------------------------------------------------------------------
 * Node removal
 * ---------------------------------------------------------------------- */

__attribute__((cold))
void
egg_patricia_remove(egg_patricia_tree_t *restrict patricia,
                   egg_patricia_node_t *restrict node)
{
	egg_patricia_node_t *parent, *child;

	assert(patricia);
	assert(node);

	if (node->r && node->l)
	{
		/* Internal node with two children: convert to glue node */
		if (node->prefix != NULL)
			Deref_Prefix(node->prefix);
		node->prefix = NULL;
		node->data   = NULL;
		return;
	}

	if (node->r == NULL && node->l == NULL)
	{
		/* Leaf node */
		parent = node->parent;
		bool node_was_right = (parent != NULL && parent->r == node);

		Deref_Prefix(node->prefix);
		nfree(node);
		patricia->num_active_node--;

		if (parent == NULL)
		{
			patricia->head = NULL;
			return;
		}

		if (node_was_right)
		{
			parent->r = NULL;
			child     = parent->l;
		}
		else
		{
			parent->l = NULL;
			child     = parent->r;
		}

		if (parent->prefix)
			return;

		/* Remove the now-childless glue parent too */
		if (parent->parent == NULL)
		{
			assert(patricia->head == parent);
			patricia->head = child;
		}
		else if (parent->parent->r == parent)
		{
			parent->parent->r = child;
		}
		else
		{
			assert(parent->parent->l == parent);
			parent->parent->l = child;
		}
		child->parent = parent->parent;
		nfree(parent);
		patricia->num_active_node--;
		return;
	}

	/* Node has exactly one child */
	child  = node->r ? node->r : node->l;
	parent = node->parent;
	bool node_was_right = (parent != NULL && parent->r == node);

	child->parent = parent;
	Deref_Prefix(node->prefix);
	nfree(node);
	patricia->num_active_node--;

	if (parent == NULL)
	{
		patricia->head = child;
		return;
	}

	if (node_was_right)
		parent->r = child;
	else
		parent->l = child;
}

/* -------------------------------------------------------------------------
 * Public convenience wrappers
 * ---------------------------------------------------------------------- */

__attribute__((hot))
egg_patricia_node_t *
make_and_lookup_ip(egg_patricia_tree_t *restrict tree, struct sockaddr *restrict in,
                   int bitlen)
{
	egg_prefix_t *prefix;
	egg_patricia_node_t *node;
	void *ipptr = NULL;

	if (in->sa_family == AF_INET6)
		ipptr = &((struct sockaddr_in6 *)in)->sin6_addr;
	else
		ipptr = &((struct sockaddr_in *)in)->sin_addr;

	prefix = New_Prefix(in->sa_family, ipptr, bitlen);
	if (__builtin_expect(prefix == NULL, 0))
		return NULL;

	node = egg_patricia_lookup(tree, prefix);
	Deref_Prefix(prefix);
	return node;
}

__attribute__((cold))
egg_patricia_node_t *
make_and_lookup(egg_patricia_tree_t *restrict tree, const char *restrict string)
{
	egg_prefix_t *prefix;
	egg_patricia_node_t *node;

	if ((prefix = ascii2prefix(AF_INET, string)) != NULL)
		node = egg_patricia_lookup(tree, prefix);
	else if ((prefix = ascii2prefix(AF_INET6, string)) != NULL)
		node = egg_patricia_lookup(tree, prefix);
	else
		return NULL;

	Deref_Prefix(prefix);
	return node;
}

__attribute__((hot))
egg_patricia_node_t *
egg_match_ip(egg_patricia_tree_t *restrict tree, struct sockaddr *restrict ip)
{
	egg_prefix_t *prefix;
	egg_patricia_node_t *node;
	void *ipptr;
	unsigned int len;
	int family;

	if (ip->sa_family == AF_INET6)
	{
		len    = 128;
		family = AF_INET6;
		ipptr  = &((struct sockaddr_in6 *)ip)->sin6_addr;
	}
	else
	{
		len    = 32;
		family = AF_INET;
		ipptr  = &((struct sockaddr_in *)ip)->sin_addr;
	}

	if ((prefix = New_Prefix(family, ipptr, (int)len)) != NULL)
	{
		node = egg_patricia_search_best(tree, prefix);
		Deref_Prefix(prefix);
		return node;
	}
	return NULL;
}

__attribute__((hot))
egg_patricia_node_t *
egg_match_ip_exact(egg_patricia_tree_t *restrict tree, struct sockaddr *restrict ip,
                  unsigned int len)
{
	egg_prefix_t *prefix;
	egg_patricia_node_t *node;
	void *ipptr;
	int family;

	if (ip->sa_family == AF_INET6)
	{
		if (len > 128)
			len = 128;
		family = AF_INET6;
		ipptr  = &((struct sockaddr_in6 *)ip)->sin6_addr;
	}
	else
	{
		if (len > 32)
			len = 32;
		family = AF_INET;
		ipptr  = &((struct sockaddr_in *)ip)->sin_addr;
	}

	if ((prefix = New_Prefix(family, ipptr, (int)len)) != NULL)
	{
		node = egg_patricia_search_exact(tree, prefix);
		Deref_Prefix(prefix);
		return node;
	}
	return NULL;
}

__attribute__((hot))
egg_patricia_node_t *
egg_match_string(egg_patricia_tree_t *restrict tree, const char *restrict string)
{
	egg_patricia_node_t *node;
	egg_prefix_t *prefix;

	if ((prefix = ascii2prefix(AF_INET, string)) != NULL)
	{
		node = egg_patricia_search_best(tree, prefix);
		Deref_Prefix(prefix);
	}
	else if ((prefix = ascii2prefix(AF_INET6, string)) != NULL)
	{
		node = egg_patricia_search_best(tree, prefix);
		Deref_Prefix(prefix);
	}
	else
		return NULL;

	return node;
}

__attribute__((cold))
egg_patricia_node_t *
egg_match_exact_string(egg_patricia_tree_t *restrict tree, const char *restrict string)
{
	egg_prefix_t *prefix;
	egg_patricia_node_t *node;

	if ((prefix = ascii2prefix(AF_INET, string)) != NULL)
	{
		node = egg_patricia_search_exact(tree, prefix);
		Deref_Prefix(prefix);
	}
	else if ((prefix = ascii2prefix(AF_INET6, string)) != NULL)
	{
		node = egg_patricia_search_exact(tree, prefix);
		Deref_Prefix(prefix);
	}
	else
		return NULL;

	return node;
}
