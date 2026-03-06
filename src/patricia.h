/* Adapted from devinkbrown/ophion (GPL v2) */
/*
 * Dave Plonka <plonka@doit.wisc.edu>
 *
 * This product includes software developed by the University of Michigan,
 * Merit Network, Inc., and their contributors.
 *
 * This file had been called "radix.h" in the MRT sources.
 *
 * I renamed it to "patricia.h" since it's not an implementation of a general
 * radix trie.  Also, pulled in various requirements from "mrt.h" and added
 * some other things it could be used as a standalone API.
 */

#ifndef EGG_PATRICIA_H
#define EGG_PATRICIA_H

#include <sys/socket.h>
#include <netinet/in.h>

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

#define egg_prefix_touchar(prefix) ((unsigned char *)&(prefix)->add.sin)
#define MAXLINE 1024
#define BIT_TEST(f, b)  ((f) & (b))

typedef struct _egg_prefix_t
{
	unsigned short family;	/* AF_INET | AF_INET6 */
	unsigned short bitlen;	/* same as mask? */
	int ref_count;		/* reference count */
	union
	{
		struct in_addr sin;
		struct in6_addr sin6;
	}
	add;
}
egg_prefix_t;


typedef struct _egg_patricia_node_t
{
	unsigned int bit;	/* flag if this node used */
	egg_prefix_t *prefix;	/* who we are in patricia tree */
	struct _egg_patricia_node_t *l, *r;	/* left and right children */
	struct _egg_patricia_node_t *parent;	/* may be used */
	void *data;
}
egg_patricia_node_t;

typedef struct _egg_patricia_tree_t
{
	egg_patricia_node_t *head;
	unsigned int maxbits;	/* for IP, 32 bit addresses */
	int num_active_node;	/* for debug purpose */
}
egg_patricia_tree_t;


egg_patricia_node_t *egg_match_ip(egg_patricia_tree_t *tree, struct sockaddr *ip);
egg_patricia_node_t *egg_match_ip_exact(egg_patricia_tree_t *tree, struct sockaddr *ip,
				      unsigned int len);
egg_patricia_node_t *egg_match_string(egg_patricia_tree_t *tree, const char *string);
egg_patricia_node_t *egg_match_exact_string(egg_patricia_tree_t *tree, const char *string);
egg_patricia_node_t *egg_patricia_search_exact(egg_patricia_tree_t *patricia, egg_prefix_t *prefix);
egg_patricia_node_t *egg_patricia_search_best(egg_patricia_tree_t *patricia, egg_prefix_t *prefix);
egg_patricia_node_t *egg_patricia_search_best2(egg_patricia_tree_t *patricia,
					     egg_prefix_t *prefix, int inclusive);
egg_patricia_node_t *egg_patricia_lookup(egg_patricia_tree_t *patricia, egg_prefix_t *prefix);

void egg_patricia_remove(egg_patricia_tree_t *patricia, egg_patricia_node_t *node);
egg_patricia_tree_t *egg_new_patricia(int maxbits);
void egg_clear_patricia(egg_patricia_tree_t *patricia, void (*func) (void *));
void egg_destroy_patricia(egg_patricia_tree_t *patricia, void (*func) (void *));
void egg_patricia_process(egg_patricia_tree_t *patricia, void (*func) (egg_prefix_t *, void *));
void egg_init_patricia(void);


egg_patricia_node_t *make_and_lookup(egg_patricia_tree_t *tree, const char *string);
egg_patricia_node_t *make_and_lookup_ip(egg_patricia_tree_t *tree, struct sockaddr *, int bitlen);


#define EGG_PATRICIA_MAXBITS 128
#define EGG_PATRICIA_NBIT(x)        (0x80 >> ((x) & 0x7f))
#define EGG_PATRICIA_NBYTE(x)       ((x) >> 3)

#define EGG_PATRICIA_DATA_GET(node, type) (type *)((node)->data)
#define EGG_PATRICIA_DATA_SET(node, value) ((node)->data = (void *)(value))

#define EGG_PATRICIA_WALK(Xhead, Xnode) \
    do { \
	egg_patricia_node_t *Xstack[EGG_PATRICIA_MAXBITS+1]; \
	egg_patricia_node_t **Xsp = Xstack; \
	egg_patricia_node_t *Xrn = (Xhead); \
	while ((Xnode = Xrn)) { \
	    if (Xnode->prefix)

#define EGG_PATRICIA_WALK_ALL(Xhead, Xnode) \
do { \
	egg_patricia_node_t *Xstack[EGG_PATRICIA_MAXBITS+1]; \
	egg_patricia_node_t **Xsp = Xstack; \
	egg_patricia_node_t *Xrn = (Xhead); \
	while ((Xnode = Xrn)) { \
	    if (1)

#define EGG_PATRICIA_WALK_BREAK { \
	    if (Xsp != Xstack) { \
		Xrn = *(--Xsp); \
	     } else { \
		Xrn = (egg_patricia_node_t *) 0; \
	    } \
	    continue; }

#define EGG_PATRICIA_WALK_END \
	    if (Xrn->l) { \
		if (Xrn->r) { \
		    *Xsp++ = Xrn->r; \
		} \
		Xrn = Xrn->l; \
	    } else if (Xrn->r) { \
		Xrn = Xrn->r; \
	    } else if (Xsp != Xstack) { \
		Xrn = *(--Xsp); \
	    } else { \
		Xrn = (egg_patricia_node_t *) 0; \
	    } \
	} \
    } while (0)

#endif /* EGG_PATRICIA_H */
