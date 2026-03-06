/* Adapted from devinkbrown/ophion (GPL v2) */
/*
 * dictionary.h: Dictionary-based storage.
 *
 * Copyright (c) 2007 William Pitcock <nenolod -at- sacredspiral.co.uk>
 * Copyright (c) 2007 Jilles Tjoelker <jilles -at- stack.nl>
 * Copyright (c) 2025 ophion development team
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice is present in all copies.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef EGG_DICTIONARY_H
#define EGG_DICTIONARY_H

#include <stdint.h>
#include <stddef.h>

typedef struct egg_dictionary egg_dictionary;
typedef struct egg_dictionary_element egg_dictionary_element;
typedef struct egg_dictionary_iter egg_dictionary_iter;

struct egg_dictionary;

typedef int (*DCF)(const void *a, const void *b);

/* DCF-compatible wrapper around strcasecmp.
 * Use this as the comparator when dictionary keys are C strings. */
static inline int egg_dict_strcasecmp(const void *a, const void *b)
{
	return strcasecmp((const char *)a, (const char *)b);
}

struct egg_dictionary_element
{
	egg_dictionary_element *left, *right, *prev, *next;
	void *data;
	const void *key;
	int position;
};

struct egg_dictionary_iter
{
	egg_dictionary_element *cur, *next;
};

/*
 * this is a convenience macro for inlining iteration of dictionaries.
 */
#define EGG_DICTIONARY_FOREACH(element, state, dict) for (egg_dictionary_foreach_start((dict), (state)); (element = egg_dictionary_foreach_cur((dict), (state))); egg_dictionary_foreach_next((dict), (state)))

/*
 * egg_dictionary_create() creates a new dictionary tree which has a name.
 * name is the name, compare_cb is the comparator.
 */
extern egg_dictionary *egg_dictionary_create(const char *name, DCF compare_cb);

/*
 * egg_dictionary_set_comparator_func() resets the comparator used for lookups
 * and insertions in the DTree structure.
 */
extern void egg_dictionary_set_comparator_func(egg_dictionary *dict,
	DCF compare_cb);

/*
 * egg_dictionary_get_comparator_func() returns the comparator used for lookups
 * and insertions in the DTree structure.
 */
extern DCF egg_dictionary_get_comparator_func(egg_dictionary *dict);

/*
 * egg_dictionary_get_linear_index() returns the linear index of an object in
 * the DTree structure.
 */
extern int egg_dictionary_get_linear_index(egg_dictionary *dict, const void *key);

/*
 * egg_dictionary_destroy() destroys all entries in a dtree, and also optionally
 * calls a defined callback function to destroy any data attached to it.
 */
extern void egg_dictionary_destroy(egg_dictionary *dtree,
	void (*destroy_cb)(egg_dictionary_element *delem, void *privdata),
	void *privdata);

/*
 * egg_dictionary_foreach() iterates all entries in a dtree, and also optionally
 * calls a defined callback function to use any data attached to it.
 *
 * To shortcircuit iteration, return non-zero from the callback function.
 */
extern void egg_dictionary_foreach(egg_dictionary *dtree,
	int (*foreach_cb)(egg_dictionary_element *delem, void *privdata),
	void *privdata);

/*
 * egg_dictionary_search() iterates all entries in a dtree, and also optionally
 * calls a defined callback function to use any data attached to it.
 *
 * When the object is found, a non-NULL is returned from the callback, which
 * results in that object being returned to the user.
 */
extern void *egg_dictionary_search(egg_dictionary *dtree,
	void *(*foreach_cb)(egg_dictionary_element *delem, void *privdata),
	void *privdata);

/*
 * egg_dictionary_foreach_start() begins an iteration over all items
 * keeping state in the given struct. If there is only one iteration
 * in progress at a time, it is permitted to remove the current element
 * of the iteration (but not any other element).
 */
extern void egg_dictionary_foreach_start(egg_dictionary *dtree,
	egg_dictionary_iter *state);

/*
 * egg_dictionary_foreach_cur() returns the current element of the iteration,
 * or NULL if there are no more elements.
 */
extern void *egg_dictionary_foreach_cur(egg_dictionary *dtree,
	egg_dictionary_iter *state);

/*
 * egg_dictionary_foreach_next() moves to the next element.
 */
extern void egg_dictionary_foreach_next(egg_dictionary *dtree,
	egg_dictionary_iter *state);

/*
 * egg_dictionary_add() adds a key->value entry to the dictionary tree.
 */
extern egg_dictionary_element *egg_dictionary_add(egg_dictionary *dtree, const void *key, void *data);

/*
 * egg_dictionary_find() returns an egg_dictionary_element container from a
 * dtree for key 'key'.
 */
extern egg_dictionary_element *egg_dictionary_find(egg_dictionary *dtree, const void *key);

/*
 * egg_dictionary_retrieve() returns data from a dtree for key 'key'.
 */
extern void *egg_dictionary_retrieve(egg_dictionary *dtree, const void *key);

/*
 * egg_dictionary_delete() deletes a key->value entry from the dictionary tree.
 */
extern void *egg_dictionary_delete(egg_dictionary *dtree, const void *key);

/*
 * egg_dictionary_size() returns the number of elements in a dictionary tree.
 */
extern size_t egg_dictionary_size(egg_dictionary *dtree);

void egg_dictionary_stats(egg_dictionary *dict, void (*cb)(const char *line, void *privdata), void *privdata);
void egg_dictionary_stats_walk(void (*cb)(const char *line, void *privdata), void *privdata);

#ifndef _WIN32

#define EGG_POINTER_TO_INT(x)		((int32_t) (long) (x))
#define EGG_INT_TO_POINTER(x)		((void *) (long) (int32_t) (x))

#define EGG_POINTER_TO_UINT(x)		((uint32_t) (unsigned long) (x))
#define EGG_UINT_TO_POINTER(x)		((void *) (unsigned long) (uint32_t) (x))

#else

#define EGG_POINTER_TO_INT(x)		((int32_t) (unsigned long long) (x))
#define EGG_INT_TO_POINTER(x)		((void *) (unsigned long long) (int32_t) (x))

#define EGG_POINTER_TO_UINT(x)		((uint32_t) (unsigned long long) (x))
#define EGG_UINT_TO_POINTER(x)		((void *) (unsigned long long) (uint32_t) (x))

#endif /* _WIN32 */

static inline int egg_int32cmp(const void *a, const void *b)
{
	return EGG_POINTER_TO_INT(b) - EGG_POINTER_TO_INT(a);
}

static inline int egg_uint32cmp(const void *a, const void *b)
{
	return EGG_POINTER_TO_UINT(b) - EGG_POINTER_TO_UINT(a);
}

#endif /* EGG_DICTIONARY_H */
