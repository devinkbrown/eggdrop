/* Adapted from devinkbrown/ophion (GPL v2) */
/*
 * charybdis: an advanced ircd
 * dictionary.c: Dictionary-based information storage.
 *
 * Copyright (c) 2007 William Pitcock <nenolod -at- sacredspiral.co.uk>
 * Copyright (c) 2007 Jilles Tjoelker <jilles -at- stack.nl>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <assert.h>
#include "main.h"
#include "eggdrop.h"
#include "dictionary.h"

/* Simple linked-list node used to track the global registry of all
 * live egg_dictionary instances (used only by egg_dictionary_stats_walk). */
struct dict_registry_node {
	egg_dictionary *dict;
	struct dict_registry_node *next;
};

static struct dict_registry_node *dictionary_registry = NULL;

static void registry_add(egg_dictionary *dict)
{
	struct dict_registry_node *node = nmalloc(sizeof(*node));
	node->dict = dict;
	node->next = dictionary_registry;
	dictionary_registry = node;
}

static void registry_remove(egg_dictionary *dict)
{
	struct dict_registry_node **pp = &dictionary_registry;
	while (*pp) {
		if ((*pp)->dict == dict) {
			struct dict_registry_node *dead = *pp;
			*pp = dead->next;
			nfree(dead);
			return;
		}
		pp = &(*pp)->next;
	}
}

struct egg_dictionary
{
	DCF compare_cb;
	egg_dictionary_element *root, *head, *tail;
	unsigned int count;
	char *id;
	unsigned int dirty:1;
};

/*
 * egg_dictionary_create(const char *name, DCF compare_cb)
 *
 * Dictionary object factory.
 *
 * Inputs:
 *     - dictionary name
 *     - function to use for comparing two entries in the dtree
 *
 * Outputs:
 *     - on success, a new dictionary object.
 *
 * Side Effects:
 *     - if services runs out of memory and cannot allocate the object,
 *       the program will abort.
 */
egg_dictionary *egg_dictionary_create(const char *name,
	DCF compare_cb)
{
	egg_dictionary *dtree = (egg_dictionary *) nmalloc(sizeof(egg_dictionary));

	dtree->compare_cb = compare_cb;
	dtree->id = strdup(name);

	registry_add(dtree);

	return dtree;
}

/*
 * egg_dictionary_set_comparator_func(egg_dictionary *dict,
 *     DCF compare_cb)
 *
 * Resets the comparator function used by the dictionary code for
 * updating the DTree structure.
 *
 * Inputs:
 *     - dictionary object
 *     - new comparator function (passed as functor)
 *
 * Outputs:
 *     - nothing
 *
 * Side Effects:
 *     - the dictionary comparator function is reset.
 */
void egg_dictionary_set_comparator_func(egg_dictionary *dict,
	DCF compare_cb)
{
	assert(dict != NULL);
	assert(compare_cb != NULL);

	dict->compare_cb = compare_cb;
}

/*
 * egg_dictionary_get_comparator_func(egg_dictionary *dict)
 *
 * Returns the current comparator function used by the dictionary.
 *
 * Inputs:
 *     - dictionary object
 *
 * Outputs:
 *     - comparator function (returned as functor)
 *
 * Side Effects:
 *     - none
 */
DCF
egg_dictionary_get_comparator_func(egg_dictionary *dict)
{
	assert(dict != NULL);

	return dict->compare_cb;
}

/*
 * egg_dictionary_get_linear_index(egg_dictionary *dict,
 *     const void *key)
 *
 * Gets a linear index number for key.
 *
 * Inputs:
 *     - dictionary tree object
 *     - pointer to data
 *
 * Outputs:
 *     - position, from zero.
 *
 * Side Effects:
 *     - rebuilds the linear index if the tree is marked as dirty.
 */
int
egg_dictionary_get_linear_index(egg_dictionary *dict, const void *key)
{
	assert(dict != NULL);

	egg_dictionary_element *elem = egg_dictionary_find(dict, key);
	if (elem == NULL)
		return -1;

	if (!dict->dirty)
		return elem->position;

	int i = 0;
	for (egg_dictionary_element *delem = dict->head; delem != NULL; delem = delem->next, i++)
		delem->position = i;

	dict->dirty = 0;

	return elem->position;
}

/*
 * egg_dictionary_retune(egg_dictionary *dict, const void *key)
 *
 * Retunes the tree, self-optimizing for the element which belongs to key.
 *
 * Inputs:
 *     - node to begin search from
 *
 * Outputs:
 *     - none
 *
 * Side Effects:
 *     - a new root node is nominated.
 */
static void
egg_dictionary_retune(egg_dictionary *dict, const void *key)
{
	assert(dict != NULL);

	if (dict->root == NULL)
		return;

	/*
	 * we initialize n with known values, since it's on stack
	 * memory. otherwise the dict would become corrupted.
	 *
	 * n is used for temporary storage while the tree is retuned.
	 */
	egg_dictionary_element n, *tn, *left, *right, *node;
	n.left = n.right = NULL;
	left = right = &n;

	/* this for(;;) loop is the main workhorse of the rebalancing */
	for (node = dict->root; ; )
	{
		int ret = dict->compare_cb(key, node->key);
		if (ret == 0)
			break;

		if (ret < 0)
		{
			if (node->left == NULL)
				break;

			if ((ret = dict->compare_cb(key, node->left->key)) < 0)
			{
				tn = node->left;
				node->left = tn->right;
				tn->right = node;
				node = tn;

				if (node->left == NULL)
					break;
			}

			right->left = node;
			right = node;
			node = node->left;
		}
		else
		{
			if (node->right == NULL)
				break;

			if ((ret = dict->compare_cb(key, node->right->key)) > 0)
			{
				tn = node->right;
				node->right = tn->left;
				tn->left = node;
				node = tn;

				if (node->right == NULL)
					break;
			}

			left->right = node;
			left = node;
			node = node->right;
		}
	}

	left->right = node->left;
	right->left = node->right;

	node->left = n.right;
	node->right = n.left;

	dict->root = node;
}

/*
 * egg_dictionary_link(egg_dictionary *dict,
 *     egg_dictionary_element *delem)
 *
 * Links a dictionary tree element to the dictionary.
 *
 * When we add new nodes to the tree, it becomes the
 * next nominated root. This is perhaps not a wise
 * optimization because of automatic retuning, but
 * it keeps the code simple.
 *
 * Inputs:
 *     - dictionary tree
 *     - dictionary tree element
 *
 * Outputs:
 *     - nothing
 *
 * Side Effects:
 *     - a node is linked to the dictionary tree
 */
static egg_dictionary_element *
egg_dictionary_link(egg_dictionary *dict,
	egg_dictionary_element *delem)
{
	assert(dict != NULL);
	assert(delem != NULL);

	dict->dirty = 1;
	dict->count++;

	if (dict->root == NULL)
	{
		delem->left = delem->right = NULL;
		delem->next = delem->prev = NULL;
		dict->head = dict->tail = dict->root = delem;
	}
	else
	{
		egg_dictionary_retune(dict, delem->key);

		int ret = dict->compare_cb(delem->key, dict->root->key);
		if (ret < 0)
		{
			delem->left = dict->root->left;
			delem->right = dict->root;
			dict->root->left = NULL;

			if (dict->root->prev)
				dict->root->prev->next = delem;
			else
				dict->head = delem;

			delem->prev = dict->root->prev;
			delem->next = dict->root;
			dict->root->prev = delem;
			dict->root = delem;
		}
		else if (ret > 0)
		{
			delem->right = dict->root->right;
			delem->left = dict->root;
			dict->root->right = NULL;

			if (dict->root->next)
				dict->root->next->prev = delem;
			else
				dict->tail = delem;

			delem->next = dict->root->next;
			delem->prev = dict->root;
			dict->root->next = delem;
			dict->root = delem;
		}
		else
		{
			dict->root->key = delem->key;
			dict->root->data = delem->data;
			dict->count--;

			nfree(delem);
			delem = dict->root;
		}
	}

	return delem;
}

/*
 * egg_dictionary_unlink_root(egg_dictionary *dict)
 *
 * Unlinks the root dictionary tree element from the dictionary.
 *
 * Inputs:
 *     - dictionary tree
 *
 * Outputs:
 *     - nothing
 *
 * Side Effects:
 *     - the root node is unlinked from the dictionary tree
 */
static void
egg_dictionary_unlink_root(egg_dictionary *dict)
{
	dict->dirty = 1;

	egg_dictionary_element *delem = dict->root;
	if (delem == NULL)
		return;

	if (dict->root->left == NULL)
		dict->root = dict->root->right;
	else if (dict->root->right == NULL)
		dict->root = dict->root->left;
	else
	{
		/* Make the node with the next highest key the new root.
		 * This node has a NULL left pointer. */
		egg_dictionary_element *nextnode = delem->next;
		assert(nextnode->left == NULL);
		if (nextnode == delem->right)
		{
			dict->root = nextnode;
			dict->root->left = delem->left;
		}
		else
		{
			egg_dictionary_element *parentofnext = delem->right;
			while (parentofnext->left != NULL && parentofnext->left != nextnode)
				parentofnext = parentofnext->left;
			assert(parentofnext->left == nextnode);
			parentofnext->left = nextnode->right;
			dict->root = nextnode;
			dict->root->left = delem->left;
			dict->root->right = delem->right;
		}
	}

	/* linked list */
	if (delem->prev != NULL)
		delem->prev->next = delem->next;

	if (dict->head == delem)
		dict->head = delem->next;

	if (delem->next)
		delem->next->prev = delem->prev;

	if (dict->tail == delem)
		dict->tail = delem->prev;

	dict->count--;
}

/*
 * egg_dictionary_destroy(egg_dictionary *dtree,
 *     void (*destroy_cb)(egg_dictionary_element *delem, void *privdata),
 *     void *privdata);
 *
 * Recursively destroys all nodes in a dictionary tree.
 *
 * Inputs:
 *     - dictionary tree object
 *     - optional iteration callback
 *     - optional opaque/private data to pass to callback
 *
 * Outputs:
 *     - nothing
 *
 * Side Effects:
 *     - on success, a dtree and optionally its children are destroyed.
 *
 * Notes:
 *     - if this is called without a callback, the objects bound to the
 *       DTree will not be destroyed.
 */
void egg_dictionary_destroy(egg_dictionary *dtree,
	void (*destroy_cb)(egg_dictionary_element *delem, void *privdata),
	void *privdata)
{
	assert(dtree != NULL);

	egg_dictionary_element *n, *tn;
	for (n = dtree->head; n != NULL; n = tn)
	{
		tn = n->next;
		if (destroy_cb != NULL)
			(*destroy_cb)(n, privdata);
		nfree(n);
	}

	registry_remove(dtree);
	nfree(dtree->id);
	nfree(dtree);
}

/*
 * egg_dictionary_foreach(egg_dictionary *dtree,
 *     void (*destroy_cb)(egg_dictionary_element *delem, void *privdata),
 *     void *privdata);
 *
 * Iterates over all entries in a DTree.
 *
 * Inputs:
 *     - dictionary tree object
 *     - optional iteration callback
 *     - optional opaque/private data to pass to callback
 *
 * Outputs:
 *     - nothing
 *
 * Side Effects:
 *     - on success, a dtree is iterated
 */
void egg_dictionary_foreach(egg_dictionary *dtree,
	int (*foreach_cb)(egg_dictionary_element *delem, void *privdata),
	void *privdata)
{
	assert(dtree != NULL);

	egg_dictionary_element *n, *tn;
	for (n = dtree->head; n != NULL; n = tn)
	{
		tn = n->next;
		/* delem_t is a subclass of node_t. */
		egg_dictionary_element *delem = (egg_dictionary_element *) n;

		if (foreach_cb != NULL)
			(*foreach_cb)(delem, privdata);
	}
}

/*
 * egg_dictionary_search(egg_dictionary *dtree,
 *     void (*destroy_cb)(egg_dictionary_element *delem, void *privdata),
 *     void *privdata);
 *
 * Searches all entries in a DTree using a custom callback.
 *
 * Inputs:
 *     - dictionary tree object
 *     - optional iteration callback
 *     - optional opaque/private data to pass to callback
 *
 * Outputs:
 *     - on success, the requested object
 *     - on failure, NULL.
 *
 * Side Effects:
 *     - a dtree is iterated until the requested conditions are met
 */
void *egg_dictionary_search(egg_dictionary *dtree,
	void *(*foreach_cb)(egg_dictionary_element *delem, void *privdata),
	void *privdata)
{
	assert(dtree != NULL);

	void *ret = NULL;
	egg_dictionary_element *n, *tn;
	for (n = dtree->head; n != NULL; n = tn)
	{
		tn = n->next;
		/* delem_t is a subclass of node_t. */
		egg_dictionary_element *delem = (egg_dictionary_element *) n;

		if (foreach_cb != NULL)
			ret = (*foreach_cb)(delem, privdata);

		if (ret)
			break;
	}

	return ret;
}

/*
 * egg_dictionary_foreach_start(egg_dictionary *dtree,
 *     egg_dictionary_iter *state);
 *
 * Initializes a static DTree iterator.
 *
 * Inputs:
 *     - dictionary tree object
 *     - static DTree iterator
 *
 * Outputs:
 *     - nothing
 *
 * Side Effects:
 *     - the static iterator, &state, is initialized.
 */
void egg_dictionary_foreach_start(egg_dictionary *dtree,
	egg_dictionary_iter *state)
{
	assert(dtree != NULL);
	assert(state != NULL);

	state->cur = NULL;
	state->next = NULL;

	/* find first item */
	state->cur = dtree->head;

	if (state->cur == NULL)
		return;

	/* make state->cur point to first item and state->next point to
	 * second item */
	state->next = state->cur;
	egg_dictionary_foreach_next(dtree, state);
}

/*
 * egg_dictionary_foreach_cur(egg_dictionary *dtree,
 *     egg_dictionary_iter *state);
 *
 * Returns the data from the current node being iterated by the
 * static iterator.
 *
 * Inputs:
 *     - dictionary tree object
 *     - static DTree iterator
 *
 * Outputs:
 *     - reference to data in the current dtree node being iterated
 *
 * Side Effects:
 *     - none
 */
void *egg_dictionary_foreach_cur(egg_dictionary *dtree __attribute__((unused)),
	egg_dictionary_iter *state)
{
	assert(dtree != NULL);
	assert(state != NULL);

	return state->cur != NULL ? state->cur->data : NULL;
}

/*
 * egg_dictionary_foreach_next(egg_dictionary *dtree,
 *     egg_dictionary_iter *state);
 *
 * Advances a static DTree iterator.
 *
 * Inputs:
 *     - dictionary tree object
 *     - static DTree iterator
 *
 * Outputs:
 *     - nothing
 *
 * Side Effects:
 *     - the static iterator, &state, is advanced to a new DTree node.
 */
void egg_dictionary_foreach_next(egg_dictionary *dtree,
	egg_dictionary_iter *state)
{
	assert(dtree != NULL);
	assert(state != NULL);

	if (state->cur == NULL)
	{
		putlog(LOG_MISC, "*", "egg_dictionary_foreach_next(): called again after iteration finished on dtree<%p>", (void *)dtree);
		return;
	}

	state->cur = state->next;

	if (state->next == NULL)
		return;

	state->next = state->next->next;
}

/*
 * egg_dictionary_find(egg_dictionary *dtree, const void *key)
 *
 * Looks up a DTree node by name.
 *
 * Inputs:
 *     - dictionary tree object
 *     - name of node to lookup
 *
 * Outputs:
 *     - on success, the dtree node requested
 *     - on failure, NULL
 *
 * Side Effects:
 *     - none
 */
egg_dictionary_element *egg_dictionary_find(egg_dictionary *dict, const void *key)
{
	assert(dict != NULL);

	/* retune for key, key will be the tree's root if it's available */
	egg_dictionary_retune(dict, key);

	if (dict->root && !dict->compare_cb(key, dict->root->key))
		return dict->root;

	return NULL;
}

/*
 * egg_dictionary_add(egg_dictionary *dtree, const void *key, void *data)
 *
 * Creates a new DTree node and binds data to it.
 *
 * Inputs:
 *     - dictionary tree object
 *     - name for new DTree node
 *     - data to bind to the new DTree node
 *
 * Outputs:
 *     - on success, a new DTree node
 *     - on failure, NULL
 *
 * Side Effects:
 *     - data is inserted into the DTree.
 */
egg_dictionary_element *egg_dictionary_add(egg_dictionary *dict, const void *key, void *data)
{
	assert(dict != NULL);
	assert(data != NULL);
	assert(egg_dictionary_find(dict, key) == NULL);

	egg_dictionary_element *delem = nmalloc(sizeof(*delem));
	delem->key = key;
	delem->data = data;

	return egg_dictionary_link(dict, delem);
}

/*
 * egg_dictionary_delete(egg_dictionary *dtree, const void *key)
 *
 * Deletes data from a dictionary tree.
 *
 * Inputs:
 *     - dictionary tree object
 *     - name of DTree node to delete
 *
 * Outputs:
 *     - on success, the remaining data that needs to be freed
 *     - on failure, NULL
 *
 * Side Effects:
 *     - data is removed from the DTree.
 *
 * Notes:
 *     - the returned data needs to be freed/released manually!
 */
void *egg_dictionary_delete(egg_dictionary *dtree, const void *key)
{
	egg_dictionary_element *delem = egg_dictionary_find(dtree, key);

	if (delem == NULL)
		return NULL;

	void *data = delem->data;

	egg_dictionary_unlink_root(dtree);
	nfree(delem);

	return data;
}

/*
 * egg_dictionary_retrieve(egg_dictionary *dtree, const void *key)
 *
 * Retrieves data from a dictionary.
 *
 * Inputs:
 *     - dictionary tree object
 *     - name of node to lookup
 *
 * Outputs:
 *     - on success, the data bound to the DTree node.
 *     - on failure, NULL
 *
 * Side Effects:
 *     - none
 */
void *egg_dictionary_retrieve(egg_dictionary *dtree, const void *key)
{
	egg_dictionary_element *delem = egg_dictionary_find(dtree, key);

	if (delem == NULL)
		return NULL;

	return delem->data;
}

/*
 * egg_dictionary_size(egg_dictionary *dict)
 *
 * Returns the size of a dictionary.
 *
 * Inputs:
 *     - dictionary tree object
 *
 * Outputs:
 *     - size of dictionary
 *
 * Side Effects:
 *     - none
 */
size_t egg_dictionary_size(egg_dictionary *dict)
{
	assert(dict != NULL);

	return dict->count;
}

/* returns the sum of the depths of the subtree rooted in delem at depth depth */
static int
stats_recurse(const egg_dictionary_element *delem, int depth, int *pmaxdepth)
{
	if (depth > *pmaxdepth)
		*pmaxdepth = depth;

	int result = depth;
	if (delem == NULL)
		return result;
	if (delem->left)
		result += stats_recurse(delem->left, depth + 1, pmaxdepth);
	if (delem->right)
		result += stats_recurse(delem->right, depth + 1, pmaxdepth);
	return result;
}

/*
 * egg_dictionary_stats(egg_dictionary *dict, void (*cb)(const char *line, void *privdata), void *privdata)
 *
 * Returns stats for a dictionary.
 *
 * Inputs:
 *     - dictionary tree object
 *     - callback
 *     - data for callback
 *
 * Outputs:
 *     - none
 *
 * Side Effects:
 *     - callback called with stats text
 */
void egg_dictionary_stats(egg_dictionary *dict, void (*cb)(const char *line, void *privdata), void *privdata)
{
	assert(dict != NULL);

	char str[256];
	if (dict->count)
	{
		int maxdepth = 0;
		int sum = stats_recurse(dict->root, 0, &maxdepth);
		snprintf(str, sizeof str, "%-30s %-15s %-10u %-10d %-10d %-10d", dict->id, "DICT", dict->count, sum, sum / dict->count, maxdepth);
	}
	else
	{
		snprintf(str, sizeof str, "%-30s %-15s %-10s %-10s %-10s %-10s", dict->id, "DICT", "0", "0", "0", "0");
	}

	cb(str, privdata);
}

void egg_dictionary_stats_walk(void (*cb)(const char *line, void *privdata), void *privdata)
{
	struct dict_registry_node *ptr;

	for (ptr = dictionary_registry; ptr != NULL; ptr = ptr->next)
	{
		egg_dictionary_stats(ptr->dict, cb, privdata);
	}
}
