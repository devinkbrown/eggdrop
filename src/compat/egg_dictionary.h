/*
 * compat/egg_dictionary.h — thin shim: maps egg_dictionary_* → op_htab_*
 *
 * Eggdrop used a splay-tree dictionary (dictionary.c).  That has been replaced
 * by libop's Robin Hood open-addressing hash table (op_htab).  This header lets
 * existing call sites compile unchanged by providing macros and a type alias.
 *
 * Only the subset actually used in eggdrop is mapped here:
 *   create / destroy / add / retrieve / delete
 *
 * Copyright (C) 2026 ophion development team
 * GPL-2.0-or-later
 */

#ifndef EGG_COMPAT_DICTIONARY_H
#define EGG_COMPAT_DICTIONARY_H

/* op_lib.h must already be included by the time this header is pulled in,
 * because op_htab is defined there.  channels.c and userrec.c both include
 * op_lib.h first, so this is always satisfied. */
#ifndef LIBOP_LIB_H
#  error "Include op_lib.h before egg_dictionary.h"
#endif

/* Type alias: egg_dictionary is just an op_htab. */
typedef op_htab egg_dictionary;

/* egg_dict_strcasecmp: historic DCF comparator — unused by op_htab (which
 * performs its own case-folding), kept so callers compile without changes. */
#ifndef egg_dict_strcasecmp
static inline int egg_dict_strcasecmp(const void *a, const void *b)
{
	return strcasecmp((const char *)a, (const char *)b);
}
#endif

/*
 * egg_dictionary_create — create a new IRC-case-insensitive string keyed table.
 * The comparator argument is accepted but ignored; op_htab_create_istr handles
 * case folding internally.
 */
#define egg_dictionary_create(name, cmp_fn)  op_htab_create_istr((name), 16)

/*
 * egg_dictionary_destroy — destroy the table.
 * destroy_cb and privdata are accepted for API compatibility but are not
 * forwarded; all callers pass NULL for both.
 */
#define egg_dictionary_destroy(dict, destroy_cb, privdata) \
        op_htab_destroy((dict), NULL, (privdata))

/*
 * egg_dictionary_add — insert key→data.
 * Returns void (op_htab_set returns int); no caller inspects the return value.
 */
#define egg_dictionary_add(dict, key, data) \
        ((void)op_htab_set((dict), (void *)(uintptr_t)(key), (data), NULL))

/*
 * egg_dictionary_retrieve — look up by key, returning the value or NULL.
 */
#define egg_dictionary_retrieve(dict, key)  op_htab_get((dict), (key))

/*
 * egg_dictionary_delete — remove key from the table, returning the old value.
 */
#define egg_dictionary_delete(dict, key)    op_htab_del((dict), (key))

#endif /* EGG_COMPAT_DICTIONARY_H */
