/*
 * compat/balloc.h — compatibility shim: maps egg_bh_* → op_bh_* from libop.
 *
 * Eggdrop now uses the full libop balloc (op_balloc.h / balloc.c) instead of
 * its own copy.  This header keeps existing callers working without changes.
 *
 * Note: forward-declares op_bh without including op_lib.h to avoid pulling
 * stdlib.h after eggdrop.h's malloc redefinition.
 *
 * Copyright (C) 2026 ophion development team
 * GPL-2.0-or-later
 */

#ifndef EGG_BALLOC_H
#define EGG_BALLOC_H

#include <stddef.h>

/* Forward declaration — full definition is in op_balloc.h / libop */
struct op_bh;
typedef struct op_bh op_bh;
typedef op_bh egg_bh;

op_bh *op_bh_create(size_t elemsize, size_t elemsperblock, const char *desc);
void  *op_bh_alloc(op_bh *bh);
void   op_bh_free(op_bh *bh, void *ptr);
int    op_bh_destroy(op_bh *bh);

#define egg_bh_create(elemsize, elemsperblock, desc) \
        op_bh_create((elemsize), (elemsperblock), (desc))
#define egg_bh_alloc(bh)       op_bh_alloc(bh)
#define egg_bh_free(bh, ptr)   op_bh_free((bh), (ptr))
#define egg_bh_destroy(bh)     op_bh_destroy(bh)

#endif /* EGG_BALLOC_H */
