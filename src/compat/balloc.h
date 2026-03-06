/*
 * balloc.h -- mmap-backed slab allocator interface.
 *
 * Ported from ophion's op_balloc to eggdrop.
 *
 * Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 * Copyright (C) 1996-2002 Hybrid Development Team
 * Copyright (C) 2002-2006 ircd-ratbox development team
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef EGG_BALLOC_H
#define EGG_BALLOC_H

#include <stddef.h>

typedef struct egg_bh egg_bh;

egg_bh *egg_bh_create(size_t elemsize, int elemsperblock, const char *desc);
void   *egg_bh_alloc(egg_bh *bh);
void    egg_bh_free(egg_bh *bh, void *ptr);
void    egg_bh_destroy(egg_bh *bh);

#endif /* EGG_BALLOC_H */
