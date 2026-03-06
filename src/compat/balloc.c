/*
 * balloc.c -- mmap-backed slab allocator.
 *
 * Ported from ophion's op_balloc to eggdrop.
 *
 * Replaces the old malloc-wrapper with a real slab allocator backed by
 * anonymous mmap().  Each egg_bh maintains a per-heap intrusive free list
 * over a set of mmap'd slabs.
 *
 *   Allocation:  O(1) -- pop from free_head; grow by one slab when empty.
 *   Free:        O(1) -- push to free_head.
 *   Destroy:     munmap() each slab -- memory is actually returned to the OS.
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

#define _GNU_SOURCE 1

/* Define COMPILING_MEM so eggdrop.h does not replace malloc/free with
 * error-producing macros -- balloc IS the allocator and must call the
 * real functions. */
#define COMPILING_MEM

#include "main.h"
#include "../eggdrop.h"
#include "balloc.h"
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

/* MAP_ANON is the BSD name; MAP_ANONYMOUS is the Linux/POSIX name. */
#ifndef MAP_ANONYMOUS
# ifdef MAP_ANON
#  define MAP_ANONYMOUS MAP_ANON
# else
#  error "Neither MAP_ANONYMOUS nor MAP_ANON is available"
# endif
#endif

/* Intrusive singly-linked free list stored inside each free element.
 * The first sizeof(void*) bytes of a free element hold the next-free ptr. */
#define FREELIST_NEXT(p)  (*(void **)(p))

/* Round v up to the nearest multiple of align (align must be power-of-two). */
#define ALIGN_UP(v, align)  (((v) + (size_t)(align) - 1) & ~((size_t)(align) - 1))

/* Header embedded at the very start of every mmap'd slab.
 * Uses a simple singly-linked list instead of op_dlink. */
typedef struct egg_bh_slab
{
	struct egg_bh_slab *next;   /* next slab in egg_bh.block_list         */
	size_t              map_size; /* total bytes mmap'd (for munmap)       */
} egg_bh_slab_t;

/* Private definition of egg_bh (opaque to callers via balloc.h). */
struct egg_bh
{
	size_t        elemSize;       /* requested element size (for reporting) */
	size_t        elem_stride;    /* elemSize rounded up to pointer alignment */
	unsigned long elemsPerBlock;  /* elements per slab */
	size_t        data_off;       /* byte offset from slab start to first element */
	void         *free_head;      /* head of the intrusive free list */
	egg_bh_slab_t *block_list;   /* singly-linked list of slabs */
	size_t        nfree;          /* total free elements across all slabs */
	size_t        nused;          /* total allocated elements */
	char         *desc;
};

static long egg_page_size;

static void _egg_bh_fail(const char *reason, const char *file, int line)
	__attribute__((noreturn));
#define egg_bh_fail(x) _egg_bh_fail(x, __FILE__, __LINE__)

static void
_egg_bh_fail(const char *reason, const char *file, int line)
{
	(void)file;
	(void)line;
	fatal(reason, 0);
	/* fatal() does not return; this keeps the compiler happy. */
	abort();
}

static void
egg_bh_init_page_size(void)
{
	if (egg_page_size <= 0) {
		egg_page_size = sysconf(_SC_PAGESIZE);
		if (egg_page_size <= 0)
			egg_page_size = 4096;
	}
}

/* Allocate one new slab, link it into bh->block_list, and push all its
 * elements onto bh->free_head (in reverse order for cache-friendly first use). */
static void
egg_bh_grow(egg_bh *bh)
{
	size_t slab_data = bh->data_off + bh->elem_stride * bh->elemsPerBlock;
	size_t map_size  = ALIGN_UP(slab_data, (size_t)egg_page_size);

	void *mem = mmap(NULL, map_size,
	                 PROT_READ | PROT_WRITE,
	                 MAP_PRIVATE | MAP_ANONYMOUS,
	                 -1, 0);
	if (mem == MAP_FAILED)
		egg_bh_fail("mmap failed in egg_bh_grow");

	egg_bh_slab_t *slab = mem;
	slab->map_size = map_size;

	/* Prepend to block_list */
	slab->next     = bh->block_list;
	bh->block_list = slab;

	/* Push in reverse order so the first alloc returns the lowest-address elem. */
	char *base = (char *)mem + bh->data_off;
	for (long i = (long)bh->elemsPerBlock - 1; i >= 0; --i)
	{
		void *elem = base + (size_t)i * bh->elem_stride;
		FREELIST_NEXT(elem) = bh->free_head;
		bh->free_head = elem;
	}
	bh->nfree += bh->elemsPerBlock;
}

egg_bh *
egg_bh_create(size_t elemsize, int elemsperblock, const char *desc)
{
	if (elemsize == 0 || elemsperblock <= 0)
		egg_bh_fail("egg_bh_create: idiotic sizes");
	if (elemsize < sizeof(void *))
		egg_bh_fail("egg_bh_create: elemsize too small for free-list pointer");

	egg_bh_init_page_size();

	egg_bh *bh = malloc(sizeof(egg_bh));
	if (bh == NULL)
		egg_bh_fail("egg_bh_create: malloc failed");

	bh->elemSize      = elemsize;
	bh->elem_stride   = ALIGN_UP(elemsize, sizeof(void *));
	bh->elemsPerBlock = (unsigned long)elemsperblock;
	/* Ensure the data region starts after the slab header, aligned to stride. */
	bh->data_off      = ALIGN_UP(sizeof(egg_bh_slab_t), bh->elem_stride);
	bh->free_head     = NULL;
	bh->block_list    = NULL;
	bh->nfree         = 0;
	bh->nused         = 0;
	bh->desc          = (desc != NULL) ? strdup(desc) : NULL;

	egg_bh_grow(bh);   /* pre-populate one slab */
	return bh;
}

void *
egg_bh_alloc(egg_bh *bh)
{
	if (bh == NULL)
		egg_bh_fail("egg_bh_alloc: bh == NULL");

	if (bh->free_head == NULL)
		egg_bh_grow(bh);

	void *elem    = bh->free_head;
	bh->free_head = FREELIST_NEXT(elem);
	bh->nfree--;
	bh->nused++;
	memset(elem, 0, bh->elemSize);
	return elem;
}

void
egg_bh_free(egg_bh *bh, void *ptr)
{
	if (bh == NULL)
	{
		putlog(LOG_MISC, "*", "%s", "egg_bh_free: bh == NULL");
		return;
	}
	if (ptr == NULL)
	{
		putlog(LOG_MISC, "*", "%s", "egg_bh_free: ptr == NULL");
		return;
	}

	FREELIST_NEXT(ptr) = bh->free_head;
	bh->free_head = ptr;
	bh->nfree++;
	bh->nused--;
}

void
egg_bh_destroy(egg_bh *bh)
{
	if (bh == NULL)
		return;

	/* munmap each slab; walk the singly-linked list. */
	egg_bh_slab_t *slab = bh->block_list;
	while (slab != NULL)
	{
		egg_bh_slab_t *next     = slab->next;
		size_t         map_size = slab->map_size;
		munmap(slab, map_size);
		slab = next;
	}

	free(bh->desc);
	free(bh);
}
