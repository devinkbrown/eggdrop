/*
 * filelist.c -- part of filesys.mod
 *   functions to sort and manage file lists
 *
 * Written by Fabian Knittel <fknittel@gmx.de>
 */
/*
 * Copyright (C) 1999 - 2025 Eggheads Development Team
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include "filelist.h"

static filelist_t *filelist_new(void)
{
  filelist_t *flist;

  flist = op_malloc(sizeof(filelist_t));
  flist->tot = 0;
  flist->elements = NULL;
  return flist;
}

static void filelist_free(filelist_t *flist)
{
  if (!flist)
    return;
  for (int i = 0; i < flist->tot; i++) {
    if (flist->elements[i].output)
      my_free(flist->elements[i].output);
    my_free(flist->elements[i].fn);
  }
  if (flist->elements)
    my_free(flist->elements);
  my_free(flist);
}

/* Increase number of filelist entries.
 */
static void filelist_add(filelist_t *flist, char *filename)
{
  flist->tot++;
  flist->elements = op_realloc(flist->elements, flist->tot * sizeof(filelist_t));
  FILELIST_LE(flist).fn = op_strdup(filename);
  FILELIST_LE(flist).output = NULL;
}

/* Add data to the end of filelist entry's output string
 */
static void filelist_addout(filelist_t *flist, char *desc)
{
  if (FILELIST_LE(flist).output) {
    op_strbuf_t _b;
    op_strbuf_printf(&_b, "%s%s", FILELIST_LE(flist).output, desc);
    FILELIST_LE(flist).output = op_realloc(FILELIST_LE(flist).output, op_strbuf_len(&_b) + 1);
    strlcpy(FILELIST_LE(flist).output, op_strbuf_str(&_b), op_strbuf_len(&_b) + 1);
    op_strbuf_free(&_b);
  } else {
    size_t desc_sz = strlen(desc) + 1;
    FILELIST_LE(flist).output = op_malloc(desc_sz);
    strlcpy(FILELIST_LE(flist).output, desc, desc_sz);
  }
}

/* Dump all data to specified idx */
static void filelist_idxshow(filelist_t *flist, int idx)
{
  for (int i = 0; i < flist->tot; i++)
    dprintf(idx, "%s", flist->elements[i].output);
}

/* Uses QSort to sort the list of filenames. This function is
 * called recursively.
 */
static void filelist_qsort(filelist_t *flist, int l, int r)
{
  int i = l, j = r, middle;
  filelist_element_t *el = flist->elements, elt;

  middle = ((l + r) / 2);
  do {
    while (strcmp(el[i].fn, el[middle].fn) < 0)
      i++;
    while (strcmp(el[j].fn, el[middle].fn) > 0)
      j--;
    if (i <= j) {
      if (strcmp(el[j].fn, el[i].fn)) {
        elt.fn = el[j].fn;
        elt.output = el[j].output;
        el[j].fn = el[i].fn;
        el[j].output = el[i].output;
        el[i].fn = elt.fn;
        el[i].output = elt.output;
      }
      i++;
      j--;
    }
  } while (i <= j);
  if (l < j)
    filelist_qsort(flist, l, j);
  if (i < r)
    filelist_qsort(flist, i, r);
}

/* Sort list of filenames.
 */
static void filelist_sort(filelist_t *flist)
{
  if (flist->tot < 2)
    return;
  filelist_qsort(flist, 0, (flist->tot - 1));
}
