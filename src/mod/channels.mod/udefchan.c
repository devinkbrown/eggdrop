/*
 * udefchan.c -- part of channels.mod
 *   user definable channel flags/settings
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

static op_bh *udef_struct_bh = nullptr;
static op_bh *udef_chans_bh  = nullptr;

static int expmem_udef(struct udef_struct *ul)
{
  int i = 0;

  for (; ul; ul = ul->next) {
    i += sizeof(struct udef_struct);
    i += strlen(ul->name) + 1;
    i += expmem_udef_chans(ul->type, ul->values);
  }
  return i;
}

static int expmem_udef_chans(int type, struct udef_chans *ul)
{
  int i = 0;

  for (; ul; ul = ul->next) {
    i += sizeof(struct udef_chans);
    i += strlen(ul->chan) + 1;
    if (type == UDEF_STR && ul->value)
      i += strlen((char *) ul->value) + 1;
  }
  return i;
}

static intptr_t getudef(struct udef_chans *ul, char *name)
{
  intptr_t val = 0;

  for (; ul; ul = ul->next)
    if (!strcasecmp(ul->chan, name)) {
      val = ul->value;
      break;
    }
  return val;
}

static intptr_t ngetudef(char *name, char *chan)
{
  struct udef_struct *l;
  struct udef_chans *ll;

  for (l = udef; l; l = l->next)
    if (!strcasecmp(l->name, name)) {
      for (ll = l->values; ll; ll = ll->next)
        if (!strcasecmp(ll->chan, chan))
          return ll->value;
      break;
    }
  return 0;
}

static void setudef(struct udef_struct *us, char *name, intptr_t value)
{
  struct udef_chans *ul, *ul_last = nullptr;

  for (ul = us->values; ul; ul_last = ul, ul = ul->next)
    if (!strcasecmp(ul->chan, name)) {
      ul->value = value;
      return;
    }

  if (!udef_chans_bh)
    udef_chans_bh = op_bh_create(sizeof(struct udef_chans), 32, "udef_chans");
  ul = op_bh_alloc(udef_chans_bh);
  ul->chan = op_strdup(name);
  ul->value = value;
  ul->next = nullptr;
  if (ul_last)
    ul_last->next = ul;
  else
    us->values = ul;
}

static void initudef(int type, char *name, int defined)
{
  struct udef_struct *ul, *ul_last = nullptr;

  if (strlen(name) < 1)
    return;

  for (ul = udef; ul; ul_last = ul, ul = ul->next)
    if (ul->name && !strcasecmp(ul->name, name)) {
      if (defined) {
        debug1("UDEF: %s defined", ul->name);
        ul->defined = 1;
      }
      return;
    }

  debug2("Creating %s (type %d)", name, type);
  if (!udef_struct_bh)
    udef_struct_bh = op_bh_create(sizeof(struct udef_struct), 16, "udef_struct");
  ul = op_bh_alloc(udef_struct_bh);
  ul->name = op_strdup(name);
  if (defined)
    ul->defined = 1;
  else
    ul->defined = 0;
  ul->type = type;
  ul->values = nullptr;
  ul->next = nullptr;
  if (ul_last)
    ul_last->next = ul;
  else
    udef = ul;
}

static void free_udef(struct udef_struct *ul)
{
  struct udef_struct *ull;

  for (; ul; ul = ull) {
    ull = ul->next;
    free_udef_chans(ul->values, ul->type);
    op_free(ul->name);
    op_bh_free(udef_struct_bh, ul);
  }
}

static void free_udef_chans(struct udef_chans *ul, int type)
{
  struct udef_chans *ull;

  for (; ul; ul = ull) {
    ull = ul->next;
    if (type == UDEF_STR && ul->value)
      op_free((void *) ul->value);
    op_free(ul->chan);
    op_bh_free(udef_chans_bh, ul);
  }
}
