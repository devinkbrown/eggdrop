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

static int expmem_udef(const op_vec_t *vec)
{
  int i = 0;

  for (size_t vi = 0; vi < vec->size; vi++) {
    const struct udef_struct *ul = (const struct udef_struct *)op_vec_get(vec, vi);
    i += sizeof(struct udef_struct);
    i += strlen(ul->name) + 1;
    i += expmem_udef_chans(ul->type, &ul->values);
  }
  return i;
}

static int expmem_udef_chans(int type, const op_vec_t *values)
{
  int i = 0;

  for (size_t vi = 0; vi < values->size; vi++) {
    const struct udef_chans *ul = (const struct udef_chans *)op_vec_get(values, vi);
    i += sizeof(struct udef_chans);
    i += strlen(ul->chan) + 1;
    if (type == UDEF_STR && ul->value)
      i += strlen((const char *) ul->value) + 1;
  }
  return i;
}

static intptr_t getudef(const op_vec_t *values, char *name)
{
  for (size_t i = 0; i < values->size; i++) {
    const struct udef_chans *ul = (const struct udef_chans *)op_vec_get(values, i);
    if (!op_strcasecmp(ul->chan, name))
      return ul->value;
  }
  return 0;
}

static intptr_t ngetudef(char *name, char *chan)
{
  for (size_t i = 0; i < udef_vec.size; i++) {
    const struct udef_struct *l = (const struct udef_struct *)op_vec_get(&udef_vec, i);
    if (!op_strcasecmp(l->name, name))
      return getudef(&l->values, chan);
  }
  return 0;
}

static void setudef(struct udef_struct *us, char *name, intptr_t value)
{
  for (size_t i = 0; i < us->values.size; i++) {
    struct udef_chans *ul = (struct udef_chans *)op_vec_get(&us->values, i);
    if (!op_strcasecmp(ul->chan, name)) {
      ul->value = value;
      return;
    }
  }

  if (!udef_chans_bh)
    udef_chans_bh = op_bh_create(sizeof(struct udef_chans), 32, "udef_chans");
  struct udef_chans *ul = (struct udef_chans *)op_bh_alloc(udef_chans_bh);
  ul->chan = op_strdup(name);
  ul->value = value;
  op_vec_push(&us->values, ul);
}

static void initudef(int type, char *name, int defined)
{
  if (strlen(name) < 1)
    return;

  for (size_t i = 0; i < udef_vec.size; i++) {
    struct udef_struct *ul = (struct udef_struct *)op_vec_get(&udef_vec, i);
    if (ul->name && !op_strcasecmp(ul->name, name)) {
      if (defined) {
        debug1("UDEF: %s defined", ul->name);
        ul->defined = 1;
      }
      return;
    }
  }

  debug2("Creating %s (type %d)", name, type);
  if (!udef_struct_bh)
    udef_struct_bh = op_bh_create(sizeof(struct udef_struct), 16, "udef_struct");
  struct udef_struct *ul = (struct udef_struct *)op_bh_alloc(udef_struct_bh);
  ul->name = op_strdup(name);
  ul->defined = defined ? 1 : 0;
  ul->type = type;
  /* ul->values is zero-initialised by op_bh_alloc — valid for op_vec_t */
  op_vec_push(&udef_vec, ul);
}

static void free_udef_chans(op_vec_t *values, int type)
{
  for (size_t i = 0; i < values->size; i++) {
    struct udef_chans *ul = (struct udef_chans *)op_vec_get(values, i);
    if (type == UDEF_STR && ul->value)
      op_free((void *) ul->value);
    op_free(ul->chan);
    op_bh_free(udef_chans_bh, ul);
  }
  op_vec_fini(values, nullptr, nullptr);
}

static void free_udef(op_vec_t *vec)
{
  for (size_t i = 0; i < vec->size; i++) {
    struct udef_struct *ul = (struct udef_struct *)op_vec_get(vec, i);
    free_udef_chans(&ul->values, ul->type);
    op_free(ul->name);
    op_bh_free(udef_struct_bh, ul);
  }
  op_vec_clear(vec, nullptr, nullptr);
}
