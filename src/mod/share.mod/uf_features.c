/*
 * uf_features.c -- part of share.mod
 *
 */
/*
 * Copyright (C) 2000 - 2025 Eggheads Development Team
 * Written by Fabian Knittel <fknittel@gmx.de>
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
/*
 * Userfile feature protocol description:
 *
 *
 *               LEAF                                  HUB
 *
 *   uf_features_dump():
 *      Finds out which features
 *      it supports / wants to use
 *      and then dumps those. The
 *      list is appended to the
 *      user file send ack.
 *
 *      "s uy <features>"   --+
 *                            |
 *                            +-->   uf_features_parse():
 *                                      Parses the given list of features,
 *                                      given in a string, separated with
 *                                      spaces. Decides which features to
 *                                      accept/use. Those features are then
 *                                      locally set:
 *
 *                                      dcc[idx].u.bot->uff_flags |= <feature_flag>
 *
 *                                      and sent back to the LEAF:
 *
 *                              +---    "s feats <accepted_features>"
 *                              |
 *   uf_features_check():    <--+
 *      Checks whether the responded
 *      features are still accepted
 *      by us. If they are, we set
 *      the flags locally:
 *
 *      dcc[idx].u.bot->uff_flags |= <feature_flag>
 */


typedef struct uff_list_struct {
  uff_table_t *entry;           /* Pointer to entry in table. This is
                                 * not copied or anything, we just refer
                                 * to the original table entry.         */
} uff_list_t;

/* op_vec_t of uff_list_t *, sorted ascending by entry->priority */
static op_vec_t uff_vec;
static char uff_sbuf[512];
static op_bh *uff_list_bh = nullptr;


/*
 *    Userfile features management functions
 */

static void uff_init(void)
{
  op_vec_clear(&uff_vec, nullptr, nullptr);
}

/* Calculate memory used for list.
 */
static int uff_expmem(void)
{
  return (int)(uff_vec.size * sizeof(uff_list_t));
}

/* Search for a feature by flag. Returns pointer or nullptr.
 */
static uff_list_t *uff_findentry_byflag(int flag)
{
  for (size_t i = 0; i < uff_vec.size; i++) {
    uff_list_t *ul = (uff_list_t *)op_vec_get(&uff_vec, i);
    if (ul->entry->flag & flag)
      return ul;
  }
  return nullptr;
}

/* Search for a feature by name. Returns pointer or nullptr.
 */
static uff_list_t *uff_findentry_byname(char *feature)
{
  for (size_t i = 0; i < uff_vec.size; i++) {
    uff_list_t *ul = (uff_list_t *)op_vec_get(&uff_vec, i);
    if (!strcmp(ul->entry->feature, feature))
      return ul;
  }
  return nullptr;
}

/* Insert entry into sorted position (ascending priority).
 */
static void uff_insert_entry(uff_list_t *nul)
{
  size_t idx = 0;

  while (idx < uff_vec.size) {
    uff_list_t *ul = (uff_list_t *)op_vec_get(&uff_vec, idx);
    if (ul->entry->priority >= nul->entry->priority)
      break;
    idx++;
  }
  op_vec_insert(&uff_vec, idx, nul);
}

/* Add a single feature to the list.
 */
static void uff_addfeature(uff_table_t *ut)
{
  uff_list_t *ul;

  if (uff_findentry_byname(ut->feature)) {
    putlog(LOG_MISC, "*", "(!) share: same feature name used twice: %s",
           ut->feature);
    return;
  }
  ul = uff_findentry_byflag(ut->flag);
  if (ul) {
    putlog(LOG_MISC, "*", "(!) share: feature flag %d used twice by %s and %s",
           ut->flag, ut->feature, ul->entry->feature);
    return;
  }
  if (!uff_list_bh)
    uff_list_bh = op_bh_create(sizeof(uff_list_t), 16, "uff_list");
  ul = (uff_list_t *)op_bh_alloc(uff_list_bh);
  ul->entry = ut;
  uff_insert_entry(ul);
}

/* Add a complete table to the list.
 */
static void uff_addtable(uff_table_t *ut)
{
  if (!ut)
    return;
  for (; ut->feature; ++ut)
    uff_addfeature(ut);
}

/* Remove a single feature from the list.
 */
static int uff_delfeature(uff_table_t *ut)
{
  for (size_t i = 0; i < uff_vec.size; i++) {
    uff_list_t *ul = (uff_list_t *)op_vec_get(&uff_vec, i);
    if (!strcmp(ul->entry->feature, ut->feature)) {
      op_vec_remove(&uff_vec, i);
      op_bh_free(uff_list_bh, ul);
      return 1;
    }
  }
  return 0;
}

/* Remove a complete table from the list.
 */
static void uff_deltable(uff_table_t *ut)
{
  if (!ut)
    return;
  for (; ut->feature; ++ut)
    uff_delfeature(ut);
}


/*
 *    Userfile feature parsing functions
 */

/* Parse the given features string, set internal flags appropriately and
 * eventually respond with all features we will use.
 */
static void uf_features_parse(int idx, char *par)
{
  char *buf, *s, *p;
  uff_list_t *ul;
  op_strbuf_t _sb = {};

  op_strbuf_init(&_sb);
  size_t par_sz = strlen(par) + 1;
  p = s = buf = op_malloc(par_sz);        /* Allocate temp buffer */
  op_strlcpy(buf, par, par_sz);

  /* Clear all currently set features. */
  dcc[idx].u.bot->uff_flags = 0;

  /* Parse string */
  while ((s = strchr(s, ' ')) != nullptr) {
    *s = '\0';

    /* Is the feature available and active? */
    ul = uff_findentry_byname(p);
    if (ul && (ul->entry->ask_func == nullptr || ul->entry->ask_func(idx))) {
      dcc[idx].u.bot->uff_flags |= ul->entry->flag; /* Set flag */
      if (op_strbuf_len(&_sb))
        op_strbuf_append_cstr(&_sb, " ");
      op_strbuf_append_cstr(&_sb, ul->entry->feature);
    }
    p = ++s;
  }
  op_free(buf);

  /* Send response string                                               */
  if (op_strbuf_len(&_sb))
    dprintf(idx, "s feats %s\n", op_strbuf_str(&_sb));
  op_strbuf_free(&_sb);
}

/* Return a list of features we are supporting.
 */
static char *uf_features_dump(int idx)
{
  op_strbuf_t _sb = {};

  op_strbuf_init(&_sb);
  for (size_t i = 0; i < uff_vec.size; i++) {
    uff_list_t *ul = (uff_list_t *)op_vec_get(&uff_vec, i);
    if (ul->entry->ask_func == nullptr || ul->entry->ask_func(idx)) {
      if (op_strbuf_len(&_sb))
        op_strbuf_append_cstr(&_sb, " ");
      op_strbuf_append_cstr(&_sb, ul->entry->feature); /* Add feature to list  */
    }
  }
  op_strlcpy(uff_sbuf, op_strbuf_str(&_sb), sizeof uff_sbuf);
  op_strbuf_free(&_sb);
  return uff_sbuf;
}

static int uf_features_check(int idx, char *par)
{
  char *buf, *s, *p;
  uff_list_t *ul;

  size_t par_sz = strlen(par) + 1;
  p = s = buf = op_malloc(par_sz);        /* Allocate temp buffer */
  op_strlcpy(buf, par, par_sz);

  /* Clear all currently set features. */
  dcc[idx].u.bot->uff_flags = 0;

  /* Parse string */
  while ((s = strchr(s, ' ')) != nullptr) {
    *s = '\0';

    /* Is the feature available and active? */
    ul = uff_findentry_byname(p);
    if (ul && (ul->entry->ask_func == nullptr || ul->entry->ask_func(idx)))
      dcc[idx].u.bot->uff_flags |= ul->entry->flag; /* Set flag */
    else {
      /* It isn't, and our hub wants to use it! This either happens
       * because the hub doesn't look at the features we suggested to
       * use or because our admin changed the flags, so that formerly
       * active features are now deactivated.
       *
       * In any case, we abort user file sharing.
       */
      putlog(LOG_BOTS, "*", "Bot %s tried unsupported feature!", dcc[idx].nick);
      dprintf(idx, "s e Attempt to use an unsupported feature\n");
      zapfbot(idx);

      op_free(buf);
      return 0;
    }
    p = ++s;
  }
  op_free(buf);
  return 1;
}

/* Call all active feature functions in priority order (sending).
 */
static int uff_call_sending(int idx, char *user_file)
{
  for (size_t i = 0; i < uff_vec.size; i++) {
    uff_list_t *ul = (uff_list_t *)op_vec_get(&uff_vec, i);
    if (ul->entry && ul->entry->snd &&
        (dcc[idx].u.bot->uff_flags & ul->entry->flag))
      if (!(ul->entry->snd(idx, user_file)))
        return 0; /* Failed! */
  }
  return 1;
}

/* Call all active feature functions in reverse priority order (receiving).
 */
static int uff_call_receiving(int idx, char *user_file)
{
  for (size_t i = uff_vec.size; i-- > 0; ) {
    uff_list_t *ul = (uff_list_t *)op_vec_get(&uff_vec, i);
    if (ul->entry && ul->entry->rcv &&
        (dcc[idx].u.bot->uff_flags & ul->entry->flag))
      if (!(ul->entry->rcv(idx, user_file)))
        return 0; /* Failed! */
  }
  return 1;
}


/*
 *    Userfile feature handlers
 */


/* Feature `overbots'
 */

static int uff_ask_override_bots(int idx)
{
  if (overr_local_bots)
    return 1;
  else
    return 0;
}


/*
 *     Internal user file feature table
 */

static uff_table_t internal_uff_table[] = {
  {"overbots", UFF_OVERRIDE, uff_ask_override_bots, 0, nullptr, nullptr},
  {"invites",  UFF_INVITE,   nullptr,                  0, nullptr, nullptr},
  {"exempts",  UFF_EXEMPT,   nullptr,                  0, nullptr, nullptr},
  {nullptr,       0,            nullptr,                  0, nullptr, nullptr}
};
