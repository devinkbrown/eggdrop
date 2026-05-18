/*
 * assoc.c -- part of assoc.mod
 *   the assoc code, moved here mainly from botnet.c for module work
 */
/*
 * Copyright (C) 1997 Robey Pointer
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

#define MODULE_NAME "assoc"
#define MAKING_ASSOC

#include "src/mod/module.h"
#include "src/tandem.h"
#include <stdlib.h>
#include "assoc.h"

#undef global
static Function *global = nullptr;

/* Keep track of channel associations */
typedef struct assoc_t_ {
  char name[21];
  unsigned int channel;
} assoc_t;

/* Channel name-number associations */
static op_vec_t assoc_vec;
static op_bh   *assoc_bh = nullptr;

static void botnet_send_assoc(int idx, int chan, char *nick, char *buf)
{
  op_strbuf_t _b = {};
  op_strbuf_init(&_b);
  int idx2;

  op_strbuf_appendf(&_b, "assoc %s %s %s", int_to_base64(chan), nick, buf);
  for (idx2 = 0; idx2 < dcc_total; idx2++)
    if ((dcc[idx2].type == &DCC_BOT) && (idx2 != idx) &&
        (b_numver(idx2) >= NEAT_BOTNET) &&
        !(bot_flags(dcc[idx2].user) & BOT_ISOLATE))
      botnet_send_zapf(idx2, botnetnick, dcc[idx2].nick, op_strbuf_str(&_b));
  op_strbuf_free(&_b);
}

static int assoc_expmem(void)
{
  return (int)(assoc_vec.size * sizeof(assoc_t));
}

static void link_assoc(char *bot, char *via)
{
  if (!op_strcasecmp(via, botnetnick)) {
    int idx = nextbot(bot);

    if (!(bot_flags(dcc[idx].user) & BOT_ISOLATE)) {
      for (size_t _i = 0; _i < assoc_vec.size; _i++) {
        assoc_t *a = (assoc_t *)op_vec_get(&assoc_vec, _i);
        if (!a->name[0]) continue;
        op_strbuf_t _b = {};
        op_strbuf_init(&_b);
        op_strbuf_appendf(&_b, "assoc %s %s %s", int_to_base64((int) a->channel),
                          botnetnick, a->name);
        botnet_send_zapf(idx, botnetnick, dcc[idx].nick, op_strbuf_str(&_b));
        op_strbuf_free(&_b);
      }
    }
  }
}

static void kill_assoc(int chan)
{
  for (size_t i = 0; i < assoc_vec.size; i++) {
    assoc_t *a = (assoc_t *)op_vec_get(&assoc_vec, i);
    if (a->channel == (unsigned int)chan) {
      op_vec_remove_fast(&assoc_vec, i);
      op_bh_free(assoc_bh, a);
      return;
    }
  }
}

static void kill_all_assoc(void)
{
  for (size_t i = 0; i < assoc_vec.size; i++)
    op_bh_free(assoc_bh, (assoc_t *)op_vec_get(&assoc_vec, i));
  op_vec_clear(&assoc_vec, nullptr, nullptr);
}

static void add_assoc(char *name, int chan)
{
  /* Check for existing entries with same name or same channel */
  for (size_t i = 0; i < assoc_vec.size; i++) {
    assoc_t *a = (assoc_t *)op_vec_get(&assoc_vec, i);
    if (name[0] != 0 && !op_strcasecmp(a->name, name)) {
      kill_assoc((int)a->channel);
      add_assoc(name, chan);
      return;
    }
    if (a->channel == (unsigned int)chan) {
      op_strlcpy(a->name, name, sizeof a->name);
      return;
    }
  }
  if (!assoc_bh) {
    assoc_bh = op_bh_create(sizeof(assoc_t), 16, "assoc_node");
    op_vec_init(&assoc_vec, 16);
  }
  assoc_t *b = (assoc_t *)op_bh_alloc(assoc_bh);
  b->channel = (unsigned int)chan;
  op_strlcpy(b->name, name, sizeof b->name);
  op_vec_push(&assoc_vec, b);
}

static int get_assoc(char *name)
{
  for (size_t i = 0; i < assoc_vec.size; i++) {
    assoc_t *a = (assoc_t *)op_vec_get(&assoc_vec, i);
    if (!op_strcasecmp(a->name, name))
      return (int)a->channel;
  }
  return -1;
}

static char *get_assoc_name(int chan)
{
  for (size_t i = 0; i < assoc_vec.size; i++) {
    assoc_t *a = (assoc_t *)op_vec_get(&assoc_vec, i);
    if (a->channel == (unsigned int)chan)
      return a->name;
  }
  return nullptr;
}

static int assoc_cmp_channel(const void *pa, const void *pb)
{
  const assoc_t *a = *(const assoc_t **)pa;
  const assoc_t *b = *(const assoc_t **)pb;
  return (a->channel > b->channel) - (a->channel < b->channel);
}

static void dump_assoc(int idx)
{
  if (!assoc_vec.size) {
    dprintf(idx, "%s\n", ASSOC_NOCHNAMES);
    return;
  }
  op_vec_sort(&assoc_vec, assoc_cmp_channel);
  dprintf(idx, " %s  %s\n", ASSOC_CHAN, ASSOC_NAME);
  for (size_t i = 0; i < assoc_vec.size; i++) {
    assoc_t *a = (assoc_t *)op_vec_get(&assoc_vec, i);
    if (!a->name[0]) continue;
    dprintf(idx, "%c%5d %s\n", (a->channel < GLOBAL_CHANS) ? ' ' : '*',
            a->channel % GLOBAL_CHANS, a->name);
  }
}

static int cmd_assoc(struct userrec *u, int idx, char *par)
{
  char *num;
  int chan;

  if (!par[0]) {
    putlog(LOG_CMDS, "*", "#%s# assoc", dcc[idx].nick);
    dump_assoc(idx);
  } else if (!u || !(u->flags & USER_BOTMAST))
    dprintf(idx, "%s", MISC_NOSUCHCMD);
  else {
    num = newsplit(&par);
    if (num[0] == '*') {
      chan = GLOBAL_CHANS + egg_atoi(num + 1);
      if ((chan < GLOBAL_CHANS) || (chan > 199999)) {
        dprintf(idx, "%s\n", ASSOC_LCHAN_RANGE);
        return 0;
      }
    } else {
      chan = egg_atoi(num);
      if (chan == 0) {
        dprintf(idx, "%s\n", ASSOC_PARTYLINE);
        return 0;
      } else if ((chan < 1) || (chan >= GLOBAL_CHANS)) {
        dprintf(idx, "%s\n", ASSOC_CHAN_RANGE);
        return 0;
      }
    }
    if (!par[0]) {
      /* Remove an association */
      if (get_assoc_name(chan) == nullptr) {
        dprintf(idx, ASSOC_NONAME_CHAN, (chan < GLOBAL_CHANS) ? "" : "*",
                chan % GLOBAL_CHANS);
        return 0;
      }
      kill_assoc(chan);
      putlog(LOG_CMDS, "*", "#%s# assoc %d", dcc[idx].nick, chan);
      dprintf(idx, ASSOC_REMNAME_CHAN, (chan < GLOBAL_CHANS) ? "" : "*",
              chan % GLOBAL_CHANS);
      chanout_but(-1, chan, ASSOC_REMOUT_CHAN, dcc[idx].nick);
      if (chan < GLOBAL_CHANS)
        botnet_send_assoc(-1, chan, dcc[idx].nick, "0");
      return 0;
    }
    if (strlen(par) > 20) {
      dprintf(idx, "%s\n", ASSOC_CHNAME_TOOLONG);
      return 0;
    }
    if ((par[0] >= '0') && (par[0] <= '9')) {
      dprintf(idx, "%s\n", ASSOC_CHNAME_FIRSTCHAR);
      return 0;
    }
    add_assoc(par, chan);
    putlog(LOG_CMDS, "*", "#%s# assoc %d %s", dcc[idx].nick, chan, par);
    dprintf(idx, ASSOC_NEWNAME_CHAN, (chan < GLOBAL_CHANS) ? "" : "*",
            chan % GLOBAL_CHANS, par);
    chanout_but(-1, chan, ASSOC_NEWOUT_CHAN, dcc[idx].nick, par);
    if (chan < GLOBAL_CHANS)
      botnet_send_assoc(-1, chan, dcc[idx].nick, par);
  }
  return 0;
}

static int tcl_killassoc STDVAR
{
  int chan;

  BADARGS(2, 2, " chan");

  if (argv[1][0] == '&')
    kill_all_assoc();
  else {
    chan = egg_atoi(argv[1]);
    if ((chan < 1) || (chan > 199999)) {
      Tcl_AppendResult(irp, "invalid channel #", nullptr);
      return TCL_ERROR;
    }
    kill_assoc(chan);

    botnet_send_assoc(-1, chan, "*script*", "0");
  }
  return TCL_OK;
}

static int tcl_assoc STDVAR
{
  int chan;
  char *p;

  BADARGS(2, 3, " chan ?name?");

  if ((argc == 2) && ((argv[1][0] < '0') || (argv[1][0] > '9'))) {
    chan = get_assoc(argv[1]);
    if (chan == -1)
      Tcl_AppendResult(irp, "", nullptr);
    else
      Tcl_AppendResult(irp, int_to_base10(chan), nullptr);
    return TCL_OK;
  }
  chan = egg_atoi(argv[1]);
  if ((chan < 1) || (chan > 199999)) {
    Tcl_AppendResult(irp, "invalid channel #", nullptr);
    return TCL_ERROR;
  }
  if (argc == 3) {
    op_strbuf_t _b = {};
    op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "%.20s", argv[2]);
    add_assoc((char *)op_strbuf_str(&_b), chan);
    botnet_send_assoc(-1, chan, "*script*", (char *)op_strbuf_str(&_b));
    op_strbuf_free(&_b);
  }
  p = get_assoc_name(chan);
  Tcl_AppendResult(irp, p ? p : "", nullptr);
  return TCL_OK;
}

static tcl_cmds mytcl[] = {
  {"assoc",         tcl_assoc},
  {"killassoc", tcl_killassoc},
  {nullptr,                 nullptr}
};

static void zapf_assoc(char *botnick, char *code, char *par)
{
  int idx = nextbot(botnick);
  char *s, *s1, *nick;
  int linking = 0, chan;

  if ((idx >= 0) && !(bot_flags(dcc[idx].user) & BOT_ISOLATE)) {
    if (!op_strcasecmp(dcc[idx].nick, botnick))
      linking = b_status(idx) & STAT_LINKING;
    s = newsplit(&par);
    chan = base64_to_int(s);
    if ((chan > 0) && (chan < GLOBAL_CHANS)) {
      nick = newsplit(&par);
      s1 = get_assoc_name(chan);
      if (linking && ((s1 == nullptr) || (s1[0] == 0) ||
          (((intptr_t) get_user(find_entry_type("BOTFL"),
          dcc[idx].user) & BOT_HUB)))) {
        add_assoc(par, chan);
        botnet_send_assoc(idx, chan, nick, par);
        chanout_but(-1, chan, ASSOC_CHNAME_NAMED, nick, par);
      } else if (par[0] == '0') {
        kill_assoc(chan);
        chanout_but(-1, chan, ASSOC_CHNAME_REM, botnick, nick);
      } else if (get_assoc(par) != chan) {
        /* New one i didn't know about -- pass it on */
        add_assoc(par, chan);
        chanout_but(-1, chan, ASSOC_CHNAME_NAMED2, botnick, nick, par);
      }
    } else {
      dprintf(LOG_DEBUG, "ASSOC: Channel number outside bounds 0..%i\n", GLOBAL_CHANS);
    }
  }
}

static void assoc_report(int idx, int details)
{
  if (details) {
    int count = (int)assoc_vec.size;
    int size  = (int)(assoc_vec.size * sizeof(assoc_t));

    dprintf(idx, "    %d current association%s\n", count,
            (count != 1) ? "s" : "");
    dprintf(idx, "    Using %d byte%s of memory\n", size,
            (size != 1) ? "s" : "");
  }
}

static cmd_t mydcc[] = {
  {"assoc", "",   cmd_assoc, nullptr},
  {nullptr,    nullptr, nullptr,      nullptr}
};

static cmd_t mybot[] = {
  {"assoc", "",   (IntFunc) zapf_assoc, nullptr},
  {nullptr,    nullptr, nullptr,                  nullptr}
};

static cmd_t mylink[] = {
  {"*",  "",   (IntFunc) link_assoc, "assoc"},
  {nullptr, nullptr, nullptr,                     nullptr}
};

static char *assoc_close(void)
{
  kill_all_assoc();
  if (assoc_bh) {
    op_bh_destroy(assoc_bh);
    assoc_bh = nullptr;
  }
  rem_builtins(H_dcc, mydcc);
  rem_builtins(H_bot, mybot);
  rem_builtins(H_link, mylink);
  rem_tcl_commands(mytcl);
  rem_help_reference("assoc.help");
  del_lang_section("assoc");
  module_undepend(MODULE_NAME);
  return nullptr;
}

EXPORT_SCOPE char *assoc_start(Function *global_funcs);

static Function assoc_table[] = {
  (Function) assoc_start,
  (Function) assoc_close,
  (Function) assoc_expmem,
  (Function) assoc_report,
  /* 4 */ (Function) get_assoc,
  /* 5 */ (Function) get_assoc_name,
  /* 6 */ (Function) add_assoc,
  /* 7 */ (Function) kill_assoc,
  /* 8 */ (Function) kill_all_assoc,
};

char *assoc_start(Function *global_funcs)
{
  global = global_funcs;

  module_register(MODULE_NAME, assoc_table, 2, 1);
  if (!module_depend(MODULE_NAME, "eggdrop", 108, 0)) {
    module_undepend(MODULE_NAME);
    return "This module requires Eggdrop 1.8.0 or later.";
  }
  op_vec_init(&assoc_vec, 16);
  add_builtins(H_dcc, mydcc);
  add_builtins(H_bot, mybot);
  add_builtins(H_link, mylink);
  add_lang_section("assoc");
  add_tcl_commands(mytcl);
  add_help_reference("assoc.help");
  return nullptr;
}
