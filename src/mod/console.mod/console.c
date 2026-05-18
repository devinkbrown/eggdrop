/*
 * console.c -- part of console.mod
 *   saved console settings based on console.tcl
 *   by cmwagner/billyjoe/D. Senso
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

#define MODULE_NAME "console"
#define MAKING_CONSOLE

#include "src/mod/module.h"
#include "console.h"

static Function *global = nullptr;
static op_bh *console_info_bh = nullptr;
static int console_autosave = 0;
static int force_channel = 0;
static int info_party = 0;

struct console_info {
  char *channel;
  int conflags;
  int stripflags;
  int echoflags;
  int page;
  int conchan;
};

static struct user_entry_type USERENTRY_CONSOLE;


static int console_unpack(struct userrec *u, struct user_entry *e)
{
  if (!console_info_bh)
    console_info_bh = op_bh_create(sizeof(struct console_info), 32, "console_info");
  struct console_info *ci = op_bh_alloc(console_info_bh);
  char *par, *arg;

  par = e->u.list->extra;
  arg = newsplit(&par);
  ci->channel = op_strdup(arg);
  arg = newsplit(&par);
  ci->conflags = logmodes(arg);
  arg = newsplit(&par);
  ci->stripflags = stripmodes(arg);
  arg = newsplit(&par);
  ci->echoflags = (arg[0] == '1') ? 1 : 0;
  arg = newsplit(&par);
  ci->page = egg_atoi(arg);
  arg = newsplit(&par);
  ci->conchan = egg_atoi(arg);
  list_type_kill(e->u.list);
  e->u.extra = ci;
  return 1;
}

static int console_pack(struct userrec *u, struct user_entry *e)
{
  struct console_info *ci;

  ci = (struct console_info *) e->u.extra;

  op_strbuf_t _b = {};
  op_strbuf_init(&_b);
  op_strbuf_appendf(&_b, "%s %s %s %d %d %d",
                   ci->channel, masktype(ci->conflags),
                   stripmasktype(ci->stripflags), ci->echoflags,
                   ci->page, ci->conchan);

  e->u.list = alloc_list_type();
  e->u.list->next = nullptr;
  e->u.list->extra = op_strbuf_steal(&_b);

  op_free(ci->channel);
  op_bh_free(console_info_bh, ci);
  return 1;
}

static int console_kill(struct user_entry *e)
{
  struct console_info *i = e->u.extra;

  op_free(i->channel);
  op_bh_free(console_info_bh, i);
  free_user_entry(e);
  return 1;
}

static int console_write_userfile(FILE *f, struct userrec *u,
                                  struct user_entry *e)
{
  struct console_info *i = e->u.extra;

  if (fprintf(f, "--CONSOLE %s %s %s %d %d %d\n",
              i->channel, masktype(i->conflags),
              stripmasktype(i->stripflags), i->echoflags,
              i->page, i->conchan) == EOF)
    return 0;
  return 1;
}

static int console_set(struct userrec *u, struct user_entry *e, void *buf)
{
  struct console_info *ci = (struct console_info *) e->u.extra;

  if (!ci && !buf)
    return 1;

  if (ci != buf) {
    if (ci) {
      op_free(ci->channel);
      op_bh_free(console_info_bh, ci);
    }
    e->u.extra = buf;
  }

  /* Note: Do not share console info */
  return 1;
}

static const char *console_tcl_format(struct console_info *i)
{
  static op_strbuf_t _work = {};

  op_strbuf_clear(&_work);
  op_strbuf_appendf(&_work, "%s %s %s %d %d %d",
                  i->channel, masktype(i->conflags),
                  stripmasktype(i->stripflags), i->echoflags,
                  i->page, i->conchan);
  return op_strbuf_str(&_work);
}
static int console_tcl_get(Tcl_Interp *irp, struct userrec *u,
                           struct user_entry *e, int argc, char **argv)
{
  Tcl_SetResult(irp, (char *) console_tcl_format(e->u.extra), TCL_VOLATILE);
  return TCL_OK;
}

static int console_tcl_append(Tcl_Interp *irp, struct userrec *u,
                           struct user_entry *e)
{
  Tcl_AppendElement(irp, console_tcl_format(e->u.extra));
  return TCL_OK;
}

static int console_tcl_set(Tcl_Interp *irp, struct userrec *u,
                           struct user_entry *e, int argc, char **argv)
{
  struct console_info *i = e->u.extra;
  int l;

  BADARGS(4, 9, " handle CONSOLE channel flags strip echo page conchan");

  if (!i) {
    if (!console_info_bh)
      console_info_bh = op_bh_create(sizeof(struct console_info), 32, "console_info");
    i = op_bh_alloc(console_info_bh);
  }
  if (i->channel)
    op_free(i->channel);
  l = strlen(argv[3]);
  if (l > 80)
    l = 80;
  i->channel = user_malloc(l + 1);
  op_strlcpy(i->channel, argv[3], l + 1);
  if (argc > 4) {
    i->conflags = logmodes(argv[4]);
    if (argc > 5) {
      i->stripflags = stripmodes(argv[5]);
      if (argc > 6) {
        i->echoflags = (argv[6][0] == '1') ? 1 : 0;
        if (argc > 7) {
          i->page = egg_atoi(argv[7]);
          if (argc > 8)
            i->conchan = egg_atoi(argv[8]);
        }
      }
    }
  }
  set_user(&USERENTRY_CONSOLE, u, i);
  return TCL_OK;
}

static int console_expmem(struct user_entry *e)
{
  struct console_info *i = e->u.extra;

  return sizeof(struct console_info) + strlen(i->channel) + 1;
}

static void console_display(int idx, struct user_entry *e)
{
  struct console_info *i = e->u.extra;

  if (dcc[idx].user && (dcc[idx].user->flags & USER_MASTER)) {
    dprintf(idx, "  %s\n", CONSOLE_SAVED_SETTINGS);
    dprintf(idx, "    %s %s\n", CONSOLE_CHANNEL, i->channel);
    dprintf(idx, "    %s %s, %s %s, %s %s\n", CONSOLE_FLAGS,
            masktype(i->conflags), CONSOLE_STRIPFLAGS,
            stripmasktype(i->stripflags), CONSOLE_ECHO,
            i->echoflags ? CONSOLE_YES : CONSOLE_NO);
    dprintf(idx, "    %s %d, %s %s%d\n", CONSOLE_PAGE_SETTING, i->page,
            CONSOLE_CHANNEL2, (i->conchan < GLOBAL_CHANS) ? "" : "*",
            i->conchan % GLOBAL_CHANS);
  }
}

static int console_dupuser(struct userrec *new, struct userrec *old,
                           struct user_entry *e)
{
  struct console_info *i = e->u.extra, *j;

  if (!console_info_bh)
    console_info_bh = op_bh_create(sizeof(struct console_info), 32, "console_info");
  j = op_bh_alloc(console_info_bh);
  memcpy(j, i, sizeof(struct console_info));

  j->channel = op_strdup(i->channel);
  return set_user(e->type, new, j);
}

static struct user_entry_type USERENTRY_CONSOLE = {
  nullptr,
  console_dupuser,
  console_unpack,
  console_pack,
  console_write_userfile,
  console_kill,
  nullptr,
  console_set,
  console_tcl_get,
  console_tcl_set,
  console_expmem,
  console_display,
  "CONSOLE",
  console_tcl_append
};

static int console_chon(char *handle, int idx)
{
  struct flag_record fr = { FR_GLOBAL | FR_CHAN };
  struct console_info *i = get_user(&USERENTRY_CONSOLE, dcc[idx].user);

  if (dcc[idx].type == &DCC_CHAT) {
    if (i) {
      if (i->channel && i->channel[0])
        op_strlcpy(dcc[idx].u.chat->con_chan, i->channel, sizeof dcc[idx].u.chat->con_chan);
      get_user_flagrec(dcc[idx].user, &fr, i->channel);
      dcc[idx].u.chat->con_flags = check_conflags(&fr, i->conflags);
      dcc[idx].u.chat->strip_flags = i->stripflags;
      if (i->echoflags)
        dcc[idx].status |= STAT_ECHO;
      else
        dcc[idx].status &= ~STAT_ECHO;
      if (i->page) {
        dcc[idx].status |= STAT_PAGE;
        dcc[idx].u.chat->max_line = i->page;
        if (!dcc[idx].u.chat->line_count)
          dcc[idx].u.chat->current_lines = 0;
      }
      dcc[idx].u.chat->channel = i->conchan;
    } else if (force_channel > -1)
      dcc[idx].u.chat->channel = force_channel;
    if ((dcc[idx].u.chat->channel >= 0) &&
        (dcc[idx].u.chat->channel < GLOBAL_CHANS)) {
      botnet_send_join_idx(idx, -1);
      check_tcl_chjn(botnetnick, dcc[idx].nick, dcc[idx].u.chat->channel,
                     geticon(idx), dcc[idx].sock, dcc[idx].host);
    }
    if (info_party) {
      char *p = get_user(&USERENTRY_INFO, dcc[idx].user);

      if (p) {
        if (dcc[idx].u.chat->channel >= 0) {
          chanout_but(-1, dcc[idx].u.chat->channel,
                      "*** [%s] %s\n", dcc[idx].nick, p);
          op_strbuf_t _b = {};
          op_strbuf_init(&_b);
          op_strbuf_appendf(&_b, "[%s] %s", dcc[idx].nick, p);
          botnet_send_chan(-1, botnetnick, nullptr, dcc[idx].u.chat->channel,
                          op_strbuf_str(&_b));
          op_strbuf_free(&_b);
        }
      }
    }
  }
  return 0;
}

static int console_store(struct userrec *u, int idx, char *par)
{
  struct console_info *i = get_user(&USERENTRY_CONSOLE, u);

  if (!i) {
    if (!console_info_bh)
      console_info_bh = op_bh_create(sizeof(struct console_info), 32, "console_info");
    i = op_bh_alloc(console_info_bh);
  }
  if (i->channel)
    op_free(i->channel);
  i->channel = op_strdup(dcc[idx].u.chat->con_chan);
  i->conflags = dcc[idx].u.chat->con_flags;
  i->stripflags = dcc[idx].u.chat->strip_flags;
  i->echoflags = (dcc[idx].status & STAT_ECHO) ? 1 : 0;
  if (dcc[idx].status & STAT_PAGE)
    i->page = dcc[idx].u.chat->max_line;
  else
    i->page = 0;
  i->conchan = dcc[idx].u.chat->channel;
  if (par) {
    dprintf(idx, "%s\n", CONSOLE_SAVED_SETTINGS2);
    dprintf(idx, "  %s %s\n", CONSOLE_CHANNEL, i->channel);
    dprintf(idx, "  %s %s, %s %s, %s %s\n", CONSOLE_FLAGS,
            masktype(i->conflags), CONSOLE_STRIPFLAGS,
            stripmasktype(i->stripflags), CONSOLE_ECHO,
            i->echoflags ? CONSOLE_YES : CONSOLE_NO);
    dprintf(idx, "  %s %d, %s %d\n", CONSOLE_PAGE_SETTING, i->page,
            CONSOLE_CHANNEL2, i->conchan);
  }
  set_user(&USERENTRY_CONSOLE, u, i);
  return 0;
}

/* cmds.c:cmd_console calls this, better than chof bind - drummer,07/25/1999 */
static int console_dostore(int idx)
{
  if (console_autosave)
    console_store(dcc[idx].user, idx, nullptr);
  return 0;
}

static tcl_ints myints[] = {
  {"console-autosave", &console_autosave, 0},
  {"force-channel",    &force_channel,    0},
  {"info-party",       &info_party,       0},
  {nullptr,               nullptr,              0}
};

static cmd_t mychon[] = {
  {"*",  "",   console_chon, "console:chon"},
  {nullptr, nullptr, nullptr,                   nullptr}
};

static cmd_t mydcc[] = {
  {"store", "",   console_store, nullptr},
  {nullptr,    nullptr, nullptr,          nullptr}
};

static char *console_close(void)
{
  rem_builtins(H_chon, mychon);
  rem_builtins(H_dcc, mydcc);
  rem_tcl_ints(myints);
  rem_help_reference("console.help");
  del_entry_type(&USERENTRY_CONSOLE);
  del_lang_section("console");
  module_undepend(MODULE_NAME);
  return nullptr;
}

EXPORT_SCOPE char *console_start(Function *global_funcs);

static Function console_table[] = {
  (Function) console_start,
  (Function) console_close,
  (Function) nullptr,
  (Function) nullptr,
  (Function) console_dostore,
};

char *console_start(Function *global_funcs)
{
  global = global_funcs;

  module_register(MODULE_NAME, console_table, 1, 3);
  if (!module_depend(MODULE_NAME, "eggdrop", 108, 0)) {
    module_undepend(MODULE_NAME);
    return "This module requires Eggdrop 1.8.0 or later.";
  }
  add_builtins(H_chon, mychon);
  add_builtins(H_dcc, mydcc);
  add_tcl_ints(myints);
  add_help_reference("console.help");
  USERENTRY_CONSOLE.get = def_get;
  add_entry_type(&USERENTRY_CONSOLE);
  add_lang_section("console");
  return nullptr;
}
