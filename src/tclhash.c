/*
 * tclhash.c -- handles:
 *   bind and unbind
 *   checking and triggering the various in-bot bindings
 *   listing current bindings
 *   adding/removing new binding tables
 *   (non-Tcl) procedure lookups for msg/dcc/file commands
 *   (Tcl) binding internal procedures to msg/dcc/file commands
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

#include "main.h"

extern Tcl_Interp *interp;
extern struct dcc_t *dcc;
extern struct userrec *userlist;
extern int dcc_total;
extern time_t now;
extern cmd_t C_dcc[];

p_tcl_bind_list bind_table_list;
static op_htab *bind_table_ht    = nullptr;

/* op_bh slab allocators for the three fixed-size tclhash node types.
 * Initialized in init_bind(), destroyed in kill_bind(). */
static op_bh *tcl_cmd_heap       = nullptr;
static op_bh *tcl_bind_mask_heap = nullptr;
static op_bh *tcl_bind_list_heap = nullptr;

/* Set to 1 whenever a bind is added or marked deleted.
 * garbage_collect_tclhash() uses this to skip the traversal when nothing
 * has changed, turning the common idle case into an O(1) check. */
static int tclhash_dirty = 0;

/* Bind-table head pointers; always present (nullptr when Tcl is disabled). */
p_tcl_bind_list H_chat, H_act, H_bcst, H_chon, H_chof, H_load, H_unld, H_link,
                H_disc, H_dcc, H_chjn, H_chpt, H_bot, H_time, H_nkch, H_away,
                H_note, H_filt, H_event, H_die, H_cron, H_log = nullptr;
#ifdef TLS
p_tcl_bind_list H_tls = nullptr;
#endif

#include "script.h"


/* ===================================================================
 * SHARED CODE — unconditional, used by both Tcl and no-Tcl builds.
 * Data structures are identical; only dispatch differs.
 * =================================================================== */

/* Allocate a tcl_cmd_t from the slab, zeroed. */
static tcl_cmd_t *tcl_cmd_alloc(void)
{
  tcl_cmd_t *tc = op_bh_alloc(tcl_cmd_heap);
  memset(tc, 0, sizeof *tc);
  return tc;
}

/* Delete trigger/command — return struct to slab, string to op_malloc pool. */
static void tcl_cmd_delete(tcl_cmd_t *tc)
{
  op_free(tc->func_name);
  op_bh_free(tcl_cmd_heap, tc);
}

/* Delete bind and its elements. */
static void tcl_bind_mask_delete(tcl_bind_mask_t *tm)
{
  tcl_cmd_t *tc, *tc_next;

  for (tc = tm->first; tc; tc = tc_next) {
    tc_next = tc->next;
    tcl_cmd_delete(tc);
  }
  op_free(tm->mask);
  op_bh_free(tcl_bind_mask_heap, tm);
}

/* Delete bind list and its elements. */
static void tcl_bind_list_delete(tcl_bind_list_t *tl)
{
  tcl_bind_mask_t *tm, *tm_next;

  for (tm = tl->first; tm; tm = tm_next) {
    tm_next = tm->next;
    tcl_bind_mask_delete(tm);
  }
  if (tl->mask_ht)
    op_htab_destroy(tl->mask_ht, nullptr, nullptr);
  op_bh_free(tcl_bind_list_heap, tl);
}

void garbage_collect_tclhash(void)
{
  tcl_bind_list_t *tl, *tl_next, *tl_prev;
  tcl_bind_mask_t *tm, *tm_next, *tm_prev;
  tcl_cmd_t *tc, *tc_next, *tc_prev;

  if (!tclhash_dirty)
    return;                     /* Nothing changed since last GC: skip */
  tclhash_dirty = 0;

  for (tl = bind_table_list, tl_prev = nullptr; tl; tl = tl_next) {
    tl_next = tl->next;

    if (tl->flags & HT_DELETED) {
      if (tl_prev)
        tl_prev->next = tl->next;
      else
        bind_table_list = tl->next;
      tcl_bind_list_delete(tl);
    } else {
      for (tm = tl->first, tm_prev = nullptr; tm; tm = tm_next) {
        tm_next = tm->next;

        if (!(tm->flags & TBM_DELETED)) {
          for (tc = tm->first, tc_prev = nullptr; tc; tc = tc_next) {
            tc_next = tc->next;

            if (tc->attributes & TC_DELETED) {
              if (tc_prev)
                tc_prev->next = tc->next;
              else
                tm->first = tc->next;
              tcl_cmd_delete(tc);
            } else
              tc_prev = tc;
          }
        }

        /* Delete the bind when it's marked as deleted or when it's empty. */
        if ((tm->flags & TBM_DELETED) || tm->first == nullptr) {
          if (tl->mask_ht)
            op_htab_del(tl->mask_ht, tm->mask);
          if (tm_prev)
            tm_prev->next = tm->next;
          else
            tl->first = tm_next;
          tcl_bind_mask_delete(tm);
        } else
          tm_prev = tm;
      }
      tl_prev = tl;
    }
  }
}

/* Find or create a bind mask entry for the given mask string. */
static tcl_bind_mask_t *find_or_add_mask(tcl_bind_list_t *tl, const char *mask)
{
  tcl_bind_mask_t *tm;

  for (tm = tl->first; tm; tm = tm->next)
    if (!(tm->flags & TBM_DELETED) && !strcmp(tm->mask, mask))
      return tm;
  tm = op_bh_alloc(tcl_bind_mask_heap);
  memset(tm, 0, sizeof *tm);
  tm->mask  = op_strdup(mask);
  tm->next  = tl->first;
  tl->first = tm;
  if (tl->mask_ht)
    op_htab_set(tl->mask_ht, tm->mask, tm, nullptr);
  return tm;
}

tcl_bind_list_t *add_bind_table(const char *nme, int flg, IntFunc func)
{
  tcl_bind_list_t *tl, *tl_prev;
  int v;

  /* Do not allow coders to use bind table names longer than
   * 15 characters. */
  Assert(strlen(nme) <= 15);

  for (tl = bind_table_list, tl_prev = nullptr; tl; tl_prev = tl, tl = tl->next) {
    if (tl->flags & HT_DELETED)
      continue;
    v = strcasecmp(tl->name, nme);
    if (!v) {
      if (func && !tl->func)
        tl->func = func;
      return tl;
    }
    if (v > 0)
      break;                    /* New. Insert at start of list.        */
  }

  tl = op_bh_alloc(tcl_bind_list_heap);
  memset(tl, 0, sizeof *tl);
  strlcpy(tl->name, nme, sizeof(tl->name));
  tl->flags = flg;
  tl->func = func;
  tl->mask_ht = op_htab_create_istr("bind_masks", 16);

  if (tl_prev) {
    tl->next = tl_prev->next;
    tl_prev->next = tl;
  } else {
    tl->next = bind_table_list;
    bind_table_list = tl;
  }

  if (bind_table_ht)
    op_htab_set(bind_table_ht, tl->name, tl, nullptr);
  putlog(LOG_DEBUG, "*", "Allocated bind table %s (flags %d)", nme, flg);
  return tl;
}

void del_bind_table(tcl_bind_list_t *tl_which)
{
  tcl_bind_list_t *tl;

  for (tl = bind_table_list; tl; tl = tl->next) {
    if (tl->flags & HT_DELETED)
      continue;
    if (tl == tl_which) {
      tl->flags |= HT_DELETED;
      if (bind_table_ht)
        op_htab_del(bind_table_ht, tl->name);
      tclhash_dirty = 1;
      putlog(LOG_DEBUG, "*", "De-Allocated bind table %s", tl->name);
      return;
    }
  }
  putlog(LOG_DEBUG, "*", "??? Tried to delete not listed bind table ???");
}

tcl_bind_list_t *find_bind_table(const char *nme)
{
  tcl_bind_list_t *tl;

  if (bind_table_ht) {
    tl = op_htab_get(bind_table_ht, nme);
    if (tl && !(tl->flags & HT_DELETED))
      return tl;
    return nullptr;
  }
  /* Fallback: linear scan (htab not yet initialised). */
  for (tl = bind_table_list; tl; tl = tl->next) {
    if (!(tl->flags & HT_DELETED) && !strcasecmp(tl->name, nme))
      return tl;
  }
  return nullptr;
}

/* Add command (remove old one if necessary) */
int bind_bind_entry(tcl_bind_list_t *tl, const char *flags,
                    const char *cmd, const char *proc)
{
  tcl_cmd_t *tc;
  tcl_bind_mask_t *tm;

  if (!tl || !cmd || !proc)
    return 0;

  tm = find_or_add_mask(tl, cmd);

  /* Proc already defined? If so, replace flags. */
  for (tc = tm->first; tc; tc = tc->next) {
    if (tc->attributes & TC_DELETED)
      continue;
    if (!strcmp(tc->func_name, proc)) {
      tc->flags.match = FR_GLOBAL | FR_CHAN;
      break_down_flags(flags, &(tc->flags), nullptr);
      return 1;
    }
  }

  /* If this bind list is not stackable, remove the
   * old entry from this bind. */
  if (!(tl->flags & HT_STACKABLE)) {
    for (tc = tm->first; tc; tc = tc->next) {
      if (tc->attributes & TC_DELETED)
        continue;
      /* NOTE: We assume there's only one not-yet-deleted entry. */
      tc->attributes |= TC_DELETED;
      tclhash_dirty = 1;
      break;
    }
  }

  tc = tcl_cmd_alloc();
  tc->flags.match = FR_GLOBAL | FR_CHAN;
  break_down_flags(flags, &(tc->flags), nullptr);
  tc->func_name = op_strdup(proc);

  /* Link into linked list of the bind's command list. */
  tc->next = tm->first;
  tm->first = tc;
  tclhash_dirty = 1;

  return 1;
}

int unbind_bind_entry(tcl_bind_list_t *tl, const char *flags,
                             const char *cmd, const char *proc)
{
  tcl_bind_mask_t *tm;

  if (!tl || !cmd || !proc)
    return 0;

  /* Search for matching bind in bind list. */
  for (tm = tl->first; tm; tm = tm->next) {
    if (tm->flags & TBM_DELETED)
      continue;
    if (!strcmp(cmd, tm->mask))
      break;                    /* Found it! fall out! */
  }

  if (tm) {
    tcl_cmd_t *tc;

    /* Search for matching proc in bind. */
    for (tc = tm->first; tc; tc = tc->next) {
      if (tc->attributes & TC_DELETED)
        continue;
      if (!strcasecmp(tc->func_name, proc)) {
        /* Erase proc regardless of flags. */
        tc->attributes |= TC_DELETED;
        tclhash_dirty = 1;
        return 1;               /* Match.       */
      }
    }
  }
  return 0;                     /* No match.    */
}

/* Find out whether this bind matches the mask or provides the
 * requested attributes, depending on the specified requirements.
 */
static int check_bind_match(const char *match, char *mask, int match_type)
{
  switch (match_type & 0x07) {
  case MATCH_PARTIAL:
    return (!strncasecmp(match, mask, strlen(match)));
    break;
  case MATCH_EXACT:
    return (!strcasecmp(match, mask));
    break;
  case MATCH_CASE:
    return (!strcmp(match, mask));
    break;
  case MATCH_MASK:
    return (wild_match_per(mask, match));
    break;
  case MATCH_MODE:
    return (wild_match_partial_case(mask, match));
    break;
  case MATCH_CRON:
    return (cron_match(mask, match));
    break;
  default:
    break;
  }
  return 0;
}

/* Check if the provided flags suffice for this command/trigger. */
static int check_bind_flags(struct flag_record *flags, struct flag_record *atr,
                            int match_type)
{
  if (match_type & BIND_USE_ATTR) {
    if (match_type & BIND_HAS_BUILTINS)
      return (flagrec_ok(flags, atr));
    else
      return (flagrec_eq(flags, atr));
  }
  return 1;
}


/* Build argv[] from the param string (e.g. " $_dcc1 $_dcc2 $_dcc3").
 * Each "$_varname" token is looked up in egg_vars[].
 * Returns the number of args placed into argv[]. */
static int build_argv(const char *param, const char **argv, int maxargc)
{
  char pbuf[2048];
  char *tok, *brkt;
  int argc = 0;

  if (!param || !*param)
    return 0;
  strlcpy(pbuf, param, sizeof pbuf);
  tok = strtok_r(pbuf, " ", &brkt);
  while (tok && argc < maxargc) {
    if (tok[0] == '$' && tok[1] == '_')
      argv[argc++] = egg_getvar(tok + 1);   /* skip leading '$' */
    tok = strtok_r(nullptr, " ", &brkt);
  }
  return argc;
}


/* ===================================================================
 * TCL-ONLY CODE — Tcl builtin trampolines, trigger_bind, tcl_bind
 * command, and Tcl-specific versions of add_builtins/rem_builtins.
 * =================================================================== */

#ifdef HAVE_TCL

#ifdef DEBUG_CONTEXT
char last_bind_called[512] = "";
#endif

#ifdef TLS
static int builtin_idx STDVAR;
#endif

static int builtin_2char STDVAR;
static int builtin_3char STDVAR;
static int builtin_5int STDVAR;
static int builtin_cron STDVAR;
static int builtin_char STDVAR;
static int builtin_chpt STDVAR;
static int builtin_chjn STDVAR;
static int builtin_evnt STDVAR;
static int builtin_idxchar STDVAR;
static int builtin_charidx STDVAR;
static int builtin_chat STDVAR;
static int builtin_dcc STDVAR;
static int builtin_log STDVAR;

static int builtin_3char STDVAR
{
  void (*F)(char *, char *, char *) = (void (*)(char *, char *, char *)) cd;

  BADARGS(4, 4, " from to args");

  CHECKVALIDITY(builtin_3char);
  F(argv[1], argv[2], argv[3]);
  return TCL_OK;
}

static int builtin_2char STDVAR
{
  void (*F)(char *, char *) = (void (*)(char *, char *)) cd;

  BADARGS(3, 3, " nick msg");

  CHECKVALIDITY(builtin_2char);
  F(argv[1], argv[2]);
  return TCL_OK;
}

static int builtin_5int STDVAR
{
  void (*F)(int, int, int, int, int) = (void (*)(int, int, int, int, int)) cd;

  BADARGS(6, 6, " min hrs dom mon year");

  CHECKVALIDITY(builtin_5int);
  F(egg_atoi(argv[1]), egg_atoi(argv[2]), egg_atoi(argv[3]), egg_atoi(argv[4]), egg_atoi(argv[5]));
  return TCL_OK;
}

static int builtin_cron STDVAR
{
  void (*F)(int, int, int, int, int) = (void (*)(int, int, int, int, int)) cd;

  BADARGS(6, 6, " min hrs dom weekday");

  CHECKVALIDITY(builtin_cron);
  F(egg_atoi(argv[1]), egg_atoi(argv[2]), egg_atoi(argv[3]), egg_atoi(argv[4]), egg_atoi(argv[5]));
  return TCL_OK;
}

static int builtin_char STDVAR
{
  void (*F)(char *) = (void (*)(char *)) cd;

  BADARGS(2, 2, " handle");

  CHECKVALIDITY(builtin_char);
  F(argv[1]);
  return TCL_OK;
}

static int builtin_chpt STDVAR
{
  void (*F)(char *, char *, int) = (void (*)(char *, char *, int)) cd;

  BADARGS(3, 3, " bot nick sock");

  CHECKVALIDITY(builtin_chpt);
  F(argv[1], argv[2], egg_atoi(argv[3]));
  return TCL_OK;
}

static int builtin_chjn STDVAR
{
  void (*F)(char *, char *, int, char, int, char *) =
    (void (*)(char *, char *, int, char, int, char *)) cd;

  BADARGS(6, 6, " bot nick chan# flag&sock host");

  CHECKVALIDITY(builtin_chjn);
  F(argv[1], argv[2], egg_atoi(argv[3]), argv[4][0],
    argv[4][0] ? egg_atoi(argv[4] + 1) : 0, argv[5]);
  return TCL_OK;
}

static int builtin_evnt STDVAR
{
  Function F = (Function) cd;

  BADARGS(2, 3, " event ?arg?");

  CHECKVALIDITY(builtin_evnt);
  if (argc==2) {
    ((void (*)(char *)) F)(argv[1]);
  } else {
    ((void (*)(char *, char *)) F)(argv[1], argv[2]);
  }
  return TCL_OK;
}

static int builtin_idxchar STDVAR
{
  Function F = (Function) cd;
  int idx;
  char *r;

  BADARGS(3, 3, " idx args");

  CHECKVALIDITY(builtin_idxchar);
  idx = findidx(egg_atoi(argv[1]));
  if (idx < 0) {
    Tcl_AppendResult(irp, "invalid idx", nullptr);
    return TCL_ERROR;
  }
  r = ((char *(*)(int, char *)) F)(idx, argv[2]);

  Tcl_ResetResult(irp);
  Tcl_AppendResult(irp, r, nullptr);
  return TCL_OK;
}

static int builtin_charidx STDVAR
{
  Function F = (Function) cd;
  int idx;

  BADARGS(3, 3, " handle idx");

  CHECKVALIDITY(builtin_charidx);
  idx = findanyidx(egg_atoi(argv[2]));
  if (idx < 0) {
    Tcl_AppendResult(irp, "invalid idx", nullptr);
    return TCL_ERROR;
  }
  Tcl_AppendResult(irp, int_to_base10(((intptr_t (*)(char *, int)) F)(argv[1], idx)), nullptr);

  return TCL_OK;
}

static int builtin_chat STDVAR
{
  void (*F)(char *, int, char *) = (void (*)(char *, int, char *)) cd;
  int ch;

  BADARGS(4, 4, " handle idx text");

  CHECKVALIDITY(builtin_chat);
  ch = egg_atoi(argv[2]);
  F(argv[1], ch, argv[3]);
  return TCL_OK;
}

static int builtin_dcc STDVAR
{
  int idx;
  Function F = (Function) cd;

  BADARGS(4, 4, " hand idx param");

  CHECKVALIDITY(builtin_dcc);
  idx = findidx(egg_atoi(argv[2]));
  if (idx < 0) {
    Tcl_AppendResult(irp, "invalid idx", nullptr);
    return TCL_ERROR;
  }

  /* CMD_LEAVE is the sentinel for partyline/filesys 'quit'.  Return
   * TCL_BREAK so check_bind() can detect it via the Tcl return-code
   * rather than inspecting the result string. */
  if (F == CMD_LEAVE)
    return TCL_BREAK;

  /* Check if it's a password change, if so, don't show the password. We
   * don't need pretty formats here, as it's only for debugging purposes.
   */
  debug4("tcl: builtin dcc call: %s %s %s %s", argv[0], argv[1], argv[2],
         (!strcmp(argv[0] + 5, "newpass") || !strcmp(argv[0] + 5, "chpass")) ?
         "[something]" : argv[3]);
  ((void (*)(struct userrec *, int, char *)) F)(dcc[idx].user, idx, argv[3]);
  Tcl_ResetResult(irp);
  Tcl_AppendResult(irp, "0", nullptr);
  return TCL_OK;
}

static int builtin_log STDVAR
{
  void (*F)(char *, char *, char *) = (void (*)(char *, char *, char *)) cd;

  BADARGS(3, 3, " lvl chan msg");

  CHECKVALIDITY(builtin_log);
  F(argv[1], argv[2], argv[3]);
  return TCL_OK;
}

#ifdef TLS
static int builtin_idx STDVAR
{
  void (*F)(int) = (void (*)(int)) cd;

  BADARGS(2, 2, " idx");

  CHECKVALIDITY(builtin_idx);
  F(egg_atoi(argv[1]));
  return TCL_OK;
}
#endif

/* Trigger (execute) a Tcl proc */
static int trigger_bind(const char *proc, const char *param, char *mask)
{
  int x;
  struct egg_rusage_timer rt = {};

  /* Set the lastbind variable before evaluating the proc so that the name
   * of the command that triggered the bind will be available to the proc.
   * This feature is used by scripts such as userinfo.tcl
   */
  Tcl_SetVar(interp, "lastbind", mask, TCL_GLOBAL_ONLY);

  if(proc && proc[0] != '*') { /* proc[0] != '*' excludes internal binds */
#ifdef DEBUG_CONTEXT
    strlcpy(last_bind_called, proc, sizeof last_bind_called);
#endif
    debug1("triggering bind %s", proc);
    egg_timer_start(&rt);
  }
  x = Tcl_VarEval(interp, proc, param, nullptr);
  double ums, sms;
  if (proc && proc[0] != '*' && egg_timer_stop(&rt, &ums, &sms))
    debug3("triggered bind %s, user %.3fms sys %.3fms", proc, ums, sms);

  if (x == TCL_ERROR) {
    putlog(LOG_MISC, "*", "Tcl error [%s]: %s", proc, tcl_resultstring());
    Tcl_BackgroundError(interp);

    return BIND_EXECUTED;
  }

  /* CMD_LEAVE (partyline/filesys quit) signals via TCL_BREAK. */
  if (x == TCL_BREAK)
    return BIND_QUIT;

  return (tcl_resultint() > 0) ? BIND_EXEC_LOG : BIND_EXECUTED;
}

static void dump_bind_tables(Tcl_Interp *irp)
{
  tcl_bind_list_t *tl;
  uint8_t i;

  for (tl = bind_table_list, i = 0; tl; tl = tl->next) {
    if (tl->flags & HT_DELETED)
      continue;
    if (i)
      Tcl_AppendResult(irp, ", ", nullptr);
    else
      i = 1;
    Tcl_AppendResult(irp, tl->name, nullptr);
  }
}

static int tcl_getbinds(tcl_bind_list_t *tl_kind, const char *name)
{
  tcl_bind_mask_t *tm;

  for (tm = tl_kind->first; tm; tm = tm->next) {
    if (tm->flags & TBM_DELETED)
      continue;
    if (!strcasecmp(tm->mask, name)) {
      tcl_cmd_t *tc;

      for (tc = tm->first; tc; tc = tc->next) {
        if (tc->attributes & TC_DELETED)
          continue;
        Tcl_AppendElement(interp, tc->func_name);
      }
      break;
    }
  }
  return TCL_OK;
}

static int tcl_bind STDVAR
{
  tcl_bind_list_t *tl;

  /* cd defines what tcl_bind is supposed do: 0 = bind, 1 = unbind. */
  if ((long int) cd == 1)
    BADARGS(5, 5, " type flags cmd/mask procname");

  else
    BADARGS(4, 5, " type flags cmd/mask ?procname?");

  tl = find_bind_table(argv[1]);
  if (!tl) {
    Tcl_AppendResult(irp, "bad type, should be one of: ", nullptr);
    dump_bind_tables(irp);
    return TCL_ERROR;
  }
  if ((long int) cd == 1) {
    if (!unbind_bind_entry(tl, argv[2], argv[3], argv[4])) {
      /* Don't error if trying to re-unbind a builtin */
      if (argv[4][0] != '*' || argv[4][4] != ':' ||
          strcmp(argv[3], &argv[4][5]) || strncmp(argv[1], &argv[4][1], 3)) {
        Tcl_AppendResult(irp, "no such binding", nullptr);
        return TCL_ERROR;
      }
    }
  } else {
    if (argc == 4)
      return tcl_getbinds(tl, argv[3]);
    bind_bind_entry(tl, argv[2], argv[3], argv[4]);
  }
  Tcl_AppendResult(irp, argv[3], nullptr);
  return TCL_OK;
}

static cd_tcl_cmd cd_cmd_table[] = {
  {"bind",   tcl_bind, (void *) 0},
  {"unbind", tcl_bind, (void *) 1},
  {0}
};

int check_validity(char *nme, IntFunc func)
{
  char *p;
  tcl_bind_list_t *tl;

  if (*nme != '*')
    return 0;
  p = strchr(nme + 1, ':');
  if (p == nullptr)
    return 0;
  *p = 0;
  tl = find_bind_table(nme + 1);
  *p = ':';
  if (!tl)
    return 0;
  if (tl->func != func)
    return 0;
  return 1;
}

/* Bring the default msg/dcc/fil commands into the Tcl interpreter */
void add_builtins(tcl_bind_list_t *tl, cmd_t *cc)
{
  int k;
  char *l;
  cd_tcl_cmd table[2];

  table[0].callback = tl->func;
  table[1].name = nullptr;
  for (int i = 0; cc[i].name; i++) {
    op_arena_mark_t mark = op_arena_save(op_event_arena());
    op_strbuf_t p = {};
    op_strbuf_init(&p);
    op_strbuf_appendf(&p, "*%s:%s", tl->name,
                 cc[i].funcname ? cc[i].funcname : cc[i].name);
    l = op_arena_alloc(op_event_arena(), Tcl_ScanElement(op_strbuf_str(&p), &k) + 1);
    Tcl_ConvertElement(op_strbuf_str(&p), l, k | TCL_DONT_USE_BRACES);
    table[0].name = op_strbuf_str(&p);
    table[0].cdata = (void *) cc[i].func;
    add_cd_tcl_cmds(table);
    bind_bind_entry(tl, cc[i].flags, cc[i].name, l);
    op_strbuf_free(&p);
    op_arena_restore(op_event_arena(), mark);
  }
}

/* Remove the default msg/dcc/fil commands from the Tcl interpreter */
void rem_builtins(tcl_bind_list_t *table, cmd_t *cc)
{
  int k;
  char *l;

  for (int i = 0; cc[i].name; i++) {
    op_arena_mark_t mark = op_arena_save(op_event_arena());
    op_strbuf_t p = {};
    op_strbuf_init(&p);
    op_strbuf_appendf(&p, "*%s:%s", table->name,
                 cc[i].funcname ? cc[i].funcname : cc[i].name);
    l = op_arena_alloc(op_event_arena(), Tcl_ScanElement(op_strbuf_str(&p), &k) + 1);
    Tcl_ConvertElement(op_strbuf_str(&p), l, k | TCL_DONT_USE_BRACES);
    Tcl_DeleteCommand(interp, op_strbuf_str(&p));
    unbind_bind_entry(table, cc[i].flags, cc[i].name, l);
    op_strbuf_free(&p);
    op_arena_restore(op_event_arena(), mark);
  }
}

/* Dispatch macro for Tcl builds — calls trigger_bind. */
#define DISPATCH(tc, param, mask, argv, argc) \
  trigger_bind((tc)->func_name, param, mask)


/* ===================================================================
 * NO-TCL-ONLY CODE — native dispatch, build_argv, add_builtins.
 * =================================================================== */

#else /* !HAVE_TCL */

/* Called by check_tcl_bind for C DCC builtin entries.
 * argv[0] = handle, argv[1] = sock-as-string, argv[2] = args */
static int native_dcc_call(void *cd, const char **argv, int argc)
{
  void (*F)(struct userrec *, int, char *) = cd;
  int idx;

  if (argc < 3)
    return 0;
  idx = findidx(egg_atoi(argv[1]));
  if (idx < 0)
    return 0;
  F(dcc[idx].user, idx, (char *) argv[2]);
  return 0;
}

/* Dispatch a native bind entry. Returns BIND_EXECUTED or BIND_EXEC_LOG. */
static int dispatch_native(tcl_cmd_t *tc, const char **argv, int argc)
{
  int x;

  if (tc->native_fn)
    x = ((int (*)(void *, const char **, int)) tc->native_fn)
          (tc->native_cd, argv, argc);
  else
    x = script_call(tc->func_name, argc, argv);
  return x > 0 ? BIND_EXEC_LOG : BIND_EXECUTED;
}

int check_validity(char *fn, IntFunc func)
{
  return 1;
}

void add_builtins(tcl_bind_list_t *tl, cmd_t *cc)
{
  tcl_bind_mask_t *tm;
  tcl_cmd_t *tc;
  struct flag_record fr;

  if (!tl)
    return;
  for (int i = 0; cc[i].name; i++) {
    op_strbuf_t key_buf = {};
    op_strbuf_init(&key_buf);
    op_strbuf_appendf(&key_buf, "*%s:%s", tl->name,
                 cc[i].funcname ? cc[i].funcname : cc[i].name);
    const char *key = op_strbuf_str(&key_buf);

    egg_bzero(&fr, sizeof fr);
    fr.match = FR_GLOBAL | FR_CHAN;
    break_down_flags(cc[i].flags ? cc[i].flags : "", &fr, nullptr);

    tm = find_or_add_mask(tl, cc[i].name);

    /* Skip if already registered */
    for (tc = tm->first; tc; tc = tc->next)
      if (!(tc->attributes & TC_DELETED) && !strcmp(tc->func_name, key)) {
        op_strbuf_free(&key_buf);
        goto next_cmd;
      }

    tc = tcl_cmd_alloc();
    tc->flags     = fr;
    tc->func_name = op_strdup(key);
    tc->native_fn = tl->func;         /* type-specific trampoline */
    tc->native_cd = (void *) cc[i].func;  /* actual C handler       */
    tc->next      = tm->first;
    tm->first     = tc;
    tclhash_dirty = 1;
    op_strbuf_free(&key_buf);

  next_cmd:;
  }
}

void rem_builtins(tcl_bind_list_t *tl, cmd_t *cc)
{
  if (!tl)
    return;
  for (int i = 0; cc[i].name; i++) {
    op_strbuf_t key_buf = {};
    op_strbuf_init(&key_buf);
    op_strbuf_appendf(&key_buf, "*%s:%s", tl->name,
                 cc[i].funcname ? cc[i].funcname : cc[i].name);
    unbind_bind_entry(tl, cc[i].flags, cc[i].name, op_strbuf_str(&key_buf));
    op_strbuf_free(&key_buf);
  }
}

/* Dispatch macro for no-Tcl builds — calls dispatch_native. */
#define DISPATCH(tc, param, mask, argv, argc) \
  dispatch_native(tc, argv, argc)

#endif /* HAVE_TCL */


/* ===================================================================
 * UNIFIED DISPATCHER — check_tcl_bind, used by both build modes.
 * The DISPATCH macro routes to trigger_bind (Tcl) or
 * dispatch_native (no-Tcl).
 * =================================================================== */

int check_tcl_bind(tcl_bind_list_t *tl, const char *match,
                   struct flag_record *atr, const char *param, int match_type)
{
  int x, result = 0, cnt = 0, finish = 0;
  [[maybe_unused]] char *mask = nullptr;
  tcl_bind_mask_t *tm, *tm_last = nullptr, *tm_p = nullptr;
  tcl_cmd_t *tc, *htc = nullptr;
  char *str, *varName, *brkt;
  const char *argv[16];
  [[maybe_unused]] int argc;

  if (!tl)
    return BIND_NOMATCH;

  /* Reconstruct argv from param string.  In Tcl builds the DISPATCH macro
   * ignores argv/argc (it calls trigger_bind instead), but build_argv is
   * harmless and keeps the code path unified. */
  argc = build_argv(param, argv, 16);

  /* Fast path: O(1) lookup for MATCH_EXACT via mask_ht. */
  if ((match_type & 0x07) == MATCH_EXACT && tl->mask_ht) {
    tm = op_htab_get(tl->mask_ht, match);
    if (!tm || (tm->flags & TBM_DELETED))
      goto exact_miss;

    for (tc = tm->first; tc; tc = tc->next) {
      if (tc->attributes & TC_DELETED)
        continue;
      if (!check_bind_flags(&tc->flags, atr, match_type))
        continue;
      cnt++;
      if (!(match_type & BIND_STACKABLE)) {
        htc = tc;
        mask = tm->mask;
        cnt = 1;
        break;
      }
      tc->hits++;
      x = DISPATCH(tc, param, tm->mask, argv, argc);
      if ((match_type & BIND_ALTER_ARGS) && tcl_resultempty())
        goto finally;
      if ((match_type & BIND_STACKRET) && x == BIND_EXEC_LOG) {
        if (!result)
          result = x;
        continue;
      }
      if ((match_type & BIND_WANTRET) && x == BIND_EXEC_LOG)
        goto finally;
    }
    if (!cnt) {
exact_miss:
      x = BIND_NOMATCH;
      goto finally;
    }
    if (result) { x = result; goto finally; }
    if (htc) {
      htc->hits++;
      x = DISPATCH(htc, param, mask, argv, argc);
      goto finally;
    }
    x = BIND_EXECUTED;
    goto finally;
  }

  for (tm = tl->first; tm && !finish; tm_last = tm, tm = tm->next) {

    if (tm->flags & TBM_DELETED)
      continue;                 /* This bind mask was deleted */

    if (!check_bind_match(match, tm->mask, match_type))
      continue;                 /* This bind does not match. */

    for (tc = tm->first; tc; tc = tc->next) {

      /* Search for valid entry. */
      if (!(tc->attributes & TC_DELETED)) {

        /* Check if the provided flags suffice for this command. */
        if (check_bind_flags(&tc->flags, atr, match_type)) {
          cnt++;
          tm_p = tm_last;

          /* Not stackable */
          if (!(match_type & BIND_STACKABLE)) {

            /* Remember information about this bind. */
            mask = tm->mask;
            htc = tc;

            /* Either this is a non-partial match, which means we
             * only want to execute _one_ bind ...
             */
            if ((match_type & 0x07) != MATCH_PARTIAL ||
              /* ... or this happens to be an exact match. */
              !strcasecmp(match, tm->mask)) {
              cnt = 1;
              finish = 1;
            }

            /* We found a match so break out of the inner loop. */
            break;
          }

          /*
           * Stackable; could be multiple commands/triggers.
           * Note: This code assumes BIND_ALTER_ARGS, BIND_WANTRET, and
           *       BIND_STACKRET will only be used for stackable binds.
           */

          tc->hits++;
          x = DISPATCH(tc, param, tm->mask, argv, argc);

          if (match_type & BIND_ALTER_ARGS) {
            if (tcl_resultempty())
              goto finally;
          } else if ((match_type & BIND_STACKRET) && x == BIND_EXEC_LOG) {
            if (!result)
              result = x;
            continue;
          } else if ((match_type & BIND_WANTRET) && x == BIND_EXEC_LOG)
            goto finally;
        }
      }
    }
  }

  if (!cnt) {
    x = BIND_NOMATCH;
    goto finally;
  }

  /* Do this before updating the preferred entries information,
   * since we don't want to change the order of stacked binds
   */
  if (result) {           /* BIND_STACKRET */
    x = result;
    goto finally;
  }

  if ((match_type & 0x07) == MATCH_MASK || (match_type & 0x07) == MATCH_CASE) {
    x = BIND_EXECUTED;
    goto finally;
  }

  /* Hit counter */
  if (htc)
    htc->hits++;

  if (cnt > 1) {
    x = BIND_AMBIGUOUS;
    goto finally;
  }

  /* Now that we have found exactly one bind, we can update the
   * preferred entries information.
   */
  if (tm_p && tm_p->next) {
    tm = tm_p->next;            /* Move mask to front of bind's mask list. */
    tm_p->next = tm->next;      /* Unlink mask from list. */
    tm->next = tl->first;       /* Re-add mask to front of list. */
    tl->first = tm;
  }

  x = DISPATCH(htc, param, mask, argv, argc);

finally:
  str = op_arena_strdup(op_event_arena(), param);

  for (varName = strtok_r(str,  " $:", &brkt);
       varName;
       varName = strtok_r(nullptr, " $:", &brkt))
  {
    Tcl_UnsetVar(interp, varName, 0);
  }

  return x;
}


/* ===================================================================
 * UNIFIED check_tcl_* HELPERS — set variables, call check_tcl_bind.
 * Tcl_SetVar works in both builds (maps to egg_setvar via lush.h).
 * =================================================================== */

/* Check for tcl-bound dcc command, return 1 if found
 * dcc: proc-name <handle> <sock> <args...>
 */
int check_tcl_dcc(const char *cmd, int idx, const char *args)
{
  struct flag_record fr = { FR_GLOBAL | FR_CHAN };
  int x;

  get_user_flagrec(dcc[idx].user, &fr, dcc[idx].u.chat->con_chan);
  op_strbuf_t s = {};
  op_strbuf_init(&s);
  op_strbuf_appendf(&s, "%ld", dcc[idx].sock);
  Tcl_SetVar(interp, "_dcc1", (char *) dcc[idx].nick, 0);
  Tcl_SetVar(interp, "_dcc2", op_strbuf_str(&s), 0);
  op_strbuf_free(&s);
  Tcl_SetVar(interp, "_dcc3", (char *) args, 0);
  x = check_tcl_bind(H_dcc, cmd, &fr, " $_dcc1 $_dcc2 $_dcc3",
                     MATCH_PARTIAL | BIND_USE_ATTR | BIND_HAS_BUILTINS);
  if (x == BIND_AMBIGUOUS) {
    dprintf(idx, "%s", MISC_AMBIGUOUS);
    return 0;
  }
  if (x == BIND_NOMATCH) {
    dprintf(idx, "%s", MISC_NOSUCHCMD);
    return 0;
  }

  /* We return 1 to leave the partyline */
  if (x == BIND_QUIT)           /* CMD_LEAVE, 'quit' */
    return 1;

  if (x == BIND_EXEC_LOG)
    putlog(LOG_CMDS, "*", "#%s# %s %s", dcc[idx].nick, cmd, args);
  return 0;
}

void check_tcl_bot(const char *nick, const char *code, const char *param)
{
  Tcl_SetVar(interp, "_bot1", (char *) nick, 0);
  Tcl_SetVar(interp, "_bot2", (char *) code, 0);
  Tcl_SetVar(interp, "_bot3", (char *) param, 0);
  check_tcl_bind(H_bot, code, 0, " $_bot1 $_bot2 $_bot3", MATCH_EXACT);
}

void check_tcl_chonof(char *hand, int sock, tcl_bind_list_t *tl)
{
  struct flag_record fr = { FR_GLOBAL | FR_CHAN };
  struct userrec *u;

  u = get_user_by_handle(userlist, hand);
  touch_laston(u, "partyline", now);
  get_user_flagrec(u, &fr, nullptr);
  Tcl_SetVar(interp, "_chonof1", (char *) hand, 0);
  op_strbuf_t s = {};
  op_strbuf_init(&s);
  op_strbuf_appendf(&s, "%d", sock);
  Tcl_SetVar(interp, "_chonof2", op_strbuf_str(&s), 0);
  op_strbuf_free(&s);
  check_tcl_bind(tl, hand, &fr, " $_chonof1 $_chonof2", MATCH_MASK |
                 BIND_USE_ATTR | BIND_STACKABLE | BIND_WANTRET);
}

void check_tcl_chatactbcst(const char *from, int chan, const char *text,
                           tcl_bind_list_t *tl)
{
  op_strbuf_t s = {};
  op_strbuf_init(&s);
  op_strbuf_appendf(&s, "%d", chan);
  Tcl_SetVar(interp, "_cab1", (char *) from, 0);
  Tcl_SetVar(interp, "_cab2", op_strbuf_str(&s), 0);
  op_strbuf_free(&s);
  Tcl_SetVar(interp, "_cab3", (char *) text, 0);
  check_tcl_bind(tl, text, 0, " $_cab1 $_cab2 $_cab3",
                 MATCH_MASK | BIND_STACKABLE);
}

void check_tcl_nkch(const char *ohand, const char *nhand)
{
  Tcl_SetVar(interp, "_nkch1", (char *) ohand, 0);
  Tcl_SetVar(interp, "_nkch2", (char *) nhand, 0);
  check_tcl_bind(H_nkch, ohand, 0, " $_nkch1 $_nkch2",
                 MATCH_MASK | BIND_STACKABLE);
}

void check_tcl_link(const char *bot, const char *via)
{
  Tcl_SetVar(interp, "_link1", (char *) bot, 0);
  Tcl_SetVar(interp, "_link2", (char *) via, 0);
  check_tcl_bind(H_link, bot, 0, " $_link1 $_link2",
                 MATCH_MASK | BIND_STACKABLE);
}

void check_tcl_disc(const char *bot)
{
  Tcl_SetVar(interp, "_disc1", (char *) bot, 0);
  check_tcl_bind(H_disc, bot, 0, " $_disc1", MATCH_MASK | BIND_STACKABLE);
}

void check_tcl_loadunld(const char *mod, tcl_bind_list_t *tl)
{
  Tcl_SetVar(interp, "_lu1", (char *) mod, 0);
  check_tcl_bind(tl, mod, 0, " $_lu1", MATCH_MASK | BIND_STACKABLE);
}

const char *check_tcl_filt(int idx, const char *text)
{
  int x;
  struct flag_record fr = { FR_GLOBAL | FR_CHAN };

  op_strbuf_t s = {};
  op_strbuf_init(&s);
  op_strbuf_appendf(&s, "%ld", dcc[idx].sock);
  get_user_flagrec(dcc[idx].user, &fr, dcc[idx].u.chat->con_chan);
  Tcl_SetVar(interp, "_filt1", op_strbuf_str(&s), 0);
  op_strbuf_free(&s);
  Tcl_SetVar(interp, "_filt2", (char *) text, 0);
  x = check_tcl_bind(H_filt, text, &fr, " $_filt1 $_filt2",
                     MATCH_MASK | BIND_USE_ATTR | BIND_STACKABLE |
                     BIND_WANTRET | BIND_ALTER_ARGS);
  if ((x == BIND_EXECUTED || x == BIND_EXEC_LOG) && interp) {
    if (tcl_resultempty())
      return "";
    else
      return tcl_resultstring();
  }
  return text;
}

int check_tcl_note(const char *from, const char *to, const char *text)
{
  int x;

  Tcl_SetVar(interp, "_note1", (char *) from, 0);
  Tcl_SetVar(interp, "_note2", (char *) to, 0);
  Tcl_SetVar(interp, "_note3", (char *) text, 0);

  x = check_tcl_bind(H_note, to, 0, " $_note1 $_note2 $_note3",
                     MATCH_MASK | BIND_STACKABLE | BIND_WANTRET);

  return (x == BIND_EXEC_LOG);
}

void check_tcl_listen(const char *cmd, int idx)
{
  op_strbuf_t s = {};
  op_strbuf_init(&s);
  op_strbuf_appendf(&s, "%d", idx);

  Tcl_SetVar(interp, "_listen1", (char *) cmd, 0);
  Tcl_SetVar(interp, "_listen2", op_strbuf_str(&s), 0);
  check_tcl_bind(find_bind_table("listen"), cmd, 0,
                 " $_listen1 $_listen2", MATCH_EXACT | BIND_STACKABLE);
  op_strbuf_free(&s);
}

void check_tcl_chjn(const char *bot, const char *nick, int chan,
                    const char type, int sock, const char *host)
{
  struct flag_record fr = { FR_GLOBAL };
  char t[2];

  t[0] = type;
  t[1] = 0;
  switch (type) {
  case '*':
    fr.global = USER_OWNER;
    break;
  case '+':
    fr.global = USER_MASTER;
    break;
  case '@':
    fr.global = USER_OP;
    break;
  case '^':
    fr.global = USER_HALFOP;
    break;
  case '%':
    fr.global = USER_BOTMAST;
  }
  op_strbuf_t s = {}, u = {};
  op_strbuf_appendf(&s, "%d", chan);
  op_strbuf_appendf(&u, "%d", sock);
  Tcl_SetVar(interp, "_chjn1", (char *) bot, 0);
  Tcl_SetVar(interp, "_chjn2", (char *) nick, 0);
  Tcl_SetVar(interp, "_chjn3", op_strbuf_str(&s), 0);
  Tcl_SetVar(interp, "_chjn4", (char *) t, 0);
  Tcl_SetVar(interp, "_chjn5", op_strbuf_str(&u), 0);
  Tcl_SetVar(interp, "_chjn6", (char *) host, 0);
  check_tcl_bind(H_chjn, op_strbuf_str(&s), &fr,
                 " $_chjn1 $_chjn2 $_chjn3 $_chjn4 $_chjn5 $_chjn6",
                 MATCH_MASK | BIND_STACKABLE);
  op_strbuf_free(&s);
  op_strbuf_free(&u);
}

void check_tcl_chpt(const char *bot, const char *hand, int sock, int chan)
{
  op_strbuf_t u = {}, v = {};
  op_strbuf_appendf(&u, "%d", sock);
  op_strbuf_appendf(&v, "%d", chan);
  Tcl_SetVar(interp, "_chpt1", (char *) bot, 0);
  Tcl_SetVar(interp, "_chpt2", (char *) hand, 0);
  Tcl_SetVar(interp, "_chpt3", op_strbuf_str(&u), 0);
  Tcl_SetVar(interp, "_chpt4", op_strbuf_str(&v), 0);
  check_tcl_bind(H_chpt, op_strbuf_str(&v), 0, " $_chpt1 $_chpt2 $_chpt3 $_chpt4",
                 MATCH_MASK | BIND_STACKABLE);
  op_strbuf_free(&u);
  op_strbuf_free(&v);
}

void check_tcl_away(const char *bot, int idx, const char *msg)
{
  op_strbuf_t u = {};
  op_strbuf_init(&u);
  op_strbuf_appendf(&u, "%d", idx);
  Tcl_SetVar(interp, "_away1", (char *) bot, 0);
  Tcl_SetVar(interp, "_away2", op_strbuf_str(&u), 0);
  op_strbuf_free(&u);
  Tcl_SetVar(interp, "_away3", msg ? (char *) msg : "", 0);
  check_tcl_bind(H_away, bot, 0, " $_away1 $_away2 $_away3",
                 MATCH_MASK | BIND_STACKABLE);
}

void check_tcl_time_and_cron(struct tm *tm)
{
  op_strbuf_t y = {};
  op_strbuf_init(&y);

  op_strbuf_appendf(&y, "%02d", tm->tm_min);
  Tcl_SetVar(interp, "_time1", op_strbuf_str(&y), 0);
  Tcl_SetVar(interp, "_cron1", op_strbuf_str(&y), 0);
  op_strbuf_clear(&y);
  op_strbuf_appendf(&y, "%02d", tm->tm_hour);
  Tcl_SetVar(interp, "_time2", op_strbuf_str(&y), 0);
  Tcl_SetVar(interp, "_cron2", op_strbuf_str(&y), 0);
  op_strbuf_clear(&y);
  op_strbuf_appendf(&y, "%02d", tm->tm_mday);
  Tcl_SetVar(interp, "_time3", op_strbuf_str(&y), 0);
  Tcl_SetVar(interp, "_cron3", op_strbuf_str(&y), 0);
  op_strbuf_clear(&y);
  op_strbuf_appendf(&y, "%02d", tm->tm_mon);
  Tcl_SetVar(interp, "_time4", op_strbuf_str(&y), 0);
  op_strbuf_clear(&y);
  op_strbuf_appendf(&y, "%04d", tm->tm_year + 1900);
  Tcl_SetVar(interp, "_time5", op_strbuf_str(&y), 0);
  op_strbuf_clear(&y);
  op_strbuf_appendf(&y, "%02d %02d %02d %02d %04d", tm->tm_min, tm->tm_hour,
               tm->tm_mday, tm->tm_mon, tm->tm_year + 1900);
  check_tcl_bind(H_time, op_strbuf_str(&y), 0,
                 " $_time1 $_time2 $_time3 $_time4 $_time5",
                 MATCH_MASK | BIND_STACKABLE);

  op_strbuf_clear(&y);
  op_strbuf_appendf(&y, "%02d", tm->tm_mon + 1);
  Tcl_SetVar(interp, "_cron4", op_strbuf_str(&y), 0);
  op_strbuf_clear(&y);
  op_strbuf_appendf(&y, "%02d", tm->tm_wday);
  Tcl_SetVar(interp, "_cron5", op_strbuf_str(&y), 0);
  op_strbuf_clear(&y);
  op_strbuf_appendf(&y, "%02d %02d %02d %02d %02d", tm->tm_min, tm->tm_hour,
               tm->tm_mday, tm->tm_mon + 1, tm->tm_wday);
  check_tcl_bind(H_cron, op_strbuf_str(&y), 0,
                 " $_cron1 $_cron2 $_cron3 $_cron4 $_cron5",
                 MATCH_CRON | BIND_STACKABLE);
  op_strbuf_free(&y);
}

void check_tcl_event(const char *event)
{
  Tcl_SetVar(interp, "_event1", (char *) event, TCL_GLOBAL_ONLY);
  check_tcl_bind(H_event, event, 0, " $::_event1",
                 MATCH_EXACT | BIND_STACKABLE);
}

void check_tcl_event_arg(const char *event, const char *arg)
{
    Tcl_SetVar(interp, "_event1", (char *) event, TCL_GLOBAL_ONLY);
    Tcl_SetVar(interp, "_event2", (char *) arg, TCL_GLOBAL_ONLY);
    check_tcl_bind(H_event, event, 0, " $::_event1 $::_event2",
                   MATCH_EXACT | BIND_STACKABLE);
}

int check_tcl_signal(const char *event)
{
  int x;

  Tcl_SetVar(interp, "_event1", (char *) event, TCL_GLOBAL_ONLY);
  x = check_tcl_bind(H_event, event, 0, " $::_event1",
                 MATCH_EXACT | BIND_STACKABLE | BIND_STACKRET);
  return (x == BIND_EXEC_LOG);
}

void check_tcl_die(const char *reason)
{
  Tcl_SetVar(interp, "_die1", reason, 0);
  check_tcl_bind(H_die, reason, 0, " $_die1", MATCH_MASK | BIND_STACKABLE);
}

void check_tcl_log(int lv, char *chan, char *msg)
{
  [[maybe_unused]] Tcl_Obj* prev_result;

  /* We have to store the old result, as check_tcl_bind may override it.
   * In no-Tcl builds the Tcl_*RefCount / Tcl_*ObjResult calls are no-ops. */
  prev_result = Tcl_GetObjResult(interp);
  Tcl_IncrRefCount(prev_result);

  op_strbuf_t mask = {};
  op_strbuf_init(&mask);
  op_strbuf_appendf(&mask, "%s %s", chan, msg);
  Tcl_SetVar(interp, "_log1", masktype(lv), TCL_GLOBAL_ONLY);
  Tcl_SetVar(interp, "_log2", chan, TCL_GLOBAL_ONLY);
  Tcl_SetVar(interp, "_log3", msg, TCL_GLOBAL_ONLY);
  check_tcl_bind(H_log, op_strbuf_str(&mask), 0, " $::_log1 $::_log2 $::_log3",
                 MATCH_MASK | BIND_STACKABLE);
  op_strbuf_free(&mask);

  Tcl_SetObjResult(interp, prev_result);
  Tcl_DecrRefCount(prev_result);
}

#ifdef TLS
int check_tcl_tls(int sock)
{
  int x;

  op_strbuf_t s = {};
  op_strbuf_init(&s);
  op_strbuf_appendf(&s, "%d", sock);
  Tcl_SetVar(interp, "_tls", op_strbuf_str(&s), 0);
  x = check_tcl_bind(H_tls, op_strbuf_str(&s), 0, " $_tls", MATCH_MASK | BIND_STACKABLE |
                     BIND_WANTRET);
  op_strbuf_free(&s);
  return (x == BIND_EXEC_LOG);
}
#endif


/* ===================================================================
 * tell_binds — list current bindings (unified, uses the richer
 * formatting from the Tcl build).
 * =================================================================== */

void tell_binds(int idx, char *par)
{
  tcl_bind_list_t *tl, *tl_kind;
  tcl_bind_mask_t *tm;
  int fnd = 0, showall = 0, patmatc = 0, maxname = 0;
  int ok = 0, showpy = 0, showtcl = 0;
  tcl_cmd_t *tc;
  char *name, *proc, *s, flg[100];

  if (par[0])
    name = newsplit(&par);
  else
    name = nullptr;
  if (par[0])
    s = newsplit(&par);
  else
    s = nullptr;

  if (name)
    tl_kind = find_bind_table(name);
  else
    tl_kind = nullptr;

  if ((name && name[0] && !strcasecmp(name, "all")) ||
      (s && s[0] && !strcasecmp(s, "all")))
    showall = 1;
  if ((name && name[0] && !strcasecmp(name, "tcl")) ||
      (s && s[0] && !strcasecmp(s, "all")))
    showtcl = 1;
  if ((name && name[0] && !strcasecmp(name, "python")) ||
      (s && s[0] && !strcasecmp(s, "all")))
    showpy = 1;
  if (tl_kind == nullptr && !showpy && !showtcl && name && name[0] && strcasecmp(name, "all"))
    patmatc = 1;

  for (tl = tl_kind ? tl_kind : bind_table_list; tl;
       tl = tl_kind ? 0 : tl->next) {
    if (tl->flags & HT_DELETED)
      continue;
    for (tm = tl->first; tm; tm = tm->next) {
      if (tm->flags & TBM_DELETED)
        continue;
      for (tc = tm->first; tc; tc = tc->next) {
        if (tc->attributes & TC_DELETED)
          continue;
        if (strlen(tl->name) > maxname) {
          maxname = strlen(tl->name);
        }
      }
    }
  }
  dprintf(idx, "%s", MISC_CMDBINDS);
  dprintf(idx, "  %*s FLAGS    COMMAND              HITS BINDING (TCL)\n",
        maxname, "TYPE");
  for (tl = tl_kind ? tl_kind : bind_table_list; tl;
       tl = tl_kind ? 0 : tl->next) {
    if (tl->flags & HT_DELETED)
      continue;
    for (tm = tl->first; tm; tm = tm->next) {
      if (tm->flags & TBM_DELETED)
        continue;
      for (tc = tm->first; tc; tc = tc->next) {
        if (tc->attributes & TC_DELETED)
          continue;
        proc = tc->func_name;
        build_flags(flg, &(tc->flags), nullptr);
        ok = 0;
        if (showall) {
          ok = 1;
        } else if (patmatc || showpy || showtcl) {
          if ((patmatc == 1) && (proc[0] != '*')) {
            if (wild_match_per(name, tl->name) ||
                wild_match_per(name, tm->mask) ||
                wild_match_per(name, tc->func_name)) {
              ok = 1;
            }
          } else if (showpy && !(strncasecmp(tc->func_name, "*python:", strlen("*python:")))) {
            ok = 1;
          } else if (showtcl && (strncasecmp(tc->func_name, "*", strlen("*")))) {
            ok = 1;
          }
        } else if (proc[0] != '*') {
          ok = 1;
        }
        if (ok) {
          dprintf(idx, "  %*s %-8s %-20s %4d %s\n", maxname, tl->name, flg,
                  tm->mask, tc->hits, tc->func_name);
          fnd = 1;
        }
      }
    }
  }
  if (!fnd) {
    if (patmatc)
      dprintf(idx, "No command bindings found that match %s\n", name);
    else if (tl_kind)
      dprintf(idx, "No command bindings for type: %s.\n", name);
    else
      dprintf(idx, "No command bindings exist.\n");
  }
}


/* ===================================================================
 * init_bind / kill_bind — slab heaps and bind table creation.
 * Shared heap/htab init with #ifdef for table-specific setup.
 * =================================================================== */

void init_bind(void)
{
  /* Create slab heaps for the three fixed-size tclhash node types. */
  tcl_cmd_heap       = op_bh_create(sizeof(tcl_cmd_t),       128, "tcl_cmd");
  tcl_bind_mask_heap = op_bh_create(sizeof(tcl_bind_mask_t),  64, "tcl_bind_mask");
  tcl_bind_list_heap = op_bh_create(sizeof(tcl_bind_list_t),  32, "tcl_bind_list");

  bind_table_list = nullptr;
  bind_table_ht   = op_htab_create_istr("bind_tables", 32);

  /* Core bind tables — created once, Tcl builds attach validators after. */
  H_dcc   = add_bind_table("dcc",   0,            nullptr);
  H_filt  = add_bind_table("filt",  HT_STACKABLE, nullptr);
  H_unld  = add_bind_table("unld",  HT_STACKABLE, nullptr);
  H_load  = add_bind_table("load",  HT_STACKABLE, nullptr);
  H_link  = add_bind_table("link",  HT_STACKABLE, nullptr);
  H_disc  = add_bind_table("disc",  HT_STACKABLE, nullptr);
  H_nkch  = add_bind_table("nkch",  HT_STACKABLE, nullptr);
  H_away  = add_bind_table("away",  HT_STACKABLE, nullptr);
  H_chat  = add_bind_table("chat",  HT_STACKABLE, nullptr);
  H_act   = add_bind_table("act",   HT_STACKABLE, nullptr);
  H_bcst  = add_bind_table("bcst",  HT_STACKABLE, nullptr);
  H_chon  = add_bind_table("chon",  HT_STACKABLE, nullptr);
  H_chof  = add_bind_table("chof",  HT_STACKABLE, nullptr);
  H_chpt  = add_bind_table("chpt",  HT_STACKABLE, nullptr);
  H_chjn  = add_bind_table("chjn",  HT_STACKABLE, nullptr);
  H_bot   = add_bind_table("bot",   0,            nullptr);
  H_event = add_bind_table("evnt",  HT_STACKABLE, nullptr);
  H_log   = add_bind_table("log",   HT_STACKABLE, nullptr);
  H_die   = add_bind_table("die",   HT_STACKABLE, nullptr);
  H_time  = add_bind_table("time",  HT_STACKABLE, nullptr);
  H_cron  = add_bind_table("cron",  HT_STACKABLE, nullptr);
  H_note  = add_bind_table("note",  0,            nullptr);
#ifdef TLS
  H_tls   = add_bind_table("tls",   HT_STACKABLE, nullptr);
#endif

#ifdef HAVE_TCL
  add_cd_tcl_cmds(cd_cmd_table);
  H_dcc->func   = builtin_dcc;
  H_filt->func  = builtin_idxchar;
  H_unld->func  = builtin_char;
  H_load->func  = builtin_char;
  H_link->func  = builtin_2char;
  H_disc->func  = builtin_char;
  H_nkch->func  = builtin_2char;
  H_away->func  = builtin_chat;
  H_chat->func  = builtin_chat;
  H_act->func   = builtin_chat;
  H_bcst->func  = builtin_chat;
  H_chon->func  = builtin_charidx;
  H_chof->func  = builtin_charidx;
  H_chpt->func  = builtin_chpt;
  H_chjn->func  = builtin_chjn;
  H_bot->func   = builtin_3char;
  H_event->func = builtin_evnt;
  H_log->func   = builtin_log;
  H_die->func   = builtin_char;
  H_time->func  = builtin_5int;
  H_cron->func  = builtin_cron;
  H_note->func  = builtin_3char;
#ifdef TLS
  H_tls->func   = builtin_idx;
#endif
#else
  H_dcc->func   = (IntFunc) native_dcc_call;
#endif /* HAVE_TCL */

  /* Module bind tables — pre-created so find_bind_table() succeeds before
   * modules are loaded and register their own tables. */
  add_bind_table("msg",      0,            nullptr);
  add_bind_table("msgm",     HT_STACKABLE, nullptr);
  add_bind_table("pub",      0,            nullptr);
  add_bind_table("pubm",     HT_STACKABLE, nullptr);
  add_bind_table("join",     HT_STACKABLE, nullptr);
  add_bind_table("part",     HT_STACKABLE, nullptr);
  add_bind_table("nick",     HT_STACKABLE, nullptr);
  add_bind_table("kick",     HT_STACKABLE, nullptr);
  add_bind_table("mode",     HT_STACKABLE, nullptr);
  add_bind_table("sign",     HT_STACKABLE, nullptr);
  add_bind_table("topc",     HT_STACKABLE, nullptr);
  add_bind_table("notc",     HT_STACKABLE, nullptr);
  add_bind_table("raw",      HT_STACKABLE, nullptr);
  add_bind_table("rawt",     HT_STACKABLE, nullptr);
  add_bind_table("ctcp",     HT_STACKABLE, nullptr);
  add_bind_table("ctcr",     HT_STACKABLE, nullptr);
  add_bind_table("flud",     HT_STACKABLE, nullptr);
  add_bind_table("wall",     HT_STACKABLE, nullptr);
  add_bind_table("invt",     HT_STACKABLE, nullptr);
  add_bind_table("need",     HT_STACKABLE, nullptr);
  add_bind_table("splt",     HT_STACKABLE, nullptr);
  add_bind_table("rejn",     HT_STACKABLE, nullptr);
  add_bind_table("ircaway",  HT_STACKABLE, nullptr);
  add_bind_table("account",  HT_STACKABLE, nullptr);
  add_bind_table("chghost",  HT_STACKABLE, nullptr);
  add_bind_table("isupport", HT_STACKABLE, nullptr);
  add_bind_table("out",      HT_STACKABLE, nullptr);
  add_bind_table("monitor",  HT_STACKABLE, nullptr);
  add_bind_table("stdreply", HT_STACKABLE, nullptr);
  add_bind_table("rcvd",     HT_STACKABLE, nullptr);
  add_bind_table("sent",     HT_STACKABLE, nullptr);
  add_bind_table("lost",     HT_STACKABLE, nullptr);
  add_bind_table("tout",     HT_STACKABLE, nullptr);
  add_bind_table("fil",      0,            nullptr);
  add_bind_table("chanset",  HT_STACKABLE, nullptr);
  add_bind_table("ccht",     HT_STACKABLE, nullptr);
  add_bind_table("cmsg",     HT_STACKABLE, nullptr);
  add_bind_table("htgt",     HT_STACKABLE, nullptr);
  add_bind_table("wspr",     HT_STACKABLE, nullptr);
  add_bind_table("wspm",     HT_STACKABLE, nullptr);
  add_bind_table("rmst",     HT_STACKABLE, nullptr);
  add_bind_table("usst",     HT_STACKABLE, nullptr);
  add_bind_table("usrntc",   HT_STACKABLE, nullptr);
  add_bind_table("listen",   HT_STACKABLE, nullptr);
  add_builtins(H_dcc, C_dcc);
}

void kill_bind(void)
{
  tcl_bind_list_t *tl, *tl_next;

  rem_builtins(H_dcc, C_dcc);
  for (tl = bind_table_list; tl; tl = tl_next) {
    tl_next = tl->next;

    if (!(tl->flags |= HT_DELETED))
      putlog(LOG_DEBUG, "*", "De-Allocated bind table %s", tl->name);
    tcl_bind_list_delete(tl);
  }
  H_log = nullptr;
  bind_table_list = nullptr;
  if (bind_table_ht) {
    op_htab_destroy(bind_table_ht, nullptr, nullptr);
    bind_table_ht = nullptr;
  }

  /* Destroy slab heaps (all nodes already freed above). */
  op_bh_destroy(tcl_cmd_heap);       tcl_cmd_heap       = nullptr;
  op_bh_destroy(tcl_bind_mask_heap); tcl_bind_mask_heap = nullptr;
  op_bh_destroy(tcl_bind_list_heap); tcl_bind_list_heap = nullptr;
}
