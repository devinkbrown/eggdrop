/*
 * tclchan.c -- part of channels.mod
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

/* Tcl command handlers — in non-Tcl builds these compile (STDVAR, BADARGS,
 * and all Tcl_* calls are stubbed by lush.h) but are never registered via
 * add_tcl_commands (which is itself a no-op in non-Tcl builds).
 */

static int tcl_killban STDVAR
{
  struct chanset_t *chan;

  BADARGS(2, 2, " ban");

  if (u_delban(NULL, argv[1], 1) > 0) {
    for (chan = chanset; chan; chan = chan->next)
      add_mode(chan, '-', 'b', argv[1]);
    Tcl_AppendResult(irp, "1", NULL);
  } else
    Tcl_AppendResult(irp, "0", NULL);
  return TCL_OK;
}

static int tcl_killchanban STDVAR
{
  struct chanset_t *chan;

  BADARGS(3, 3, " channel ban");

  chan = findchan_by_dname(argv[1]);
  if (!chan) {
    Tcl_AppendResult(irp, "invalid channel: ", argv[1], NULL);
    return TCL_ERROR;
  }
  if (u_delban(chan, argv[2], 1) > 0) {
    add_mode(chan, '-', 'b', argv[2]);
    Tcl_AppendResult(irp, "1", NULL);
  } else
    Tcl_AppendResult(irp, "0", NULL);
  return TCL_OK;
}

static int tcl_killexempt STDVAR
{
  struct chanset_t *chan;

  BADARGS(2, 2, " exempt");

  if (u_delexempt(NULL, argv[1], 1) > 0) {
    for (chan = chanset; chan; chan = chan->next)
      add_mode(chan, '-', 'e', argv[1]);
    Tcl_AppendResult(irp, "1", NULL);
  } else
    Tcl_AppendResult(irp, "0", NULL);
  return TCL_OK;
}

static int tcl_killchanexempt STDVAR
{
  struct chanset_t *chan;

  BADARGS(3, 3, " channel exempt");

  chan = findchan_by_dname(argv[1]);
  if (!chan) {
    Tcl_AppendResult(irp, "invalid channel: ", argv[1], NULL);
    return TCL_ERROR;
  }
  if (u_delexempt(chan, argv[2], 1) > 0) {
    add_mode(chan, '-', 'e', argv[2]);
    Tcl_AppendResult(irp, "1", NULL);
  } else
    Tcl_AppendResult(irp, "0", NULL);
  return TCL_OK;
}

static int tcl_killinvite STDVAR
{
  struct chanset_t *chan;

  BADARGS(2, 2, " invite");

  if (u_delinvite(NULL, argv[1], 1) > 0) {
    for (chan = chanset; chan; chan = chan->next)
      add_mode(chan, '-', 'I', argv[1]);
    Tcl_AppendResult(irp, "1", NULL);
  } else
    Tcl_AppendResult(irp, "0", NULL);
  return TCL_OK;
}

static int tcl_killchaninvite STDVAR
{
  struct chanset_t *chan;

  BADARGS(3, 3, " channel invite");

  chan = findchan_by_dname(argv[1]);
  if (!chan) {
    Tcl_AppendResult(irp, "invalid channel: ", argv[1], NULL);
    return TCL_ERROR;
  }
  if (u_delinvite(chan, argv[2], 1) > 0) {
    add_mode(chan, '-', 'I', argv[2]);
    Tcl_AppendResult(irp, "1", NULL);
  } else
    Tcl_AppendResult(irp, "0", NULL);
  return TCL_OK;
}

static int tcl_stick STDVAR
{
  struct chanset_t *chan;
  int ok = 0;

  BADARGS(2, 3, " ban ?channel?");

  if (argc == 3) {
    chan = findchan_by_dname(argv[2]);
    if (!chan) {
      Tcl_AppendResult(irp, "invalid channel: ", argv[2], NULL);
      return TCL_ERROR;
    }
    if (u_setsticky_ban(chan, argv[1], !strncmp(argv[0], "un", 2) ? 0 : 1))
      ok = 1;
  }
  if (!ok && u_setsticky_ban(NULL, argv[1], !strncmp(argv[0], "un", 2) ?
      0 : 1))
    ok = 1;
  if (ok)
    Tcl_AppendResult(irp, "1", NULL);
  else
    Tcl_AppendResult(irp, "0", NULL);
  return TCL_OK;
}

static int tcl_stickinvite STDVAR
{
  struct chanset_t *chan;
  int ok = 0;

  BADARGS(2, 3, " invite ?channel?");

  if (argc == 3) {
    chan = findchan_by_dname(argv[2]);
    if (!chan) {
      Tcl_AppendResult(irp, "invalid channel: ", argv[2], NULL);
      return TCL_ERROR;
    }
    if (u_setsticky_invite(chan, argv[1], !strncmp(argv[0], "un", 2) ? 0 : 1))
      ok = 1;
  }
  if (!ok && u_setsticky_invite(NULL, argv[1], !strncmp(argv[0], "un", 2) ?
      0 : 1))
    ok = 1;
  if (ok)
    Tcl_AppendResult(irp, "1", NULL);
  else
    Tcl_AppendResult(irp, "0", NULL);
  return TCL_OK;
}

static int tcl_stickexempt STDVAR
{
  struct chanset_t *chan;
  int ok = 0;

  BADARGS(2, 3, " exempt ?channel?");

  if (argc == 3) {
    chan = findchan_by_dname(argv[2]);
    if (!chan) {
      Tcl_AppendResult(irp, "invalid channel: ", argv[2], NULL);
      return TCL_ERROR;
    }
    if (u_setsticky_exempt(chan, argv[1], !strncmp(argv[0], "un", 2) ? 0 : 1))
      ok = 1;
  }
  if (!ok && u_setsticky_exempt(NULL, argv[1], !strncmp(argv[0], "un", 2) ?
      0 : 1))
    ok = 1;
  if (ok)
    Tcl_AppendResult(irp, "1", NULL);
  else
    Tcl_AppendResult(irp, "0", NULL);
  return TCL_OK;
}

static int tcl_isban STDVAR
{
  struct chanset_t *chan;
  int chanarg = 1, ok = 0;

  BADARGS(2, 4, " ban ?channel? ?-channel?");

  if (argc >= 3) {
    chan = findchan_by_dname(argv[2]);
    if (!chan) {
      Tcl_AppendResult(irp, "invalid channel: ", argv[2], NULL);
      return TCL_ERROR;
    }
    if (u_equals_mask(chan->bans, chan->bans_ht, argv[1]))
      ok = 1;
  }
  if (argc == 4) {
    if (!strcasecmp(argv[3], "-channel")) {
      chanarg = 0;
    } else {
      Tcl_AppendResult(irp, "invalid flag", NULL);
      return TCL_ERROR;
    }
  }
  if (u_equals_mask(global_bans, global_bans_ht, argv[1]) && chanarg)
    ok = 1;
  if (ok)
    Tcl_AppendResult(irp, "1", NULL);
  else
    Tcl_AppendResult(irp, "0", NULL);
  return TCL_OK;
}

static int tcl_isexempt STDVAR
{
  struct chanset_t *chan;
  int chanarg = 1, ok = 0;

  BADARGS(2, 4, " exempt ?channel? ?-channel?");

  if (argc >= 3) {
    chan = findchan_by_dname(argv[2]);
    if (!chan) {
      Tcl_AppendResult(irp, "invalid channel: ", argv[2], NULL);
      return TCL_ERROR;
    }
    if (u_equals_mask(chan->exempts, chan->exempts_ht, argv[1]))
      ok = 1;
  }
  if (argc == 4) {
    if (!strcasecmp(argv[3], "-channel")) {
      chanarg = 0;
    } else {
      Tcl_AppendResult(irp, "invalid flag", NULL);
      return TCL_ERROR;
    }
  }
  if (u_equals_mask(global_exempts, global_exempts_ht, argv[1]) && chanarg)
    ok = 1;
  if (ok)
    Tcl_AppendResult(irp, "1", NULL);
  else
    Tcl_AppendResult(irp, "0", NULL);
  return TCL_OK;
}

static int tcl_isinvite STDVAR
{
  struct chanset_t *chan;
  int chanarg = 1, ok = 0;

  BADARGS(2, 4, " invite ?channel? ?-channel?");

  if (argc >= 3) {
    chan = findchan_by_dname(argv[2]);
    if (!chan) {
      Tcl_AppendResult(irp, "invalid channel: ", argv[2], NULL);
      return TCL_ERROR;
    }
    if (u_equals_mask(chan->invites, chan->invites_ht, argv[1]))
      ok = 1;
  }
  if (argc == 4) {
    if (!strcasecmp(argv[3], "-channel")) {
      chanarg = 0;
    } else {
      Tcl_AppendResult(irp, "invalid flag", NULL);
      return TCL_ERROR;
    }
  }
  if (u_equals_mask(global_invites, global_invites_ht, argv[1]) && chanarg)
    ok = 1;
  if (ok)
    Tcl_AppendResult(irp, "1", NULL);
  else
    Tcl_AppendResult(irp, "0", NULL);
  return TCL_OK;
}


static int tcl_isbansticky STDVAR
{
  struct chanset_t *chan;
  int chanarg = 1, ok = 0;

  BADARGS(2, 4, " ban ?channel? ?-channel?");

  if (argc >= 3) {
    chan = findchan_by_dname(argv[2]);
    if (!chan) {
      Tcl_AppendResult(irp, "invalid channel: ", argv[2], NULL);
      return TCL_ERROR;
    }
    if (u_sticky_mask(chan->bans, chan->bans_ht, argv[1]))
      ok = 1;
  }
  if (argc == 4) {
    if (!strcasecmp(argv[3], "-channel")) {
      chanarg = 0;
    } else {
      Tcl_AppendResult(irp, "invalid flag", NULL);
      return TCL_ERROR;
    }
  }
  if (u_sticky_mask(global_bans, global_bans_ht, argv[1]) && chanarg)
    ok = 1;
  if (ok)
    Tcl_AppendResult(irp, "1", NULL);
  else
    Tcl_AppendResult(irp, "0", NULL);
  return TCL_OK;
}

static int tcl_isexemptsticky STDVAR
{
  struct chanset_t *chan;
  int chanarg = 1, ok = 0;

  BADARGS(2, 4, " exempt ?channel? ?-channel?");

  if (argc >= 3) {
    chan = findchan_by_dname(argv[2]);
    if (!chan) {
      Tcl_AppendResult(irp, "invalid channel: ", argv[2], NULL);
      return TCL_ERROR;
    }
    if (u_sticky_mask(chan->exempts, chan->exempts_ht, argv[1]))
      ok = 1;
  }
  if (argc == 4) {
    if (!strcasecmp(argv[3], "-channel")) {
      chanarg = 0;
    } else {
      Tcl_AppendResult(irp, "invalid flag", NULL);
      return TCL_ERROR;
    }
  }
  if (u_sticky_mask(global_exempts, global_exempts_ht, argv[1]) && chanarg)
    ok = 1;
  if (ok)
    Tcl_AppendResult(irp, "1", NULL);
  else
    Tcl_AppendResult(irp, "0", NULL);
  return TCL_OK;
}

static int tcl_isinvitesticky STDVAR
{
  struct chanset_t *chan;
  int chanarg = 1, ok = 0;

  BADARGS(2, 4, " invite ?channel? ?-channel?");

  if (argc >= 3) {
    chan = findchan_by_dname(argv[2]);
    if (!chan) {
      Tcl_AppendResult(irp, "invalid channel: ", argv[2], NULL);
      return TCL_ERROR;
    }
    if (u_sticky_mask(chan->invites, chan->invites_ht, argv[1]))
      ok = 1;
  }
  if (argc == 4) {
    if (!strcasecmp(argv[3], "-channel")) {
      chanarg = 0;
    } else {
      Tcl_AppendResult(irp, "invalid flag", NULL);
      return TCL_ERROR;
    }
  }
  if (u_sticky_mask(global_invites, global_invites_ht, argv[1]) && chanarg)
    ok = 1;
  if (ok)
    Tcl_AppendResult(irp, "1", NULL);
  else
    Tcl_AppendResult(irp, "0", NULL);
  return TCL_OK;
}

static int tcl_ispermban STDVAR
{
  struct chanset_t *chan;
  int chanarg = 1, ok = 0;

  BADARGS(2, 4, " ban ?channel? ?-channel?");

  if (argc >= 3) {
    chan = findchan_by_dname(argv[2]);
    if (chan == NULL) {
      Tcl_AppendResult(irp, "invalid channel: ", argv[2], NULL);
      return TCL_ERROR;
    }
    if (u_equals_mask(chan->bans, chan->bans_ht, argv[1]) == 2)
      ok = 1;
  }
  if (argc == 4) {
    if (!strcasecmp(argv[3], "-channel")) {
      chanarg = 0;
    } else {
      Tcl_AppendResult(irp, "invalid flag", NULL);
      return TCL_ERROR;
    }
  }
  if ((u_equals_mask(global_bans, global_bans_ht, argv[1]) == 2) && chanarg)
    ok = 1;
  if (ok)
    Tcl_AppendResult(irp, "1", NULL);
  else
    Tcl_AppendResult(irp, "0", NULL);
  return TCL_OK;
}

static int tcl_ispermexempt STDVAR
{
  struct chanset_t *chan;
  int chanarg = 1, ok = 0;

  BADARGS(2, 4, " exempt ?channel? ?-channel?");

  if (argc >= 3) {
    chan = findchan_by_dname(argv[2]);
    if (chan == NULL) {
      Tcl_AppendResult(irp, "invalid channel: ", argv[2], NULL);
      return TCL_ERROR;
    }
    if (u_equals_mask(chan->exempts, chan->exempts_ht, argv[1]) == 2)
      ok = 1;
  }
  if (argc == 4) {
    if (!strcasecmp(argv[3], "-channel")) {
      chanarg = 0;
    } else {
      Tcl_AppendResult(irp, "invalid flag", NULL);
      return TCL_ERROR;
    }
  }
  if ((u_equals_mask(global_exempts, global_exempts_ht, argv[1]) == 2) && chanarg)
    ok = 1;
  if (ok)
    Tcl_AppendResult(irp, "1", NULL);
  else
    Tcl_AppendResult(irp, "0", NULL);
  return TCL_OK;
}

static int tcl_isperminvite STDVAR
{
  struct chanset_t *chan;
  int chanarg = 1, ok = 0;

  BADARGS(2, 4, " invite ?channel? ?-channel?");

  if (argc >= 3) {
    chan = findchan_by_dname(argv[2]);
    if (chan == NULL) {
      Tcl_AppendResult(irp, "invalid channel: ", argv[2], NULL);
      return TCL_ERROR;
    }
    if (u_equals_mask(chan->invites, chan->invites_ht, argv[1]) == 2)
      ok = 1;
  }
  if (argc == 4) {
    if (!strcasecmp(argv[3], "-channel")) {
      chanarg = 0;
    } else {
      Tcl_AppendResult(irp, "invalid flag", NULL);
      return TCL_ERROR;
    }
  }
  if ((u_equals_mask(global_invites, global_invites_ht, argv[1]) == 2) && chanarg)
    ok = 1;
  if (ok)
    Tcl_AppendResult(irp, "1", NULL);
  else
    Tcl_AppendResult(irp, "0", NULL);
  return TCL_OK;
}

static int tcl_matchban STDVAR
{
  struct chanset_t *chan;
  int chanarg = 1, ok = 0;

  BADARGS(2, 4, " user!nick@host ?channel? ?-channel?");

  if (argc >= 3) {
    chan = findchan_by_dname(argv[2]);
    if (chan == NULL) {
      Tcl_AppendResult(irp, "invalid channel: ", argv[2], NULL);
      return TCL_ERROR;
    }
    if (u_match_mask_trie(chan->bans, chan->ban_ip_trie, argv[1]))
      ok = 1;
  }
  if (argc == 4) {
    if (!strcasecmp(argv[3], "-channel")) {
      chanarg = 0;
    } else {
      Tcl_AppendResult(irp, "invalid flag", NULL);
      return TCL_ERROR;
    }
  }
  if ((u_match_mask(global_bans, argv[1])) && chanarg)
    ok = 1;
  if (ok)
    Tcl_AppendResult(irp, "1", NULL);
  else
    Tcl_AppendResult(irp, "0", NULL);
  return TCL_OK;
}

static int tcl_matchexempt STDVAR
{
  struct chanset_t *chan;
  int chanarg = 1, ok = 0;

  BADARGS(2, 4, " user!nick@host ?channel? ?-channel?");

  if (argc >= 3) {
    chan = findchan_by_dname(argv[2]);
    if (chan == NULL) {
      Tcl_AppendResult(irp, "invalid channel: ", argv[2], NULL);
      return TCL_ERROR;
    }
    if (u_match_mask_trie(chan->exempts, chan->exempt_ip_trie, argv[1]))
      ok = 1;
  }
  if (argc == 4) {
    if (!strcasecmp(argv[3], "-channel")) {
      chanarg = 0;
    } else {
      Tcl_AppendResult(irp, "invalid flag", NULL);
      return TCL_ERROR;
    }
  }
  if ((u_match_mask(global_exempts, argv[1])) && chanarg)
    ok = 1;
  if (ok)
    Tcl_AppendResult(irp, "1", NULL);
  else
    Tcl_AppendResult(irp, "0", NULL);
  return TCL_OK;
}

static int tcl_matchinvite STDVAR
{
  struct chanset_t *chan;
  int chanarg = 1, ok = 0;

  BADARGS(2, 4, " user!nick@host ?channel? ?-channel?");

  if (argc >= 3) {
    chan = findchan_by_dname(argv[2]);
    if (chan == NULL) {
      Tcl_AppendResult(irp, "invalid channel: ", argv[2], NULL);
      return TCL_ERROR;
    }
    if (u_match_mask_trie(chan->invites, chan->invite_ip_trie, argv[1]))
      ok = 1;
  }
  if (argc == 4) {
    if (!strcasecmp(argv[3], "-channel")) {
      chanarg = 0;
    } else {
      Tcl_AppendResult(irp, "invalid flag", NULL);
      return TCL_ERROR;
    }
  }
  if ((u_match_mask(global_invites, argv[1])) && chanarg)
    ok = 1;
  if (ok)
    Tcl_AppendResult(irp, "1", NULL);
  else
    Tcl_AppendResult(irp, "0", NULL);
  return TCL_OK;
}

static int tcl_newchanban STDVAR
{
  time_t expire_time;
  struct chanset_t *chan;
  char ban[161], cmt[MASKREASON_LEN], from[HANDLEN + 1];
  int sticky = 0;
  module_entry *me;

  BADARGS(5, 7, " channel ban creator comment ?lifetime? ?options?");

  chan = findchan_by_dname(argv[1]);
  if (chan == NULL) {
    Tcl_AppendResult(irp, "invalid channel: ", argv[1], NULL);
    return TCL_ERROR;
  }
  if (argc == 7) {
    if (!strcasecmp(argv[6], "none"));
    else if (!strcasecmp(argv[6], "sticky"))
      sticky = 1;
    else {
      Tcl_AppendResult(irp, "invalid option ", argv[6], " (must be one of: ",
                       "sticky, none)", NULL);
      return TCL_ERROR;
    }
  }
  strlcpy(ban, argv[2], sizeof ban);
  strlcpy(from, argv[3], sizeof from);
  strlcpy(cmt, argv[4], sizeof cmt);
  if (argc == 5) {
    if (chan->ban_time == 0)
      expire_time = 0;
    else
      expire_time = now + 60 * chan->ban_time;
  } else if ((expire_time = get_expire_time(irp, argv[5])) == -1)
    return TCL_ERROR;
  if (u_addban(chan, ban, from, cmt, expire_time, sticky))
    if ((me = module_find("irc", 0, 0)))
      ((void (*)(struct chanset_t *, char *, int)) me->funcs[IRC_CHECK_THIS_BAN])(chan, ban, sticky);
  return TCL_OK;
}

static int tcl_newban STDVAR
{
  time_t expire_time;
  struct chanset_t *chan;
  char ban[UHOSTLEN], cmt[MASKREASON_LEN], from[HANDLEN + 1];
  int sticky = 0;
  module_entry *me;

  BADARGS(4, 6, " ban creator comment ?lifetime? ?options?");

  if (argc == 6) {
    if (!strcasecmp(argv[5], "none"));
    else if (!strcasecmp(argv[5], "sticky"))
      sticky = 1;
    else {
      Tcl_AppendResult(irp, "invalid option ", argv[5], " (must be one of: ",
                       "sticky, none)", NULL);
      return TCL_ERROR;
    }
  }
  strlcpy(ban, argv[1], sizeof ban);
  strlcpy(from, argv[2], sizeof from);
  strlcpy(cmt, argv[3], sizeof cmt);
  if (argc == 4) {
    if (global_ban_time == 0)
      expire_time = 0;
    else
      expire_time = now + 60 * global_ban_time;
  } else if ((expire_time = get_expire_time(irp, argv[4])) == -1)
    return TCL_ERROR;
  if (u_addban(NULL, ban, from, cmt, expire_time, sticky))
    if ((me = module_find("irc", 0, 0)))
      for (chan = chanset; chan != NULL; chan = chan->next)
        ((void (*)(struct chanset_t *, char *, int)) me->funcs[IRC_CHECK_THIS_BAN])(chan, ban, sticky);
  return TCL_OK;
}

static int tcl_newchanexempt STDVAR
{
  time_t expire_time;
  struct chanset_t *chan;
  char exempt[161], cmt[MASKREASON_LEN], from[HANDLEN + 1];
  int sticky = 0;

  BADARGS(5, 7, " channel exempt creator comment ?lifetime? ?options?");

  chan = findchan_by_dname(argv[1]);
  if (chan == NULL) {
    Tcl_AppendResult(irp, "invalid channel: ", argv[1], NULL);
    return TCL_ERROR;
  }
  if (argc == 7) {
    if (!strcasecmp(argv[6], "none"));
    else if (!strcasecmp(argv[6], "sticky"))
      sticky = 1;
    else {
      Tcl_AppendResult(irp, "invalid option ", argv[6], " (must be one of: ",
                       "sticky, none)", NULL);
      return TCL_ERROR;
    }
  }
  strlcpy(exempt, argv[2], sizeof exempt);
  strlcpy(from, argv[3], sizeof from);
  strlcpy(cmt, argv[4], sizeof cmt);
  if (argc == 5) {
    if (chan->exempt_time == 0)
      expire_time = 0;
    else
      expire_time = now + 60 * chan->exempt_time;
  } else if ((expire_time = get_expire_time(irp, argv[5])) == -1)
    return TCL_ERROR;
  if (u_addexempt(chan, exempt, from, cmt, expire_time, sticky))
    add_mode(chan, '+', 'e', exempt);
  return TCL_OK;
}

static int tcl_newexempt STDVAR
{
  time_t expire_time;
  struct chanset_t *chan;
  char exempt[UHOSTLEN], cmt[MASKREASON_LEN], from[HANDLEN + 1];
  int sticky = 0;

  BADARGS(4, 6, " exempt creator comment ?lifetime? ?options?");

  if (argc == 6) {
    if (!strcasecmp(argv[5], "none"));
    else if (!strcasecmp(argv[5], "sticky"))
      sticky = 1;
    else {
      Tcl_AppendResult(irp, "invalid option ", argv[5], " (must be one of: ",
                       "sticky, none)", NULL);
      return TCL_ERROR;
    }
  }
  strlcpy(exempt, argv[1], sizeof exempt);
  strlcpy(from, argv[2], sizeof from);
  strlcpy(cmt, argv[3], sizeof cmt);
  if (argc == 4) {
    if (global_exempt_time == 0)
      expire_time = 0;
    else
      expire_time = now + 60 * global_exempt_time;
  } else if ((expire_time = get_expire_time(irp, argv[4])) == -1)
    return TCL_ERROR;
  u_addexempt(NULL, exempt, from, cmt, expire_time, sticky);
  for (chan = chanset; chan; chan = chan->next)
    add_mode(chan, '+', 'e', exempt);
  return TCL_OK;
}

static int tcl_newchaninvite STDVAR
{
  time_t expire_time;
  struct chanset_t *chan;
  char invite[161], cmt[MASKREASON_LEN], from[HANDLEN + 1];
  int sticky = 0;

  BADARGS(5, 7, " channel invite creator comment ?lifetime? ?options?");

  chan = findchan_by_dname(argv[1]);
  if (chan == NULL) {
    Tcl_AppendResult(irp, "invalid channel: ", argv[1], NULL);
    return TCL_ERROR;
  }
  if (argc == 7) {
    if (!strcasecmp(argv[6], "none"));
    else if (!strcasecmp(argv[6], "sticky"))
      sticky = 1;
    else {
      Tcl_AppendResult(irp, "invalid option ", argv[6], " (must be one of: ",
                       "sticky, none)", NULL);
      return TCL_ERROR;
    }
  }
  strlcpy(invite, argv[2], sizeof invite);
  strlcpy(from, argv[3], sizeof from);
  strlcpy(cmt, argv[4], sizeof cmt);
  if (argc == 5) {
    if (chan->invite_time == 0)
      expire_time = 0;
    else
      expire_time = now + 60 * chan->invite_time;
  } else if ((expire_time = get_expire_time(irp, argv[5])) == -1)
    return TCL_ERROR;
  if (u_addinvite(chan, invite, from, cmt, expire_time, sticky))
    add_mode(chan, '+', 'I', invite);
  return TCL_OK;
}

static int tcl_newinvite STDVAR
{
  time_t expire_time;
  struct chanset_t *chan;
  char invite[UHOSTLEN], cmt[MASKREASON_LEN], from[HANDLEN + 1];
  int sticky = 0;

  BADARGS(4, 6, " invite creator comment ?lifetime? ?options?");

  if (argc == 6) {
    if (!strcasecmp(argv[5], "none"));
    else if (!strcasecmp(argv[5], "sticky"))
      sticky = 1;
    else {
      Tcl_AppendResult(irp, "invalid option ", argv[5], " (must be one of: ",
                       "sticky, none)", NULL);
      return TCL_ERROR;
    }
  }
  strlcpy(invite, argv[1], sizeof invite);
  strlcpy(from, argv[2], sizeof from);
  strlcpy(cmt, argv[3], sizeof cmt);
  if (argc == 4) {
    if (global_invite_time == 0)
      expire_time = 0;
    else
      expire_time = now + 60 * global_invite_time;
  } else if ((expire_time = get_expire_time(irp, argv[4])) == -1)
    return TCL_ERROR;
  u_addinvite(NULL, invite, from, cmt, expire_time, sticky);
  for (chan = chanset; chan; chan = chan->next)
    add_mode(chan, '+', 'I', invite);
  return TCL_OK;
}

static int tcl_channel_info(Tcl_Interp *irp, struct chanset_t *chan)
{
  char s[121];
  EGG_CONST char *args[2];
  struct udef_struct *ul;

  get_mode_protect(chan, s, sizeof s);
  Tcl_AppendElement(irp, s);
  Tcl_AppendElement(irp, int_to_base10(chan->idle_kick));
  Tcl_AppendElement(irp, int_to_base10(chan->stopnethack_mode));
  Tcl_AppendElement(irp, int_to_base10(chan->revenge_mode));
  Tcl_AppendElement(irp, chan->need_op);
  Tcl_AppendElement(irp, chan->need_invite);
  Tcl_AppendElement(irp, chan->need_key);
  Tcl_AppendElement(irp, chan->need_unban);
  Tcl_AppendElement(irp, chan->need_limit);
  { op_strbuf_t t; op_strbuf_printf(&t, "%d:%d", chan->flood_pub_thr, chan->flood_pub_time); Tcl_AppendElement(irp, op_strbuf_str(&t)); op_strbuf_free(&t); }
  { op_strbuf_t t; op_strbuf_printf(&t, "%d:%d", chan->flood_ctcp_thr, chan->flood_ctcp_time); Tcl_AppendElement(irp, op_strbuf_str(&t)); op_strbuf_free(&t); }
  { op_strbuf_t t; op_strbuf_printf(&t, "%d:%d", chan->flood_join_thr, chan->flood_join_time); Tcl_AppendElement(irp, op_strbuf_str(&t)); op_strbuf_free(&t); }
  { op_strbuf_t t; op_strbuf_printf(&t, "%d:%d", chan->flood_kick_thr, chan->flood_kick_time); Tcl_AppendElement(irp, op_strbuf_str(&t)); op_strbuf_free(&t); }
  { op_strbuf_t t; op_strbuf_printf(&t, "%d:%d", chan->flood_deop_thr, chan->flood_deop_time); Tcl_AppendElement(irp, op_strbuf_str(&t)); op_strbuf_free(&t); }
  { op_strbuf_t t; op_strbuf_printf(&t, "%d:%d", chan->flood_nick_thr, chan->flood_nick_time); Tcl_AppendElement(irp, op_strbuf_str(&t)); op_strbuf_free(&t); }
  { op_strbuf_t t; op_strbuf_printf(&t, "%d:%d", chan->aop_min, chan->aop_max); Tcl_AppendElement(irp, op_strbuf_str(&t)); op_strbuf_free(&t); }
  Tcl_AppendElement(irp, int_to_base10(chan->ban_type));
  Tcl_AppendElement(irp, int_to_base10(chan->ban_time));
  Tcl_AppendElement(irp, int_to_base10(chan->exempt_time));
  Tcl_AppendElement(irp, int_to_base10(chan->invite_time));
  if (chan->status & CHAN_ENFORCEBANS)
    Tcl_AppendElement(irp, "+enforcebans");
  else
    Tcl_AppendElement(irp, "-enforcebans");
  if (chan->status & CHAN_DYNAMICBANS)
    Tcl_AppendElement(irp, "+dynamicbans");
  else
    Tcl_AppendElement(irp, "-dynamicbans");
  if (chan->status & CHAN_NOUSERBANS)
    Tcl_AppendElement(irp, "-userbans");
  else
    Tcl_AppendElement(irp, "+userbans");
  if (chan->status & CHAN_OPONJOIN)
    Tcl_AppendElement(irp, "+autoop");
  else
    Tcl_AppendElement(irp, "-autoop");
  if (chan->status & CHAN_AUTOHALFOP)
    Tcl_AppendElement(irp, "+autohalfop");
  else
    Tcl_AppendElement(irp, "-autohalfop");
  if (chan->status & CHAN_BITCH)
    Tcl_AppendElement(irp, "+bitch");
  else
    Tcl_AppendElement(irp, "-bitch");
  if (chan->status & CHAN_GREET)
    Tcl_AppendElement(irp, "+greet");
  else
    Tcl_AppendElement(irp, "-greet");
  if (chan->status & CHAN_PROTECTOPS)
    Tcl_AppendElement(irp, "+protectops");
  else
    Tcl_AppendElement(irp, "-protectops");
  if (chan->status & CHAN_PROTECTHALFOPS)
    Tcl_AppendElement(irp, "+protecthalfops");
  else
    Tcl_AppendElement(irp, "-protecthalfops");
  if (chan->status & CHAN_PROTECTFRIENDS)
    Tcl_AppendElement(irp, "+protectfriends");
  else
    Tcl_AppendElement(irp, "-protectfriends");
  if (chan->status & CHAN_DONTKICKOPS)
    Tcl_AppendElement(irp, "+dontkickops");
  else
    Tcl_AppendElement(irp, "-dontkickops");
  if (chan->status & CHAN_INACTIVE)
    Tcl_AppendElement(irp, "+inactive");
  else
    Tcl_AppendElement(irp, "-inactive");
  if (chan->status & CHAN_LOGSTATUS)
    Tcl_AppendElement(irp, "+statuslog");
  else
    Tcl_AppendElement(irp, "-statuslog");
  if (chan->status & CHAN_REVENGE)
    Tcl_AppendElement(irp, "+revenge");
  else
    Tcl_AppendElement(irp, "-revenge");
  if (chan->status & CHAN_REVENGEBOT)
    Tcl_AppendElement(irp, "+revengebot");
  else
    Tcl_AppendElement(irp, "-revengebot");
  if (chan->status & CHAN_SECRET)
    Tcl_AppendElement(irp, "+secret");
  else
    Tcl_AppendElement(irp, "-secret");
  if (chan->status & CHAN_SHARED)
    Tcl_AppendElement(irp, "+shared");
  else
    Tcl_AppendElement(irp, "-shared");
  if (chan->status & CHAN_AUTOVOICE)
    Tcl_AppendElement(irp, "+autovoice");
  else
    Tcl_AppendElement(irp, "-autovoice");
  if (chan->status & CHAN_CYCLE)
    Tcl_AppendElement(irp, "+cycle");
  else
    Tcl_AppendElement(irp, "-cycle");
  if (chan->status & CHAN_SEEN)
    Tcl_AppendElement(irp, "+seen");
  else
    Tcl_AppendElement(irp, "-seen");
  if (chan->ircnet_status & CHAN_DYNAMICEXEMPTS)
    Tcl_AppendElement(irp, "+dynamicexempts");
  else
    Tcl_AppendElement(irp, "-dynamicexempts");
  if (chan->ircnet_status & CHAN_NOUSEREXEMPTS)
    Tcl_AppendElement(irp, "-userexempts");
  else
    Tcl_AppendElement(irp, "+userexempts");
  if (chan->ircnet_status & CHAN_DYNAMICINVITES)
    Tcl_AppendElement(irp, "+dynamicinvites");
  else
    Tcl_AppendElement(irp, "-dynamicinvites");
  if (chan->ircnet_status & CHAN_NOUSERINVITES)
    Tcl_AppendElement(irp, "-userinvites");
  else
    Tcl_AppendElement(irp, "+userinvites");
  if (chan->status & CHAN_NODESYNCH)
    Tcl_AppendElement(irp, "+nodesynch");
  else
    Tcl_AppendElement(irp, "-nodesynch");
  if (chan->status & CHAN_STATIC)
    Tcl_AppendElement(irp, "+static");
  else
    Tcl_AppendElement(irp, "-static");
  for (ul = udef; ul; ul = ul->next) {
    /* If it's undefined, skip it. */
    if (!ul->defined || !ul->name)
      continue;

    if (ul->type == UDEF_FLAG) {
      op_strbuf_t t;
      op_strbuf_printf(&t, "%c%s",
               getudef(ul->values, chan->dname) ? '+' : '-', ul->name);
      Tcl_AppendElement(irp, op_strbuf_str(&t));
      op_strbuf_free(&t);
    } else if (ul->type == UDEF_INT) {
      char *x;
      op_strbuf_t b_buf;
      op_strbuf_printf(&b_buf, "%" PRIdPTR, getudef(ul->values, chan->dname));
      args[0] = ul->name;
      args[1] = op_strbuf_str(&b_buf);
      x = Tcl_Merge(2, args);
      Tcl_AppendElement(irp, x);
      Tcl_Free((char *) x);
      op_strbuf_free(&b_buf);
    } else if (ul->type == UDEF_STR) {
      char *p = (char *) getudef(ul->values, chan->dname);
      op_strbuf_t buf;

      if (!p)
        p = "{}";

      op_strbuf_printf(&buf, "%s %s", ul->name, p);
      Tcl_AppendElement(irp, op_strbuf_str(&buf));
      op_strbuf_free(&buf);
    } else
      debug1("UDEF-ERROR: unknown type %d", ul->type);
  }
  return TCL_OK;
}

#define APPEND_KEYVAL(x, y) { \
  Tcl_AppendElement(irp, x);  \
  Tcl_AppendElement(irp, y);  \
}

static int tcl_channel_getlist(Tcl_Interp *irp, struct chanset_t *chan)
{
  char s[121], *str;
  EGG_CONST char **argv = NULL;
  Tcl_Size argc = 0;
  struct udef_struct *ul;

  /* String values first */
  get_mode_protect(chan, s, sizeof s);
  APPEND_KEYVAL("chanmode", s);
  APPEND_KEYVAL("need-op", chan->need_op);
  APPEND_KEYVAL("need-invite", chan->need_invite);
  APPEND_KEYVAL("need-key", chan->need_key);
  APPEND_KEYVAL("need-unban", chan->need_unban);
  APPEND_KEYVAL("need-limit", chan->need_limit);

  /* Integers now */
  APPEND_KEYVAL("idle-kick", int_to_base10(chan->idle_kick));
  APPEND_KEYVAL("stopnethack-mode", int_to_base10(chan->stopnethack_mode));
  APPEND_KEYVAL("revenge-mode", int_to_base10(chan->revenge_mode));
  APPEND_KEYVAL("ban-type", int_to_base10(chan->ban_type));
  APPEND_KEYVAL("ban-time", int_to_base10(chan->ban_time));
  APPEND_KEYVAL("exempt-time", int_to_base10(chan->exempt_time));
  APPEND_KEYVAL("invite-time", int_to_base10(chan->invite_time));
  { op_strbuf_t t; op_strbuf_printf(&t, "%d %d", chan->flood_pub_thr, chan->flood_pub_time); APPEND_KEYVAL("flood-chan", op_strbuf_str(&t)); op_strbuf_free(&t); }
  { op_strbuf_t t; op_strbuf_printf(&t, "%d %d", chan->flood_ctcp_thr, chan->flood_ctcp_time); APPEND_KEYVAL("flood-ctcp", op_strbuf_str(&t)); op_strbuf_free(&t); }
  { op_strbuf_t t; op_strbuf_printf(&t, "%d %d", chan->flood_join_thr, chan->flood_join_time); APPEND_KEYVAL("flood-join", op_strbuf_str(&t)); op_strbuf_free(&t); }
  { op_strbuf_t t; op_strbuf_printf(&t, "%d %d", chan->flood_kick_thr, chan->flood_kick_time); APPEND_KEYVAL("flood-kick", op_strbuf_str(&t)); op_strbuf_free(&t); }
  { op_strbuf_t t; op_strbuf_printf(&t, "%d %d", chan->flood_deop_thr, chan->flood_deop_time); APPEND_KEYVAL("flood-deop", op_strbuf_str(&t)); op_strbuf_free(&t); }
  { op_strbuf_t t; op_strbuf_printf(&t, "%d %d", chan->flood_nick_thr, chan->flood_nick_time); APPEND_KEYVAL("flood-nick", op_strbuf_str(&t)); op_strbuf_free(&t); }
  { op_strbuf_t t; op_strbuf_printf(&t, "%d %d", chan->aop_min, chan->aop_max); APPEND_KEYVAL("aop-delay", op_strbuf_str(&t)); op_strbuf_free(&t); }

  /* Last, but not least - flags */
  APPEND_KEYVAL("enforcebans",
               channel_enforcebans(chan) ?  "1" : "0");
  APPEND_KEYVAL("dynamicbans",
               channel_dynamicbans(chan) ?  "1" : "0");
  APPEND_KEYVAL("userbans",
               channel_nouserbans(chan) ?  "1" : "0");
  APPEND_KEYVAL("autoop",
               channel_autoop(chan) ?  "1" : "0");
  APPEND_KEYVAL("autohalfop",
               channel_autohalfop(chan) ?  "1" : "0");
  APPEND_KEYVAL("bitch",
               channel_bitch(chan) ?  "1" : "0");
  APPEND_KEYVAL("greet",
               channel_greet(chan) ?  "1" : "0");
  APPEND_KEYVAL("protectops",
               channel_protectops(chan) ?  "1" : "0");
  APPEND_KEYVAL("protecthalfops",
               channel_protecthalfops(chan) ?  "1" : "0");
  APPEND_KEYVAL("protectfriends",
               channel_protectfriends(chan) ?  "1" : "0");
  APPEND_KEYVAL("dontkickops",
               channel_dontkickops(chan) ?  "1" : "0");
  APPEND_KEYVAL("inactive",
               channel_inactive(chan) ?  "1" : "0");
  APPEND_KEYVAL("statuslog",
               channel_logstatus(chan) ?  "1" : "0");
  APPEND_KEYVAL("revenge",
               channel_revenge(chan) ?  "1" : "0");
  APPEND_KEYVAL("revengebot",
               channel_revengebot(chan) ?  "1" : "0");
  APPEND_KEYVAL("secret",
               channel_secret(chan) ?  "1" : "0");
  APPEND_KEYVAL("shared",
               channel_shared(chan) ?  "1" : "0");
  APPEND_KEYVAL("autovoice",
               channel_autovoice(chan) ?  "1" : "0");
  APPEND_KEYVAL("cycle",
               channel_cycle(chan) ?  "1" : "0");
  APPEND_KEYVAL("seen",
               channel_seen(chan) ?  "1" : "0");
  APPEND_KEYVAL("nodesynch",
               channel_nodesynch(chan) ?  "1" : "0");
  APPEND_KEYVAL("static",
               channel_static(chan) ?  "1" : "0");
  APPEND_KEYVAL("dynamicexempts",
               channel_dynamicexempts(chan) ?  "1" : "0");
  APPEND_KEYVAL("userexempts",
               channel_nouserexempts(chan) ?  "1" : "0");
  APPEND_KEYVAL("dynamicinvites",
               channel_dynamicinvites(chan) ?  "1" : "0");
  APPEND_KEYVAL("userinvites",
               channel_nouserinvites(chan) ?  "1" : "0");

  /* User defined settings */
  for (ul = udef; ul && ul->name; ul = ul->next) {
    if (ul->type == UDEF_STR) {
      str = (char *) getudef(ul->values, chan->dname);
      if (!str)
        str = "{}";
      Tcl_SplitList(irp, str, &argc, &argv);
      if (argc > 0)
        APPEND_KEYVAL(ul->name, argv[0]);
      Tcl_Free((char *) argv);
    } else {
      op_strbuf_t t;
      op_strbuf_printf(&t, "%" PRIdPTR, getudef(ul->values, chan->dname));
      APPEND_KEYVAL(ul->name, op_strbuf_str(&t));
      op_strbuf_free(&t);
    }
  }

  return TCL_OK;
}

static int tcl_channel_get(Tcl_Interp *irp, struct chanset_t *chan,
                           char *setting)
{
  char s[121], *str = NULL;
  EGG_CONST char **argv = NULL;
  Tcl_Size argc = 0;
  struct udef_struct *ul;

  if (!strcmp(setting, "chanmode"))
    get_mode_protect(chan, s, sizeof s);
  else if (!strcmp(setting, "need-op"))
    strlcpy(s, chan->need_op, sizeof s);
  else if (!strcmp(setting, "need-invite"))
    strlcpy(s, chan->need_invite, sizeof s);
  else if (!strcmp(setting, "need-key"))
    strlcpy(s, chan->need_key, sizeof s);
  else if (!strcmp(setting, "need-unban"))
    strlcpy(s, chan->need_unban, sizeof s);
  else if (!strcmp(setting, "need-limit"))
    strlcpy(s, chan->need_limit, sizeof s);
  else if (!strcmp(setting, "idle-kick"))
    strlcpy(s, int_to_base10(chan->idle_kick), sizeof s);
  else if (!strcmp(setting, "stopnethack-mode") || !strcmp(setting, "stop-net-hack"))
    strlcpy(s, int_to_base10(chan->stopnethack_mode), sizeof s);
  else if (!strcmp(setting, "revenge-mode"))
    strlcpy(s, int_to_base10(chan->revenge_mode), sizeof s);
  else if (!strcmp(setting, "ban-type"))
    strlcpy(s, int_to_base10(chan->ban_type), sizeof s);
  else if (!strcmp(setting, "ban-time"))
    strlcpy(s, int_to_base10(chan->ban_time), sizeof s);
  else if (!strcmp(setting, "exempt-time"))
    strlcpy(s, int_to_base10(chan->exempt_time), sizeof s);
  else if (!strcmp(setting, "invite-time"))
    strlcpy(s, int_to_base10(chan->invite_time), sizeof s);
  else if (!strcmp(setting, "flood-chan")) {
    op_strbuf_t t;
    op_strbuf_printf(&t, "%d %d", chan->flood_pub_thr, chan->flood_pub_time);
    Tcl_AppendResult(irp, op_strbuf_str(&t), NULL);
    op_strbuf_free(&t);
    return TCL_OK;
  }
  else if (!strcmp(setting, "flood-ctcp")) {
    op_strbuf_t t;
    op_strbuf_printf(&t, "%d %d", chan->flood_ctcp_thr, chan->flood_ctcp_time);
    Tcl_AppendResult(irp, op_strbuf_str(&t), NULL);
    op_strbuf_free(&t);
    return TCL_OK;
  }
  else if (!strcmp(setting, "flood-join")) {
    op_strbuf_t t;
    op_strbuf_printf(&t, "%d %d", chan->flood_join_thr, chan->flood_join_time);
    Tcl_AppendResult(irp, op_strbuf_str(&t), NULL);
    op_strbuf_free(&t);
    return TCL_OK;
  }
  else if (!strcmp(setting, "flood-kick")) {
    op_strbuf_t t;
    op_strbuf_printf(&t, "%d %d", chan->flood_kick_thr, chan->flood_kick_time);
    Tcl_AppendResult(irp, op_strbuf_str(&t), NULL);
    op_strbuf_free(&t);
    return TCL_OK;
  }
  else if (!strcmp(setting, "flood-deop")) {
    op_strbuf_t t;
    op_strbuf_printf(&t, "%d %d", chan->flood_deop_thr, chan->flood_deop_time);
    Tcl_AppendResult(irp, op_strbuf_str(&t), NULL);
    op_strbuf_free(&t);
    return TCL_OK;
  }
  else if (!strcmp(setting, "flood-nick")) {
    op_strbuf_t t;
    op_strbuf_printf(&t, "%d %d", chan->flood_nick_thr, chan->flood_nick_time);
    Tcl_AppendResult(irp, op_strbuf_str(&t), NULL);
    op_strbuf_free(&t);
    return TCL_OK;
  }
  else if (!strcmp(setting, "aop-delay")) {
    op_strbuf_t t;
    op_strbuf_printf(&t, "%d %d", chan->aop_min, chan->aop_max);
    Tcl_AppendResult(irp, op_strbuf_str(&t), NULL);
    op_strbuf_free(&t);
    return TCL_OK;
  }
  else if CHKFLAG_POS(CHAN_ENFORCEBANS, "enforcebans", chan->status)
  else if CHKFLAG_POS(CHAN_DYNAMICBANS, "dynamicbans", chan->status)
  else if CHKFLAG_NEG(CHAN_NOUSERBANS, "userbans", chan->status)
  else if CHKFLAG_POS(CHAN_OPONJOIN, "autoop", chan->status)
  else if CHKFLAG_POS(CHAN_AUTOHALFOP, "autohalfop", chan->status)
  else if CHKFLAG_POS(CHAN_BITCH, "bitch", chan->status)
  else if CHKFLAG_POS(CHAN_GREET, "greet", chan->status)
  else if CHKFLAG_POS(CHAN_PROTECTOPS, "protectops", chan->status)
  else if CHKFLAG_POS(CHAN_PROTECTHALFOPS, "protecthalfops", chan->status)
  else if CHKFLAG_POS(CHAN_PROTECTFRIENDS, "protectfriends", chan->status)
  else if CHKFLAG_POS(CHAN_DONTKICKOPS, "dontkickops", chan->status)
  else if CHKFLAG_POS(CHAN_INACTIVE, "inactive", chan->status)
  else if CHKFLAG_POS(CHAN_LOGSTATUS, "statuslog", chan->status)
  else if CHKFLAG_POS(CHAN_REVENGE, "revenge", chan->status)
  else if CHKFLAG_POS(CHAN_REVENGEBOT, "revengebot", chan->status)
  else if CHKFLAG_POS(CHAN_SECRET, "secret", chan->status)
  else if CHKFLAG_POS(CHAN_SHARED, "shared", chan->status)
  else if CHKFLAG_POS(CHAN_AUTOVOICE, "autovoice", chan->status)
  else if CHKFLAG_POS(CHAN_CYCLE, "cycle", chan->status)
  else if CHKFLAG_POS(CHAN_SEEN, "seen", chan->status)
  else if CHKFLAG_POS(CHAN_NODESYNCH, "nodesynch", chan->status)
  else if CHKFLAG_POS(CHAN_STATIC, "static", chan->status)
  else if CHKFLAG_POS(CHAN_DYNAMICEXEMPTS, "dynamicexempts",
                      chan->ircnet_status)
  else if CHKFLAG_NEG(CHAN_NOUSEREXEMPTS, "userexempts",
                      chan->ircnet_status)
  else if CHKFLAG_POS(CHAN_DYNAMICINVITES, "dynamicinvites",
                      chan->ircnet_status)
  else if CHKFLAG_NEG(CHAN_NOUSERINVITES, "userinvites",
                      chan->ircnet_status)
  else {
    /* Hopefully it's a user-defined flag. */
    for (ul = udef; ul && ul->name; ul = ul->next) {
      if (!strcmp(setting, ul->name))
        break;
    }
    if (!ul || !ul->name) {
      /* Error if it wasn't found. */
      Tcl_AppendResult(irp, "Unknown channel setting.", NULL);
      return TCL_ERROR;
    }

    if (ul->type == UDEF_STR) {
      str = (char *) getudef(ul->values, chan->dname);
      if (!str)
        str = "{}";
      Tcl_SplitList(irp, str, &argc, &argv);
      if (argc > 0)
        Tcl_AppendResult(irp, argv[0], NULL);
      Tcl_Free((char *) argv);
    } else {
      /* Flag or int, all the same. */
      op_strbuf_t t;
      op_strbuf_printf(&t, "%" PRIdPTR, getudef(ul->values, chan->dname));
      Tcl_AppendResult(irp, op_strbuf_str(&t), NULL);
      op_strbuf_free(&t);
    }
    return TCL_OK;
  }

  /* Ok, if we make it this far, the result is "s". */
  Tcl_AppendResult(irp, s, NULL);
  return TCL_OK;
}

static int tcl_channel STDVAR
{
  struct chanset_t *chan;

  BADARGS(2, -1, " command ?options?");

  if (!strcmp(argv[1], "add")) {
    BADARGS(3, 4, " add channel-name ?options-list?");

    if (argc == 3)
      return tcl_channel_add(irp, argv[2], "");
    return tcl_channel_add(irp, argv[2], argv[3]);
  }
  if (!strcmp(argv[1], "set")) {
    BADARGS(3, -1, " set channel-name ?options?");

    chan = findchan_by_dname(argv[2]);
    if (chan == NULL) {
      if (chan_hack == 1)
        return TCL_OK;          /* Ignore channel settings for a static
                                 * channel which has been removed from
                                 * the config */
      Tcl_AppendResult(irp, "no such channel record", NULL);
      return TCL_ERROR;
    }
    return tcl_channel_modify(irp, chan, argc - 3, &argv[3]);
  }
  if (!strcmp(argv[1], "get")) {
    BADARGS(3, 4, " get channel-name ?setting-name?");

    chan = findchan_by_dname(argv[2]);
    if (chan == NULL) {
      Tcl_AppendResult(irp, "no such channel record", NULL);
      return TCL_ERROR;
    }
    if (argc == 4)
      return tcl_channel_get(irp, chan, argv[3]);
    else
      return tcl_channel_getlist(irp, chan);
  }
  if (!strcmp(argv[1], "info")) {
    BADARGS(3, 3, " info channel-name");

    chan = findchan_by_dname(argv[2]);
    if (chan == NULL) {
      Tcl_AppendResult(irp, "no such channel record", NULL);
      return TCL_ERROR;
    }
    return tcl_channel_info(irp, chan);
  }
  if (!strcmp(argv[1], "remove")) {
    BADARGS(3, 3, " remove channel-name");

    chan = findchan_by_dname(argv[2]);
    if (chan == NULL) {
      Tcl_AppendResult(irp, "no such channel record", NULL);
      return TCL_ERROR;
    }
    remove_channel(chan);
    return TCL_OK;
  }
  Tcl_AppendResult(irp, "unknown channel command: should be one of: ",
                   "add, set, get, info, remove", NULL);
  return TCL_ERROR;
}

/* tcl_channel_modify is now defined in chancfg.c (included before this file). */


static int tcl_do_masklist(maskrec *m, Tcl_Interp *irp)
{
  char *p;
  EGG_CONST char *list[6];

  for (; m; m = m->next) {
    op_strbuf_t ts, ts1, ts2;
    op_strbuf_printf(&ts, "%" PRId64, (int64_t) m->expire);
    op_strbuf_printf(&ts1, "%" PRId64, (int64_t) m->added);
    op_strbuf_printf(&ts2, "%" PRId64, (int64_t) m->lastactive);
    list[0] = m->mask;
    list[1] = m->desc;
    list[2] = op_strbuf_str(&ts);
    list[3] = op_strbuf_str(&ts1);
    list[4] = op_strbuf_str(&ts2);
    list[5] = m->user;
    p = Tcl_Merge(6, list);
    Tcl_AppendElement(irp, p);
    Tcl_Free((char *) p);
    op_strbuf_free(&ts);
    op_strbuf_free(&ts1);
    op_strbuf_free(&ts2);
  }
  return TCL_OK;
}

static int tcl_banlist STDVAR
{
  struct chanset_t *chan;

  BADARGS(1, 2, " ?channel?");

  if (argc == 2) {
    chan = findchan_by_dname(argv[1]);
    if (chan == NULL) {
      Tcl_AppendResult(irp, "invalid channel: ", argv[1], NULL);
      return TCL_ERROR;
    }
    return tcl_do_masklist(chan->bans, irp);
  }

  return tcl_do_masklist(global_bans, irp);
}

static int tcl_exemptlist STDVAR
{
  struct chanset_t *chan;

  BADARGS(1, 2, " ?channel?");

  if (argc == 2) {
    chan = findchan_by_dname(argv[1]);
    if (chan == NULL) {
      Tcl_AppendResult(irp, "invalid channel: ", argv[1], NULL);
      return TCL_ERROR;
    }
    return tcl_do_masklist(chan->exempts, irp);
  }

  return tcl_do_masklist(global_exempts, irp);
}

static int tcl_invitelist STDVAR
{
  struct chanset_t *chan;

  BADARGS(1, 2, " ?channel?");

  if (argc == 2) {
    chan = findchan_by_dname(argv[1]);
    if (chan == NULL) {
      Tcl_AppendResult(irp, "invalid channel: ", argv[1], NULL);
      return TCL_ERROR;
    }
    return tcl_do_masklist(chan->invites, irp);
  }
  return tcl_do_masklist(global_invites, irp);
}

static int tcl_channels STDVAR
{
  struct chanset_t *chan;

  BADARGS(1, 1, "");

  for (chan = chanset; chan; chan = chan->next)
    Tcl_AppendElement(irp, chan->dname);
  return TCL_OK;
}

static int tcl_savechannels STDVAR
{
  BADARGS(1, 1, "");

  if (!chanfile[0]) {
    Tcl_AppendResult(irp, "no channel file", NULL);
    return TCL_ERROR;
  }
  write_channels();
  return TCL_OK;
}

static int tcl_loadchannels STDVAR
{
  BADARGS(1, 1, "");

  if (!chanfile[0]) {
    Tcl_AppendResult(irp, "no channel file", NULL);
    return TCL_ERROR;
  }
  read_channels(1, 1);
  return TCL_OK;
}

static int tcl_validchan STDVAR
{
  struct chanset_t *chan;

  BADARGS(2, 2, " channel");

  chan = findchan_by_dname(argv[1]);
  if (chan == NULL)
    Tcl_AppendResult(irp, "0", NULL);
  else
    Tcl_AppendResult(irp, "1", NULL);
  return TCL_OK;
}

static int tcl_isdynamic STDVAR
{
  struct chanset_t *chan;

  BADARGS(2, 2, " channel");

  chan = findchan_by_dname(argv[1]);
  if (chan != NULL)
    if (!channel_static(chan)) {
      Tcl_AppendResult(irp, "1", NULL);
      return TCL_OK;
    }
  Tcl_AppendResult(irp, "0", NULL);
  return TCL_OK;
}

static int tcl_getchaninfo STDVAR
{
  char s[161];
  struct userrec *u;

  BADARGS(3, 3, " handle channel");

  u = get_user_by_handle(userlist, argv[1]);
  if (!u || (u->flags & USER_BOT))
    return TCL_OK;
  get_handle_chaninfo(argv[1], argv[2], s, sizeof s);
  Tcl_AppendResult(irp, s, NULL);
  return TCL_OK;
}

static int tcl_setchaninfo STDVAR
{
  struct chanset_t *chan;

  BADARGS(4, 4, " handle channel info");

  chan = findchan_by_dname(argv[2]);
  if (chan == NULL) {
    Tcl_AppendResult(irp, "illegal channel: ", argv[2], NULL);
    return TCL_ERROR;
  }
  if (!strcasecmp(argv[3], "none")) {
    set_handle_chaninfo(userlist, argv[1], argv[2], NULL);
    return TCL_OK;
  }
  set_handle_chaninfo(userlist, argv[1], argv[2], argv[3]);
  return TCL_OK;
}

static int tcl_setlaston STDVAR
{
  time_t t = now;
  struct userrec *u;

  BADARGS(2, 4, " handle ?channel? ?timestamp?");

  u = get_user_by_handle(userlist, argv[1]);
  if (!u) {
    Tcl_AppendResult(irp, "No such user: ", argv[1], NULL);
    return TCL_ERROR;
  }
  if (argc == 4)
    t = (time_t) atoi(argv[3]);
  if (argc == 3 && ((argv[2][0] != '#') && (argv[2][0] != '&')))
    t = (time_t) atoi(argv[2]);
  if (argc == 2 || (argc == 3 && ((argv[2][0] != '#') && (argv[2][0] != '&'))))
    set_handle_laston("*", u, t);
  else
    set_handle_laston(argv[2], u, t);
  return TCL_OK;
}

static int tcl_addchanrec STDVAR
{
  struct userrec *u;

  BADARGS(3, 3, " handle channel");

  u = get_user_by_handle(userlist, argv[1]);
  if (!u) {
    Tcl_AppendResult(irp, "0", NULL);
    return TCL_OK;
  }
  if (!findchan_by_dname(argv[2])) {
    Tcl_AppendResult(irp, "0", NULL);
    return TCL_OK;
  }
  if (get_chanrec(u, argv[2]) != NULL) {
    Tcl_AppendResult(irp, "0", NULL);
    return TCL_OK;
  }
  (void)add_chanrec(u, argv[2]);
  Tcl_AppendResult(irp, "1", NULL);
  return TCL_OK;
}

static int tcl_delchanrec STDVAR
{
  struct userrec *u;

  BADARGS(3, 3, " handle channel");

  u = get_user_by_handle(userlist, argv[1]);
  if (!u) {
    Tcl_AppendResult(irp, "0", NULL);
    return TCL_OK;
  }
  if (get_chanrec(u, argv[2]) == NULL) {
    Tcl_AppendResult(irp, "0", NULL);
    return TCL_OK;
  }
  del_chanrec(u, argv[2]);
  Tcl_AppendResult(irp, "1", NULL);
  return TCL_OK;
}

static int tcl_haschanrec STDVAR
{
  struct userrec *u;
  struct chanset_t *chan;
  struct chanuserrec *chanrec;

  BADARGS(3, 3, " handle channel");

  chan = findchan_by_dname(argv[2]);
  if (chan == NULL) {
    Tcl_AppendResult(irp, "illegal channel: ", argv[2], NULL);
    return TCL_ERROR;
  }
  u = get_user_by_handle(userlist, argv[1]);
  if (!u) {
    Tcl_AppendResult(irp, "No such user: ", argv[1], NULL);
    return TCL_ERROR;
  }
  chanrec = get_chanrec(u, chan->dname);
  if (chanrec) {
    Tcl_AppendResult(irp, "1", NULL);
    return TCL_OK;
  }
  Tcl_AppendResult(irp, "0", NULL);
  return TCL_OK;
}

/* init_masklist, init_channel, clear_masklist, clear_channel, and
 * tcl_channel_add are now defined in chancfg.c (included before this file).
 */

static int tcl_setudef STDVAR
{
  int type;

  BADARGS(3, 3, " type name");

  if (!strcasecmp(argv[1], "flag"))
    type = UDEF_FLAG;
  else if (!strcasecmp(argv[1], "int"))
    type = UDEF_INT;
  else if (!strcasecmp(argv[1], "str"))
    type = UDEF_STR;
  else {
    Tcl_AppendResult(irp, "invalid type. Must be one of: flag, int, str",
                     NULL);
    return TCL_ERROR;
  }
  initudef(type, argv[2], 1);
  return TCL_OK;
}

static int tcl_renudef STDVAR
{
  struct udef_struct *ul;
  int type, found = 0;

  BADARGS(4, 4, " type oldname newname");

  if (!strcasecmp(argv[1], "flag"))
    type = UDEF_FLAG;
  else if (!strcasecmp(argv[1], "int"))
    type = UDEF_INT;
  else if (!strcasecmp(argv[1], "str"))
    type = UDEF_STR;
  else {
    Tcl_AppendResult(irp, "invalid type. Must be one of: flag, int, str",
                     NULL);
    return TCL_ERROR;
  }
  for (ul = udef; ul; ul = ul->next) {
    if (ul->type == type && !strcasecmp(ul->name, argv[2])) {
      op_free(ul->name);
      ul->name = op_strdup(argv[3]);
      found = 1;
    }
  }
  if (!found) {
    Tcl_AppendResult(irp, "not found", NULL);
    return TCL_ERROR;
  } else
    return TCL_OK;
}

static int tcl_deludef STDVAR
{
  struct udef_struct *ul, *ull;
  int type, found = 0;

  BADARGS(3, 3, " type name");

  if (!strcasecmp(argv[1], "flag"))
    type = UDEF_FLAG;
  else if (!strcasecmp(argv[1], "int"))
    type = UDEF_INT;
  else if (!strcasecmp(argv[1], "str"))
    type = UDEF_STR;
  else {
    Tcl_AppendResult(irp, "invalid type. Must be one of: flag, int, str",
                     NULL);
    return TCL_ERROR;
  }
  for (ul = udef; ul; ul = ul->next) {
    ull = ul->next;
    if (!ull)
      break;
    if (ull->type == type && !strcasecmp(ull->name, argv[2])) {
      ul->next = ull->next;
      op_free(ull->name);
      free_udef_chans(ull->values, ull->type);
      op_free(ull);
      found = 1;
    }
  }
  if (udef) {
    if (udef->type == type && !strcasecmp(udef->name, argv[2])) {
      ul = udef->next;
      op_free(udef->name);
      free_udef_chans(udef->values, udef->type);
      op_free(udef);
      udef = ul;
      found = 1;
    }
  }
  if (!found) {
    Tcl_AppendResult(irp, "not found", NULL);
    return TCL_ERROR;
  } else
    return TCL_OK;
}

static int tcl_getudefs STDVAR
{
  struct udef_struct *ul;
  int type = 0;

  BADARGS(1, 2, " ?type?");

  if (argc > 1) {
    if (!strcasecmp(argv[1], "flag"))
      type = UDEF_FLAG;
    else if (!strcasecmp(argv[1], "int"))
      type = UDEF_INT;
    else if (!strcasecmp(argv[1], "str"))
      type = UDEF_STR;
    else {
      Tcl_AppendResult(irp, "invalid type. Valid types are: flag, int, str",
                       NULL);
      return TCL_ERROR;
    }
  }
  for (ul = udef; ul; ul = ul->next)
    if (!type || (ul->type == type)) {
      Tcl_AppendElement(irp, ul->name);
    }

  return TCL_OK;
}

static int tcl_chansettype STDVAR
{
  struct udef_struct *ul;

  BADARGS(2, 2, " setting");

  /* String values first */
  if (!strcmp(argv[1], "chanmode") ||
      !strcmp(argv[1], "need-op") ||
      !strcmp(argv[1], "need-invite") ||
      !strcmp(argv[1], "need-key") ||
      !strcmp(argv[1], "need-unban") ||
      !strcmp(argv[1], "need-limit")) {
    Tcl_AppendResult(irp, "str", NULL);
  /* Couplets */
  } else if (!strcmp(argv[1], "flood-chan") ||
             !strcmp(argv[1], "flood-ctcp") ||
             !strcmp(argv[1], "flood-join") ||
             !strcmp(argv[1], "flood-kick") ||
             !strcmp(argv[1], "flood-deop") ||
             !strcmp(argv[1], "flood-nick") ||
             !strcmp(argv[1], "aop-delay")) {
    Tcl_AppendResult(irp, "pair", NULL);
  /* Integers now */
  } else if (!strcmp(argv[1], "idle-kick") ||
             !strcmp(argv[1], "stopnethack-mode") ||
             !strcmp(argv[1], "revenge-mode") ||
             !strcmp(argv[1], "ban-type") ||
             !strcmp(argv[1], "ban-time") ||
             !strcmp(argv[1], "exempt-time") ||
             !strcmp(argv[1], "invite-time")) {
    Tcl_AppendResult(irp, "int", NULL);
  /* Last, but not least - flags */
  } else if (!strcmp(argv[1], "enforcebans") ||
             !strcmp(argv[1], "dynamicbans") ||
             !strcmp(argv[1], "userbans") ||
             !strcmp(argv[1], "autoop") ||
             !strcmp(argv[1], "autohalfop") ||
             !strcmp(argv[1], "bitch") ||
             !strcmp(argv[1], "greet") ||
             !strcmp(argv[1], "protectops") ||
             !strcmp(argv[1], "protecthalfops") ||
             !strcmp(argv[1], "protectfriends") ||
             !strcmp(argv[1], "dontkickops") ||
             !strcmp(argv[1], "inactive") ||
             !strcmp(argv[1], "statuslog") ||
             !strcmp(argv[1], "revenge") ||
             !strcmp(argv[1], "revengebot") ||
             !strcmp(argv[1], "secret") ||
             !strcmp(argv[1], "shared") ||
             !strcmp(argv[1], "autovoice") ||
             !strcmp(argv[1], "cycle") ||
             !strcmp(argv[1], "seen") ||
             !strcmp(argv[1], "nodesynch") ||
             !strcmp(argv[1], "static") ||
             !strcmp(argv[1], "dynamicexempts") ||
             !strcmp(argv[1], "userexempts") ||
             !strcmp(argv[1], "dynamicinvites") ||
             !strcmp(argv[1], "userinvites")) {
    Tcl_AppendResult(irp, "flag", NULL);
  } else {
    /* Must be a UDEF. */
    for (ul = udef; ul && ul->name; ul = ul->next) {
      if (!strcmp(argv[1], ul->name))
        break;
    }
    if (!ul || !ul->name) {
      Tcl_AppendResult(irp, "unknown channel setting.", NULL);
      return TCL_ERROR;
    }
    if (ul->type == UDEF_STR)
      Tcl_AppendResult(irp, "str", NULL);
    else if (ul->type == UDEF_INT)
      Tcl_AppendResult(irp, "int", NULL);
    else if (ul->type == UDEF_FLAG)
      Tcl_AppendResult(irp, "flag", NULL);
    else
        /* won't happen unless some day we create
         * a new type and forget to add it here
         */
      Tcl_AppendResult(irp, "unknown", NULL);
  }

  return TCL_OK;

}

static tcl_cmds channels_cmds[] = {
  {"killban",               tcl_killban},
  {"killchanban",       tcl_killchanban},
  {"isbansticky",       tcl_isbansticky},
  {"isban",                   tcl_isban},
  {"ispermban",           tcl_ispermban},
  {"matchban",             tcl_matchban},
  {"newchanban",         tcl_newchanban},
  {"newban",                 tcl_newban},
  {"killexempt",         tcl_killexempt},
  {"killchanexempt", tcl_killchanexempt},
  {"isexemptsticky", tcl_isexemptsticky},
  {"isexempt",             tcl_isexempt},
  {"ispermexempt",     tcl_ispermexempt},
  {"matchexempt",       tcl_matchexempt},
  {"newchanexempt",   tcl_newchanexempt},
  {"newexempt",           tcl_newexempt},
  {"killinvite",         tcl_killinvite},
  {"killchaninvite", tcl_killchaninvite},
  {"isinvitesticky", tcl_isinvitesticky},
  {"isinvite",             tcl_isinvite},
  {"isperminvite",     tcl_isperminvite},
  {"matchinvite",       tcl_matchinvite},
  {"newchaninvite",   tcl_newchaninvite},
  {"newinvite",           tcl_newinvite},
  {"channel",               tcl_channel},
  {"channels",             tcl_channels},
  {"exemptlist",         tcl_exemptlist},
  {"invitelist",         tcl_invitelist},
  {"banlist",               tcl_banlist},
  {"savechannels",     tcl_savechannels},
  {"loadchannels",     tcl_loadchannels},
  {"validchan",           tcl_validchan},
  {"isdynamic",           tcl_isdynamic},
  {"getchaninfo",       tcl_getchaninfo},
  {"setchaninfo",       tcl_setchaninfo},
  {"setlaston",           tcl_setlaston},
  {"addchanrec",         tcl_addchanrec},
  {"delchanrec",         tcl_delchanrec},
  {"stick",                   tcl_stick},
  {"unstick",                 tcl_stick},
  {"stickban",                tcl_stick},
  {"unstickban",              tcl_stick},
  {"stickinvite",       tcl_stickinvite},
  {"unstickinvite",     tcl_stickinvite},
  {"stickexempt",       tcl_stickexempt},
  {"unstickexempt",     tcl_stickexempt},
  {"setudef",               tcl_setudef},
  {"renudef",               tcl_renudef},
  {"deludef",               tcl_deludef},
  {"getudefs",             tcl_getudefs},
  {"chansettype",       tcl_chansettype},
  {"haschanrec",         tcl_haschanrec},
  {NULL,                           NULL}
};
