/*
 * seen.c -- part of seen.mod
 *  Implement the seen.tcl script functionality via module
 *
 * by ButchBub - Scott G. Taylor (staylor@mrynet.com)
 *
 * 0.1     1997-07-29      Initial. [BB]
 * 1.0     1997-07-31      Release. [BB]
 * 1.1     1997-08-05      Add nick->handle lookup for NICK's. [BB]
 * 1.2     1997-08-20      Minor fixes. [BB]
 * 1.2a    1997-08-24      Minor fixes. [BB]
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

/*
 *  Currently, PUB, DCC and MSG commands are supported.  No party-line
 *      filtering is performed.
 *
 *  For boyfriend/girlfriend support, this module relies on the XTRA
 *      fields in the userfile to use BF and GF, respectively, for
 *      these fields.
 *
 *  userinfo1.0.tcl nicely compliments this script by providing
 *      the necessary commands to facilitate modification of these
 *      fields via DCC and IRC MSG commands.
 *
 *  A basic definition of the parsing syntax follows:
 *
 *      trigger :: seen [ <key> [ [ and | or ] <key> [...]]]
 *
 *        <key> :: <keyword> [ <keyarg> ]
 *
 *    <keyword> :: god | jesus | shit | me | yourself | my | <nick>'s |
 *                 your
 *       <nick> :: (any current on-channel IRC nick or userlist nick or handle)
 *
 *     <keyarg> :: (see below)
 *
 *              KEYWORD KEYARG
 *
 *              my      boyfriend
 *                      bf
 *                      girlfriend
 *                      gf
 *              your    owner
 *                      admin
 *                      (other)
 *              NICK's  boyfriend
 *                      bf
 *                      girlfriend
 *                      gf
 *
 */

#define MODULE_NAME "seen"
#define MAKING_SEEN

#include "src/mod/module.h"

#include "src/users.h"
#include "src/chan.h"
#include "channels.mod/channels.h"

static Function *global = nullptr;
static void wordshift(char *first, char *rest);
static void do_seen(int idx, const char *prefix, char *nick, char *hand, char *channel, char *text);
static char *match_trigger(char *word);
static char *getxtra(char *hand, char *field);
static const char *fixnick(char *nick);

typedef struct {
  char *key;
  char *text;
} trig_data;

static trig_data trigdata[] = {
  {"god",      "Let's not get into a religious discussion, %s"},
  {"jesus",    "Let's not get into a religious discussion, %s"},
  {"shit",                         "Here's looking at you, %s"},
  {"yourself",          "Yeah, whenever I look in a mirror..."},
  {nullptr, "                                  You found me, %s!"},
  {"elvis",                 "Last time I was on the moon man."},
  {nullptr,                                                  nullptr}
};

static int seen_expmem(void)
{
  return 0;
}

/* PUB `seen' trigger. */
static int pub_seen(char *nick, char *host, char *hand,
                    char *channel, char *text)
{
  struct chanset_t *chan = findchan_by_dname(channel);

  if ((chan != nullptr) && channel_seen(chan)) {
    op_strbuf_t sb;
    op_strbuf_init(&sb);
    op_strbuf_appendf(&sb, "PRIVMSG %s :", chan->name);
    do_seen(DP_HELP, op_strbuf_str(&sb), nick, hand, chan->dname, text);
    op_strbuf_free(&sb);
  }
  return 0;
}

static int msg_seen(char *nick, char *host, struct userrec *u, char *text)
{
  if (!u) {
    putlog(LOG_CMDS, "*", "[%s!%s] seen %s", nick, host, text);
    return 0;
  }
  putlog(LOG_CMDS, "*", "(%s!%s) !%s! SEEN %s", nick, host, u->handle, text);
  {
    op_strbuf_t _p;
    op_strbuf_init(&_p);
    op_strbuf_appendf(&_p, "PRIVMSG %s :", nick);
    do_seen(DP_SERVER, op_strbuf_str(&_p), nick, u->handle, "", text);
    op_strbuf_free(&_p);
  }
  return 0;
}

static int dcc_seen(struct userrec *u, int idx, char *par)
{
  putlog(LOG_CMDS, "*", "#%s# seen %s", dcc[idx].nick, par);
  do_seen(idx, "", dcc[idx].nick, dcc[idx].nick, "", par);
  return 0;
}

static void do_seen(int idx, const char *prefix, char *nick, char *hand,
                    char *channel, char *text)
{
  char word1[512], word2[512], whotarget[128], object[128],
       *oix, *lastonplace = 0;
  op_strbuf_t whoredirect;
  struct userrec *urec;
  struct chanset_t *chan;
  struct laston_info *li;
  struct chanuserrec *cr;
  memberlist *m = nullptr;
  int onchan = 0, i;
  long tv;
  time_t laston = 0, work;

  whotarget[0]   = 0;
  op_strbuf_init(&whoredirect);
  object[0]      = 0;

  /* Was ANYONE specified */
  if (!text[0]) {
    dprintf(idx, "%sUm, %s, it might help if you ask me about _someone_...\n",
            prefix, nick);
    goto done;
  }

  wordshift(word1, text);
  oix = strchr(word1, '\'');
  /* Have we got a NICK's target? */
  if (oix == word1)
    return;                     /* Skip anything starting with ' */
  if (oix && *oix && ((oix[1] && (oix[1] == 's' || oix[1] == 'S') &&
      !oix[2]) || (!oix[1] && (oix[-1] == 's' || oix[-1] == 'z' ||
      oix[-1] == 'x' || oix[-1] == 'S' || oix[-1] == 'Z' ||
      oix[-1] == 'X')))) {
    strlcpy(object, word1, sizeof object);
    object[oix - word1] = 0;
    wordshift(word1, text);
    if (!word1[0]) {
      dprintf(idx, "%s%s's what, %s?\n", prefix, object, nick);
      goto done;
    }
    urec = get_user_by_handle(userlist, object);
    if (!urec) {
      chan = chanset;
      while (chan) {
        onchan = 0;
        m = ismember(chan, object);
        if (m) {
          onchan = 1;
          urec = get_user_from_member(m);
          if (!urec || !strcasecmp(object, urec->handle))
            break;
          op_strbuf_appendf(&whoredirect, "%s is %s, and ", object, urec->handle);
          strlcpy(object, urec->handle, sizeof object);
          break;
        }
        chan = chan->next;
      }
      if (!onchan) {
        dprintf(idx, "%sI don't think I know who %s is, %s.\n",
                prefix, object, nick);
        goto done;
      }
    }
    if (!strcasecmp(word1, "bf") || !strcasecmp(word1, "boyfriend")) {
      strlcpy(whotarget, getxtra(object, "BF"), sizeof whotarget);
      if (whotarget[0]) {
        op_strbuf_clear(&whoredirect);
        op_strbuf_appendf(&whoredirect, "%s boyfriend is %s, and ", fixnick(object), whotarget);
        goto targetcont;
      }
      dprintf(idx,
              "%sI don't know who %s boyfriend is, %s.\n",
              prefix, fixnick(object), nick);
      goto done;
    }
    if (!strcasecmp(word1, "gf") || !strcasecmp(word1, "girlfriend")) {
      strlcpy(whotarget, getxtra(object, "GF"), sizeof whotarget);
      if (whotarget[0]) {
        op_strbuf_clear(&whoredirect);
        op_strbuf_appendf(&whoredirect, "%s girlfriend is %s, and ", fixnick(object), whotarget);
        goto targetcont;
      }
      dprintf(idx,
              "%sI don't know who %s girlfriend is, %s.\n",
              prefix, fixnick(object), nick);
      goto done;
    }
    dprintf(idx,
            "%sWhy are you bothering me with questions about %s %s, %s?\n",
            prefix, fixnick(object), word1, nick);
    goto done;
  }
  /* Keyword "my" */
  if (!strcasecmp(word1, "my")) {
    wordshift(word1, text);
    if (!word1[0]) {
      dprintf(idx, "%sYour what, %s?\n", prefix, nick);
      goto done;
    }
    /* Do I even KNOW the requester? */
    if (hand[0] == '*' || !hand[0]) {
      dprintf(idx,
              "%sI don't know you, %s, so I don't know about your %s.\n",
              prefix, nick, word1);
      goto done;
    }
    /* "my boyfriend" */
    if (!strcasecmp(word1, "boyfriend") || !strcasecmp(word1, "bf")) {
      strlcpy(whotarget, getxtra(hand, "BF"), sizeof whotarget);
      if (whotarget[0]) {
        op_strbuf_clear(&whoredirect);
        op_strbuf_appendf(&whoredirect, "%s, your boyfriend is %s, and ", nick, whotarget);
      } else {
        dprintf(idx, "%sI didn't know you had a boyfriend, %s\n", prefix, nick);
        goto done;
      }
    }
    /* "my girlfriend" */
    else if (!strcasecmp(word1, "girlfriend") ||
             !strcasecmp(word1, "gf")) {
      strlcpy(whotarget, getxtra(hand, "GF"), sizeof whotarget);
      if (whotarget[0]) {
        op_strbuf_clear(&whoredirect);
        op_strbuf_appendf(&whoredirect, "%s, your girlfriend is %s, and ", nick, whotarget);
      } else {
        dprintf(idx, "%sI didn't know you had a girlfriend, %s\n", prefix,
                nick);
        goto done;
      }
    } else {
      dprintf(idx, "%sI don't know anything about your %s, %s.\n", prefix,
              word1, nick);
      goto done;
    }
  }
  /* "your" keyword */
  else if (!strcasecmp(word1, "your")) {
    wordshift(word1, text);
    /* "your admin" */
    if (!strcasecmp(word1, "owner") || !strcasecmp(word1, "admin")) {
      if (admin[0]) {
        strlcpy(word2, admin, sizeof word2);
        wordshift(whotarget, word2);
        op_strbuf_appendf(&whoredirect, "My owner is %s, and ", whotarget);
        if (!strcasecmp(whotarget, hand)) {
          if (!strcasecmp(hand, nick))
            op_strbuf_append_cstr(&whoredirect, "that's YOU!!!");
          else
            op_strbuf_appendf(&whoredirect, "that's YOU, %s!", nick);
          dprintf(idx, "%s%s\n", prefix, op_strbuf_str(&whoredirect));
          goto done;
        }
      } else {                    /* owner variable munged or not set */
        dprintf(idx,
                "%sI don't seem to recall who my owner is right now...\n",
                prefix);
        goto done;
      }
    } else {                      /* no "your" target specified */
      dprintf(idx, "%sLet's not get personal, %s.\n", prefix, nick);
      goto done;
    }
  }
  /* Check for keyword match in the internal table */
  else if (match_trigger(word1)) {
    op_strbuf_t _b;
    op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "%s%s\n", prefix, match_trigger(word1));
    dprintf(idx, op_strbuf_str(&_b), nick);
    op_strbuf_free(&_b);
    goto done;
  }
  /* Otherwise, make the target to the first word and continue */
  else
    strlcpy(whotarget, word1, sizeof whotarget);

targetcont:
  /* Looking for ones own nick? */
  if (!rfc_casecmp(nick, whotarget)) {
    dprintf(idx, "%s%sLooking for yourself, eh %s?\n",
            prefix, op_strbuf_str(&whoredirect), nick);
    goto done;
  }
  /* Check if nick is on a channel */
  chan = chanset;
  while (chan) {
    m = ismember(chan, whotarget);
    if (m) {
      onchan = 1;
      urec = get_user_from_member(m);
      if (!urec || !strcasecmp(whotarget, urec->handle))
        break;
      op_strbuf_appendf(&whoredirect, "%s is %s, and ", whotarget, urec->handle);
      break;
    }
    chan = chan->next;
  }
  /* Check if nick is on a channel by xref'ing to handle */
  if (!onchan) {
    chan = chanset;
    while (chan) {
      m = chan->channel.member;
      while (m && m->nick[0]) {
        urec = get_user_from_member(m);
        if (urec && !strcasecmp(urec->handle, whotarget)) {
          op_strbuf_appendf(&whoredirect, "%s is %s, and ", whotarget, m->nick);
          strlcpy(whotarget, m->nick, sizeof whotarget);
          break;
        }
        m = m->next;
      }
      chan = chan->next;
    }
  }
  /* Check if the target was on the channel, but is netsplit */
  chan = findchan_by_dname(channel);
  if (chan) {
    m = ismember(chan, whotarget);
    if (m && chan_issplit(m)) {
      dprintf(idx, "%s%s%s was just here, but got netsplit.\n",
              prefix, op_strbuf_str(&whoredirect), whotarget);
      goto done;
    }
  }
  /* Check if the target IS on the channel */
  if (chan && m) {
    dprintf(idx, "%s%s%s is on the channel right now!\n",
            prefix, op_strbuf_str(&whoredirect), whotarget);
    goto done;
  }
  /* Target not on this channel. Check other channels */
  chan = chanset;
  while (chan) {
    m = ismember(chan, whotarget);
    if (m && chan_issplit(m)) {
      dprintf(idx,
              "%s%s%s was just on %s, but got netsplit.\n",
              prefix, op_strbuf_str(&whoredirect), whotarget, chan->dname);
      goto done;
    }
    if (m) {
      dprintf(idx,
              "%s%s%s is on %s right now!\n",
              prefix, op_strbuf_str(&whoredirect), whotarget, chan->dname);
      goto done;
    }
    chan = chan->next;
  }
  /* Target isn't on any of my channels. */
  /* See if target matches a handle in my userlist. */
  urec = get_user_by_handle(userlist, whotarget);
  /* No match, then bail out */
  if (!urec) {
    dprintf(idx, "%s%sI don't know who %s is.\n",
            prefix, op_strbuf_str(&whoredirect), whotarget);
    goto done;
  }
  /* We had a userlist match to a handle */
  /* Is the target currently DCC CHAT to me on the botnet? */
  for (i = 0; i < dcc_total; i++) {
    if (dcc[i].type->flags & DCT_CHAT) {
      if (!strcasecmp(whotarget, dcc[i].nick)) {
        if (!rfc_casecmp(channel, dcc[i].u.chat->con_chan) &&
            dcc[i].u.chat->con_flags & LOG_PUBLIC) {
          op_strbuf_appendf(&whoredirect, "%s is 'observing' this channel right now from my party line!", whotarget);
          dprintf(idx, "%s%s\n", prefix, op_strbuf_str(&whoredirect));
        } else {
          dprintf(idx,
                  "%s%s%s is linked to me via DCC CHAT right now!\n",
                  prefix, op_strbuf_str(&whoredirect), whotarget);
        }
        goto done;
      }
    }
  }
  /* Target known, but nowhere to be seen. Give last IRC and botnet time */
  wordshift(word1, text);
  if (!strcasecmp(word1, "anywhere"))
    cr = nullptr;
  else
    for (cr = urec->chanrec; cr; cr = cr->next) {
      if (!rfc_casecmp(cr->channel, channel)) {
        if (cr->laston) {
          laston = cr->laston;
          lastonplace = channel;
          break;
        }
      }
    }
  if (!cr) {
    li = get_user(&USERENTRY_LASTON, urec);
    if (!li || !li->lastonplace || !li->lastonplace[0]) {
      dprintf(idx, "%s%sI've never seen %s around.\n",
              prefix, op_strbuf_str(&whoredirect), whotarget);
      goto done;
    }
    lastonplace = li->lastonplace;
    laston = li->laston;
  }
  {
    op_strbuf_t dur;
    op_strbuf_init(&dur);
    word1[0] = 0;
    work = now - laston;
    if (work >= 86400) {
      tv = work / 86400;
      op_strbuf_appendf(&dur, "%li day%s, ", tv, (tv == 1) ? "" : "s");
      work = work % 86400;
    }
    if (work >= 3600) {
      tv = work / 3600;
      op_strbuf_appendf(&dur, "%li hour%s, ", tv, (tv == 1) ? "" : "s");
      work = work % 3600;
    }
    if (work >= 60) {
      tv = work / 60;
      op_strbuf_appendf(&dur, "%li minute%s, ", tv, (tv == 1) ? "" : "s");
    }
    if (op_strbuf_empty(&dur)) {
      op_strbuf_append_cstr(&dur, "just moments ago!!");
    } else {
      op_strbuf_truncate(&dur, op_strbuf_len(&dur) - 2);
      op_strbuf_append_cstr(&dur, " ago.");
    }
    {
      op_strbuf_t _w;
      op_strbuf_init(&_w);
      if (lastonplace[0] && (strchr(CHANMETA, lastonplace[0]) != nullptr))
        op_strbuf_appendf(&_w, "on IRC channel %s", lastonplace);
      else if (lastonplace[0] == '@')
        op_strbuf_appendf(&_w, "on %s", lastonplace + 1);
      else if (lastonplace[0] != 0)
        op_strbuf_appendf(&_w, "on my %s", lastonplace);
      else
        op_strbuf_appendf(&_w, "seen");
      dprintf(idx, "%s%s%s was last %s %s\n",
              prefix, op_strbuf_str(&whoredirect), whotarget, op_strbuf_str(&_w), op_strbuf_str(&dur));
      op_strbuf_free(&_w);
    }
    op_strbuf_free(&dur);
  }
done:
  op_strbuf_free(&whoredirect);
}

static const char *fixnick(char *nick)
{
  static op_strbuf_t _fixit;

  if (!nick)
    return nullptr;
  if (!nick[0])
    op_strbuf_clear(&_fixit);
  else {
    char last = nick[strlen(nick) - 1];
    const char *suffix = (last == 's' || last == 'S' || last == 'x' ||
                          last == 'X' || last == 'z' || last == 'Z') ? "'" : "'s";
    op_strbuf_clear(&_fixit);
    op_strbuf_appendf(&_fixit, "%s%s", nick, suffix);
  }
  return op_strbuf_str(&_fixit);
}

static char *match_trigger(char *word)
{
  trig_data *t = trigdata;

  while (t->key) {
    if (!strcasecmp(word, t->key))
      return t->text;
    t++;
  }
  return (char *) nullptr;
}

static char *getxtra(char *hand, char *field)
{
  static op_strbuf_t _fixit;
  struct userrec *urec;
  struct user_entry *ue;
  struct xtra_key *xk;

  urec = get_user_by_handle(userlist, hand);
  if (urec) {
    ue = find_user_entry(&USERENTRY_XTRA, urec);
    if (ue)
      for (xk = ue->u.extra; xk; xk = xk->next)
        if (xk->key && !strcasecmp(xk->key, field)) {
          if (xk->data[0] == '{' && xk->data[strlen(xk->data) - 1] == '}' &&
              strlen(xk->data) > 2) {
            op_strbuf_clear(&_fixit);
            op_strbuf_appendf(&_fixit, "%.*s",
                            (int)(strlen(xk->data) - 2), &xk->data[1]);
            return (char *) op_strbuf_str(&_fixit);
          } else {
            return xk->data;
          }
        }
  }
  return "";
}

static void wordshift(char *first, char *rest)
{
  char *p, *q = rest;

  do {
    p = newsplit(&q);
    strlcpy(first, p, 512);
    memmove(rest, q, strlen(q) + 1);
  } while (!strcasecmp(first, "and") || !strcasecmp(first, "or"));
}

/* Report on current seen info for .modulestat. */
static void seen_report(int idx, int details)
{
  if (details) {
    int size = seen_expmem();

    dprintf(idx, "    Using %d byte%s of memory\n", size,
            (size != 1) ? "s" : "");
  }
}

/* PUB channel builtin commands. */
static cmd_t seen_pub[] = {
  {"seen", "",    pub_seen, nullptr},
  {nullptr,   nullptr, nullptr,      nullptr}
};

static cmd_t seen_dcc[] = {
  {"seen", "",   dcc_seen, nullptr},
  {nullptr,   nullptr, nullptr,     nullptr}
};

static cmd_t seen_msg[] = {
  {"seen", "",   msg_seen, nullptr},
  {nullptr,   nullptr, nullptr,     nullptr}
};

static int server_seen_setup(char *mod)
{
  p_tcl_bind_list H_temp;

  if ((H_temp = find_bind_table("msg")))
    add_builtins(H_temp, seen_msg);
  return 0;
}

static int irc_seen_setup(char *mod)
{
  p_tcl_bind_list H_temp;

  if ((H_temp = find_bind_table("pub")))
    add_builtins(H_temp, seen_pub);
  return 0;
}

static cmd_t seen_load[] = {
  {"server", "",   server_seen_setup, nullptr},
  {"irc",    "",   irc_seen_setup,    nullptr},
  {nullptr,     nullptr, nullptr,              nullptr}
};

static char *seen_close(void)
{
  p_tcl_bind_list H_temp;

  rem_builtins(H_load, seen_load);
  rem_builtins(H_dcc, seen_dcc);
  rem_help_reference("seen.help");
  if ((H_temp = find_bind_table("pub")))
    rem_builtins(H_temp, seen_pub);
  if ((H_temp = find_bind_table("msg")))
    rem_builtins(H_temp, seen_msg);
  module_undepend(MODULE_NAME);
  return nullptr;
}

EXPORT_SCOPE char *seen_start(Function *egg_func_table);

static Function seen_table[] = {
  (Function) seen_start,
  (Function) seen_close,
  (Function) seen_expmem,
  (Function) seen_report,
};

char *seen_start(Function *egg_func_table)
{
  global = egg_func_table;

  module_register(MODULE_NAME, seen_table, 2, 1);
  if (!module_depend(MODULE_NAME, "eggdrop", 108, 0)) {
    module_undepend(MODULE_NAME);
    return "This module requires Eggdrop 1.8.0 or later.";
  }
  add_builtins(H_load, seen_load);
  add_builtins(H_dcc, seen_dcc);
  add_help_reference("seen.help");
  server_seen_setup(nullptr);
  irc_seen_setup(nullptr);
  trigdata[4].key = botnetnick;
  return nullptr;
}
