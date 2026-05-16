/*
 * chan.c -- part of irc.mod
 *   channel member management, mode utilities
 *   includes chan_enforce.c and chan_handlers.c
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

#include "irc.h"


/* Returns a pointer to a new channel member structure.
 */
static memberlist *newmember(struct chanset_t *chan)
{
  memberlist *x;

  for (x = chan->channel.member; x && x->nick[0]; x = x->next);
  if (!x) {
    fatal("newmember: missing sentinel in member list", 0);
    abort();
  }
  x->next = (memberlist *) channel_malloc_member();
  x->next->next = nullptr;
  x->next->nick[0] = 0;
  x->next->split = 0L;
  x->next->last = 0L;
  x->next->delay = 0L;
  chan->channel.members++;
  return x;
}

/* Remove channel members for which no WHO reply was received */
static void sync_members(struct chanset_t *chan)
{
  memberlist *m, *next, *prev;

  for (m = chan->channel.member, prev = 0; m && m->nick[0]; m = next) {
    next = m->next;
    if (!chan_whosynced(m)) {
      if (chan->channel.member_ht && m->nick[0])
        op_htab_del(chan->channel.member_ht, m->nick);
      if (prev)
        prev->next = next;
      else
        chan->channel.member = next;
      channel_free_member(m);
      chan->channel.members--;
    } else
      prev = m;
  }
}

/* Always pass the channel dname (display name) to this function <cybah>
 */
static void update_idle(char *chname, char *nick)
{
  memberlist *m;
  struct chanset_t *chan;

  chan = findchan_by_dname(chname);
  if (chan) {
    m = ismember(chan, nick);
    if (m)
      m->last = now;
  }
}

/* set user account on all members on all channels,
 * trigger account bind if account state was not "unknown" (empty string)
 */
static void setaccount(char *nick, char *account)
{
  memberlist *m;
  struct chanset_t *chan;

  for (chan = chanset; chan; chan = chan->next) {
    if ((m = ismember(chan, nick))) {
      if (rfc_casecmp(m->account, account)) {
        /* account was known */
        if (m->account[0]) {
          if (!strcmp(account, "*")) {
            putlog(LOG_JOIN, chan->dname, "%s!%s has logged out of their account", nick, m->userhost);
          } else {
            putlog(LOG_JOIN, chan->dname, "%s!%s logged in to their account %s", nick, m->userhost, account);
          }
          check_tcl_account(m->nick, m->userhost, get_user_from_member(m), chan->dname, account);
        }
        strlcpy(m->account, account, sizeof m->account);
      }
    }
  }
  /* Username for nick could be different after account change, invalidate cache */
  clear_chanlist_member(nick);
}

/* Returns the current channel mode.
 */
static const char *getchanmode(struct chanset_t *chan)
{
  static op_strbuf_t s = {};
  int atr;

  op_strbuf_clear(&s);
  op_strbuf_appendf(&s, "+");
  atr = chan->channel.mode;
  if (atr & CHANINV)
    op_strbuf_appendc(&s, 'i');
  if (atr & CHANPRIV)
    op_strbuf_appendc(&s, 'p');
  if (atr & CHANSEC)
    op_strbuf_appendc(&s, 's');
  if (atr & CHANMODER)
    op_strbuf_appendc(&s, 'm');
  if (atr & CHANNOCLR)
    op_strbuf_appendc(&s, 'c');
  if (atr & CHANNOCTCP)
    op_strbuf_appendc(&s, 'C');
  if (atr & CHANREGON)
    op_strbuf_appendc(&s, 'R');
  if (atr & CHANTOPIC)
    op_strbuf_appendc(&s, 't');
  if (atr & CHANMODREG)
    op_strbuf_appendc(&s, 'M');
  if (atr & CHANLONLY)
    op_strbuf_appendc(&s, 'r');
  if (atr & CHANDELJN)
    op_strbuf_appendc(&s, 'D');
  if (atr & CHANSTRIP)
    op_strbuf_appendc(&s, 'u');
  if (atr & CHANNONOTC)
    op_strbuf_appendc(&s, 'N');
  if (atr & CHANNOAMSG)
    op_strbuf_appendc(&s, 'T');
  if (atr & CHANINVIS)
    op_strbuf_appendc(&s, 'd');
  if (atr & CHANNOMSG)
    op_strbuf_appendc(&s, 'n');
  if (atr & CHANANON)
    op_strbuf_appendc(&s, 'a');
  if (atr & CHANKEY)
    op_strbuf_appendc(&s, 'k');
  if (chan->channel.maxmembers != 0)
    op_strbuf_appendc(&s, 'l');
  if (chan->channel.key[0])
    op_strbuf_appendf(&s, " %s", chan->channel.key);
  if (chan->channel.maxmembers != 0)
    op_strbuf_appendf(&s, " %s", int_to_base10(chan->channel.maxmembers));
  return op_strbuf_str(&s);
}

#include "chan_enforce.c"
#include "chan_handlers.c"
