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
  x->next->next = NULL;
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
static char *getchanmode(struct chanset_t *chan)
{
  static char s[121];
  int atr, i;

  s[0] = '+';
  i = 1;
  atr = chan->channel.mode;
  if (atr & CHANINV)
    s[i++] = 'i';
  if (atr & CHANPRIV)
    s[i++] = 'p';
  if (atr & CHANSEC)
    s[i++] = 's';
  if (atr & CHANMODER)
    s[i++] = 'm';
  if (atr & CHANNOCLR)
    s[i++] = 'c';
  if (atr & CHANNOCTCP)
    s[i++] = 'C';
  if (atr & CHANREGON)
    s[i++] = 'R';
  if (atr & CHANTOPIC)
    s[i++] = 't';
  if (atr & CHANMODREG)
    s[i++] = 'M';
  if (atr & CHANLONLY)
    s[i++] = 'r';
  if (atr & CHANDELJN)
    s[i++] = 'D';
  if (atr & CHANSTRIP)
    s[i++] = 'u';
  if (atr & CHANNONOTC)
    s[i++] = 'N';
  if (atr & CHANNOAMSG)
    s[i++] = 'T';
  if (atr & CHANINVIS)
    s[i++] = 'd';
  if (atr & CHANNOMSG)
    s[i++] = 'n';
  if (atr & CHANANON)
    s[i++] = 'a';
  if (atr & CHANKEY)
    s[i++] = 'k';
  if (chan->channel.maxmembers != 0)
    s[i++] = 'l';
  s[i] = 0;
  if (chan->channel.key[0]) {
    op_strbuf_t _b;
    op_strbuf_printf(&_b, " %s", chan->channel.key);
    strlcat(s, op_strbuf_str(&_b), sizeof s);
    op_strbuf_free(&_b);
  }
  if (chan->channel.maxmembers != 0) {
    op_strbuf_t _b;
    op_strbuf_printf(&_b, " %s", int_to_base10(chan->channel.maxmembers));
    strlcat(s, op_strbuf_str(&_b), sizeof s);
    op_strbuf_free(&_b);
  }
  return s;
}

#include "chan_enforce.c"
#include "chan_handlers.c"
