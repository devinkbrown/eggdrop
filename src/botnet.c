/*
 * botnet.c -- handles:
 *   keeping track of which bot's connected where in the chain
 *   dumping a list of bots or a bot tree to a user
 *   channel name associations on the party line
 *   rejecting a bot
 *   linking, unlinking, and relaying to another bot
 *   pinging the bots periodically and checking leaf status
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
#include "tandem.h"

extern int dcc_total, backgrd, connect_timeout, max_dcc, egg_numver;
extern struct userrec *userlist;
extern struct dcc_t *dcc;
extern time_t now;
extern Tcl_Interp *interp;

tand_t *tandbot;                   /* Keep track of tandem bots on the botnet */
party_t *party;                    /* Keep track of people on the botnet */
static int party_size = 0;

/* Slab allocator for tand_t nodes — lazy-initialised on first addbot. */
static op_bh *tand_bh = NULL;
int tands = 0;                     /* Number of bots on the botnet */
int parties = 0;                   /* Number of people on the botnet */
char botnetnick[HANDLEN + 1] = ""; /* Botnet nickname */
int share_unlinks = 0;             /* Allow remote unlinks of my sharebots? */
#ifdef TLS
int tls_vfybots = 0;               /* Verify SSL certificates from bots? */
#endif

int expmem_botnet(void)
{
  int size = 0, i;

  size = tands * sizeof(tand_t);
  size += party_size * sizeof(party_t);
  for (i = 0; i < parties; i++) {
    if (party[i].away)
      size += strlen(party[i].away) + 1;
    if (party[i].from)
      size += strlen(party[i].from) + 1;
  }
  return size;
}

void init_bots(void)
{
  tandbot = NULL;
}

tand_t *findbot(char *who)
{
  tand_t *ptr;

  for (ptr = tandbot; ptr; ptr = ptr->next)
    if (!strcasecmp(ptr->bot, who))
      return ptr;
  return NULL;
}

/* Add a tandem bot to our chain list
 */
void addbot(char *who, char *from, char *next, char flag, int vernum, int ssl)
{
  tand_t **ptr = &tandbot, *ptr2;

  while (*ptr) {
    if (!strcasecmp((*ptr)->bot, who))
      putlog(LOG_BOTS, "*", "!!! Duplicate botnet bot entry!!");
    ptr = &((*ptr)->next);
  }
  if (!tand_bh)
    tand_bh = op_bh_create(sizeof(tand_t), 32, "tand_t");
  ptr2 = op_bh_alloc(tand_bh);
  strlcpy(ptr2->bot, who, sizeof ptr2->bot);
  ptr2->share = flag;
  ptr2->ver = vernum;
  ptr2->next = *ptr;
  ptr2->ssl = ssl;
  *ptr = ptr2;
  /* May be via itself */
  ptr2->via = findbot(from);
  if (!strcasecmp(next, botnetnick))
    ptr2->uplink = (tand_t *) 1;
  else
    ptr2->uplink = findbot(next);
  tands++;
}

void updatebot(int idx, char *who, char share, int vernum)
{
  tand_t *ptr = findbot(who);

  if (ptr) {
    if (share)
      ptr->share = share;
    if (vernum)
      ptr->ver = vernum;
    botnet_send_update(idx, ptr);
  }
}

/* For backward 1.0 compatibility:
 * grab the (first) sock# for a user on another bot
 */
int partysock(char *bot, char *nick)
{
  int i;

  for (i = 0; i < parties; i++) {
    if ((!strcasecmp(party[i].bot, bot)) &&
        (!strcasecmp(party[i].nick, nick)))
      return party[i].sock;
  }
  return 0;
}

/* Set the botnetnick and truncate as necessary */
void set_botnetnick(const char *newnick) {
  strlcpy(botnetnick, newnick, sizeof botnetnick);
}

/* New botnet member
 */
int addparty(char *bot, char *nick, int chan, char flag, int sock,
             char *from, int *idx)
{
  int i;

  for (i = 0; i < parties; i++) {
    /* Just changing the channel of someone already on? */
    if (!strcasecmp(party[i].bot, bot) && (party[i].sock == sock)) {
      int oldchan = party[i].chan;

      party[i].chan = chan;
      party[i].timer = now;
      if (from[0]) {
        if (flag == ' ')
          flag = '-';
        party[i].flag = flag;
        if (party[i].from)
          nfree(party[i].from);
        party[i].from = nmalloc(strlen(from) + 1);
        strlcpy(party[i].from, from, sizeof(party[i].from));
      }
      *idx = i;
      return oldchan;
    }
  }
  /* New member */
  if (!party_size) {
      party_size = 1;
      party = nmalloc(party_size * sizeof(party_t));
  }
  else if (parties == party_size) {
    party_size <<= 1;
    party = nrealloc(party, party_size * sizeof(party_t));
    debug1("botnet: party size doubled to %i.", party_size);
  }
  strlcpy(party[parties].nick, nick, HANDLEN + 1);
  strlcpy(party[parties].bot, bot, HANDLEN + 1);
  party[parties].chan = chan;
  party[parties].sock = sock;
  party[parties].status = 0;
  party[parties].away = 0;
  party[parties].timer = now;   /* cope. */
  if (from[0]) {
    if (flag == ' ')
      flag = '-';
    party[parties].flag = flag;
    party[parties].from = nmalloc(strlen(from) + 1);
    strlcpy(party[parties].from, from, sizeof(party[parties].from));
  } else {
    party[parties].flag = ' ';
    party[parties].from = nmalloc(10);
    strlcpy(party[parties].from, "(unknown)", sizeof(party[parties].from));
  }
  *idx = parties;
  parties++;
  return -1;
}

/* Alter status flags for remote party-line user.
 */
void partystat(char *bot, int sock, int add, int rem)
{
  int i;

  for (i = 0; i < parties; i++) {
    if ((!strcasecmp(party[i].bot, bot)) && (party[i].sock == sock)) {
      party[i].status |= add;
      party[i].status &= ~rem;
    }
  }
}

/* Other bot is sharing idle info.
 */
void partysetidle(char *bot, int sock, int secs)
{
  int i;

  for (i = 0; i < parties; i++) {
    if ((!strcasecmp(party[i].bot, bot)) && (party[i].sock == sock)) {
      party[i].timer = (now - (time_t) secs);
    }
  }
}

/* Return someone's chat channel.
 */
int getparty(char *bot, int sock)
{
  int i;

  for (i = 0; i < parties; i++) {
    if (!strcasecmp(party[i].bot, bot) && (party[i].sock == sock)) {
      return i;
    }
  }
  return -1;
}

/* Un-idle someone
 */
int partyidle(char *bot, char *nick)
{
  bool ok = false;

  for (int i = 0; i < parties; i++) {
    if ((!strcasecmp(party[i].bot, bot)) &&
        (!strcasecmp(party[i].nick, nick))) {
      party[i].timer = now;
      ok = true;
    }
  }
  return ok;
}

/* Change someone's nick
 */
int partynick(char *bot, int sock, char *nick)
{
  char work[HANDLEN + 1];
  int i;

  for (i = 0; i < parties; i++) {
    if (!strcasecmp(party[i].bot, bot) && (party[i].sock == sock)) {
      strlcpy(work, party[i].nick, sizeof(work));
      strlcpy(party[i].nick, nick, HANDLEN + 1);
      strlcpy(nick, work, sizeof(nick));
      return i;
    }
  }
  return -1;
}

/* Set away message
 */
void partyaway(char *bot, int sock, char *msg)
{
  int i;

  for (i = 0; i < parties; i++) {
    if ((!strcasecmp(party[i].bot, bot)) && (party[i].sock == sock)) {
      if (party[i].away)
        nfree(party[i].away);
      if (msg[0]) {
        party[i].away = nmalloc(strlen(msg) + 1);
        strlcpy(party[i].away, msg, sizeof(party[i].away));
      } else
        party[i].away = 0;
    }
  }
}

/* Remove a tandem bot from the chain list. */
void rembot(char *whoin)
{
  tand_t **ptr = &tandbot, *ptr2;
  struct userrec *u;
  char *who = NULL;
  size_t len = 0;

  /* Need to save the nick for later as it MAY be a pointer to ptr->bot, and we free(ptr) in here. */
  len = strlen(whoin);
  who = nmalloc(len + 1);
  strlcpy(who, whoin, len + 1);

  while (*ptr) {
    if (!strcasecmp((*ptr)->bot, who))
      break;
    ptr = &((*ptr)->next);
  }
  if (!*ptr) {
    /* May have just .unlink *'d. */
    nfree(who);
    return;
  }
  check_tcl_disc(who);

  u = get_user_by_handle(userlist, who);
  if (u != NULL)
    touch_laston(u, "unlinked", now);

  ptr2 = *ptr;
  *ptr = ptr2->next;
  op_bh_free(tand_bh, ptr2);
  tands--;

  dupwait_notify(who);
  nfree(who);
}

void remparty(char *bot, int sock)
{
  int i;

  for (i = 0; i < parties; i++)
    if ((!strcasecmp(party[i].bot, bot)) && (party[i].sock == sock)) {
      parties--;
      if (party[i].from)
        nfree(party[i].from);
      if (party[i].away)
        nfree(party[i].away);
      if (i < parties) {
        strlcpy(party[i].bot, party[parties].bot, sizeof(party[i].bot));
        strlcpy(party[i].nick, party[parties].nick, sizeof(party[i].nick));
        party[i].chan = party[parties].chan;
        party[i].sock = party[parties].sock;
        party[i].flag = party[parties].flag;
        party[i].status = party[parties].status;
        party[i].timer = party[parties].timer;
        party[i].from = party[parties].from;
        party[i].away = party[parties].away;
      }
    }
}

/* Cancel every user that was on a certain bot
 */
static void rempartybot(char *bot)
{
  int i;

  for (i = 0; i < parties; i++)
    if (!strcasecmp(party[i].bot, bot)) {
      if (party[i].chan >= 0)
        check_tcl_chpt(bot, party[i].nick, party[i].sock, party[i].chan);
      remparty(bot, party[i].sock);
      i--;
    }
}

/* Remove every bot linked 'via' bot <x>
 */
void unvia(int idx, tand_t *who)
{
  tand_t *bot, *bot2;

  if (!who)
    return;                     /* Safety */
  rempartybot(who->bot);
  bot = tandbot;
  while (bot) {
    if (bot->uplink == who) {
      unvia(idx, bot);
      bot2 = bot->next;
      rembot(bot->bot);
      bot = bot2;
    } else
      bot = bot->next;
  }
#ifndef NO_OLD_BOTNET
  /* Every bot unvia's bots behind anyway, so why send msg's for
   * EVERY one? - will this break things?!
   */
  tandout_but(idx, "unlinked %s\n", who->bot);
#endif
}

/* Return index into dcc list of the bot that connects us to bot <x>
 */
int nextbot(char *who)
{
  int j;
  tand_t *bot = findbot(who);

  if (!bot)
    return -1;

  for (j = 0; j < dcc_total; j++)
    if (bot->via && !strcasecmp(bot->via->bot, dcc[j].nick) &&
        (dcc[j].type == &DCC_BOT))
      return j;
  return -1;                    /* We're not connected to 'via' */
}

/* Return name of the bot that is directly connected to bot X
 */
char *lastbot(char *who)
{
  tand_t *bot = findbot(who);

  if (!bot)
    return "*";
  else if (bot->uplink == (tand_t *) 1)
    return botnetnick;
  else
    return bot->uplink->bot;
}

/* Modern version of 'whom' (use local data)
 */
void answer_local_whom(int idx, int chan)
{
  op_strbuf_t format;
  char c;
  int i, t, nicklen, botnicklen, total = 0;

  if (chan == -1)
    dprintf(idx, "%s (+: %s, *: %s)\n", BOT_BOTNETUSERS, BOT_PARTYLINE,
            BOT_LOCALCHAN);
  else if (chan > 0) {
#ifdef HAVE_TCL
    {
      op_strbuf_t tcl_cmd;
      op_strbuf_printf(&tcl_cmd, "assoc %d", chan);
      if ((Tcl_Eval(interp, op_strbuf_str(&tcl_cmd)) != TCL_OK) || tcl_resultempty())
        dprintf(idx, "%s %s%d:\n", BOT_USERSONCHAN,
                (chan < GLOBAL_CHANS) ? "" : "*", chan % GLOBAL_CHANS);
      else
        dprintf(idx, "%s '%s%s' (%s%d):\n", BOT_USERSONCHAN,
                (chan < GLOBAL_CHANS) ? "" : "*", tcl_resultstring(),
                (chan < GLOBAL_CHANS) ? "" : "*", chan % GLOBAL_CHANS);
      op_strbuf_free(&tcl_cmd);
    }
#else
    dprintf(idx, "%s %s%d:\n", BOT_USERSONCHAN,
            (chan < GLOBAL_CHANS) ? "" : "*", chan % GLOBAL_CHANS);
#endif /* HAVE_TCL */
  }
  /* Find longest nick and botnick */
  nicklen = botnicklen = 0;
  for (i = 0; i < dcc_total; i++)
    if (dcc[i].type == &DCC_CHAT) {
      if ((chan == -1) || ((chan >= 0) && (dcc[i].u.chat->channel == chan))) {
        t = strlen(dcc[i].nick);
        if (t > nicklen)
          nicklen = t;
        t = strlen(botnetnick);
        if (t > botnicklen)
          botnicklen = t;
      }
    }
  for (i = 0; i < parties; i++) {
    if ((chan == -1) || ((chan >= 0) && (party[i].chan == chan))) {
      t = strlen(party[i].nick);
      if (t > nicklen)
        nicklen = t;
      t = strlen(party[i].bot);
      if (t > botnicklen)
        botnicklen = t;
    }
  }
  if (nicklen < 9)
    nicklen = 9;
  if (botnicklen < 9)
    botnicklen = 9;

  op_strbuf_printf(&format, "%%-%us   %%-%us  %%s\n", nicklen, botnicklen);
  dprintf(idx, op_strbuf_str(&format), " Nick", " Bot", " Host");
  dprintf(idx, op_strbuf_str(&format), "----------", "---------", "--------------------");
  op_strbuf_reset(&format, "%%c%%-%us %%c %%-%us  %%s%%s\n", nicklen, botnicklen);
  for (i = 0; i < dcc_total; i++)
    if (dcc[i].type == &DCC_CHAT) {
      if ((chan == -1) || ((chan >= 0) && (dcc[i].u.chat->channel == chan))) {
        op_strbuf_t idle;
        op_strbuf_init(&idle);
        c = geticon(i);
        if (c == '-')
          c = ' ';
        if (now - dcc[i].timeval > 300) {
          uint64_t days, hrs, mins;

          days = (now - dcc[i].timeval) / 86400;
          hrs = ((now - dcc[i].timeval) - (days * 86400)) / 3600;
          mins = ((now - dcc[i].timeval) - (hrs * 3600)) / 60;
          if (days > 0)
            op_strbuf_printf(&idle, " [idle %" PRIu64 "d%" PRIu64 "h]", days, hrs);
          else if (hrs > 0)
            op_strbuf_printf(&idle, " [idle %" PRIu64 "h%" PRIu64 "m]", hrs, mins);
          else
            op_strbuf_printf(&idle, " [idle %" PRIu64 "m]", mins);
        }
        total++;
        dprintf(idx, op_strbuf_str(&format), c, dcc[i].nick,
                (dcc[i].u.chat->channel == 0) && (chan == -1) ? '+' :
                (dcc[i].u.chat->channel >= GLOBAL_CHANS) &&
                (chan == -1) ? '*' : ' ', botnetnick, dcc[i].host,
                op_strbuf_str(&idle));
        op_strbuf_free(&idle);
        if (dcc[i].u.chat->away != NULL)
          dprintf(idx, "   AWAY: %s\n", dcc[i].u.chat->away);
      }
    }
  for (i = 0; i < parties; i++) {
    if ((chan == -1) || ((chan >= 0) && (party[i].chan == chan))) {
      op_strbuf_t idle;
      op_strbuf_init(&idle);
      c = party[i].flag;
      if (c == '-')
        c = ' ';
      if (party[i].timer == 0L)
        op_strbuf_printf(&idle, " [idle?]");
      else if (now - party[i].timer > 300) {
        uint64_t days, hrs, mins;

        days = (now - party[i].timer) / 86400;
        hrs = ((now - party[i].timer) - (days * 86400)) / 3600;
        mins = ((now - party[i].timer) - (hrs * 3600)) / 60;
        if (days > 0)
          op_strbuf_printf(&idle, " [idle %" PRIu64 "d%" PRIu64 "h]", days, hrs);
        else if (hrs > 0)
          op_strbuf_printf(&idle, " [idle %" PRIu64 "h%" PRIu64 "m]", hrs, mins);
        else
          op_strbuf_printf(&idle, " [idle %" PRIu64 "m]", mins);
      }
      total++;
      dprintf(idx, op_strbuf_str(&format), c, party[i].nick,
              (party[i].chan == 0) && (chan == -1) ? '+' : ' ',
              party[i].bot, party[i].from, op_strbuf_str(&idle));
      op_strbuf_free(&idle);
      if (party[i].status & PLSTAT_AWAY)
        dprintf(idx, "   %s: %s\n", MISC_AWAY,
                party[i].away ? party[i].away : "");
    }
  }
  dprintf(idx, "Total users: %d\n", total);
  op_strbuf_free(&format);
}

/* Show z a list of all bots connected
 */
void tell_bots(int idx)
{
  if (!tands) {
    dprintf(idx, "%s\n", BOT_NOBOTSLINKED);
    return;
  }
  op_strbuf_t s;
  op_strbuf_init(&s);
  op_strbuf_append_cstr(&s, botnetnick);

  for (tand_t *bot = tandbot; bot; bot = bot->next) {
    if (op_strbuf_len(&s) > (size_t)(500 - HANDLEN)) {
      dprintf(idx, "Bots: %s\n", op_strbuf_str(&s));
      op_strbuf_clear(&s);
    }
    if (op_strbuf_len(&s))
      op_strbuf_append_cstr(&s, ", ");
    op_strbuf_append_cstr(&s, bot->bot);
  }
  if (op_strbuf_len(&s))
    dprintf(idx, "Bots: %s\n", op_strbuf_str(&s));
  op_strbuf_free(&s);
  dprintf(idx, "%s: %d\n", MISC_TOTAL, tands + 1);
}

/* Show a simpleton bot tree
 */
void tell_bottree(int idx, int showver)
{
  char s[161];
  char c = '-';
  tand_t *last[20], *this, *bot, *bot2 = NULL, *lastbot = NULL;
  int lev = 0, more = 1, mark[20], cnt, i, imark;
  bool ok = false;
  char work[1024];
  int tothops = 0;

  if (tands == 0) {
    dprintf(idx, "%s\n", BOT_NOBOTSLINKED);
    return;
  }
  s[0] = 0;
  i = 0;

  for (bot = tandbot; bot; bot = bot->next) {
    if (!bot->uplink) {
      if (i) {
        s[i++] = ',';
        s[i++] = ' ';
      }
      strlcpy(s + i, bot->bot, sizeof(s) - i);
      i += strlen(bot->bot);
    }
  }
  dprintf(idx, "- Link    = Encrypted link    + Userfile Sharing\n");
  dprintf(idx, "------------------------------------------------\n");
  if (s[0])
    dprintf(idx, "(%s %s)\n", BOT_NOTRACEINFO, s);
  if (showver)
    dprintf(idx, "%s (%d.%d.%d.%d)\n", botnetnick,
            egg_numver / 1000000,
            egg_numver % 1000000 / 10000,
            egg_numver % 10000 / 100, egg_numver % 100);
  else
    dprintf(idx, "%s\n", botnetnick);
  this = (tand_t *) 1;
  work[0] = 0;
  while (more) {
    if (lev == 20) {
      dprintf(idx, "\n%s\n", BOT_COMPLEXTREE);
      return;
    }
    cnt = 0;
    tothops += lev;
    for (bot = tandbot; bot; bot = bot->next)
      if (bot->uplink == this)
        cnt++;
    bot = tandbot;
    if (cnt) {
      imark = 0;
      for (i = 0; i < lev; i++) {
        if (mark[i])
          strlcpy(work + imark, "  |  ", sizeof(work) - imark);
        else
          strlcpy(work + imark, "     ", sizeof(work) - imark);
        imark += 5;
      }
      if (cnt > 1) {
        if (bot->ssl) {
          strlcpy(work + imark, "  |=", sizeof(work) - imark);
        } else {
          strlcpy(work + imark, "  |-", sizeof(work) - imark);
        }
      } else {
        if (bot->ssl) {
          strlcpy(work + imark, "  `=", sizeof(work) - imark);
        } else {
          strlcpy(work + imark, "  `-", sizeof(work) - imark);
        }
      }
      s[0] = 0;
      bot = tandbot;
      while (!s[0]) {
        if (bot->uplink == this) {
          op_strbuf_t line;
          if (bot->ver) {
            if ((bot->share=='-') && (bot->ssl)) {
              c = '=';
            } else {
              c = bot->share;
            }
            op_strbuf_printf(&line, "%c%s", c, bot->bot);
            if (showver)
              op_strbuf_appendf(&line, " (%d.%d.%d.%d)",
                      bot->ver / 1000000,
                      bot->ver % 1000000 / 10000,
                      bot->ver % 10000 / 100, bot->ver % 100);
          } else
            op_strbuf_printf(&line, "-%s", bot->bot);
          strlcpy(s, op_strbuf_str(&line), sizeof(s));
          op_strbuf_free(&line);
        } else
          bot = bot->next;
      }
      dprintf(idx, "%s%s\n", work, s);
      if (cnt > 1)
        mark[lev] = 1;
      else
        mark[lev] = 0;
      work[0] = 0;
      last[lev] = this;
      this = bot;
      lev++;
      more = 1;
    } else {
      while (cnt == 0) {
        /* No subtrees from here */
        if (lev == 0) {
          dprintf(idx, "(( tree error ))\n");
          return;
        }
        ok = false;
        for (bot = tandbot; bot; bot = bot->next) {
          if (bot->uplink == last[lev - 1]) {
            if (this == bot)
              ok = true;
            else if (ok) {
              cnt++;
              if (cnt == 1) {
                op_strbuf_t line;
                bot2 = bot;
                if (bot->ver) {
                  if ((bot->share=='-') && (bot->ssl)) {
                    c = '=';
                  } else {
                    c = bot->share;
                  }
                  op_strbuf_printf(&line, "%c%s", c, bot->bot);
                  if (showver)
                    op_strbuf_appendf(&line, " (%d.%d.%d.%d)",
                            bot->ver / 1000000,
                            bot->ver % 1000000 / 10000,
                            bot->ver % 10000 / 100, bot->ver % 100);
                } else
                  op_strbuf_printf(&line, "-%s", bot->bot);
                strlcpy(s, op_strbuf_str(&line), sizeof(s));
                op_strbuf_free(&line);
              }
            }
          }
          lastbot = bot;
        }
        if (cnt) {
          imark = 0;
          for (i = 1; i < lev; i++) {
            if (mark[i - 1])
              strlcpy(work + imark, "  |  ", sizeof(work) - imark);
            else
              strlcpy(work + imark, "     ", sizeof(work) - imark);
            imark += 5;
          }
          more = 1;
          if (cnt > 1)
            dprintf(idx, "%s  |%s%s\n", work, lastbot->ssl ? "=" : "-", s);
          else
            dprintf(idx, "%s  `%s%s\n", work, lastbot->ssl ? "=" : "-", s);
          this = bot2;
          work[0] = 0;
          if (cnt > 1)
            mark[lev - 1] = 1;
          else
            mark[lev - 1] = 0;
        } else {
          /* This was the last child */
          lev--;
          if (lev == 0) {
            more = 0;
            cnt = 999;
          } else {
            more = 1;
            this = last[lev];
          }
        }
      }
    }
  }
  /* Hop information: (9d) */
  dprintf(idx, "------------------------------------------------\n");
  dprintf(idx, "Average hops: %3.1f, total bots: %d\n",
          ((float) tothops) / ((float) tands), tands + 1);
}

/* Dump list of links to a new bot
 */
void dump_links(int z)
{
  char x[1024];

  for (tand_t *bot = tandbot; bot; bot = bot->next) {
    char *p = (bot->uplink == (tand_t *) 1) ? botnetnick : bot->uplink->bot;
#ifndef NO_OLD_BOTNET
    if (b_numver(z) < NEAT_BOTNET) {
      op_strbuf_t _b;
      op_strbuf_printf(&_b, "nlinked %s %s %c%d\n", bot->bot,
                       p, bot->share, bot->ver);
      dprint(z, (char *)op_strbuf_str(&_b), (int) op_strbuf_len(&_b));
      op_strbuf_free(&_b);
    } else
#endif
    {
      int l = simple_sprintf(x, "n %s %s %c%D\n", bot->bot, p,
                             bot->share, bot->ver);
      dprint(z, x, l);
    }
  }
  if (!(bot_flags(dcc[z].user) & BOT_ISOLATE)) {
    /* Dump party line members */
    for (int i = 0; i < dcc_total; i++) {
      if (dcc[i].type == &DCC_CHAT) {
        if ((dcc[i].u.chat->channel >= 0) &&
            (dcc[i].u.chat->channel < GLOBAL_CHANS)) {
#ifndef NO_OLD_BOTNET
          if (b_numver(z) < NEAT_BOTNET) {
            op_strbuf_t _b;
            op_strbuf_printf(&_b, "join %s %s %d %c%ld %s\n",
                             botnetnick, dcc[i].nick,
                             dcc[i].u.chat->channel, geticon(i),
                             dcc[i].sock, dcc[i].host);
            dprint(z, (char *)op_strbuf_str(&_b), (int) op_strbuf_len(&_b));
            op_strbuf_free(&_b);
            if (dcc[i].u.chat->away) {
              op_strbuf_t _ba;
              op_strbuf_printf(&_ba, "away %s %ld %s\n", botnetnick,
                               dcc[i].sock, dcc[i].u.chat->away);
              dprint(z, (char *)op_strbuf_str(&_ba), (int) op_strbuf_len(&_ba));
              op_strbuf_free(&_ba);
            }
            op_strbuf_t _bi;
            op_strbuf_printf(&_bi, "idle %s %ld %" PRId64 "\n", botnetnick,
                             dcc[i].sock, (int64_t) (now - dcc[i].timeval));
            dprint(z, (char *)op_strbuf_str(&_bi), (int) op_strbuf_len(&_bi));
            op_strbuf_free(&_bi);
          } else
#endif
          {
            int l = simple_sprintf(x, "j !%s %s %D %c%D %s\n",
                                   botnetnick, dcc[i].nick,
                                   dcc[i].u.chat->channel, geticon(i),
                                   dcc[i].sock, dcc[i].host);
            dprint(z, x, l);
            l = simple_sprintf(x, "i %s %D %D %s\n", botnetnick,
                               dcc[i].sock, now - dcc[i].timeval,
                               dcc[i].u.chat->away ? dcc[i].u.chat->away : "");
            dprint(z, x, l);
          }
        }
      }
    }
    for (int i = 0; i < parties; i++) {
#ifndef NO_OLD_BOTNET
      if (b_numver(z) < NEAT_BOTNET) {
        op_strbuf_t _b;
        op_strbuf_printf(&_b, "join %s %s %d %c%d %s\n",
                         party[i].bot, party[i].nick,
                         party[i].chan, party[i].flag,
                         party[i].sock, party[i].from);
        dprint(z, (char *)op_strbuf_str(&_b), (int) op_strbuf_len(&_b));
        op_strbuf_free(&_b);
        if ((party[i].status & PLSTAT_AWAY) || (party[i].timer != 0)) {
          if (party[i].status & PLSTAT_AWAY) {
            op_strbuf_t _ba;
            op_strbuf_printf(&_ba, "away %s %d %s\n", party[i].bot,
                             party[i].sock, party[i].away);
            dprint(z, (char *)op_strbuf_str(&_ba), (int) op_strbuf_len(&_ba));
            op_strbuf_free(&_ba);
          }
          op_strbuf_t _bi;
          op_strbuf_printf(&_bi, "idle %s %d %" PRId64 "\n", party[i].bot,
                           party[i].sock, (int64_t) (now - party[i].timer));
          dprint(z, (char *)op_strbuf_str(&_bi), (int) op_strbuf_len(&_bi));
          op_strbuf_free(&_bi);
        }
      } else
#endif
      {
        int l = simple_sprintf(x, "j %s %s %D %c%D %s\n",
                               party[i].bot, party[i].nick,
                               party[i].chan, party[i].flag,
                               party[i].sock, party[i].from);
        dprint(z, x, l);
        if ((party[i].status & PLSTAT_AWAY) || (party[i].timer != 0)) {
          l = simple_sprintf(x, "i %s %D %D %s\n", party[i].bot,
                             party[i].sock, now - party[i].timer,
                             party[i].away ? party[i].away : "");
          dprint(z, x, l);
        }
      }
    }
  }
}

int in_chain(char *who)
{
  if (findbot(who))
    return 1;
  if (!strcasecmp(who, botnetnick))
    return 1;
  return 0;
}

int bots_in_subtree(tand_t *bot)
{
  int nr = 1;
  tand_t *b;

  if (!bot)
    return 0;
  for (b = tandbot; b; b = b->next) {
    if (b->bot[0] && (b->uplink == bot)) {
      nr += bots_in_subtree(b);
    }
  }
  return nr;
}

int users_in_subtree(tand_t *bot)
{
  if (!bot)
    return 0;
  int nr = 0;
  for (int i = 0; i < parties; i++)
    if (!strcasecmp(party[i].bot, bot->bot))
      nr++;
  for (tand_t *b = tandbot; b; b = b->next)
    if (b->bot[0] && (b->uplink == bot))
      nr += users_in_subtree(b);
  return nr;
}

/* Break link with a tandembot
 */
int botunlink(int idx, char *nick, char *reason, char *from)
{
  if (nick[0] == '*')
    dprintf(idx, "%s\n", BOT_UNLINKALL);
  for (int i = 0; i < dcc_total; i++) {
    if ((nick[0] == '*') || !strcasecmp(dcc[i].nick, nick)) {
      if (dcc[i].type == &DCC_FORK_BOT) {
        if (idx >= 0)
          dprintf(idx, "%s: %s -> %s.\n", BOT_KILLLINKATTEMPT,
                  dcc[i].nick, dcc[i].host);
        putlog(LOG_BOTS, "*", "%s: %s -> %s:%d",
               BOT_KILLLINKATTEMPT, dcc[i].nick, dcc[i].host, dcc[i].port);
        killsock(dcc[i].sock);
        lostdcc(i);
        if (nick[0] != '*')
          return 1;
      } else if (dcc[i].type == &DCC_BOT_NEW) {
        if (idx >= 0)
          dprintf(idx, "%s %s.\n", BOT_ENDLINKATTEMPT, dcc[i].nick);
        putlog(LOG_BOTS, "*", "%s %s @ %s:%d",
               "Stopped trying to link", dcc[i].nick, dcc[i].host, dcc[i].port);
        killsock(dcc[i].sock);
        lostdcc(i);
        if (nick[0] != '*')
          return 1;
      } else if (dcc[i].type == &DCC_BOT) {
        if (idx >= 0)
          dprintf(idx, "%s %s.\n", BOT_BREAKLINK, dcc[i].nick);
        else if ((idx == -3) && (b_status(i) & STAT_SHARE) && !share_unlinks)
          return -1;
        tand_t *bot = findbot(dcc[i].nick);
        int bots = bots_in_subtree(bot);
        int users = users_in_subtree(bot);
        {
          op_strbuf_t s;
          if (reason && reason[0]) {
            op_strbuf_printf(&s, "%s %s (%s (%s)) (lost %d bot%s and %d user%s)",
                     BOT_UNLINKEDFROM, dcc[i].nick, reason, from, bots,
                     (bots != 1) ? "s" : "", users, (users != 1) ?
                     "s" : "");
            dprintf(i, "bye %s\n", reason);
          } else {
            op_strbuf_printf(&s, "%s %s (%s) (lost %d bot%s and %d user%s)",
                     BOT_UNLINKEDFROM, dcc[i].nick, from, bots,
                     (bots != 1) ? "s" : "", users,
                     (users != 1) ? "s" : "");
            dprintf(i, "bye No reason\n");
          }
          putlog(LOG_BOTS, "*", "%s.", op_strbuf_str(&s));
          dprintf(idx, "%s.\n", op_strbuf_str(&s));
          botnet_send_unlinked(i, dcc[i].nick, op_strbuf_str(&s));
          op_strbuf_free(&s);
        }
        killsock(dcc[i].sock);
        lostdcc(i);
        if (nick[0] != '*')
          return 1;
      }
    }
  }
  if (idx >= 0 && nick[0] != '*')
    dprintf(idx, "%s\n", BOT_NOTCONNECTED);
  if (nick[0] != '*') {
    tand_t *bot = findbot(nick);
    if (bot) {
      /* The internal bot list is desynched from the dcc list
       * sometimes. While we still search for the bug, provide
       * an easy way to clear out those `ghost'-bots.
       * Fabian (2000-08-02)  */
      char *ghost = "BUG!!: Found bot `%s' in internal bot list, but it\n"
                    "   shouldn't have been there! Removing.\n"
                    "   This is a known bug we haven't fixed yet. If this\n"
                    "   bot is the newest eggdrop version available and you\n"
                    "   know a *reliable* way to reproduce the bug, please\n"
                    "   contact us - we need your help!\n";
      if (idx >= 0)
        dprintf(idx, ghost, nick);
      else
        putlog(LOG_MISC, "*", ghost, nick);
      rembot(bot->bot);
      return 1;
    }
  }
  if (nick[0] == '*') {
    dprintf(idx, "%s\n", BOT_WIPEBOTTABLE);
    while (tandbot)
      rembot(tandbot->bot);
    while (parties) {
      parties--;
      /* Assert? */
      if (party[parties].chan >= 0)
        check_tcl_chpt(party[parties].bot, party[parties].nick, party[parties].sock,
                       party[parties].chan);
    }
#ifdef HAVE_TCL
    Tcl_Eval(interp, "killassoc &");
#endif /* HAVE_TCL */
  }
  return 0;
}

static void botlink_resolve_success(int);
static void botlink_resolve_failure(int);

/* Link to another bot
 */
int botlink(char *linker, int idx, char *nick)
{
  struct userrec *u = get_user_by_handle(userlist, nick);
  if (!u || !(u->flags & USER_BOT)) {
    if (idx >= 0)
      dprintf(idx, "%s %s\n", nick, BOT_BOTUNKNOWN);
  } else if (!strcasecmp(nick, botnetnick)) {
    if (idx >= 0)
      dprintf(idx, "%s\n", BOT_CANTLINKMYSELF);
  } else if (in_chain(nick) && (idx != -3)) {
    if (idx >= 0)
      dprintf(idx, "%s\n", BOT_ALREADYLINKED);
  } else if (bot_flags(u) & BOT_REJECT) {
    if (idx >= 0) {
      dprintf(idx, "%s %s\n", BOT_REJECTING, nick);
    }
  } else {
    for (int i = 0; i < dcc_total; i++)
      if ((dcc[i].user == u) &&
          ((dcc[i].type == &DCC_FORK_BOT) || (dcc[i].type == &DCC_BOT_NEW))) {
        if (idx >= 0)
          dprintf(idx, "%s\n", BOT_ALREADYLINKING);
        return 0;
      }
    /* Address to connect to is in 'info' */
    struct bot_addr *bi = (struct bot_addr *) get_user(&USERENTRY_BOTADDR, u);
    if (!bi || !strlen(bi->address) || !bi->telnet_port ||
        (bi->telnet_port <= 0)) {
      if (idx >= 0) {
        dprintf(idx, "%s '%s'.\n", BOT_NOTELNETADDY, nick);
        dprintf(idx, "%s .chaddr %s %s\n",
                MISC_USEFORMAT, nick, MISC_CHADDRFORMAT);
      }
    } else if (dcc_total == max_dcc && increase_socks_max()) {
      if (idx >= 0)
        dprintf(idx, "%s\n", DCC_TOOMANYDCCS1);
    } else {
      correct_handle(nick);

      if (idx > -2)
#ifdef IPV6
      {
        if (strchr(bi->address, ':'))
          putlog(LOG_BOTS, "*", "%s %s at [%s]:%d ...", BOT_LINKING, nick,
                 bi->address, bi->telnet_port);
        else
          putlog(LOG_BOTS, "*", "%s %s at %s:%d ...", BOT_LINKING, nick,
                 bi->address, bi->telnet_port);
      }
#else
        putlog(LOG_BOTS, "*", "%s %s at %s:%d ...", BOT_LINKING, nick,
               bi->address, bi->telnet_port);
#endif
      int i = new_dcc(&DCC_DNSWAIT, sizeof(struct dns_info));
      dcc[i].timeval = now;
      dcc[i].port = bi->telnet_port;
#ifdef TLS
      dcc[i].ssl = (bi->ssl & TLS_BOT);
#endif
      dcc[i].user = u;
      strlcpy(dcc[i].nick, nick, sizeof(dcc[i].nick));
      strlcpy(dcc[i].host, bi->address, sizeof(dcc[i].host));
      dcc[i].u.dns->ibuf = idx;
      dcc[i].u.dns->cptr = get_data_ptr(strlen(linker) + 1);
      strlcpy(dcc[i].u.dns->cptr, linker, sizeof(dcc[i].u.dns->cptr));
      dcc[i].u.dns->host = get_data_ptr(strlen(dcc[i].host) + 1);
      strlcpy(dcc[i].u.dns->host, dcc[i].host, sizeof(dcc[i].u.dns->host));
      dcc[i].u.dns->dns_success = botlink_resolve_success;
      dcc[i].u.dns->dns_failure = botlink_resolve_failure;
      dcc[i].u.dns->dns_type = RES_IPBYHOST;
      dcc[i].u.dns->type = &DCC_FORK_BOT;
      dcc_dnsipbyhost(bi->address);
      return 1;
    }
  }
  return 0;
}

static void botlink_resolve_failure(int i)
{
  char s[81];

  putlog(LOG_BOTS, "*", DCC_LINKFAIL, dcc[i].nick);
  strlcpy(s, dcc[i].nick, sizeof(s));
  nfree(dcc[i].u.dns->cptr);
  lostdcc(i);
  autolink_cycle(s);            /* Check for more auto-connections */
}

static void botlink_resolve_success(int i)
{
  int idx = dcc[i].u.dns->ibuf;
  char *linker = dcc[i].u.dns->cptr;

  changeover_dcc(i, &DCC_FORK_BOT, sizeof(struct bot_info));
  dcc[i].timeval = now;
  strlcpy(dcc[i].u.bot->linker, linker, sizeof dcc[i].u.bot->linker);
  strlcpy(dcc[i].u.bot->version, "(primitive bot)", sizeof(dcc[i].u.bot->version));
  dcc[i].u.bot->numver = idx;
  dcc[i].u.bot->port = dcc[i].port;     /* Remember where i started */
#ifdef TLS
  dcc[i].u.bot->ssl = dcc[i].ssl;       /* Remember where I started */
#endif
  nfree(linker);
  setsnport(dcc[i].sockname, dcc[i].port);
  dcc[i].sock = getsock(dcc[i].sockname.family, SOCK_STRONGCONN);
  if (dcc[i].sock < 0 || open_telnet_raw(dcc[i].sock, &dcc[i].sockname) < 0) {
    failed_link(i);
  }
#ifdef TLS
  else if (dcc[i].ssl && ssl_handshake(dcc[i].sock, TLS_CONNECT,
           tls_vfybots, LOG_BOTS, dcc[i].host, NULL)) {
    failed_link(i);
  }
#endif
}

static void failed_tandem_relay(int idx)
{
  int uidx = -1;

  for (int i = 0; i < dcc_total; i++)
    if ((dcc[i].type == &DCC_PRE_RELAY) &&
        (dcc[i].u.relay->sock == dcc[idx].sock))
      uidx = i;
  if (uidx < 0) {
    putlog(LOG_MISC, "*", "%s  %ld -> %d", BOT_CANTFINDRELAYUSER,
           dcc[idx].sock, dcc[idx].u.relay->sock);
    killsock(dcc[idx].sock);
    lostdcc(idx);
    return;
  }
  dprintf(uidx, "%s %s.\n", BOT_CANTLINKTO, dcc[idx].nick);
  dcc[uidx].status = dcc[uidx].u.relay->old_status;
  struct chat_info *ci = dcc[uidx].u.relay->chat;
  nfree(dcc[uidx].u.relay);
  dcc[uidx].u.chat = ci;
  dcc[uidx].type = &DCC_CHAT;
  killsock(dcc[idx].sock);
  lostdcc(idx);
  return;
}


static void tandem_relay_resolve_failure(int);
static void tandem_relay_resolve_success(int);

/* Relay to another tandembot
 */
void tandem_relay(int idx, char *nick, int i)
{
  struct userrec *u;
  struct bot_addr *bi;
  struct chat_info *ci;

  u = get_user_by_handle(userlist, nick);
  if (!u || !(u->flags & USER_BOT)) {
    dprintf(idx, "%s %s\n", nick, BOT_BOTUNKNOWN);
    return;
  }
  if (!strcasecmp(nick, botnetnick)) {
    dprintf(idx, "%s\n", BOT_CANTRELAYMYSELF);
    return;
  }
  /* Address to connect to is in 'info' */
  bi = (struct bot_addr *) get_user(&USERENTRY_BOTADDR, u);
  if (!bi || !strlen(bi->address) || !bi->relay_port || (bi->relay_port <= 0)) {
    dprintf(idx, "%s '%s'.\n", BOT_NOTELNETADDY, nick);
    dprintf(idx, "%s .chaddr %s %s\n", MISC_USEFORMAT, nick,
            MISC_CHADDRFORMAT);
    return;
  }
  i = new_dcc(&DCC_DNSWAIT, sizeof(struct dns_info));
  if (i < 0) {
    dprintf(idx, "%s\n", DCC_TOOMANYDCCS1);
    return;
  }

  dcc[i].sock = getsock(AF_INET, SOCK_STRONGCONN | SOCK_VIRTUAL);
  if (dcc[i].sock < 0) {
    lostdcc(i);
    dprintf(idx, "%s\n", MISC_NOFREESOCK);
    return;
  }

  dcc[i].port = bi->relay_port;
#ifdef TLS
  dcc[i].ssl = (bi->ssl & TLS_RELAY);
#endif
  dcc[i].addr = 0L;
  strlcpy(dcc[i].nick, nick, sizeof(dcc[i].nick));
  dcc[i].user = u;
  strlcpy(dcc[i].host, bi->address, sizeof(dcc[i].host));
#ifdef IPV6
  if (strchr(bi->address, ':'))
    dprintf(idx, "%s %s @ [%s]:%d ...\n", BOT_CONNECTINGTO, nick,
            bi->address, bi->relay_port);
  else
#endif
  dprintf(idx, "%s %s @ %s:%d ...\n", BOT_CONNECTINGTO, nick,
          bi->address, bi->relay_port);
  dprintf(idx, "%s\n", BOT_BYEINFO1);
  dcc[idx].type = &DCC_PRE_RELAY;
  ci = dcc[idx].u.chat;
  dcc[idx].u.relay = get_data_ptr(sizeof(struct relay_info));
  dcc[idx].u.relay->chat = ci;
  dcc[idx].u.relay->old_status = dcc[idx].status;
  dcc[i].timeval = now;
  dcc[idx].u.relay->sock = dcc[i].sock;
  dcc[i].u.dns->ibuf = dcc[idx].sock;
  dcc[i].u.dns->host = get_data_ptr(strlen(bi->address) + 1);
  strlcpy(dcc[i].u.dns->host, bi->address, sizeof(dcc[i].u.dns->host));
  dcc[i].u.dns->dns_success = tandem_relay_resolve_success;
  dcc[i].u.dns->dns_failure = tandem_relay_resolve_failure;
  dcc[i].u.dns->dns_type = RES_IPBYHOST;
  dcc[i].u.dns->type = &DCC_FORK_RELAY;
  dcc_dnsipbyhost(bi->address);
}

static void tandem_relay_resolve_failure(int idx)
{
  int uidx = -1;

  for (int i = 0; i < dcc_total; i++)
    if ((dcc[i].type == &DCC_PRE_RELAY) &&
        (dcc[i].u.relay->sock == dcc[idx].sock)) {
      uidx = i;
      break;
    }
  if (uidx < 0) {
    putlog(LOG_MISC, "*", "%s  %ld -> %d", BOT_CANTFINDRELAYUSER,
           dcc[idx].sock, dcc[idx].u.relay->sock);
    killsock(dcc[idx].sock);
    lostdcc(idx);
    return;
  }
  struct chat_info *ci = dcc[uidx].u.relay->chat;
  dprintf(uidx, "%s %s.\n", BOT_CANTLINKTO, dcc[idx].nick);
  dcc[uidx].status = dcc[uidx].u.relay->old_status;
  nfree(dcc[uidx].u.relay);
  dcc[uidx].u.chat = ci;
  dcc[uidx].type = &DCC_CHAT;
  killsock(dcc[idx].sock);
  lostdcc(idx);
}

static void tandem_relay_resolve_success(int i)
{
  int sock = dcc[i].u.dns->ibuf;

  changeover_dcc(i, &DCC_FORK_RELAY, sizeof(struct relay_info));
  dcc[i].u.relay->chat = get_data_ptr(sizeof(struct chat_info));

  dcc[i].u.relay->sock = sock;
  dcc[i].u.relay->port = dcc[i].port;
  dcc[i].u.relay->chat->away = NULL;
  dcc[i].u.relay->chat->msgs_per_sec = 0;
  dcc[i].u.relay->chat->con_flags = 0;
  dcc[i].u.relay->chat->buffer = NULL;
  dcc[i].u.relay->chat->max_line = 0;
  dcc[i].u.relay->chat->line_count = 0;
  dcc[i].u.relay->chat->current_lines = 0;
  dcc[i].timeval = now;
#ifdef IPV6
  if (dcc[i].sockname.family == AF_INET6) {
    killsock(dcc[i].sock);
    dcc[i].sock = getsock(AF_INET6, SOCK_STRONGCONN | SOCK_VIRTUAL);
    dcc[i].sockname.addr.s6.sin6_port = htons(dcc[i].port);
    dcc[i].u.relay->sock = dcc[i].sock;
  } else
#endif
    dcc[i].sockname.addr.s4.sin_port = htons(dcc[i].port);
  if (open_telnet_raw(dcc[i].sock, &dcc[i].sockname) < 0)
    failed_tandem_relay(i);
#ifdef TLS
  else if (dcc[i].ssl && ssl_handshake(dcc[i].sock, TLS_CONNECT,
           tls_vfybots, LOG_BOTS, dcc[i].host, NULL))
    failed_tandem_relay(i);
#endif
}

/* Input from user before connect is ready
 */
static void pre_relay(int idx, char *buf, int i)
{
  int tidx = -1;

  for (i = 0; i < dcc_total; i++)
    if ((dcc[i].type == &DCC_FORK_RELAY) &&
        (dcc[i].u.relay->sock == dcc[idx].sock)) {
      tidx = i;
      break;
    }
  if (tidx < 0) {
    /* Now try to find it among the DNSWAIT sockets instead. */
    for (i = 0; i < dcc_total; i++)
      if ((dcc[i].type == &DCC_DNSWAIT) &&
          (dcc[i].sock == dcc[idx].u.relay->sock)) {
        tidx = i;
        break;
      }
  }
  if (tidx < 0) {
    putlog(LOG_MISC, "*", "%s  %ld -> %d", BOT_CANTFINDRELAYUSER,
           dcc[idx].sock, dcc[idx].u.relay->sock);
    killsock(dcc[idx].sock);
    lostdcc(idx);
    return;
  }
  if (!strcasecmp(buf, "*bye*")) {
    /* Disconnect */
    struct chat_info *ci = dcc[idx].u.relay->chat;

    dprintf(idx, "%s %s.\n", BOT_ABORTRELAY1, dcc[tidx].nick);
    dprintf(idx, "%s %s.\n\n", BOT_ABORTRELAY2, botnetnick);
    putlog(LOG_MISC, "*", "%s %s -> %s", BOT_ABORTRELAY3, dcc[idx].nick,
           dcc[tidx].nick);
    dcc[idx].status = dcc[idx].u.relay->old_status;
    nfree(dcc[idx].u.relay);
    dcc[idx].u.chat = ci;
    dcc[idx].type = &DCC_CHAT;
    killsock(dcc[tidx].sock);
    lostdcc(tidx);
    return;
  }
}

/* User disconnected before her relay had finished connecting
 */
static void failed_pre_relay(int idx)
{
  int tidx = -1;

  for (int i = 0; i < dcc_total; i++)
    if ((dcc[i].type == &DCC_FORK_RELAY) &&
        (dcc[i].u.relay->sock == dcc[idx].sock)) {
      tidx = i;
      break;
    }
  if (tidx < 0) {
    /* Now try to find it among the DNSWAIT sockets instead. */
    for (int i = 0; i < dcc_total; i++)
      if ((dcc[i].type == &DCC_DNSWAIT) &&
          (dcc[i].sock == dcc[idx].u.relay->sock)) {
        tidx = i;
        break;
      }
  }
  if (tidx < 0) {
    putlog(LOG_MISC, "*", "%s  %ld -> %d", BOT_CANTFINDRELAYUSER,
           dcc[idx].sock, dcc[idx].u.relay->sock);
    killsock(dcc[idx].sock);
    lostdcc(idx);
    return;
  }
  putlog(LOG_MISC, "*", "%s [%s]%s/%d", BOT_LOSTDCCUSER, dcc[idx].nick,
         dcc[idx].host, dcc[idx].port);
  putlog(LOG_MISC, "*", "(%s %s)", BOT_DROPPINGRELAY, dcc[tidx].nick);
  if ((dcc[tidx].sock != STDOUT) || backgrd) {
    if (idx > tidx) {
      int t = tidx;

      tidx = idx;
      idx = t;
    }
    killsock(dcc[tidx].sock);
    lostdcc(tidx);
  } else
    fatal("Lost my terminal?!", 0);
  killsock(dcc[idx].sock);
  lostdcc(idx);
}

static void cont_tandem_relay(int idx, char *buf, int i)
{
  int uidx = -1;
  struct relay_info *ri;

  for (i = 0; i < dcc_total; i++)
    if ((dcc[i].type == &DCC_PRE_RELAY) &&
        (dcc[i].u.relay->sock == dcc[idx].sock))
      uidx = i;
  if (uidx < 0) {
    putlog(LOG_MISC, "*", "%s  %ld -> %d", BOT_CANTFINDRELAYUSER,
           dcc[i].sock, dcc[i].u.relay->sock);
    killsock(dcc[i].sock);
    lostdcc(i);
    return;
  }
  dcc[idx].type = &DCC_RELAY;
  dcc[idx].u.relay->sock = dcc[uidx].sock;
  dcc[uidx].u.relay->sock = dcc[idx].sock;
  dprintf(uidx, "%s %s ...\n", BOT_RELAYSUCCESS, dcc[idx].nick);
  dprintf(uidx, "%s\n\n", BOT_BYEINFO2);
  putlog(LOG_MISC, "*", "%s %s -> %s", BOT_RELAYLINK,
         dcc[uidx].nick, dcc[idx].nick);
  ri = dcc[uidx].u.relay;       /* YEAH */
  dcc[uidx].type = &DCC_CHAT;
  dcc[uidx].u.chat = ri->chat;
  if (dcc[uidx].u.chat->channel >= 0) {
    chanout_but(-1, dcc[uidx].u.chat->channel, "*** %s %s\n",
                dcc[uidx].nick, BOT_PARTYLEFT);
    if (dcc[uidx].u.chat->channel < GLOBAL_CHANS)
      botnet_send_part_idx(uidx, NULL);
    check_tcl_chpt(botnetnick, dcc[uidx].nick, dcc[uidx].sock,
                   dcc[uidx].u.chat->channel);
  }
  check_tcl_chof(dcc[uidx].nick, dcc[uidx].sock);
  dcc[uidx].type = &DCC_RELAYING;
  dcc[uidx].u.relay = ri;
  if (dcc[uidx].status & STAT_TELNET)
    tputs(dcc[idx].sock, TLN_IAC_C TLN_DO_C TLN_STATUS_C, 3);
}

static void eof_dcc_relay(int idx)
{
  int j;

  for (j = 0; j < dcc_total; j++)
    if (dcc[j].sock == dcc[idx].u.relay->sock)
      break;
  if (j == dcc_total) {
    killsock(dcc[idx].sock);
    lostdcc(idx);
    return;
  }
  dcc[j].status = dcc[j].u.relay->old_status;
  /* In case echo was off, turn it back on (send IAC WON'T ECHO): */
  if (dcc[j].status & STAT_TELNET)
    tputs(dcc[j].sock, TLN_IAC_C TLN_WONT_C TLN_ECHO_C, 3);
  putlog(LOG_MISC, "*", "%s: %s -> %s", BOT_ENDRELAY1, dcc[j].nick,
         dcc[idx].nick);
  dprintf(j, "\n\n*** %s %s\n", BOT_ENDRELAY2, botnetnick);
  struct chat_info *ci = dcc[j].u.relay->chat;
  nfree(dcc[j].u.relay);
  dcc[j].u.chat = ci;
  dcc[j].type = &DCC_CHAT;
  if (dcc[j].u.chat->channel >= 0) {
    chanout_but(-1, dcc[j].u.chat->channel, "*** %s %s.\n",
                dcc[j].nick, BOT_PARTYREJOINED);
    if (dcc[j].u.chat->channel < GLOBAL_CHANS)
      botnet_send_join_idx(j, -1);
  }
  check_tcl_chon(dcc[j].nick, dcc[j].sock);
  check_tcl_chjn(botnetnick, dcc[j].nick, dcc[j].u.chat->channel,
                 geticon(j), dcc[j].sock, dcc[j].host);
  killsock(dcc[idx].sock);
  lostdcc(idx);
}

static void eof_dcc_relaying(int idx)
{
  int x = dcc[idx].u.relay->sock;

  putlog(LOG_MISC, "*", "%s [%s]%s/%d", BOT_LOSTDCCUSER, dcc[idx].nick,
         dcc[idx].host, dcc[idx].port);
  killsock(dcc[idx].sock);
  lostdcc(idx);
  int j;
  for (j = 0; (dcc[j].sock != x) || (dcc[j].type == &DCC_FORK_RELAY); j++);
  putlog(LOG_MISC, "*", "(%s %s)", BOT_DROPPEDRELAY, dcc[j].nick);
  killsock(dcc[j].sock);
  lostdcc(j);                   /* Drop connection to the bot */
}

static void dcc_relay(int idx, char *buf, int j)
{
  unsigned char *src, *dst;

  for (j = 0; dcc[j].sock != dcc[idx].u.relay->sock ||
       dcc[j].type != &DCC_RELAYING; j++);
  /* If redirecting to a non-telnet user, swallow telnet IAC, escape sequences
   * and CR. */
  if (!(dcc[j].status & STAT_TELNET)) {
    src = (unsigned char *) buf;
    dst = (unsigned char *) buf;
    while (*src) {
      /* Search for IAC, escape sequences and CR. */
      if (*src == TLN_IAC) {
        src++;
        if ((*src >= TLN_WILL) && (*src <= TLN_DONT)) {
          src++;
          if (*src)
            src++;
        }
        else if (*src)
          src++;
      } else if (*src == ESC) {
        src++;
        if (*src == '[') { /* CSI */
          src++;
          /* Search for the end of the escape sequence. */
          while (*src && *src++ != 'm');
        }
      } else if (*src == '\r') /* CR */
        src++;
      else {
        if (src > dst)
          *dst = *src;
        src++;
        dst++;
      }
    }
    if (src > dst)
      *dst = 0;
    if (!buf[0])
      dprintf(-dcc[idx].u.relay->sock, " \n");
    else
      dprintf(-dcc[idx].u.relay->sock, "%s\n", buf);
    return;
  }
  /* Telnet user */
  if (!buf[0])
    dprintf(-dcc[idx].u.relay->sock, " \r\n");
  else
    dprintf(-dcc[idx].u.relay->sock, "%s\r\n", buf);
}

static void dcc_relaying(int idx, char *buf, int j)
{
  struct chat_info *ci;

  if (strcasecmp(buf, "*bye*")) {
    dprintf(-dcc[idx].u.relay->sock, "%s\n", buf);
    return;
  }
  for (j = 0; (dcc[j].sock != dcc[idx].u.relay->sock) ||
       (dcc[j].type != &DCC_RELAY); j++);
  dcc[idx].status = dcc[idx].u.relay->old_status;
  /* In case echo was off, turn it back on (send IAC WON'T ECHO): */
  if (dcc[idx].status & STAT_TELNET)
    dprintf(idx, TLN_IAC_C TLN_WONT_C TLN_ECHO_C "\n");
  dprintf(idx, "\n(%s %s.)\n", BOT_BREAKRELAY, dcc[j].nick);
  dprintf(idx, "%s %s.\n\n", BOT_ABORTRELAY2, botnetnick);
  putlog(LOG_MISC, "*", "%s: %s -> %s", BOT_RELAYBROKEN,
         dcc[idx].nick, dcc[j].nick);
  if (dcc[idx].u.relay->chat->channel >= 0) {
    chanout_but(-1, dcc[idx].u.relay->chat->channel,
                "*** %s joined the party line.\n", dcc[idx].nick);
    if (dcc[idx].u.relay->chat->channel < GLOBAL_CHANS)
      botnet_send_join_idx(idx, -1);
  }
  ci = dcc[idx].u.relay->chat;
  nfree(dcc[idx].u.relay);
  dcc[idx].u.chat = ci;
  dcc[idx].type = &DCC_CHAT;
  check_tcl_chon(dcc[idx].nick, dcc[idx].sock);
  if (dcc[idx].u.chat->channel >= 0)
    check_tcl_chjn(botnetnick, dcc[idx].nick, dcc[idx].u.chat->channel,
                   geticon(idx), dcc[idx].sock, dcc[idx].host);
  killsock(dcc[j].sock);
  lostdcc(j);
}

static void display_relay(int i, char *other)
{
  snprintf(other, 160, "rela  -> sock %d", dcc[i].u.relay->sock);
}

static void display_relaying(int i, char *other)
{
  snprintf(other, 160, ">rly  -> sock %d", dcc[i].u.relay->sock);
}

static void display_tandem_relay(int i, char *other)
{
  strlcpy(other, "other  rela", 160);
}

static void display_pre_relay(int i, char *other)
{
  strlcpy(other, "other  >rly", 160);
}

static int expmem_relay(void *x)
{
  struct relay_info *p = (struct relay_info *) x;
  int tot = sizeof(struct relay_info);

  if (p->chat)
    tot += DCC_CHAT.expmem(p->chat);
  return tot;
}

static void kill_relay(int idx, void *x)
{
  struct relay_info *p = (struct relay_info *) x;

  if (p->chat)
    DCC_CHAT.kill(idx, p->chat);
  nfree(p);
}

struct dcc_table DCC_RELAY = {
  "RELAY",
  0,                            /* Flags */
  eof_dcc_relay,
  dcc_relay,
  NULL,
  NULL,
  display_relay,
  expmem_relay,
  kill_relay,
  NULL,
  NULL
};

static void out_relay(int idx, char *buf, void *x)
{
  struct relay_info *p = (struct relay_info *) x;

  if (p && p->chat)
    DCC_CHAT.output(idx, buf, p->chat);
  else
    tputs(dcc[idx].sock, buf, strlen(buf));
}

struct dcc_table DCC_RELAYING = {
  "RELAYING",
  0,                            /* Flags */
  eof_dcc_relaying,
  dcc_relaying,
  NULL,
  NULL,
  display_relaying,
  expmem_relay,
  kill_relay,
  out_relay,
  NULL
};

struct dcc_table DCC_FORK_RELAY = {
  "FORK_RELAY",
  0,                            /* Flags */
  failed_tandem_relay,
  cont_tandem_relay,
  &connect_timeout,
  failed_tandem_relay,
  display_tandem_relay,
  expmem_relay,
  kill_relay,
  NULL,
  NULL
};

struct dcc_table DCC_PRE_RELAY = {
  "PRE_RELAY",
  0,                            /* Flags */
  failed_pre_relay,
  pre_relay,
  NULL,
  NULL,
  display_pre_relay,
  expmem_relay,
  kill_relay,
  NULL,
  NULL
};

/* Every 5 minutes, send 'ping' to each bot -- no exceptions
 */
void check_botnet_pings(void)
{
  for (int i = 0; i < dcc_total; i++)
    if (dcc[i].type == &DCC_BOT)
      if (dcc[i].status & STAT_PINGED) {
        tand_t *bot = findbot(dcc[i].nick);
        int bots = bots_in_subtree(bot);
        int users = users_in_subtree(bot);
        {
          op_strbuf_t s;
          op_strbuf_printf(&s, "%s: %s (lost %d bot%s and %d user%s)",
                   BOT_PINGTIMEOUT, dcc[i].nick, bots,
                   (bots != 1) ? "s" : "", users, (users != 1) ? "s" : "");
          putlog(LOG_BOTS, "*", "%s.", op_strbuf_str(&s));
          botnet_send_unlinked(i, dcc[i].nick, op_strbuf_str(&s));
          op_strbuf_free(&s);
        }
        killsock(dcc[i].sock);
        lostdcc(i);
      }
  for (int i = 0; i < dcc_total; i++)
    if (dcc[i].type == &DCC_BOT) {
      botnet_send_ping(i);
      dcc[i].status |= STAT_PINGED;
    }
  for (int i = 0; i < dcc_total; i++)
    if ((dcc[i].type == &DCC_BOT) && (dcc[i].status & STAT_LEAF)) {
      tand_t *leaf_bot, *leaf_via = findbot(dcc[i].nick);

      for (leaf_bot = tandbot; leaf_bot; leaf_bot = leaf_bot->next) {
        if ((leaf_via == leaf_bot->via) && (leaf_bot != leaf_via)) {
          /* Not leaflike behavior */
          if (dcc[i].status & STAT_WARNED) {
            dprintf(i, "bye %s\n", BOT_BOTNOTLEAFLIKE);
            leaf_bot = findbot(dcc[i].nick);
            int bots = bots_in_subtree(leaf_bot);
            int users = users_in_subtree(leaf_bot);
            {
              op_strbuf_t s;
              op_strbuf_printf(&s, "%s %s (%s) (lost %d bot%s and %d user%s)",
                       BOT_DISCONNECTED, dcc[i].nick, BOT_BOTNOTLEAFLIKE,
                       bots, (bots != 1) ? "s" : "", users, (users != 1) ?
                       "s" : "");
              putlog(LOG_BOTS, "*", "%s.", op_strbuf_str(&s));
              botnet_send_unlinked(i, dcc[i].nick, op_strbuf_str(&s));
              op_strbuf_free(&s);
            }
            killsock(dcc[i].sock);
            lostdcc(i);
          } else {
            botnet_send_reject(i, botnetnick, NULL, leaf_bot->bot, NULL, NULL);
            dcc[i].status |= STAT_WARNED;
          }
        } else
          dcc[i].status &= ~STAT_WARNED;
      }
    }
}

void zapfbot(int idx)
{
  tand_t *bot = findbot(dcc[idx].nick);
  int bots = bots_in_subtree(bot);
  int users = users_in_subtree(bot);
  {
    op_strbuf_t s;
    op_strbuf_printf(&s, "%s: %s (lost %d bot%s and %d user%s)", BOT_BOTDROPPED,
             dcc[idx].nick, bots, (bots != 1) ? "s" : "", users,
             (users != 1) ? "s" : "");
    putlog(LOG_BOTS, "*", "%s.", op_strbuf_str(&s));
    botnet_send_unlinked(idx, dcc[idx].nick, op_strbuf_str(&s));
    op_strbuf_free(&s);
  }
  killsock(dcc[idx].sock);
  lostdcc(idx);
}

void restart_chons(void)
{
  /* Dump party line members */
  for (int i = 0; i < dcc_total; i++) {
    if (dcc[i].type == &DCC_CHAT) {
      check_tcl_chon(dcc[i].nick, dcc[i].sock);
      check_tcl_chjn(botnetnick, dcc[i].nick, dcc[i].u.chat->channel,
                     geticon(i), dcc[i].sock, dcc[i].host);
    }
  }
  for (int i = 0; i < parties; i++) {
    check_tcl_chjn(party[i].bot, party[i].nick, party[i].chan,
                   party[i].flag, party[i].sock, party[i].from);
  }
}
