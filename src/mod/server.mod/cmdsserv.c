/*
 * cmdsserv.c -- part of server.mod
 *   handles commands from a user via dcc that cause server interaction
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

static void cmd_servers(struct userrec *u, int idx, char *par)
{
  struct server_list *x = serverlist;
  time_t t;
  struct tm *currtm;
  int i;
#ifdef IPV6
  char buf[sizeof(struct in6_addr)];
#endif
  char setpass[12];

  putlog(LOG_CMDS, "*", "#%s# servers", dcc[idx].nick);
  if (!x) {
    dprintf(idx, "There are no servers in the server list.\n");
  } else {
    dprintf(idx, "Server list:\n");
    i = 0;
    for (; x; x = x->next) {
      op_strbuf_t s;
#ifdef IPV6
      if (inet_pton(AF_INET6, x->name, buf) == 1)
        op_strbuf_printf(&s, "  [%s]:", x->name);
      else
#endif
        op_strbuf_printf(&s, "  %s:", x->name);
#ifdef TLS
      if (x->ssl)
        op_strbuf_append_cstr(&s, "+");
#endif
      if (x->pass) {
        t = time(NULL);
        currtm = localtime(&t); /* ******* */
        if ((currtm->tm_mon == 3) && (currtm->tm_mday == 1))
          strlcpy(setpass, " (hunter2)", sizeof setpass);
        else
          strlcpy(setpass, " (password)", sizeof setpass);
      } else {
        strlcpy(setpass, "", sizeof setpass);
      }
      if ((i == curserv) && realservername) {
        op_strbuf_appendf(&s, "%s%s (%s) <- I am here",
                          int_to_base10(x->port ? x->port : default_port),
                          setpass, realservername);
      } else {
        op_strbuf_appendf(&s, "%s%s", int_to_base10(x->port ? x->port : default_port), setpass);
        if (i == curserv)
          op_strbuf_append_cstr(&s, " <- I am here");
      }
      dprintf(idx, "%s\n", op_strbuf_str(&s));
      op_strbuf_free(&s);
      i++;
    }
    dprintf(idx, "End of server list.\n");
  }
}

static void cmd_dump(struct userrec *u, int idx, char *par)
{
  if (!isowner(dcc[idx].nick) && must_be_owner == 2) {
    dprintf(idx, "%s", MISC_NOSUCHCMD);
    return;
  }
  if (!par[0]) {
    dprintf(idx, "Usage: dump <server stuff>\n");
    return;
  }
  putlog(LOG_CMDS, "*", "#%s# dump %s", dcc[idx].nick, par);
  dprintf(DP_SERVER, "%s\n", par);
}

static void cmd_jump(struct userrec *u, int idx, char *par)
{
  char *other;
  char *sport;
  int port;

  if (par[0]) {
    other = newsplit(&par);
    sport = newsplit(&par);
    if (*sport == '+') {
#ifdef TLS
      use_ssl = 1;
    }
    else
      use_ssl = 0;
    port = atoi(sport);
    if (!port) {
      port = default_port;
      use_ssl = 0;
    }
    putlog(LOG_CMDS, "*", "#%s# jump %s %s%d %s", dcc[idx].nick, other,
           use_ssl ? "+" : "", port, par);
#else
    putlog(LOG_MISC, "*", "Error: Attempted to jump to SSL-enabled \
server, but Eggdrop was not compiled with SSL libraries. Skipping...");
      return;
    }
    port = atoi(sport);
    if (!port)
      port = default_port;
    putlog(LOG_CMDS, "*", "#%s# jump %s %d %s", dcc[idx].nick, other,
           port, par);
#endif
    strlcpy(newserver, other, sizeof newserver);
    newserverport = port;
    strlcpy(newserverpass, par, sizeof newserverpass);
  } else
    putlog(LOG_CMDS, "*", "#%s# jump", dcc[idx].nick);
  dprintf(idx, "%s...\n", IRC_JUMP);
  cycle_time = 0;
  nuke_server(IRC_CHANGINGSERV);
}

static void cmd_clearqueue(struct userrec *u, int idx, char *par)
{
  int msgs;

  if (!par[0]) {
    dprintf(idx, "Usage: clearqueue <mode|server|help|all>\n");
    return;
  }
  if (!strcasecmp(par, "all")) {
    msgs = modeq.tot + mq.tot + hq.tot;
    msgq_clear(&modeq);
    msgq_clear(&mq);
    msgq_clear(&hq);
    double_warned = burst = 0;
    dprintf(idx, "Removed %d message%s from all queues.\n", msgs,
            (msgs != 1) ? "s" : "");
  } else if (!strcasecmp(par, "mode")) {
    msgs = modeq.tot;
    msgq_clear(&modeq);
    if (mq.tot == 0)
      burst = 0;
    double_warned = 0;
    dprintf(idx, "Removed %d message%s from the mode queue.\n", msgs,
            (msgs != 1) ? "s" : "");
  } else if (!strcasecmp(par, "help")) {
    msgs = hq.tot;
    msgq_clear(&hq);
    double_warned = 0;
    dprintf(idx, "Removed %d message%s from the help queue.\n", msgs,
            (msgs != 1) ? "s" : "");
  } else if (!strcasecmp(par, "server")) {
    msgs = mq.tot;
    msgq_clear(&mq);
    if (modeq.tot == 0)
      burst = 0;
    double_warned = 0;
    dprintf(idx, "Removed %d message%s from the server queue.\n", msgs,
            (msgs != 1) ? "s" : "");
  } else {
    dprintf(idx, "Usage: clearqueue <mode|server|help|all>\n");
    return;
  }
  putlog(LOG_CMDS, "*", "#%s# clearqueue %s", dcc[idx].nick, par);
}

/* .create <channel> [ownerkey] [modes]
 * Send IRCX CREATE to create a channel and gain +q (owner).
 * ownerkey: the OWNERKEY credential (optional, default none)
 * modes: initial channel modes to set after creation (optional)
 */
static void cmd_create(struct userrec *u, int idx, char *par)
{
  char *channel, *ownerkey, *modes;

  if (!par[0]) {
    dprintf(idx, "Usage: create <channel> [ownerkey] [modes]\n");
    return;
  }
  if (!ircx_enabled) {
    dprintf(idx, "IRCX is not enabled on the current server.\n");
    return;
  }
  channel  = newsplit(&par);
  ownerkey = newsplit(&par);
  modes    = par;  /* remainder is modes */

  putlog(LOG_CMDS, "*", "#%s# create %s", dcc[idx].nick, channel);
  if (modes[0])
    dprintf(DP_SERVER, "CREATE %s %s\n", channel, modes);
  else
    dprintf(DP_SERVER, "CREATE %s\n", channel);

  /* If an ownerkey was supplied, update the ircxautoowner entry for this
   * channel so that future reconnects use it. */
  if (ownerkey[0]) {
    struct chanset_t *ch = findchan_by_dname(channel);
    if (ch)
      strlcpy(ch->ircx_ownerkey, ownerkey, sizeof(ch->ircx_ownerkey));
  }
  dprintf(idx, "Sent CREATE %s\n", channel);
}

static cmd_t C_dcc_serv[] = {
  {"dump",       "m",  (IntFunc) cmd_dump,       NULL},
  {"jump",       "m",  (IntFunc) cmd_jump,       NULL},
  {"servers",    "o",  (IntFunc) cmd_servers,    NULL},
  {"clearqueue", "m",  (IntFunc) cmd_clearqueue, NULL},
  {"create",     "m",  (IntFunc) cmd_create,     NULL},
  {NULL,         NULL, NULL,                      NULL}
};
