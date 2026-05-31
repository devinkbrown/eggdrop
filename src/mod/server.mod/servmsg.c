/*
 * servmsg.c -- part of server.mod
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

#include "../irc.mod/irc.h"
#include "../channels.mod/channels.h"
#include <errno.h>
#include "server.h"
char *encode_msgtags(Tcl_Obj *msgtagdict);
static const char *encode_msgtag(const char *key, const char *value);
static int del_capabilities(char *);
static int del_capability(char *name);
static void free_capability(struct capability *z);
static time_t last_ctcp = (time_t) 0L;
static int multistatus = 0, count_ctcp = 0;
static char altnick_char = 0;
op_vec_t cap_vec;
struct capability *find_capability(char *capname);
static op_bh *capability_bh  = nullptr;
static op_bh *cap_values_bh  = nullptr;
static int monitor_add(char * nick, int send);
static int monitor_del (char *nick);
static int monitor_show(Tcl_Obj *mlist, int mode, char *nick);
static void monitor_clear(void);
int account_notify = 1, extended_join = 1, account_tag = 0;

/* Account name from the IRCv3 'account' message tag for the message
 * currently being processed in server_activity().  Empty string means
 * the tag was absent.  Handlers may read this during dispatch.
 * Non-static so server.c can place it in server_table[56] and irc.mod
 * can access it via server_funcs[56] / the current_msgtag_account macro. */
char current_msgtag_account[NICKMAX + 1];

/* Batch reference from the IRCv3 'batch' message tag for the message
 * currently being processed.  Empty string means no batch tag present. */
static char current_msgtag_batch[64 + 1];

/* =========================================================================
 * IRCv3 BATCH accumulator — generic + chathistory
 *
 * When a server opens any batch (BATCH +<ref> <type> [params...]), every
 * raw line tagged @batch=<ref> is buffered until BATCH -<ref> arrives.
 *
 * On close:
 *  - "chathistory" batches fire the legacy do_tcl("batch:chathistory", ...)
 *    path for backward compatibility.
 *  - ALL batch types fire the generic H_batch bind table:
 *      bind batch <flags> <type-pattern> <proc>
 *      proc my_handler {type ref lines} { ... }
 *    where <lines> is a Tcl list of the accumulated raw message strings.
 *  - "netsplit" and "netjoin" batches also fire via H_batch with their
 *    respective type strings so scripts can handle them directly.
 *
 * Lines per batch are capped at BATCH_LINE_CAP to prevent memory bombs.
 * ========================================================================= */
constexpr size_t BATCH_LINE_CAP = 1000;

typedef struct {
  char   type[64];    /* batch type, e.g. "chathistory", "netsplit" */
  char   target[512]; /* first parameter from BATCH + line (channel / nick) */
  char  *key;         /* op_strdup'd key used as the htab key (freed together) */
  char **lines;       /* accumulated raw lines (op_malloc'd strings) */
  size_t n;           /* number of lines stored */
  size_t cap;         /* allocated capacity */
} batch_accum_t;

/* Hash table: batch refid (char *) → batch_accum_t * */
static op_htab *batch_ht = nullptr;

/* H_batch — bind table for generic IRCv3 batch delivery.
 * Lazily initialised on first use; lives for the module lifetime. */
static p_tcl_bind_list H_batch = nullptr;

static void batch_accum_free(batch_accum_t *acc)
{
  if (!acc)
    return;
  op_free(acc->key);   /* free the heap-allocated htab key stored alongside */
  for (size_t i = 0; i < acc->n; i++)
    op_free(acc->lines[i]);
  op_free(acc->lines);
  op_free(acc);
}

static void batch_accum_append(batch_accum_t *acc, const char *line)
{
  if (acc->n >= BATCH_LINE_CAP)
    return; /* cap reached — drop further lines */
  if (acc->n >= acc->cap) {
    size_t newcap = acc->cap ? acc->cap * 2 : 16;
    if (newcap > BATCH_LINE_CAP)
      newcap = BATCH_LINE_CAP;
    acc->lines = (char **)op_realloc(acc->lines, newcap * sizeof(char *));
    acc->cap = newcap;
  }
  acc->lines[acc->n++] = op_strdup(line);
}

/* Deliver a completed chathistory batch to Tcl via the legacy path.
 * Fires: [batch:chathistory <target> <line1> <line2> ...] */
static void batch_deliver_chathistory(batch_accum_t *acc)
{
  op_strbuf_t sb = {};
  op_strbuf_init(&sb);
  op_strbuf_appendf(&sb, "%s", acc->target);
  for (size_t i = 0; i < acc->n; i++) {
    op_strbuf_appendf(&sb, " {%s}", acc->lines[i]);
  }
  do_tcl("batch:chathistory", (char *)op_strbuf_str(&sb));
  op_strbuf_free(&sb);
}

/* batch_ensure_table — lazily create the H_batch bind table on first use.
 * The table is stackable so multiple scripts can bind the same type pattern. */
static void batch_ensure_table(void)
{
  if (!H_batch)
    H_batch = add_bind_table("batch", HT_STACKABLE, nullptr);
}

/* check_tcl_batch — fire the H_batch bind for a completed batch.
 *
 * Sets Tcl variables and calls every proc bound to a pattern that matches
 * <type>:
 *   proc my_handler {type ref lines} { ... }
 *
 * <lines> is a properly-formed Tcl list built with Tcl_DStringAppendElement
 * so each accumulated line is individually quoted.
 */
static void check_tcl_batch(const char *type, const char *ref,
                             batch_accum_t *acc)
{
  batch_ensure_table();

  /* Build the Tcl list of lines. */
  Tcl_DString ds;
  Tcl_DStringInit(&ds);
  for (size_t i = 0; i < acc->n; i++)
    Tcl_DStringAppendElement(&ds, acc->lines[i]);

  Tcl_SetVar(interp, "_batch1", type,                       0);
  Tcl_SetVar(interp, "_batch2", ref,                        0);
  Tcl_SetVar(interp, "_batch3", Tcl_DStringValue(&ds),      0);

  check_tcl_bind(H_batch, type, 0,
                 " $_batch1 $_batch2 $_batch3",
                 MATCH_MASK | BIND_STACKABLE | BIND_STACKRET);

  Tcl_DStringFree(&ds);
}

/* =========================================================================
 * EXTBAN support — ISUPPORT EXTBAN=<prefix>,<types>
 * e.g. EXTBAN=~,amrRszqjnt on InspIRCd / Ophion
 * ========================================================================= */
static char extban_prefix = 0;
static char extban_types[32] = {0};

/* extban_get_prefix — return the EXTBAN prefix character (0 if not set). */
char extban_get_prefix(void) { return extban_prefix; }

/* extban_get_types — return the EXTBAN type string (empty string if not set). */
const char *extban_get_types(void) { return extban_types; }

/* extban_match — check whether a ban mask is an extban that matches nick/user/host/account.
 *
 * Returns:
 *   1  — extban matched
 *   0  — extban not matched (or not an extban, or unsupported type)
 *  -1  — this is an extban mask but the type is not supported; caller may
 *         fall back to a normal wildcard match if desired (though extbans
 *         are not meant to be matched that way).
 */
int extban_match(const char *mask, const char *nick, const char *user,
                 const char *host, const char *account)
{
  char type;
  const char *pattern;

  if (!extban_prefix || !mask || mask[0] != extban_prefix)
    return 0; /* not an extban */

  type = mask[1];
  if (!type || !strchr(extban_types, type))
    return -1; /* unrecognised type */

  pattern = mask + 2;
  /* Skip optional ':' separator used by some IRCds (e.g. ~r:accountpat) */
  if (*pattern == ':')
    pattern++;

  switch (type) {
    case 'r': /* account name match */
      if (!account || !account[0] || !strcmp(account, "*"))
        return 0; /* user is not logged in */
      return wild_match(pattern, account) ? 1 : 0;
    case 'a': /* account name (alias for 'r' on some IRCds) */
      if (!account || !account[0] || !strcmp(account, "*"))
        return 0;
      return wild_match(pattern, account) ? 1 : 0;
    case 'm': /* mask — nick!user@host */
      {
        char fullmask[UHOSTLEN + NICKLEN + 4];
        snprintf(fullmask, sizeof fullmask, "%s!%s@%s",
                 nick ? nick : "", user ? user : "", host ? host : "");
        return wild_match(pattern, fullmask) ? 1 : 0;
      }
    default:
      return -1; /* unsupported type */
  }
  /* unreachable */
}

extern int sasl;
extern int sasl_authenticate_initial(const op_vec_t *);
/* UTF-8 helpers from misc.c (core) */
extern int utf8_sanitize(char *);
extern size_t utf8_strlen(const char *);

/* We try to change to a preferred unique nick here. We always first try the
 * specified alternate nick. If that fails, we repeatedly modify the nick
 * until it gets accepted.
 *
 * sent nick:
 *     "<altnick><c>"
 *                ^--- additional count character: 1-9^-_\\[]`a-z
 *          ^--------- given, alternate nick
 *
 * The last added character is always saved in altnick_char. At the very first
 * attempt (where altnick_char is 0), we try the alternate nick without any
 * additions.
 *
 * fixed by guppy (1999/02/24) and Fabian (1999/11/26)
 */
static int gotfake433(char *from)
{
  int l = strlen(botname) - 1;

  /* First run? */
  if (altnick_char == 0) {
    char *alt = get_altbotnick();

    if (alt[0] && (rfc_casecmp(alt, botname)))
      /* Alternate nickname defined. Let's try that first. */
      op_strlcpy(botname, alt, sizeof(botname));
    else {
      /* Fall back to appending count char. nick_len is server-reported max
       * length; modern servers that support Unicode nicks count codepoints,
       * so compare against utf8_strlen() to handle multi-byte nicknames. */
      altnick_char = '0';
      if ((int)utf8_strlen(botname) >= nick_len) {
        botname[l] = altnick_char;
      } else {
        botname[++l] = altnick_char;
        botname[l + 1] = 0;
      }
    }
    /* No, we already tried the default stuff. Now we'll go through variations
     * of the original alternate nick.
     */
  } else {
    char *oknicks = "^-_\\[]`";
    char *p = strchr(oknicks, altnick_char);

    if (p == nullptr) {
      if (altnick_char == '9')
        altnick_char = oknicks[0];
      else
        altnick_char = altnick_char + 1;
    } else {
      p++;
      if (!*p)
        altnick_char = 'a' + randint(26);
      else
        altnick_char = (*p);
    }
    botname[l] = altnick_char;
  }
  putlog(LOG_MISC, "*", IRC_BOTNICKINUSE, botname);
  dprintf(DP_MODE, "NICK %s\n", botname);
  return 0;
}

/* Check for tcl-bound msg command, return 1 if found
 *
 * msg: proc-name <nick> <user@host> <handle> <args...>
 */
static int check_tcl_msg(char *cmd, char *nick, char *uhost,
                         struct userrec *u, char *args)
{
  struct flag_record fr = { FR_GLOBAL | FR_CHAN | FR_ANYWH };
  char *hand = u ? u->handle : "*";
  int x;

  get_user_flagrec(u, &fr, nullptr);
  Tcl_SetVar(interp, "_msg1", nick, 0);
  Tcl_SetVar(interp, "_msg2", uhost, 0);
  Tcl_SetVar(interp, "_msg3", hand, 0);
  Tcl_SetVar(interp, "_msg4", args, 0);
  Tcl_SetVar(interp, "server_account", current_msgtag_account, TCL_GLOBAL_ONLY);
  x = check_tcl_bind(H_msg, cmd, &fr, " $_msg1 $_msg2 $_msg3 $_msg4",
                     MATCH_EXACT | BIND_HAS_BUILTINS | BIND_USE_ATTR);
  Tcl_SetVar(interp, "server_account", "", TCL_GLOBAL_ONLY);
  if (x == BIND_EXEC_LOG)
    putlog(LOG_CMDS, "*", "(%s!%s) !%s! %s %s", nick, uhost, hand, cmd, args);
  return ((x == BIND_MATCHED) || (x == BIND_EXECUTED) || (x == BIND_EXEC_LOG));
}

static int check_tcl_msgm(char *cmd, char *nick, char *uhost,
                          struct userrec *u, char *arg)
{
  struct flag_record fr = { FR_GLOBAL | FR_CHAN | FR_ANYWH };
  op_strbuf_t args = {};
  op_strbuf_init(&args);
  int x;

  if (arg[0])
    op_strbuf_appendf(&args, "%s %s", cmd, arg);
  else
    op_strbuf_append_cstr(&args, cmd);
  get_user_flagrec(u, &fr, nullptr);
  Tcl_SetVar(interp, "_msgm1", nick, 0);
  Tcl_SetVar(interp, "_msgm2", uhost, 0);
  Tcl_SetVar(interp, "_msgm3", u ? u->handle : "*", 0);
  Tcl_SetVar(interp, "_msgm4", op_strbuf_str(&args), 0);
  Tcl_SetVar(interp, "server_account", current_msgtag_account, TCL_GLOBAL_ONLY);
  x = check_tcl_bind(H_msgm, op_strbuf_str(&args), &fr,
                     " $_msgm1 $_msgm2 $_msgm3 $_msgm4",
                     MATCH_MASK | BIND_USE_ATTR | BIND_STACKABLE | BIND_STACKRET);
  Tcl_SetVar(interp, "server_account", "", TCL_GLOBAL_ONLY);
  op_strbuf_free(&args);

  /*
   * 0 - no match
   * 1 - match, log
   * 2 - match, don't log
   */
  if (x == BIND_NOMATCH)
    return 0;
  if (x == BIND_EXEC_LOG)
    return 2;

  return 1;
}

static int check_tcl_notc(char *nick, char *uhost, struct userrec *u,
                          char *dest, char *arg)
{
  struct flag_record fr = { FR_GLOBAL | FR_CHAN | FR_ANYWH };
  int x;

  get_user_flagrec(u, &fr, nullptr);
  Tcl_SetVar(interp, "_notc1", nick, 0);
  Tcl_SetVar(interp, "_notc2", uhost, 0);
  Tcl_SetVar(interp, "_notc3", u ? u->handle : "*", 0);
  Tcl_SetVar(interp, "_notc4", arg, 0);
  Tcl_SetVar(interp, "_notc5", dest, 0);
  Tcl_SetVar(interp, "server_account", current_msgtag_account, TCL_GLOBAL_ONLY);
  x = check_tcl_bind(H_notc, arg, &fr, " $_notc1 $_notc2 $_notc3 $_notc4 $_notc5",
                     MATCH_MASK | BIND_USE_ATTR | BIND_STACKABLE | BIND_STACKRET);
  Tcl_SetVar(interp, "server_account", "", TCL_GLOBAL_ONLY);

  /*
   * 0 - no match
   * 1 - match, log
   * 2 - match, don't log
   */
  if (x == BIND_NOMATCH)
    return 0;
  if (x == BIND_EXEC_LOG)
    return 2;

  return 1;
}

static int check_tcl_raw(char *from, char *code, char *msg)
{
  int x;

  Tcl_SetVar(interp, "_raw1", from, 0);
  Tcl_SetVar(interp, "_raw2", code, 0);
  Tcl_SetVar(interp, "_raw3", msg, 0);
  x = check_tcl_bind(H_raw, code, 0, " $_raw1 $_raw2 $_raw3",
                     MATCH_MASK | BIND_STACKABLE | BIND_WANTRET);

  /* Return 1 if processed */
  return (x == BIND_EXEC_LOG);
}

/* tagstr is the string value of a Tcl dictionary (flat key/value list) */
static int check_tcl_rawt(char *from, char *code, char *msg, char *tagdict)
{
  int x;

  Tcl_SetVar(interp, "_rawt1", from, 0);
  Tcl_SetVar(interp, "_rawt2", code, 0);
  Tcl_SetVar(interp, "_rawt3", msg, 0);
  Tcl_SetVar(interp, "_rawt4", tagdict, 0);
  x = check_tcl_bind(H_rawt, code, 0, " $_rawt1 $_rawt2 $_rawt3 $_rawt4",
                    MATCH_MASK | BIND_STACKABLE | BIND_WANTRET);
  return (x == BIND_EXEC_LOG);
}

static int check_tcl_ctcpr(char *nick, char *uhost, struct userrec *u,
                           char *dest, char *keyword, char *args,
                           p_tcl_bind_list table)
{
  struct flag_record fr = { FR_GLOBAL | FR_CHAN | FR_ANYWH };
  int x;

  get_user_flagrec(u, &fr, nullptr);
  Tcl_SetVar(interp, "_ctcpr1", nick, 0);
  Tcl_SetVar(interp, "_ctcpr2", uhost, 0);
  Tcl_SetVar(interp, "_ctcpr3", u ? u->handle : "*", 0);
  Tcl_SetVar(interp, "_ctcpr4", dest, 0);
  Tcl_SetVar(interp, "_ctcpr5", keyword, 0);
  Tcl_SetVar(interp, "_ctcpr6", args, 0);
  x = check_tcl_bind(table, keyword, &fr,
                     " $_ctcpr1 $_ctcpr2 $_ctcpr3 $_ctcpr4 $_ctcpr5 $_ctcpr6",
                     MATCH_MASK | BIND_USE_ATTR | BIND_STACKABLE |
                     ((table == H_ctcp) ? BIND_WANTRET : 0));
  return (x == BIND_EXEC_LOG) || (table == H_ctcr);
}

static int check_tcl_wall(char *from, char *msg)
{
  int x;

  Tcl_SetVar(interp, "_wall1", from, 0);
  Tcl_SetVar(interp, "_wall2", msg, 0);
  x = check_tcl_bind(H_wall, msg, 0, " $_wall1 $_wall2",
                     MATCH_MASK | BIND_STACKABLE | BIND_STACKRET);

  /*
   * 0 - no match
   * 1 - match, log
   * 2 - match, don't log
   */
  if (x == BIND_NOMATCH)
    return 0;
  if (x == BIND_EXEC_LOG)
    return 2;

  return 1;
}

static int check_tcl_flud(char *nick, char *uhost, struct userrec *u,
                          char *ftype, char *chname)
{
  int x;

  Tcl_SetVar(interp, "_flud1", nick, 0);
  Tcl_SetVar(interp, "_flud2", uhost, 0);
  Tcl_SetVar(interp, "_flud3", u ? u->handle : "*", 0);
  Tcl_SetVar(interp, "_flud4", ftype, 0);
  Tcl_SetVar(interp, "_flud5", chname, 0);
  x = check_tcl_bind(H_flud, ftype, 0,
                     " $_flud1 $_flud2 $_flud3 $_flud4 $_flud5",
                     MATCH_MASK | BIND_STACKABLE | BIND_WANTRET);
  return (x == BIND_EXEC_LOG);
}

static int check_tcl_out(int which, char *msg, int sent)
{
  int x;
  const char *queue, *state = sent ? "sent" : "queued";
  op_strbuf_t args = {};
  op_strbuf_init(&args);

  switch (which) {
  case DP_MODE:
  case DP_MODE_NEXT:
    queue = "mode";
    break;
  case DP_SERVER:
  case DP_SERVER_NEXT:
    queue = "server";
    break;
  case DP_HELP:
  case DP_HELP_NEXT:
    queue = "help";
    break;
  default:
    queue = "noqueue";
  }
  op_strbuf_appendf(&args, "%s %s", queue, state);
  Tcl_SetVar(interp, "_out1", queue, 0);
  Tcl_SetVar(interp, "_out2", msg, 0);
  Tcl_SetVar(interp, "_out3", state, 0);
  x = check_tcl_bind(H_out, op_strbuf_str(&args), 0, " $_out1 $_out2 $_out3",
                     MATCH_MASK | BIND_STACKABLE | BIND_WANTRET);
  op_strbuf_free(&args);
  return (x == BIND_EXEC_LOG);
}

static int check_tcl_monitor(char *nick, int online)
{
  int x;

  Tcl_SetVar(interp, "_monitor1", nick, 0);
  Tcl_SetVar(interp, "_monitor2", online ? "1" : "0", 0);
  x = check_tcl_bind(H_monitor, nick, 0, " $_monitor1 $_monitor2",
                    MATCH_MASK | BIND_STACKABLE);

  return (x == BIND_EXEC_LOG);
}

static int match_my_nick(const char *nick)
{
  return (!rfc_casecmp(nick, botname));
}

char *encode_msgtags(Tcl_Obj *msgtagdict) {
  int done = 0;
  [[maybe_unused]] Tcl_DictSearch s;
  [[maybe_unused]] Tcl_Obj *value, *key;
  static Tcl_DString ds;
  static int ds_initialized = 0;

  if (!ds_initialized) {
    Tcl_DStringInit(&ds);
    ds_initialized = 1;
  } else {
    Tcl_DStringFree(&ds);
  }
  for (Tcl_DictObjFirst(interp, msgtagdict, &s, &key, &value, &done); !done; Tcl_DictObjNext(&s, &key, &value, &done)) {
    const char *encoded = encode_msgtag(Tcl_GetString(key), Tcl_GetString(value));
    if (!encoded[0])
      continue; /* encode_msgtag() rejected the key as invalid */
    if (Tcl_DStringLength(&ds))
      Tcl_DStringAppend(&ds, ";", -1);
    Tcl_DStringAppend(&ds, encoded, -1);
  }

  return Tcl_DStringValue(&ds);
}

/* 001: welcome to IRC (use it to fix the server name) */
static int got001(char *from, char *msg)
{
  char *key;
  struct chanset_t *chan;

  if (!serverlist_vec.size) {
    putlog(LOG_MISC, "*", "No server list when receiving 001!");
    return 0;
  }
  if (curserv < 0 || (size_t)curserv >= serverlist_vec.size) {
    putlog(LOG_MISC, "*", "Invalid server list (curserv=%d)!", curserv);
    return 0;
  }
  {
    struct server_list *x = (struct server_list *)op_vec_get(&serverlist_vec, (size_t)curserv);
    if (x->realname)
      op_free(x->realname);
    x->realname = op_strdup(from);
    if (realservername)
      op_free(realservername);
    realservername = op_strdup(from);
  }

  server_online = now;
  reconnect_attempts = 0; /* successful login — reset backoff counter */
  fixcolon(msg);
  op_strlcpy(botname, msg, NICKLEN);
  altnick_char = 0;
  if (net_type_int != NETT_TWITCH)      /* Twitch doesn't do WHOIS */
    dprintf(DP_SERVER, "WHOIS %s\n", botname); /* get user@host */
  if (initserver[0])
    do_tcl("init-server", initserver); /* Call Tcl init-server */
  check_tcl_event("init-server");

  /* On Ophion/IRCX networks, negotiate IRCX mode right after login.
   * ircx_send_negotiate() guards against double-sends (ISUPPORT IRCX token
   * may also fire this shortly after 001 via server_isupport_ircx).
   */
  if (net_type_int == NETT_OPHION && ircx_auto_negotiate)
    ircx_send_negotiate();

  {
    struct capability *botcap = find_capability("bot");
    if (botcap && botcap->enabled)
      dprintf(DP_MODE, "MODE %s +B\n", botname);
  }

  if (module_find("irc", 0, 0)) {  /* Only join if the IRC module is loaded. */
    for (chan = chanset; chan; chan = chan->next) {
      chan->status &= ~(CHAN_ACTIVE | CHAN_PEND);
      if (!channel_inactive(chan)) {

        key = chan->channel.key[0] ? chan->channel.key : chan->key_prot;
        if (key[0])
          dprintf(DP_SERVER, "JOIN %s %s\n",
                  chan->name[0] ? chan->name : chan->dname, key);
        else
          dprintf(DP_SERVER, "JOIN %s\n",
                  chan->name[0] ? chan->name : chan->dname);
      }
    }
  }

  return 0;
}

/* Got 005: ISUPPORT network information
 */
static int got005(char *from, char *msg)
{
  newsplit(&msg); /* skip botnick */
  isupport_parse(msg, isupport_set);
  return 0;
}

/* Got 442: not on channel
 */
static int got442(char *from, char *msg)
{
  char *chname, *key;
  struct chanset_t *chan;

  if (!realservername || op_strcasecmp(from, realservername))
    return 0;
  newsplit(&msg);
  chname = newsplit(&msg);
  chan = findchan(chname);
  if (chan && !channel_inactive(chan)) {
    module_entry *me = module_find("channels", 0, 0);

    putlog(LOG_MISC, chname, IRC_SERVNOTONCHAN, chname);
    if (me && me->funcs)
      ((void (*)(struct chanset_t *, int)) me->funcs[CHANNEL_CLEAR])(chan, CHAN_RESETALL);
    chan->status &= ~CHAN_ACTIVE;

    key = chan->channel.key[0] ? chan->channel.key : chan->key_prot;
    if (key[0])
      dprintf(DP_SERVER, "JOIN %s %s\n", chan->name, key);
    else
      dprintf(DP_SERVER, "JOIN %s\n", chan->name);
  }
  return 0;
}

/* Close the current server connection.
 */
static void nuke_server(char *reason)
{
  struct chanset_t *chan;
  module_entry *me;

  /* Reset IRCX per-connection state so next connect negotiates cleanly */
  ircx_enabled     = 0;
  ircx_negotiating = 0;

  if (serv >= 0) {
    int servidx = findanyidx(serv);

    if (reason && (servidx > 0))
      dprintf(servidx, "QUIT :%s\n", reason);
    for (chan = chanset; chan; chan = chan->next) {
      if (channel_active(chan))
        if ((me = module_find("irc", 1, 3)) != nullptr)
          ((void (*)(struct chanset_t *, int)) me->funcs[CHANNEL_CLEAR])(chan, CHAN_RESETALL);
    }

    disconnect_server(servidx);
    lostdcc(servidx);
  }
}

/* op_htab index for O(1) capability lookups by name.
 * Maintained in parallel with the 'cap' linked list; the list is kept
 * because external modules may iterate it directly via server_funcs[43]. */
static op_htab *cap_dict = nullptr;

/* =========================================================================
 * CAP deferred negotiation queue
 *
 * server_queue_cap_req(cap) enqueues a capability request to be sent once
 * CAP LS negotiation opens.  If the server is already in the negotiation
 * window (cap_dict is populated), the request is sent immediately.
 *
 * The queue is drained in gotcap() after the final CAP LS reply is
 * processed, and again cleared on disconnect.
 * ========================================================================= */
static op_vec_t cap_req_queue; /* op_vec_t of op_strdup'd char * */

/* server_queue_cap_req — send a CAP REQ immediately if negotiation is open,
 * otherwise enqueue for delivery when CAP LS completes. */
void server_queue_cap_req(const char *cap)
{
  if (!cap || !cap[0])
    return;
  if (cap_dict) {
    /* Negotiation window is open — send immediately. */
    dprintf(DP_MODE, "CAP REQ :%s\n", cap);
  } else {
    /* Not yet in negotiation; hold until CAP LS reply arrives. */
    op_vec_push(&cap_req_queue, op_strdup(cap));
  }
}

/* cap_req_queue_free_cb — op_vec free callback for queue entries. */
static void cap_req_queue_free_cb(void *elem, void *ud)
{
  (void)ud;
  op_free(elem);
}

/* cap_req_queue_flush — drain cap_req_queue, sending each entry as a CAP REQ.
 * Merges entries into a single CAP REQ line when they fit within CAPMAX. */
static void cap_req_queue_flush(void)
{
  if (cap_req_queue.size == 0)
    return;

  op_strbuf_t req = {};
  op_strbuf_init(&req);
  for (size_t i = 0; i < cap_req_queue.size; i++) {
    const char *cap = (const char *)op_vec_get(&cap_req_queue, i);
    /* If adding this cap would exceed CAPMAX, send what we have and reset. */
    if (!op_strbuf_empty(&req) &&
        op_strbuf_len(&req) + 1 + strlen(cap) > (size_t)CAPMAX) {
      dprintf(DP_MODE, "CAP REQ :%s\n", op_strbuf_str(&req));
      op_strbuf_free(&req);
      op_strbuf_init(&req);
    }
    if (!op_strbuf_empty(&req))
      op_strbuf_append_cstr(&req, " ");
    op_strbuf_append_cstr(&req, cap);
  }
  if (!op_strbuf_empty(&req))
    dprintf(DP_MODE, "CAP REQ :%s\n", op_strbuf_str(&req));
  op_strbuf_free(&req);

  op_vec_clear(&cap_req_queue, cap_req_queue_free_cb, nullptr);
}

/* Inline helper: resolve a nick!user@host 'from' string to a userrec,
 * honouring the IRCv3 'account' tag and any matching channel member record.
 * Callers must have already extracted 'nick' from 'from' via splitnick(). */
static inline struct userrec *lookup_msg_user(char *nick, char *from)
{
  memberlist *m = find_member_from_nick(nick);
  return lookup_user_record(m,
      m ? m->account : (current_msgtag_account[0] ? current_msgtag_account : nullptr),
      from);
}

static op_strbuf_t ctcp_reply = {};

static int lastmsgs[FLOOD_GLOBAL_MAX];
static char lastmsghost[FLOOD_GLOBAL_MAX][81];
static time_t lastmsgtime[FLOOD_GLOBAL_MAX];

/* Do on NICK, PRIVMSG, NOTICE and JOIN.
 */
static int detect_flood(char *floodnick, char *floodhost, char *from, int which)
{
  char *p; const char *ftype = nullptr;
  struct userrec *u;
  int thr = 0, lapse = 0, atr;

  /* Okay, make sure i'm not flood-checking myself */
  if (match_my_nick(floodnick))
    return 0;

  /* My user@host (?) */
  if (!op_strcasecmp(floodhost, botuserhost))
    return 0;

  u = lookup_user_record(nullptr, current_msgtag_account[0] ? current_msgtag_account : nullptr, from);
  atr = u ? u->flags : 0;
  if (atr & (USER_BOT | USER_FRIEND))
    return 0;

  /* Determine how many are necessary to make a flood */
  switch (which) {
  case FLOOD_PRIVMSG:
  case FLOOD_NOTICE:
    thr = flud_thr;
    lapse = flud_time;
    ftype = "msg";
    break;
  case FLOOD_CTCP:
    thr = flud_ctcp_thr;
    lapse = flud_ctcp_time;
    ftype = "ctcp";
    break;
  }
  if ((thr == 0) || (lapse == 0))
    return 0;                   /* No flood protection */

  p = strchr(floodhost, '@');
  if (p) {
    p++;
    if (op_strcasecmp(lastmsghost[which], p)) {        /* New */
      op_strlcpy(lastmsghost[which], p, sizeof lastmsghost[which]);
      lastmsgtime[which] = now;
      lastmsgs[which] = 0;
      return 0;
    }
  } else
    return 0;                   /* Uh... whatever. */

  if (lastmsgtime[which] < now - lapse) {
    /* Flood timer expired, reset it */
    lastmsgtime[which] = now;
    lastmsgs[which] = 0;
    return 0;
  }
  lastmsgs[which]++;
  if (lastmsgs[which] >= thr) { /* FLOOD */
    /* Reset counters */
    lastmsgs[which] = 0;
    lastmsgtime[which] = 0;
    lastmsghost[which][0] = 0;
    u = lookup_user_record(nullptr, current_msgtag_account[0] ? current_msgtag_account : nullptr, from);
    if (check_tcl_flud(floodnick, floodhost, u, (char *) ftype, "*"))
      return 0;
    /* Private msg */
    op_strbuf_t h = {};
    op_strbuf_init(&h);
    op_strbuf_appendf(&h, "*!*@%s", p);
    putlog(LOG_MISC, "*", IRC_FLOODIGNORE1, p);
    addignore(op_strbuf_str(&h), botnetnick, (which == FLOOD_CTCP) ? "CTCP flood" :
              "MSG/NOTICE flood", now + (60 * ignore_time));
    op_strbuf_free(&h);
  }
  return 0;
}


/* Got a private message.
 */
static int gotmsg(char *from, char *msg)
{
  char *to, buf[UHOSTLEN], *nick, ctcpbuf[512], *uhost = buf, *ctcp,
       *p, *p1, *code;
  struct userrec *u;
  int ctcp_count = 0;
  int ignoring;

  /* Notice to a channel, not handled here */
  if (msg[0] && ((strchr(CHANMETA, *msg) != nullptr) || (*msg == '@')))
    return 0;

  ignoring = match_ignore(from);
  to = newsplit(&msg);
  fixcolon(msg);
  op_strlcpy(uhost, from, sizeof buf);
  nick = splitnick(&uhost);
  /* Apparently servers can send CTCPs now too, not just nicks */
  if (nick[0] == '\0')
    nick = uhost;

  /* Check for CTCP: */
  op_strbuf_clear(&ctcp_reply);
  p = strchr(msg, 1);
  while ((p != nullptr) && (*p)) {
    p++;
    p1 = p;
    while ((*p != 1) && (*p != 0))
      p++;
    if (*p == 1) {
      *p = 0;
      op_strlcpy(ctcpbuf, p1, sizeof(ctcpbuf));
      ctcp = ctcpbuf;

      /* remove the ctcp in msg */
      memmove(p1 - 1, p + 1, strlen(p + 1) + 1);

      if (!ignoring)
        detect_flood(nick, uhost, from,
                     strncmp(ctcp, "ACTION ", 7) ? FLOOD_CTCP : FLOOD_PRIVMSG);
      /* Respond to the first answer_ctcp */
      p = strchr(msg, 1);
      if (ctcp_count < answer_ctcp) {
        ctcp_count++;
        if (ctcp[0] != ' ') {
          code = newsplit(&ctcp);

          /* CTCP from oper, don't interpret */
          if ((to[0] == '$') || strchr(to, '.')) {
            if (!ignoring)
              putlog(LOG_PUBLIC, to, "CTCP %s: %s from %s (%s) to %s",
                     code, ctcp, nick, uhost, to);
          } else {
            u = lookup_msg_user(nick, from);
            if (!ignoring || trigger_on_ignore) {
              if (!check_tcl_ctcp(nick, uhost, u, to, code, ctcp) && !ignoring) {
                if ((lowercase_ctcp && !op_strcasecmp(code, "DCC")) ||
                    (!lowercase_ctcp && !strcmp(code, "DCC"))) {
                  /* If it gets this far unhandled, it means that
                   * the user is totally unknown.
                   */
                  code = newsplit(&ctcp);
                  if (!strcmp(code, "CHAT")) {
                    if (!quiet_reject) {
                      if (u)
                        dprintf(DP_HELP, "NOTICE %s :I'm not accepting calls "
                                "at the moment.\n", nick);
                      else
                        dprintf(DP_HELP, "NOTICE %s :%s\n", nick,
                                DCC_NOSTRANGERS);
                    }
                    putlog(LOG_MISC, "*", "%s: %s", DCC_REFUSED, from);
                  } else
                    putlog(LOG_MISC, "*", "Refused DCC %s: %s", code, from);
                }
              }
              if (!strcmp(code, "ACTION")) {
                putlog(LOG_MSGS, "*", "Action to %s: %s %s", to, nick, ctcp);
              } else {
                putlog(LOG_MSGS, "*", "CTCP %s: %s from %s (%s)", code, ctcp,
                       nick, uhost);
              }                 /* I love a good close cascade ;) */
            }
          }
        }
      }
    }
  }
  /* Send out possible ctcp responses */
  if (!op_strbuf_empty(&ctcp_reply)) {
    if (ctcp_mode != 2) {
      dprintf(DP_HELP, "NOTICE %s :%s\n", nick, op_strbuf_str(&ctcp_reply));
    } else {
      if (now - last_ctcp > flud_ctcp_time) {
        dprintf(DP_HELP, "NOTICE %s :%s\n", nick, op_strbuf_str(&ctcp_reply));
        count_ctcp = 1;
      } else if (count_ctcp < flud_ctcp_thr) {
        dprintf(DP_HELP, "NOTICE %s :%s\n", nick, op_strbuf_str(&ctcp_reply));
        count_ctcp++;
      }
      last_ctcp = now;
    }
  }
  if (msg[0]) {
    int result = 0;
    /* Msg from oper, don't interpret */
    if ((to[0] == '$') || (strchr(to, '.') != nullptr)) {
      if (!ignoring) {
        detect_flood(nick, uhost, from, FLOOD_PRIVMSG);
        putlog(LOG_MSGS | LOG_SERV, "*", "[%s!%s to %s] %s",
               nick, uhost, to, msg);
      }
      return 0;
    }

    detect_flood(nick, uhost, from, FLOOD_PRIVMSG);
    u = lookup_msg_user(nick, from);
    code = newsplit(&msg);
    rmspace(msg);

    if (!ignoring || trigger_on_ignore) {
      result = check_tcl_msgm(code, nick, uhost, u, msg);

      if (!result || !exclusive_binds)
        if (check_tcl_msg(code, nick, uhost, u, msg))
          return 0;
    }

    if (!ignoring && result != 2)
      putlog(LOG_MSGS, "*", "[%s] %s %s", from, code, msg);
  }
  return 0;
}

/* Got a private notice.
 */
static int gotnotice(char *from, char *msg)
{
  #define CTCP_MAX 512
  char *to, *nick, ctcpbuf[CTCP_MAX], *p, *p1, buf[512], *uhost = buf, *ctcp;
  struct userrec *u;
  int ignoring;

  /* Notice to a channel, not handled here */
  if (msg[0] && ((strchr(CHANMETA, *msg) != nullptr) || (*msg == '@')))
    return 0;

  ignoring = match_ignore(from);
  to = newsplit(&msg);
  fixcolon(msg);
  op_strlcpy(uhost, from, sizeof buf);
  nick = splitnick(&uhost);

  /* Check for CTCP: */
  p = strchr(msg, 1);
  while ((p != nullptr) && (*p)) {
    p++;
    p1 = p;
    while ((*p != 1) && (*p != 0))
      p++;
    if (*p == 1) {
      *p = 0;
      if ((p - p1) >= sizeof ctcpbuf) {
        putlog(LOG_SERV, "*", "Warning: Got NOTICE CTCP reply longer than "
               STRINGIFY(CTCP_MAX) " bytes: Bogus server?");
        return 0;
      }
      op_strlcpy(ctcpbuf, p1, sizeof ctcpbuf);
      ctcp = ctcpbuf;
      memmove(p1 - 1, p + 1, strlen(p + 1) + 1);
      if (!ignoring)
        detect_flood(nick, uhost, from, FLOOD_CTCP);
      p = strchr(msg, 1);
      if (ctcp[0] != ' ') {
        char *code = newsplit(&ctcp);

        /* CTCP reply from oper, don't interpret */
        if ((to[0] == '$') || strchr(to, '.')) {
          if (!ignoring)
            putlog(LOG_PUBLIC, "*",
                   "CTCP reply %s: %s from %s (%s) to %s", code, ctcp,
                   nick, uhost, to);
        } else {
          u = lookup_msg_user(nick, from);
          if (!ignoring || trigger_on_ignore) {
            check_tcl_ctcr(nick, uhost, u, to, code, ctcp);
            if (!ignoring)
              /* Who cares? */
              putlog(LOG_MSGS, "*",
                     "CTCP reply %s: %s from %s (%s) to %s",
                     code, ctcp, nick, uhost, to);
          }
        }
      }
    }
  }
  if (msg[0]) {

    /* Notice from oper, don't interpret */
    if ((to[0] == '$') || (strchr(to, '.') != nullptr)) {
      if (!ignoring) {
        detect_flood(nick, uhost, from, FLOOD_NOTICE);
        putlog(LOG_MSGS | LOG_SERV, "*", "-%s (%s) to %s- %s",
               nick, uhost, to, msg);
      }
      return 0;
    }

    /* Server notice? */
    if ((nick[0] == 0) || (uhost[0] == 0)) {

      /* Hidden `250' connection count message from server */
      if (strncmp(msg, "Highest connection count:", 25))
        putlog(LOG_SERV, "*", "-NOTICE- %s", msg);

      return 0;
    }

    detect_flood(nick, uhost, from, FLOOD_NOTICE);
    u = lookup_msg_user(nick, from);

    if (!ignoring || trigger_on_ignore)
      if (check_tcl_notc(nick, uhost, u, botname, msg) == 2)
        return 0;

    if (!ignoring)
      putlog(LOG_MSGS, "*", "-%s (%s)- %s", nick, uhost, msg);
  }
  return 0;
}

static int gottagmsg(char *from, char *msg, Tcl_Obj *tagdict) {
  char *nick, *dictstring;

  dictstring = encode_msgtags(tagdict);

  fixcolon(msg);
  if (strchr(from, '!')) {
    nick = splitnick(&from);
    putlog(LOG_SERV, "*", "[#]%s(%s)[#] TAGMSG: %s", nick, from, dictstring);
  } else {
    putlog(LOG_SERV, "*", "[#]%s[#] TAGMSG: %s", from, dictstring);
  }
  return 0;
}

/* WALLOPS: oper's nuisance
 */
static int gotwall(char *from, char *msg)
{
  char *nick;

  fixcolon(msg);

  if (check_tcl_wall(from, msg) != 2) {
    if (strchr(from, '!')) {
      nick = splitnick(&from);
      putlog(LOG_WALL, "*", "!%s(%s)! %s", nick, from, msg);
    } else
      putlog(LOG_WALL, "*", "!%s! %s", from, msg);
  }
  return 0;
}

/* Called once a minute...
 */
static void minutely_checks(void)
{
  char *alt;

  /* Only check if we have already successfully logged in.  */
  if (!server_online)
    return;
  if (keepnick) {
    /* NOTE: now that botname can but up to NICKLEN bytes long,
     * check that it's not just a truncation of the full nick.
     */
    if (strncmp(botname, origbotname, strlen(botname))) {
      /* See if my nickname is in use and if if my nick is right. */
      alt = get_altbotnick();
      if (alt[0] && op_strcasecmp(botname, alt))
        dprintf(DP_SERVER, "ISON :%s %s %s\n", botname, origbotname, alt);
      else
        dprintf(DP_SERVER, "ISON :%s %s\n", botname, origbotname);
    }
  }
}

/* Pong from server.
 */
static int gotpong(char *from, char *msg)
{
  newsplit(&msg);
  fixcolon(msg);                /* Scrap server name */
  server_lag = now - my_atoul(msg);
  if (server_lag > 99999) {
    /* IRCnet lagmeter support by drummer */
    server_lag = now - lastpingtime;
  }
  return 0;
}

/* This is a reply on ISON :<current> <orig> [<alt>]
 */
static void got303(char *from, char *msg)
{
  char *tmp, *alt;
  int ison_orig = 0, ison_alt = 0;

  if (!keepnick || !strncmp(botname, origbotname, strlen(botname))) {
    return;
  }
  newsplit(&msg);
  fixcolon(msg);
  alt = get_altbotnick();
  tmp = newsplit(&msg);
  if (tmp[0] && !rfc_casecmp(botname, tmp)) {
    while ((tmp = newsplit(&msg))[0]) { /* no, it's NOT == */
      if (!rfc_casecmp(tmp, origbotname))
        ison_orig = 1;
      else if (alt[0] && !rfc_casecmp(tmp, alt))
        ison_alt = 1;
    }
    if (!ison_orig) {
      if (!nick_juped)
        putlog(LOG_MISC, "*", IRC_GETORIGNICK, origbotname);
      dprintf(DP_SERVER, "NICK %s\n", origbotname);
    } else if (alt[0] && !ison_alt && rfc_casecmp(botname, alt)) {
      putlog(LOG_MISC, "*", IRC_GETALTNICK, alt);
      dprintf(DP_SERVER, "NICK %s\n", alt);
    }
  }
}

/* 432 : Bad nickname
 */
static int got432(char *from, char *msg)
{
  char *erroneous, nick[NICKMAX + 1];

  newsplit(&msg);
  erroneous = newsplit(&msg);
  if (server_online)
    putlog(LOG_MISC, "*", "NICK IS INVALID: '%s' (keeping '%s').", erroneous,
           botname);
  else {
    putlog(LOG_MISC, "*", "%s", IRC_BADBOTNICK);
    if (!strcmp(erroneous, origbotname)) {
      op_strlcpy(nick, get_altbotnick(), sizeof nick);
    } else {
      make_rand_str_from_chars(nick, sizeof nick - 1, CHARSET_LOWER_ALPHA);
    }
    putlog(LOG_MISC, "*", "NICK IS INVALID: '%s' (using '%s' instead)",
            erroneous, nick);
    dprintf(DP_MODE, "NICK %s\n", nick);
    return 0;
  }
  return 0;
}

/* 433 : Nickname in use
 * Change nicks till we're acceptable or we give up
 */
static int got433(char *from, char *msg)
{
  char *tmp;

  if (server_online) {
    /* We are online and have a nickname, we'll keep it */
    newsplit(&msg);
    tmp = newsplit(&msg);
    putlog(LOG_MISC, "*", "NICK IN USE: %s (keeping '%s').", tmp, botname);
    nick_juped = 0;
    return 0;
  }
  gotfake433(from);
  return 0;
}

/* 437 : Nickname juped (IRCnet)
 */
static int got437(char *from, char *msg)
{
  char *s;
  struct chanset_t *chan;

  newsplit(&msg);
  s = newsplit(&msg);
  if (s[0] && (strchr(CHANMETA, s[0]) != nullptr)) {
    chan = findchan(s);
    if (chan) {
      if (chan->status & CHAN_ACTIVE) {
        putlog(LOG_MISC, "*", IRC_CANTCHANGENICK, s);
      } else {
        if (!channel_juped(chan)) {
          putlog(LOG_MISC, "*", IRC_CHANNELJUPED, s);
          chan->status |= CHAN_JUPED;
        }
      }
    }
  } else if (server_online) {
    if (!nick_juped)
      putlog(LOG_MISC, "*", "NICK IS JUPED: %s (keeping '%s').", s, botname);
    if (!rfc_casecmp(s, origbotname))
      nick_juped = 1;
  } else {
    putlog(LOG_MISC, "*", "%s: %s", IRC_BOTNICKJUPED, s);
    gotfake433(from);
  }
  return 0;
}

/* 438 : Nick change too fast
 */
static int got438(char *from, char *msg)
{
  newsplit(&msg);
  newsplit(&msg);
  fixcolon(msg);
  putlog(LOG_MISC, "*", "%s", msg);
  return 0;
}

static int got451(char *from, char *msg)
{
  /* Usually if we get this then we really messed up somewhere
   * or this is a non-standard server, so we log it and kill the socket
   * hoping the next server will work :) -poptix
   */
  /* Um, this does occur on a lagged anti-spoof server connection if the
   * (minutely) sending of joins occurs before the bot does its ping reply.
   * Probably should do something about it some time - beldin
   */
  putlog(LOG_MISC, "*", IRC_NOTREGISTERED1, from);
  nuke_server(IRC_NOTREGISTERED2);
  return 0;
}

/* Got error notice
 */
static int goterror(char *from, char *msg)
{
  /* IRC ERROR messages always carry a trailing parameter prefixed with ':'.
   * The fixcolon() macro handles that case correctly, but its else-branch
   * calls newsplit() which would consume the first word of a message that
   * lacks the colon — silently dropping part of the error text.  Advance
   * past a leading ':' directly to avoid that data loss. */
  if (msg[0] == ':')
    msg++;
  putlog(LOG_SERV | LOG_MSGS, "*", "-ERROR from server- %s", msg);
  if (serverror_quit) {
    putlog(LOG_SERV, "*", "Disconnecting from server.");
    nuke_server("Bah, stupid error messages.");
  }
  return 1;
}

/* Got nick change.
 */
static int gotnick(char *from, char *msg)
{
  char *nick, *alt = get_altbotnick();

  nick = splitnick(&from);
  fixcolon(msg);
  check_queues(nick, msg);
  if (match_my_nick(nick)) {
    /* Regained nick! */
    op_strlcpy(botname, msg, NICKLEN);
    altnick_char = 0;
    if (!strcmp(msg, origbotname)) {
      putlog(LOG_SERV | LOG_MISC, "*", "Regained nickname '%s'.", msg);
      nick_juped = 0;
    } else if (alt[0] && !strcmp(msg, alt))
      putlog(LOG_SERV | LOG_MISC, "*", "Regained alternate nickname '%s'.",
             msg);
    else if (keepnick && strcmp(nick, msg)) {
      putlog(LOG_SERV | LOG_MISC, "*", "Nickname changed to '%s'???", msg);
      if (!rfc_casecmp(nick, origbotname)) {
        putlog(LOG_MISC, "*", IRC_GETORIGNICK, origbotname);
        dprintf(DP_SERVER, "NICK %s\n", origbotname);
      } else if (alt[0] && !rfc_casecmp(nick, alt) &&
               op_strcasecmp(botname, origbotname)) {
        putlog(LOG_MISC, "*", IRC_GETALTNICK, alt);
        dprintf(DP_SERVER, "NICK %s\n", alt);
      }
    } else
      putlog(LOG_SERV | LOG_MISC, "*", "Nickname changed to '%s'???", msg);
  } else if ((keepnick) && (rfc_casecmp(nick, msg))) {
    /* Only do the below if there was actual nick change, case doesn't count */
    if (!rfc_casecmp(nick, origbotname)) {
      putlog(LOG_MISC, "*", IRC_GETORIGNICK, origbotname);
      dprintf(DP_SERVER, "NICK %s\n", origbotname);
    } else if (alt[0] && !rfc_casecmp(nick, alt) &&
             op_strcasecmp(botname, origbotname)) {
      putlog(LOG_MISC, "*", IRC_GETALTNICK, altnick);
      dprintf(DP_SERVER, "NICK %s\n", altnick);
    }
  }
  return 0;
}

static int gotmode(char *from, char *msg)
{
  char *ch;

  ch = newsplit(&msg);
  /* Usermode changes? */
  if (strchr(CHANMETA, ch[0]) == nullptr) {
    if (match_my_nick(ch)) {
      fixcolon(msg);
      if ((msg[0] == '+') || (msg[0] == '-')) {
        /* send a WHOIS in case our host was cloaked, but not on Twitch */
        if (net_type_int != NETT_TWITCH)
          dprintf(DP_SERVER, "WHOIS %s\n", botname);
      }
      if (check_mode_r) {
        /* umode +r? - D0H dalnet uses it to mean something different */
        if ((msg[0] == '+') && strchr(msg, 'r')) {
          int servidx = findanyidx(serv);

          putlog(LOG_MISC | LOG_JOIN, "*",
                 "%s has me i-lined (jumping)", dcc[servidx].host);
          nuke_server("i-lines suck");
        }
      }
    }
  }
  return 0;
}

/* Destroy callback for label_ack_ht: frees the heap-allocated key string. */
static void label_ack_free_cb(void *key, void *val, void *ud)
{
  (void)val;
  (void)ud;
  op_free(key);
}

static void disconnect_server(int idx)
{
  if (server_online > 0) {
    check_tcl_event("disconnect-server");
  }
  for (size_t i = 0; i < cap_vec.size; i++)
    free_capability((struct capability *)op_vec_get(&cap_vec, i));
  op_vec_clear(&cap_vec, nullptr, nullptr);
  if (cap_dict) {
    op_htab_destroy(cap_dict, nullptr, nullptr);
    cap_dict = nullptr;
  }
  /* Discard any pending labeled-response correlations from the old
   * connection — they will never be answered once we disconnect. */
  if (label_ack_ht) {
    op_htab_destroy(label_ack_ht, label_ack_free_cb, nullptr);
    label_ack_ht = nullptr;
  }
  /* Discard any in-flight batch accumulators from the previous connection.
   * batch_accum_free() frees acc->key (which is the same pointer as the htab
   * key), so we only pass the value to it — no separate key free needed. */
  if (batch_ht) {
    op_htab_iter_t it;
    op_htab_iter_init(batch_ht, &it);
    void *key, *val;
    while (op_htab_iter_next(batch_ht, &it, &key, &val)) {
      (void)key; /* acc->key == key; batch_accum_free handles it */
      batch_accum_free((batch_accum_t *)val);
    }
    op_htab_destroy(batch_ht, nullptr, nullptr);
    batch_ht = nullptr;
  }
  server_online = 0;
  if (realservername)
    op_free(realservername);
  realservername = 0;
  /* $::server should be empty for this, so isupport binds can ignore it */
  isupport_clear_values(0);
  if (dcc[idx].sock >= 0)
    killsock(dcc[idx].sock);
  dcc[idx].sock = -1;
  serv = -1;
  botuserhost[0] = 0;
}

static void eof_server(int idx)
{
  putlog(LOG_SERV, "*", "%s %s", IRC_DISCONNECTED, dcc[idx].host);
  disconnect_server(idx);
  lostdcc(idx);
}

static void display_server(int idx, op_strbuf_t *buf)
{
  op_strbuf_appendf(buf, "%s  (lag: %d)", trying_server ? "conn" : "serv", server_lag);
}

static void connect_server(void);

static void kill_server(int idx, void *x)
{
  module_entry *me;

  disconnect_server(idx);
  if ((me = module_find("channels", 0, 0)) && me->funcs) {
    struct chanset_t *chan;

    for (chan = chanset; chan; chan = chan->next)
      ((void (*)(struct chanset_t *, int)) me->funcs[CHANNEL_CLEAR])(chan, CHAN_RESETALL);
  }
  /* A new server connection will be automatically initiated in
   * about 2 seconds. */
}

static void timeout_server(int idx)
{
  putlog(LOG_SERV, "*", "Timeout: connect to %s", dcc[idx].host);
  disconnect_server(idx);
  check_tcl_event("fail-server");
  lostdcc(idx);
}

static void server_activity(int idx, char *msg, int len);

static struct dcc_table SERVER_SOCKET = {
  "SERVER",
  0,
  eof_server,
  server_activity,
  nullptr,
  timeout_server,
  display_server,
  nullptr,
  kill_server,
  nullptr,
  nullptr
};

static const char *encode_msgtag_value(const char *value)
{
  static char buf[TOTALTAGMAX+1];
  size_t written = 0;

  /* empty value and no value is identical, Tcl dict always has empty string as no-value, looks better to encode without = */
  if (!value || !*value) {
    return "";
  }
  buf[written++] = '=';

  while (*value && written < sizeof buf - 2) {
    if (*value == ';' || *value == ' ' || *value == '\\' || *value == '\r' || *value == '\n') {
      buf[written++] = '\\';
    }
    buf[written++] = *value++;
  }
  buf[written] = '\0';

  return buf;
}

/* Validate an IRCv3 message-tag key.
 *
 * Per the message-tags spec a key must match:
 *   ['+'] [ <vendor> '/' ] <sequence of A-Z a-z 0-9 '-' '_' '.' >
 *
 * Returns 1 if every character is valid, 0 otherwise.
 */
static int msgtag_key_valid(const char *key)
{
  if (!key || !*key)
    return 0;
  /* Optional client-only prefix */
  if (*key == '+')
    key++;
  /* Optional vendor prefix ends at the first '/' */
  for (; *key; key++) {
    if (isalnum((unsigned char)*key) || *key == '-' || *key == '_' ||
        *key == '.' || *key == '/')
      continue;
    return 0;
  }
  return 1;
}

static const char *encode_msgtag(const char *key, const char *value)
{
  static op_strbuf_t sb = {};

  if (!msgtag_key_valid(key)) {
    putlog(LOG_SERV, "*", "Dropping message tag with invalid key: %s", key);
    op_strbuf_clear(&sb);
    return op_strbuf_str(&sb);
  }
  op_strbuf_clear(&sb);
  op_strbuf_appendf(&sb, "%s%s", key, encode_msgtag_value(value));
  return op_strbuf_str(&sb);
}

[[maybe_unused]] static char *decode_msgtag_value(char *value, char **endptr)
{
  static char valuebuf[TOTALTAGMAX+1];
  char *tmp, *decoded = valuebuf;
  int escaped = 0;

  for (tmp = value; *tmp && *tmp != ';' && *tmp != ' ' && decoded - valuebuf < TOTALTAGMAX; tmp++) {
    if (!escaped && *tmp == '\\') {
      escaped = 1;
      continue;
    }
    if (escaped) {
      if (*tmp == ':') {
        *decoded++ = ';';
      } else if (*tmp == 'n') {
        *decoded++ = '\n';
      } else if (*tmp == 'r') {
        *decoded++ = '\r';
      } else if (*tmp == 's') {
        *decoded++ = ' ';
      } else {
        *decoded++ = *tmp;
      }
      escaped = 0;
    } else {
      *decoded++ = *tmp;
    }
  }
  /* either points to \0 or ; */
  *endptr = tmp;

  *decoded = '\0';
  return valuebuf;
}

static void server_activity(int idx, char *tagmsg, int len)
{
  char *from, *code, *msgptr;
  char rawmsg[RECVLINEMAX+7];
  [[maybe_unused]] int ret;
  [[maybe_unused]] Tcl_Obj *tagdict = Tcl_NewDictObj();

  /* Sanitize incoming IRC messages: replace invalid UTF-8 bytes with '?'.
   * Modern IRC servers and clients use UTF-8; malformed sequences could cause
   * issues in Tcl's string handling (which is internally UTF-8). */
  utf8_sanitize(tagmsg);

  Tcl_IncrRefCount(tagdict);
  if (trying_server) {
    op_strlcpy(dcc[idx].nick, "(server)", sizeof(dcc[idx].nick));
    putlog(LOG_SERV, "*", "Connected to %s", dcc[idx].host);
    trying_server = 0;
    SERVER_SOCKET.timeout_val = 0;
  }
  lastpingcheck = 0;
  /* Parse optional message-tags, regardless of whether they are enabled on our side */
  msgptr = tagmsg;
  op_strlcpy(rawmsg, tagmsg, TOTALTAGMAX+1);
  if (*tagmsg == '@') {
    char *key, *value, *lastendptr = tagmsg;

    do {
      key = lastendptr + 1;
      value = key + strcspn(key, "=; ");

      if (*value == '=') {
        Tcl_DictObjPut(interp, tagdict, Tcl_NewStringObj(key, value - key),
                       Tcl_NewStringObj(decode_msgtag_value(value + 1, &lastendptr), -1));
      } else {
        Tcl_DictObjPut(interp, tagdict, Tcl_NewStringObj(key, value - key),
                       Tcl_NewStringObj("", -1));
        lastendptr = value;
      }
    } while (*lastendptr && *lastendptr != ' ');

    msgptr = lastendptr + (*lastendptr != '\0');
  }
  from = "";
  if (*msgptr == ':') {
    msgptr++;
    from = newsplit(&msgptr);
  }
  code = newsplit(&msgptr);
  if (raw_log && ((strcmp(code, "PRIVMSG") && strcmp(code, "NOTICE")) ||
      !match_ignore(from))) {
    putlog(LOG_RAW, "*", "[@] %s", rawmsg);
  }
  /* Extract IRCv3 'account' tag so handlers can use it for user lookup. */
  {
    [[maybe_unused]] Tcl_Obj *acctkey = Tcl_NewStringObj("account", -1);
    Tcl_Obj *acctval = nullptr;
    Tcl_IncrRefCount(acctkey);
    if (Tcl_DictObjGet(interp, tagdict, acctkey, &acctval) == TCL_OK && acctval)
      op_strlcpy(current_msgtag_account, Tcl_GetString(acctval), sizeof current_msgtag_account);
    else
      current_msgtag_account[0] = '\0';
    Tcl_DecrRefCount(acctkey);
  }
  /* Extract IRCv3 'batch' tag for CHATHISTORY accumulator. */
  {
    [[maybe_unused]] Tcl_Obj *batchkey = Tcl_NewStringObj("batch", -1);
    Tcl_Obj *batchval = nullptr;
    Tcl_IncrRefCount(batchkey);
    if (Tcl_DictObjGet(interp, tagdict, batchkey, &batchval) == TCL_OK && batchval)
      op_strlcpy(current_msgtag_batch, Tcl_GetString(batchval), sizeof current_msgtag_batch);
    else
      current_msgtag_batch[0] = '\0';
    Tcl_DecrRefCount(batchkey);
  }
  /* IRCv3 labeled-response: when the server echoes back our @label= tag,
   * remove the pending entry from label_ack_ht so callers know the reply
   * has arrived.  The key string was heap-allocated by server_send_labeled. */
  if (label_ack_ht) {
    Tcl_Obj *lblkey = Tcl_NewStringObj("label", -1);
    Tcl_Obj *lblval = nullptr;
    Tcl_IncrRefCount(lblkey);
    if (Tcl_DictObjGet(interp, tagdict, lblkey, &lblval) == TCL_OK && lblval) {
      const char *lbl = Tcl_GetString(lblval);
      if (op_htab_has(label_ack_ht, lbl)) {
        op_htab_iter_t it;
        op_htab_iter_init(label_ack_ht, &it);
        void *k = nullptr, *v = nullptr;
        while (op_htab_iter_next(label_ack_ht, &it, &k, &v)) {
          if (k && !strcmp((const char *)k, lbl)) {
            op_htab_iter_del(label_ack_ht, &it);
            op_free(k);
            break;
          }
        }
        putlog(LOG_DEBUG, "*", "labeled-response: ACK label=%s", lbl);
      }
    }
    Tcl_DecrRefCount(lblkey);
  }
  /* Check both raw and rawt, to allow backwards compatibility with older
   * scripts. If rawt returns 1 (blocking), don't process raw binds.*/
  op_strlcpy(rawmsg, Tcl_GetString(tagdict), sizeof rawmsg);
  ret = check_tcl_rawt(from, code, msgptr, rawmsg);
  if (!ret) {
    check_tcl_raw(from, code, msgptr);
  }
  current_msgtag_account[0] = '\0';
  current_msgtag_batch[0] = '\0';
  Tcl_DecrRefCount(tagdict);
}

static int gotping(char *from, char *msg)
{
  fixcolon(msg);
  dprintf(DP_MODE, "PONG :%s\n", msg);
  return 0;
}

static int gotkick(char *from, char *msg)
{
  char *nick;

  nick = from;
  if (rfc_casecmp(nick, botname))
    /* Not my kick, I don't need to bother about it. */
    return 0;
  if (use_penalties) {
    last_time += 2;
    if (raw_log)
      putlog(LOG_SRVOUT, "*", "adding 2secs penalty (successful kick)");
  }
  return 0;
}

/* Another sec penalty if bot did a whois on another server.
 */
static int whoispenalty(char *from, char *msg)
{
  if (realservername && use_penalties &&
      op_strcasecmp(from, realservername)) {

    last_time += 1;

    if (raw_log)
      putlog(LOG_SRVOUT, "*", "adding 1sec penalty (remote whois)");
  }

  return 0;
}

static int got311(char *from, char *msg)
{
  char *n1, *n2, *u, *h;

  n1 = newsplit(&msg);
  n2 = newsplit(&msg);
  u = newsplit(&msg);
  h = newsplit(&msg);

  if (!n1 || !n2 || !u || !h)
    return 0;

  if (match_my_nick(n2)) {
    op_strbuf_t _b = {};
    op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "%s@%s", u, h);
    op_strlcpy(botuserhost, op_strbuf_str(&_b), sizeof botuserhost);
    op_strbuf_free(&_b);
  }

  return 0;
}

static int gotsetname(char *from, char *msg)
{
  char *nick = splitnick(&from);

  fixcolon(msg);
  /* Only update botrealname when the server echoes back our own SETNAME.
   * With the setname CAP enabled the server also sends SETNAME for other
   * channel members; those must not overwrite our realname. */
  if (match_my_nick(nick))
    op_strlcpy(botrealname, msg, sizeof botrealname);
  return 0;
}

/* BATCH — IRCv3 batch grouping (RFC-style start/end framing).
 * Format: BATCH +<refid> <type> [params...]
 *         BATCH -<refid>
 *
 * All batch types are accumulated: individual messages tagged @batch=<ref>
 * are buffered (see gotbatch_intercept in my_rawt_binds) and delivered when
 * BATCH -<ref> arrives.
 *
 * On close:
 *  - "chathistory": fires the legacy do_tcl("batch:chathistory", ...) path
 *    AND the generic H_batch bind.
 *  - ALL types: fire the generic H_batch bind:
 *      bind batch <flags> <type-pattern> <proc>
 *      proc my_handler {type ref lines} { ... }
 *  - "netsplit" / "netjoin": handled by Tcl scripts via H_batch. */
static int gotbatch(char *from, char *msg)
{
  char *refid = newsplit(&msg);

  if (!refid || !refid[0])
    return 0;

  if (refid[0] == '+') {
    char *type   = newsplit(&msg);
    char *target = newsplit(&msg);
    fixcolon(target);
    putlog(LOG_DEBUG, "*", "BATCH: open %s type=%s target=%s", refid + 1,
           type && type[0] ? type : "(unknown)", target ? target : "");
    /* Create accumulator for any batch type. */
    if (type && type[0]) {
      if (!batch_ht)
        batch_ht = op_htab_create_str("batch_accum", 8);
      if (!op_htab_has(batch_ht, refid + 1)) {
        batch_accum_t *acc = (batch_accum_t *)op_malloc(sizeof *acc);
        op_strlcpy(acc->type, type, sizeof acc->type);
        op_strlcpy(acc->target, target ? target : "", sizeof acc->target);
        acc->key   = op_strdup(refid + 1); /* shared pointer: htab key == acc->key */
        acc->lines = nullptr;
        acc->n     = 0;
        acc->cap   = 0;
        op_htab_set(batch_ht, acc->key, acc, nullptr);
      }
    }
  } else if (refid[0] == '-') {
    putlog(LOG_DEBUG, "*", "BATCH: close %s", refid + 1);
    if (batch_ht) {
      batch_accum_t *acc = (batch_accum_t *)op_htab_del(batch_ht, refid + 1);
      if (acc) {
        /* acc->key == the pointer we passed to op_htab_set; batch_accum_free
         * frees it together with the rest of the accumulator. */

        /* Legacy chathistory delivery — keep existing behaviour intact. */
        if (!op_strcasecmp(acc->type, "chathistory"))
          batch_deliver_chathistory(acc);

        /* Generic H_batch delivery for all types (including chathistory). */
        check_tcl_batch(acc->type, refid + 1, acc);

        batch_accum_free(acc);
      }
    }
  }
  return 0;
}

/* gotbatch_intercept — rawt handler that buffers lines belonging to any
 * open batch (tagged @batch=<ref>).
 *
 * Signature matches the rawt calling convention: (from, msg, tagdict).
 * Returns 1 (blocking) when the line is buffered so that the normal raw
 * handlers do not also process it.  Returns 0 for all other messages.
 *
 * Works for all batch types: chathistory, netsplit, netjoin, multiline,
 * and any future or custom types. */
static int gotbatch_intercept([[maybe_unused]] char *from,
                               char *msg,
                               [[maybe_unused]] Tcl_Obj *tags)
{
  if (!batch_ht || !current_msgtag_batch[0])
    return 0;
  batch_accum_t *acc = (batch_accum_t *)op_htab_get(batch_ht, current_msgtag_batch);
  if (!acc)
    return 0;
  /* Store the raw msg portion; the batch type from BATCH+ provides context. */
  batch_accum_append(acc, msg);
  return 1; /* block normal dispatch */
}

/* CHATHISTORY — Ophion scrollback request reply (outside a batch).
 * In practice Ophion wraps CHATHISTORY replies in BATCH; this handler
 * is a no-op safety net so the command is not left unrecognised. */
static int gotchathistory([[maybe_unused]] char *from, [[maybe_unused]] char *msg)
{
  return 0;
}

/* Got 900: RPL_LOGGEDIN, users account name is set (whether by SASL or otherwise) */
static int got900(char *from, char *msg)
{
  newsplit(&msg); /* nick */
  newsplit(&msg); /* nick!ident@host */
  newsplit(&msg); /* account */
  fixcolon(msg);
  putlog(LOG_SERV, "*", "%s: %s", from, msg);
  return 0;
}

/*
 * 465 ERR_YOUREBANNEDCREEP :You are banned from this server
 */
static int got465(char *from, char *msg)
{
  newsplit(&msg); /* nick */

  fixcolon(msg);

  putlog(LOG_SERV, "*", "Server (%s) says I'm banned: %s", from, msg);
  putlog(LOG_SERV, "*", "Disconnecting from server.");
  nuke_server("Banned from server.");
  return 1;
}

/*
 * Invalid CAP command
 */
static int got410(char *from, char *msg) {
  char *cmd;

  newsplit(&msg);

  putlog(LOG_SERV, "*", "%s", msg);
  cmd = newsplit(&msg);
  putlog(LOG_MISC, "*", "CAP sub-command %s not supported", cmd);

  return 1;
}

/* got417: ERR_INPUTTOOLONG. Client sent a message longer than allowed limit */
static int got417(char *from, char *msg) {
  newsplit(&msg);
  putlog (LOG_SERV, "*", "MESSAGE-TAG: %s reported error: %s", from, msg);

  return 1;
}

static int got421(char *from, char *msg) {
  newsplit(&msg);
  putlog(LOG_SERV, "*", "%s reported an error: %s", from, msg);

  return 1;
}

/* Helper function to quickly find a capability record.
 * Uses cap_dict (op_htab) for O(1) average lookup when populated;
 * falls back to O(n) linked-list scan during the brief window before the
 * first CAP LS reply has been processed (cap_dict not yet created). */
struct capability *find_capability(char *capname) {
  if (cap_dict)
    return op_htab_get(cap_dict, capname);

  /* Fallback: linear scan before dict is initialised */
  for (size_t i = 0; i < cap_vec.size; i++) {
    struct capability *current = (struct capability *)op_vec_get(&cap_vec, i);
    if (!op_strcasecmp(capname, current->name))
      return current;
  }
  return nullptr;
}

/* Set capability to be requested by Eggdrop */
static void add_req(char *cape) {
  struct capability *current = 0;

  putlog(LOG_DEBUG, "*", "Adding %s to CAP request list", cape);
  current = find_capability(cape);
  if (current) {
    current->requested = 1;
  } else {
    putlog(LOG_DEBUG, "*", "CAP: ERROR: Missing CAP %s record", cape);
  }
}

static void free_capability(struct capability *z) {
  for (size_t i = 0; i < z->values.size; i++)
    op_bh_free(cap_values_bh, op_vec_get(&z->values, i));
  op_vec_fini(&z->values, nullptr, nullptr);
  op_bh_free(capability_bh, z);
}

static int del_capability(char *name) {
  for (size_t i = 0; i < cap_vec.size; i++) {
    struct capability *curr = (struct capability *)op_vec_get(&cap_vec, i);
    if (!op_strcasecmp(name, curr->name)) {
      op_vec_remove_fast(&cap_vec, i);
      if (cap_dict)
        op_htab_del(cap_dict, name);
      free_capability(curr);
      return 0;
    }
  }
  putlog(LOG_SERV, "*", "CAP: %s not found, can't remove", name);
  return -1;
}


/* Remove multiple capabilities from the linked list
 * msg is in format "multi-prefix sasl server-time"
 */
static int del_capabilities(char *msg) {
  char *capptr, *saveptr = nullptr;

  for (capptr = strtok_r(msg, " ", &saveptr); capptr; capptr = strtok_r(nullptr, " ", &saveptr)) {
    del_capability(capptr);
  }
  return 0;
}

/* Add server capabilities to the linked list
 * msg is in format "multi-prefix sasl=PLAIN,EXTERNAL server-time"
 */
static int add_capabilities(const char *msg) {
  char *msgcopy = op_strdup(msg);
  char *capptr, *valptr, *val, *saveptr1 = nullptr, *saveptr2 = nullptr;
  struct capability *newcap;
  struct cap_values *newvalue;

  for (capptr = strtok_r(msgcopy, " ", &saveptr1); capptr; capptr = strtok_r(nullptr, " ", &saveptr1)) {
    valptr = strchr(capptr, '=');
    if (valptr) {
      *valptr++ = '\0';
    }
    if (find_capability(capptr)) {
      putlog(LOG_MISC, "*", "CAP: %s capability record already exists, skipping...", capptr);
      continue;
    }
    putlog(LOG_DEBUG, "*", "CAP: adding capability record: %s", capptr);
    if (!capability_bh)
      capability_bh = op_bh_create(sizeof(capability_t), 16, "capability");
    newcap = op_bh_alloc(capability_bh);
    op_strlcpy(newcap->name, capptr, sizeof newcap->name);
    op_vec_push(&cap_vec, newcap);
    /* Keep cap_dict in sync for O(1) find_capability() lookups.
     * cap_dict is pre-allocated in server_start / server_resolve_success. */
    op_htab_set(cap_dict, newcap->name, newcap, nullptr);

    if (valptr) {
      for (val = strtok_r(valptr, ",", &saveptr2); val; val = strtok_r(nullptr, ",", &saveptr2)) {
        if (!cap_values_bh)
          cap_values_bh = op_bh_create(sizeof(cap_values_t), 16, "cap_values");
        newvalue = op_bh_alloc(cap_values_bh);
        op_strlcpy(newvalue->name, val, sizeof newvalue->name);
        putlog(LOG_DEBUG, "*", "CAP: Adding value %s to capability %s", val, newcap->name);
        op_vec_push(&newcap->values, newvalue);
      }
    }
  }
  op_free(msgcopy);
  return 0;
}

static int is_cap_value(const op_vec_t *values, const char *name) {
  if (!values->size)
    return 1;
  for (size_t i = 0; i < values->size; i++) {
    const cap_values_t *v = (const cap_values_t *)op_vec_get(values, i);
    if (!strcmp(name, v->name))
      return 1;
  }
  return 0;
}

/* Got CAP message */
static int gotcap(char *from, char *msg) {
  char *cmd, *splitstr, *p;
  int remove = 0, multiline = 0;
  struct capability *current;

  newsplit(&msg);
  putlog(LOG_DEBUG, "*", "CAP: %s", msg);
  cmd = newsplit(&msg);
  /* Check for multi-line messages. If found, note it and increment to the
   * actual data field
   */
  if (msg[0] == '*') {
    multiline = 1;
    newsplit(&msg);
  }
  fixcolon(msg);
  if (!strcmp(cmd, "LS")) {
    /* Check for multi-line messages. If found, note it and increment to the cmd */
    putlog(LOG_DEBUG, "*", "CAP: %s supports CAP sub-commands: %s", from, msg);
    add_capabilities(msg);
    if (multiline) {
      return 0;
    }
    /* CAP is supported, yay! If it is supported, lets load what we want to request */
    for (size_t ci = 0; ci < cap_vec.size; ci++) {
      current = (struct capability *)op_vec_get(&cap_vec, ci); {
      if (!strcmp(current->name, "sasl")) {
        if (sasl && !(current->enabled))
          add_req(current->name);
      } else if (!strcmp(current->name, "account-notify")) {
        if ((account_notify) && (!current->enabled))
           add_req(current->name);
      } else if (!strcmp(current->name, "account-tag")) {
        if ((account_tag) && (!current->enabled))
          add_req(current->name);
      } else if (!strcmp(current->name, "extended-join")) {
        if ((extended_join) && (!current->enabled))
          add_req(current->name);
      } else if (!strcmp(current->name, "invite-notify")) {
        if ((invite_notify) && (!current->enabled))
          add_req(current->name);
      } else if (!strcmp(current->name, "away-notify")) {
        if ((away_notify) && (!current->enabled))
          add_req(current->name);
      } else if (!strcmp(current->name, "message-tags")) {
        if ((message_tags) && (!current->enabled))
          add_req(current->name);
      } else if (!strcmp(current->name, "echo-message")) {
        if ((echo_message) && (!current->enabled))
          add_req(current->name);
      } else if (!strcmp(current->name, "multi-prefix")) {
        if (!current->enabled)
          add_req(current->name);
      } else if (!strcmp(current->name, "userhost-in-names")) {
        if (!current->enabled)
          add_req(current->name);
      } else if (!strcmp(current->name, "chghost")) {
        if (!current->enabled)
          add_req(current->name);
      } else if (!strcmp(current->name, "setname")) {
        if (!current->enabled)
          add_req(current->name);
      } else if (!strcmp(current->name, "batch")) {
        /* IRCv3 batch: needed for labeled-response and chathistory */
        if (!current->enabled)
          add_req(current->name);
      } else if (!strcmp(current->name, "labeled-response")) {
        /* IRCv3 labeled-response: tag outgoing messages for echo-message
         * correlation and CHATHISTORY matching */
        if (!current->enabled)
          add_req(current->name);
      } else if (!strcmp(current->name, "msgid")) {
        /* IRCv3 msgid: unique message IDs for deduplication */
        if (!current->enabled)
          add_req(current->name);
      } else if (!strcmp(current->name, "standard-replies")) {
        /* IRCv3 standard-replies: structured error responses */
        if (!current->enabled)
          add_req(current->name);
      } else if (!strcmp(current->name, "draft/chathistory") ||
                 !strcmp(current->name, "chathistory")) {
        /* Ophion CHATHISTORY: retrieve scrollback on join */
        if (!current->enabled)
          add_req(current->name);
      } else if (!strcmp(current->name, "ophion/prop-notify")) {
        /* Ophion IRCX: auto-request property change notifications.
         * This allows the bot to receive PROP commands for channel
         * property changes (topic, memberkey, ownerkey, etc.)
         */
        if (!current->enabled)
          add_req(current->name);
      } else if (!strcmp(current->name, "ophion/multi-prefix")) {
        /* Ophion IRCX: extended prefix visibility (+qaohv) */
        if (!current->enabled)
          add_req(current->name);
      } else if (!strcmp(current->name, "server-time")) {
        /* IRCv3 server-time: adds time= ISO 8601 tag to every inbound message */
        if (!current->enabled)
          add_req(current->name);
      } else if (!strcmp(current->name, "draft/multiline") ||
                 !strcmp(current->name, "multiline")) {
        /* IRCv3 draft/multiline: BATCH-wrapped multi-line messages */
        if (!current->enabled)
          add_req(current->name);
      } else if (!strcmp(current->name, "draft/read-marker")) {
        /* IRCv3 draft/read-marker: MARKREAD last-read sync across sessions */
        if (!current->enabled)
          add_req(current->name);
      } else if (!strcmp(current->name, "cap-notify")) {
        if (!current->enabled)
          add_req(current->name);
      } else if (!strcmp(current->name, "draft/typing") ||
                 !strcmp(current->name, "typing")) {
        if (!current->enabled)
          add_req(current->name);
      } else if (!strcmp(current->name, "draft/react") ||
                 !strcmp(current->name, "react")) {
        if (!current->enabled)
          add_req(current->name);
      } else if (!strcmp(current->name, "draft/message-redaction") ||
                 !strcmp(current->name, "message-redaction")) {
        if (!current->enabled)
          add_req(current->name);
      } else if (!strcmp(current->name, "draft/channel-rename") ||
                 !strcmp(current->name, "channel-rename")) {
        if (!current->enabled)
          add_req(current->name);
      } else if (!strcmp(current->name, "bot")) {
        if (!current->enabled)
          add_req(current->name);
      } else if (!strcmp(current->name, "utf8-only")) {
        if (!current->enabled)
          add_req(current->name);
      }
      /* Add any custom capes the user listed */
      {
        char *saveptr = nullptr;
        char *cap_copy = op_strdup(cap_request);
        if ((p = strtok_r(cap_copy, " ", &saveptr))) {
          while (p != nullptr) {
            if (!strcmp(current->name, p) && (!current->enabled)) {
              add_req(p);
            }
            p = strtok_r(nullptr, " ", &saveptr);
          }
        }
        op_free(cap_copy);
      }
      }} /* end for ci / current block */
    /* Request the desired capabilities from server */
    {
      op_strbuf_t cape_req = {};
      op_strbuf_init(&cape_req);
      for (size_t ci = 0; ci < cap_vec.size; ci++) {
        current = (struct capability *)op_vec_get(&cap_vec, ci);
        if (current->requested && (!current->enabled)) {
          putlog(LOG_DEBUG, "*", "CAP: Requesting %s capability from server", current->name);
          op_strbuf_appendf(&cape_req, " %s", current->name);
        }
      }
      if (!op_strbuf_empty(&cape_req))
        dprintf(DP_MODE, "CAP REQ :%s\n", op_strbuf_str(&cape_req));
      else
        dprintf(DP_MODE, "CAP END\n");
      op_strbuf_free(&cape_req);
    }
    /* Flush any caps that were queued before CAP LS arrived. */
    cap_req_queue_flush();
    /* IRCv3 STS (Strict Transport Security): if the server advertises sts
     * with a port= value and we're on a plaintext connection, warn the user
     * so they know to switch to the TLS port. */
    {
      struct capability *stscap = find_capability("sts");
      if (stscap && stscap->values.size) {
        for (size_t vi = 0; vi < stscap->values.size; vi++) {
          const cap_values_t *v = (const cap_values_t *)op_vec_get(&stscap->values, vi);
          if (!strncmp(v->name, "port=", 5)) {
            const char *port = v->name + 5;

#ifdef TLS
            if (!use_ssl)
#endif
              putlog(LOG_SERV, "*",
                     "STS: Server offers Strict Transport Security — "
                     "TLS port %s is available. Consider using +%s in your "
                     "server list for an encrypted connection.", port, port);
#ifdef TLS
            else
              putlog(LOG_DEBUG, "*", "STS: TLS connection confirmed "
                     "(server advertises port %s)", port);
#endif
            break;
          }
        }
      }
    }
  } else if (!strcmp(cmd, "LIST")) {
    putlog(LOG_SERV, "*", "CAP: Negotiated CAP capabilities: %s", msg);
    /* You're getting the current enabled list, may as well the clear old stuff */
    if (!multistatus) {
      multistatus = 1;
      for (size_t ci = 0; ci < cap_vec.size; ci++)
        ((struct capability *)op_vec_get(&cap_vec, ci))->enabled = 0;
    }
    /* If msg starts with a *, advance to the first capability. If it doesn't,
     * this is either the end a multiline message, or not one at all, so
     * set multistatus (tracks if we are in mid-multiline message) to 0.
     */
    if (msg[0] == '*') {
      msg++;
      msg++;
    } else {
      multistatus = 0;
    }
    {
      char *saveptr = nullptr;
      splitstr = strtok_r(msg, " ", &saveptr);
      while (splitstr != nullptr) {
        current = find_capability(splitstr);
        if (!current) {
          putlog(LOG_DEBUG, "*", "CAP: %s tried to tell me we negotiated %s, \
                  but I have no record of it. Skipping...", from, splitstr);
          splitstr = strtok_r(nullptr, " ", &saveptr);
          continue;
        }
        current->enabled = 1;
        splitstr = strtok_r(nullptr, " ", &saveptr);
      }
    }
  } else if (!strcmp(cmd, "ACK")) {
    char *saveptr = nullptr;
    splitstr = strtok_r(msg, " ", &saveptr);
    while (splitstr != nullptr) {
      if (splitstr[0] == '-') {
        remove = 1;
        splitstr++;
      }
      current = find_capability(splitstr);
      if (current) {
        if (remove) {
          current->enabled = 0;
        } else {
          current->enabled = 1;
          if (sasl && !op_strcasecmp(current->name, "sasl") &&
              sasl_authenticate_initial(&current->values))
            return 1;
        }
      }
      remove = 0;
      splitstr = strtok_r(nullptr, " ", &saveptr);
    }
    current = find_capability("sasl");
    /* Let SASL code send END if SASL is enabled, to avoid race condition */
    if (!current || !current->enabled) {
      dprintf(DP_MODE, "CAP END\n");
    }
    {
      op_strbuf_t caplog = {};
      op_strbuf_init(&caplog);
      for (size_t ci = 0; ci < cap_vec.size; ci++) {
        current = (struct capability *)op_vec_get(&cap_vec, ci);
        if (current->enabled)
          op_strbuf_appendf(&caplog, " %s", current->name);
      }
      putlog(LOG_SERV, "*", "CAP: Current negotiations with %s:%s", from,
             op_strbuf_str(&caplog));
      op_strbuf_free(&caplog);
    }
  } else if (!strcmp(cmd, "NAK")) {
    putlog(LOG_SERV, "*", "CAP: Requested capability change %s rejected by %s",
        msg, from);
    dprintf(DP_MODE, "CAP END\n");
  } else if (!strcmp(cmd, "NEW")) {
    putlog(LOG_SERV, "*", "CAP: %s capabilities now available", msg);
    add_capabilities(msg);
    {
      op_strbuf_t newreq = {};
      op_strbuf_init(&newreq);
      char *saveptr = nullptr;
      char *newmsg = op_strdup(msg);
      char *tok = strtok_r(newmsg, " ", &saveptr);
      while (tok) {
        char *eq = strchr(tok, '=');
        if (eq) *eq = '\0';
        current = find_capability(tok);
        if (current && !current->enabled) {
          current->requested = 1;
          op_strbuf_appendf(&newreq, " %s", tok);
        }
        tok = strtok_r(nullptr, " ", &saveptr);
      }
      op_free(newmsg);
      if (!op_strbuf_empty(&newreq))
        dprintf(DP_MODE, "CAP REQ :%s\n", op_strbuf_str(&newreq));
      op_strbuf_free(&newreq);
    }
  } else if (!strcmp(cmd, "DEL")) {
      putlog(LOG_SERV, "*", "CAP: %s capabilities no longer available", msg);
      del_capabilities(msg);
  }
  return 0;
}

/* =========================================================================
 * IRCv3 MONITOR reply batching — numerics 730/731
 *
 * Servers may send multiple 730/731 lines in a burst (one per nick, or
 * with comma-separated nicks per line).  We accumulate all nicks across
 * consecutive 730s / 731s and fire a single Tcl bind per burst:
 *
 *   bind monitor-online  <flags> * <proc>   ;  proc <nicklist>
 *   bind monitor-offline <flags> * <proc>   ;  proc <nicklist>
 *
 * where <nicklist> is a Tcl list of nick names.
 *
 * The individual per-nick "monitor" bind (H_monitor) continues to fire as
 * before so existing scripts are not broken.
 * ========================================================================= */

static op_vec_t monitor_online_batch;   /* char * entries, op_strdup'd */
static op_vec_t monitor_offline_batch;  /* char * entries, op_strdup'd */

/* monitor_batch_free_cb — op_vec free callback for batch entries */
static void monitor_batch_free_cb(void *elem, void *ud)
{
  (void)ud;
  op_free(elem);
}

/* monitor_batch_fire — build a Tcl list from the given batch vec, call the
 * named bind table pattern, then clear and free the batch entries. */
static void monitor_batch_fire(op_vec_t *batch, const char *bindname)
{
  if (batch->size == 0)
    return;

  Tcl_DString ds;
  Tcl_DStringInit(&ds);
  for (size_t i = 0; i < batch->size; i++)
    Tcl_DStringAppendElement(&ds, (char *)op_vec_get(batch, i));

  Tcl_SetVar(interp, "_monbatch1", Tcl_DStringValue(&ds), 0);
  do_tcl((char *)bindname, Tcl_DStringValue(&ds));

  Tcl_DStringFree(&ds);
  op_vec_clear(batch, monitor_batch_free_cb, nullptr);
}

/* Got 730/RPL_MONONLINE
 * :<server> 730 <nick> :target[!user@host][,target[!user@host]]*
 */
static int got730or1(char *from, char *msg, int code)
{
  char *nick, *tok;

  newsplit(&msg);               /* Get rid of nick */
  fixcolon(msg);                /* Get rid of :    */

  op_vec_t *batch = (code == 1) ? &monitor_online_batch : &monitor_offline_batch;

  char *saveptr = nullptr;
  for (tok = strtok_r(msg, ",", &saveptr); tok; tok = strtok_r(nullptr, ",", &saveptr)) {
    char *tok_copy = op_strdup(tok);
    char *tok_ptr  = tok_copy;
    if (strchr(tok_ptr, '!')) {
      nick = splitnick(&tok_ptr);
    } else {
      nick = tok_ptr;
    }
    for (size_t i = 0; i < monitor_vec.size; i++) {
      monitor_list_t *current = (monitor_list_t *)op_vec_get(&monitor_vec, i);
      if (!rfc_casecmp(current->nick, nick)) {
        if (code == 1) {
          current->online = 1;
          putlog(LOG_SERV, "*", "%s is now online", nick);
        } else {
          current->online = 0;
          putlog(LOG_SERV, "*", "%s is now offline", nick);
        }
        /* fire the per-nick legacy bind */
        check_tcl_monitor(nick, code);
      }
    }
    /* accumulate into batch for the burst-level bind */
    op_vec_push(batch, op_strdup(nick));
    op_free(tok_copy);
  }
  return 0;
}

static int check_tcl_stdreply(char *from, const char *msgtype, char *cmd,
                               char *code, const char *context, char *desc)
{
  op_strbuf_t mask = {};
  op_strbuf_init(&mask);
  int x;

  op_strbuf_appendf(&mask, "%s:%s:%s", msgtype, cmd, code);
  Tcl_SetVar(interp, "_sr1", from,     0);
  Tcl_SetVar(interp, "_sr2", msgtype,  0);
  Tcl_SetVar(interp, "_sr3", cmd,      0);
  Tcl_SetVar(interp, "_sr4", code,     0);
  Tcl_SetVar(interp, "_sr5", context,  0);
  Tcl_SetVar(interp, "_sr6", desc,     0);
  x = check_tcl_bind(H_stdreply, op_strbuf_str(&mask), 0,
                     " $_sr1 $_sr2 $_sr3 $_sr4 $_sr5 $_sr6",
                     MATCH_MASK | BIND_STACKABLE | BIND_WANTRET);
  op_strbuf_free(&mask);
  return (x == BIND_EXEC_LOG);
}

/* Got IRCv3 standard-reply
 * :<server> <FAIL|WARN|NOTE> <command> <code> [<context>...] :<description>
 */
static int gotstdreply(char *from, char *msgtype, char *msg)
{
  char *cmd, *code, *text, *p;
  op_strbuf_t context = {};
  op_strbuf_init(&context);

  cmd  = newsplit(&msg);
  code = newsplit(&msg);
  /* Find the human-readable description: it follows a " :" separator when it
   * may contain spaces, or is simply the remaining word if there is no " :". */
  p = strstr(msg, " :");
  if (p) {
    /* context tokens sit between code and the " :" */
    if (p != msg)
      op_strbuf_append(&context, msg, (size_t)(p - msg));
    text = p + 2;           /* skip the " :" */
  } else {
    /* single-word description with no context */
    text = msg;
    if (*text == ':')
      text++;               /* strip bare leading colon if present */
  }
  putlog(LOG_SERV, "*", "%s: %s: Received a %s message from %s: %s",
         cmd, code, msgtype, from, text);
  check_tcl_stdreply(from, msgtype, cmd, code, op_strbuf_str(&context), text);
  op_strbuf_free(&context);
  return 0;
}

/* Got IRCv3 FAIL standard-reply */
static int gotstdfail(char *from, char *msg)
{
  gotstdreply(from, "FAIL", msg);
  return 0;
}

/* Got IRCv3 NOTE standard-reply */
static int gotstdnote(char *from, char *msg)
{
  gotstdreply(from, "NOTE", msg);
  return 0;
}

/* Got IRCv3 WARN standard-reply */
static int gotstdwarn(char *from, char *msg)
{
  gotstdreply(from, "WARN", msg);
  return 0;
}

/* Got 730/RPL_MONONLINE
 * :<server> 730 <nick> :target[!user@host][,target[!user@host]]*
 */
static int got730(char *from, char *msg)
{
  got730or1(from, msg, 1);
  /* Fire monitor-online bind with the accumulated nick list as a Tcl list. */
  monitor_batch_fire(&monitor_online_batch, "monitor-online");
  return 0;
}

/* Got 731/RPL_MONOFFLINE
 * :<server> 731 <nick> :target[,target2]*
 */
static int got731(char *from, char *msg)
{
  got730or1(from, msg, 0);
  /* Fire monitor-offline bind with the accumulated nick list as a Tcl list. */
  monitor_batch_fire(&monitor_offline_batch, "monitor-offline");
  return 0;
}

/* Got 732/RPL_MONLIST
 * :<server> 732 <nick> :target[,target2]*
 *
 * Clear the existing list, replace it with what the server sends us, as
 * that is what is 100% accurate
 */
static int got732(char *from, char *msg)
{
  char *tok, *nick;

/* Did we already get a 732? If no, clear the existing list, otherwise leave
 * it for appending
 */
  if (!monitor732) {
    for (size_t i = 0; i < monitor_vec.size; i++)
      op_bh_free(monitor_heap, (monitor_list_t *)op_vec_get(&monitor_vec, i));
    op_vec_clear(&monitor_vec, nullptr, nullptr);
  }

  newsplit(&msg);               /* Get rid of nick */
  fixcolon(msg);                /* Get rid of :    */

  char *saveptr = nullptr;
  for (tok = strtok_r(msg, ",", &saveptr); tok && *tok; tok = strtok_r(nullptr, ",", &saveptr)) {
    /* returned target could be in nick!u@host format */
    if (strchr(tok, '!')) {
      nick = splitnick(&tok);
    } else {
      nick = tok;
    }
    monitor_add(nick, 0);
  }
  monitor732 = 1;
  return 0;
}

/* Got 733/RPL_ENDOFMONLIST
 * :<server> 733 <nick> :End of MONITOR list
 */
static int got733(char *from, char *msg)
{
  monitor732 = 0;
  return 0;
}

/* Got 734/RPL_MONLISTFULL
 * :<server> 734 <nick> <limit> <targets> :Monitor list is full.
 */
static int got734(char *from, char *msg)
{
  putlog(LOG_SERV, "*", "Server monitor list is full, nickname not added");
  return 0;
}

static int server_isupport(char *key, char *isset_str, char *value)
{
  int isset = !strcmp(isset_str, "1");

  if (!strcmp(key, "NICKLEN") || !strcmp(key, "MAXNICKLEN")) {
    isupport_parseint(key, isset ? value : nullptr, 9, NICKMAX, 1, 9, &nick_len);
  } else if (!strcmp(key, "MONITOR")) {
    monitor005 = isset;
    isupport_parseint(key, isset ? value : nullptr, 1, 500, 1, 0, &max_monitor);
  } else if (!strcmp(key, "EXTBAN")) {
    if (isset && value && value[0]) {
      /* Format: EXTBAN=<prefix>,<types>  e.g. EXTBAN=~,amrRszqjnt */
      char *comma = strchr(value, ',');
      if (comma) {
        extban_prefix = value[0];
        op_strlcpy(extban_types, comma + 1, sizeof extban_types);
      } else {
        /* No comma — treat entire value as type list, no prefix */
        extban_prefix = 0;
        op_strlcpy(extban_types, value, sizeof extban_types);
      }
      putlog(LOG_MISC, "*", "EXTBAN: prefix='%c' types='%s'",
             extban_prefix ? extban_prefix : '-', extban_types);
    } else {
      /* EXTBAN unset (DEL or server disconnect reset) */
      extban_prefix = 0;
      extban_types[0] = '\0';
    }
  }
  return 0;
}

/* =========================================================================
 * IRCX / Ophion protocol handlers
 * Reference: https://github.com/devinkbrown/ophion
 * ========================================================================= */

/* Got 800: RPL_IRCX — server confirms IRCX mode is now active.
 * Format: :server 800 botnick :IRCX <version> <network>
 *
 * Ophion sends this in response to the client's "IRCX" command.
 * "ISIRCX" is an alias (same server handler) for unregistered clients.
 * Either way, receiving 800 means IRCX mode is fully enabled.
 */
static int got800(char *from, char *msg)
{
  newsplit(&msg); /* skip botnick */
  fixcolon(msg);
  newsplit(&msg); /* skip IRCX version token */
  /* Optional: remaining text is the network name on Ophion */
  if (*msg)
    op_strlcpy(ircx_network, msg, sizeof(ircx_network));
  /* Fall back to ISUPPORT NETWORK= if 800 reply didn't carry a name */
  if (!ircx_network[0]) {
    const char *net = isupport_get("NETWORK", strlen("NETWORK"));
    if (net)
      op_strlcpy(ircx_network, net, sizeof(ircx_network));
  }

  ircx_negotiating = 0;
  ircx_enabled     = 1;
  ircx_owner_support = 1;
  ircx_prop_support  = 1;
  putlog(LOG_MISC, "*", "IRCX: Mode enabled on %s (network: %s)",
         from, ircx_network[0] ? ircx_network : "unknown");

  /* Trigger auto-owner joins now that IRCX is confirmed */
  ircx_do_autoowner();
  return 0;
}

/* Got 801: RPL_PROPS — property value reply.
 * Format: :server 801 botnick target propname :value
 */
static int got801(char *from, char *msg)
{
  char *target, *propname;
  newsplit(&msg); /* skip botnick */
  target = newsplit(&msg);
  propname = newsplit(&msg);
  fixcolon(msg);
  putlog(LOG_MISC, target, "IRCX PROP %s on %s = %s", propname, target, msg);
  check_tcl_event("ircx-prop");
  return 0;
}

/* Got 802: RPL_ENDOFPROPS — end of PROP LIST reply. */
static int got802(char *from, char *msg)
{
  return 0; /* nothing to do; consumed */
}

/* Got 803: RPL_ACCESSLIST — one entry from ACCESS LIST reply.
 * Format: :server 803 botnick channel level mask :setter
 */
static int got803(char *from, char *msg)
{
  char *channel, *level, *mask;
  newsplit(&msg); /* skip botnick */
  channel  = newsplit(&msg);
  level    = newsplit(&msg);
  mask     = newsplit(&msg);
  fixcolon(msg);
  putlog(LOG_MISC, channel, "IRCX ACCESS: %s is %s on %s (set by %s)",
         mask, level, channel, msg[0] ? msg : "unknown");
  return 0;
}

/* Got 804: RPL_ENDOFACCESS — end of ACCESS LIST reply. */
static int got804(char *from, char *msg)
{
  return 0;
}

/* Got PROP command from server (property change notification).
 * Format: :nick!user@host PROP target propname :value
 */
static int gotprop(char *from, char *msg)
{
  char *target, *propname;
  target   = newsplit(&msg);
  propname = newsplit(&msg);
  fixcolon(msg);
  putlog(LOG_MISC, target, "IRCX: %s set PROP %s on %s = %s",
         from, propname, target, msg);
  /* Fire Tcl bind so scripts can react to property changes */
  Tcl_SetVar(interp, "_ircx_prop_from",   from,     0);
  Tcl_SetVar(interp, "_ircx_prop_target", target,   0);
  Tcl_SetVar(interp, "_ircx_prop_name",   propname, 0);
  Tcl_SetVar(interp, "_ircx_prop_value",  msg,      0);
  check_tcl_event("ircx-prop-change");
  return 0;
}

/* WHISPER — Ophion IRCX channel-scoped private message.
 * Format: :nick!user@host WHISPER #channel target :message
 * Both parties must be members of #channel.  The bot reacts to this
 * exactly like a PRIVMSG but notes the channel scope in the log. */
static int gotwhisper(char *from, char *msg)
{
  char *nick, *channel, *target;

  if (strchr(from, '!'))
    nick = splitnick(&from);
  else
    nick = from;

  channel = newsplit(&msg);
  target  = newsplit(&msg);
  fixcolon(msg);

  putlog(LOG_SERV, channel, "WHISPER from %s(%s) to %s on %s: %s",
         nick, from, target, channel, msg);

  /* Route to the msg bind if the bot is the target, otherwise log only */
  if (match_my_nick(target)) {
    struct userrec *u;
    op_strbuf_t hostbuf = {};
    op_strbuf_init(&hostbuf);
    op_strbuf_appendf(&hostbuf, "%s!%s", nick, from);
    u = get_user_by_host(op_strbuf_str(&hostbuf));
    op_strbuf_free(&hostbuf);
    check_tcl_msg("whisper", nick, from, u, msg);
  }
  return 0;
}

/* Got ACCESS command from server (access list change notification).
 * Format: :nick!user@host ACCESS channel ADD|DEL level mask
 */
static int gotaccess(char *from, char *msg)
{
  char *channel, *op, *level, *mask;
  channel = newsplit(&msg);
  op      = newsplit(&msg);
  level   = newsplit(&msg);
  mask    = newsplit(&msg);
  fixcolon(mask);
  putlog(LOG_MISC, channel, "IRCX: %s %s access %s %s on %s",
         from, op, level, mask, channel);
  return 0;
}

/* RENAME — IRCv3 draft/channel-rename.
 * :nick!user@host RENAME #old #new :reason
 * The server renames a channel.  Clients that negotiated the capability
 * receive this instead of a KICK+JOIN pair. */
static int gotrename(char *from, char *msg)
{
  char *nick, *oldchan, *newchan;
  struct chanset_t *chan;

  if (strchr(from, '!'))
    nick = splitnick(&from);
  else
    nick = from;

  oldchan = newsplit(&msg);
  newchan = newsplit(&msg);
  fixcolon(msg);

  putlog(LOG_MISC, oldchan, "RENAME: %s renamed %s to %s (%s)",
         nick, oldchan, newchan, msg);

  chan = findchan(oldchan);
  if (!chan)
    chan = findchan_by_dname(oldchan);
  if (chan) {
    chan_htab_del(chan);
    op_strlcpy(chan->dname, newchan, sizeof chan->dname);
    op_strlcpy(chan->name, newchan, sizeof chan->name);
    chan_htab_add(chan);
  }
  return 0;
}

/* REDACT — IRCv3 draft/message-redaction.
 * :nick!user@host REDACT <target> <msgid> [:reason]
 * Notifies that a previously sent message should be hidden. */
static int gotredact(char *from, char *msg)
{
  char *nick, *target, *msgid;

  if (strchr(from, '!'))
    nick = splitnick(&from);
  else
    nick = from;

  target = newsplit(&msg);
  msgid  = newsplit(&msg);
  fixcolon(msg);

  putlog(LOG_SERV, target, "REDACT: %s redacted message %s on %s%s%s",
         nick, msgid, target, msg[0] ? ": " : "", msg);
  return 0;
}

/* KNOCK — channel knock notification from another user.
 * :nick!user@host KNOCK #channel
 * Someone is requesting an invite to an invite-only channel. */
static int gotknock(char *from, char *msg)
{
  char *nick, *channel;

  if (strchr(from, '!'))
    nick = splitnick(&from);
  else
    nick = from;

  channel = newsplit(&msg);
  fixcolon(msg);

  putlog(LOG_MISC, channel, "KNOCK: %s is requesting access to %s",
         nick, channel);
  return 0;
}

/* REQUEST — IRCX typed client-to-client message.
 * :nick!user@host REQUEST <target> <tag> :text */
static int gotrequest(char *from, char *msg)
{
  char *nick, *target, *tag;

  if (strchr(from, '!'))
    nick = splitnick(&from);
  else
    nick = from;

  target = newsplit(&msg);
  tag    = newsplit(&msg);
  fixcolon(msg);

  putlog(LOG_SERV, target, "REQUEST from %s tag=%s on %s: %s",
         nick, tag, target, msg);
  return 0;
}

/* REPLY — IRCX typed reply to a previous REQUEST.
 * :nick!user@host REPLY <target> <tag> :text */
static int gotreply(char *from, char *msg)
{
  char *nick, *target, *tag;

  if (strchr(from, '!'))
    nick = splitnick(&from);
  else
    nick = from;

  target = newsplit(&msg);
  tag    = newsplit(&msg);
  fixcolon(msg);

  putlog(LOG_SERV, target, "REPLY from %s tag=%s on %s: %s",
         nick, tag, target, msg);
  return 0;
}

/* 811 RPL_LISTXSTART — IRCX extended channel list header */
static int got811(char *from, char *msg)
{
  putlog(LOG_SERV, "*", "IRCX: LISTX listing started");
  return 0;
}

/* 812 RPL_LISTXENTRY — IRCX extended channel list entry.
 * :<server> 812 <nick> <channel> <modes> <members> <created> <topictime> :<topic> */
static int got812(char *from, char *msg)
{
  char *nick, *channel, *modes, *members, *created, *topictime;

  nick      = newsplit(&msg);
  channel   = newsplit(&msg);
  modes     = newsplit(&msg);
  members   = newsplit(&msg);
  created   = newsplit(&msg);
  topictime = newsplit(&msg);
  fixcolon(msg);

  (void)nick;
  putlog(LOG_SERV, "*", "IRCX LISTX: %s [%s] %s members created=%s topic=%s: %s",
         channel, modes, members, created, topictime, msg);
  return 0;
}

/* 813 RPL_LISTXPICS — IRCX PICS label for a LISTX entry */
static int got813(char *from, char *msg)
{
  char *nick, *channel;

  nick    = newsplit(&msg);
  channel = newsplit(&msg);
  fixcolon(msg);
  (void)nick;

  putlog(LOG_SERV, "*", "IRCX LISTX: %s PICS=%s", channel, msg);
  return 0;
}

/* 816 RPL_LISTXTRUNC — IRCX LISTX output truncated */
static int got816(char *from, char *msg)
{
  putlog(LOG_SERV, "*", "IRCX: LISTX output truncated (too many results)");
  return 0;
}

/* 817 RPL_LISTXEND — IRCX LISTX listing complete */
static int got817(char *from, char *msg)
{
  putlog(LOG_SERV, "*", "IRCX: LISTX listing complete");
  return 0;
}

/* 806 RPL_MODEXLIST — IRCX MODEX mode listing */
static int got806(char *from, char *msg)
{
  char *nick, *target;

  nick   = newsplit(&msg);
  target = newsplit(&msg);
  fixcolon(msg);
  (void)nick;

  putlog(LOG_SERV, "*", "IRCX MODEX: %s modes: %s", target, msg);
  return 0;
}

/* 807 RPL_MODEXEND — IRCX MODEX listing complete */
static int got807(char *from, char *msg)
{
  char *nick, *target;

  nick   = newsplit(&msg);
  target = newsplit(&msg);
  (void)nick;

  putlog(LOG_SERV, "*", "IRCX MODEX: %s end of modes", target);
  return 0;
}

/* Handle IRCX ISUPPORT token: when server sends ISUPPORT with IRCX token,
 * automatically negotiate IRCX mode if ircx_auto_negotiate is set.
 */
static int server_isupport_ircx(char *key, char *isset_str, char *value)
{
  if (!strcmp(key, "IRCX") && !strcmp(isset_str, "1") && ircx_auto_negotiate) {
    putlog(LOG_MISC, "*", "IRCX: Server advertises IRCX via ISUPPORT");
    ircx_owner_support = 1;
    ircx_prop_support  = 1;
    ircx_send_negotiate(); /* guarded against double-send */
  }
  return 0;
}

static cmd_t my_raw_binds[] = {
  {"PRIVMSG",      "",   (IntFunc) gotmsg,          nullptr},
  {"NOTICE",       "",   (IntFunc) gotnotice,       nullptr},
  {"MODE",         "",   (IntFunc) gotmode,         nullptr},
  {"PING",         "",   (IntFunc) gotping,         nullptr},
  {"PONG",         "",   (IntFunc) gotpong,         nullptr},
  {"WALLOPS",      "",   (IntFunc) gotwall,         nullptr},
  {"FAIL",         "",   (IntFunc) gotstdfail,      nullptr},
  {"NOTE",         "",   (IntFunc) gotstdnote,      nullptr},
  {"WARN",         "",   (IntFunc) gotstdwarn,      nullptr},
  {"001",          "",   (IntFunc) got001,          nullptr},
  {"005",          "",   (IntFunc) got005,          nullptr},
  {"303",          "",   (IntFunc) got303,          nullptr},
  {"311",          "",   (IntFunc) got311,          nullptr},
  {"318",          "",   (IntFunc) whoispenalty,    nullptr},
  {"410",          "",   (IntFunc) got410,          nullptr},
  {"417",          "",   (IntFunc) got417,          nullptr},
  {"421",          "",   (IntFunc) got421,          nullptr},
  {"432",          "",   (IntFunc) got432,          nullptr},
  {"433",          "",   (IntFunc) got433,          nullptr},
  {"437",          "",   (IntFunc) got437,          nullptr},
  {"438",          "",   (IntFunc) got438,          nullptr},
  {"451",          "",   (IntFunc) got451,          nullptr},
  {"442",          "",   (IntFunc) got442,          nullptr},
  {"465",          "",   (IntFunc) got465,          nullptr},
  {"730",          "",   (IntFunc) got730,          nullptr},
  {"731",          "",   (IntFunc) got731,          nullptr},
  {"732",          "",   (IntFunc) got732,          nullptr},
  {"733",          "",   (IntFunc) got733,          nullptr},
  {"734",          "",   (IntFunc) got734,          nullptr},
  {"900",          "",   (IntFunc) got900,          nullptr},
  /* IRCX/Ophion extended protocol handlers */
  {"800",          "",   (IntFunc) got800,          nullptr},
  {"801",          "",   (IntFunc) got801,          nullptr},
  {"802",          "",   (IntFunc) got802,          nullptr},
  {"803",          "",   (IntFunc) got803,          nullptr},
  {"804",          "",   (IntFunc) got804,          nullptr},
  {"806",          "",   (IntFunc) got806,          nullptr},
  {"807",          "",   (IntFunc) got807,          nullptr},
  {"811",          "",   (IntFunc) got811,          nullptr},
  {"812",          "",   (IntFunc) got812,          nullptr},
  {"813",          "",   (IntFunc) got813,          nullptr},
  {"816",          "",   (IntFunc) got816,          nullptr},
  {"817",          "",   (IntFunc) got817,          nullptr},
  /* Note: 901 (ERR_NOTIRCX) and 902 (ERR_ALREADYIRCX) overlap with SASL
   * numerics (RPL_LOGGEDOUT, ERR_NICKLOCKED) — sasl.c handles those. */
  {"PROP",         "",   (IntFunc) gotprop,         nullptr},
  {"ACCESS",       "",   (IntFunc) gotaccess,       nullptr},
  {"WHISPER",      "",   (IntFunc) gotwhisper,      nullptr},
  {"REQUEST",      "",   (IntFunc) gotrequest,      nullptr},
  {"REPLY",        "",   (IntFunc) gotreply,        nullptr},
  {"RENAME",       "",   (IntFunc) gotrename,       nullptr},
  {"REDACT",       "",   (IntFunc) gotredact,       nullptr},
  {"KNOCK",        "",   (IntFunc) gotknock,        nullptr},
  {"NICK",         "",   (IntFunc) gotnick,         nullptr},
  {"ERROR",        "",   (IntFunc) goterror,        nullptr},
/* ircu2.10.10 has a bug when a client is throttled ERROR is sent wrong */
  {"ERROR:",       "",   (IntFunc) goterror,        nullptr},
  {"KICK",         "",   (IntFunc) gotkick,         nullptr},
  {"CAP",          "",   (IntFunc) gotcap,          nullptr},
  {"SETNAME",      "",   (IntFunc) gotsetname,      nullptr},
  {"BATCH",        "",   (IntFunc) gotbatch,        nullptr},
  {"CHATHISTORY",  "",   (IntFunc) gotchathistory,  nullptr},
  {nullptr,           nullptr, nullptr,                      nullptr}
};

static cmd_t my_rawt_binds[] = {
  {"TAGMSG",       "",   (IntFunc) gottagmsg,              nullptr},
  {"*",            "",   (IntFunc) gotbatch_intercept,     "server:batch-intercept"},
  {nullptr,           nullptr, nullptr,                      nullptr}
};

static cmd_t my_isupport_binds[] = {
  {"*",      "",   (IntFunc) server_isupport,       "server:isupport"},
  {"IRCX",   "",   (IntFunc) server_isupport_ircx,  "server:isupport-ircx"},
  {nullptr,   nullptr,   nullptr,                                            nullptr}
};

static void server_resolve_success(int);
static void server_resolve_failure(int);

/* Hook up to a server
 */
static void connect_server(void)
{
  char pass[NEWSERVERPASSMAX], botserver[NEWSERVERMAX];
#ifdef IPV6
  char buf[sizeof(struct in6_addr)];
#endif
  int servidx;
  unsigned int botserverport = 0;

  lastpingcheck = 0;
  trying_server = now;
  empty_msgq();
  if (newserverport) {          /* Jump to specified server */
    curserv = -1;             /* Reset server list */
    op_strlcpy(botserver, newserver, sizeof botserver);
    botserverport = newserverport;
    op_strlcpy(pass, newserverpass, sizeof pass);
    newserver[0] = 0;
    newserverport = 0;
    newserverpass[0] = 0;
  } else {
    if (curserv == -1)
      curserv = 999;
    pass[0] = 0;
  }
  if (!cycle_time) {
    struct chanset_t *chan;

    if (!serverlist_vec.size && !botserverport) {
      putlog(LOG_SERV, "*", "No servers in server list");
      cycle_time = 300;
      return;
    }

    servidx = new_dcc(&DCC_DNSWAIT, sizeof(struct dns_info));
    if (servidx < 0) {
      putlog(LOG_SERV, "*",
             "NO MORE DCC CONNECTIONS -- Can't create server connection.");
      return;
    }

    isupport_preconnect();
    if (connectserver[0])       /* drummer */
      do_tcl("connect-server", connectserver);
    check_tcl_event("connect-server");
    next_server(&curserv, botserver, sizeof botserver, &botserverport, pass, sizeof pass);

    op_strbuf_t s = {};
    op_strbuf_init(&s);
#ifdef IPV6
    if (inet_pton(AF_INET6, botserver, buf))
      op_strbuf_appendf(&s, "%s [%s]", IRC_SERVERTRY, botserver);
    else
#endif
      op_strbuf_appendf(&s, "%s %s", IRC_SERVERTRY, botserver);

#ifdef TLS
    op_strbuf_appendf(&s, ":%s%d", use_ssl ? "+" : "", botserverport);
    dcc[servidx].ssl = use_ssl;
#else
    op_strbuf_appendf(&s, ":%d", botserverport);
#endif
    putlog(LOG_SERV, "*", "%s", op_strbuf_str(&s));
    op_strbuf_free(&s);
    dcc[servidx].port = botserverport;
    op_strlcpy(dcc[servidx].nick, "(server)", sizeof(dcc[servidx].nick));
    op_strlcpy(dcc[servidx].host, botserver, UHOSTLEN);

    botuserhost[0] = 0;

    nick_juped = 0;
    for (chan = chanset; chan; chan = chan->next)
      chan->status &= ~CHAN_JUPED;

    dcc[servidx].timeval = now;
    dcc[servidx].sock = -1;
    size_t _len1 = strlen(dcc[servidx].host) + 1;
    dcc[servidx].u.dns->host = get_data_ptr(_len1);
    op_strlcpy(dcc[servidx].u.dns->host, dcc[servidx].host, _len1);
    size_t _len2 = strlen(pass) + 1;
    dcc[servidx].u.dns->cbuf = get_data_ptr(_len2);
    op_strlcpy(dcc[servidx].u.dns->cbuf, pass, _len2);
    dcc[servidx].u.dns->dns_success = server_resolve_success;
    dcc[servidx].u.dns->dns_failure = server_resolve_failure;
    dcc[servidx].u.dns->dns_type = RES_IPBYHOST;
    dcc[servidx].u.dns->type = &SERVER_SOCKET;
    dcc[servidx].status |= STAT_SERV;

    if (server_cycle_wait)
      /* Back to 1st server & set wait time.
       * Note: Put it here, just in case the server quits on us quickly
       */
      cycle_time = server_cycle_wait;
    else
      cycle_time = 0;

    /* I'm resolving... don't start another server connect request */
    resolvserv = 1;
    /* Resolve the hostname. */
    dcc_dnsipbyhost(dcc[servidx].host);
  }
}

static void server_resolve_failure(int servidx)
{
  serv = -1;
  resolvserv = 0;
  putlog(LOG_SERV, "*", "%s %s (%s)", IRC_FAILEDCONNECT, dcc[servidx].host,
         IRC_DNSFAILED);
  check_tcl_event("fail-server");
  lostdcc(servidx);
}

static void server_resolve_success(int servidx)
{
  char pass[121];
  op_strbuf_t errstr2 = {};
  op_strbuf_init(&errstr2);

  resolvserv = 0;
  op_strlcpy(pass, dcc[servidx].u.dns->cbuf, sizeof pass);
  changeover_dcc(servidx, &SERVER_SOCKET, 0);
  dcc[servidx].sock = getsock(dcc[servidx].sockname.family, SOCK_CONNECT);
  setsnport(dcc[servidx].sockname, dcc[servidx].port);
  serv = open_telnet_raw(dcc[servidx].sock, &dcc[servidx].sockname);
  if (serv < 0) {
    char *errstr = nullptr;
    if (errno == EINVAL) {
      errstr = IRC_VHOSTWRONGNET;
    } else if (errno == EADDRNOTAVAIL) {
      errstr = IRC_VHOSTBADADDR;
#ifdef IPV6
    } else if (errno == ENETUNREACH) {
      errstr = strerror(errno);
      op_strbuf_appendf(&errstr2, " prefer-ipv6 %i", pref_af);
#endif
    } else {
      errstr = strerror(errno);
    }
    putlog(LOG_SERV, "*", "%s %s (%s ip %s port %i %s)", IRC_FAILEDCONNECT,
           dcc[servidx].host, errstr, iptostr(&dcc[servidx].sockname.addr.sa),
           dcc[servidx].port,
           errno == ENETUNREACH ? op_strbuf_str(&errstr2) : "");

    check_tcl_event("fail-server");
    op_strbuf_free(&errstr2);
    lostdcc(servidx);
    return;
  }
#ifdef TLS
  if (dcc[servidx].ssl && ssl_handshake(serv, TLS_CONNECT, tls_vfyserver,
                                        LOG_SERV, dcc[servidx].host, nullptr)) {
    putlog(LOG_SERV, "*", "%s %s (%s)", IRC_FAILEDCONNECT, dcc[servidx].host,
           "TLS negotiation failure");
    check_tcl_event("fail-server");
    op_strbuf_free(&errstr2);
    lostdcc(servidx);
    return;
  }
#endif
  /* Queue standard login */
  dcc[servidx].timeval = now;
  SERVER_SOCKET.timeout_val = &server_timeout;
  /* Another server may have truncated it, so use the original */
  op_strlcpy(botname, origbotname, sizeof(botname));
  /* Start alternate nicks from the beginning */
  altnick_char = 0;
  check_tcl_event("preinit-server");
  /* Re-allocate cap_dict for this connection (disconnect_server destroyed it).
   * This ensures it is always available before the CAP LS reply arrives. */
  if (!cap_dict)
    cap_dict = op_htab_create_istr("capabilities", 32);
  /* Reset the outgoing burst rate limiter for the new connection. */
  op_ratelimit_reset(&outgoing_rl, op_current_time_usec());
  /* See if server supports CAP command */
  dprintf(DP_MODE, "CAP LS 302\n");
  if (pass[0])
    dprintf(DP_MODE, "PASS %s\n", pass);
  dprintf(DP_MODE, "NICK %s\n", botname);

  rmspace(botrealname);
  if (botrealname[0] == 0)
    op_strlcpy(botrealname, "/msg LamestBot hello", sizeof(botrealname));
  dprintf(DP_MODE, "USER %s . . :%s\n", botuser, botrealname);
  op_strbuf_free(&errstr2);

  /* Wait for async result now. */
}
