/*
 * botmsg.c -- handles:
 *   formatting of messages to be sent on the botnet
 *   sending different messages to different versioned bots
 *
 * by Darrin Smith (beldin@light.iinet.net.au)
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
#include "script.h"

extern struct dcc_t *dcc;
extern int dcc_total, tands;
extern char botnetnick[];
extern party_t *party;
extern Tcl_Interp *interp;
extern struct userrec *userlist;

/* OBUF removed — messages are now passed directly from op_strbuf_t to
 * dprint()/send_tand_but() without an intermediate fixed-size copy.  */


/* Old pre-1.3 botnet protocol removed — all peers must speak NEAT_BOTNET. */

/* Thank you ircu :) */
static const char tobase64array[64] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
  'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
  'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '[', ']'
};

char *int_to_base64(unsigned int val)
{
  static char buf_base64[12];
  int i = 11;

  buf_base64[11] = 0;
  if (!val) {
    buf_base64[10] = 'A';
    return buf_base64 + 10;
  }
  while (val) {
    i--;
    buf_base64[i] = tobase64array[val & 0x3f];
    val = val >> 6;
  }
  return buf_base64 + i;
}

char *int_to_base10(int val)
{
  static char buf_base10[17];
  int p = 0;
  int i = 16;

  buf_base10[16] = 0;
  if (!val) {
    buf_base10[15] = '0';
    return buf_base10 + 15;
  }
  if (val < 0) {
    p = 1;
    val *= -1;
  }
  while (val) {
    i--;
    buf_base10[i] = '0' + (val % 10);
    val /= 10;
  }
  if (p) {
    i--;
    buf_base10[i] = '-';
  }
  return buf_base10 + i;
}

char *unsigned_int_to_base10(unsigned int val)
{
  static char buf_base10[16];
  int i = 15;

  buf_base10[15] = 0;
  if (!val) {
    buf_base10[14] = '0';
    return buf_base10 + 14;
  }
  while (val) {
    i--;
    buf_base10[i] = '0' + (val % 10);
    val /= 10;
  }
  return buf_base10 + i;
}

/* simple_sprintf() — kept for third-party module ABI compatibility.
 *
 * New code in eggdrop core should use snprintf() instead.  simple_sprintf()
 * silently truncates output at 1023 bytes and its format string is not
 * validated by any compiler (%D is a non-standard base-64 specifier).
 * Removing it from the exported module API would break third-party modules,
 * so it stays as-is; internal callers should migrate to snprintf() over time.
 */
int simple_sprintf (char *buf, const char *format, ...)
{
  char *s;
  int c = 0, i;
  va_list va;

  va_start(va, format);

  while (*format && c < 1023) {
    if (*format == '%') {
      format++;
      switch (*format) {
      case 's':
        s = va_arg(va, char *);

        break;
      case 'd':
      case 'i':
        i = va_arg(va, int);

        s = int_to_base10(i);
        break;
      case 'D':
        i = va_arg(va, int);

        s = int_to_base64((unsigned int) i);
        break;
      case 'u':
        i = va_arg(va, unsigned int);

        s = unsigned_int_to_base10(i);
        break;
      case '%':
        buf[c++] = *format++;
        continue;
      case 'c':
        buf[c++] = (char) va_arg(va, int);

        format++;
        continue;
      default:
        continue;
      }
      if (s)
        while (*s && c < 1023)
          buf[c++] = *s++;
      format++;
    } else
      buf[c++] = *format++;
  }
  va_end(va);
  buf[c] = 0;
  return c;
}

/* Ditto for tandem bots
 */
void send_tand_but(int x, const char *buf, int len)
{
  int iso = 0;

  if (len < 0) {
    /* Very unlikely len would be INT_MIN */
    len = -len;
    iso = 1;
  }
  for (int i = 0; i < dcc_total; i++)
    if ((dcc[i].type == &DCC_BOT) && (i != x) &&
        (b_numver(i) >= NEAT_BOTNET) &&
        (!iso || !(bot_flags(dcc[i].user) & BOT_ISOLATE)))
      dprint(i, buf, len);
}

void botnet_send_bye(void)
{
  if (tands > 0) {
    send_tand_but(-1, "bye\n", 4);
  }
}

void botnet_send_chan(int idx, const char *botnick, const char *user, int chan, const char *data)
{
  if ((tands > 0) && (chan < GLOBAL_CHANS)) {
    op_strbuf_t _b = {};
    op_strbuf_init(&_b);
    if (user)
      op_strbuf_appendf(&_b, "c %s@%s %s %s\n", user, botnick, int_to_base64(chan), data);
    else
      op_strbuf_appendf(&_b, "c %s %s %s\n", botnick, int_to_base64(chan), data);
    send_tand_but(idx, op_strbuf_str(&_b), -(int) op_strbuf_len(&_b));
    op_strbuf_free(&_b);
  }
}

void botnet_send_act(int idx, char *botnick, char *user, int chan, char *data)
{
  if ((tands > 0) && (chan < GLOBAL_CHANS)) {
    op_strbuf_t _b = {};
    op_strbuf_init(&_b);
    if (user)
      op_strbuf_appendf(&_b, "a %s@%s %s %s\n", user, botnick, int_to_base64(chan), data);
    else
      op_strbuf_appendf(&_b, "a %s %s %s\n", botnick, int_to_base64(chan), data);
    send_tand_but(idx, op_strbuf_str(&_b), -(int) op_strbuf_len(&_b));
    op_strbuf_free(&_b);
  }
}

void botnet_send_chat(int idx, char *botnick, const char *data)
{
  if (tands > 0) {
    op_strbuf_t _b = {};
    op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "ct %s %s\n", botnick, data);
    send_tand_but(idx, op_strbuf_str(&_b), -(int)op_strbuf_len(&_b));
    op_strbuf_free(&_b);
  }
}

void botnet_send_ping(int idx)
{
    dprintf(idx, "pi\n");
}

void botnet_send_pong(int idx)
{
    dprintf(idx, "po\n");
}

ATTRIBUTE_FORMAT(printf,5,6)
void botnet_send_priv (int idx, const char *from, const char *to, const char *tobot, const char *format, ...)
{
  op_strbuf_t msg = {};
  op_strbuf_init(&msg);
  va_list va;

  va_start(va, format);
  op_strbuf_vappendf(&msg, format, va);
  va_end(va);

  op_strbuf_t _b = {};
  op_strbuf_init(&_b);
  if (tobot) {
      op_strbuf_appendf(&_b, "p %s %s@%s %s\n", from, to, tobot, op_strbuf_str(&msg));
  } else {
      op_strbuf_appendf(&_b, "p %s %s %s\n", from, to, op_strbuf_str(&msg));
  }
  op_strbuf_free(&msg);
  dprint(idx, op_strbuf_str(&_b), (int)op_strbuf_len(&_b));
  op_strbuf_free(&_b);
}

void botnet_send_who(int idx, const char *from, const char *to, int chan)
{
  op_strbuf_t _b = {};
  op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "w %s %s %s\n", from, to, int_to_base64(chan));
  dprint(idx, op_strbuf_str(&_b), (int)op_strbuf_len(&_b));
  op_strbuf_free(&_b);
}

void botnet_send_infoq(int idx, const char *par)
{
  op_strbuf_t _b = {};
  op_strbuf_init(&_b);
  op_strbuf_appendf(&_b, "i? %s\n", par);
  send_tand_but(idx, op_strbuf_str(&_b), (int)op_strbuf_len(&_b));
  op_strbuf_free(&_b);
}

void botnet_send_unlink(int idx, const char *who, char *via, const char *bot, const char *reason)
{
  op_strbuf_t _b = {};
  op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "ul %s %s %s %s\n", who, via, bot, reason);
  dprint(idx, op_strbuf_str(&_b), (int)op_strbuf_len(&_b));
  op_strbuf_free(&_b);
}

void botnet_send_link(int idx, const char *who, char *via, const char *bot)
{
  op_strbuf_t _b = {};
  op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "l %s %s %s\n", who, via, bot);
  dprint(idx, op_strbuf_str(&_b), (int)op_strbuf_len(&_b));
  op_strbuf_free(&_b);
}

void botnet_send_unlinked(int idx, char *bot, const char *args)
{
  if (tands > 0) {
    op_strbuf_t _b = {};
    op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "un %s %s\n", bot, args ? args : "");
    send_tand_but(idx, op_strbuf_str(&_b), (int)op_strbuf_len(&_b));
    op_strbuf_free(&_b);
  }
}

void botnet_send_nlinked(int idx, char *bot, char *next, char flag, int vernum)
{
  if (tands > 0) {
    op_strbuf_t _b = {};
    op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "n %s %s %c%s\n", bot, next, flag, int_to_base64(vernum));
    send_tand_but(idx, op_strbuf_str(&_b), (int)op_strbuf_len(&_b));
    op_strbuf_free(&_b);
  }
}

void botnet_send_traced(int idx, const char *bot, const char *buf)
{
  op_strbuf_t _b = {};
  op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "td %s %s\n", bot, buf);
  dprint(idx, op_strbuf_str(&_b), (int)op_strbuf_len(&_b));
  op_strbuf_free(&_b);
}

void botnet_send_trace(int idx, const char *to, const char *from, const char *buf)
{
  op_strbuf_t _b = {};
  op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "t %s %s %s:%s\n", to, from, buf, botnetnick);
  dprint(idx, op_strbuf_str(&_b), (int)op_strbuf_len(&_b));
  op_strbuf_free(&_b);
}

void botnet_send_update(int idx, tand_t *ptr)
{
  if (tands > 0) {
    op_strbuf_t _b = {};
    op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "u %s %c%s\n", ptr->bot, ptr->share, int_to_base64(ptr->ver));
    send_tand_but(idx, op_strbuf_str(&_b), (int)op_strbuf_len(&_b));
    op_strbuf_free(&_b);
  }
}

void botnet_send_reject(int idx, char *fromp, char *frombot, char *top,
                        char *tobot, char *reason)
{
  if (!(bot_flags(dcc[idx].user) & BOT_ISOLATE)) {
    op_strbuf_t _b = {};
    op_strbuf_init(&_b);
    op_strbuf_append_cstr(&_b, "r ");
    if (frombot)
      op_strbuf_appendf(&_b, "%s@%s", fromp, frombot);
    else
      op_strbuf_append_cstr(&_b, fromp);
    op_strbuf_append_cstr(&_b, " ");
    if (tobot)
      op_strbuf_appendf(&_b, "%s@%s", top, tobot);
    else
      op_strbuf_append_cstr(&_b, top);
    op_strbuf_appendf(&_b, " %s\n", reason ? reason : "");
    dprint(idx, op_strbuf_str(&_b), (int)op_strbuf_len(&_b));
    op_strbuf_free(&_b);
  }
}

void botnet_send_zapf(int idx, const char *a, const char *b, const char *c)
{
  op_strbuf_t _b = {};
  op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "z %s %s %s\n", a, b, c);
  dprint(idx, op_strbuf_str(&_b), (int)op_strbuf_len(&_b));
  op_strbuf_free(&_b);
}

void botnet_send_zapf_broad(int idx, const char *a, const char *b, const char *c)
{
  if (tands > 0) {
    op_strbuf_t _b = {};
    op_strbuf_init(&_b);
    if (b)
      op_strbuf_appendf(&_b, "zb %s %s %s\n", a, b, c);
    else
      op_strbuf_appendf(&_b, "zb %s %s\n", a, c);
    send_tand_but(idx, op_strbuf_str(&_b), (int)op_strbuf_len(&_b));
    op_strbuf_free(&_b);
  }
}

void botnet_send_motd(int idx, const char *from, const char *to)
{
  op_strbuf_t _b = {};
  op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "m %s %s\n", from, to);
  dprint(idx, op_strbuf_str(&_b), (int)op_strbuf_len(&_b));
  op_strbuf_free(&_b);
}

void botnet_send_filereject(int idx, char *path, char *from, char *reason)
{
  op_strbuf_t _b = {};
  op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "f! %s %s %s\n", path, from, reason);
  dprint(idx, op_strbuf_str(&_b), (int)op_strbuf_len(&_b));
  op_strbuf_free(&_b);
}

void botnet_send_filesend(int idx, const char *path, const char *from, const char *data)
{
  op_strbuf_t _b = {};
  op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "fs %s %s %s\n", path, from, data);
  dprint(idx, op_strbuf_str(&_b), (int)op_strbuf_len(&_b));
  op_strbuf_free(&_b);
}

void botnet_send_filereq(int idx, char *from, char *bot, char *path)
{
  op_strbuf_t _b = {};
  op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "fr %s %s:%s\n", from, bot, path);
  dprint(idx, op_strbuf_str(&_b), (int)op_strbuf_len(&_b));
  op_strbuf_free(&_b);
}

void botnet_send_idle(int idx, char *bot, int sock, int idle, char *away)
{
  if (tands > 0) {
    char _b64_sock[12], _b64_idle[12];
    op_strlcpy(_b64_sock, int_to_base64(sock), sizeof _b64_sock);
    op_strlcpy(_b64_idle, int_to_base64(idle), sizeof _b64_idle);
    op_strbuf_t _b = {};
    op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "i %s %s %s %s\n", bot, _b64_sock, _b64_idle,
                      away ? away : "");
    send_tand_but(idx, op_strbuf_str(&_b), -(int)op_strbuf_len(&_b));
    op_strbuf_free(&_b);
  }
}

void botnet_send_away(int idx, char *bot, int sock, char *msg, int linking)
{
  if (tands > 0) {
    op_strbuf_t _b = {};
    op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "aw %s%s %s %s\n",
                      ((idx >= 0) && linking) ? "!" : "",
                      bot, int_to_base64(sock), msg ? msg : "");
    send_tand_but(idx, op_strbuf_str(&_b), -(int)op_strbuf_len(&_b));
    op_strbuf_free(&_b);
  }
}

void botnet_send_join_idx(int useridx, int oldchan)
{
  if (tands > 0) {
    char _b64_chan[12], _b64_sock[12];
    op_strlcpy(_b64_chan, int_to_base64(dcc[useridx].u.chat->channel), sizeof _b64_chan);
    op_strlcpy(_b64_sock, int_to_base64(dcc[useridx].sock), sizeof _b64_sock);
    op_strbuf_t _b = {};
    op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "j %s %s %s %c%s %s\n",
                      botnetnick, dcc[useridx].nick,
                      _b64_chan, geticon(useridx), _b64_sock, dcc[useridx].host);
    send_tand_but(-1, op_strbuf_str(&_b), -(int)op_strbuf_len(&_b));
    op_strbuf_free(&_b);
  }
}

void botnet_send_join_party(int idx, int linking, int useridx, int oldchan)
{
  if (tands > 0) {
    char _b64_chan[12], _b64_sock[12];
    op_strlcpy(_b64_chan, int_to_base64(party[useridx].chan), sizeof _b64_chan);
    op_strlcpy(_b64_sock, int_to_base64(party[useridx].sock), sizeof _b64_sock);
    op_strbuf_t _b = {};
    op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "j %s%s %s %s %c%s %s\n",
                      linking ? "!" : "",
                      party[useridx].bot, party[useridx].nick,
                      _b64_chan, party[useridx].flag, _b64_sock,
                      party[useridx].from ? party[useridx].from : "");
    send_tand_but(idx, op_strbuf_str(&_b), -(int)op_strbuf_len(&_b));
    op_strbuf_free(&_b);
  }
}

void botnet_send_part_idx(int useridx, const char *reason)
{
  if (tands > 0) {
    op_strbuf_t _b = {};
    op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "pt %s %s %s %s\n", botnetnick,
                      dcc[useridx].nick, int_to_base64(dcc[useridx].sock),
                      reason ? reason : "");
    send_tand_but(-1, op_strbuf_str(&_b), -(int)op_strbuf_len(&_b));
    op_strbuf_free(&_b);
  }
}

void botnet_send_part_party(int idx, int partyidx, char *reason, int silent)
{
  if (tands > 0) {
    op_strbuf_t _b = {};
    op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "pt %s%s %s %s %s\n",
                      silent ? "!" : "", party[partyidx].bot,
                      party[partyidx].nick, int_to_base64(party[partyidx].sock),
                      reason ? reason : "");
    send_tand_but(idx, op_strbuf_str(&_b), -(int)op_strbuf_len(&_b));
    op_strbuf_free(&_b);
  }
}

void botnet_send_nkch(int useridx, char *oldnick)
{
  if (tands > 0) {
    op_strbuf_t _b = {};
    op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "nc %s %s %s\n", botnetnick,
                      int_to_base64(dcc[useridx].sock), dcc[useridx].nick);
    send_tand_but(-1, op_strbuf_str(&_b), -(int)op_strbuf_len(&_b));
    op_strbuf_free(&_b);
  }
}

void botnet_send_nkch_part(int butidx, int useridx, char *oldnick)
{
  if (tands > 0) {
    op_strbuf_t _b = {};
    op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "nc %s %s %s\n", party[useridx].bot,
                      int_to_base64(party[useridx].sock), party[useridx].nick);
    send_tand_but(butidx, op_strbuf_str(&_b), -(int)op_strbuf_len(&_b));
    op_strbuf_free(&_b);
  }
}

/* This part of add_note is more relevant to the botnet than
 * to the notes file.
 */
int add_note(char *to, char *from, const char *msg, int idx, int echo)
{
  #define FROMLEN 40
  int iaway, sock;
  int status;
  char *p, ss[24];
  struct userrec *u;
  char msgbuf[451];

  /* Notes have a length limit. Note + PRIVMSG header + nick + date must
   * be less than 512.
   */
  if (strlen(msg) > 450) {
    op_strlcpy(msgbuf, msg, sizeof msgbuf);
    msg = msgbuf;
  }

  /* Is this a cross-bot note? If it is, 'to' will be of the format
   * 'user@bot'.
   */
  p = strchr(to, '@');
  if (p != nullptr) {
    char x[21];

    *p = 0;
    op_strlcpy(x, to, sizeof x);
    *p = '@';
    p++;

    if (!op_strcasecmp(p, botnetnick)) /* To me?? */
      return add_note(x, from, msg, idx, echo); /* Start over, dimwit. */

    op_strbuf_t _botf = {};
    op_strbuf_init(&_botf);
    if (op_strcasecmp(from, botnetnick)) {
      if (strlen(from) > FROMLEN)
        from[FROMLEN] = 0;

      if (strchr(from, '@'))
        op_strbuf_append_cstr(&_botf, from);
      else
        op_strbuf_appendf(&_botf, "%s@%s", from, botnetnick);

    } else
      op_strbuf_append_cstr(&_botf, botnetnick);

    int i = nextbot(p);
    if (i < 0) {
      if (idx >= 0)
        dprintf(idx, "%s", BOT_NOTHERE);

      op_strbuf_free(&_botf);
      return NOTE_ERROR;
    }

    if (idx >= 0 && echo)
      dprintf(idx, "-> %s@%s: %s\n", x, p, msg);

    if (idx >= 0) {
      op_strbuf_t _ssf = {};
      op_strbuf_init(&_ssf);
      op_strbuf_appendf(&_ssf, "%lu:%s", dcc[idx].sock, op_strbuf_str(&_botf));
      botnet_send_priv(i, op_strbuf_str(&_ssf), x, p, "%s", msg);
      op_strbuf_free(&_ssf);
    } else
      botnet_send_priv(i, op_strbuf_str(&_botf), x, p, "%s", msg);

    op_strbuf_free(&_botf);
    return NOTE_OK;             /* Forwarded to the right bot */
  }

  /* Might be form "sock:nick" */
  splitc(ss, to, ':');
  rmspace(ss);
  if (!ss[0])
    sock = -1;
  else
    sock = egg_atoi(ss);

  /* Don't process if there's a note binding for it */
  if (idx != -2) {            /* Notes from bots don't trigger it */
    if (check_tcl_note(from, to, msg)) {
      if (idx >= 0 && echo)
        dprintf(idx, "-> %s: %s\n", to, msg);

      return NOTE_TCL;
    }
  }

  /* Valid user? */
  u = get_user_by_handle(userlist, to);
  if (!u) {
    if (idx >= 0)
      dprintf(idx, "%s", USERF_UNKNOWN);

    return NOTE_ERROR;
  }

  /* Is the note to a bot? */
  if (is_bot(u)) {
    if (idx >= 0)
      dprintf(idx, "%s", BOT_NONOTES);

    return NOTE_ERROR;
  }

  /* Is user rejecting notes from this source? */
  if (match_noterej(u, from)) {
    if (idx >= 0)
      dprintf(idx, "%s rejected your note.\n", u->handle);

    return NOTE_REJECT;
  }

  status = NOTE_STORED;
  iaway = 0;

  /* Online right now? */
  for (int i = 0; i < dcc_total; i++) {
    if ((dcc[i].type->flags & DCT_GETNOTES) &&
        (sock == -1 || sock == dcc[i].sock) &&
        !op_strcasecmp(dcc[i].nick, to)) {
      int aok = 1;

      if (dcc[i].type == &DCC_CHAT) {

        /* Only check away if it's not from a bot. */
        if (dcc[i].u.chat->away != nullptr && idx != -2) {
          aok = 0;

          if (idx >= 0)
            dprintf(idx, "%s %s: %s\n", dcc[i].nick, BOT_USERAWAY,
                    dcc[i].u.chat->away);

          if (!iaway)
            iaway = i;
          status = NOTE_AWAY;
        }
      }

      if (aok) {
        char *fr = from;
        op_strbuf_t work = {};
        op_strbuf_init(&work);

        while (*msg == '<' || *msg == '>') {
          p = newsplit(&msg);

          if (*p == '<')
            op_strbuf_appendf(&work, "via %s, ", p + 1);
          else if (*from == '@')
            fr = p + 1;
        }

        if (idx == -2 || !op_strcasecmp(from, botnetnick))
          dprintf(i, "*** [%s] %s%s\n", fr,
                  op_strbuf_len(&work) ? op_strbuf_str(&work) : "", msg);
        else
          dprintf(i, "%cNote [%s]: %s%s\n", 7, fr,
                  op_strbuf_len(&work) ? op_strbuf_str(&work) : "", msg);
        op_strbuf_free(&work);

        if (idx >= 0 && echo)
          dprintf(idx, "-> %s: %s\n", to, msg);

        return NOTE_OK;
      }
    }
  }

  if (idx == -2)
    return NOTE_OK; /* Error msg from a tandembot: don't store. */

  /* Call 'storenote' command. */
  op_strbuf_t _idx = {};
  op_strbuf_init(&_idx);
  op_strbuf_appendf(&_idx, "%ld", (idx >= 0) ? dcc[idx].sock : -1L);
  Tcl_SetVar(interp, "_from", from, 0);
  Tcl_SetVar(interp, "_to",   to,   0);
  Tcl_SetVar(interp, "_data", msg,  0);
  Tcl_SetVar(interp, "_idx",  op_strbuf_str(&_idx), 0);
  {
    op_strbuf_t cmd = {};
    op_strbuf_init(&cmd);
    op_strbuf_appendf(&cmd, "storenote {%s} {%s} {%s} %s", from, to, msg,
                     op_strbuf_str(&_idx));
    op_strbuf_free(&_idx);
    int rc = egg_eval(op_strbuf_str(&cmd));
    op_strbuf_free(&cmd);
    if (!rc) {
      if (!tcl_resultempty())
        status = NOTE_FWD;

      /* User is away in all sessions -- just notify the user that a
       * message arrived and was stored (only oldest session is notified).
       */
      if (status == NOTE_AWAY)
        dprintf(iaway, "*** %s.\n", BOT_NOTEARRIVED);

      return status;
    }
  }

  /* If we haven't returned anything else by now, assume an error occurred. */
  return NOTE_ERROR;
}
