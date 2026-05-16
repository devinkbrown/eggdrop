/*
 * webui.c -- part of webui.mod
 */
/*
 * Copyright (C) 2023 - 2025 Michael Ortmann MIT License
 * Copyright (C) 2025 Eggheads Development Team
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

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif
#include "src/mod/module.h"

#ifdef TLS
#define MODULE_NAME "webui"

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#ifdef __APPLE__
#  define st_mtim st_mtimespec
#endif
#include <opssl/crypto.h>
#include <opssl/conn.h>
#include "src/version.h"
#include "src/perf.h"
#include "src/egg_perf_types.h"

extern module_entry *module_list;

constexpr char WS_GUID[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
constexpr char WS_KEY[]  = "Sec-WebSocket-Key:";
constexpr int  WS_KEYLEN = 24;
constexpr int  WS_LEN    = 28;
constexpr int  WS_ECHO_ON  = 0x01;
constexpr int  WS_ECHO_OFF = 0x02;

/* Log ring buffer for /api/logs */
constexpr int LOG_RING_SIZE = 200;

struct log_entry {
  char time[20];
  char flags[8];
  char msg[LOGLINELEN];
};

static struct log_entry log_ring[LOG_RING_SIZE];
static int log_ring_head;
static int log_ring_count;

static Function *global = nullptr;

static const uint8_t alert[] = {0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x0a};

/* ---- Auth system ---- */

static char webui_token[65] = "";

#define MAX_WS_PUSH 8
static int ws_push_socks[MAX_WS_PUSH];
static int ws_push_count = 0;

/* HTTP method types */
enum {
  HTTP_GET = 0,
  HTTP_POST,
  HTTP_DELETE,
  HTTP_OPTIONS,
  HTTP_UNKNOWN
};

/* ---- JSON helpers ---- */

static void json_escape(op_strbuf_t *b, const char *s)
{
  if (!s) {
    op_strbuf_append_cstr(b, "null");
    return;
  }
  op_strbuf_appendc(b, '"');
  for (; *s; s++) {
    switch (*s) {
      case '"':  op_strbuf_append_cstr(b, "\\\""); break;
      case '\\': op_strbuf_append_cstr(b, "\\\\"); break;
      case '\n': op_strbuf_append_cstr(b, "\\n"); break;
      case '\r': op_strbuf_append_cstr(b, "\\r"); break;
      case '\t': op_strbuf_append_cstr(b, "\\t"); break;
      default:
        if ((unsigned char)*s < 0x20) {
          char esc[8];
          snprintf(esc, sizeof esc, "\\u%04x", (unsigned char)*s);
          op_strbuf_append_cstr(b, esc);
        } else {
          op_strbuf_appendc(b, *s);
        }
    }
  }
  op_strbuf_appendc(b, '"');
}

/* ---- HTTP response helpers ---- */

static const char *server_hdr(void)
{
  static char buf[64];
  if (stealth_telnets)
    return "nginx/1.28.1";
  snprintf(buf, sizeof buf, "Eggdrop/" EGG_STRINGVER "+" EGG_PATCH);
  return buf;
}

static void send_json_response(int idx, op_strbuf_t *body)
{
  op_strbuf_t hdr = {};
  op_strbuf_init(&hdr);
  op_strbuf_appendf(&hdr,
    "HTTP/1.1 200 OK\r\n"
    "Content-Length: %zu\r\n"
    "Content-Type: application/json\r\n"
    "Cache-Control: no-cache\r\n"
    "Access-Control-Allow-Origin: *\r\n"
    "Server: %s\r\n"
    "\r\n",
    op_strbuf_len(body), server_hdr());

  size_t hlen = op_strbuf_len(&hdr);
  size_t blen = op_strbuf_len(body);
  char *resp = op_malloc(hlen + blen);
  memcpy(resp, op_strbuf_str(&hdr), hlen);
  memcpy(resp + hlen, op_strbuf_str(body), blen);
  op_strbuf_free(&hdr);

  tputs(dcc[idx].sock, resp, (unsigned int)(hlen + blen));
  op_free(resp);
}

static void send_401(int idx)
{
  const char *body = "{\"error\":\"unauthorized\"}";
  size_t blen = strlen(body);

  op_strbuf_t hdr = {};
  op_strbuf_init(&hdr);
  op_strbuf_appendf(&hdr,
    "HTTP/1.1 401 Unauthorized\r\n"
    "Content-Length: %zu\r\n"
    "Content-Type: application/json\r\n"
    "Access-Control-Allow-Origin: *\r\n"
    "Server: %s\r\n"
    "\r\n",
    blen, server_hdr());

  size_t hlen = op_strbuf_len(&hdr);
  char *resp = op_malloc(hlen + blen);
  memcpy(resp, op_strbuf_str(&hdr), hlen);
  memcpy(resp + hlen, body, blen);
  op_strbuf_free(&hdr);

  tputs(dcc[idx].sock, resp, (unsigned int)(hlen + blen));
  op_free(resp);
  killsock(dcc[idx].sock);
  lostdcc(idx);
}

static void send_200_ok(int idx)
{
  op_strbuf_t b = {};
  op_strbuf_init(&b);
  op_strbuf_append_cstr(&b, "{\"ok\":true}");
  send_json_response(idx, &b);
  op_strbuf_free(&b);
}

static void send_400(int idx, const char *msg)
{
  op_strbuf_t body = {};
  op_strbuf_init(&body);
  op_strbuf_appendf(&body, "{\"error\":\"%s\"}", msg);

  op_strbuf_t hdr = {};
  op_strbuf_init(&hdr);
  op_strbuf_appendf(&hdr,
    "HTTP/1.1 400 Bad Request\r\n"
    "Content-Length: %zu\r\n"
    "Content-Type: application/json\r\n"
    "Access-Control-Allow-Origin: *\r\n"
    "Server: %s\r\n"
    "\r\n",
    op_strbuf_len(&body), server_hdr());

  size_t hlen = op_strbuf_len(&hdr);
  size_t blen = op_strbuf_len(&body);
  char *resp = op_malloc(hlen + blen);
  memcpy(resp, op_strbuf_str(&hdr), hlen);
  memcpy(resp + hlen, op_strbuf_str(&body), blen);
  op_strbuf_free(&hdr);
  op_strbuf_free(&body);

  tputs(dcc[idx].sock, resp, (unsigned int)(hlen + blen));
  op_free(resp);
  killsock(dcc[idx].sock);
  lostdcc(idx);
}

/* ---- Auth check ---- */

static int check_auth(const char *buf)
{
  if (!webui_token[0]) return 1; /* no token configured = open access */
  /* check Authorization: Bearer <token> */
  const char *auth = strstr(buf, "Authorization: Bearer ");
  if (auth) {
    auth += 22;
    size_t tlen = strlen(webui_token);
    if (!strncmp(auth, webui_token, tlen) &&
        (auth[tlen] == '\r' || auth[tlen] == '\n' || auth[tlen] == '\0'))
      return 1;
  }
  /* check ?token= in URL */
  const char *qt = strstr(buf, "?token=");
  if (qt) {
    qt += 7;
    size_t tlen = strlen(webui_token);
    if (!strncmp(qt, webui_token, tlen) &&
        (qt[tlen] == ' ' || qt[tlen] == '&' || qt[tlen] == '\0'))
      return 1;
  }
  return 0;
}

/* ---- Method parsing ---- */

static int parse_method(const char *buf)
{
  if (!strncmp(buf, "GET ", 4))     return HTTP_GET;
  if (!strncmp(buf, "POST ", 5))    return HTTP_POST;
  if (!strncmp(buf, "DELETE ", 7))  return HTTP_DELETE;
  if (!strncmp(buf, "OPTIONS ", 8)) return HTTP_OPTIONS;
  return HTTP_UNKNOWN;
}

/* Get pointer to request body (after \r\n\r\n) */
static const char *get_body(const char *buf)
{
  const char *p = strstr(buf, "\r\n\r\n");
  return p ? p + 4 : nullptr;
}

/* Simple JSON string field extractor — finds "key":"value" and copies value */
static int json_get_str(const char *json, const char *key, char *out, size_t outsz)
{
  char pat[64];
  snprintf(pat, sizeof pat, "\"%s\"", key);
  const char *p = strstr(json, pat);
  if (!p) return -1;
  p += strlen(pat);
  while (*p == ' ' || *p == ':') p++;
  if (*p != '"') return -1;
  p++;
  size_t i = 0;
  while (*p && *p != '"' && i < outsz - 1) {
    if (*p == '\\' && *(p + 1)) { p++; }
    out[i++] = *p++;
  }
  out[i] = '\0';
  return 0;
}

/* Simple JSON integer field extractor */
static int json_get_int(const char *json, const char *key, int *out)
{
  char pat[64];
  snprintf(pat, sizeof pat, "\"%s\"", key);
  const char *p = strstr(json, pat);
  if (!p) return -1;
  p += strlen(pat);
  while (*p == ' ' || *p == ':') p++;
  if (*p == '-' || (*p >= '0' && *p <= '9')) {
    *out = atoi(p);
    return 0;
  }
  return -1;
}

/* URL-decode in place (handles %XX) */
static void url_decode(char *s)
{
  char *d = s;
  while (*s) {
    if (*s == '%' && s[1] && s[2]) {
      char hex[3] = {s[1], s[2], '\0'};
      *d++ = (char)strtol(hex, nullptr, 16);
      s += 3;
    } else {
      *d++ = *s++;
    }
  }
  *d = '\0';
}

/* ---- API endpoint handlers ---- */

static void api_status(int idx)
{
  int nchan = 0;
  for (struct chanset_t *c = chanset; c; c = c->next)
    nchan++;

  time_t uptime = now - online_since;

  op_strbuf_t b = {};
  op_strbuf_init(&b);
  op_strbuf_appendf(&b,
    "{\"uptime\":%lld,\"online_since\":%lld,"
    "\"nick\":\"%s\",\"server\":\"%s\","
    "\"channels\":%d,\"users\":%d}",
    (long long)uptime, (long long)online_since,
    botname, botnetnick,
    nchan, count_users(userlist));

  send_json_response(idx, &b);
  op_strbuf_free(&b);
}

static void api_channels(int idx)
{
  op_strbuf_t b = {};
  op_strbuf_init(&b);
  op_strbuf_appendc(&b, '[');

  int first = 1;
  for (struct chanset_t *c = chanset; c; c = c->next) {
    if (!first) op_strbuf_appendc(&b, ',');
    first = 0;

    int nmembers = 0;
    for (memberlist *m = c->channel.member; m; m = m->next)
      nmembers++;

    /* Build mode string from channel.mode bitmask */
    char modes[32];
    char *mp = modes;
    *mp++ = '+';
    if (c->channel.mode & CHANINV)   *mp++ = 'i';
    if (c->channel.mode & CHANPRIV)  *mp++ = 'p';
    if (c->channel.mode & CHANSEC)   *mp++ = 's';
    if (c->channel.mode & CHANMODER) *mp++ = 'm';
    if (c->channel.mode & CHANTOPIC) *mp++ = 't';
    if (c->channel.mode & CHANNOMSG) *mp++ = 'n';
    if (c->channel.mode & CHANLIMIT) *mp++ = 'l';
    if (c->channel.mode & CHANKEY)   *mp++ = 'k';
    *mp = '\0';

    op_strbuf_append_cstr(&b, "{\"name\":");
    json_escape(&b, c->dname);
    op_strbuf_appendf(&b, ",\"members\":%d,\"topic\":", nmembers);
    json_escape(&b, c->channel.topic);
    op_strbuf_append_cstr(&b, ",\"modes\":");
    json_escape(&b, modes);
    op_strbuf_appendc(&b, '}');
  }

  op_strbuf_appendc(&b, ']');
  send_json_response(idx, &b);
  op_strbuf_free(&b);
}

static void api_users_list(int idx)
{
  op_strbuf_t b = {};
  op_strbuf_init(&b);
  op_strbuf_appendc(&b, '[');

  int first = 1;
  for (struct userrec *u = userlist; u; u = u->next) {
    if (!first) op_strbuf_appendc(&b, ',');
    first = 0;

    /* Build global flags string */
    struct flag_record fr = {FR_GLOBAL, 0, 0, 0, 0, 0};
    get_user_flagrec(u, &fr, nullptr);
    char flagbuf[64];
    build_flags(flagbuf, &fr, nullptr);

    /* Gather channel names */
    op_strbuf_t chans = {};
    op_strbuf_init(&chans);
    int cfirst = 1;
    for (struct chanuserrec *cr = u->chanrec; cr; cr = cr->next) {
      if (!cfirst) op_strbuf_append_cstr(&chans, ", ");
      cfirst = 0;
      op_strbuf_append_cstr(&chans, cr->channel);
    }

    op_strbuf_append_cstr(&b, "{\"handle\":");
    json_escape(&b, u->handle);
    op_strbuf_append_cstr(&b, ",\"flags\":");
    json_escape(&b, flagbuf);
    op_strbuf_append_cstr(&b, ",\"channels\":");
    json_escape(&b, op_strbuf_len(&chans) ? op_strbuf_str(&chans) : "--");
    op_strbuf_appendc(&b, '}');
    op_strbuf_free(&chans);
  }

  op_strbuf_appendc(&b, ']');
  send_json_response(idx, &b);
  op_strbuf_free(&b);
}

static void api_user_detail(int idx, const char *handle)
{
  struct userrec *u = get_user_by_handle(userlist, (char *)handle);
  if (!u) {
    send_400(idx, "user not found");
    return;
  }

  op_strbuf_t b = {};
  op_strbuf_init(&b);
  op_strbuf_append_cstr(&b, "{\"handle\":");
  json_escape(&b, u->handle);

  /* Global flags */
  struct flag_record fr = {FR_GLOBAL, 0, 0, 0, 0, 0};
  get_user_flagrec(u, &fr, nullptr);
  char flagbuf[64];
  build_flags(flagbuf, &fr, nullptr);
  op_strbuf_append_cstr(&b, ",\"flags\":");
  json_escape(&b, flagbuf);

  /* Hosts */
  op_strbuf_append_cstr(&b, ",\"hosts\":[");
  struct list_type *hosts = get_user(&USERENTRY_HOSTS, u);
  int first = 1;
  for (struct list_type *h = hosts; h; h = h->next) {
    if (!first) op_strbuf_appendc(&b, ',');
    first = 0;
    json_escape(&b, h->extra);
  }
  op_strbuf_appendc(&b, ']');

  /* Channel records */
  op_strbuf_append_cstr(&b, ",\"channels\":[");
  first = 1;
  for (struct chanuserrec *cr = u->chanrec; cr; cr = cr->next) {
    if (!first) op_strbuf_appendc(&b, ',');
    first = 0;
    struct flag_record cfr = {FR_CHAN, 0, 0, 0, 0, 0};
    get_user_flagrec(u, &cfr, cr->channel);
    char cflagbuf[64];
    build_flags(cflagbuf, &cfr, nullptr);
    op_strbuf_append_cstr(&b, "{\"name\":");
    json_escape(&b, cr->channel);
    op_strbuf_append_cstr(&b, ",\"flags\":");
    json_escape(&b, cflagbuf);
    op_strbuf_appendc(&b, '}');
  }
  op_strbuf_append_cstr(&b, "]}");

  send_json_response(idx, &b);
  op_strbuf_free(&b);
}

static void api_traffic(int idx)
{
  struct egg_traffic_snap in, out;
  egg_traffic_get_snap(&in, &out);

  uint64_t total_in = in.irc + in.bn + in.partyline + in.trans + in.unknown + in.filesys;
  uint64_t total_out = out.irc + out.bn + out.partyline + out.trans + out.unknown + out.filesys;

  op_strbuf_t b = {};
  op_strbuf_init(&b);
  op_strbuf_appendf(&b,
    "{\"in_today\":%llu,\"out_today\":%llu,"
    "\"in_irc\":%llu,\"out_irc\":%llu,"
    "\"in_bn\":%llu,\"out_bn\":%llu,"
    "\"in_partyline\":%llu,\"out_partyline\":%llu}",
    (unsigned long long)total_in, (unsigned long long)total_out,
    (unsigned long long)in.irc, (unsigned long long)out.irc,
    (unsigned long long)in.bn, (unsigned long long)out.bn,
    (unsigned long long)in.partyline, (unsigned long long)out.partyline);

  send_json_response(idx, &b);
  op_strbuf_free(&b);
}

static void api_perf(int idx)
{
  struct egg_perf_metrics pm = egg_perf_snapshot();

  uint64_t avg_ns = pm.tick_count ? pm.tick_ns_total / pm.tick_count : 0;
  uint64_t idle_pct = pm.tick_count ? (pm.idle_ticks * 100) / pm.tick_count : 0;

  op_strbuf_t b = {};
  op_strbuf_init(&b);
  op_strbuf_appendf(&b,
    "{\"tick_count\":%llu,\"tick_avg_ns\":%llu,\"tick_max_ns\":%llu,"
    "\"idle_pct\":%llu,\"bind_dispatches\":%llu,"
    "\"arena_allocs\":%llu,\"arena_peak_bytes\":%llu,"
    "\"hist\":[%llu,%llu,%llu,%llu,%llu]}",
    (unsigned long long)pm.tick_count,
    (unsigned long long)avg_ns,
    (unsigned long long)pm.tick_ns_max,
    (unsigned long long)idle_pct,
    (unsigned long long)pm.bind_dispatches,
    (unsigned long long)pm.arena_allocs,
    (unsigned long long)pm.arena_peak_bytes,
    (unsigned long long)pm.tick_hist[0],
    (unsigned long long)pm.tick_hist[1],
    (unsigned long long)pm.tick_hist[2],
    (unsigned long long)pm.tick_hist[3],
    (unsigned long long)pm.tick_hist[4]);

  send_json_response(idx, &b);
  op_strbuf_free(&b);
}

static void api_logs(int idx)
{
  op_strbuf_t b = {};
  op_strbuf_init(&b);
  op_strbuf_appendc(&b, '[');

  int count = log_ring_count < LOG_RING_SIZE ? log_ring_count : LOG_RING_SIZE;
  int start = (log_ring_head - count + LOG_RING_SIZE) % LOG_RING_SIZE;
  int first = 1;

  for (int i = 0; i < count; i++) {
    int slot = (start + i) % LOG_RING_SIZE;
    struct log_entry *e = &log_ring[slot];
    if (!e->msg[0]) continue;

    if (!first) op_strbuf_appendc(&b, ',');
    first = 0;

    op_strbuf_append_cstr(&b, "{\"time\":");
    json_escape(&b, e->time);
    op_strbuf_append_cstr(&b, ",\"flags\":");
    json_escape(&b, e->flags);
    op_strbuf_append_cstr(&b, ",\"msg\":");
    json_escape(&b, e->msg);
    op_strbuf_appendc(&b, '}');
  }

  op_strbuf_appendc(&b, ']');
  send_json_response(idx, &b);
  op_strbuf_free(&b);
}

static void api_channel_members(int idx, const char *channame)
{
  struct chanset_t *chan = findchan_by_dname(channame);
  if (!chan) {
    send_400(idx, "channel not found");
    return;
  }

  op_strbuf_t b = {};
  op_strbuf_init(&b);
  op_strbuf_appendc(&b, '[');

  int first = 1;
  for (memberlist *m = chan->channel.member; m; m = m->next) {
    if (!m->nick[0]) continue;
    if (!first) op_strbuf_appendc(&b, ',');
    first = 0;

    op_strbuf_append_cstr(&b, "{\"nick\":");
    json_escape(&b, m->nick);
    op_strbuf_append_cstr(&b, ",\"userhost\":");
    json_escape(&b, m->userhost);

    char flagstr[16];
    char *fp = flagstr;
    if (m->flags & CHANOP)     *fp++ = 'o';
    if (m->flags & CHANVOICE)  *fp++ = 'v';
    if (m->flags & CHANHALFOP) *fp++ = 'h';
    *fp = '\0';

    op_strbuf_append_cstr(&b, ",\"flags\":");
    json_escape(&b, flagstr);
    op_strbuf_appendf(&b, ",\"joined\":%lld", (long long)m->joined);
    op_strbuf_appendf(&b, ",\"op\":%s", (m->flags & CHANOP) ? "true" : "false");
    op_strbuf_appendf(&b, ",\"voice\":%s", (m->flags & CHANVOICE) ? "true" : "false");
    op_strbuf_appendf(&b, ",\"halfop\":%s", (m->flags & CHANHALFOP) ? "true" : "false");
    op_strbuf_appendc(&b, '}');
  }

  op_strbuf_appendc(&b, ']');
  send_json_response(idx, &b);
  op_strbuf_free(&b);
}

static void api_channel_bans(int idx, const char *channame)
{
  struct chanset_t *chan = findchan_by_dname(channame);
  if (!chan) {
    send_400(idx, "channel not found");
    return;
  }

  op_strbuf_t b = {};
  op_strbuf_init(&b);
  op_strbuf_appendc(&b, '[');

  int first = 1;
  for (masklist *ban = chan->channel.ban; ban; ban = ban->next) {
    if (!ban->mask || !ban->mask[0]) continue;
    if (!first) op_strbuf_appendc(&b, ',');
    first = 0;

    op_strbuf_append_cstr(&b, "{\"mask\":");
    json_escape(&b, ban->mask);
    op_strbuf_append_cstr(&b, ",\"who\":");
    json_escape(&b, ban->who);
    op_strbuf_appendf(&b, ",\"added\":%lld}", (long long)ban->timer);
  }

  op_strbuf_appendc(&b, ']');
  send_json_response(idx, &b);
  op_strbuf_free(&b);
}

static void api_ignores(int idx)
{
  op_strbuf_t b = {};
  op_strbuf_init(&b);
  op_strbuf_appendc(&b, '[');

  int first = 1;
  for (struct igrec *ig = global_ign; ig; ig = ig->next) {
    if (!first) op_strbuf_appendc(&b, ',');
    first = 0;

    op_strbuf_append_cstr(&b, "{\"mask\":");
    json_escape(&b, ig->igmask);
    op_strbuf_append_cstr(&b, ",\"by\":");
    json_escape(&b, ig->user);
    op_strbuf_append_cstr(&b, ",\"reason\":");
    json_escape(&b, ig->msg);
    op_strbuf_appendf(&b, ",\"added\":%lld", (long long)ig->added);
    op_strbuf_appendf(&b, ",\"expires\":%lld}", (long long)ig->expire);
  }

  op_strbuf_appendc(&b, ']');
  send_json_response(idx, &b);
  op_strbuf_free(&b);
}

static void api_modules(int idx)
{
  op_strbuf_t b = {};
  op_strbuf_init(&b);
  op_strbuf_appendc(&b, '[');

  int first = 1;
  for (module_entry *m = module_list; m; m = m->next) {
    if (!first) op_strbuf_appendc(&b, ',');
    first = 0;

    op_strbuf_append_cstr(&b, "{\"name\":");
    json_escape(&b, m->name);
    op_strbuf_appendf(&b, ",\"version\":\"%d.%d\"}", m->major, m->minor);
  }

  op_strbuf_appendc(&b, ']');
  send_json_response(idx, &b);
  op_strbuf_free(&b);
}

static void api_botnet(int idx)
{
  op_strbuf_t b = {};
  op_strbuf_init(&b);
  op_strbuf_appendc(&b, '[');

  int first = 1;
  for (int i = 0; i < dcc_total; i++) {
    if (!dcc[i].type || strcmp(dcc[i].type->name, "BOT"))
      continue;
    if (!first) op_strbuf_appendc(&b, ',');
    first = 0;

    op_strbuf_append_cstr(&b, "{\"handle\":");
    json_escape(&b, dcc[i].nick);
    op_strbuf_append_cstr(&b, ",\"address\":");
    json_escape(&b, dcc[i].host);
    op_strbuf_append_cstr(&b, ",\"version\":");
    json_escape(&b, dcc[i].u.bot ? dcc[i].u.bot->version : "");
    op_strbuf_appendc(&b, '}');
  }

  op_strbuf_appendc(&b, ']');
  send_json_response(idx, &b);
  op_strbuf_free(&b);
}

/* ---- POST endpoint handlers ---- */

static void api_auth_post(int idx, const char *body)
{
  if (!body) {
    send_401(idx);
    return;
  }
  char token[65] = "";
  json_get_str(body, "token", token, sizeof token);
  if (!webui_token[0] || !strcmp(token, webui_token)) {
    op_strbuf_t b = {};
    op_strbuf_init(&b);
    op_strbuf_append_cstr(&b, "{\"ok\":true}");
    send_json_response(idx, &b);
    op_strbuf_free(&b);
    killsock(dcc[idx].sock);
    lostdcc(idx);
  } else {
    send_401(idx);
  }
}

static void api_say_post(int idx, const char *body)
{
  if (!body) { send_400(idx, "missing body"); return; }
  char channel[128] = "";
  char message[512] = "";
  json_get_str(body, "channel", channel, sizeof channel);
  json_get_str(body, "message", message, sizeof message);
  if (!channel[0] || !message[0]) {
    send_400(idx, "channel and message required");
    return;
  }
  dprintf(DP_SERVER, "PRIVMSG %s :%s\r\n", channel, message);
  putlog(LOG_MISC, "*", "WebUI: PRIVMSG %s :%s", channel, message);
  send_200_ok(idx);
  killsock(dcc[idx].sock);
  lostdcc(idx);
}

static void api_kick_post(int idx, const char *body)
{
  if (!body) { send_400(idx, "missing body"); return; }
  char channel[128] = "";
  char nick[NICKLEN] = "";
  char reason[256] = "Requested";
  json_get_str(body, "channel", channel, sizeof channel);
  json_get_str(body, "nick", nick, sizeof nick);
  json_get_str(body, "reason", reason, sizeof reason);
  if (!channel[0] || !nick[0]) {
    send_400(idx, "channel and nick required");
    return;
  }
  dprintf(DP_SERVER, "KICK %s %s :%s\r\n", channel, nick, reason);
  putlog(LOG_MISC, "*", "WebUI: KICK %s %s :%s", channel, nick, reason);
  send_200_ok(idx);
  killsock(dcc[idx].sock);
  lostdcc(idx);
}

static void api_restart_post(int idx)
{
  putlog(LOG_MISC, "*", "WebUI: Restart requested");
  send_200_ok(idx);
  killsock(dcc[idx].sock);
  lostdcc(idx);
  do_restart = 1;
}

static void api_users_post(int idx, const char *body)
{
  if (!body) { send_400(idx, "missing body"); return; }
  char handle[HANDLEN + 1] = "";
  char hostmask[UHOSTLEN] = "";
  char flags[64] = "";
  json_get_str(body, "handle", handle, sizeof handle);
  json_get_str(body, "hostmask", hostmask, sizeof hostmask);
  json_get_str(body, "flags", flags, sizeof flags);
  if (!handle[0]) {
    send_400(idx, "handle required");
    return;
  }
  struct userrec *u = adduser(userlist, handle,
                              hostmask[0] ? hostmask : "*!*@*", nullptr, 0);
  if (!u) {
    send_400(idx, "adduser failed");
    return;
  }
  if (flags[0]) {
    struct flag_record fr = {FR_GLOBAL, 0, 0, 0, 0, 0};
    break_down_flags(flags, &fr, nullptr);
    set_user_flagrec(u, &fr, nullptr);
  }
  putlog(LOG_MISC, "*", "WebUI: Added user %s", handle);
  send_200_ok(idx);
  killsock(dcc[idx].sock);
  lostdcc(idx);
}

static void api_user_delete(int idx, const char *handle)
{
  if (deluser((char *)handle)) {
    putlog(LOG_MISC, "*", "WebUI: Deleted user %s", handle);
    send_200_ok(idx);
  } else {
    send_400(idx, "user not found");
    return;
  }
  killsock(dcc[idx].sock);
  lostdcc(idx);
}

static void api_ignores_post(int idx, const char *body)
{
  if (!body) { send_400(idx, "missing body"); return; }
  char mask[256] = "";
  char reason[256] = "WebUI";
  int duration = 0;
  json_get_str(body, "mask", mask, sizeof mask);
  json_get_str(body, "reason", reason, sizeof reason);
  json_get_int(body, "duration", &duration);
  if (!mask[0]) {
    send_400(idx, "mask required");
    return;
  }
  addignore(mask, "WebUI", reason, (time_t)duration * 60);
  putlog(LOG_MISC, "*", "WebUI: Added ignore %s (%s) %dm", mask, reason, duration);
  send_200_ok(idx);
  killsock(dcc[idx].sock);
  lostdcc(idx);
}

static void api_ignores_delete(int idx, const char *body)
{
  if (!body) { send_400(idx, "missing body"); return; }
  char mask[256] = "";
  json_get_str(body, "mask", mask, sizeof mask);
  if (!mask[0]) {
    send_400(idx, "mask required");
    return;
  }
  if (delignore(mask)) {
    putlog(LOG_MISC, "*", "WebUI: Removed ignore %s", mask);
    send_200_ok(idx);
  } else {
    send_400(idx, "ignore not found");
    return;
  }
  killsock(dcc[idx].sock);
  lostdcc(idx);
}

/* ---- Log capture via HOOK_LOG ---- */

static void ws_push_broadcast(const char *json, size_t len);

static void webui_log_hook(int type, const char *chan, const char *msg)
{
  struct log_entry *e = &log_ring[log_ring_head];
  log_ring_head = (log_ring_head + 1) % LOG_RING_SIZE;
  if (log_ring_count < LOG_RING_SIZE)
    log_ring_count++;

  time_t t = now;
  struct tm tm;
  localtime_r(&t, &tm);
  strftime(e->time, sizeof e->time, "%H:%M:%S", &tm);

  const char *flag = "*";
  if (type & LOG_MSGS)   flag = "m";
  else if (type & LOG_PUBLIC) flag = "p";
  else if (type & LOG_CMDS)  flag = "o";
  else if (type & LOG_JOIN)  flag = "j";
  else if (type & LOG_SERV)  flag = "s";
  else if (type & LOG_BOTS)  flag = "b";
  strlcpy(e->flags, flag, sizeof e->flags);

  strlcpy(e->msg, msg, sizeof e->msg);
  size_t len = strlen(e->msg);
  if (len > 0 && e->msg[len - 1] == '\n')
    e->msg[len - 1] = '\0';

  /* Broadcast to push WS clients */
  if (ws_push_count > 0) {
    op_strbuf_t b = {};
    op_strbuf_init(&b);
    op_strbuf_append_cstr(&b, "{\"type\":\"log\",\"data\":{\"time\":");
    json_escape(&b, e->time);
    op_strbuf_append_cstr(&b, ",\"flags\":");
    json_escape(&b, e->flags);
    op_strbuf_append_cstr(&b, ",\"msg\":");
    json_escape(&b, e->msg);
    op_strbuf_append_cstr(&b, "}}");
    ws_push_broadcast(op_strbuf_str(&b), op_strbuf_len(&b));
    op_strbuf_free(&b);
  }
}

/* ---- WebSocket push (live /ws endpoint) ---- */

static size_t webui_frame(const char **dst, const char *src, size_t len);

static void ws_push_broadcast(const char *json, size_t len)
{
  const char *framed;
  size_t flen = webui_frame(&framed, json, len);
  for (int i = 0; i < ws_push_count; i++)
    tputs(ws_push_socks[i], (char *)framed, (unsigned int)flen);
}

static void ws_push_remove(long sock)
{
  for (int i = 0; i < ws_push_count; i++) {
    if (ws_push_socks[i] == sock) {
      ws_push_socks[i] = ws_push_socks[--ws_push_count];
      return;
    }
  }
}

static void ws_push_eof(int idx)
{
  debug2("webui: ws_push_eof() idx %i sock %li", idx, dcc[idx].sock);
  ws_push_remove(dcc[idx].sock);
  killsock(dcc[idx].sock);
  lostdcc(idx);
}

static void ws_push_activity(int idx, char *buf, int len)
{
  /* Push WS clients only receive; handle close frames */
  if (len >= 2 && (buf[0] & 0x08)) {
    ws_push_remove(dcc[idx].sock);
    killsock(dcc[idx].sock);
    lostdcc(idx);
    return;
  }
  /* Ignore other input from push clients (ping/pong handled by socklist) */
}

static void ws_push_display(int idx, op_strbuf_t *buf)
{
  op_strbuf_append_cstr(buf, "webui ws-push");
}

static void kill_ws_push(int idx, void *x)
{
  (void)idx;
  (void)x;
  /* Remove from push list on kill */
  ws_push_remove(dcc[idx].sock);
}

static struct dcc_table DCC_WEBUI_WS = {
  "WEBUI_WS",
  0,
  ws_push_eof,
  ws_push_activity,
  nullptr,
  nullptr,
  ws_push_display,
  nullptr,
  kill_ws_push,
  nullptr,
  nullptr
};

/* ---- Timer for status broadcast ---- */

static time_t ws_push_last_status;

static void ws_push_status_tick(void)
{
  if (ws_push_count == 0) return;
  if (now - ws_push_last_status < 5) return;
  ws_push_last_status = now;

  int nchan = 0;
  for (struct chanset_t *c = chanset; c; c = c->next)
    nchan++;

  op_strbuf_t b = {};
  op_strbuf_init(&b);
  op_strbuf_appendf(&b,
    "{\"type\":\"status\",\"data\":{"
    "\"uptime\":%lld,\"channels\":%d,\"users\":%d}}",
    (long long)(now - online_since), nchan, count_users(userlist));

  ws_push_broadcast(op_strbuf_str(&b), op_strbuf_len(&b));
  op_strbuf_free(&b);
}

/* ---- HTTP routing ---- */

static void put_404(int idx) {
  op_strbuf_t b = {};
  op_strbuf_init(&b);
  op_strbuf_appendf(&b,
    "HTTP/1.1 404 \r\n"
    "Content-Length: 13\r\n"
    "Content-Type: text/plain\r\n"
    "Server: %s\r\n"
    "\r\n"
    "404 Not Found", server_hdr());

  size_t len = op_strbuf_len(&b);
  char *resp = op_malloc(len);
  memcpy(resp, op_strbuf_str(&b), len);
  op_strbuf_free(&b);

  tputs(dcc[idx].sock, resp, (unsigned int)len);
  op_free(resp);
  killsock(dcc[idx].sock);
  lostdcc(idx);
}

static void send_cors_preflight(int idx)
{
  const char *resp =
    "HTTP/1.1 204 No Content\r\n"
    "Access-Control-Allow-Origin: *\r\n"
    "Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS\r\n"
    "Access-Control-Allow-Headers: Authorization, Content-Type\r\n"
    "Access-Control-Max-Age: 86400\r\n"
    "\r\n";
  tputs(dcc[idx].sock, (char *)resp, (unsigned int)strlen(resp));
  killsock(dcc[idx].sock);
  lostdcc(idx);
}

/* cache file data by modification time */
struct file_cache_struct {
  char filename[27];
  char content_type[25];
  struct timespec st_mtim;
  char *data;
  off_t size;
} file_cache[3] = {
  {"webui/apple-touch-icon.png", "image/png",                { .tv_sec = -1, .tv_nsec = -1 }, nullptr, 0},
  {"webui/favicon.ico",          "image/x-icon",             { .tv_sec = -1, .tv_nsec = -1 }, nullptr, 0},
  {"webui/index.html",           "text/html; charset=utf-8", { .tv_sec = -1, .tv_nsec = -1 }, nullptr, 0}
};

static void put_file(int idx, int file_cache_index) {
  struct stat sb;
  struct file_cache_struct *f = &file_cache[file_cache_index];
  int fd;

  if (stat(f->filename, &sb) < 0) {
    putlog(LOG_MISC, "*", "WEBUI error: stat(%s): %s", f->filename, strerror(errno));
    put_404(idx);
    return;
  }
  if ((f->st_mtim.tv_sec != sb.st_mtim.tv_sec) ||
      (f->st_mtim.tv_nsec != sb.st_mtim.tv_nsec)) {
    if ((fd = open(f->filename, O_RDONLY)) < 0) {
      putlog(LOG_MISC, "*", "WEBUI error: open(%s): %s", f->filename, strerror(errno));
      put_404(idx);
      return;
    }
    f->data = op_realloc(f->data, sb.st_size);
    if (read(fd, f->data, sb.st_size) < 0) {
      putlog(LOG_MISC, "*", "WEBUI error: read(%s): %s", f->filename, strerror(errno));
      close(fd);
      put_404(idx);
      return;
    }
    close(fd);
    f->st_mtim.tv_sec = sb.st_mtim.tv_sec;
    f->st_mtim.tv_nsec = sb.st_mtim.tv_nsec;
    f->size = sb.st_size;
  }

  op_strbuf_t hdr = {};
  op_strbuf_init(&hdr);
  op_strbuf_appendf(&hdr,
    "HTTP/1.1 200 OK\r\n"
    "Content-Length: %jd\r\n"
    "Content-Type: %s\r\n"
    "Server: %s\r\n"
    "\r\n",
    (intmax_t)f->size, f->content_type, server_hdr());

  size_t hlen = op_strbuf_len(&hdr);
  char *resp = op_malloc(hlen + f->size);
  memcpy(resp, op_strbuf_str(&hdr), hlen);
  memcpy(resp + hlen, f->data, f->size);
  op_strbuf_free(&hdr);

  tputs(dcc[idx].sock, resp, (unsigned int)(hlen + f->size));
  op_free(resp);
}

/* Parse the request path from "METHOD /path HTTP/1.1\r\n..." */
static int parse_path(const char *buf, int method, char *path, size_t pathsz)
{
  const char *start;
  switch (method) {
    case HTTP_GET:     start = buf + 4; break;
    case HTTP_POST:    start = buf + 5; break;
    case HTTP_DELETE:  start = buf + 7; break;
    case HTTP_OPTIONS: start = buf + 8; break;
    default: return -1;
  }
  const char *end = start;
  while (*end && *end != ' ' && *end != '?' && *end != '\r')
    end++;
  size_t len = (size_t)(end - start);
  if (len >= pathsz) len = pathsz - 1;
  memcpy(path, start, len);
  path[len] = '\0';
  return 0;
}

static void webui_http_eof(int idx)
{
  debug2("webui: webui_http_eof() idx %i sock %li", idx, dcc[idx].sock);
  dcc[idx].u.webui_listen_idx = 0;
  killsock(dcc[idx].sock);
  lostdcc(idx);
}

static void webui_http_activity(int idx, char *buf, int len)
{
  int listen_idx;
  char *response;

  if (len > 0 && buf[0] == 0x16) {
    putlog(LOG_MISC, "*",
           "WEBUI error: %s requested TLS handshake for non-ssl port",
           iptostr(&dcc[idx].sockname.addr.sa));
    tputs(dcc[idx].sock, (char *) alert, sizeof alert);
    killsock(dcc[idx].sock);
    lostdcc(idx);
    return;
  }

  int method = parse_method(buf);
  if (len < 16 || method == HTTP_UNKNOWN) {
    putlog(LOG_MISC, "*",
           "WEBUI error: %s sent unsupported HTTP method",
           iptostr(&dcc[idx].sockname.addr.sa));
    killsock(dcc[idx].sock);
    lostdcc(idx);
    return;
  }

  struct egg_rusage_timer rt;
  egg_timer_start(&rt);
  debug2("webui: webui_http_activity(): idx %i len %i", idx, len);
  buf[len] = '\0';

  char path[128];
  if (parse_path(buf, method, path, sizeof path) < 0) {
    put_404(idx);
    return;
  }

  debug2("webui: %s %s", method == HTTP_GET ? "GET" :
         method == HTTP_POST ? "POST" :
         method == HTTP_DELETE ? "DELETE" : "OPTIONS", path);

  /* Handle CORS preflight */
  if (method == HTTP_OPTIONS) {
    send_cors_preflight(idx);
    return;
  }

  /* Auth check for all /api/ endpoints (except /api/auth POST) */
  if (!strncmp(path, "/api/", 5) && strcmp(path, "/api/auth")) {
    if (!check_auth(buf)) {
      send_401(idx);
      return;
    }
  }

  /* Also require auth for /ws */
  if (!strcmp(path, "/ws") && !check_auth(buf)) {
    send_401(idx);
    return;
  }

  /* ---- GET routes ---- */
  if (method == HTTP_GET) {
    if (!strcmp(path, "/api/status")) {
      api_status(idx);
      killsock(dcc[idx].sock);
      lostdcc(idx);
    } else if (!strcmp(path, "/api/channels")) {
      api_channels(idx);
      killsock(dcc[idx].sock);
      lostdcc(idx);
    } else if (!strcmp(path, "/api/users")) {
      api_users_list(idx);
      killsock(dcc[idx].sock);
      lostdcc(idx);
    } else if (!strncmp(path, "/api/users/", 11) && path[11]) {
      char handle[HANDLEN + 1];
      strlcpy(handle, path + 11, sizeof handle);
      url_decode(handle);
      api_user_detail(idx, handle);
      killsock(dcc[idx].sock);
      lostdcc(idx);
    } else if (!strcmp(path, "/api/traffic")) {
      api_traffic(idx);
      killsock(dcc[idx].sock);
      lostdcc(idx);
    } else if (!strcmp(path, "/api/perf")) {
      api_perf(idx);
      killsock(dcc[idx].sock);
      lostdcc(idx);
    } else if (!strcmp(path, "/api/logs")) {
      api_logs(idx);
      killsock(dcc[idx].sock);
      lostdcc(idx);
    } else if (!strcmp(path, "/api/ignores")) {
      api_ignores(idx);
      killsock(dcc[idx].sock);
      lostdcc(idx);
    } else if (!strcmp(path, "/api/modules")) {
      api_modules(idx);
      killsock(dcc[idx].sock);
      lostdcc(idx);
    } else if (!strcmp(path, "/api/botnet")) {
      api_botnet(idx);
      killsock(dcc[idx].sock);
      lostdcc(idx);
    } else if (!strncmp(path, "/api/channels/", 14)) {
      /* Parse /api/channels/<name>/members or /api/channels/<name>/bans */
      char channame[CHANNELLEN + 1];
      const char *rest = path + 14;
      const char *slash = strchr(rest, '/');
      if (slash) {
        size_t nlen = (size_t)(slash - rest);
        if (nlen >= sizeof channame) nlen = sizeof channame - 1;
        memcpy(channame, rest, nlen);
        channame[nlen] = '\0';
        url_decode(channame);
        if (!strcmp(slash + 1, "members")) {
          api_channel_members(idx, channame);
          killsock(dcc[idx].sock);
          lostdcc(idx);
        } else if (!strcmp(slash + 1, "bans")) {
          api_channel_bans(idx, channame);
          killsock(dcc[idx].sock);
          lostdcc(idx);
        } else {
          put_404(idx);
        }
      } else {
        put_404(idx);
      }
    } else if (!strcmp(path, "/")) {
      put_file(idx, 2);
    } else if (!strcmp(path, "/favicon.ico")) {
      put_file(idx, 1);
    } else if (!strcmp(path, "/apple-touch-icon.png")) {
      put_file(idx, 0);
    } else if (!strcmp(path, "/w")) {
      /* WebSocket upgrade for partyline terminal */
      char *key = strstr(buf, WS_KEY);
      if (!key) {
        putlog(LOG_MISC, "*", "WEBUI error: Sec-WebSocket-Key not found ip %s",
               iptostr(&dcc[idx].sockname.addr.sa));
        put_404(idx);
        return;
      }
      key += sizeof WS_KEY;
      for (int i = 0; i < WS_KEYLEN; i++)
        if (!key[i]) {
          putlog(LOG_MISC, "*", "WEBUI error: Sec-WebSocket-Key too short ip %s",
                 iptostr(&dcc[idx].sockname.addr.sa));
          put_404(idx);
          return;
        }

      uint8_t hash[OPSSL_SHA1_DIGEST_LEN];
      opssl_sha1_ctx_t sha1_ctx;
      opssl_sha1_init(&sha1_ctx);
      opssl_sha1_update(&sha1_ctx, key, WS_KEYLEN);
      opssl_sha1_update(&sha1_ctx, WS_GUID, (sizeof WS_GUID) - 1);
      opssl_sha1_final(&sha1_ctx, hash);

      char out[WS_LEN + 1];
      if (b64_ntop(hash, sizeof hash, out, sizeof out) != WS_LEN) {
        putlog(LOG_MISC, "*", "WEBUI error: b64_ntop() != WS_LEN");
        put_404(idx);
        return;
      }

      {
        op_strbuf_t hdr = {};
        op_strbuf_init(&hdr);
        op_strbuf_appendf(&hdr,
          "HTTP/1.1 101 Switching Protocols\r\n"
          "Upgrade: websocket\r\n"
          "Connection: Upgrade\r\n"
          "Sec-WebSocket-Accept: %s\r\n"
          "\r\n", out);
        size_t hlen = op_strbuf_len(&hdr);
        response = op_malloc(hlen + 1);
        memcpy(response, op_strbuf_str(&hdr), hlen + 1);
        op_strbuf_free(&hdr);
        tputs(dcc[idx].sock, response, (unsigned int)hlen);
        op_free(response);
      }

      sock_list *socklist_i = &socklist[findsock(dcc[idx].sock)];
      socklist_i->flags |= SOCK_WS;
      socklist_i->flags &= ~SOCK_BINARY;
      debug2("webui: unset flag SOCK_BINARY idx %i sock %li", idx, dcc[idx].sock);
      debug4("webui: set flag SOCK_WS socklist %i idx %i sock %li status %lu",
             findsock(dcc[idx].sock), idx, dcc[idx].sock, dcc[idx].status);

      dcc[idx].status |= STAT_USRONLY;

      listen_idx = dcc[idx].u.webui_listen_idx;
      dcc[idx].u.webui_listen_idx = 0;
      dcc_telnet_hostresolved2(idx, listen_idx);
    } else if (!strcmp(path, "/ws")) {
      /* WebSocket upgrade for push notifications */
      char *key = strstr(buf, WS_KEY);
      if (!key) {
        putlog(LOG_MISC, "*", "WEBUI error: Sec-WebSocket-Key not found ip %s",
               iptostr(&dcc[idx].sockname.addr.sa));
        put_404(idx);
        return;
      }
      key += sizeof WS_KEY;
      for (int i = 0; i < WS_KEYLEN; i++)
        if (!key[i]) {
          putlog(LOG_MISC, "*", "WEBUI error: Sec-WebSocket-Key too short ip %s",
                 iptostr(&dcc[idx].sockname.addr.sa));
          put_404(idx);
          return;
        }

      uint8_t hash[OPSSL_SHA1_DIGEST_LEN];
      opssl_sha1_ctx_t sha1_ctx;
      opssl_sha1_init(&sha1_ctx);
      opssl_sha1_update(&sha1_ctx, key, WS_KEYLEN);
      opssl_sha1_update(&sha1_ctx, WS_GUID, (sizeof WS_GUID) - 1);
      opssl_sha1_final(&sha1_ctx, hash);

      char out[WS_LEN + 1];
      if (b64_ntop(hash, sizeof hash, out, sizeof out) != WS_LEN) {
        putlog(LOG_MISC, "*", "WEBUI error: b64_ntop() != WS_LEN");
        put_404(idx);
        return;
      }

      {
        op_strbuf_t hdr = {};
        op_strbuf_init(&hdr);
        op_strbuf_appendf(&hdr,
          "HTTP/1.1 101 Switching Protocols\r\n"
          "Upgrade: websocket\r\n"
          "Connection: Upgrade\r\n"
          "Sec-WebSocket-Accept: %s\r\n"
          "\r\n", out);
        size_t hlen = op_strbuf_len(&hdr);
        response = op_malloc(hlen + 1);
        memcpy(response, op_strbuf_str(&hdr), hlen + 1);
        op_strbuf_free(&hdr);
        tputs(dcc[idx].sock, response, (unsigned int)hlen);
        op_free(response);
      }

      /* Register as push WS client */
      if (ws_push_count >= MAX_WS_PUSH) {
        putlog(LOG_MISC, "*", "WEBUI: Max push WS clients reached, rejecting");
        killsock(dcc[idx].sock);
        lostdcc(idx);
        return;
      }

      sock_list *socklist_i = &socklist[findsock(dcc[idx].sock)];
      socklist_i->flags |= SOCK_WS;
      socklist_i->flags &= ~SOCK_BINARY;

      ws_push_socks[ws_push_count++] = dcc[idx].sock;
      changeover_dcc(idx, &DCC_WEBUI_WS, 0);
      dcc[idx].u.other = nullptr;
    } else {
      put_404(idx);
    }
  }

  /* ---- POST routes ---- */
  else if (method == HTTP_POST) {
    const char *body = get_body(buf);
    if (!strcmp(path, "/api/auth")) {
      api_auth_post(idx, body);
    } else if (!strcmp(path, "/api/say")) {
      api_say_post(idx, body);
    } else if (!strcmp(path, "/api/kick")) {
      api_kick_post(idx, body);
    } else if (!strcmp(path, "/api/restart")) {
      api_restart_post(idx);
    } else if (!strcmp(path, "/api/users")) {
      api_users_post(idx, body);
    } else if (!strcmp(path, "/api/ignores")) {
      api_ignores_post(idx, body);
    } else {
      put_404(idx);
    }
  }

  /* ---- DELETE routes ---- */
  else if (method == HTTP_DELETE) {
    const char *body = get_body(buf);
    if (!strncmp(path, "/api/users/", 11) && path[11]) {
      char handle[HANDLEN + 1];
      strlcpy(handle, path + 11, sizeof handle);
      url_decode(handle);
      api_user_delete(idx, handle);
    } else if (!strcmp(path, "/api/ignores")) {
      api_ignores_delete(idx, body);
    } else {
      put_404(idx);
    }
  }

  else {
    put_404(idx);
  }

  if ((dcc[idx].sock != -1) && (len == 511)) {
    opssl_conn_t *ssl = socklist[findsock(dcc[idx].sock)].ssl;
    if (ssl)
      debug2("webui: opssl_read(): idx %i len %zi", idx, opssl_read(ssl, buf, 511));
    else
      debug2("webui: read(): idx %i len %li", idx, read(dcc[idx].sock, buf, 511));
  }
  double ums, sms;
  if (egg_timer_stop(&rt, &ums, &sms))
    debug2("webui: webui_http_activity(): user %.3fms sys %.3fms", ums, sms);
}

static void webui_http_display(int idx, op_strbuf_t *buf)
{
  op_strbuf_append_cstr(buf, dcc[idx].ssl ? "webui https" : "webui http");
}

static void kill_webui_http(int idx, void *x)
{
  (void)idx;
  (void)x;
}

static struct dcc_table DCC_WEBUI_HTTP = {
  "WEBUI_HTTP",
  0,
  webui_http_eof,
  webui_http_activity,
  nullptr,
  nullptr,
  webui_http_display,
  nullptr,
  kill_webui_http,
  nullptr,
  nullptr
};

static void webui_dcc_telnet_hostresolved(int idx, int listen_idx)
{
    debug2("webui_dcc_telnet_hostresolved() idx %i listen_idx %i", idx, listen_idx);
    changeover_dcc(idx, &DCC_WEBUI_HTTP, 0);
    dcc[idx].u.webui_listen_idx = listen_idx;
    sockoptions(dcc[idx].sock, EGG_OPTION_SET, SOCK_BINARY);
    sockoptions(dcc[idx].sock, EGG_OPTION_UNSET, SOCK_BUFFER);
}

static size_t escape_html(char *dst, size_t dst_size, const char *src, size_t src_size) {
  char *d = dst;

  for (int i = 0; i < (int)src_size; i++) {
    switch ((unsigned char) src[i]) {
      case '"':
        if (dst_size < 6) return d - dst;
        *d++ = '&'; *d++ = 'q'; *d++ = 'u'; *d++ = 'o'; *d++ = 't'; *d++ = ';';
        dst_size -= 6;
        break;
      case '&':
        if (dst_size < 5) return d - dst;
        *d++ = '&'; *d++ = 'a'; *d++ = 'm'; *d++ = 'p'; *d++ = ';';
        dst_size -= 5;
        break;
      case '\'':
        if (dst_size < 6) return d - dst;
        *d++ = '&'; *d++ = 'a'; *d++ = 'p'; *d++ = 'o'; *d++ = 's'; *d++ = ';';
        dst_size -= 6;
        break;
      case '<':
        if (dst_size < 4) return d - dst;
        *d++ = '&'; *d++ = 'l'; *d++ = 't'; *d++ = ';';
        dst_size -= 4;
        break;
      case '>':
        if (dst_size < 4) return d - dst;
        *d++ = '&'; *d++ = 'g'; *d++ = 't'; *d++ = ';';
        dst_size -= 4;
        break;
      case ESC:
        if ((i + 3) < (int)src_size) {
          if (((unsigned char) src[i + 1] == '[') &&
              ((unsigned char) src[i + 2] == '0') &&
              ((unsigned char) src[i + 3] == 'm')) {
            if (dst_size < 4) return d - dst;
            *d++ = '<'; *d++ = '/'; *d++ = 'b'; *d++ = '>';
            dst_size -= 4;
          } else if (((unsigned char) src[i + 1] == '[') &&
                     ((unsigned char) src[i + 2] == '1') &&
                     ((unsigned char) src[i + 3] == 'm')) {
            if (dst_size < 3) return d - dst;
            *d++ = '<'; *d++ = 'b'; *d++ = '>';
            dst_size -= 3;
          }
          i += 3;
        }
        break;
      case TLN_IAC:
        if ((i + 2) < (int)src_size) {
          if (dst_size < 1) return d - dst;
          if (((unsigned char) src[i + 1] == TLN_WILL) &&
              ((unsigned char) src[i + 2] == TLN_ECHO)) {
            *d++ = WS_ECHO_OFF;
            dst_size--;
          } else if (((unsigned char) src[i + 1] == TLN_WONT) &&
                     ((unsigned char) src[i + 2] == TLN_ECHO)) {
            *d++ = WS_ECHO_ON;
            dst_size--;
          }
          i += 2;
        }
        break;
      default:
        if (dst_size < 1) return d - dst;
        *d++ = src[i];
        dst_size--;
    }
  }
  return d - dst;
}

static size_t webui_frame(const char **dst, const char *src, size_t len) {
  static thread_local char buf[LOGLINELEN];
  uint16_t len2;

  len = escape_html(buf + 4, (sizeof buf) - 4, src, len);
  if (len < 0x7e) {
    buf[2] = (char)0x81;
    buf[3] = len;
    *dst = buf + 2;
    len += 2;
  } else {
    buf[0] = (char)0x81;
    buf[1] = 0x7e;
    len2 = htons(len);
    memcpy(buf + 2, &len2, 2);
    *dst = buf;
    len += 4;
  }
  return len;
}

static void webui_unframe(int sock, char *buf, int *len)
{
  int hdrlen;
  uint8_t *key, *payload;
  uint16_t status_code;

  key = (uint8_t *) buf;
  if (*len < 2) {
    putlog(LOG_MISC, "*", "WEBUI error: WebSocket frame too short (%d bytes) from sock %i", *len, sock);
    killsock(sock);
    lostdcc(findanyidx(sock));
    return;
  }
  if (key[1] < 0xfe)
    hdrlen = 6;
  else if (key[1] == 0xfe)
    hdrlen = 8;
  else
    hdrlen = 14;
  if (*len < hdrlen) {
    putlog(LOG_MISC, "*", "WEBUI error: truncated WebSocket frame (%d < %d bytes) from sock %i", *len, hdrlen, sock);
    killsock(sock);
    lostdcc(findanyidx(sock));
    return;
  }
  if (key[1] < 0xfe) {
    key += 2;
    *len -= 6;
  } else if (key[1] == 0xfe) {
    key += 4;
    *len -= 8;
  } else {
    key += 10;
    *len -= 14;
  }
  payload = key + 4;
  for (int i = 0; i < *len; i++)
    payload[i] = payload[i] ^ key[i % 4];

  if (buf[0] & 0x08) {
    status_code = ntohs(*((uint16_t *) payload));
    putlog(LOG_MISC, "*", "WEBUI: connection closed by peer with status code %i%s sock %i",
           status_code, status_code == 1001 ? " (Going Away)" : "", sock);
    killsock(sock);
    lostdcc(findanyidx(sock));
    return;
  }

  memmove(buf, payload, *len);
  memcpy(buf + *len, "\r\n", 3);
  *len += 2;
}

/* ---- Tcl config variable ---- */

static tcl_strings webui_tcl_strings[] = {
  {"webui-token", webui_token, 64, 0},
  {NULL, NULL, 0, 0}
};

/* ---- 1-second hook for push WS status updates ---- */

static void webui_secondly(void)
{
  ws_push_status_tick();
}

static char *webui_close(void)
{
  int idx;

  del_hook(HOOK_LOG, (Function) webui_log_hook);
  del_hook(HOOK_DCC_TELNET_HOSTRESOLVED, (Function) webui_dcc_telnet_hostresolved);
  del_hook(HOOK_WEBUI_FRAME, (Function) webui_frame);
  del_hook(HOOK_WEBUI_UNFRAME, (Function) webui_unframe);
  del_hook(HOOK_SECONDLY, (Function) webui_secondly);
  rem_tcl_strings(webui_tcl_strings);
  for (idx = 0; idx < dcc_total; idx++) {
    if (!strcmp(dcc[idx].nick, "(webui)") ||
        !strcmp(dcc[idx].type->name, "WEBUI_HTTP") ||
        !strcmp(dcc[idx].type->name, "WEBUI_WS") ||
        (socklist[findsock(dcc[idx].sock)].flags & SOCK_WS)) {
      debug2("webui: webui_close(): closing sock idx %i, %li", idx, dcc[idx].sock);
      killsock(dcc[idx].sock);
      lostdcc(idx);
    }
  }
  ws_push_count = 0;
  for (idx = 0; idx < (int)(sizeof file_cache / sizeof file_cache[0]); idx++) {
    if (file_cache[idx].data) {
      op_free(file_cache[idx].data);
      file_cache[idx].data = nullptr;
      file_cache[idx].st_mtim.tv_sec  = -1;
      file_cache[idx].st_mtim.tv_nsec = -1;
    }
  }
  return nullptr;
}

EXPORT_SCOPE char *webui_start(Function *global_funcs);

static Function webui_table[] = {
  (Function) webui_start,
  (Function) webui_close,
  nullptr,
  nullptr,
};

#endif
char *webui_start(Function *global_funcs)
{
#ifdef TLS
  global = global_funcs;
  module_register(MODULE_NAME, webui_table, 0, 10);
  if (!module_depend(MODULE_NAME, "eggdrop", 110, 0)) {
    module_undepend(MODULE_NAME);
    return "This module requires Eggdrop 1.10.0 or later.";
  }
  add_hook(HOOK_DCC_TELNET_HOSTRESOLVED, (Function) webui_dcc_telnet_hostresolved);
  add_hook(HOOK_WEBUI_FRAME, (Function) webui_frame);
  add_hook(HOOK_WEBUI_UNFRAME, (Function) webui_unframe);
  add_hook(HOOK_LOG, (Function) webui_log_hook);
  add_hook(HOOK_SECONDLY, (Function) webui_secondly);
  add_tcl_strings(webui_tcl_strings);

  memset(log_ring, 0, sizeof log_ring);
  log_ring_head = 0;
  log_ring_count = 0;
  ws_push_count = 0;
  ws_push_last_status = 0;

  return nullptr;
#else
  return "Initialization failure: configured with --disable-tls or TLS library not found";
#endif
}
