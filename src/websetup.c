/*
 * websetup.c -- HTTP-based first-launch configuration wizard for Eggdrop
 *
 * Serves a single-page setup form on a plain HTTP socket. On submission,
 * writes a ready-to-use TOML config file and exits. Intended to be invoked
 * via `eggdrop -w [port] [outfile]` before the bot's event loop starts.
 *
 * Uses only POSIX sockets — no io_uring, no TLS, no event loop.
 *
 * Copyright (C) 2026 Eggheads Development Team
 */

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif
#include "main.h"

#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#include "websetup.h"

/* Maximum POST body we'll accept (64KB is plenty for form data) */
#define MAX_POST_BODY  65536
#define MAX_HEADER_BUF 4096

/* ---- URL-decode --------------------------------------------------------- */

static int hex_digit(char c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static void url_decode(char *dst, const char *src, size_t maxlen)
{
  size_t i = 0;
  while (*src && i < maxlen - 1) {
    if (*src == '%' && hex_digit(src[1]) >= 0 && hex_digit(src[2]) >= 0) {
      dst[i++] = (char)((hex_digit(src[1]) << 4) | hex_digit(src[2]));
      src += 3;
    } else if (*src == '+') {
      dst[i++] = ' ';
      src++;
    } else {
      dst[i++] = *src++;
    }
  }
  dst[i] = '\0';
}

/* ---- Form field extraction ---------------------------------------------- */

static int get_form_field(const char *body, const char *key, char *out, size_t outlen)
{
  size_t klen = strlen(key);
  const char *p = body;

  while ((p = strstr(p, key)) != nullptr) {
    if (p != body && *(p - 1) != '&') {
      p += klen;
      continue;
    }
    if (p[klen] != '=') {
      p += klen;
      continue;
    }
    p += klen + 1;
    const char *end = strchr(p, '&');
    size_t vlen = end ? (size_t)(end - p) : strlen(p);
    if (vlen >= outlen) vlen = outlen - 1;
    char tmp[512];
    if (vlen >= sizeof(tmp)) vlen = sizeof(tmp) - 1;
    memcpy(tmp, p, vlen);
    tmp[vlen] = '\0';
    url_decode(out, tmp, outlen);
    return 1;
  }
  out[0] = '\0';
  return 0;
}

static int get_form_bool(const char *body, const char *key)
{
  char val[16];
  if (!get_form_field(body, key, val, sizeof(val)))
    return 0;
  return (val[0] == '1' || val[0] == 'o' || val[0] == 't' || val[0] == 'y');
}

static int get_form_int(const char *body, const char *key, int def)
{
  char val[32];
  if (!get_form_field(body, key, val, sizeof(val)))
    return def;
  int v = atoi(val);
  return v ? v : def;
}

/* ---- TOML writer (mirrors run_setup_wizard output) ---------------------- */

static int write_toml_config(const char *outfile, const char *body)
{
  char nick[64], altnick[64], realname[128], username[64];
  char admin[128], network[64], owner[64];
  char server[256], server_pass[128], port_buf[16];
  char sasl_user[64], sasl_pass[128];
  char dot_server[64];
  char ircx_ownerkey[128];
  char channels[8][64];
  char userfile[64], chanfile[64], logfile[128];
  char tmp[128];
  int nchan, port, use_ssl, net_idx;
  int want_sasl, sasl_mech_val;
  int want_ircx, ircx_want_autoowner;
  int want_dot;
  int listen_port, botnet_port;
  int want_notes, want_seen, want_transfer, want_filesys;
  FILE *fp;

  static const char * const net_type_map[] = {
    "Libera", "EFnet", "IRCnet", "Undernet", "DALnet",
    "QuakeNet", "Rizon", "Ophion", "EFnet"
  };
  static const char * const net_labels[] = {
    "Libera.Chat", "EFnet", "IRCnet", "Undernet", "DALnet",
    "QuakeNet", "Rizon", "Ophion (IRCX)", "Other"
  };

  get_form_field(body, "nick", nick, sizeof(nick));
  if (!*nick) return -1;

  get_form_field(body, "altnick", altnick, sizeof(altnick));
  if (!*altnick) snprintf(altnick, sizeof(altnick), "%s?", nick);

  get_form_field(body, "realname", realname, sizeof(realname));
  if (!*realname) snprintf(realname, sizeof(realname), "/msg %s help", nick);

  get_form_field(body, "username", username, sizeof(username));
  if (!*username) {
    op_strlcpy(username, nick, sizeof(username));
    for (int i = 0; username[i]; i++)
      username[i] = (char)tolower((unsigned char)username[i]);
  }

  get_form_field(body, "admin", admin, sizeof(admin));
  if (!*admin) op_strlcpy(admin, "Admin <admin@example.com>", sizeof(admin));

  get_form_field(body, "owner", owner, sizeof(owner));
  if (!*owner) op_strlcpy(owner, nick, sizeof(owner));

  net_idx = get_form_int(body, "net_idx", 0);
  if (net_idx < 0 || net_idx > 8) net_idx = 0;

  if (net_idx < 8)
    op_strlcpy(network, net_labels[net_idx], sizeof(network));
  else
    get_form_field(body, "network", network, sizeof(network));
  if (!*network) op_strlcpy(network, "Other", sizeof(network));

  want_ircx = (net_idx == 7);
  const char *net_type_str = net_type_map[net_idx];

  get_form_field(body, "server", server, sizeof(server));
  if (!*server) op_strlcpy(server, "irc.libera.chat", sizeof(server));

  use_ssl = get_form_bool(body, "use_ssl");

  get_form_field(body, "port", port_buf, sizeof(port_buf));
  port = atoi(port_buf);
  if (port <= 0 || port > 65535) port = use_ssl ? 6697 : 6667;

  get_form_field(body, "server_pass", server_pass, sizeof(server_pass));

  want_sasl = get_form_bool(body, "want_sasl");
  sasl_mech_val = get_form_int(body, "sasl_mech", 0);
  get_form_field(body, "sasl_user", sasl_user, sizeof(sasl_user));
  get_form_field(body, "sasl_pass", sasl_pass, sizeof(sasl_pass));

  want_dot = get_form_bool(body, "want_dot");
  get_form_field(body, "dot_server", dot_server, sizeof(dot_server));
  if (want_dot && !*dot_server)
    op_strlcpy(dot_server, "1.1.1.1", sizeof(dot_server));

  get_form_field(body, "ircx_ownerkey", ircx_ownerkey, sizeof(ircx_ownerkey));
  ircx_want_autoowner = get_form_bool(body, "ircx_autoowner");

  /* Channels: channel0 through channel7 */
  nchan = 0;
  for (int i = 0; i < 8; i++) {
    char key[16];
    snprintf(key, sizeof(key), "channel%d", i);
    get_form_field(body, key, tmp, sizeof(tmp));
    if (*tmp && tmp[0] == '#') {
      op_strlcpy(channels[nchan], tmp, sizeof(channels[0]));
      nchan++;
    }
  }

  get_form_field(body, "userfile", userfile, sizeof(userfile));
  if (!*userfile) snprintf(userfile, sizeof(userfile), "%s.user", nick);

  get_form_field(body, "chanfile", chanfile, sizeof(chanfile));
  if (!*chanfile) snprintf(chanfile, sizeof(chanfile), "%s.chan", nick);

  get_form_field(body, "logfile", logfile, sizeof(logfile));
  if (!*logfile) snprintf(logfile, sizeof(logfile), "%s.log", nick);

  listen_port = get_form_int(body, "listen_port", 3333);
  if (listen_port < 0 || listen_port > 65535) listen_port = 3333;

  botnet_port = get_form_int(body, "botnet_port", 0);
  if (botnet_port < 0 || botnet_port > 65535) botnet_port = 0;

  want_notes    = get_form_bool(body, "want_notes");
  want_seen     = get_form_bool(body, "want_seen");
  want_transfer = get_form_bool(body, "want_transfer");
  want_filesys  = get_form_bool(body, "want_filesys");

  /* ── Write the TOML file ── */
  fp = fopen(outfile, "w");
  if (!fp) return -1;

  fprintf(fp,
"# Eggdrop TOML configuration file\n"
"# Generated by: eggdrop --web-setup\n"
"#\n"
"# Run the bot with:  eggdrop %s\n"
"# On first run the bot creates its user file automatically from owner =\n"
"# (no -m flag required).\n"
"#\n"
"# Full documentation: doc/settings/\n"
"\n", outfile);

  fprintf(fp,
"[modules]\n"
"load = [\n"
"  \"pbkdf2\",\n"
"  \"blowfish\",\n"
"  \"channels\",\n"
"  \"server\",\n"
"  \"ctcp\",\n"
"  \"irc\",\n"
"  \"dns\",\n"
"  \"console\",\n"
"  \"uptime\",\n");
  if (want_notes)    fprintf(fp, "  \"notes\",\n");
  if (want_seen)     fprintf(fp, "  \"seen\",\n");
  if (want_transfer) fprintf(fp, "  \"transfer\",\n");
  if (want_filesys)  fprintf(fp, "  \"filesys\",\n");
  fprintf(fp, "]\n\n");

  fprintf(fp,
"[bot]\n"
"nick     = \"%s\"\n"
"altnick  = \"%s\"\n"
"realname = \"%s\"\n"
"username = \"%s\"\n"
"admin    = \"%s\"\n"
"network  = \"%s\"\n"
"owner    = \"%s\"\n"
"notify_newusers = \"%s\"\n"
"default_flags   = \"hp\"\n"
"\n", nick, altnick, realname, username, admin, network, owner, owner);

  fprintf(fp,
"[servers]\n"
"list = [\n");
  if (*server_pass)
    fprintf(fp, "  \"%s:%s%d:%s\",\n", server, use_ssl ? "+" : "", port, server_pass);
  else
    fprintf(fp, "  \"%s:%s%d\",\n", server, use_ssl ? "+" : "", port);
  fprintf(fp, "]\n\n");

  fprintf(fp, "[channels]\nlist = [");
  for (int i = 0; i < nchan; i++)
    fprintf(fp, "%s\"%s\"", i ? ", " : "", channels[i]);
  fprintf(fp, "]\n\n"
"default_chanmode         = \"nt\"\n"
"default_ban_time         = 120\n"
"default_exempt_time      = 60\n"
"default_invite_time      = 60\n"
"default_ban_type         = 3\n"
"default_idle_kick        = 0\n"
"default_stopnethack_mode = 0\n"
"default_revenge_mode     = 0\n"
"default_flood_chan        = \"15:60\"\n"
"default_flood_deop        = \"3:10\"\n"
"default_flood_kick        = \"3:10\"\n"
"default_flood_join        = \"5:60\"\n"
"default_flood_ctcp        = \"3:60\"\n"
"default_flood_nick        = \"5:60\"\n"
"default_aop_delay         = \"5:30\"\n"
"\n");

  if (want_ircx && nchan > 0) {
    for (int i = 0; i < nchan; i++) {
      fprintf(fp, "[[chanset]]\nchannel     = \"%s\"\n", channels[i]);
      if (*ircx_ownerkey)
        fprintf(fp, "ownerkey    = \"%s\"\n", ircx_ownerkey);
      if (ircx_want_autoowner)
        fprintf(fp, "ircx_create = true\n");
      fprintf(fp, "\n");
    }
  }

  fprintf(fp,
"[paths]\n"
"userfile      = \"%s\"\n"
"chanfile      = \"%s\"\n"
"help_path     = \"help/\"\n"
"text_path     = \"text/\"\n"
"motd          = \"text/motd\"\n"
"telnet_banner = \"text/banner\"\n"
#ifdef EGG_MODDIR
"mod_path      = \"" EGG_MODDIR "/\"\n"
#else
"mod_path      = \"modules/\"\n"
#endif
"\n", userfile, chanfile);

  fprintf(fp,
"[logging]\n"
"entries = [\n"
"  \"mco * %s\",\n"
"]\n"
"max_logs          = 20\n"
"max_logsize       = 0\n"
"log_time          = 1\n"
"timestamp_format  = \"[%%H:%%M:%%S]\"\n"
"keep_all_logs     = 0\n"
"switch_logfiles_at = 300\n"
"quiet_save        = 0\n"
"\n", logfile);

  fprintf(fp,
"[irc]\n"
"net_type        = \"%s\"\n"
"ctcp_mode       = 0\n"
"learn_users     = 0\n"
"allow_hello     = 1\n"
"allow_addhost   = 1\n"
"keep_nick       = 1\n"
"server_timeout  = 60\n"
"server_cycle_wait = 60\n"
"msg_rate        = 2\n"
"answer_ctcp     = 3\n"
"flood_msg       = \"5:60\"\n"
"flood_ctcp      = \"3:60\"\n"
"bounce_bans     = 0\n"
"bounce_exempts  = 0\n"
"bounce_invites  = 0\n"
"bounce_modes    = 0\n"
"prevent_mixing  = 1\n"
"mode_buf_length = 200\n"
"opchars         = \"@\"\n"
"\n", net_type_str);

  fprintf(fp,
"[network]\n"
"default_port    = %d\n"
"connect_timeout = 15\n"
"prefer_ipv6     = 0\n"
"\n", use_ssl ? 6697 : 6667);

  fprintf(fp,
"[security]\n"
"must_be_owner        = 1\n"
"require_p            = 1\n"
"stealth_telnets      = 0\n"
"open_telnets         = 0\n"
"protect_telnet       = 0\n"
"dcc_flood_thr        = 3\n"
"telnet_flood         = \"16:60\"\n"
"paranoid_telnet_flood = 1\n"
"cidr_support         = 0\n"
"\n");

  fprintf(fp,
"[behaviour]\n"
"max_socks        = 100\n"
"allow_dk_cmds    = 1\n"
"dupwait_timeout  = 5\n"
"check_stoned     = 1\n"
"serverror_quit   = 1\n"
"max_queue_msg    = 300\n"
"trigger_on_ignore = 0\n"
"exclusive_binds  = 0\n"
"double_mode      = 1\n"
"double_server    = 1\n"
"double_help      = 1\n"
"optimize_kicks   = 1\n"
"stack_limit      = 4\n"
"hourly_updates   = 0\n"
"ignore_time      = 15\n"
"remote_boots     = 2\n"
"share_unlinks    = 1\n"
"wait_split       = 600\n"
"wait_info        = 180\n"
"\n");

  if (want_sasl) {
    fprintf(fp,
"[sasl]\n"
"sasl           = 1\n"
"sasl_mechanism = %d\n"
"sasl_username  = \"%s\"\n", sasl_mech_val, sasl_user);
    if (*sasl_pass)
      fprintf(fp, "sasl_password  = \"%s\"\n", sasl_pass);
    fprintf(fp, "sasl_continue  = 1\n"
"sasl_timeout   = 15\n\n");
  }

  fprintf(fp,
"[ctcp]\n\n");

  if (want_ircx) {
    fprintf(fp,
"[ircx]\n"
"ircx_auto_negotiate = 1\n");
    if (*ircx_ownerkey)
      fprintf(fp, "ircx_ownerkey = \"%s\"\n", ircx_ownerkey);
    fprintf(fp, "\n");
  }

  fprintf(fp,
"[share]\n"
"allow_resync   = 0\n"
"resync_time    = 900\n"
"private_global = 0\n"
"private_user   = 0\n"
"override_bots  = 0\n"
"\n");

  fprintf(fp,
"[dns]\n"
"dns_maxsends   = 4\n"
"dns_retrydelay = 3\n"
"dns_cache      = 86400\n"
"dns_negcache   = 600\n"
"\n");

  if (want_notes) {
    fprintf(fp,
"[notes]\n"
"max_notes     = 50\n"
"note_life     = 60\n"
"allow_fwd     = 0\n"
"notify_users  = 0\n"
"notify_onjoin = 1\n"
"\n");
  }

  if (want_transfer) {
    fprintf(fp,
"[transfer]\n"
"max_dloads       = 3\n"
"dcc_block        = 0\n"
"xfer_timeout     = 30\n"
"sharefail_unlink = 0\n"
"\n");
  }

  if (want_filesys) {
    fprintf(fp,
"[filesys]\n"
"files_path     = \"filesys\"\n"
"incoming_path  = \"filesys/incoming\"\n"
"upload_to_pwd  = 0\n"
"max_file_users = 20\n"
"max_filesize   = 1024\n"
"\n");
  }

  fprintf(fp,
"[console]\n"
"console          = \"mkcoblxs\"\n"
"console_autosave = 1\n"
"force_channel    = 0\n"
"info_party       = 0\n"
"\n");

  fprintf(fp,
"[crypto]\n"
"pbkdf2_re_encode  = 1\n"
"blowfish_use_mode = \"cbc\"\n"
"\n");

  fprintf(fp,
"[tcl]\n"
"commands = [\n"
"  \"unbind dcc n simul *dcc:simul\",\n");
  if (want_dot && *dot_server)
    fprintf(fp, "  \"dnsdot on %s\",\n", dot_server);
  if (listen_port > 0)
    fprintf(fp, "  \"listen %d users\",\n", listen_port);
  if (botnet_port > 0)
    fprintf(fp, "  \"listen %d bots\",\n", botnet_port);
  fprintf(fp, "]\n\n");

  fclose(fp);
  return 0;
}

/* ---- HTML page ---------------------------------------------------------- */

static const char WIZARD_HTML[] =
"<!DOCTYPE html>\n"
"<html lang=\"en\">\n"
"<head>\n"
"<meta charset=\"utf-8\">\n"
"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
"<title>Eggdrop Setup Wizard</title>\n"
"<style>\n"
"*{box-sizing:border-box;margin:0;padding:0}\n"
":root{\n"
"  --bg:oklch(12% 0.02 260);\n"
"  --surface:oklch(16% 0.02 260);\n"
"  --border:oklch(26% 0.02 260);\n"
"  --text:oklch(92% 0 0);\n"
"  --muted:oklch(65% 0 0);\n"
"  --accent:oklch(72% 0.18 160);\n"
"  --accent-dim:oklch(40% 0.12 160);\n"
"  --danger:oklch(65% 0.2 25);\n"
"}\n"
"body{font-family:system-ui,-apple-system,sans-serif;background:var(--bg);\n"
"  color:var(--text);min-height:100vh;display:flex;justify-content:center;\n"
"  padding:2rem 1rem;line-height:1.5}\n"
".wizard{max-width:640px;width:100%}\n"
"h1{font-size:1.75rem;margin-bottom:0.5rem}\n"
".subtitle{color:var(--muted);margin-bottom:2rem}\n"
".step{background:var(--surface);border:1px solid var(--border);\n"
"  border-radius:12px;padding:1.5rem;margin-bottom:1rem;display:none}\n"
".step.active{display:block}\n"
".step h2{font-size:1.1rem;margin-bottom:1rem;color:var(--accent)}\n"
"label{display:block;font-size:0.85rem;color:var(--muted);margin-bottom:0.25rem;\n"
"  margin-top:0.75rem}\n"
"input[type=text],input[type=number],input[type=password],select{\n"
"  width:100%;padding:0.6rem 0.75rem;background:var(--bg);border:1px solid var(--border);\n"
"  border-radius:6px;color:var(--text);font-size:0.95rem}\n"
"input:focus,select:focus{outline:none;border-color:var(--accent)}\n"
".check-row{display:flex;align-items:center;gap:0.5rem;margin-top:0.75rem}\n"
".check-row input{width:auto}\n"
".check-row label{margin:0;font-size:0.95rem;color:var(--text)}\n"
".btn-row{display:flex;gap:0.75rem;margin-top:1.5rem;justify-content:flex-end}\n"
"button{padding:0.6rem 1.5rem;border:none;border-radius:6px;font-size:0.9rem;\n"
"  cursor:pointer;font-weight:500;transition:background 0.15s}\n"
".btn-next{background:var(--accent);color:oklch(15% 0 0)}\n"
".btn-next:hover{background:oklch(78% 0.18 160)}\n"
".btn-back{background:var(--border);color:var(--text)}\n"
".btn-back:hover{background:oklch(32% 0.02 260)}\n"
".btn-submit{background:var(--accent);color:oklch(15% 0 0);font-size:1rem;padding:0.75rem 2rem}\n"
".progress{display:flex;gap:0.5rem;margin-bottom:1.5rem}\n"
".progress .dot{width:10px;height:10px;border-radius:50%;background:var(--border);\n"
"  transition:background 0.2s}\n"
".progress .dot.done{background:var(--accent)}\n"
".progress .dot.current{background:var(--accent);box-shadow:0 0 8px var(--accent-dim)}\n"
".hint{font-size:0.8rem;color:var(--muted);margin-top:0.25rem}\n"
"#result{display:none;text-align:center;padding:3rem}\n"
"#result h2{color:var(--accent);font-size:1.5rem;margin-bottom:1rem}\n"
"#result code{background:var(--surface);padding:0.5rem 1rem;border-radius:6px;\n"
"  font-family:monospace;font-size:1.1rem}\n"
"</style>\n"
"</head>\n"
"<body>\n"
"<div class=\"wizard\">\n"
"<h1>Eggdrop Setup</h1>\n"
"<p class=\"subtitle\">Configure your bot in a few steps.</p>\n"
"<div class=\"progress\" id=\"progress\"></div>\n"
"<form id=\"form\" method=\"POST\" action=\"/setup\">\n"
"\n"
"<div class=\"step active\" id=\"step1\">\n"
"<h2>1. Bot Identity</h2>\n"
"<label for=\"nick\">Bot nickname *</label>\n"
"<input type=\"text\" name=\"nick\" id=\"nick\" required placeholder=\"MyBot\">\n"
"<label for=\"altnick\">Alternate nick</label>\n"
"<input type=\"text\" name=\"altnick\" id=\"altnick\" placeholder=\"MyBot?\">\n"
"<div class=\"hint\">Used when primary nick is taken. ? = random digit.</div>\n"
"<label for=\"realname\">Real name (GECOS)</label>\n"
"<input type=\"text\" name=\"realname\" id=\"realname\" placeholder=\"/msg MyBot help\">\n"
"<label for=\"username\">IRC username (ident)</label>\n"
"<input type=\"text\" name=\"username\" id=\"username\" placeholder=\"mybot\">\n"
"<label for=\"admin\">Admin contact</label>\n"
"<input type=\"text\" name=\"admin\" id=\"admin\" placeholder=\"Admin <admin@example.com>\">\n"
"<label for=\"owner\">Owner handle (your IRC nick) *</label>\n"
"<input type=\"text\" name=\"owner\" id=\"owner\" required placeholder=\"YourNick\">\n"
"<div class=\"btn-row\"><button type=\"button\" class=\"btn-next\" onclick=\"goStep(2)\">Next</button></div>\n"
"</div>\n"
"\n"
"<div class=\"step\" id=\"step2\">\n"
"<h2>2. IRC Server</h2>\n"
"<label for=\"net_idx\">Network</label>\n"
"<select name=\"net_idx\" id=\"net_idx\" onchange=\"netChange()\">\n"
"<option value=\"0\">Libera.Chat</option>\n"
"<option value=\"1\">EFnet</option>\n"
"<option value=\"2\">IRCnet</option>\n"
"<option value=\"3\">Undernet</option>\n"
"<option value=\"4\">DALnet</option>\n"
"<option value=\"5\">QuakeNet</option>\n"
"<option value=\"6\">Rizon</option>\n"
"<option value=\"7\">Ophion (IRCX)</option>\n"
"<option value=\"8\">Other / custom</option>\n"
"</select>\n"
"<label for=\"server\">Server hostname</label>\n"
"<input type=\"text\" name=\"server\" id=\"server\" placeholder=\"irc.libera.chat\">\n"
"<div class=\"check-row\"><input type=\"checkbox\" name=\"use_ssl\" id=\"use_ssl\" value=\"1\" checked>\n"
"<label for=\"use_ssl\">Use SSL/TLS</label></div>\n"
"<label for=\"port\">Port</label>\n"
"<input type=\"number\" name=\"port\" id=\"port\" placeholder=\"6697\">\n"
"<label for=\"server_pass\">Server password (optional)</label>\n"
"<input type=\"password\" name=\"server_pass\" id=\"server_pass\">\n"
"<div class=\"check-row\"><input type=\"checkbox\" name=\"want_sasl\" id=\"want_sasl\" value=\"1\">\n"
"<label for=\"want_sasl\">Enable SASL authentication</label></div>\n"
"<div id=\"sasl_opts\" style=\"display:none\">\n"
"<label for=\"sasl_mech\">SASL mechanism</label>\n"
"<select name=\"sasl_mech\" id=\"sasl_mech\">\n"
"<option value=\"0\">PLAIN</option>\n"
"<option value=\"2\">EXTERNAL (cert)</option>\n"
"<option value=\"3\">SCRAM-SHA-256</option>\n"
"<option value=\"4\">SCRAM-SHA-512</option>\n"
"</select>\n"
"<label for=\"sasl_user\">SASL username</label>\n"
"<input type=\"text\" name=\"sasl_user\" id=\"sasl_user\">\n"
"<label for=\"sasl_pass\">SASL password</label>\n"
"<input type=\"password\" name=\"sasl_pass\" id=\"sasl_pass\">\n"
"</div>\n"
"<div class=\"check-row\"><input type=\"checkbox\" name=\"want_dot\" id=\"want_dot\" value=\"1\">\n"
"<label for=\"want_dot\">Enable DNS-over-TLS</label></div>\n"
"<div id=\"dot_opts\" style=\"display:none\">\n"
"<label for=\"dot_server\">DoT server IP</label>\n"
"<input type=\"text\" name=\"dot_server\" id=\"dot_server\" value=\"1.1.1.1\">\n"
"</div>\n"
"<div class=\"btn-row\">\n"
"<button type=\"button\" class=\"btn-back\" onclick=\"goStep(1)\">Back</button>\n"
"<button type=\"button\" class=\"btn-next\" onclick=\"goStep(3)\">Next</button></div>\n"
"</div>\n"
"\n"
"<div class=\"step\" id=\"step3\">\n"
"<h2>3. Channels</h2>\n"
"<label for=\"channel0\">Channel 1 *</label>\n"
"<input type=\"text\" name=\"channel0\" id=\"channel0\" required placeholder=\"#mychannel\">\n"
"<label for=\"channel1\">Channel 2</label>\n"
"<input type=\"text\" name=\"channel1\" id=\"channel1\" placeholder=\"#other\">\n"
"<label for=\"channel2\">Channel 3</label>\n"
"<input type=\"text\" name=\"channel2\" id=\"channel2\">\n"
"<label for=\"channel3\">Channel 4</label>\n"
"<input type=\"text\" name=\"channel3\" id=\"channel3\">\n"
"<div id=\"ircx_opts\" style=\"display:none\">\n"
"<label for=\"ircx_ownerkey\">IRCX Owner Key</label>\n"
"<input type=\"text\" name=\"ircx_ownerkey\" id=\"ircx_ownerkey\">\n"
"<div class=\"check-row\"><input type=\"checkbox\" name=\"ircx_autoowner\" id=\"ircx_autoowner\" value=\"1\" checked>\n"
"<label for=\"ircx_autoowner\">Auto-request owner (+q)</label></div>\n"
"</div>\n"
"<div class=\"btn-row\">\n"
"<button type=\"button\" class=\"btn-back\" onclick=\"goStep(2)\">Back</button>\n"
"<button type=\"button\" class=\"btn-next\" onclick=\"goStep(4)\">Next</button></div>\n"
"</div>\n"
"\n"
"<div class=\"step\" id=\"step4\">\n"
"<h2>4. Files &amp; Ports</h2>\n"
"<label for=\"userfile\">User file</label>\n"
"<input type=\"text\" name=\"userfile\" id=\"userfile\" placeholder=\"bot.user\">\n"
"<label for=\"chanfile\">Channel file</label>\n"
"<input type=\"text\" name=\"chanfile\" id=\"chanfile\" placeholder=\"bot.chan\">\n"
"<label for=\"logfile\">Log file</label>\n"
"<input type=\"text\" name=\"logfile\" id=\"logfile\" placeholder=\"bot.log\">\n"
"<label for=\"listen_port\">DCC/telnet port (0 = disable)</label>\n"
"<input type=\"number\" name=\"listen_port\" id=\"listen_port\" value=\"3333\">\n"
"<label for=\"botnet_port\">Botnet port (0 = disable)</label>\n"
"<input type=\"number\" name=\"botnet_port\" id=\"botnet_port\" value=\"0\">\n"
"<div class=\"btn-row\">\n"
"<button type=\"button\" class=\"btn-back\" onclick=\"goStep(3)\">Back</button>\n"
"<button type=\"button\" class=\"btn-next\" onclick=\"goStep(5)\">Next</button></div>\n"
"</div>\n"
"\n"
"<div class=\"step\" id=\"step5\">\n"
"<h2>5. Modules</h2>\n"
"<div class=\"check-row\"><input type=\"checkbox\" name=\"want_notes\" id=\"want_notes\" value=\"1\" checked>\n"
"<label for=\"want_notes\">Notes (user-to-user messaging)</label></div>\n"
"<div class=\"check-row\"><input type=\"checkbox\" name=\"want_seen\" id=\"want_seen\" value=\"1\">\n"
"<label for=\"want_seen\">Seen (last-seen tracking)</label></div>\n"
"<div class=\"check-row\"><input type=\"checkbox\" name=\"want_transfer\" id=\"want_transfer\" value=\"1\">\n"
"<label for=\"want_transfer\">Transfer (DCC file transfers)</label></div>\n"
"<div class=\"check-row\"><input type=\"checkbox\" name=\"want_filesys\" id=\"want_filesys\" value=\"1\">\n"
"<label for=\"want_filesys\">Filesys (in-bot file system)</label></div>\n"
"<div class=\"btn-row\">\n"
"<button type=\"button\" class=\"btn-back\" onclick=\"goStep(4)\">Back</button>\n"
"<button type=\"submit\" class=\"btn-submit\">Create Config</button></div>\n"
"</div>\n"
"\n"
"</form>\n"
"<div id=\"result\">\n"
"<h2>Configuration saved!</h2>\n"
"<p style=\"margin-bottom:1rem;color:var(--muted)\">Start the bot with:</p>\n"
"<code id=\"run-cmd\">./eggdrop eggdrop.toml</code>\n"
"<p style=\"margin-top:1.5rem;color:var(--muted)\">You can close this page now.</p>\n"
"</div>\n"
"</div>\n"
"<script>\n"
"const steps=5;\n"
"let cur=1;\n"
"function buildProgress(){const p=document.getElementById('progress');\n"
"  for(let i=1;i<=steps;i++){const d=document.createElement('div');\n"
"  d.className='dot';d.id='dot'+i;p.appendChild(d);}updateDots();}\n"
"function updateDots(){for(let i=1;i<=steps;i++){const d=document.getElementById('dot'+i);\n"
"  d.className=i<cur?'dot done':i===cur?'dot current':'dot';}}\n"
"function goStep(n){document.getElementById('step'+cur).classList.remove('active');\n"
"  cur=n;document.getElementById('step'+cur).classList.add('active');updateDots();}\n"
"buildProgress();\n"
"const nets=['irc.libera.chat','irc.efnet.org','irc.ircnet.net','irc.undernet.org',\n"
"  'irc.dal.net','irc.quakenet.org','irc.rizon.net','irc.example.net','irc.example.net'];\n"
"function netChange(){const i=document.getElementById('net_idx').value;\n"
"  document.getElementById('server').placeholder=nets[i];\n"
"  document.getElementById('ircx_opts').style.display=i==='7'?'block':'none';}\n"
"document.getElementById('want_sasl').onchange=function(){\n"
"  document.getElementById('sasl_opts').style.display=this.checked?'block':'none';};\n"
"document.getElementById('want_dot').onchange=function(){\n"
"  document.getElementById('dot_opts').style.display=this.checked?'block':'none';};\n"
"document.getElementById('form').onsubmit=function(e){e.preventDefault();\n"
"  const fd=new FormData(this);const params=new URLSearchParams(fd);\n"
"  fetch('/setup',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},\n"
"    body:params.toString()}).then(r=>r.json()).then(d=>{\n"
"    if(d.ok){document.getElementById('form').style.display='none';\n"
"      document.querySelector('.progress').style.display='none';\n"
"      document.getElementById('run-cmd').textContent='./eggdrop '+d.file;\n"
"      document.getElementById('result').style.display='block';}\n"
"    else{alert('Error: '+d.error);}}).catch(err=>alert('Request failed: '+err));};\n"
"</script>\n"
"</body>\n"
"</html>\n";

/* ---- HTTP server -------------------------------------------------------- */

static void send_full(int fd, const char *buf, size_t len)
{
  while (len > 0) {
    ssize_t n = write(fd, buf, len);
    if (n <= 0) break;
    buf += n;
    len -= (size_t)n;
  }
}

static void send_response(int fd, int status, const char *content_type,
                          const char *body, size_t body_len)
{
  const char *status_text = (status == 200) ? "OK" : "Bad Request";
  op_strbuf_t hdr = {};
  op_strbuf_init(&hdr);
  op_strbuf_appendf(&hdr,
    "HTTP/1.1 %d %s\r\n"
    "Content-Type: %s\r\n"
    "Content-Length: %zu\r\n"
    "Connection: close\r\n"
    "\r\n",
    status, status_text, content_type, body_len);
  send_full(fd, op_strbuf_str(&hdr), op_strbuf_len(&hdr));
  op_strbuf_free(&hdr);
  if (body_len > 0)
    send_full(fd, body, body_len);
}

static int read_request(int fd, char *buf, size_t bufsize)
{
  size_t total = 0;
  while (total < bufsize - 1) {
    ssize_t n = read(fd, buf + total, bufsize - 1 - total);
    if (n <= 0) break;
    total += (size_t)n;
    buf[total] = '\0';
    /* Check if we have the full request */
    char *hdr_end = strstr(buf, "\r\n\r\n");
    if (hdr_end) {
      size_t hdr_len = (size_t)(hdr_end - buf) + 4;
      /* Check Content-Length for POST bodies */
      char *cl = op_strcasestr(buf, "Content-Length:");
      if (cl) {
        int content_len = atoi(cl + 15);
        if (content_len > 0 && (int)(total - hdr_len) >= content_len)
          break;
        if (content_len <= 0)
          break;
      } else {
        /* GET with no body */
        if (buf[0] == 'G')
          break;
      }
    }
  }
  return (int)total;
}

int run_web_setup(int port, const char *outfile)
{
  int srv_fd, cli_fd;
  struct sockaddr_in6 addr = {};
  int opt = 1;

  signal(SIGPIPE, SIG_IGN);

  srv_fd = socket(AF_INET6, SOCK_STREAM, 0);
  if (srv_fd < 0) {
    fprintf(stderr, "ERROR: socket(): %s\n", strerror(errno));
    return 1;
  }

  setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  /* Allow IPv4 connections on the same socket */
  opt = 0;
  setsockopt(srv_fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));

  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons((uint16_t)port);
  addr.sin6_addr = in6addr_any;

  if (bind(srv_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    fprintf(stderr, "ERROR: bind() port %d: %s\n", port, strerror(errno));
    close(srv_fd);
    return 1;
  }

  if (listen(srv_fd, 4) < 0) {
    fprintf(stderr, "ERROR: listen(): %s\n", strerror(errno));
    close(srv_fd);
    return 1;
  }

  printf("\n"
         "╔══════════════════════════════════════════════════╗\n"
         "║     Eggdrop Web Setup Wizard                     ║\n"
         "╠══════════════════════════════════════════════════╣\n"
         "║  Open your browser and go to:                    ║\n"
         "║                                                  ║\n"
         "║    http://localhost:%-5d                         ║\n"
         "║                                                  ║\n"
         "║  The wizard will guide you through               ║\n"
         "║  creating a configuration file.                  ║\n"
         "║                                                  ║\n"
         "║  Press Ctrl+C to cancel.                         ║\n"
         "╚══════════════════════════════════════════════════╝\n\n",
         port);
  fflush(stdout);

  /* Serve until config is written */
  for (;;) {
    cli_fd = accept(srv_fd, nullptr, nullptr);
    if (cli_fd < 0) {
      if (errno == EINTR) continue;
      break;
    }

    char *reqbuf = op_malloc(MAX_POST_BODY + MAX_HEADER_BUF);

    int reqlen = read_request(cli_fd, reqbuf, MAX_POST_BODY + MAX_HEADER_BUF);
    if (reqlen <= 0) { op_free(reqbuf); close(cli_fd); continue; }

    if (strncmp(reqbuf, "GET ", 4) == 0) {
      /* Serve the wizard page */
      send_response(cli_fd, 200, "text/html; charset=utf-8",
                    WIZARD_HTML, sizeof(WIZARD_HTML) - 1);
    } else if (strncmp(reqbuf, "POST /setup", 11) == 0) {
      /* Find the body */
      char *body = strstr(reqbuf, "\r\n\r\n");
      if (body) {
        body += 4;
        int rc = write_toml_config(outfile, body);
        if (rc == 0) {
          op_strbuf_t json = {};
          op_strbuf_init(&json);
          op_strbuf_appendf(&json, "{\"ok\":true,\"file\":\"%s\"}", outfile);
          send_response(cli_fd, 200, "application/json",
                        op_strbuf_str(&json), op_strbuf_len(&json));
          op_strbuf_free(&json);
          op_free(reqbuf);
          close(cli_fd);
          close(srv_fd);

          printf("Config written: %s\n"
                 "Start the bot with:  ./eggdrop %s\n\n",
                 outfile, outfile);
          return 0;
        } else {
          const char *err = "{\"ok\":false,\"error\":\"Failed to write config file\"}";
          send_response(cli_fd, 400, "application/json", err, strlen(err));
        }
      } else {
        const char *err = "{\"ok\":false,\"error\":\"Malformed request\"}";
        send_response(cli_fd, 400, "application/json", err, strlen(err));
      }
    } else {
      send_response(cli_fd, 400, "text/plain", "Bad Request\n", 12);
    }

    op_free(reqbuf);
    close(cli_fd);
  }

  close(srv_fd);
  return 1;
}
