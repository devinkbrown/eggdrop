/*
 * configtoml.c -- TOML configuration file parser for Eggdrop
 *
 * Reads a .toml config file and drives the same Tcl variable and
 * command interface that a traditional eggdrop.conf Tcl script
 * would drive, so the rest of the codebase needs no changes.
 *
 * Supported TOML subset (sufficient for all eggdrop settings):
 *   [section]            -- section headers
 *   key = "string"       -- double-quoted strings (with \n \t \r \\ \" escapes)
 *   key = 'literal'      -- single-quoted literal strings (no escapes)
 *   key = 42             -- bare integers
 *   key = true / false   -- booleans (mapped to 1 / 0)
 *   key = ["a", "b"]     -- inline arrays of strings
 *   # comment            -- line comments (also permitted after values)
 *
 * Variable-name convention: TOML uses underscores in bare keys; this
 * parser converts underscores to dashes when setting Tcl variables, so
 *   botnet_nick = "MyBot"  --> Tcl var "botnet-nick"
 *   help_path   = "help/"  --> Tcl var "help-path"
 *
 * Special sections drive Tcl commands instead of (or in addition to)
 * variable sets:
 *   [modules]  load     = ["dns", "server", ...]  --> loadmodule X per entry
 *   [servers]  list     = ["host:port", ...]      --> server add X per entry
 *   [channels] list     = ["#chan", ...]           --> channel add X per entry
 *   [logging]  entries  = ["flags chan file"]      --> logfile X per entry
 *   [scripts]  load     = ["scripts/foo.tcl", …]  --> source X per entry
 *   [help]     load     = ["userinfo.help", …]    --> loadhelp X per entry
 *   [tcl]      commands = ["unbind …", …]         --> Tcl_Eval(X) per entry
 *
 * Copyright (C) 2026 Eggheads Development Team
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 */

#include "main.h"
#include "configtoml.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Maximum length of a single config line. */
#define TOML_LINE_MAX 4096

/* Recognised top-level TOML sections. */
typedef enum {
  SEC_NONE     = 0,
  SEC_BOT,        /* [bot]      -- nick, admin, username, … */
  SEC_SERVERS,    /* [servers]  -- list = ["host:port", …]  */
  SEC_CHANNELS,   /* [channels] -- list = ["#chan", …]       */
  SEC_MODULES,    /* [modules]  -- load = ["dns", …]         */
  SEC_PATHS,      /* [paths]    -- userfile, chanfile, …     */
  SEC_LOGGING,    /* [logging]  -- entries = ["flags ch f"]  */
  SEC_NETWORK,    /* [network]  -- vhost4, vhost6, nat_ip, … */
  SEC_SECURITY,   /* [security] -- owner, stealth_telnets, … */
  SEC_SCRIPTS,    /* [scripts]  -- load = ["scripts/f.tcl"]  */
  SEC_HELP,       /* [help]     -- load = ["userinfo.help"]  */
  SEC_TCL,        /* [tcl]      -- commands = ["unbind …"]   */
  SEC_OTHER,      /* unknown section — still pass through    */
} TomlSection;

/* Tcl interpreter declared in tcl.c and extern'd via main.h. */
extern Tcl_Interp *interp;

/* -----------------------------------------------------------------------
 * String helpers
 * --------------------------------------------------------------------- */

/* Trim leading and trailing ASCII whitespace in-place. */
static char *trim(char *s)
{
  char *end;
  while (*s && isspace((unsigned char)*s))
    s++;
  end = s + strlen(s);
  while (end > s && isspace((unsigned char)*(end - 1)))
    end--;
  *end = '\0';
  return s;
}

/*
 * Parse a TOML quoted string (single or double quotes).
 * src points at the opening quote character.
 * Writes at most dstlen-1 unescaped bytes to dst and NUL-terminates.
 * Returns pointer to the character after the closing quote, or NULL
 * on a parse error (unterminated string).
 */
static const char *parse_quoted(const char *src, char *dst, size_t dstlen)
{
  size_t i = 0;

  /* Triple-quoted strings: """...""" or '''...''' (may span multiple lines). */
  if ((src[0] == '"' && src[1] == '"' && src[2] == '"') ||
      (src[0] == '\'' && src[1] == '\'' && src[2] == '\'')) {
    char q = src[0];
    src += 3;
    /* Per TOML spec: an immediate newline after the opening """ is trimmed. */
    if (*src == '\n') src++;
    while (*src) {
      if (src[0] == q && src[1] == q && src[2] == q) {
        src += 3;
        break;
      }
      if (q == '"' && *src == '\\') {
        src++;
        switch (*src) {
          case 'n':  if (i < dstlen - 1) dst[i++] = '\n'; break;
          case 't':  if (i < dstlen - 1) dst[i++] = '\t'; break;
          case 'r':  if (i < dstlen - 1) dst[i++] = '\r'; break;
          case '"':  if (i < dstlen - 1) dst[i++] = '"';  break;
          case '\\': if (i < dstlen - 1) dst[i++] = '\\'; break;
          case '\n': /* line-ending backslash: skip whitespace */
            while (*src && isspace((unsigned char)*src)) src++;
            continue;
          default:   if (i < dstlen - 1) dst[i++] = *src; break;
        }
      } else {
        if (i < dstlen - 1)
          dst[i++] = *src;
      }
      if (*src) src++;
    }
    dst[i] = '\0';
    return src;
  }

  /* Single-character quote: " or ' */
  char quote = *src++;

  while (*src && *src != quote) {
    if (*src == '\\' && quote == '"') {
      /* Double-quoted strings support escape sequences. */
      src++;
      switch (*src) {
        case 'n':  if (i < dstlen - 1) dst[i++] = '\n'; break;
        case 't':  if (i < dstlen - 1) dst[i++] = '\t'; break;
        case 'r':  if (i < dstlen - 1) dst[i++] = '\r'; break;
        case '"':  if (i < dstlen - 1) dst[i++] = '"';  break;
        case '\\': if (i < dstlen - 1) dst[i++] = '\\'; break;
        default:   if (i < dstlen - 1) dst[i++] = *src; break;
      }
    } else {
      if (i < dstlen - 1)
        dst[i++] = *src;
    }
    src++;
  }

  if (*src != quote)
    return NULL; /* unterminated string */

  dst[i] = '\0';
  return src + 1; /* advance past closing quote */
}

/*
 * Convert a TOML key to a Tcl variable name.
 * Eggdrop uses dash-separated names (e.g. "botnet-nick", "help-path").
 * Since TOML bare keys cannot contain dashes, config authors write
 * underscores; we swap them here.
 */
static void key_to_tclvar(const char *key, char *out, size_t outlen)
{
  size_t i;
  for (i = 0; i < outlen - 1 && key[i]; i++)
    out[i] = (key[i] == '_') ? '-' : key[i];
  out[i] = '\0';
}

/* -----------------------------------------------------------------------
 * Tcl interface helpers
 * --------------------------------------------------------------------- */

static void set_tcl_var(const char *key, const char *value)
{
  char tclvar[256];
  key_to_tclvar(key, tclvar, sizeof tclvar);
  Tcl_SetVar(interp, tclvar, value, TCL_GLOBAL_ONLY);
}

static void run_tcl_cmd(const char *cmd)
{
  if (Tcl_Eval(interp, cmd) != TCL_OK)
    putlog(LOG_MISC, "*", "TOML config: Tcl error running '%s': %s",
           cmd, Tcl_GetStringResult(interp));
}

/* -----------------------------------------------------------------------
 * Inline-array parser
 * --------------------------------------------------------------------- */

typedef void (*ArrayCb)(const char *item, void *ud);

/*
 * Returns 1 if the string (which must begin with '[') contains a closing ']'
 * that is not inside a string or nested array.  Used to detect whether an
 * array value spans multiple lines and needs further accumulation.
 */
static int array_is_complete(const char *s)
{
  int depth = 0;
  while (*s) {
    /* Triple-quoted strings */
    if ((s[0] == '"' && s[1] == '"' && s[2] == '"') ||
        (s[0] == '\'' && s[1] == '\'' && s[2] == '\'')) {
      char q = s[0];
      s += 3;
      while (*s) {
        if (s[0] == q && s[1] == q && s[2] == q) { s += 3; break; }
        if (*s == '\\') s++;   /* skip escaped char */
        if (*s) s++;
      }
      continue;
    }
    /* Single or double-quoted string */
    if (*s == '"' || *s == '\'') {
      char q = *s++;
      while (*s && *s != q) {
        if (*s == '\\') s++;
        if (*s) s++;
      }
      if (*s) s++;
      continue;
    }
    if (*s == '[')       depth++;
    else if (*s == ']') { depth--; if (depth == 0) return 1; }
    s++;
  }
  return 0;
}

/*
 * Parse a TOML inline string array: ["a", "b", …]
 * Calls cb(item, ud) for each string element found.
 * Returns 0 on success, -1 on parse error.
 */
static int parse_string_array(const char *src, ArrayCb cb, void *ud)
{
  char item[TOML_LINE_MAX];

  if (*src != '[')
    return -1;
  src++;

  while (*src) {
    while (*src && isspace((unsigned char)*src))
      src++;
    if (*src == ']' || !*src)
      break;
    /* TOML comment between array elements: skip to end of line. */
    if (*src == '#') {
      while (*src && *src != '\n')
        src++;
      continue;
    }
    if (*src == '"' || *src == '\'') {
      src = parse_quoted(src, item, sizeof item);
      if (!src)
        return -1;
      cb(item, ud);
    }
    /* Advance past comma or to closing bracket */
    while (*src && *src != ',' && *src != ']' && *src != '\n')
      src++;
    if (*src == ',')
      src++;
  }
  return 0;
}

/* -----------------------------------------------------------------------
 * Array callbacks for special sections
 * --------------------------------------------------------------------- */

/* Count of servers added during the current readtomlconfig() call. */
static int toml_server_count = 0;

static void cb_loadmodule(const char *name, void *ud)
{
  char cmd[256];
  (void)ud;
  egg_snprintf(cmd, sizeof cmd, "loadmodule %s", name);
  run_tcl_cmd(cmd);
}

/*
 * server list entry format (chosen to stay close to the `server add` syntax):
 *   "host"                  → server add host
 *   "host:port"             → server add host port
 *   "host:+port"            → server add host +port   (SSL)
 *   "host:+port:password"   → server add host +port password
 */
static void cb_server_add(const char *entry, void *ud)
{
  char cmd[512];
  char host[256] = {0}, portpart[64] = {0}, pass[128] = {0};
  char *colon;
  (void)ud;

  strlcpy(host, entry, sizeof host);

  colon = strchr(host, ':');
  if (colon) {
    *colon = '\0';
    const char *rest = colon + 1;           /* "+port" or "port" or "+port:pass" */
    char ssl[2] = {0, 0};
    if (*rest == '+') { ssl[0] = '+'; rest++; }

    char *colon2 = strchr(rest, ':');
    if (colon2) {
      /* Has password */
      size_t plen = (size_t)(colon2 - rest);
      if (plen >= sizeof portpart) plen = sizeof portpart - 1;
      memcpy(portpart, rest, plen);
      portpart[plen] = '\0';
      strlcpy(pass, colon2 + 1, sizeof pass);
      egg_snprintf(cmd, sizeof cmd, "server add %s %s%s %s",
                   host, ssl, portpart, pass);
    } else {
      strlcpy(portpart, rest, sizeof portpart);
      egg_snprintf(cmd, sizeof cmd, "server add %s %s%s",
                   host, ssl, portpart);
    }
  } else {
    egg_snprintf(cmd, sizeof cmd, "server add %s", host);
  }

  run_tcl_cmd(cmd);
  toml_server_count++;
}

static void cb_channel_add(const char *name, void *ud)
{
  char cmd[256];
  (void)ud;
  egg_snprintf(cmd, sizeof cmd, "channel add %s", name);
  run_tcl_cmd(cmd);
}

/*
 * Logging entry format: "flags channel logfile"
 * e.g. "mco * eggdrop.log"
 */
static void cb_logfile(const char *entry, void *ud)
{
  char cmd[512];
  (void)ud;
  egg_snprintf(cmd, sizeof cmd, "logfile %s", entry);
  run_tcl_cmd(cmd);
}

static void cb_source(const char *path, void *ud)
{
  char cmd[512];
  (void)ud;
  egg_snprintf(cmd, sizeof cmd, "source %s", path);
  run_tcl_cmd(cmd);
}

static void cb_loadhelp(const char *file, void *ud)
{
  char cmd[256];
  (void)ud;
  egg_snprintf(cmd, sizeof cmd, "loadhelp %s", file);
  run_tcl_cmd(cmd);
}

/* Used by [tcl] commands = [...] — each entry is a raw Tcl command. */
static void cb_tcl_eval(const char *cmd, void *ud)
{
  (void)ud;
  run_tcl_cmd(cmd);
}

/* -----------------------------------------------------------------------
 * Value parser
 * --------------------------------------------------------------------- */

/*
 * Parse the raw string after '=' into a printable value.
 * Handles quoted strings, inline arrays (returned verbatim), bare
 * integers and booleans (true→"1", false→"0").
 * Returns 0 on success, -1 on error.
 */
static int parse_value(const char *raw, char *out, size_t outlen)
{
  while (*raw && isspace((unsigned char)*raw))
    raw++;

  if (*raw == '"' || *raw == '\'')
    return parse_quoted(raw, out, outlen) ? 0 : -1;

  if (*raw == '[') {
    /* Return the whole inline-array literal for array callbacks. */
    strlcpy(out, raw, outlen);
    return 0;
  }

  /* Bare value: integer, boolean, or unquoted word. */
  strlcpy(out, raw, outlen);

  /* Trim trailing whitespace and inline comment. */
  char *p = out;
  while (*p && !isspace((unsigned char)*p) && *p != '#')
    p++;
  *p = '\0';

  /* Normalise booleans to Tcl-friendly 1/0. */
  if (strcmp(out, "true")  == 0) { strlcpy(out, "1", outlen); return 0; }
  if (strcmp(out, "false") == 0) { strlcpy(out, "0", outlen); return 0; }

  return 0;
}

/* -----------------------------------------------------------------------
 * Section name → enum
 * --------------------------------------------------------------------- */

static TomlSection section_from_name(const char *name)
{
  if (strcmp(name, "bot")      == 0) return SEC_BOT;
  if (strcmp(name, "servers")  == 0) return SEC_SERVERS;
  if (strcmp(name, "channels") == 0) return SEC_CHANNELS;
  if (strcmp(name, "modules")  == 0) return SEC_MODULES;
  if (strcmp(name, "paths")    == 0) return SEC_PATHS;
  if (strcmp(name, "logging")  == 0) return SEC_LOGGING;
  if (strcmp(name, "network")  == 0) return SEC_NETWORK;
  if (strcmp(name, "security") == 0) return SEC_SECURITY;
  if (strcmp(name, "scripts")  == 0) return SEC_SCRIPTS;
  if (strcmp(name, "help")     == 0) return SEC_HELP;
  if (strcmp(name, "tcl")      == 0) return SEC_TCL;
  return SEC_OTHER;
}

/* -----------------------------------------------------------------------
 * Key-value dispatch
 * --------------------------------------------------------------------- */

static void process_kv(TomlSection sec, const char *key, const char *value)
{
  switch (sec) {
    case SEC_MODULES:
      if (strcmp(key, "load") == 0 && *value == '[') {
        parse_string_array(value, cb_loadmodule, NULL);
        return;
      }
      break;

    case SEC_SERVERS:
      if (strcmp(key, "list") == 0 && *value == '[') {
        parse_string_array(value, cb_server_add, NULL);
        return;
      }
      break;

    case SEC_CHANNELS:
      if (strcmp(key, "list") == 0 && *value == '[') {
        parse_string_array(value, cb_channel_add, NULL);
        return;
      }
      break;

    case SEC_LOGGING:
      if (strcmp(key, "entries") == 0 && *value == '[') {
        parse_string_array(value, cb_logfile, NULL);
        return;
      }
      break;

    case SEC_SCRIPTS:
      if (strcmp(key, "load") == 0 && *value == '[') {
        parse_string_array(value, cb_source, NULL);
        return;
      }
      break;

    case SEC_HELP:
      if (strcmp(key, "load") == 0 && *value == '[') {
        parse_string_array(value, cb_loadhelp, NULL);
        return;
      }
      break;

    case SEC_TCL:
      if (strcmp(key, "commands") == 0 && *value == '[') {
        parse_string_array(value, cb_tcl_eval, NULL);
        return;
      }
      break;

    default:
      break;
  }

  /* All other keys: set as a Tcl global variable (underscore→dash). */
  set_tcl_var(key, value);
}

/* -----------------------------------------------------------------------
 * Public API
 * --------------------------------------------------------------------- */

int readtomlconfig(const char *fname)
{
  FILE *fp;
  char line[TOML_LINE_MAX];
  /*
   * ml_value: accumulation buffer for multi-line arrays.
   * Sized for many triple-quoted Tcl proc definitions.
   */
  static char ml_value[TOML_LINE_MAX * 64];
  char key[256], value[TOML_LINE_MAX];
  char sec_name[128] = "";
  TomlSection cur_sec = SEC_NONE;
  int lineno = 0;
  int ok = 1;

  fp = fopen(fname, "r");
  if (!fp) {
    putlog(LOG_MISC, "*", "TOML config: cannot open '%s': %s",
           fname, strerror(errno));
    return 0;
  }

  while (fgets(line, sizeof line, fp)) {
    lineno++;
    char *p = trim(line);

    /* Skip blank lines and full-line comments. */
    if (!*p || *p == '#')
      continue;

    /* Section header: [name] */
    if (*p == '[') {
      char *end = strchr(p + 1, ']');
      if (!end) {
        putlog(LOG_MISC, "*", "TOML config:%d: malformed section header",
               lineno);
        continue;
      }
      *end = '\0';
      strlcpy(sec_name, trim(p + 1), sizeof sec_name);
      cur_sec = section_from_name(sec_name);
      continue;
    }

    /* Key = value */
    char *eq = strchr(p, '=');
    if (!eq)
      continue;

    *eq = '\0';
    char *k = trim(p);
    char *v = trim(eq + 1);

    /* Strip inline comment from bare values (not inside quotes/arrays). */
    if (*v != '"' && *v != '\'' && *v != '[') {
      char *hash = strchr(v, '#');
      if (hash) {
        *hash = '\0';
        v = trim(v);
      }
    }

    if (!*k)
      continue;

    strlcpy(key, k, sizeof key);

    /*
     * Multi-line array: if the value starts with '[' but the closing ']'
     * is not yet present (e.g. the array spans multiple lines or contains
     * triple-quoted strings), keep reading lines until the array is complete.
     * This is required for [tcl] commands that include proc definitions.
     */
    if (*v == '[' && !array_is_complete(v)) {
      strlcpy(ml_value, v, sizeof ml_value);
      while (!array_is_complete(ml_value)) {
        if (!fgets(line, sizeof line, fp))
          break;
        lineno++;
        /*
         * Append the raw line (trimmed of newline only, NOT of leading '#').
         * Lines beginning with '#' may be Tcl comments inside a triple-quoted
         * string and must not be discarded.  parse_string_array() handles
         * TOML-level '#' comments between array elements by skipping to EOL.
         */
        size_t llen = strlen(line);
        while (llen > 0 && (line[llen-1] == '\n' || line[llen-1] == '\r'))
          line[--llen] = '\0';
        strlcat(ml_value, "\n", sizeof ml_value);
        strlcat(ml_value, line, sizeof ml_value);
      }
      v = ml_value;
    }

    if (parse_value(v, value, sizeof value) < 0) {
      putlog(LOG_MISC, "*", "TOML config:%d: parse error for key '%s'",
             lineno, key);
      continue;
    }

    process_kv(cur_sec, key, value);
  }

  fclose(fp);

  /* ---- Validate required settings ---- */
  {
    const char *nick_val  = Tcl_GetVar(interp, "nick",  TCL_GLOBAL_ONLY);
    const char *owner_val = Tcl_GetVar(interp, "owner", TCL_GLOBAL_ONLY);

    if (!nick_val || !*nick_val) {
      putlog(LOG_MISC, "*",
             "TOML config: 'nick' is not set in [bot] — bot will not function.");
      ok = 0;
    }
    if (!owner_val || !*owner_val) {
      putlog(LOG_MISC, "*",
             "TOML config: 'owner' is not set in [security] — no one can "
             "control this bot.");
      ok = 0;
    }
    if (toml_server_count == 0) {
      putlog(LOG_MISC, "*",
             "TOML config: no servers defined in [servers] list — "
             "the bot will not connect to IRC.");
      ok = 0;
    }
    toml_server_count = 0;   /* reset for potential reload */
  }

  return ok;
}

/* -----------------------------------------------------------------------
 * Interactive setup wizard
 * --------------------------------------------------------------------- */

/*
 * Prompt the user for a value on stdin.  If they press Enter without
 * typing anything, def is used instead.  Result is written to buf
 * (at most buflen-1 bytes) and NUL-terminated.
 */
static void prompt(const char *question, const char *def,
                   char *buf, size_t buflen)
{
  if (def && *def)
    printf("  %s [%s]: ", question, def);
  else
    printf("  %s: ", question);
  fflush(stdout);

  if (!fgets(buf, (int)buflen, stdin)) {
    /* EOF / error – use default */
    strlcpy(buf, def ? def : "", buflen);
    printf("\n");
    return;
  }

  /* Strip trailing newline. */
  buf[strcspn(buf, "\r\n")] = '\0';

  /* Fall back to default on empty input. */
  if (!*buf && def)
    strlcpy(buf, def, buflen);
}

/*
 * Prompt for yes/no.  Returns 1 for yes, 0 for no.
 */
static int prompt_yn(const char *question, int def)
{
  char buf[8];
  printf("  %s [%s]: ", question, def ? "Y/n" : "y/N");
  fflush(stdout);

  if (!fgets(buf, sizeof buf, stdin)) {
    printf("\n");
    return def;
  }
  buf[strcspn(buf, "\r\n")] = '\0';
  if (!*buf)
    return def;
  return (*buf == 'y' || *buf == 'Y');
}

int run_setup_wizard(const char *outfile)
{
  char nick[64], altnick[64], realname[128], username[64];
  char admin[128], network[64], owner[64];
  char server[256], channel[64];
  char userfile[64], chanfile[64], logfile[128];
  int  use_ssl;
  int  want_notes, want_transfer, want_filesys, want_seen;
  FILE *fp;

  printf("\n");
  printf("╔══════════════════════════════════════════════╗\n");
  printf("║       Eggdrop Configuration Setup Wizard     ║\n");
  printf("╠══════════════════════════════════════════════╣\n");
  printf("║  This wizard creates a TOML config file.     ║\n");
  printf("║  Press Enter to accept the default value.    ║\n");
  printf("╚══════════════════════════════════════════════╝\n\n");

  printf("── Bot identity ──────────────────────────────\n");
  prompt("Bot nick",        "Eggdrop",          nick,     sizeof nick);
  prompt("Alternate nick",  "Eggdrop0",         altnick,  sizeof altnick);
  prompt("Real name",       "/msg Eggdrop help",realname, sizeof realname);
  prompt("IRC username",    "eggdrop",          username, sizeof username);
  prompt("Admin contact",   "Admin <admin@example.com>", admin, sizeof admin);
  prompt("IRC network name","Libera",           network,  sizeof network);
  prompt("Bot owner handle","YourNick",         owner,    sizeof owner);

  printf("\n── Server ────────────────────────────────────\n");
  prompt("IRC server hostname", "irc.libera.chat", server, sizeof server);
  use_ssl = prompt_yn("Use SSL (port 6697)?", 1);

  printf("\n── Channel ───────────────────────────────────\n");
  prompt("Channel to join", "#egghelp", channel, sizeof channel);

  printf("\n── Files ─────────────────────────────────────\n");
  prompt("User file name",  "eggdrop.user",     userfile, sizeof userfile);
  prompt("Chan file name",  "eggdrop.chan",      chanfile, sizeof chanfile);
  prompt("Log file name",   "eggdrop.log",       logfile,  sizeof logfile);

  printf("\n── Optional modules ──────────────────────────\n");
  want_notes    = prompt_yn("Enable notes (user-to-user messaging)?", 1);
  want_seen     = prompt_yn("Enable seen (track last seen time)?",    0);
  want_transfer = prompt_yn("Enable transfer (DCC file transfers)?",  0);
  want_filesys  = prompt_yn("Enable filesys (bot file system)?",      0);

  printf("\n");

  fp = fopen(outfile, "w");
  if (!fp) {
    printf("ERROR: cannot write to '%s': %s\n", outfile, strerror(errno));
    return 1;
  }

  fprintf(fp,
"# Eggdrop TOML configuration file\n"
"# Generated by: eggdrop --setup\n"
"#\n"
"# Run the bot with:  eggdrop %s\n"
"# (No chmod needed — eggdrop reads this directly.)\n"
"#\n"
"# Full documentation: doc/settings/\n"
"# Report issues    : https://github.com/eggheads/eggdrop/issues\n"
"\n", outfile);

  /* [modules] — always-on core set, plus whatever the user opted into. */
  fprintf(fp,
"[modules]\n"
"# Modules to load at startup.  Comment out lines you don't need.\n"
"load = [\n"
"  \"pbkdf2\",    # Generation-2 userfile encryption (recommended)\n"
"  \"blowfish\",  # Legacy userfile encryption support\n"
"  \"channels\",  # Channel tracking\n"
"  \"server\",    # Core IRC server support\n"
"  \"ctcp\",      # CTCP reply handling\n"
"  \"irc\",       # Basic IRC functionality\n"
"  \"console\",   # Console setting persistence\n"
"  \"uptime\",    # Uptime reporting\n");

  if (want_notes)
    fprintf(fp, "  \"notes\",     # User-to-user note storage\n");
  if (want_seen)
    fprintf(fp, "  \"seen\",      # Last-seen time tracking\n");
  if (want_transfer)
    fprintf(fp, "  \"transfer\",  # DCC file transfer support\n");
  if (want_filesys)
    fprintf(fp, "  \"filesys\",   # In-bot file system\n");

  fprintf(fp, "]\n\n");

  fprintf(fp,
"[bot]\n"
"nick        = \"%s\"\n"
"altnick     = \"%s\"\n"
"realname    = \"%s\"\n"
"username    = \"%s\"\n"
"admin       = \"%s\"\n"
"network     = \"%s\"\n"
"owner       = \"%s\"\n"
"\n", nick, altnick, realname, username, admin, network, owner);

  fprintf(fp,
"[servers]\n"
"# Format: \"host:port\" for plain, \"host:+port\" for SSL,\n"
"#         \"host:+port:password\" to include a server password.\n"
"list = [\n"
"  \"%s:%s\",\n"
"]\n"
"\n",
    server, use_ssl ? "+6697" : "6667");

  fprintf(fp,
"[channels]\n"
"list = [\"%s\"]\n"
"\n", channel);

  fprintf(fp,
"[paths]\n"
"userfile = \"%s\"\n"
"chanfile  = \"%s\"\n"
"help_path = \"help/\"\n"
"mod_path  = \"modules/\"\n"
"\n", userfile, chanfile);

  fprintf(fp,
"[logging]\n"
"# Each entry: \"flags channel logfile\"\n"
"#   flags: m=messages, o=commands, c=channel, b=bots, …\n"
"entries = [\n"
"  \"mco * %s\",\n"
"]\n"
"\n", logfile);

  fprintf(fp,
"[network]\n"
"# Uncomment and set vhost4/vhost6 if you have multiple IPs.\n"
"# vhost4 = \"0.0.0.0\"\n"
"# vhost6 = \"0::0\"\n"
"# nat_ip = \"\"  # set to external IP if behind NAT\n"
"default_port = 6667\n"
"\n");

  fprintf(fp,
"[security]\n"
"stealth_telnets  = 0\n"
"require_p        = 0\n"
"password_timeout = 180\n"
"# share_unlinks  = 1\n"
);

  fclose(fp);

  printf("╔══════════════════════════════════════════════╗\n");
  printf("║  Config written successfully.                ║\n");
  printf("╠══════════════════════════════════════════════╣\n");
  printf("║  Next steps:                                 ║\n");
  printf("║    1. Review the generated file.             ║\n");
  printf("║    2. Create user file:  eggdrop -m <conf>   ║\n");
  printf("║    3. Start the bot:     eggdrop <conf>      ║\n");
  printf("╚══════════════════════════════════════════════╝\n");
  printf("\n  Config file: %s\n\n", outfile);

  return 0;
}
