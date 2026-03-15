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
  SEC_BOT,        /* [bot]        -- nick, admin, username, …         */
  SEC_SERVERS,    /* [servers]    -- list = ["host:port", …]          */
  SEC_CHANNELS,   /* [channels]   -- list = ["#chan", …]              */
  SEC_MODULES,    /* [modules]    -- load = ["dns", …]                */
  SEC_PATHS,      /* [paths]      -- userfile, chanfile, …            */
  SEC_LOGGING,    /* [logging]    -- entries = ["flags ch f"]         */
  SEC_NETWORK,    /* [network]    -- vhost4, vhost6, nat_ip, …        */
  SEC_SECURITY,   /* [security]   -- owner, stealth_telnets, …        */
  SEC_SCRIPTS,    /* [scripts]    -- load = ["scripts/f.tcl"]         */
  SEC_HELP,       /* [help]       -- load = ["userinfo.help"]         */
  SEC_TCL,        /* [tcl]        -- commands = ["unbind …"]          */
  SEC_CHANSET,    /* [[chanset]]  -- per-channel settings             */
  SEC_OTHER,      /* unknown section — still pass through             */
} TomlSection;

/* -----------------------------------------------------------------------
 * [[chanset]] per-channel state
 * Each [[chanset]] block contributes one entry.  IRCX settings are
 * accumulated and emitted as a single ircxautoowner call when the block
 * ends (next [[chanset]], next [section], or EOF).
 * --------------------------------------------------------------------- */
static char chanset_channel[64];
static char chanset_ownerkey[128];
static int  chanset_ircx_create;
static char chanset_ircx_modes[32];
static int  chanset_has_ircx;

static void reset_chanset_state(void)
{
  chanset_channel[0]    = '\0';
  chanset_ownerkey[0]   = '\0';
  chanset_ircx_create   = 0;
  chanset_ircx_modes[0] = '\0';
  chanset_has_ircx      = 0;
}

/* Emit ircxautoowner for the current block if any IRCX keys were set. */
static void flush_chanset_ircx(void)
{
  char cmd[512];
  if (!chanset_has_ircx || !chanset_channel[0])
    return;
  if (chanset_ircx_modes[0])
    egg_snprintf(cmd, sizeof cmd, "ircxautoowner %s \"%s\" %d \"%s\"",
                 chanset_channel, chanset_ownerkey,
                 chanset_ircx_create, chanset_ircx_modes);
  else
    egg_snprintf(cmd, sizeof cmd, "ircxautoowner %s \"%s\" %d",
                 chanset_channel, chanset_ownerkey, chanset_ircx_create);
  run_tcl_cmd(cmd);
  chanset_has_ircx = 0;
}

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
 * Returns 1 if a triple-quoted string (which must begin with """ or ''')
 * contains its closing triple-quote.  Used to detect whether the value
 * spans multiple lines and needs further line accumulation.
 */
static int triplestr_is_complete(const char *s)
{
  char q;
  if (!s || (s[0] != '"' && s[0] != '\'') || s[1] != s[0] || s[2] != s[0])
    return 1; /* not a triple-quoted string — treat as complete */
  q = s[0];
  s += 3;
  /* Skip an immediate newline per TOML spec. */
  if (*s == '\n') s++;
  while (*s) {
    if (s[0] == q && s[1] == q && s[2] == q)
      return 1;
    if (q == '"' && *s == '\\') s++; /* skip escaped char */
    if (*s) s++;
  }
  return 0;
}

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
  if (strcmp(name, "chanset")  == 0) return SEC_CHANSET;
  if (strcmp(name, "ircx")     == 0) return SEC_OTHER; /* IRCX/Ophion — vars set via Tcl */
  return SEC_OTHER;
}

/* -----------------------------------------------------------------------
 * Channel flag lookup
 * Names taken verbatim from tclchan.c tcl_channel_get/modify.
 * These are boolean: true/1 → +flag, false/0 → -flag.
 * Everything else is a valued option: "channel set #chan opt val".
 * --------------------------------------------------------------------- */
static int is_chan_flag(const char *key)
{
  static const char * const flags[] = {
    "autoop",        "autohalfop",    "autovoice",
    "bitch",         "cycle",         "dontkickops",
    "dynamicbans",   "dynamicexempts","dynamicinvites",
    "enforcebans",   "greet",         "inactive",
    "nodesynch",     "protectfriends","protecthalfops",
    "protectops",    "revenge",       "revengebot",
    "secret",        "seen",          "shared",
    "static",        "statuslog",     "userbans",
    "userexempts",   "userinvites",
    NULL
  };
  const char * const *f;
  for (f = flags; *f; f++)
    if (strcmp(key, *f) == 0)
      return 1;
  return 0;
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
      /* [tcl] code = """..."""  — evaluate a multi-line Tcl script block.
       * The value has already been unquoted by parse_value() / parse_quoted(),
       * so we receive the raw Tcl text and can eval it directly.  This is
       * more ergonomic than the commands array for proc definitions and other
       * multi-statement code. */
      if (strcmp(key, "code") == 0) {
        run_tcl_cmd(value);
        return;
      }
      break;

    case SEC_CHANSET:
      /* channel = "#name" — identifies which channel this block configures. */
      if (strcmp(key, "channel") == 0) {
        strlcpy(chanset_channel, value, sizeof chanset_channel);
        return;
      }
      if (!chanset_channel[0])
        return; /* channel key must appear before other settings */

      /* IRCX / Ophion settings — accumulated and emitted as ircxautoowner. */
      if (strcmp(key, "ownerkey") == 0 || strcmp(key, "ircx_ownerkey") == 0) {
        strlcpy(chanset_ownerkey, value, sizeof chanset_ownerkey);
        chanset_has_ircx = 1;
        return;
      }
      if (strcmp(key, "ircx_create") == 0) {
        chanset_ircx_create = atoi(value);
        chanset_has_ircx = 1;
        return;
      }
      if (strcmp(key, "ircx_create_modes") == 0) {
        strlcpy(chanset_ircx_modes, value, sizeof chanset_ircx_modes);
        chanset_has_ircx = 1;
        return;
      }

      /* Remaining keys: either a boolean flag or a valued option.
       * Boolean flags use +/- prefix with no value argument.
       * Valued options use "channel set #chan option-name value". */
      {
        char tclkey[64], cmd[512];
        key_to_tclvar(key, tclkey, sizeof tclkey);
        if (is_chan_flag(tclkey)) {
          /* true/1 → +flag, false/0 → -flag */
          egg_snprintf(cmd, sizeof cmd, "channel set %s %s%s",
                       chanset_channel,
                       (strcmp(value, "0") == 0) ? "-" : "+",
                       tclkey);
        } else {
          egg_snprintf(cmd, sizeof cmd, "channel set %s %s %s",
                       chanset_channel, tclkey, value);
        }
        run_tcl_cmd(cmd);
      }
      return;

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

    /* Section header: [name] or [[name]] (TOML array-of-tables) */
    if (*p == '[') {
      int is_aot = (p[1] == '[');  /* array-of-tables: [[name]] */
      char *inner = p + 1 + (is_aot ? 1 : 0);
      char *end   = strchr(inner, ']');
      if (!end) {
        putlog(LOG_MISC, "*", "TOML config:%d: malformed section header",
               lineno);
        continue;
      }
      *end = '\0';
      strlcpy(sec_name, trim(inner), sizeof sec_name);

      /* Flush any pending [[chanset]] IRCX state before switching sections. */
      if (cur_sec == SEC_CHANSET)
        flush_chanset_ircx();

      if (is_aot) {
        /* Only [[chanset]] array-of-tables is handled specially. */
        if (strcmp(sec_name, "chanset") == 0) {
          cur_sec = SEC_CHANSET;
          reset_chanset_state();
        } else {
          cur_sec = SEC_OTHER;
        }
      } else {
        cur_sec = section_from_name(sec_name);
        /* [chanset] (non-array form) — reset state for a fresh block. */
        if (cur_sec == SEC_CHANSET)
          reset_chanset_state();
      }
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
     * Multi-line value accumulation.
     *
     * Arrays: if the value starts with '[' but the closing ']' is not yet
     * present, keep reading lines until the array is complete.  Required for
     * [tcl] commands arrays that contain proc definitions.
     *
     * Triple-quoted strings: if the value starts with """ or ''' but the
     * closing triple-quote is not yet present, accumulate lines likewise.
     * Required for [tcl] code = """...""" multi-line Tcl script blocks.
     */
    {
      int needs_accum = 0;
      int is_array = (*v == '[');
      int is_triplestr = (!is_array &&
                         ((*v == '"' && v[1] == '"' && v[2] == '"') ||
                          (*v == '\'' && v[1] == '\'' && v[2] == '\'')));
      if (is_array && !array_is_complete(v))
        needs_accum = 1;
      if (is_triplestr && !triplestr_is_complete(v))
        needs_accum = 1;

      if (needs_accum) {
        strlcpy(ml_value, v, sizeof ml_value);
        for (;;) {
          int done = is_array ? array_is_complete(ml_value)
                              : triplestr_is_complete(ml_value);
          if (done) break;
          if (!fgets(line, sizeof line, fp)) break;
          lineno++;
          /*
           * Append the raw line (newline stripped, but NOT leading '#').
           * Tcl comments inside triple-quoted strings must not be discarded.
           */
          size_t llen = strlen(line);
          while (llen > 0 && (line[llen-1] == '\n' || line[llen-1] == '\r'))
            line[--llen] = '\0';
          strlcat(ml_value, "\n", sizeof ml_value);
          strlcat(ml_value, line, sizeof ml_value);
        }
        v = ml_value;
      }
    }

    if (parse_value(v, value, sizeof value) < 0) {
      putlog(LOG_MISC, "*", "TOML config:%d: parse error for key '%s'",
             lineno, key);
      continue;
    }

    process_kv(cur_sec, key, value);
  }

  fclose(fp);

  /* Flush any [[chanset]] block that was still open at EOF. */
  if (cur_sec == SEC_CHANSET)
    flush_chanset_ircx();

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

/*
 * Prompt for a required (non-empty) value.  Re-asks until the user
 * types something.
 */
static void prompt_required(const char *question, char *buf, size_t buflen)
{
  for (;;) {
    printf("  %s: ", question);
    fflush(stdout);
    if (!fgets(buf, (int)buflen, stdin)) {
      buf[0] = '\0';
      printf("\n");
      return;
    }
    buf[strcspn(buf, "\r\n")] = '\0';
    if (*buf)
      return;
    printf("  (Required — please enter a value.)\n");
  }
}

/*
 * Numbered-menu prompt.  options[] must be NULL-terminated.
 * def is the 0-based default index.  Returns the 0-based chosen index.
 */
static int prompt_menu(const char *question,
                       const char * const *options, int def)
{
  int n = 0, i;
  char buf[16];

  while (options[n])
    n++;
  for (i = 0; i < n; i++)
    printf("    %d) %s%s\n", i + 1, options[i],
           i == def ? "  (default)" : "");
  for (;;) {
    printf("  %s [%d]: ", question, def + 1);
    fflush(stdout);
    if (!fgets(buf, sizeof buf, stdin)) {
      printf("\n");
      return def;
    }
    buf[strcspn(buf, "\r\n")] = '\0';
    if (!*buf)
      return def;
    i = atoi(buf) - 1;
    if (i >= 0 && i < n)
      return i;
    printf("  Please enter a number between 1 and %d.\n", n);
  }
}

/* Print a wizard step header. */
static void step_header(int step, int total, const char *title)
{
  printf("\n  ┌─ Step %d/%d — %s\n", step, total, title);
}

int run_setup_wizard(const char *outfile)
{
  /* Bot identity */
  char nick[64], altnick[64], realname[128], username[64];
  char admin[128], network[64], owner[64];
  /* Server */
  char server[256], server_pass[128], port_buf[16];
  int  net_idx, use_ssl, port;
  const char *net_type_str;           /* string value for net-type Tcl var */
  /* SASL */
  int  want_sasl, sasl_mech_val;
  char sasl_user[64], sasl_pass[128];
  /* IRCX / Ophion */
  int  want_ircx;
  char ircx_ownerkey[128];
  int  ircx_want_autoowner;
  /* Channels */
  char channels[8][64];
  int  nchan;
  /* Files */
  char userfile[64], chanfile[64], logfile[128];
  /* Modules */
  int  want_notes, want_transfer, want_filesys, want_seen;
  /* Working buffer */
  char tmp[128];
  int  i;
  FILE *fp;

  static const char * const net_labels[] = {
    "Libera.Chat",   "EFnet",     "IRCnet",
    "Undernet",      "DALnet",    "QuakeNet",
    "Rizon",         "Ophion (IRCX)", "Other / custom",
    NULL
  };
  static const char * const net_defaults[] = {
    "irc.libera.chat",   "irc.efnet.org",    "irc.ircnet.net",
    "irc.undernet.org",  "irc.dal.net",      "irc.quakenet.org",
    "irc.rizon.net",     "irc.example.net",  "irc.example.net"
  };
  /* net-type string values for the Tcl variable */
  static const char * const net_type_map[] = {
    "Libera", "EFnet", "IRCnet", "Undernet", "DALnet",
    "QuakeNet", "Rizon", "Ophion", "EFnet"   /* Other defaults to EFnet */
  };

  static const char * const sasl_labels[] = {
    "PLAIN  (username + password)",
    "EXTERNAL  (client certificate)",
    "SCRAM-SHA-256",
    "SCRAM-SHA-512",
    NULL
  };
  /* Maps sasl_labels index → sasl_mechanism Tcl value */
  static const int sasl_mech_map[] = { 0, 2, 3, 4 };

  printf("\n"
         "╔══════════════════════════════════════════════╗\n"
         "║       Eggdrop Configuration Setup Wizard     ║\n"
         "╠══════════════════════════════════════════════╣\n"
         "║  This wizard creates a TOML config file.     ║\n"
         "║  Press Enter to accept the default value.    ║\n"
         "╚══════════════════════════════════════════════╝\n");

  /* ── Step 1/5: Bot identity ─────────────────────────── */
  step_header(1, 5, "Bot identity");
  prompt_required("Bot nick (no spaces)", nick, sizeof nick);

  /* Smart defaults derived from nick */
  snprintf(tmp, sizeof tmp, "%s?", nick);
  prompt("Alternate nick (? replaced by a random digit)", tmp,
         altnick, sizeof altnick);

  snprintf(tmp, sizeof tmp, "/msg %s help", nick);
  prompt("Real name (IRC GECOS)", tmp, realname, sizeof realname);

  /* Lowercase nick as default IRC username */
  strlcpy(tmp, nick, sizeof tmp);
  for (i = 0; tmp[i]; i++)
    tmp[i] = (char)tolower((unsigned char)tmp[i]);
  prompt("IRC username (ident)", tmp, username, sizeof username);

  prompt("Admin contact", "Admin <admin@example.com>", admin, sizeof admin);
  prompt_required("Bot owner handle (your IRC nick)", owner, sizeof owner);

  /* ── Step 2/5: IRC server ───────────────────────────── */
  step_header(2, 5, "IRC server");

  printf("  Network:\n");
  net_idx      = prompt_menu("Choose network", net_labels, 0);
  net_type_str = net_type_map[net_idx];
  want_ircx    = (net_idx == 7); /* "Ophion (IRCX)" is index 7 */

  /* Use short network name for [bot] network = ... */
  if (net_idx < 8)
    strlcpy(network, net_labels[net_idx], sizeof network);
  else
    prompt("Network name (display only)", "MyNetwork", network, sizeof network);

  prompt("IRC server hostname", net_defaults[net_idx], server, sizeof server);
  use_ssl = prompt_yn("Use SSL/TLS?", 1);

  snprintf(tmp, sizeof tmp, "%d", use_ssl ? 6697 : 6667);
  prompt("Port", tmp, port_buf, sizeof port_buf);
  port = atoi(port_buf);
  if (port <= 0 || port > 65535)
    port = use_ssl ? 6697 : 6667;

  printf("  Server password (leave empty for none): ");
  fflush(stdout);
  if (!fgets(server_pass, sizeof server_pass, stdin)) {
    server_pass[0] = '\0';
    printf("\n");
  } else {
    server_pass[strcspn(server_pass, "\r\n")] = '\0';
  }

  /* SASL — only offered when SSL is enabled */
  want_sasl    = 0;
  sasl_mech_val = 0;
  sasl_user[0] = sasl_pass[0] = '\0';
  if (use_ssl) {
    printf("\n  ┌─ SASL authentication (optional)\n");
    want_sasl = prompt_yn("Enable SASL?", 0);
    if (want_sasl) {
      int mech_idx;
      printf("  Mechanism:\n");
      mech_idx      = prompt_menu("Choose SASL mechanism", sasl_labels, 0);
      sasl_mech_val = sasl_mech_map[mech_idx];
      prompt("SASL username", nick, sasl_user, sizeof sasl_user);
      if (sasl_mech_val != 2) /* not EXTERNAL — needs a password */
        prompt_required("SASL password", sasl_pass, sizeof sasl_pass);
    }
  }

  /* ── IRCX / Ophion options (only when Ophion network selected) ─────── */
  ircx_ownerkey[0]   = '\0';
  ircx_want_autoowner = 0;
  if (want_ircx) {
    printf("\n  ┌─ IRCX / Ophion settings\n");
    printf("  │  The bot sends IRCX after login to enable owner (+q) mode,\n");
    printf("  │  channel properties (PROP), and access lists (ACCESS).\n");
    prompt("  │  Global OWNERKEY (grants +q on join, leave empty if none)",
           "", ircx_ownerkey, sizeof ircx_ownerkey);
    ircx_want_autoowner = prompt_yn("  Auto-request owner (+q) on your channels?", 1);
  }

  /* ── Step 3/5: Channels ─────────────────────────────── */
  step_header(3, 5, "Channels");
  printf("  Enter channels to join.  First is required; empty line to stop.\n");

  nchan = 0;
  for (;;) {
    char cbuf[64];
    int  required = (nchan == 0);

    if (required) {
      prompt_required("Channel 1 (e.g. #egghelp)", cbuf, sizeof cbuf);
    } else {
      printf("  Channel %d (Enter to stop): ", nchan + 1);
      fflush(stdout);
      if (!fgets(cbuf, sizeof cbuf, stdin)) { printf("\n"); break; }
      cbuf[strcspn(cbuf, "\r\n")] = '\0';
      if (!*cbuf)
        break;
    }

    /* Validate: channel name must start with '#' */
    if (cbuf[0] != '#') {
      if (required) {
        printf("  (Channel names must start with '#' — try again.)\n");
        continue;
      }
      break;
    }

    strlcpy(channels[nchan], cbuf, sizeof channels[0]);
    if (++nchan >= 8)
      break;
  }

  /* ── Step 4/5: Files ────────────────────────────────── */
  step_header(4, 5, "Files");

  /* Defaults derived from nick */
  snprintf(tmp, sizeof tmp, "%s.user", nick);
  prompt("User file", tmp, userfile, sizeof userfile);
  snprintf(tmp, sizeof tmp, "%s.chan", nick);
  prompt("Chan file", tmp, chanfile, sizeof chanfile);
  snprintf(tmp, sizeof tmp, "%s.log",  nick);
  prompt("Log file",  tmp, logfile,  sizeof logfile);

  /* ── Step 5/5: Optional modules ─────────────────────── */
  step_header(5, 5, "Optional modules");
  want_notes    = prompt_yn("Enable notes    (user-to-user messaging)?", 1);
  want_seen     = prompt_yn("Enable seen     (track last-seen times)?",  0);
  want_transfer = prompt_yn("Enable transfer (DCC file transfers)?",     0);
  want_filesys  = prompt_yn("Enable filesys  (in-bot file system)?",     0);

  /* ── Summary & confirmation ──────────────────────────── */
  printf("\n"
         "╔══════════════════════════════════════════════╗\n"
         "║              Configuration Summary           ║\n"
         "╚══════════════════════════════════════════════╝\n");
  printf("  Nick       : %s / %s\n",     nick, altnick);
  printf("  Owner      : %s\n",           owner);
  printf("  Network    : %s  (%s)\n",     network, server);
  printf("  Net type   : %s%s\n",         net_type_str,
         want_ircx ? " — IRCX/Ophion mode enabled" : "");
  printf("  Connection : %s port %d%s\n",
         use_ssl ? "SSL/TLS" : "plain", port,
         want_sasl ? " + SASL" : "");
  printf("  Channels   :");
  for (i = 0; i < nchan; i++)
    printf(" %s", channels[i]);
  printf("\n");
  printf("  User file  : %s\n",           userfile);
  printf("  Output     : %s\n\n",         outfile);

  if (!prompt_yn("Write this configuration to disk?", 1))
    return 1;

  /* ── Write config ────────────────────────────────────── */
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
"# On first run the bot creates its user file automatically from owner =\n"
"# (no -m flag required).\n"
"#\n"
"# Full documentation: doc/settings/\n"
"# Report issues    : https://github.com/eggheads/eggdrop/issues\n"
"\n", outfile);

  /* [modules] */
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

  /* [bot] */
  fprintf(fp,
"[bot]\n"
"nick     = \"%s\"\n"
"altnick  = \"%s\"\n"
"realname = \"%s\"\n"
"username = \"%s\"\n"
"admin    = \"%s\"\n"
"network  = \"%s\"\n"
"owner    = \"%s\"\n"
"\n", nick, altnick, realname, username, admin, network, owner);

  /* [servers] */
  fprintf(fp,
"[servers]\n"
"# Format: \"host:port\" for plain, \"host:+port\" for SSL,\n"
"#         \"host:+port:password\" to include a server password.\n"
"list = [\n");
  if (*server_pass)
    fprintf(fp, "  \"%s:%s%d:%s\",\n",
            server, use_ssl ? "+" : "", port, server_pass);
  else
    fprintf(fp, "  \"%s:%s%d\",\n",
            server, use_ssl ? "+" : "", port);
  fprintf(fp, "]\n\n");

  /* [channels] */
  fprintf(fp, "[channels]\nlist = [");
  for (i = 0; i < nchan; i++)
    fprintf(fp, "%s\"%s\"", i ? ", " : "", channels[i]);
  fprintf(fp, "]\n\n");

  /* [[chanset]] — one block per channel.
   * For IRCX networks, pre-populate ownerkey and create settings.
   * For non-IRCX, write commented-out template blocks. */
  if (want_ircx && nchan > 0) {
    fprintf(fp,
"# ---------------------------------------------------------------------------\n"
"# Per-channel settings (IRCX / Ophion)\n"
"# ---------------------------------------------------------------------------\n");
    for (i = 0; i < nchan; i++) {
      fprintf(fp,
"[[chanset]]\n"
"channel          = \"%s\"\n",
              channels[i]);
      if (*ircx_ownerkey)
        fprintf(fp, "ownerkey         = \"%s\"\n", ircx_ownerkey);
      else
        fprintf(fp, "# ownerkey       = \"\"  # set your OWNERKEY here\n");
      if (ircx_want_autoowner)
        fprintf(fp,
"ircx_create      = true\n"
"# ircx_create_modes = \"+nts\"  # optional modes after CREATE\n");
      fprintf(fp, "\n");
    }
  } else if (nchan > 0) {
    fprintf(fp,
"# ---------------------------------------------------------------------------\n"
"# Per-channel settings  (uncomment and edit as needed)\n"
"# ---------------------------------------------------------------------------\n"
"# [[chanset]]\n"
"# channel  = \"%s\"\n"
"# chanmode = \"+nts\"      # forced channel modes\n"
"# idle_kick = 0          # kick idle users after N minutes (0 = off)\n"
"# key_prot  = \"\"         # protect this join key\n"
"\n",
            channels[0]);
  }

  /* [paths] */
  fprintf(fp,
"[paths]\n"
"userfile  = \"%s\"\n"
"chanfile  = \"%s\"\n"
"help_path = \"help/\"\n"
#ifdef EGG_MODDIR
"mod_path  = \"" EGG_MODDIR "/\"\n"
#else
"mod_path  = \"modules/\"\n"
#endif
"\n", userfile, chanfile);

  /* [logging] */
  fprintf(fp,
"[logging]\n"
"# Flags: m=messages o=commands c=channel b=bots j=joins s=server k=kicks\n"
"entries = [\n"
"  \"mco * %s\",\n"
"]\n"
"\n", logfile);

  /* [irc] */
  fprintf(fp,
"[irc]\n"
"# Network type affects protocol behaviour.\n"
"# Values: EFnet IRCnet Undernet DALnet Libera QuakeNet Rizon Ophion\n"
"net_type = \"%s\"\n"
"\n", net_type_str);

  /* [network] */
  fprintf(fp,
"[network]\n"
"# Uncomment to bind to a specific address on multi-homed hosts.\n"
"# vhost4 = \"0.0.0.0\"\n"
"# vhost6 = \"0::0\"\n"
"# nat_ip = \"\"  # set to external IP if behind NAT\n"
"default_port = %d\n"
"\n", use_ssl ? 6697 : 6667);

  /* [security] */
  fprintf(fp,
"[security]\n"
"stealth_telnets = 0\n"
"require_p       = 0\n"
"\n");

  /* [sasl] — only written when the user enabled it */
  if (want_sasl) {
    fprintf(fp,
"[sasl]\n"
"sasl           = 1\n"
"sasl_mechanism = %d\n"
"sasl_username  = \"%s\"\n",
            sasl_mech_val, sasl_user);
    if (*sasl_pass)
      fprintf(fp, "sasl_password  = \"%s\"\n", sasl_pass);
    fprintf(fp, "\n");
  }

  /* [ircx] — only written when user chose Ophion network */
  if (want_ircx) {
    fprintf(fp,
"[ircx]\n"
"# Ophion/IRCX protocol support.\n"
"# The bot negotiates IRCX mode after login, enabling:\n"
"#   +q owner mode, PROP channel properties, ACCESS lists, CREATE command.\n"
"ircx_auto_negotiate = 1\n");
    if (*ircx_ownerkey)
      fprintf(fp, "ircx_ownerkey = \"%s\"\n\n", ircx_ownerkey);
    else
      fprintf(fp, "# ircx_ownerkey = \"\"  # set to your OWNERKEY if required\n\n");
  }

  /* [tcl] */
  fprintf(fp,
"# ---------------------------------------------------------------------------\n"
"# TCL\n"
"# Raw Tcl evaluated after all settings are applied.\n"
"# ---------------------------------------------------------------------------\n"
"\n"
"[tcl]\n"
"commands = [\n"
"  # Disable the 'simul' partyline command (security best practice).\n"
"  \"unbind dcc n simul *dcc:simul\",\n"
"]\n"
"\n");

  /* IRCX auto-owner Tcl code block.
   * We register channels with ircxautoowner directly in the code block so
   * the list is populated before any server connections are made.
   * ircx_do_autoowner() runs when got800 (RPL_IRCX) fires and joins each
   * channel with the OWNERKEY so the server grants +q immediately on join.
   * If ircxautoowner is called while IRCX is already active (e.g. late bind
   * or manual call), the immediate-trigger path in tclserv.c handles it. */
  if (want_ircx && ircx_want_autoowner && nchan > 0) {
    fprintf(fp,
"# IRCX: register channels for auto-owner (+q) on every server connect.\n"
"# The bot joins each channel with the OWNERKEY; the server grants +q.\n"
"# ircxautoowner <channel> [ownerkey] [create-if-empty 0|1]\n"
"code = \"\"\"\n");
    for (i = 0; i < nchan; i++)
      fprintf(fp, "ircxautoowner %s \"%s\" 1\n",
              channels[i], ircx_ownerkey);
    fprintf(fp,
"\"\"\"\n"
"\n");
  } else {
    fprintf(fp,
"# Multi-line Tcl can also be written as a code block:\n"
"# code = \"\"\"\n"
"# proc my_greeting {nick host hand chan} {\n"
"#   putserv \"PRIVMSG $chan :Welcome, $nick!\"\n"
"# }\n"
"# bind join - * my_greeting\n"
"# \"\"\"\n"
"\n");
  }

  fclose(fp);

  printf("\n"
         "╔══════════════════════════════════════════════╗\n"
         "║  Config written successfully!                ║\n"
         "╠══════════════════════════════════════════════╣\n"
         "║  Next steps:                                 ║\n"
         "║    1. Review the generated file.             ║\n"
         "║    2. Start the bot:  eggdrop <conf>         ║\n"
         "║       The bot creates its user file          ║\n"
         "║       automatically on first run.            ║\n"
         "╚══════════════════════════════════════════════╝\n");
  printf("\n  Config file: %s\n\n", outfile);

  return 0;
}
