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
#include <op_toml.h>
#include "script.h"
#include "modules.h"

extern char moddir[121]; /* defined in modules.c */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
static struct {
  char channel[64];
  char ownerkey[128];
  int ircx_create;
  char ircx_modes[32];
  int has_ircx;
} chanset_state;

static void run_tcl_cmd(const char *cmd);   /* forward decl */
static void set_tcl_var(const char *key, const char *value); /* forward decl */

static void reset_chanset_state(void)
{
  chanset_state.channel[0]     = '\0';
  chanset_state.ownerkey[0]    = '\0';
  chanset_state.ircx_create    = 0;
  chanset_state.ircx_modes[0]  = '\0';
  chanset_state.has_ircx       = 0;
}

/* Emit ircxautoowner for the current block if any IRCX keys were set. */
static void flush_chanset_ircx(void)
{
  if (!chanset_state.has_ircx || !chanset_state.channel[0])
    return;
  op_strbuf_t cmd = {};
  op_strbuf_init(&cmd);
  if (chanset_state.ircx_modes[0])
    op_strbuf_appendf(&cmd, "ircxautoowner %s \"%s\" %d \"%s\"",
                     chanset_state.channel, chanset_state.ownerkey,
                     chanset_state.ircx_create, chanset_state.ircx_modes);
  else
    op_strbuf_appendf(&cmd, "ircxautoowner %s \"%s\" %d",
                     chanset_state.channel, chanset_state.ownerkey, chanset_state.ircx_create);
  run_tcl_cmd(op_strbuf_str(&cmd));
  op_strbuf_free(&cmd);
  chanset_state.has_ircx = 0;
}

/* Tcl interpreter declared in tcl.c and extern'd via main.h. */
extern Tcl_Interp *interp;
extern char origbotname[], owner[];

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
  notcl_setvar(tclvar, value);
}

static void run_tcl_cmd(const char *cmd)
{
  if (interp) {
    egg_eval_log(cmd, cmd);
    return;
  }

  /* No-TCL: dispatch known channel commands natively via the channels module
   * function table.  All other commands are silently ignored (they require
   * Tcl scripting and cannot work without it).
   *
   * "channel add NAME"           — create a new channel (no extra options)
   * "channel add NAME OPTS"      — create channel with options string
   * "channel set NAME OP [VAL]"  — set one or more options on an existing channel
   */
  if (!strncmp(cmd, "channel add ", 12) ||
      !strncmp(cmd, "channel set ", 12)) {
    module_entry *me = module_find("channels", 0, 0);
    if (!me) {
      putlog(LOG_MISC, "*",
             "TOML config: channels module not loaded, cannot run: %s", cmd);
      return;
    }
    if (!strncmp(cmd, "channel add ", 12)) {
      /* Extract NAME and optional OPTS from "channel add NAME [OPTS]" */
      int (*chan_add)(Tcl_Interp *, char *, char *) =
        (int (*)(Tcl_Interp *, char *, char *)) me->funcs[37];
      char name[256], opts[1024];
      const char *p = cmd + 12;
      const char *space;

      while (*p == ' ') p++;
      space = strchr(p, ' ');
      if (space) {
        size_t nlen = space - p;
        if (nlen >= sizeof name) return;
        memcpy(name, p, nlen);
        name[nlen] = '\0';
        p = space + 1;
        while (*p == ' ') p++;
        op_strlcpy(opts, p, sizeof opts);
      } else {
        op_strlcpy(name, p, sizeof name);
        opts[0] = '\0';
      }
      if (chan_add)
        chan_add(nullptr, name, opts);
    } else {
      /* "channel set NAME OP [VAL]" */
      int (*chan_mod)(Tcl_Interp *, struct chanset_t *, int, char **) =
        (int (*)(Tcl_Interp *, struct chanset_t *, int, char **)) me->funcs[38];
      const char *p = cmd + 12;
      const char *space;
      char name[256];

      while (*p == ' ') p++;
      space = strchr(p, ' ');
      if (!space || !chan_mod)
        return;
      {
        size_t nlen = space - p;
        struct chanset_t *chan;
        char **item;
        int items, i;

        if (nlen >= sizeof name) return;
        memcpy(name, p, nlen);
        name[nlen] = '\0';
        p = space + 1;
        while (*p == ' ') p++;
        if (!*p) return;

        chan = findchan_by_dname(name);
        if (!chan) return;

        /* Tokenise remaining args the same way egg_split_list does. */
        items = 0;
        {
          const char *q = p;
          while (*q) {
            while (*q == ' ' || *q == '\t') q++;
            if (!*q) break;
            if (*q == '{') { while (*q && *q != '}') q++; if (*q) q++; }
            else           { while (*q && *q != ' ' && *q != '\t') q++; }
            items++;
          }
        }
        if (!items) return;
        item = op_malloc(items * sizeof(char *));
        {
          const char *q = p;
          int j = 0;
          while (*q && j < items) {
            int len;
            const char *start;
            while (*q == ' ' || *q == '\t') q++;
            if (*q == '{') {
              q++;
              start = q;
              while (*q && *q != '}') q++;
              len = q - start;
              if (*q) q++;
            } else {
              start = q;
              while (*q && *q != ' ' && *q != '\t') q++;
              len = q - start;
            }
            item[j] = op_malloc(len + 1);
            memcpy(item[j], start, len);
            item[j][len] = '\0';
            j++;
          }
        }
        chan_mod(nullptr, chan, items, item);
        for (i = 0; i < items; i++)
          op_free(item[i]);
        op_free(item);
      }
    }
  }
  /* "server add HOST [PORT [PASS]]" */
  if (!strncmp(cmd, "server add ", 11)) {
    module_entry *me = module_find("server", 0, 0);
    if (!me) {
      putlog(LOG_MISC, "*",
             "TOML config: server module not loaded, cannot run: %s", cmd);
      return;
    }
    {
      void (*srv_add)(const char *) =
        (void (*)(const char *)) me->funcs[55];
      /* Rebuild "HOST:PORT:PASS" from "server add HOST [PORT [PASS]]" */
      const char *p = cmd + 11;
      char host[256], port[16], pass[128];
      host[0] = port[0] = pass[0] = '\0';
      while (*p == ' ') p++;
      {
        const char *sp = strchr(p, ' ');
        if (sp) {
          size_t hlen = sp - p;
          if (hlen >= sizeof host) return;
          memcpy(host, p, hlen);
          host[hlen] = '\0';
          p = sp + 1;
          while (*p == ' ') p++;
          sp = strchr(p, ' ');
          if (sp) {
            size_t plen = sp - p;
            if (plen >= sizeof port) plen = sizeof port - 1;
            memcpy(port, p, plen);
            port[plen] = '\0';
            p = sp + 1;
            while (*p == ' ') p++;
            op_strlcpy(pass, p, sizeof pass);
          } else {
            op_strlcpy(port, p, sizeof port);
          }
        } else {
          op_strlcpy(host, p, sizeof host);
        }
      }
      {
        op_strbuf_t es = {};
        op_strbuf_init(&es);
        if (pass[0])
          op_strbuf_appendf(&es, "%s:%s:%s", host, port, pass);
        else if (port[0])
          op_strbuf_appendf(&es, "%s:%s", host, port);
        else
          op_strbuf_append_cstr(&es, host);
        if (srv_add)
          srv_add(op_strbuf_str(&es));
        op_strbuf_free(&es);
      }
    }
    return;
  }
  /* All other commands require Tcl and are silently skipped in no-TCL builds. */
}

typedef void (*ArrayCb)(const char *item, void *ud);

/* -----------------------------------------------------------------------
 * Array callbacks for special sections
 * --------------------------------------------------------------------- */

/* TOML parsing state counters */
static struct {
  int server_count;    /* Count of servers added during the current readtomlconfig() call */
  int module_count;    /* Count of modules loaded during the current readtomlconfig() call */
} toml_parse_state;

static void cb_loadmodule(const char *name, [[maybe_unused]] void *ud)
{
  if (interp) {
    op_strbuf_t cmd = {};
    op_strbuf_init(&cmd);
    op_strbuf_appendf(&cmd, "loadmodule %s", name);
    run_tcl_cmd(op_strbuf_str(&cmd));
    op_strbuf_free(&cmd);
  } else {
    const char *err = module_load((char *) name);
    if (err && strcmp(err, "Already loaded."))
      putlog(LOG_MISC, "*", "TOML config: loadmodule %s: %s", name, err);
  }
  toml_parse_state.module_count++;
}

/*
 * server list entry format (chosen to stay close to the `server add` syntax):
 *   "host"                  → server add host
 *   "host:port"             → server add host port
 *   "host:+port"            → server add host +port   (SSL)
 *   "host:+port:password"   → server add host +port password
 */
static void cb_server_add(const char *entry, [[maybe_unused]] void *ud)
{
  char host[256] = {}, portpart[68] = {}, pass[128] = {};

  op_strlcpy(host, entry, sizeof host);

  char *colon = strchr(host, ':');
  if (colon) {
    *colon = '\0';
    const char *rest = colon + 1;     /* "+port" or "port" or "+port:pass" */
    /* Preserve SSL '+' prefix as part of portpart (e.g. "+6697"). */
    const char *colon2 = strchr(rest, ':');
    if (colon2) {
      /* Has password — copy "+port" or "port" verbatim, then grab pass. */
      size_t plen = (size_t)(colon2 - rest);
      if (plen >= sizeof portpart) plen = sizeof portpart - 1;
      memcpy(portpart, rest, plen);
      portpart[plen] = '\0';
      op_strlcpy(pass, colon2 + 1, sizeof pass);
    } else {
      op_strlcpy(portpart, rest, sizeof portpart);
    }
  }

  {
    op_strbuf_t cmd = {};
    op_strbuf_init(&cmd);
    if (pass[0])
      op_strbuf_appendf(&cmd, "server add %s %s %s", host, portpart, pass);
    else if (portpart[0])
      op_strbuf_appendf(&cmd, "server add %s %s", host, portpart);
    else
      op_strbuf_appendf(&cmd, "server add %s", host);
    run_tcl_cmd(op_strbuf_str(&cmd));
    op_strbuf_free(&cmd);
  }
  toml_parse_state.server_count++;
}

static void cb_channel_add(const char *name, [[maybe_unused]] void *ud)
{
  op_strbuf_t cmd = {};
  op_strbuf_init(&cmd);
  op_strbuf_appendf(&cmd, "channel add %s", name);
  run_tcl_cmd(op_strbuf_str(&cmd));
  op_strbuf_free(&cmd);
}

/*
 * Logging entry format: "flags channel logfile"
 * e.g. "mco * eggdrop.log"
 */
static void cb_logfile(const char *entry, [[maybe_unused]] void *ud)
{
  op_strbuf_t cmd = {};
  op_strbuf_init(&cmd);
  op_strbuf_appendf(&cmd, "logfile %s", entry);
  run_tcl_cmd(op_strbuf_str(&cmd));
  op_strbuf_free(&cmd);
}

static void cb_source(const char *path, [[maybe_unused]] void *ud)
{
  /* Route .py files to the script engine (Python) regardless of Tcl. */
  const char *ext = strrchr(path, '.');
  if (ext && !op_strcasecmp(ext, ".py")) {
    script_load(path);
    return;
  }
  if (interp) {
    op_strbuf_t cmd = {};
    op_strbuf_init(&cmd);
    op_strbuf_appendf(&cmd, "source %s", path);
    run_tcl_cmd(op_strbuf_str(&cmd));
    op_strbuf_free(&cmd);
  } else {
    script_load(path);
  }
}

static void cb_loadhelp(const char *file, [[maybe_unused]] void *ud)
{
  op_strbuf_t cmd = {};
  op_strbuf_init(&cmd);
  op_strbuf_appendf(&cmd, "loadhelp %s", file);
  run_tcl_cmd(op_strbuf_str(&cmd));
  op_strbuf_free(&cmd);
}

/* Used by [tcl] commands = [...] — each entry is a raw Tcl command. */
static void cb_tcl_eval(const char *cmd, [[maybe_unused]] void *ud)
{
  run_tcl_cmd(cmd);
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
    nullptr
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
    case SEC_BOT:
      /* In no-TCL builds the "nick" variable is not registered in any
       * notcl table (it's managed by a Tcl trace in server.mod at runtime),
       * so we must write origbotname directly here. */
      if (strcmp(key, "nick") == 0) {
        op_strlcpy(origbotname, value, NICKLEN);
        set_tcl_var(key, value);
        return;
      }
      break;

    case SEC_PATHS:
      /* lang_dir overrides where language files are searched.  Apply it
       * immediately so that any subsequent add_lang_section() calls (from
       * module loads) use the new path. */
      if (strcmp(key, "lang_dir") == 0) {
        set_lang_dir(value);
        return;
      }
      break;

    case SEC_TCL:
      /* [tcl] code = """..."""  — evaluate a multi-line Tcl script block. */
      if (strcmp(key, "code") == 0) {
        run_tcl_cmd(value);
        return;
      }
      break;

    case SEC_CHANSET:
      /* channel = "#name" — identifies which channel this block configures. */
      if (strcmp(key, "channel") == 0) {
        op_strlcpy(chanset_state.channel, value, sizeof chanset_state.channel);
        return;
      }
      if (!chanset_state.channel[0])
        return; /* channel key must appear before other settings */

      /* IRCX / Ophion settings — accumulated and emitted as ircxautoowner. */
      if (strcmp(key, "ownerkey") == 0 || strcmp(key, "ircx_ownerkey") == 0) {
        op_strlcpy(chanset_state.ownerkey, value, sizeof chanset_state.ownerkey);
        chanset_state.has_ircx = 1;
        return;
      }
      if (strcmp(key, "ircx_create") == 0) {
        chanset_state.ircx_create = egg_atoi(value);
        chanset_state.has_ircx = 1;
        return;
      }
      if (strcmp(key, "ircx_create_modes") == 0) {
        op_strlcpy(chanset_state.ircx_modes, value, sizeof chanset_state.ircx_modes);
        chanset_state.has_ircx = 1;
        return;
      }

      /* Remaining keys: either a boolean flag or a valued option.
       * Boolean flags use +/- prefix with no value argument.
       * Valued options use "channel set #chan option-name value". */
      {
        char tclkey[64];
        key_to_tclvar(key, tclkey, sizeof tclkey);
        op_strbuf_t cmd = {};
        op_strbuf_init(&cmd);
        if (is_chan_flag(tclkey))
          op_strbuf_appendf(&cmd, "channel set %s %s%s",
                           chanset_state.channel,
                           (strcmp(value, "0") == 0) ? "-" : "+",
                           tclkey);
        else
          op_strbuf_appendf(&cmd, "channel set %s %s %s",
                           chanset_state.channel, tclkey, value);
        run_tcl_cmd(op_strbuf_str(&cmd));
        op_strbuf_free(&cmd);
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

/* prescan_paths: pre-scan [paths] for settings needed before the main parse.
 *
 *   lang_dir  — must be set before init_language(1).
 *   mod_path  — must be set before [modules] are loaded.
 *
 * Uses op_toml for proper parsing (handles quoted strings, multi-line, etc).
 */
void prescan_paths(const char *fname)
{
  char errbuf[256];
  op_toml_table_t *root = op_toml_parse_file(fname, errbuf, sizeof errbuf);
  if (!root)
    return;

  op_toml_table_t *paths = op_toml_table(root, "paths");
  if (paths) {
    const char *val;
    if (op_toml_str(paths, "lang_dir", &val) == 1)
      set_lang_dir(val);
    if (op_toml_str(paths, "mod_path", &val) == 1 && *val) {
      op_strlcpy(moddir, val, sizeof moddir);
      size_t n = strlen(moddir);
      if (n && moddir[n - 1] != '/' && n + 1 < sizeof moddir) {
        moddir[n]     = '/';
        moddir[n + 1] = '\0';
      }
    }
  }
  op_toml_free(root);
}

void prescan_runtime(const char *fname, int *nthreads_out, int *io_shards_out)
{
  char errbuf[256];
  op_toml_table_t *root = op_toml_parse_file(fname, errbuf, sizeof errbuf);
  if (!root)
    return;

  static const char * const sections[] = {
    "performance", "runtime", "bot", nullptr
  };

  for (const char * const *name = sections; *name; name++) {
    op_toml_table_t *tbl = op_toml_table(root, *name);
    if (!tbl)
      continue;

    long val;
    if (nthreads_out && op_toml_int(tbl, "nthreads", &val) == 1 &&
        val >= 0 && val <= 1024)
      *nthreads_out = (int)val;
    if (io_shards_out && op_toml_int(tbl, "io_shards", &val) == 1 &&
        val >= 0 && val <= 1024)
      *io_shards_out = (int)val;
  }

  op_toml_free(root);
}

/* -----------------------------------------------------------------------
 * op_toml walk helpers
 * --------------------------------------------------------------------- */

/* Buffer for [paths] entries so they can be replayed after all modules load. */
constexpr int PATHS_BUF_MAX = 32;
typedef struct { char key[256]; char val[4096]; } PathsEntry;

/* Context for the op_toml_iter walk callback. */
struct walk_ctx {
  TomlSection sec;
  const op_toml_table_t *tbl;
  PathsEntry *paths_buf;
  int        *paths_buf_n;
};

/* op_toml_iter callback: dispatch each key in a section table. */
static void walk_key_cb(const char *key, void *ud)
{
  struct walk_ctx *ctx = ud;

  /* Array keys: dispatch through the matching callback. */
  op_toml_arr_t *arr = op_toml_arr(ctx->tbl, key);
  if (arr) {
    ArrayCb cb = nullptr;
    if (ctx->sec == SEC_MODULES  && strcmp(key, "load") == 0)     cb = cb_loadmodule;
    if (ctx->sec == SEC_SERVERS  && strcmp(key, "list") == 0)     cb = cb_server_add;
    if (ctx->sec == SEC_CHANNELS && strcmp(key, "list") == 0)     cb = cb_channel_add;
    if (ctx->sec == SEC_LOGGING  && strcmp(key, "entries") == 0)  cb = cb_logfile;
    if (ctx->sec == SEC_SCRIPTS  && strcmp(key, "load") == 0)     cb = cb_source;
    if (ctx->sec == SEC_HELP     && strcmp(key, "load") == 0)     cb = cb_loadhelp;
    if (ctx->sec == SEC_TCL      && strcmp(key, "commands") == 0) cb = cb_tcl_eval;
    if (cb) {
      for (int i = 0; i < op_toml_arr_len(arr); i++) {
        const char *s;
        if (op_toml_arr_str(arr, i, &s) == 1)
          cb(s, nullptr);
      }
    }
    return;
  }

  /* Sub-table keys: skip (walked as separate sections). */
  if (op_toml_table(ctx->tbl, key))
    return;

  /* Scalar: resolve to a string value for process_kv. */
  const char *sval;
  long ival;
  int bval;
  op_strbuf_t _b = {};
  op_strbuf_init(&_b);
  const char *val = nullptr;

  if (op_toml_str(ctx->tbl, key, &sval) == 1)
    val = sval;
  else if (op_toml_int(ctx->tbl, key, &ival) == 1) {
    op_strbuf_appendf(&_b, "%ld", ival);
    val = op_strbuf_str(&_b);
  } else if (op_toml_bool(ctx->tbl, key, &bval) == 1)
    val = bval ? "1" : "0";

  if (!val) {
    op_strbuf_free(&_b);
    return;
  }

  /* Buffer [paths] entries for replay after modules load. */
  if (ctx->paths_buf && *ctx->paths_buf_n < PATHS_BUF_MAX) {
    op_strlcpy(ctx->paths_buf[*ctx->paths_buf_n].key, key,
            sizeof ctx->paths_buf[*ctx->paths_buf_n].key);
    op_strlcpy(ctx->paths_buf[*ctx->paths_buf_n].val, val,
            sizeof ctx->paths_buf[*ctx->paths_buf_n].val);
    (*ctx->paths_buf_n)++;
  }

  process_kv(ctx->sec, key, val);
  op_strbuf_free(&_b);
}

/* Walk a section table: iterate all keys in file order. */
static void walk_section(TomlSection sec, const op_toml_table_t *tbl,
                          PathsEntry *pbuf, int *pn)
{
  struct walk_ctx ctx = { .sec = sec, .tbl = tbl,
                          .paths_buf = pbuf, .paths_buf_n = pn };
  op_toml_iter(tbl, walk_key_cb, &ctx);
}

/* Known section names (checked to identify "unknown" sections). */
static int is_known_section(const char *name)
{
  static const char *known[] = {
    "bot", "network", "security", "paths", "modules",
    "servers", "channels", "logging", "scripts", "help", "tcl",
    "chanset", "performance", "runtime", nullptr
  };
  for (const char **k = known; *k; k++)
    if (strcmp(name, *k) == 0) return 1;
  return 0;
}

/* op_toml_iter callback on root: walk any unknown (pass-through) sections. */
static void walk_unknown_cb(const char *key, void *ud)
{
  const op_toml_table_t *root = ud;
  if (is_known_section(key)) return;
  op_toml_table_t *t = op_toml_table(root, key);
  if (!t) return;
  walk_section(SEC_OTHER, t, nullptr, nullptr);
}

/* -----------------------------------------------------------------------
 * readtomlconfig — parse with op_toml, dispatch in dependency order
 * --------------------------------------------------------------------- */

int readtomlconfig(const char *fname)
{
  char errbuf[256];
  op_toml_table_t *root = op_toml_parse_file(fname, errbuf, sizeof errbuf);
  if (!root) {
    putlog(LOG_MISC, "*", "TOML config: %s", errbuf);
    return 0;
  }

  int ok = 1;
  PathsEntry paths_buf[PATHS_BUF_MAX];
  int paths_buf_n = 0;

  /* Walk sections in dependency order.  Modules must load before paths
   * replay and command-based sections (servers, channels, etc). */
  static const struct { const char *name; TomlSection sec; } order[] = {
    {"bot",      SEC_BOT},
    {"network",  SEC_NETWORK},
    {"security", SEC_SECURITY},
    {"modules",  SEC_MODULES},      /* loads modules → registers vars/commands */
    {"servers",  SEC_SERVERS},
    {"channels", SEC_CHANNELS},
    {"logging",  SEC_LOGGING},
    {"scripts",  SEC_SCRIPTS},
    {"help",     SEC_HELP},
    {"tcl",      SEC_TCL},
  };

  for (size_t i = 0; i < sizeof order / sizeof order[0]; i++) {
    op_toml_table_t *t = op_toml_table(root, order[i].name);
    if (t) walk_section(order[i].sec, t, nullptr, nullptr);
  }

  /* [paths] — buffer entries for replay after module vars are registered. */
  {
    op_toml_table_t *t = op_toml_table(root, "paths");
    if (t) walk_section(SEC_PATHS, t, paths_buf, &paths_buf_n);
  }

  /* [[chanset]] array of tables — per-channel settings. */
  {
    op_toml_arr_t *arr = op_toml_arr(root, "chanset");
    if (arr) {
      for (int i = 0; i < op_toml_arr_len(arr); i++) {
        op_toml_table_t *ct = op_toml_arr_table(arr, i);
        if (!ct) continue;
        reset_chanset_state();
        walk_section(SEC_CHANSET, ct, nullptr, nullptr);
        flush_chanset_ircx();
      }
    }
  }

  /* Unknown sections — set keys as Tcl variables (pass-through). */
  op_toml_iter(root, walk_unknown_cb, (void *)root);

  /* Replay [paths] now that all modules have loaded and registered
   * their variables (e.g. chanfile from channels.mod). */
  for (int i = 0; i < paths_buf_n; i++)
    process_kv(SEC_PATHS, paths_buf[i].key, paths_buf[i].val);

  /* ---- Validate required settings ---- */
  {
    char nick_buf[256], owner_buf[256];
    const char *nick_val  = notcl_getvar("nick", nick_buf, sizeof nick_buf);
    const char *owner_val = notcl_getvar("owner", owner_buf, sizeof owner_buf);

    if (!nick_val || !*nick_val) {
      putlog(LOG_MISC, "*",
             "ERROR: 'nick' is required in [bot] section of %s", fname);
      ok = 0;
    }
    if (!owner_val || !*owner_val) {
      putlog(LOG_MISC, "*",
             "ERROR: 'owner' is required in [security] section of %s", fname);
      ok = 0;
    }
    if (toml_parse_state.server_count == 0) {
      putlog(LOG_MISC, "*",
             "TOML config: no servers defined in [servers] list — "
             "the bot will not connect to IRC.");
      ok = 0;
    }
    toml_parse_state.server_count = 0;
    if (toml_parse_state.module_count == 0)
      putlog(LOG_MISC, "*",
             "WARNING: No modules configured in %s — bot may not function correctly",
             fname);
    toml_parse_state.module_count = 0;
  }

  if (ok)
    putlog(LOG_MISC, "*", "Config loaded: %s", fname);

  op_toml_free(root);
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
    op_strlcpy(buf, def ? def : "", buflen);
    printf("\n");
    return;
  }

  /* Strip trailing newline. */
  buf[strcspn(buf, "\r\n")] = '\0';

  /* Fall back to default on empty input. */
  if (!*buf && def)
    op_strlcpy(buf, def, buflen);
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
 * Numbered-menu prompt.  options[] must be nullptr-terminated.
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
    i = egg_atoi(buf) - 1;
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
  /* DNS-over-TLS */
  int  want_dot;
  char dot_server[64];
  /* Channels */
  char channels[8][64];
  int  nchan;
  /* Files */
  char userfile[64], chanfile[64], logfile[128];
  /* Listen ports */
  int  listen_port, botnet_port;
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
    nullptr
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
    nullptr
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
  step_header(1, 6, "Bot identity");
  prompt_required("Bot nick (no spaces)", nick, sizeof nick);

  /* Smart defaults derived from nick */
  {
    op_strbuf_t _t = {};
    op_strbuf_init(&_t);
    op_strbuf_appendf(&_t, "%s?", nick);
    prompt("Alternate nick (? replaced by a random digit)", op_strbuf_str(&_t),
           altnick, sizeof altnick);
    op_strbuf_free(&_t);
  }
  {
    op_strbuf_t _t = {};
    op_strbuf_init(&_t);
    op_strbuf_appendf(&_t, "/msg %s help", nick);
    prompt("Real name (IRC GECOS)", op_strbuf_str(&_t), realname, sizeof realname);
    op_strbuf_free(&_t);
  }

  /* Lowercase nick as default IRC username */
  op_strlcpy(tmp, nick, sizeof tmp);
  for (i = 0; tmp[i]; i++)
    tmp[i] = (char)tolower((unsigned char)tmp[i]);
  prompt("IRC username (ident)", tmp, username, sizeof username);

  prompt("Admin contact", "Admin <admin@example.com>", admin, sizeof admin);
  prompt_required("Bot owner handle (your IRC nick)", owner, sizeof owner);

  /* ── Step 2/5: IRC server ───────────────────────────── */
  step_header(2, 6, "IRC server");

  printf("  Network:\n");
  net_idx      = prompt_menu("Choose network", net_labels, 0);
  net_type_str = net_type_map[net_idx];
  want_ircx    = (net_idx == 7); /* "Ophion (IRCX)" is index 7 */

  /* Use short network name for [bot] network = ... */
  if (net_idx < 8)
    op_strlcpy(network, net_labels[net_idx], sizeof network);
  else
    prompt("Network name (display only)", "MyNetwork", network, sizeof network);

  prompt("IRC server hostname", net_defaults[net_idx], server, sizeof server);
  use_ssl = prompt_yn("Use SSL/TLS?", 1);

  prompt("Port", int_to_base10(use_ssl ? 6697 : 6667), port_buf, sizeof port_buf);
  port = egg_atoi(port_buf);
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

  /* DNS-over-TLS — offered when SSL is enabled */
  want_dot = 0;
  dot_server[0] = '\0';
  if (use_ssl) {
    printf("\n  ┌─ DNS-over-TLS (DoT, RFC 7858) — optional\n");
    printf("  │  Routes DNS queries over an encrypted TLS connection.\n");
    printf("  │  Recommended: 1.1.1.1 (Cloudflare — fast, privacy-respecting)\n");
    printf("  │  Alternative: 9.9.9.9 (Quad9 — malware-blocking + privacy)\n");
    want_dot = prompt_yn("  Enable DNS-over-TLS?", 0);
    if (want_dot)
      prompt("  │  DoT server IP (numeric)", "1.1.1.1",
             dot_server, sizeof dot_server);
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
  step_header(3, 6, "Channels");
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

    op_strlcpy(channels[nchan], cbuf, sizeof channels[0]);
    if (++nchan >= 8)
      break;
  }

  /* ── Step 4/6: Files ────────────────────────────────── */
  step_header(4, 6, "Files");

  /* Defaults derived from nick */
  {
    op_strbuf_t _b = {};
    op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "%s.user", nick);
    prompt("User file", op_strbuf_str(&_b), userfile, sizeof userfile);
    op_strbuf_clear(&_b);
    op_strbuf_appendf(&_b, "%s.chan", nick);
    prompt("Chan file", op_strbuf_str(&_b), chanfile, sizeof chanfile);
    op_strbuf_clear(&_b);
    op_strbuf_appendf(&_b, "%s.log", nick);
    prompt("Log file", op_strbuf_str(&_b), logfile, sizeof logfile);
    op_strbuf_free(&_b);
  }

  /* ── Step 5/6: Listen ports ──────────────────────────── */
  step_header(5, 6, "Listen ports");
  printf("  Eggdrop needs a TCP port to accept DCC chat and telnet\n"
         "  connections, and a separate port for botnet links.\n"
         "  Enter 0 to disable a port.\n\n");

  prompt("DCC / telnet port (for users connecting to the bot)", "3333",
         tmp, sizeof tmp);
  listen_port = egg_atoi(tmp);
  if (listen_port < 0 || listen_port > 65535)
    listen_port = 3333;

  prompt("Botnet port (for linking with other Eggdrop bots, 0 = none)", "0",
         tmp, sizeof tmp);
  botnet_port = egg_atoi(tmp);
  if (botnet_port < 0 || botnet_port > 65535)
    botnet_port = 0;

  /* ── Step 6/6: Optional modules ─────────────────────── */
  step_header(6, 6, "Optional modules");
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
  printf("  Server     : %s%s:%d%s\n",
         use_ssl ? "SSL " : "", server, port,
         want_sasl ? " + SASL" : "");
  printf("  Network    : %s  (%s%s)\n",   network, net_type_str,
         want_ircx ? ", IRCX/Ophion" : "");
  printf("  Channels   :");
  for (i = 0; i < nchan; i++)
    printf(" %s", channels[i]);
  printf("\n");
  printf("  User file  : %s\n",           userfile);
  printf("  Chan file  : %s\n",           chanfile);
  printf("  Log file   : %s\n",           logfile);
  if (listen_port > 0)
    printf("  DCC port   : %d\n",         listen_port);
  if (botnet_port > 0)
    printf("  Botnet port: %d\n",         botnet_port);
  printf("  Config     : %s\n\n",         outfile);

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

  /* ── [modules] ─────────────────────────────────────────────────────────── */
  fprintf(fp,
"[modules]\n"
"load = [\n"
"  \"pbkdf2\",    # Generation-2 userfile encryption (recommended)\n"
"  \"blowfish\",  # Legacy userfile encryption support\n"
"  \"channels\",  # Channel tracking\n"
"  \"server\",    # Core IRC server support\n"
"  \"ctcp\",      # CTCP reply handling\n"
"  \"irc\",       # Basic IRC functionality\n"
"  \"dns\",       # Async DNS resolver\n"
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
  fprintf(fp,
"  # \"share\",     # Userfile sharing between botnet links\n"
"  # \"compress\",  # Compress shared userfiles (requires zlib)\n"
"  # \"ident\",     # Built-in ident server\n"
"]\n\n");

  /* ── [bot] ──────────────────────────────────────────────────────────────── */
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

  /* ── [servers] ──────────────────────────────────────────────────────────── */
  fprintf(fp,
"[servers]\n"
"# \"host:port\" plain  |  \"host:+port\" SSL  |  \"host:+port:password\"\n"
"list = [\n");
  if (*server_pass)
    fprintf(fp, "  \"%s:%s%d:%s\",\n",
            server, use_ssl ? "+" : "", port, server_pass);
  else
    fprintf(fp, "  \"%s:%s%d\",\n",
            server, use_ssl ? "+" : "", port);
  fprintf(fp, "]\n\n");

  /* ── [channels] ─────────────────────────────────────────────────────────── */
  fprintf(fp, "[channels]\nlist = [");
  for (i = 0; i < nchan; i++)
    fprintf(fp, "%s\"%s\"", i ? ", " : "", channels[i]);
  fprintf(fp, "]\n\n"
"# Channel defaults — applied to every channel.\n"
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

  /* ── [[chanset]] ────────────────────────────────────────────────────────── */
  if (want_ircx && nchan > 0) {
    for (i = 0; i < nchan; i++) {
      fprintf(fp,
"[[chanset]]\n"
"channel     = \"%s\"\n",
              channels[i]);
      if (*ircx_ownerkey)
        fprintf(fp, "ownerkey    = \"%s\"\n", ircx_ownerkey);
      else
        fprintf(fp, "# ownerkey  = \"\"  # OWNERKEY for +q on join\n");
      if (ircx_want_autoowner)
        fprintf(fp,
"ircx_create = true\n"
"# ircx_create_modes = \"+nts\"\n");
      fprintf(fp, "\n");
    }
  } else if (nchan > 0) {
    fprintf(fp,
"# Per-channel overrides — one [[chanset]] block per channel.\n"
"# [[chanset]]\n"
"# channel   = \"%s\"\n"
"# chanmode  = \"+nts\"\n"
"# cycle     = false\n"
"# idle_kick = 0\n"
"\n",
            channels[0]);
  }

  /* ── [paths] ────────────────────────────────────────────────────────────── */
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
"# lang_dir    = \"\"  # override language file directory (useful for non-default installs)\n"
"\n", userfile, chanfile);

  /* ── [logging] ──────────────────────────────────────────────────────────── */
  fprintf(fp,
"[logging]\n"
"# Flags: m=messages o=commands c=channel b=bots j=joins s=server k=kicks\n"
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

  /* ── [irc] ──────────────────────────────────────────────────────────────── */
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
"# init_server   = \"\"  # raw commands sent after registration\n"
"# connect_server = \"\" # raw commands sent before registration\n"
"\n", net_type_str);

  /* ── [network] ──────────────────────────────────────────────────────────── */
  fprintf(fp,
"[network]\n"
"default_port    = %d\n"
"connect_timeout = 15\n"
"prefer_ipv6     = 0\n"
"# vhost4 = \"\"  # bind outgoing/listening to this IPv4 address\n"
"# vhost6 = \"\"  # bind outgoing/listening to this IPv6 address\n"
"# nat_ip = \"\"  # external IP if behind NAT\n"
"# listen_addr = \"\"         # address for DCC/telnet listeners\n"
"# reserved_portrange = \"\"  # e.g. \"2010:2020\" for DCC port range\n"
"\n", use_ssl ? 6697 : 6667);

  /* ── [security] ─────────────────────────────────────────────────────────── */
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

  /* ── [behaviour] ────────────────────────────────────────────────────────── */
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

  /* ── [sasl] — only when user enabled SASL ──────────────────────────────── */
  if (want_sasl) {
    fprintf(fp,
"[sasl]\n"
"sasl           = 1\n"
"sasl_mechanism = %d\n"
"sasl_username  = \"%s\"\n",
            sasl_mech_val, sasl_user);
    if (*sasl_pass)
      fprintf(fp, "sasl_password  = \"%s\"\n", sasl_pass);
    fprintf(fp,
"sasl_continue  = 1\n"
"sasl_timeout   = 15\n"
"\n");
  }

  /* ── [ctcp] ─────────────────────────────────────────────────────────────── */
  fprintf(fp,
"[ctcp]\n"
"# Override CTCP replies — leave commented to use the built-in version string.\n"
"# ctcp_version  = \"Eggdrop (Linux)\"\n"
"# ctcp_finger   = \"Eggdrop (Linux)\"\n"
"# ctcp_userinfo = \"Eggdrop (Linux)\"\n"
"\n");

  /* ── [ircx] — only when user chose Ophion ─────────────────────────────── */
  if (want_ircx) {
    fprintf(fp,
"[ircx]\n"
"ircx_auto_negotiate = 1\n");
    if (*ircx_ownerkey)
      fprintf(fp, "ircx_ownerkey = \"%s\"\n", ircx_ownerkey);
    else
      fprintf(fp, "# ircx_ownerkey = \"\"  # global OWNERKEY (grants +q on join)\n");
    fprintf(fp, "\n");
  }

  /* ── [share] ────────────────────────────────────────────────────────────── */
  fprintf(fp,
"[share]\n"
"# Userfile sharing with linked bots (requires share.mod).\n"
"allow_resync   = 0\n"
"resync_time    = 900\n"
"private_global = 0\n"
"private_user   = 0\n"
"override_bots  = 0\n"
"# private_globals = \"\"  # space-separated flags to keep local\n"
"\n");

  /* ── [dns] ──────────────────────────────────────────────────────────────── */
  fprintf(fp,
"[dns]\n"
"dns_maxsends   = 4\n"
"dns_retrydelay = 3\n"
"dns_cache      = 86400\n"
"dns_negcache   = 600\n"
"# dns_servers  = \"\"  # space-separated IPs; empty = use /etc/resolv.conf\n"
"#\n"
"# DNS-over-TLS (DoT) — enable in the [tcl] commands block below.\n"
"# Requires TLS support in the build.  Recommended: 1.1.1.1 (Cloudflare).\n"
"#   dnsdot on 1.1.1.1        # Cloudflare — fast, privacy-respecting\n"
"#   dnsdot on 9.9.9.9        # Quad9 — malware-blocking, privacy-focused\n"
"#   dnsdot on 8.8.8.8        # Google\n"
"#   dnsdot off               # revert to plain UDP\n"
"\n");

  /* ── [notes] — only when user wants notes ──────────────────────────────── */
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

  /* ── [transfer] — only when user wants transfer ────────────────────────── */
  if (want_transfer) {
    fprintf(fp,
"[transfer]\n"
"max_dloads       = 3\n"
"dcc_block        = 0\n"
"xfer_timeout     = 30\n"
"sharefail_unlink = 0\n"
"\n");
  }

  /* ── [filesys] — only when user wants filesys ──────────────────────────── */
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

  /* ── [console] ──────────────────────────────────────────────────────────── */
  fprintf(fp,
"[console]\n"
"console          = \"mkcoblxs\"\n"
"console_autosave = 1\n"
"force_channel    = 0\n"
"info_party       = 0\n"
"\n");

  /* ── [crypto] ───────────────────────────────────────────────────────────── */
  fprintf(fp,
"[crypto]\n"
"pbkdf2_re_encode  = 1\n"
"blowfish_use_mode = \"cbc\"\n"
"# pbkdf2_method  = \"SHA256\"\n"
"# pbkdf2_rounds  = 16000\n"
"# compress_level = 9\n"
"\n");

  /* ── [tcl] ──────────────────────────────────────────────────────────────── */
  fprintf(fp,
"[tcl]\n"
"# Tcl commands run after the config is loaded.  Requires a Tcl-enabled build;\n"
"# this section is silently ignored in no-Tcl builds.\n"
"commands = [\n"
"  # Disable the 'simul' partyline command (security best practice).\n"
"  \"unbind dcc n simul *dcc:simul\",\n");
  if (want_dot && *dot_server)
    fprintf(fp,
"  # DNS-over-TLS: route all DNS queries over TLS to %s (port 853).\n"
"  # Use -noverify if you have a self-signed resolver cert.\n"
"  \"dnsdot on %s\",\n", dot_server, dot_server);
  else
    fprintf(fp,
"  # DNS-over-TLS (DoT): uncomment to route DNS over TLS to Cloudflare.\n"
"  # Other options: 9.9.9.9 (Quad9/privacy), 8.8.8.8 (Google)\n"
"  # \"dnsdot on 1.1.1.1\",\n");
  if (listen_port > 0)
    fprintf(fp,
"  # Open DCC/telnet port for users (DCC chat, .tcl console, etc.).\n"
"  \"listen %d users\",\n", listen_port);
  if (botnet_port > 0)
    fprintf(fp,
"  # Open botnet port for linking with other Eggdrop bots.\n"
"  \"listen %d bots\",\n", botnet_port);
  fprintf(fp,
"]\n"
"\n");

  /* Example code block — commented out by default. */
  fprintf(fp,
"# code = \"\"\"\n"
"# proc my_greeting {nick host hand chan} {\n"
"#   putserv \"PRIVMSG $chan :Welcome to $chan, $nick!\"\n"
"# }\n"
"# bind join - * my_greeting\n"
"# \"\"\"\n"
"\n");

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
