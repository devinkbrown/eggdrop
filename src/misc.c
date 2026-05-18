/*
 * misc.c -- handles:
 *   split() maskhost() dumplots() daysago() days() daysdur()
 *   logging things
 *   queueing output for the bot (msg and help)
 *   resync buffers for sharebots
 *   help system
 *   motd display and %var substitution
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
#include "async_log.h"
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include "chan.h"
#include "tandem.h"
#include "modules.h"
#include "egg_store.h"

#include <sys/utsname.h>

#include "stat.h"

extern struct dcc_t *dcc;
extern struct chanset_t *chanset;

extern char helpdir[], version[], origbotname[], botname[], admin[], network[],
            motdfile[], ver[], botnetnick[], bannerfile[], textdir[];
extern int  backgrd, con_chan, term_z, use_stderr, dcc_total, keep_all_logs;

extern time_t now;
extern Tcl_Interp *interp;

char logfile_suffix[21] = ".%d%b%Y";    /* Format of logfile suffix */
char log_ts[33] = "[%H:%M:%S]"; /* Timestamp format for logfile entries */

int shtime = 1;                 /* Display the time with console output */
log_t *logs = 0;                /* Logfiles */
int max_logs = 5;               /* Max log files, mismatch config on purpose */
int max_logsize = 0;            /* Maximum logfile size, 0 for no limit */
int raw_log = 0;                /* Display output to server to LOG_SERVEROUT */
int conmask = LOG_MODES | LOG_CMDS | LOG_MISC; /* Console mask */
int show_uname = 1;

typedef struct {
  char *name;
  int type;
} help_item_t;

typedef struct {
  char *name;
  op_vec_t items;
} help_ref_t;

static op_vec_t    help_refs;
static op_bh      *help_ref_bh  = nullptr;
static op_bh      *help_item_bh = nullptr;

/* ---- help topic index --------------------------------------------------- */
typedef struct {
  char *refname;  /* op_strdup of ref->name */
  int   type;     /* item->type: 0=msg/, 1=helpdir, 2=set/ */
} help_idx_entry_t;

static op_htab *help_idx_irc = nullptr;  /* IRC topics (type==0) */
static op_htab *help_idx_dcc = nullptr;  /* DCC topics (type!=0) */

static void help_idx_entry_free(void *key, void *val, void *ud)
{
  (void)key; (void)ud;
  help_idx_entry_t *e = (help_idx_entry_t *)val;
  op_free(e->refname);
  op_free(e);
}

static void help_idx_clear(void)
{
  if (help_idx_irc) { op_htab_destroy(help_idx_irc, help_idx_entry_free, nullptr); help_idx_irc = nullptr; }
  if (help_idx_dcc) { op_htab_destroy(help_idx_dcc, help_idx_entry_free, nullptr); help_idx_dcc = nullptr; }
}

static void help_idx_rebuild(void)
{
  help_idx_clear();
  for (size_t i = 0; i < help_refs.size; i++) {
    help_ref_t *ref = (help_ref_t *)op_vec_get(&help_refs, i);
    for (size_t j = 0; j < ref->items.size; j++) {
      help_item_t *item = (help_item_t *)op_vec_get(&ref->items, j);
      op_htab **idx = (item->type == 0) ? &help_idx_irc : &help_idx_dcc;
      if (!*idx)
        *idx = op_htab_create_str(item->type == 0 ? "help_idx_irc" : "help_idx_dcc", 64);
      if (!op_htab_get(*idx, item->name)) {
        help_idx_entry_t *e = (help_idx_entry_t *)op_malloc(sizeof *e);
        e->refname = op_strdup(ref->name);
        e->type    = item->type;
        op_htab_set(*idx, item->name, e, nullptr);
      }
    }
  }
}

/* ---- help file content cache -------------------------------------------- */
typedef struct {
  char  *path;   /* heap-alloc'd; also the htab key */
  char  *buf;    /* heap-alloc'd file content */
  size_t len;
} help_cache_t;

static op_htab *help_cache_ht = nullptr;

static void help_cache_entry_free(void *key, void *val, void *ud)
{
  (void)key; (void)ud;
  help_cache_t *e = (help_cache_t *)val;
  op_free(e->path);
  op_free(e->buf);
  op_free(e);
}

static void help_cache_clear(void)
{
  if (help_cache_ht) { op_htab_destroy(help_cache_ht, help_cache_entry_free, nullptr); help_cache_ht = nullptr; }
}

/* Open a help file, reading from the in-memory cache when possible.
 * Returns a FILE* the caller must fclose().  fclose() on an fmemopen
 * stream is cheap — it only releases stdio state, not the cached buffer. */
static FILE *help_fopen_cached(const char *path)
{
  if (help_cache_ht) {
    help_cache_t *e = (help_cache_t *)op_htab_get(help_cache_ht, path);
    if (e)
      return fmemopen(e->buf, e->len, "r");
  }
  FILE *f = fopen(path, "r");
  if (!f) return nullptr;
  char tmp[4096];
  op_strbuf_t sb = {};
  op_strbuf_init(&sb);
  while (fgets(tmp, sizeof tmp, f) != nullptr)
    op_strbuf_append_cstr(&sb, tmp);
  fclose(f);
  size_t len = op_strbuf_len(&sb);
  if (!len) { op_strbuf_free(&sb); return nullptr; }
  help_cache_t *e = (help_cache_t *)op_malloc(sizeof *e);
  e->len  = len;
  e->buf  = (char *)op_malloc(len + 1);
  memcpy(e->buf, op_strbuf_str(&sb), len);
  e->buf[len] = '\0';
  e->path = op_strdup(path);
  op_strbuf_free(&sb);
  if (!help_cache_ht)
    help_cache_ht = op_htab_create_str("help_cache", 16);
  op_htab_set(help_cache_ht, e->path, e, nullptr);
  return fmemopen(e->buf, e->len, "r");
}

/* Help system state */
static struct {
  int flags;
} help_state;


/* Expected memory usage
 */

void init_misc(void)
{
  static int last = 0;

  if (max_logs < 1)
    max_logs = 1;
  if (logs)
    logs = op_realloc(logs, max_logs * sizeof(log_t));
  else
    logs = op_malloc(max_logs * sizeof(log_t));
  for (; last < max_logs; last++) {
    logs[last].filename = logs[last].chname = nullptr;
    logs[last].mask = 0;
    logs[last].f = nullptr;
    /* Added by cybah  */
    logs[last].szlast[0] = 0;
    logs[last].repeats = 0;
    /* Added by rtc  */
    logs[last].flags = 0;
  }
}


/*
 *    Misc functions
 */

/* low-level stuff for other modules
 */
int is_file(const char *s)
{
  struct stat ss;
  int i = stat(s, &ss);

  if (i < 0)
    return 0;
  if ((ss.st_mode & S_IFREG) || (ss.st_mode & S_IFLNK))
    return 1;
  return 0;
}

/*  This implementation wont overrun dst - 'max' is the max bytes that dst
 *  can be, including the null terminator. So if 'dst' is a 128 byte buffer,
 *  pass 128 as 'max'. The function will _always_ null-terminate 'dst'.
 *
 *  Returns: The number of characters appended to 'dst'.
 *
 *  Usage example:
 *
 *    char buf[128];
 *    size_t bufsize = sizeof(buf);
 *
 *    buf[0] = 0, bufsize--;
 *
 *    while (blah && bufsize) {
 *      bufsize -= egg_strcatn(buf, <some-long-string>, sizeof(buf));
 *    }
 *
 *  <Cybah>
 */
int egg_strcatn(char *dst, const char *src, size_t max)
{
  size_t tmpmax = 0;

  /* find end of 'dst' */
  while (*dst && max > 0) {
    dst++;
    max--;
  }

  /*    Store 'max', so we can use it to workout how many characters were
   *  written later on.
   */
  tmpmax = max;

  /* copy up to, but not including the null terminator */
  while (*src && max > 1) {
    *dst++ = *src++;
    max--;
  }

  /* null-terminate the buffer */
  *dst = 0;

  /*    Don't include the terminating null in our count, as it will cumulate
   *  in loops - causing a headache for the caller.
   */
  return tmpmax - max;
}

int my_strcpy(char *a, const char *b)
{
  const char *c = b;

  while (*b)
    *a++ = *b++;
  *a = *b;
  return b - c;
}

/* Split first word off of rest and put it in first
 */
void splitc(char *first, char *rest, char divider)
{
  char *p = strchr(rest, divider);

  if (p == nullptr) {
    if (first != rest && first)
      first[0] = 0;
    return;
  }
  *p = 0;
  if (first != nullptr)
    strcpy(first, rest);
  if (first != rest)
    memmove(rest, p + 1, strlen(p + 1) + 1);
}

/*    As above, but lets you specify the 'max' number of bytes (EXCLUDING the
 * terminating null).
 *
 * Example of use:
 *
 * char buf[HANDLEN + 1];
 *
 * splitcn(buf, input, "@", HANDLEN);
 *
 * <Cybah>
 */
void splitcn(char *first, char *rest, char divider, size_t max)
{
  char *p = strchr(rest, divider);

  if (p == nullptr) {
    if (first != rest && first)
      first[0] = 0;
    return;
  }
  *p = 0;
  if (first != nullptr)
    op_strlcpy(first, rest, max);
  if (first != rest)
    memmove(rest, p + 1, strlen(p + 1) + 1);
}

char *splitnick(char **blah)
{
  char *p = strchr(*blah, '!'), *q = *blah;

  if (p) {
    *p = 0;
    *blah = p + 1;
    return q;
  }
  return "";
}

void remove_crlf(char **line)
{
  char *p = *line;
  const char *end = p + strlen(p);
  const char *crlf = op_simd_find_delim(p, end, '\r', '\n');
  if (crlf < end)
    *(char *)crlf = 0;
}

char *newsplit(char **rest)
{
  char *o, *r;

  if (!rest)
    return "";
  o = *rest;
  /* Skip leading spaces — SIMD-accelerated for long runs. */
  {
    const char *end = o + strlen(o);
    size_t spaces = op_simd_count_leading(o, end, ' ');
    o += spaces;
    /* Find the next space or end-of-string. */
    r = o;
    const char *delim = op_simd_find_delim(o, end, ' ', '\0');
    o = (char *)delim;
  }
  if (*o)
    *o++ = 0;
  *rest = o;
  return r;
}

/* maskhost(), modified to support custom mask types, as defined
 * by mIRC.
 * Does not require a proper hostmask in 's'. Accepts any strings,
 * including empty ones and attempts to provide meaningful results.
 *
 * Strings containing no '@' character will be parsed as if the
 * whole string is a host.
 * Strings containing no '!' character will be interpreted as if
 * there is no nick.
 * '!' as a nick/user separator must precede any '@' characters.
 * Otherwise it will be considered a part of the host.
 * Supported types are listed in tcl-commands.doc in the maskhost
 * command section. Type 3 resembles the older maskhost() most closely.
 *
 * Specific examples (with type=3):
 *
 * "nick!user@is.the.lamest.bg"  -> *!*user@*.the.lamest.bg (ccTLD)
 * "nick!user@is.the.lamest.com" -> *!*user@*.lamest.com (gTLD)
 * "lamest.example"              -> *!*@lamest.example
 * "whatever@lamest.example"     -> *!*whatever@lamest.example
 * "com.example@user!nick"       -> *!*com.example@user!nick
 * "!"                           -> *!*@!
 * "@"                           -> *!*@*
 * ""                            -> *!*@*
 * "abc!user@2001:db8:618:5c0:263:15:dead:babe"
 * -> *!*user@2001:db8:618:5c0:263:15:dead:*
 * "abc!user@0:0:0:0:0:ffff:1.2.3.4"
 * -> *!*user@0:0:0:0:0:ffff:1.2.3.*
 */
void maskaddr(const char *s, char *nw, int type)
{
  int d = type % 5, num = 1;
  const char *p, *u = 0, *h = 0, *ss;

  /* Look for user and host.. */
  ss = (char *)s;
  u = strchr(s, '!');
  if (u)
    h = strchr(u, '@');
  if (!h) {
    h = strchr(s, '@');
    u = 0;
  }

  /* Print nick if required and available */
  if (!u || (type % 10) < 5)
    *nw++ = '*';
  else {
    memcpy(nw, s, u - s);
    nw += u - s;
  }
  *nw++ = '!';

  /* Write user if required and available */
  u = (u ? u + 1 : ss);
  if (!h || (d == 2) || (d == 4))
    *nw++ = '*';
  else {
    if (d) {
      *nw++ = '*';
      if (strchr("~+-^=", *u))
        u++; /* trim leading crap */
    }
    memcpy(nw, u, h - u);
    nw += h - u;
  }
  *nw++ = '@';

  if (type >= 30) {
    op_strlcpy(nw, "*", UHOSTLEN);
    return;
  }

  /* The rest is for the host */
  h = (h ? h + 1 : ss);
  for (p = h; *p; p++) /* hostname? */
    if ((*p > '9' || *p < '0') && *p != '.') {
      num = 0;
      break;
    }
  p = strrchr(h, ':'); /* IPv6? */
  /* Mask out after the last colon/dot */
  if (p && d > 2) {
    if ((u = strrchr(p, '.')))
      p = u;
    memcpy(nw, h, ++p - h);
    nw += p - h;
    *nw++ = '*';
    *nw = 0;
  } else if (!p && !num && type >= 10) {
      /* we have a hostname and type
       requires us to replace numbers */
    num = 0;
    for (p = h; *p; p++) {
      if (*p < '0' || *p > '9') {
        *nw++ = *p;
        num = 0;
      } else {
        if (type < 20)
          *nw++ = '?';
        else if (!num) {
          *nw++ = '*';
          num = 1; /* place only one '*'
                      per numeric sequence */
        }
      }
    }
    *nw = 0;
  } else if (d > 2 && (p = strrchr(h, '.'))) {
    if (num) { /* IPv4 */
      memcpy(nw, h, p - h);
      nw += p - h;
      *nw++ = '.';
      *nw++ = '*';
      *nw = 0;
      return;
    }
    for (u = h, d = 0; (u = strchr(++u, '.')); d++);
    if (d < 2) { /* types < 2 don't mask the host */
      op_strlcpy(nw, h, UHOSTLEN);
      return;
    }
    u = strchr(h, '.');
    if (d > 3 || (d == 3 && strlen(p) > 3))
      u = strchr(++u, '.'); /* ccTLD or not? Look above. */
    {
      op_strbuf_t _b = {};
      op_strbuf_init(&_b);
      op_strbuf_appendf(&_b, "*%s", u);
      op_strlcpy(nw, op_strbuf_str(&_b), UHOSTLEN);
      op_strbuf_free(&_b);
    }
  } else if (!*h)
      /* take care if the mask is empty or contains only '@' */
      op_strlcpy(nw, "*", UHOSTLEN);
    else
      op_strlcpy(nw, h, UHOSTLEN);
}

/* Dump a potentially super-long string of text.
 */
void dumplots(int idx, const char *prefix, const char *data)
{
  const char *p = data, *q, *n;
  const int max_data_len = 500 - strlen(prefix);

  if (!*data) {
    dprintf(idx, "%s\n", prefix);
    return;
  }
  while (strlen(p) > max_data_len) {
    q = p + max_data_len;
    /* Search for embedded linefeed first */
    n = strchr(p, '\n');
    if (n && n < q) {
      /* Great! dump that first line then start over */
      dprintf(idx, "%s%.*s\n", prefix, (int)(n - p), p);
      p = n + 1;
    } else {
      /* Search backwards for the last space */
      while (*q != ' ' && q != p)
        q--;
      if (q == p)
        q = p + max_data_len;
      dprintf(idx, "%s%.*s\n", prefix, (int)(q - p), p);
      p = q;
      if (*q == ' ')
        p++;
    }
  }
  /* Last trailing bit: split by linefeeds if possible */
  n = strchr(p, '\n');
  while (n) {
    dprintf(idx, "%s%.*s\n", prefix, (int)(n - p), p);
    p = n + 1;
    n = strchr(p, '\n');
  }
  if (*p)
    dprintf(idx, "%s%s\n", prefix, p);  /* Last trailing bit */
}

/* Convert an interval (in seconds) to one of:
 * "19 days ago", "1 day ago", "18:12"
 */
const char *daysago(time_t now, time_t then)
{
  static op_strbuf_t _b = {};

  if (now - then > 86400) {
    int days = (now - then) / 86400;

    op_strbuf_clear(&_b);
    op_strbuf_appendf(&_b, "%d day%s ago", days, (days == 1) ? "" : "s");
  } else {
    char tmp[6];
    strftime(tmp, sizeof tmp, "%H:%M", localtime(&then));
    op_strbuf_clear(&_b);
    op_strbuf_append_cstr(&_b, tmp);
  }
  return op_strbuf_str(&_b);
}

/* Convert an interval (in seconds) to one of:
 * "in 19 days", "in 1 day", "at 18:12"
 */
const char *days(time_t now, time_t then)
{
  static op_strbuf_t _b = {};

  if (now - then > 86400) {
    int days = (now - then) / 86400;

    op_strbuf_clear(&_b);
    op_strbuf_appendf(&_b, "in %d day%s", days, (days == 1) ? "" : "s");
  } else {
    char tmp[9];
    strftime(tmp, sizeof tmp, "at %H:%M", localtime(&now));
    op_strbuf_clear(&_b);
    op_strbuf_append_cstr(&_b, tmp);
  }
  return op_strbuf_str(&_b);
}

/* Convert an interval (in seconds) to one of:
 * "for 19 days", "for 1 day", "for 09:10"
 */
const char *daysdur(time_t now, time_t then)
{
  static op_strbuf_t _b = {};

  if (now - then > 86400) {
    int days = (now - then) / 86400;

    op_strbuf_clear(&_b);
    op_strbuf_appendf(&_b, "for %d day%s", days, (days == 1) ? "" : "s");
  } else {
    int hrs, mins;

    time_t diff = now - then;
    hrs = (int) (diff / 3600);
    mins = (int) ((diff - (hrs * 3600)) / 60);
    op_strbuf_clear(&_b);
    op_strbuf_appendf(&_b, "for %02d:%02d", hrs, mins);
  }
  return op_strbuf_str(&_b);
}


/*
 *    Logging functions
 */

/* Log something
 * putlog(level,channel_name,format,...);
 */
ATTRIBUTE_FORMAT(printf,3,4)
void putlog (int type, char *chname, const char *format, ...)
{
  static int inhere = 0;
  int tsl = 0;
  char s[LOGLINELEN], *out, ct[81], *s2, stamp[34];
  va_list va;
  time_t now2 = time(nullptr);
  static time_t now2_last = 0; /* cache expensive localtime() */
  static struct tm t;

  if (now2 != now2_last) {
    now2_last = now2;
    localtime_r(&now2, &t);
  }

  va_start(va, format);

  /* Create the timestamp */
  if (shtime) {
    tsl = strftime(stamp, sizeof(stamp) - 2, log_ts, &t);
    stamp[tsl++] = ' ';
    stamp[tsl] = 0;
  }
  else
    *stamp = '\0';

  /* Format log entry at offset 'tsl,' then i can prepend the timestamp */
  out = s + tsl;
  /* No need to check if out should be null-terminated here,
   * just do it! <cybah>
   */
  vsnprintf(out, LOGLINEMAX - tsl, format, va);
  out[LOGLINEMAX - tsl] = 0;
  if (keep_all_logs) {
    if (!logfile_suffix[0])
      strftime(ct, 12, ".%d%b%Y", &t);
    else {
      strftime(ct, 80, logfile_suffix, &t);
      ct[80] = 0;
      s2 = ct;
      /* replace spaces by underscores */
      while (s2[0]) {
        if (s2[0] == ' ')
          s2[0] = '_';
        s2++;
      }
    }
  }
  /* Make sure the bind list is initialized and we're not looping here */
  if (!inhere && H_log) {
    inhere = 1;
    check_tcl_log(type, chname, out);
    inhere = 0;
  }
  if (!inhere && hook_log) {
    inhere = 1;
    hook_log(type, chname, out);
    inhere = 0;
  }
  /* Place the timestamp in the string to be printed */
  if (out[0] && shtime) {
    memcpy(s, stamp, tsl);
    out = s;
  }
  op_strlcat(out, "\n", LOGLINELEN - (size_t)(out - s));
  if (!use_stderr) {
    for (int i = 0; i < max_logs; i++) {
      if ((logs[i].filename != nullptr) && (logs[i].mask & type) &&
          ((chname[0] == '*') || (logs[i].chname[0] == '*') ||
           (!rfc_casecmp(chname, logs[i].chname)))) {

        if (async_log_active()) {
          /* Async path: writer thread owns all FILE* handles.
           * Repeat detection stays on the main thread; file I/O is offloaded. */
          bool slot_open = async_log_slot_open(i);

          /* Determine the open path (NULL when the writer already has it) */
          const char *open_path = nullptr;
          op_strbuf_t pathbuf   = {};
          bool        have_pathbuf = false;
          if (!slot_open) {
            if (keep_all_logs) {
              op_strbuf_init(&pathbuf);
              op_strbuf_appendf(&pathbuf, "%s%s", logs[i].filename, ct);
              open_path    = op_strbuf_str(&pathbuf);
              have_pathbuf = true;
            } else {
              open_path = logs[i].filename;
            }
          }

          if (!op_strcasecmp(out + tsl, logs[i].szlast)) {
            logs[i].repeats++;
          } else {
            if (logs[i].repeats > 0) {
              /* Combine stamp + repeat notice into one write */
              op_strbuf_t rb = {};
              op_strbuf_init(&rb);
              op_strbuf_append_cstr(&rb, stamp);
              op_strbuf_appendf(&rb, MISC_LOGREPEAT, logs[i].repeats);
              async_log_write(i, open_path, op_strbuf_str(&rb));
              op_strbuf_free(&rb);
              logs[i].repeats = 0;
              open_path = nullptr; /* slot is now open */
            }
            async_log_write(i, open_path, out);
            op_strlcpy(logs[i].szlast, out + tsl, LOGLINEMAX);
          }

          if (have_pathbuf)
            op_strbuf_free(&pathbuf);

        } else {
          /* Sync path (original code) */
          if (logs[i].f == nullptr) {
            /* Open this logfile */
            if (keep_all_logs) {
              op_strbuf_t path = {};
              op_strbuf_init(&path);
              op_strbuf_appendf(&path, "%s%s", logs[i].filename, ct);
              logs[i].f = fopen(op_strbuf_str(&path), "a");
              op_strbuf_free(&path);
              if (logs[i].f)
                setvbuf(logs[i].f, nullptr, _IOLBF, 0);
            } else if ((logs[i].f = fopen(logs[i].filename, "a")))
              setvbuf(logs[i].f, nullptr, _IOLBF, 0);
          }
          if (logs[i].f != nullptr) {
            if (!op_strcasecmp(out + tsl, logs[i].szlast))
              logs[i].repeats++;
            else {
              if (logs[i].repeats > 0) {
                fprintf(logs[i].f, "%s", stamp);
                fprintf(logs[i].f, MISC_LOGREPEAT, logs[i].repeats);
                logs[i].repeats = 0;
              }
              fputs(out, logs[i].f);
              op_strlcpy(logs[i].szlast, out + tsl, LOGLINEMAX);
            }
          }
        }
      }
    }
  }
  for (int i = 0; i < dcc_total; i++) {
    if (((dcc[i].type == &DCC_CHAT) && (dcc[i].u.chat->con_flags & type)) ||
        ((dcc[i].type == &DCC_PRE_RELAY) && (dcc[i].u.relay->chat->con_flags & type))) {
      if ((chname[0] == '*') || (dcc[i].u.chat->con_chan[0] == '*') ||
          !rfc_casecmp(chname, dcc[i].u.chat->con_chan)) {
        dprintf(i, "%s", out);
      }
    }
  }
  if (!backgrd && !con_chan && term_z < 0)
    dprintf(DP_STDOUT, "%s", out);
  else if ((type & LOG_MISC) && use_stderr) {
    if (shtime)
      out += tsl;
    dprintf(DP_STDERR, "%s", out);
  }
  va_end(va);
}

/* Called as soon as the logfile suffix changes. All logs are closed
 * and the new suffix is stored in `logfile_suffix'.
 */
void logsuffix_change(char *s)
{
  char *s2 = logfile_suffix;

  /* If the suffix didn't really change, ignore. It's probably a rehash. */
  if (!s || (s && s2 && !strcmp(s, s2)))
    return;

  debug0("Logfile suffix changed. Closing all open logs.");
  op_strlcpy(logfile_suffix, s, sizeof logfile_suffix);
  while (s2[0]) {
    if (s2[0] == ' ')
      s2[0] = '_';
    s2++;
  }
  if (async_log_active())
    async_log_flush();  /* ensure all pending lines are on disk before close */
  for (int i = 0; i < max_logs; i++) {
    if (async_log_active() && async_log_slot_open(i)) {
      async_log_close(i);
    } else if (logs[i].f) {
      fclose(logs[i].f);
      logs[i].f = nullptr;
    }
  }
}

void check_logsize(void)
{
  struct stat ss;

  if (!keep_all_logs && max_logsize > 0) {
    for (int i = 0; i < max_logs; i++) {
      if (logs[i].filename) {
        if (stat(logs[i].filename, &ss) != 0) {
          break;
        }
        if ((ss.st_size >> 10) > max_logsize) {
          if (logs[i].f) {
            /* write to the log before closing it huh.. */
            putlog(LOG_MISC, "*", MISC_CLOGS, logs[i].filename, ss.st_size);
            fclose(logs[i].f);
            logs[i].f = nullptr;
          }

          {
            op_strbuf_t buf = {};
            op_strbuf_init(&buf);
            op_strbuf_appendf(&buf, "%s.yesterday", logs[i].filename);
            unlink(op_strbuf_str(&buf));
            movefile(logs[i].filename, op_strbuf_str(&buf));
            op_strbuf_free(&buf);
          }
        }
      }
    }
  }
}

/*
 *     String substitution functions
 */

/* Column formatting state */
static struct {
  int cols;
  int colsofar;
  int blind;
  int subwidth;
  bool colstrings_ready;
  op_vec_t colstrings;  /* op_vec_t of op_strdup'd column strings — replaces the \377-delimited colstr. */
} col_state = { .subwidth = 70 };

static void colstrings_drain(void)
{
  size_t i;
  void *p;

  OP_VEC_FOREACH(&col_state.colstrings, i, p)
    op_free(p);
  op_vec_clear(&col_state.colstrings, nullptr, nullptr);
}

/* Append a column entry and flush a row to s when enough columns are ready. */
static void subst_addcol(char *s, size_t sz, char *newcol)
{
  char *col;
  int colwidth;
  size_t n;

  if (!col_state.colstrings_ready) {
    op_vec_init(&col_state.colstrings, 4);
    col_state.colstrings_ready = true;
  }

  if (newcol[0] && newcol[0] != '\377') {
    col_state.colsofar++;
    op_vec_push(&col_state.colstrings, op_strdup(newcol));
  }

  n = op_vec_size(&col_state.colstrings);
  if ((col_state.colsofar == col_state.cols) || (newcol[0] == '\377' && n > 0)) {
    col_state.colsofar = 0;
    colwidth = (col_state.subwidth - 5) / col_state.cols;
    {
      op_strbuf_t _b = {};
      op_strbuf_init(&_b);
      op_strbuf_append_cstr(&_b, "     ");
      for (size_t j = 0; j < n; j++) {
        col = op_vec_get(&col_state.colstrings, j);
        op_strbuf_append_cstr(&_b, col);
        if (j < n - 1) {             /* pad all but the last column */
          for (int i = (int) strlen(col); i < colwidth; i++)
            op_strbuf_append_cstr(&_b, " ");
        }
        op_free(col);
      }
      op_strlcpy(s, op_strbuf_str(&_b), sz);
      op_strbuf_free(&_b);
    }
    op_vec_clear(&col_state.colstrings, nullptr, nullptr);
  }
}

char *egg_uname(void)
{
  struct utsname u;
  static op_strbuf_t sb = {};
  static bool sb_inited;

  if (show_uname) {
    if (uname(&u) < 0)
      return "*unknown*";
    if (!sb_inited) {
      op_strbuf_init(&sb);
      sb_inited = true;
    }
    op_strbuf_clear(&sb);
    op_strbuf_appendf(&sb, "%s %s", u.sysname, u.release);
    return (char *) op_strbuf_str(&sb);
  }
  else
    return "";
}

/* Substitute %x codes in help files
 *
 * %B = bot nickname
 * %V = version
 * %C = list of channels i monitor
 * %E = eggdrop banner
 * %A = admin line
 * %n = network name
 * %T = current time ("14:15")
 * %N = user's nickname
 * %U = display system name if possible
 * %{+xy}     require flags to read this section
 * %{-}       turn of required flag matching only
 * %{center}  center this line
 * %{cols=N}  start of columnated section (indented)
 * %{help=TOPIC} start a section for a particular command
 * %{end}     end of section
 */
constexpr int HELP_BUF_LEN = 256;
constexpr int HELP_BOLD    = 1;
constexpr int HELP_REV     = 2;
constexpr int HELP_UNDER   = 4;
constexpr int HELP_FLASH   = 8;

void help_subst(char *s, char *nick, struct flag_record *flags,
                int isdcc, char *topic)
{
  struct chanset_t *chan;
  int center = 0;
  char xx[HELP_BUF_LEN + 1], *current, *q, chr, *writeidx, *readidx, *towrite,
       sub[512];

  if (s == nullptr) {
    /* Used to reset substitutions */
    col_state.blind = 0;
    col_state.cols = 0;
    col_state.subwidth = 70;
    if (col_state.colstrings_ready && !op_vec_empty(&col_state.colstrings))
      colstrings_drain();
    help_state.flags = isdcc;
    return;
  }
  op_strlcpy(xx, s, sizeof xx);
  readidx = xx;
  writeidx = s;
  current = strchr(readidx, '%');
  while (current) {
    /* Are we about to copy a chuck to the end of the buffer?
     * if so return
     */
    if ((writeidx + (current - readidx)) >= (s + HELP_BUF_LEN)) {
      memcpy(writeidx, readidx, (s + HELP_BUF_LEN) - writeidx);
      s[HELP_BUF_LEN] = 0;
      return;
    }
    chr = *(current + 1);
    *current = 0;
    if (!col_state.blind)
      writeidx = stpcpy(writeidx, readidx);
    towrite = nullptr;
    switch (chr) {
    case 'b':
      if (glob_hilite(*flags)) {
        if (help_state.flags & HELP_IRC) {
          towrite = "\002";
        } else if (help_state.flags & HELP_BOLD) {
          help_state.flags &= ~HELP_BOLD;
          towrite = "\033[0m";
        } else {
          help_state.flags |= HELP_BOLD;
          towrite = "\033[1m";
        }
      }
      break;
    case 'v':
      if (glob_hilite(*flags)) {
        if (help_state.flags & HELP_IRC) {
          towrite = "\026";
        } else if (help_state.flags & HELP_REV) {
          help_state.flags &= ~HELP_REV;
          towrite = "\033[0m";
        } else {
          help_state.flags |= HELP_REV;
          towrite = "\033[7m";
        }
      }
      break;
    case '_':
      if (glob_hilite(*flags)) {
        if (help_state.flags & HELP_IRC) {
          towrite = "\037";
        } else if (help_state.flags & HELP_UNDER) {
          help_state.flags &= ~HELP_UNDER;
          towrite = "\033[0m";
        } else {
          help_state.flags |= HELP_UNDER;
          towrite = "\033[4m";
        }
      }
      break;
    case 'f':
      if (glob_hilite(*flags)) {
        if (help_state.flags & HELP_FLASH) {
          if (help_state.flags & HELP_IRC)
            towrite = "\002\037";
          else
            towrite = "\033[0m";
          help_state.flags &= ~HELP_FLASH;
        } else {
          help_state.flags |= HELP_FLASH;
          if (help_state.flags & HELP_IRC)
            towrite = "\037\002";
          else
            towrite = "\033[5m";
        }
      }
      break;
    case 'U':
      towrite = egg_uname();
      break;
    case 'B':
      towrite = (isdcc ? botnetnick : botname);
      break;
    case 'V':
      towrite = ver;
      break;
    case 'E':
      towrite = version;
      break;
    case 'A':
      towrite = admin;
      break;
    case 'n':
      towrite = network;
      break;
    case 'T':
      strftime(sub, sizeof sub, "%H:%M", localtime(&now));
      towrite = sub;
      break;
    case 'N':
      towrite = strchr(nick, ':');
      if (towrite)
        towrite++;
      else
        towrite = nick;
      break;
    case 'C':
      if (!col_state.blind)
        for (chan = chanset; chan; chan = chan->next) {
          if ((strlen(chan->dname) + writeidx + 2) >= (s + HELP_BUF_LEN)) {
            memcpy(writeidx, chan->dname, (s + HELP_BUF_LEN) - writeidx);
            s[HELP_BUF_LEN] = 0;
            return;
          }
          writeidx = stpcpy(writeidx, chan->dname);
          if (chan->next) {
            *writeidx++ = ',';
            *writeidx++ = ' ';
          }
        }
      break;
    case '{':
      q = current;
      current++;
      while ((*current != '}') && (*current))
        current++;
      if (*current) {
        *current = 0;
        current--;
        q += 2;
        /* Now q is the string and p is where the rest of the fcn expects */
        if (!strncmp(q, "help=", 5)) {
          if (topic && op_strcasecmp(q + 5, topic))
            col_state.blind |= 2;
          else
            col_state.blind &= ~2;
        } else if (!(col_state.blind & 2)) {
          if (q[0] == '+') {
            struct flag_record fr = { FR_GLOBAL | FR_CHAN };

            break_down_flags(q + 1, &fr, nullptr);

            /* We used to check flagrec_ok(), but we can use flagrec_eq()
             * instead because lower flags are automatically added now.
             */
            if (!flagrec_eq(&fr, flags))
              col_state.blind |= 1;
            else
              col_state.blind &= ~1;
          } else if (q[0] == '-')
            col_state.blind &= ~1;
          else if (!op_strcasecmp(q, "end")) {
            col_state.blind &= ~1;
            col_state.subwidth = 70;
            if (col_state.cols) {
              sub[0] = 0;
              subst_addcol(sub, sizeof sub, "\377");
              col_state.cols = 0;
              towrite = sub;
            }
          } else if (!op_strcasecmp(q, "center"))
            center = 1;
          else if (!strncmp(q, "cols=", 5)) {
            char *r;

            col_state.cols = egg_atoi(q + 5);
            col_state.colsofar = 0;
            /* colstrings is already empty; no reset needed */
            r = strchr(q + 5, '/');
            if (r != nullptr)
              col_state.subwidth = egg_atoi(r + 1);
          }
        }
      } else
        current = q;            /* no } so ignore */
      break;
    default:
      if (!col_state.blind) {
        *writeidx++ = chr;
        if (writeidx >= (s + HELP_BUF_LEN)) {
          *writeidx = 0;
          return;
        }
      }
    }
    if (towrite && !col_state.blind) {
      if ((writeidx + strlen(towrite)) >= (s + HELP_BUF_LEN)) {
        memcpy(writeidx, towrite, (s + HELP_BUF_LEN) - writeidx);
        s[HELP_BUF_LEN] = 0;
        return;
      }
      writeidx = stpcpy(writeidx, towrite);
    }
    if (chr) {
      readidx = current + 2;
      current = strchr(readidx, '%');
    } else {
      readidx = current + 1;
      current = nullptr;
    }
  }
  if (!col_state.blind) {
    int i = strlen(readidx);
    if (i && ((writeidx + i) >= (s + HELP_BUF_LEN))) {
      memcpy(writeidx, readidx, (s + HELP_BUF_LEN) - writeidx);
      s[HELP_BUF_LEN] = 0;
      return;
    }
    op_strlcpy(writeidx, readidx, (s + HELP_BUF_LEN + 1) - writeidx);
  } else
    *writeidx = 0;
  if (center) {
    op_strlcpy(xx, s, sizeof(xx));
    int i = 35 - (int)(strlen(xx) / 2);
    if (i > 0) {
      s[0] = 0;
      for (int j = 0; j < i; j++)
        s[j] = ' ';
      op_strlcpy(s + i, xx, HELP_BUF_LEN + 1 - i);
    }
  }
  if (col_state.cols) {
    op_strlcpy(xx, s, sizeof xx);
    s[0] = 0;
    subst_addcol(s, sizeof s, xx);
  }
}

static void scan_help_file(help_ref_t *current, const char *filename, int type)
{
  FILE *f;
  char s[HELP_BUF_LEN + 1], *p, *q;

  if (is_file(filename) && (f = fopen(filename, "r"))) {
    while (fgets(s, HELP_BUF_LEN, f) != nullptr) {
      p = s;
      while ((q = strstr(p, "%{help="))) {
        q += 7;
        if ((p = strchr(q, '}'))) {
          *p = 0;
          help_item_t *item = (help_item_t *)op_bh_alloc(help_item_bh);
          item->name = op_malloc((size_t)(p - q + 1));
          op_strlcpy(item->name, q, (size_t)(p - q + 1));
          item->type = type;
          op_vec_push(&current->items, item);
          /* Populate topic index — first-wins for duplicate topic names */
          {
            op_htab **idx = (type == 0) ? &help_idx_irc : &help_idx_dcc;
            if (!*idx)
              *idx = op_htab_create_str(type == 0 ? "help_idx_irc" : "help_idx_dcc", 64);
            if (!op_htab_get(*idx, item->name)) {
              help_idx_entry_t *he = (help_idx_entry_t *)op_malloc(sizeof *he);
              he->refname = op_strdup(current->name);
              he->type    = type;
              op_htab_set(*idx, item->name, he, nullptr);
            }
          }
          p++;
        } else
          p = "";
      }
    }
    if (ferror(f))
      putlog(LOG_MISC, "*", "Error reading help file");
    fclose(f);
  }
}

void add_help_reference(char *file)
{
  if (!help_ref_bh) {
    help_ref_bh  = op_bh_create(sizeof(help_ref_t),  16, "help_ref");
    help_item_bh = op_bh_create(sizeof(help_item_t), 64, "help_item");
    op_vec_init(&help_refs, 16);
  }
  for (size_t i = 0; i < help_refs.size; i++) {
    help_ref_t *ref = (help_ref_t *)op_vec_get(&help_refs, i);
    if (!strcmp(ref->name, file))
      return;
  }
  help_ref_t *current = (help_ref_t *)op_bh_alloc(help_ref_bh);
  current->name = op_strdup(file);
  op_vec_init(&current->items, 16);
  op_vec_push(&help_refs, current);
  {
    op_strbuf_t s = {};
    op_strbuf_init(&s);
    op_strbuf_appendf(&s, "%smsg/%s", helpdir, file);
    scan_help_file(current, op_strbuf_str(&s), 0);
    op_strbuf_clear(&s);
    op_strbuf_appendf(&s, "%s%s", helpdir, file);
    scan_help_file(current, op_strbuf_str(&s), 1);
    op_strbuf_clear(&s);
    op_strbuf_appendf(&s, "%sset/%s", helpdir, file);
    scan_help_file(current, op_strbuf_str(&s), 2);
    op_strbuf_free(&s);
  }
}

void rem_help_reference(char *file)
{
  for (size_t i = 0; i < help_refs.size; i++) {
    help_ref_t *ref = (help_ref_t *)op_vec_get(&help_refs, i);
    if (!strcmp(ref->name, file)) {
      /* Clear caches before invalidating item->name pointers used as htab keys */
      help_cache_clear();
      help_idx_clear();
      for (size_t j = 0; j < ref->items.size; j++) {
        help_item_t *item = (help_item_t *)op_vec_get(&ref->items, j);
        op_free(item->name);
        op_bh_free(help_item_bh, item);
      }
      op_vec_fini(&ref->items, nullptr, nullptr);
      op_free(ref->name);
      op_vec_remove_fast(&help_refs, i);
      op_bh_free(help_ref_bh, ref);
      help_idx_rebuild();
      return;
    }
  }
}

void reload_help_data(void)
{
  help_cache_clear();
  help_idx_clear();
  /* Collect names before clearing */
  op_vec_t names;
  op_vec_init(&names, help_refs.size);
  for (size_t i = 0; i < help_refs.size; i++) {
    help_ref_t *ref = (help_ref_t *)op_vec_get(&help_refs, i);
    op_vec_push(&names, op_strdup(ref->name));
  }
  /* Clear all refs */
  for (size_t i = 0; i < help_refs.size; i++) {
    help_ref_t *ref = (help_ref_t *)op_vec_get(&help_refs, i);
    for (size_t j = 0; j < ref->items.size; j++) {
      help_item_t *item = (help_item_t *)op_vec_get(&ref->items, j);
      op_free(item->name);
      op_bh_free(help_item_bh, item);
    }
    op_vec_fini(&ref->items, nullptr, nullptr);
    op_free(ref->name);
    op_bh_free(help_ref_bh, ref);
  }
  op_vec_clear(&help_refs, nullptr, nullptr);
  /* Re-add */
  for (size_t i = 0; i < names.size; i++) {
    char *name = (char *)op_vec_get(&names, i);
    add_help_reference(name);
    op_free(name);
  }
  op_vec_fini(&names, nullptr, nullptr);
}

void debug_help(int idx)
{
  for (size_t i = 0; i < help_refs.size; i++) {
    help_ref_t *ref = (help_ref_t *)op_vec_get(&help_refs, i);
    dprintf(idx, "HELP FILE(S): %s\n", ref->name);
    for (size_t j = 0; j < ref->items.size; j++) {
      help_item_t *item = (help_item_t *)op_vec_get(&ref->items, j);
      dprintf(idx, "   %s (%s)\n", item->name,
              (item->type == 0) ? "msg/" : (item->type == 1) ? "" : "set/");
    }
  }
}

static FILE *resolve_help(int dcc, char *file)
{
  if (!(dcc & HELP_TEXT)) {
    /* O(1) htab lookup — avoids double linear scan over all refs×items */
    op_htab *idx = !dcc ? help_idx_irc : help_idx_dcc;
    if (idx) {
      help_idx_entry_t *e = (help_idx_entry_t *)op_htab_get(idx, file);
      if (e) {
        op_strbuf_t s = {};
        op_strbuf_init(&s);
        if (e->type == 0)
          op_strbuf_appendf(&s, "%smsg/%s", helpdir, e->refname);
        else if (e->type == 1)
          op_strbuf_appendf(&s, "%s%s", helpdir, e->refname);
        else
          op_strbuf_appendf(&s, "%sset/%s", helpdir, e->refname);
        FILE *f = help_fopen_cached(op_strbuf_str(&s));
        op_strbuf_free(&s);
        return f;
      }
    }
    /* Fallback linear scan (index not yet populated) */
    for (size_t i = 0; i < help_refs.size; i++) {
      help_ref_t *ref = (help_ref_t *)op_vec_get(&help_refs, i);
      for (size_t j = 0; j < ref->items.size; j++) {
        help_item_t *item = (help_item_t *)op_vec_get(&ref->items, j);
        if (!strcmp(item->name, file)) {
          op_strbuf_t s = {};
          op_strbuf_init(&s);
          FILE *f = nullptr;
          if (!item->type && !dcc) {
            op_strbuf_appendf(&s, "%smsg/%s", helpdir, ref->name);
            f = help_fopen_cached(op_strbuf_str(&s));
          } else if (dcc && item->type) {
            if (item->type == 1)
              op_strbuf_appendf(&s, "%s%s", helpdir, ref->name);
            else
              op_strbuf_appendf(&s, "%sset/%s", helpdir, ref->name);
            f = help_fopen_cached(op_strbuf_str(&s));
          }
          op_strbuf_free(&s);
          if (f) return f;
        }
      }
    }
    return nullptr;
  }
  /* HELP_TEXT: open from textdir without caching (content may change) */
  {
    op_strbuf_t s = {};
    op_strbuf_init(&s);
    op_strbuf_appendf(&s, "%s%s", textdir, file);
    if (is_file(op_strbuf_str(&s))) {
      FILE *f = fopen(op_strbuf_str(&s), "r");
      op_strbuf_free(&s);
      return f;
    }
    op_strbuf_free(&s);
    return nullptr;
  }
}

void showhelp(char *who, char *file, struct flag_record *flags, int fl)
{
  int lines = 0;
  char s[HELP_BUF_LEN + 1];
  FILE *f = resolve_help(fl, file);

  if (f) {
    help_subst(nullptr, nullptr, 0, HELP_IRC, nullptr);  /* Clear flags */
    while (fgets(s, HELP_BUF_LEN, f) != nullptr) {
      if (s[strlen(s) - 1] == '\n')
        s[strlen(s) - 1] = 0;
      if (!s[0])
        op_strlcpy(s, " ", sizeof(s));
      help_subst(s, who, flags, 0, file);
      if ((s[0]) && (strlen(s) > 1)) {
        dprintf(DP_HELP, "NOTICE %s :%s\n", who, s);
        lines++;
      }
    }
    /* fgets == nullptr means error or empty file, so check for error */
    if (ferror(f)) {
      putlog(LOG_MISC, "*", "Error reading help file");
    }
    fclose(f);
  }
  if (!lines && !(fl & HELP_TEXT))
    dprintf(DP_HELP, "NOTICE %s :%s\n", who, IRC_NOHELP2);
}

static int display_tellhelp(int idx, char *file, FILE *f,
                            struct flag_record *flags)
{
  char s[HELP_BUF_LEN + 1];
  int lines = 0;

  if (f) {
    help_subst(nullptr, nullptr, 0,
               (dcc[idx].status & (STAT_TELNET | STAT_WS)) ? 0 : HELP_IRC, nullptr);
    while (fgets(s, HELP_BUF_LEN, f) != nullptr) {
      if (s[strlen(s) - 1] == '\n')
        s[strlen(s) - 1] = 0;
      if (!s[0])
        op_strlcpy(s, " ", sizeof(s));
      help_subst(s, dcc[idx].nick, flags, 1, file);
      if (s[0]) {
        dprintf(idx, "%s\n", s);
        lines++;
      }
    }
    /* fgets == nullptr means error or empty file, so check for error */
    if (ferror(f)) {
      putlog(LOG_MISC, "*", "Error displaying help");
    }
    fclose(f);
  }
  return lines;
}

void tellhelp(int idx, char *file, struct flag_record *flags, int fl)
{
  int lines = 0;
  FILE *f = resolve_help(HELP_DCC | fl, file);

  if (f)
    lines = display_tellhelp(idx, file, f, flags);
  if (!lines && !(fl & HELP_TEXT))
    dprintf(idx, "%s\n", IRC_NOHELP2);
}

/* Same as tellallhelp, just using wild_match instead of strcmp
 */
void tellwildhelp(int idx, char *match, struct flag_record *flags)
{
  FILE *f;
  bool found = false;

  for (size_t i = 0; i < help_refs.size; i++) {
    help_ref_t *ref = (help_ref_t *)op_vec_get(&help_refs, i);
    for (size_t j = 0; j < ref->items.size; j++) {
      help_item_t *item = (help_item_t *)op_vec_get(&ref->items, j);
      if (wild_match(match, item->name) && item->type) {
        op_strbuf_t s = {};
        op_strbuf_init(&s);
        if (item->type == 1)
          op_strbuf_appendf(&s, "%s%s", helpdir, ref->name);
        else
          op_strbuf_appendf(&s, "%sset/%s", helpdir, ref->name);
        f = help_fopen_cached(op_strbuf_str(&s));
        op_strbuf_free(&s);
        if (f) {
          display_tellhelp(idx, item->name, f, flags);
          found = true;
        }
      }
    }
  }
  if (!found)
    dprintf(idx, "%s\n", IRC_NOHELP2);
}

/* Same as tellwildhelp, just using strcmp instead of wild_match
 */
void tellallhelp(int idx, char *match, struct flag_record *flags)
{
  FILE *f;
  bool found = false;

  for (size_t i = 0; i < help_refs.size; i++) {
    help_ref_t *ref = (help_ref_t *)op_vec_get(&help_refs, i);
    for (size_t j = 0; j < ref->items.size; j++) {
      help_item_t *item = (help_item_t *)op_vec_get(&ref->items, j);
      if (!strcmp(match, item->name) && item->type) {
        op_strbuf_t s = {};
        op_strbuf_init(&s);
        if (item->type == 1)
          op_strbuf_appendf(&s, "%s%s", helpdir, ref->name);
        else
          op_strbuf_appendf(&s, "%sset/%s", helpdir, ref->name);
        f = help_fopen_cached(op_strbuf_str(&s));
        op_strbuf_free(&s);
        if (f) {
          display_tellhelp(idx, item->name, f, flags);
          found = true;
        }
      }
    }
  }
  if (!found)
    dprintf(idx, "%s\n", IRC_NOHELP2);
}

/* Substitute vars in a lang text to dcc chatter
 */
void sub_lang(int idx, char *text)
{
  char s[1024];
  struct flag_record fr = { FR_GLOBAL | FR_CHAN };

  get_user_flagrec(dcc[idx].user, &fr, dcc[idx].u.chat->con_chan);
  help_subst(nullptr, nullptr, 0,
             (dcc[idx].status & (STAT_TELNET | STAT_WS)) ? 0 : HELP_IRC, nullptr);
  op_strlcpy(s, text, sizeof s);
  if (s[strlen(s) - 1] == '\n')
    s[strlen(s) - 1] = 0;
  if (!s[0])
    op_strlcpy(s, " ", sizeof(s));
  help_subst(s, dcc[idx].nick, &fr, 1, botnetnick);
  if (s[0])
    dprintf(idx, "%s\n", s);
}

/* This will return a pointer to the first character after the @ in the
 * string given it.  Possibly it's time to think about a regexp library
 * for eggdrop...
 */
char *extracthostname(char *hostmask)
{
  char *p = strrchr(hostmask, '@');

  return p ? p + 1 : "";
}

/* Show motd to dcc chatter
 */
void show_motd(int idx)
{
  FILE *vv;
  char s[1024];
  struct flag_record fr = { FR_GLOBAL | FR_CHAN };

  if (!is_file(motdfile))
    return;

  vv = fopen(motdfile, "r");
  if (!vv)
    return;

  get_user_flagrec(dcc[idx].user, &fr, dcc[idx].u.chat->con_chan);
  dprintf(idx, "\n");
  /* reset the help_subst variables to their defaults */
  help_subst(nullptr, nullptr, 0,
             (dcc[idx].status & (STAT_TELNET | STAT_WS)) ? 0 : HELP_IRC, nullptr);
  while (fgets(s, sizeof s, vv) != nullptr) {
    if (s[strlen(s) - 1] == '\n')
      s[strlen(s) - 1] = 0;
    if (!s[0])
      op_strlcpy(s, " ", sizeof(s));
    help_subst(s, dcc[idx].nick, &fr, 1, botnetnick);
    if (s[0])
      dprintf(idx, "%s\n", s);
  }
  /* fgets == nullptr means error or empty file, so check for error */
  if (ferror(vv)) {
    putlog(LOG_MISC, "*", "Error reading MOTD for DCC");
  }
  fclose(vv);
  dprintf(idx, "\n");
}

/* Show banner to telnet user
 */
void show_banner(int idx)
{
  FILE *vv;
  char s[1024];
  struct flag_record fr = { FR_GLOBAL | FR_CHAN };

  if (!is_file(bannerfile))
    return;

  vv = fopen(bannerfile, "r");
  if (!vv)
    return;

  get_user_flagrec(dcc[idx].user, &fr, dcc[idx].u.chat->con_chan);
  /* reset the help_subst variables to their defaults */
  help_subst(nullptr, nullptr, 0, 0, nullptr);
  while (fgets(s, sizeof s, vv) != nullptr) {
    if (s[strlen(s) - 1] == '\n')
      s[strlen(s) - 1] = 0;
    if (!s[0])
      op_strlcpy(s, " ", sizeof(s));
    help_subst(s, dcc[idx].nick, &fr, 0, botnetnick);
    if (s[0])
      dprintf(idx, "%s\n", s);
  }
  /* fgets == nullptr means error or empty file, so check for error */
  if (ferror(vv)) {
      putlog(LOG_MISC, "*", "Error reading banner");
  }
  fclose(vv);
}

void make_rand_str_from_chars(char *s, const int len, char *chars)
{
  for (int i = 0; i < len; i++)
    s[i] = chars[randint(strlen(chars))];
  s[len] = 0;
}

/* Create a string with random lower case letters and digits
 */
void make_rand_str(char *s, const int len)
{
  make_rand_str_from_chars(s, len, CHARSET_LOWER_ALPHA_NUM);
}

/* Convert an octal string into a decimal integer value.  If the string
 * is empty or contains non-octal characters, -1 is returned.
 * Deprecated, use strtol() instead.
 */
int oatoi(const char *octal)
{
  if (!*octal)
    return -1;
  int i = 0;
  for (; ((*octal >= '0') && (*octal <= '7')); octal++)
    i = (i * 8) + (*octal - '0');
  if (*octal)
    return -1;
  return i;
}

/* Return an allocated buffer which contains a copy of the string
 * 'str', with all 'div' characters escaped by 'mask'. 'mask'
 * characters are escaped too.
 *
 * Remember to free the returned memory block.
 */
char *str_escape(const char *str, const char div, const char mask)
{
  const int len = strlen(str);
  int buflen = (2 * len), blen = 0;
  char *buf = op_malloc(buflen + 1), *b = buf;
  const char *s;

  if (!buf)
    return nullptr;
  for (s = str; *s; s++) {
    /* Resize buffer. */
    if ((buflen - blen) <= 3) {
      buflen = (buflen * 2);
      buf = op_realloc(buf, buflen + 1);
      if (!buf)
        return nullptr;
      b = buf + blen;
    }

    if (*s == div || *s == mask) {
      {
        op_strbuf_t _e = {};
        op_strbuf_init(&_e);
        op_strbuf_appendf(&_e, "%c%02x", mask, (unsigned char)*s);
        memcpy(b, op_strbuf_str(&_e), op_strbuf_len(&_e));
        op_strbuf_free(&_e);
      }
      b += 3;
      blen += 3;
    } else {
      *(b++) = *s;
      blen++;
    }
  }
  *b = 0;
  return buf;
}

/* Search for a certain character 'div' in the string 'str', while
 * ignoring escaped characters prefixed with 'mask'.
 *
 * The string
 *
 *   "\\3a\\5c i am funny \\3a):further text\\5c):oink"
 *
 * as str, '\\' as mask and ':' as div would change the str buffer
 * to
 *
 *   ":\\ i am funny :)"
 *
 * and return a pointer to "further text\\5c):oink".
 *
 * NOTE: If you look carefully, you'll notice that strchr_unescape()
 *       behaves differently than strchr().
 */
char *strchr_unescape(char *str, const char div, const char esc_char)
{
  char buf[3];
  char *s, *p;

  buf[2] = 0;
  for (s = p = str; *s; s++, p++) {
    if (*s == esc_char) {       /* Found escape character.              */
      /* Convert code to character. */
      buf[0] = s[1], buf[1] = s[2];
      *p = (unsigned char) strtol(buf, nullptr, 16);
      s += 2;
    } else if (*s == div) {
      *p = *s = 0;
      return (s + 1);           /* Found searched for character.        */
    } else
      *p = *s;
  }
  *p = 0;
  return nullptr;
}

/* Is every character in a string a digit? */
int str_isdigit(const char *str)
{
  if (!*str)
    return 0;

  for (; *str; ++str) {
    if (!isdigit((unsigned char)(*str)))
      return 0;
  }
  return 1;
}

/* As strchr_unescape(), but converts the complete string, without
 * searching for a specific delimiter character.
 */
void str_unescape(char *str, const char esc_char)
{
  (void) strchr_unescape(str, 0, esc_char);
}

/* Kills the bot. s1 is the reason shown to other bots,
 * s2 the reason shown on the partyline. (Sup 25Jul2001)
 */
[[noreturn]] void kill_bot(const char *s1, const char *s2)
{
  check_tcl_die(s2);
  call_hook(HOOK_DIE);
  chatout("*** %s\n", s1);
  botnet_send_chat(-1, botnetnick, s1);
  botnet_send_bye();
  write_userfile(-1);
  egg_store_shutdown();
  fatal(s2, 2);
  __builtin_unreachable();
}

/* Compares two strings with constant-time algorithm to avoid timing attack and
 * returns 0, if strings match, similar to strcmp().
 */
/* https://github.com/jedisct1/libsodium/blob/451bafc0d3d95d18f916dd7051687d343597228c/src/libsodium/crypto_verify/sodium/verify.c */
/*
 * ISC License
 *
 * Copyright (c) 2013-2020
 * Frank Denis <j at pureftpd dot org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
int crypto_verify(const char *x_, const char *y_)
{
  const volatile unsigned char *volatile x =
    (const volatile unsigned char *volatile) x_;
  const volatile unsigned char *volatile y =
    (const volatile unsigned char *volatile) y_;
  volatile uint_fast16_t d = 0U;

  /* Could leak string length */
  int n = strlen(x_);
  if (n != (int)strlen(y_))
    return 1;

  for (int i = 0; i < n; i++) {
    d |= x[i] ^ y[i];
  }
  return (1 & ((d - 1) >> 8)) - 1;
}

/*
 * UTF-8 utilities
 *
 * IRC messages may contain arbitrary bytes, but modern servers and clients
 * generally send UTF-8 text.  These helpers let the core validate and
 * iterate over UTF-8 data without depending on locale settings.
 */

/* Return the byte length of the UTF-8 character whose first byte is *p,
 * or 0 if the byte cannot begin a valid UTF-8 sequence (i.e. it is a
 * stray continuation byte 0x80-0xBF or an overlong/invalid lead byte
 * 0xC0-0xC1 / 0xF5-0xFF).
 */
int utf8_char_len(const unsigned char *p)
{
  if (*p < 0x80)          return 1;  /* ASCII */
  if (*p < 0xC2)          return 0;  /* stray continuation or C0/C1 overlong */
  if (*p < 0xE0)          return 2;  /* U+0080 .. U+07FF  */
  if (*p < 0xF0)          return 3;  /* U+0800 .. U+FFFF  */
  if (*p <= 0xF4)         return 4;  /* U+10000 .. U+10FFFF */
  return 0;                          /* > 0xF4: beyond Unicode range */
}

/* Return 1 if the first len bytes of s form a valid UTF-8 sequence,
 * 0 otherwise.  NUL bytes are treated as ordinary bytes (valid ASCII).
 */
int utf8_valid(const char *s, size_t len)
{
  const unsigned char *p = (const unsigned char *) s;
  const unsigned char *end = p + len;

  while (p < end) {
    int clen = utf8_char_len(p);
    if (clen == 0)
      return 0;
    if (p + clen > end)
      return 0;                      /* truncated sequence */
    /* Validate continuation bytes (must be 10xxxxxx) */
    for (int i = 1; i < clen; i++) {
      if ((p[i] & 0xC0) != 0x80)
        return 0;
    }
    /* Reject overlong encodings and surrogates U+D800-U+DFFF */
    if (clen == 2 && (p[0] & 0x1E) == 0) return 0;
    if (clen == 3) {
      unsigned cp = ((p[0] & 0x0F) << 12) | ((p[1] & 0x3F) << 6) | (p[2] & 0x3F);
      if (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF)) return 0;
    }
    if (clen == 4) {
      unsigned cp = ((p[0] & 0x07) << 18) | ((p[1] & 0x3F) << 12) |
                    ((p[2] & 0x3F) << 6)  |  (p[3] & 0x3F);
      if (cp < 0x10000 || cp > 0x10FFFF) return 0;
    }
    p += clen;
  }
  return 1;
}

/* Count Unicode codepoints in the NUL-terminated string s.
 * Invalid bytes each count as one codepoint (the replacement character).
 */
size_t utf8_strlen(const char *s)
{
  const unsigned char *p = (const unsigned char *) s;
  size_t count = 0;

  while (*p) {
    int clen = utf8_char_len(p);
    if (clen == 0) {
      /* Invalid byte: treat as single replacement character and advance 1 */
      p++;
    } else {
      p += clen;
    }
    count++;
  }
  return count;
}

/* Replace invalid UTF-8 bytes in s (NUL-terminated, modified in-place)
 * with '?'.  The string length never increases.  Returns the number of
 * bytes replaced.
 */
int utf8_sanitize(char *s)
{
  unsigned char *p = (unsigned char *) s;
  int replaced = 0;

  while (*p) {
    int clen = utf8_char_len(p);
    int valid = 0;
    if (clen > 0) {
      /* Check all continuation bytes */
      valid = 1;
      for (int i = 1; i < clen; i++) {
        if ((p[i] & 0xC0) != 0x80) { valid = 0; break; }
      }
      /* Check for overlong / surrogate */
      if (valid && clen == 2 && (p[0] & 0x1E) == 0) valid = 0;
      if (valid && clen == 3) {
        unsigned cp = ((p[0] & 0x0F) << 12) | ((p[1] & 0x3F) << 6) | (p[2] & 0x3F);
        if (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF)) valid = 0;
      }
      if (valid && clen == 4) {
        unsigned cp = ((p[0] & 0x07) << 18) | ((p[1] & 0x3F) << 12) |
                      ((p[2] & 0x3F) << 6)  |  (p[3] & 0x3F);
        if (cp < 0x10000 || cp > 0x10FFFF) valid = 0;
      }
    }
    if (!valid) {
      *p = '?';
      p++;
      replaced++;
    } else {
      p += clen;
    }
  }
  return replaced;
}

void egg_format_duration(uint64_t sec, char *out, size_t outlen)
{
  op_strbuf_t s = {};
  op_strbuf_init(&s);
  uint64_t tmp;

  if (sec == 0) {
    op_strlcpy(out, "0 seconds", outlen);
    return;
  }
  op_strbuf_init(&s);
  if (sec >= 31536000) {
    tmp = sec / 31536000; sec -= tmp * 31536000;
    op_strbuf_appendf(&s, "%" PRIu64 " year%s ", tmp, tmp == 1 ? "" : "s");
  }
  if (sec >= 604800) {
    tmp = sec / 604800; sec -= tmp * 604800;
    op_strbuf_appendf(&s, "%" PRIu64 " week%s ", tmp, tmp == 1 ? "" : "s");
  }
  if (sec >= 86400) {
    tmp = sec / 86400; sec -= tmp * 86400;
    op_strbuf_appendf(&s, "%" PRIu64 " day%s ", tmp, tmp == 1 ? "" : "s");
  }
  if (sec >= 3600) {
    tmp = sec / 3600; sec -= tmp * 3600;
    op_strbuf_appendf(&s, "%" PRIu64 " hour%s ", tmp, tmp == 1 ? "" : "s");
  }
  if (sec >= 60) {
    tmp = sec / 60; sec -= tmp * 60;
    op_strbuf_appendf(&s, "%" PRIu64 " minute%s ", tmp, tmp == 1 ? "" : "s");
  }
  if (sec > 0)
    op_strbuf_appendf(&s, "%" PRIu64 " second%s", sec, sec == 1 ? "" : "s");
  size_t slen = op_strbuf_len(&s);
  if (slen > 0 && op_strbuf_str(&s)[slen - 1] == ' ')
    op_strbuf_truncate(&s, slen - 1);
  op_strlcpy(out, op_strbuf_str(&s), outlen);
  op_strbuf_free(&s);
}

void egg_format_uptime(time_t seconds, char *out, size_t outlen)
{
  op_strbuf_t s = {};

  op_strbuf_init(&s);
  if (seconds > 86400) {
    int days = (int)(seconds / 86400);
    op_strbuf_appendf(&s, "%d day%s, ", days, days >= 2 ? "s" : "");
    seconds -= days * 86400;
  }
  int hr = (int)(seconds / 3600);
  seconds -= hr * 3600;
  int min = (int)(seconds / 60);
  op_strbuf_appendf(&s, "%02d:%02d", hr, min);
  op_strlcpy(out, op_strbuf_str(&s), outlen);
  op_strbuf_free(&s);
}
