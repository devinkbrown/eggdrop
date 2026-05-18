/*
 * isupport.c -- part of server.mod
 *   handles raw 005 (isupport)
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

#include "src/mod/module.h"
#include "server.h"

typedef struct isupport {
  const char *key, *value, *defaultvalue;
} isupport_t;

static op_htab *isupport_ht = nullptr;
static p_tcl_bind_list H_isupport;
static op_bh *isupport_bh = nullptr;
static const char isupport_default[4096] = "CASEMAPPING=rfc1459 CHANNELLEN=200 NICKLEN=9 CHANTYPES=#& PREFIX=(ov)@+ CHANMODES=b,k,l,imnpst MODES=3 MAXCHANNELS=10 TOPICLEN=250 KICKLEN=250 STATUSMSG=@+";

static int hexdigit2dec[128] = {
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*   0 -   9 */
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*  10 -  19 */
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*  20 -  29 */
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*  30 -  39 */
  -1, -1, -1, -1, -1, -1, -1, -1,  0,  1, /*  40 -  49 */
   2,  3,  4,  5,  6,  7,  8,  9, -1, -1, /*  50 -  59 */
  -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, /*  60 -  69 */
  15, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*  70 -  79 */
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*  80 -  89 */
  -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, /*  90 -  99 */
  13, 14, 15, -1, -1, -1, -1, -1, -1, -1, /* 100 - 109 */
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 110 - 119 */
  -1, -1, -1, -1, -1, -1, -1, -1          /* 120 - 127 */
};

int tcl_isupport STDOBJVAR;
int isupport_bind STDVAR;
int check_tcl_isupport(struct isupport *data, const char *key, const char *value);
char *traced_isupport(ClientData cdata, Tcl_Interp *irp, EGG_CONST char *name1, EGG_CONST char *name2, int flags);

static tcl_cmds my_tcl_objcmds[] = {
  {"isupport", tcl_isupport},
  {nullptr,       nullptr        }
};

/*** Utility functions ***/

static char *strrangedup(const char *value, size_t len) {
  char *str = op_malloc(len + 1);
  memcpy(str, value, len);
  str[len] = '\0';
  return str;
}

static char *strrangedup_toupper(const char *value, size_t len) {
  char *str = op_malloc(len + 1);

  int i = 0;
  for (; i < len; i++) {
    str[i] = toupper((unsigned char)value[i]);
  }
  str[i] = '\0';
  return str;
}


/* Parse a 005 value that is expected to be an int.
   Args are:
    - key
    - value (a string numeric)
    - minimum expected value
    - maximum expected value
    - truncate into allowed range if outside allowed range?
    - default value to use if outside allowed range
 */
int isupport_parseint(const char *key, const char *value, int min, int max, int truncate, int defaultvalue, int *dst)
{
  long result;
  char *tmp;

  if (!value) {
    /* not set at all => default value, not an error, happens on disconnect */
    *dst = defaultvalue;
    return 0;
  }
  result = strtol(value, &tmp, 0);
  if (*tmp != '\0') {
    putlog(LOG_MISC, "*", "Error while parsing ISUPPORT intvalue for key '%s'='%s': Not an integer, using default value %d", key, value, defaultvalue);
    *dst = defaultvalue;
    return -1;
  }
  if ((result < min || result > max) && !truncate) {
    putlog(LOG_MISC, "*", "Error while parsing ISUPPORT intvalue for key '%s'='%s': Out of range (violated constraint %d <= %ld <= %d), using default value %d", key, value, min, result, max, defaultvalue);
    *dst = defaultvalue;
    return -2;
  }
  if (result < min) {
    putlog(LOG_MISC, "*", "Warning while parsing ISUPPORT intvalue for key '%s'='%s': Out of range, truncating %ld to minimum %d", key, value, result, min);
    result = min;
  } else if (result > max) {
    putlog(LOG_MISC, "*", "Warning while parsing ISUPPORT intvalue for key '%s'='%s': Out of range, truncating %ld to maximum %d", key, value, result, max);
    result = max;
  }
  *dst = (int)result;
  return 0;
}

/*** isupport key record managing functions ***/

static void isupport_free(struct isupport *data) {
  op_free((void *)data->key);
  if (data->value)
    op_free((void *)data->value);
  if (data->defaultvalue)
    op_free((void *)data->defaultvalue);
  op_bh_free(isupport_bh, data);
}

static struct isupport *add_record(const char *key, size_t keylen) {
  if (!isupport_bh) {
    isupport_bh = op_bh_create(sizeof(isupport_t), 32, "isupport");
    isupport_ht = op_htab_create_str("isupport", 32);
  }
  struct isupport *data = op_bh_alloc(isupport_bh);
  data->key = strrangedup_toupper(key, keylen);
  op_htab_set(isupport_ht, (void *)data->key, data, nullptr);
  return data;
}

static void del_record(struct isupport *data) {
  op_htab_del(isupport_ht, (void *)data->key);
  isupport_free(data);
}

/* find record — O(1) via hash table */
static struct isupport *find_record(const char *key, size_t keylen) {
  char upper[256];
  size_t n = keylen < sizeof upper - 1 ? keylen : sizeof upper - 1;
  for (size_t i = 0; i < n; i++)
    upper[i] = (char)toupper((unsigned char)key[i]);
  upper[n] = '\0';
  return (struct isupport *)op_htab_get(isupport_ht, upper);
}

/* find record in list for key, case insensitive, create record if it does not exist */
static struct isupport *get_record(const char *key, size_t keylen) {
  struct isupport *data = find_record(key, keylen);

  if (!data)
    data = add_record(key, keylen);

  return data;
}

const char *isupport_get_from_record(struct isupport *data)
{
  return data->value ? data->value : data->defaultvalue;
}

const char *isupport_get(const char *key, size_t keylen)
{
  struct isupport *data = find_record(key, keylen);

  return data ? isupport_get_from_record(data) : nullptr;
}

static void isupport_set_value(const char *key, size_t keylen, const char *value, size_t valuelen, int setdefault)
{
  int ret = 0;
  const char *old;
  char *new;
  struct isupport *data = get_record(key, keylen);

  if (setdefault && data->defaultvalue && strlen(data->defaultvalue) == valuelen && !strncmp(data->defaultvalue, value, valuelen))
    return;
  if (!setdefault && data->value && strlen(data->value) == valuelen && !strncmp(data->value, value, valuelen))
    return;

  old = isupport_get_from_record(data);
  new = strrangedup(value, valuelen);

  if (!old || strcmp(old, new)) {
    ret = check_tcl_isupport(data, data->key, new);
  }
  if (!setdefault && ret) {
    if (!data->defaultvalue && !data->value) {
      del_record(data);
    }
    op_free(new);
  } else {
    if (setdefault) {
      if (data->defaultvalue) {
        op_free((void *)data->defaultvalue);
      }
      data->defaultvalue = new;
    } else {
      if (data->value) {
        op_free((void *)data->value);
      }
      data->value = new;
    }
  }
}

void isupport_set(const char *key, size_t keylen, const char *value, size_t valuelen)
{
  isupport_set_value(key, keylen, value, valuelen, 0);
}

void isupport_setdefault(const char *key, size_t keylen, const char *value, size_t valuelen)
{
  isupport_set_value(key, keylen, value, valuelen, 1);
}

void isupport_unset(const char *key, size_t keylen)
{
  struct isupport *data = find_record(key, keylen);

  if (!data) {
    return;
  }
  /* does not unset default values */
  if (data->value) {
    int ret = check_tcl_isupport(data, data->key, nullptr);
    if (!ret) {
      if (data->defaultvalue) {
        op_free((void *)data->value);
        data->value = nullptr;
      } else {
        del_record(data);
      }
    }
  }
}

/*** isupport parse/setstr ***/

static int isupport_hex2chr(const char *seq, size_t digits) {
  int result = 0;
  int digit;
  while (digits--) {
    result *=  16;
    digit = hexdigit2dec[(int)(unsigned char)*seq++];
    if (digit == -1)
      return -1;
    result += digit;
  }
  /* disallow \x00 */
  return result ? result : -1;
}

static const char *isupport_encode(const char *value) {
  static char buf[512];
  int i, j;

  for (i = j = 0; i < strlen(value) && j < sizeof buf - strlen("\\xHH") - 1; i++) {
    if ((unsigned char)value[i] < 33 || (unsigned char)value[i] > 126) {
      static const char _hex[] = "0123456789abcdef";
      unsigned char _c = (unsigned char)value[i];
      buf[j++] = '\\';
      buf[j++] = 'x';
      buf[j++] = _hex[_c >> 4];
      buf[j++] = _hex[_c & 0xf];
    }
    else
      buf[j++] = value[i];
  }
  buf[j] = '\0';
  return buf;
}

static size_t isupport_decode(char *buf, size_t bufsize,
    const char *value, size_t len)
{
  const char *ch;
  char *bufptr = buf;
  int state = 0, hexchr;

  for (ch = value; (ch - value) < len && (bufptr - buf) < bufsize - 1; ch++) {
    if (state == 0 && *ch == '\\') {
      state++;
    } else if (state == 1) {
      if (*ch != 'x')
        goto rollback;
      state++;
    } else if (state == 2) {
      hexchr = isupport_hex2chr(ch, 2);
      if (hexchr == -1)
        goto rollback;
      *bufptr++ = hexchr;
      ch++;
      state = 0;
    } else {
rollback:
      if (state > 0)
        *bufptr++ = '\\';
      if (state > 1)
        *bufptr++ = 'x';
      state = 0;
      *bufptr++ = *ch;
    }
  }
  *bufptr = '\0';
  return (size_t)(bufptr - buf);
}

static void isupport_parse(const char *str,
    void (*set_cb)(const char *key, size_t keylen, const char *v, size_t vlen))
{
  static char buf[512];
  size_t keylen, valuelen;
  const char *key, *value;

  while (1) {
    while (*str == ' ')
      str++;
    /* :are supported by this server */
    if (!*str || *str == ':')
      break;
    key = str;
    keylen = strcspn(key, "= ");
    if (key[0] == '-') {
      putlog(LOG_MISC, "*", "isupport unsetting with -KEY is not supported, please report this");
      str = key + keylen;
    } else {
      value = key + keylen + (key[keylen] == '=');
      valuelen = strcspn(value, " ");
      valuelen = isupport_decode(buf, sizeof buf, value, valuelen);
      if (set_cb) {
        set_cb(key, keylen, buf, valuelen);
      }
      str = value + valuelen;
    }
  }
}


/*** Module utility functions ***/


void isupport_clear(void) {
  if (!isupport_ht)
    return;
  op_htab_iter_t it;
  op_htab_iter_init(isupport_ht, &it);
  void *k, *v;
  while (op_htab_iter_next(isupport_ht, &it, &k, &v)) {
    struct isupport *data = (struct isupport *)v;
    op_free((void *)data->key);
    if (data->value)        op_free((void *)data->value);
    if (data->defaultvalue) op_free((void *)data->defaultvalue);
    op_bh_free(isupport_bh, data);
  }
  op_htab_destroy(isupport_ht, nullptr, nullptr);
  isupport_ht = nullptr;
}

void isupport_clear_values(int cleardefaultvalues) {
  if (!isupport_ht)
    return;
  op_htab_iter_t it;
  op_htab_iter_init(isupport_ht, &it);
  void *k, *v;
  while (op_htab_iter_next(isupport_ht, &it, &k, &v)) {
    struct isupport *data = (struct isupport *)v;
    if ((cleardefaultvalues && data->defaultvalue) || (!cleardefaultvalues && data->value)) {
      if (cleardefaultvalues && data->value) {
        /* no bind trigger, value > defaultvalue, this does not change the effective value */
        /* and the bind should never be allowed to prevent changing default values */
        op_free((void *)data->defaultvalue);
        data->defaultvalue = nullptr;
      } else if (!cleardefaultvalues && data->defaultvalue) {
        if (!strcmp(data->value, data->defaultvalue) || !check_tcl_isupport(data, data->key, data->defaultvalue)) {
          op_free((void *)data->value);
          data->value = nullptr;
        }
      } else {
        if (!check_tcl_isupport(data, data->key, nullptr)) {
          /* entry will be empty, delete it — use iter_del to stay safe */
          op_htab_iter_del(isupport_ht, &it);
          isupport_free(data);
        }
      }
    }
  }
}

/* moved out of isupport_init because the following problem:
 * loadmodule irc (wants isupport binds)
 * -> loadmodule server
 * -> isupport_init (create H_isupport and do server.mod binds)
 * -> parse defaults and call binds -- but irc binds cannot be added before H_isupport exists
 * then irc.mod adds isupport binds, but those will not be called for the default values unless they change
 * this is not necessary before each connect, just before the very first one to trigger default binds
 */
void isupport_preconnect(void) {
  const char *def = Tcl_GetVar(interp, "isupport-default", TCL_GLOBAL_ONLY);
  if (!def)
    def = isupport_default;
  isupport_parse(def, isupport_setdefault);
}

void isupport_init(void) {
  H_isupport = add_bind_table("isupport", HT_STACKABLE, isupport_bind);
  /* Must be added after reading, if the variable was set before loading mod. */
  Tcl_TraceVar(interp, "isupport-default",
               TCL_TRACE_READS | TCL_TRACE_WRITES | TCL_TRACE_UNSETS,
               traced_isupport, nullptr);
  add_tcl_objcommands(my_tcl_objcmds);
}

void isupport_fini(void) {
  del_bind_table(H_isupport);
  Tcl_UntraceVar(interp, "isupport-default",
                 TCL_TRACE_READS | TCL_TRACE_WRITES | TCL_TRACE_UNSETS,
                 traced_isupport, nullptr);
  rem_tcl_commands(my_tcl_objcmds);
  isupport_clear(); /* destroys isupport_ht */
  if (isupport_bh) {
    op_bh_destroy(isupport_bh);
    isupport_bh = nullptr;
  }
}

size_t isupport_expmem(void) {
  size_t bytes = 0;
  if (!isupport_ht)
    return 0;
  op_htab_iter_t it;
  op_htab_iter_init(isupport_ht, &it);
  void *k, *v;
  while (op_htab_iter_next(isupport_ht, &it, &k, &v)) {
    struct isupport *data = (struct isupport *)v;
    bytes += sizeof *data;
    if (data->value)        bytes += strlen(data->value) + 1;
    if (data->defaultvalue) bytes += strlen(data->defaultvalue) + 1;
    if (data->key)          bytes += strlen(data->key) + 1;
  }
  return bytes;
}

/*** .status information ***/

#define FITS_INTO(len, key, value) ((strlen((key)) + ((value) ? strlen((value)) : 0) + 2) < (len))

static void isupport_stringify(int idx, char *buf, size_t bufsize, size_t *len,
    size_t prefixlen, const char *key, const char *value)
{
  if (value)
    value = isupport_encode(value);
  if (!FITS_INTO(bufsize - *len, key, value)) {
    dprintf(idx, "%s\n", buf);
    *len = prefixlen;
    if (!FITS_INTO(bufsize - *len, key, value)) {
      dprintf(idx, "    isupport info too long to display.\n");
      return;
    }
  }
  op_strlcat(buf + *len, " ", bufsize - *len);
  op_strlcat(buf + *len, key, bufsize - *len);
  if (value && value[0]) {
    op_strlcat(buf + *len, "=", bufsize - *len);
    op_strlcat(buf + *len, value, bufsize - *len);
  }
  *len = strlen(buf);
}

void isupport_report(int idx, const char *prefix, int details)
{
  char buf[450];
  size_t prefixlen, len;

  if (!server_online)
    return;

  {
    op_strbuf_t _b = {};
    op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "%sisupport:", prefix);
    op_strlcpy(buf, op_strbuf_str(&_b), sizeof buf);
    op_strbuf_free(&_b);
  }
  len = prefixlen = strlen(buf);
  if (isupport_ht) {
    op_htab_iter_t it;
    op_htab_iter_init(isupport_ht, &it);
    void *k, *v;
    while (op_htab_iter_next(isupport_ht, &it, &k, &v)) {
      struct isupport *data = (struct isupport *)v;
      isupport_stringify(idx, buf, sizeof buf, &len, prefixlen, data->key, isupport_get_from_record(data));
    }
  }
  if (len > prefixlen)
    dprintf(idx, "%s\n", buf);

  if (details) {
    {
      op_strbuf_t _b = {};
      op_strbuf_init(&_b);
      op_strbuf_appendf(&_b, "%sisupport (default):", prefix);
      op_strlcpy(buf, op_strbuf_str(&_b), sizeof buf);
      op_strbuf_free(&_b);
    }
    len = prefixlen = strlen(buf);
    if (isupport_ht) {
      op_htab_iter_t it2;
      op_htab_iter_init(isupport_ht, &it2);
      void *k2, *v2;
      while (op_htab_iter_next(isupport_ht, &it2, &k2, &v2)) {
        struct isupport *data = (struct isupport *)v2;
        if (data->defaultvalue)
          isupport_stringify(idx, buf, sizeof buf, &len, prefixlen, data->key, data->defaultvalue);
      }
    }
    if (len > prefixlen)
      dprintf(idx, "%s\n", buf);
  }
}

static const char *isupport_get_prefixchars(void)
{
  const char *str = isupport_get("PREFIX", strlen("PREFIX"));

  if (str) {
    str = strchr(str, ')');
    if (str && str[1]) {
      return str + 1;
    }
  }
  return "+%@&~";
}
