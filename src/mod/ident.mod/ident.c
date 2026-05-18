/*
 * ident.c -- part of ident.mod
 */
/*
 * Copyright (c) 2018 - 2019 Michael Ortmann MIT License
 * Copyright (C) 2019 - 2025 Eggheads Development Team
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

#define MODULE_NAME "ident"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "src/mod/module.h"
#include "server.mod/server.h"

constexpr int IDENT_METHOD_OIDENT  = 0;
constexpr int IDENT_METHOD_BUILTIN = 1;
constexpr int IDENT_SIZE           = 1000; /* rfc1413 */

static Function *global = nullptr, *server_funcs = nullptr;

static int ident_method = IDENT_METHOD_OIDENT;
static int ident_port = 113;

static tcl_ints identints[] = {
  {"ident-method", &ident_method, 0},
  {"ident-port",   &ident_port,   0},
  {nullptr,           nullptr,          0}
};

static void ident_builtin_off(void);

static cmd_t ident_raw[] = {
  {"001", "",   (IntFunc) ident_builtin_off, "ident:001"},
  {nullptr,  nullptr, nullptr,                        nullptr}
};

static void ident_activity(int idx, char *buf, int len)
{
  int s;
  char buf2[IDENT_SIZE + sizeof " : USERID : UNIX : \r\n" + NICKLEN], *pos;
  size_t count;
  ssize_t i;

  s = answer(dcc[idx].sock, &dcc[idx].sockname, 0, 0);
  killsock(dcc[idx].sock);
  dcc[idx].sock = s;
  if ((i = read(s, buf2, IDENT_SIZE)) < 0) {
    putlog(LOG_MISC, "*", "Ident error: %s", strerror(errno));
    return;
  }
  buf2[i] = 0;
  if (!(pos = strpbrk(buf2, "\r\n"))) {
    putlog(LOG_MISC, "*", "Ident error: could not read request.");
    return;
  }
  {
    op_strbuf_t _b = {};
    op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, " : USERID : UNIX : %s\r\n", botname);
    op_strlcpy(pos, op_strbuf_str(&_b), (sizeof buf2) - (size_t)(pos - buf2));
    op_strbuf_free(&_b);
  }
  count = strlen(buf2) + 1;
  if ((i = write(s, buf2, count)) != count) {
    if (i < 0)
      putlog(LOG_MISC, "*", "Ident error: %s", strerror(errno));
    else
      putlog(LOG_MISC, "*", "Ident error: Wrote %ld bytes instead of %ld bytes.", (long)i, (long)count);
    return;
  }
  putlog(LOG_MISC, "*", "Ident: Responded.");
  ident_builtin_off();
}

static void ident_display(int idx, op_strbuf_t *buf)
{
  op_strbuf_append_cstr(buf, "ident (ready)");
}

static struct dcc_table DCC_IDENTD = {
  "IDENTD",
  DCT_LISTEN,
  nullptr,
  ident_activity,
  nullptr,
  nullptr,
  ident_display,
  nullptr,
  nullptr,
  nullptr,
  nullptr
};

static void ident_oidentd(void)
{
  char *home = getenv("HOME");
  FILE *fd;
  op_strbuf_t data_buf = {}, identstr_buf = {}, path_buf = {};
  char line[256], buf[256];
  char s[EGG_INET_ADDRSTRLEN];
  int ret, prevtime, servidx;
  socklen_t namelen;
  struct sockaddr_storage ss;

  op_strbuf_appendf(&identstr_buf, "### eggdrop_%s", pid_file);
  const char *identstr = op_strbuf_str(&identstr_buf);

  if (!home) {
    putlog(LOG_MISC, "*",
           "Ident error: variable HOME is not in the current environment.");
    op_strbuf_free(&identstr_buf);
    return;
  }
  if (strlen(home) + sizeof("/.oidentd.conf") - 1 >= PATH_MAX) {
    putlog(LOG_MISC, "*", "Ident error: path too long.");
    op_strbuf_free(&identstr_buf);
    return;
  }
  op_strbuf_appendf(&path_buf, "%s/.oidentd.conf", home);
  const char *path = op_strbuf_str(&path_buf);
  op_strbuf_init(&data_buf);
  fd = fopen(path, "r");
  if (fd != nullptr) {
    while (fgets(line, 255, fd)) {
      /* If it is not an Eggdrop entry, don't mess with it */
      if (!strstr(line, "### eggdrop_")) {
        op_strbuf_append_cstr(&data_buf, line);
      } else {
        /* If it is Eggdrop but not me, check for expiration and remove */
        if (!strstr(line, identstr)) {
          char *saveptr = nullptr;
          op_strlcpy(buf, line, sizeof buf);
          strtok_r(buf, "!", &saveptr);
          prevtime = egg_atoi(strtok_r(nullptr, "!", &saveptr));
          if ((now - prevtime) > 300) {
            putlog(LOG_DEBUG, "*", "IDENT: Removing expired oident.conf "
                "entry: \"%s\"", buf);
          } else {
            op_strbuf_append_cstr(&data_buf, line);
          }
        }
      }
    }
    fclose(fd);
  } else if (errno != ENOENT)
    putlog(LOG_MISC, "*", "IDENT error: fopen(%s): %s", path, strerror(errno));
  /* To minimize a known race condition, this code is called now */
  servidx = -1;
  for (int i = 0; i < dcc_total; i++)
    if (dcc[i].status & STAT_SERV) {
      servidx = i;
      break;
    }
  if (servidx < 0 ) {
    putlog(LOG_MISC, "*", "IDENT: Error could not find server socket");
    op_strbuf_free(&data_buf);
    op_strbuf_free(&identstr_buf);
    op_strbuf_free(&path_buf);
    return;
  }
  namelen = sizeof ss;
  ret = getsockname(dcc[servidx].sock, (struct sockaddr *) &ss, &namelen);
  if (ret) {
    putlog(LOG_DEBUG, "*", "IDENT: Error getting socket info for writing");
  }
  fd = fopen(path, "w");
  if (fd != nullptr) {
    if (op_strbuf_len(&data_buf))
      fprintf(fd, "%s", op_strbuf_str(&data_buf));
    if (ss.ss_family == AF_INET) {
      struct sockaddr_in *saddr = (struct sockaddr_in *)&ss;
      fprintf(fd, "lport %" PRIu16 " from %s { reply \"%s\" } "
                "### eggdrop_%s !%" PRId64 "\n", ntohs(saddr->sin_port),
                inet_ntop(AF_INET, &(saddr->sin_addr), s, sizeof s),
                botuser, pid_file, (int64_t) now);
#ifdef IPV6
    } else if (ss.ss_family == AF_INET6) {
      struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)&ss;
      fprintf(fd, "lport %" PRIu16 " from %s { reply \"%s\" } "
                "### eggdrop_%s !%" PRId64 "\n", ntohs(saddr->sin6_port),
                inet_ntop(AF_INET6, &(saddr->sin6_addr), s, sizeof s),
                botuser, pid_file, (int64_t) now);
#endif
    } else {
      putlog(LOG_MISC, "*", "IDENT: Error writing oident.conf line");
    }
    fclose(fd);
  } else {
    putlog(LOG_MISC, "*", "IDENT: Error opening oident.conf for writing");
  }
  op_strbuf_free(&data_buf);
  op_strbuf_free(&identstr_buf);
  op_strbuf_free(&path_buf);
}

static void ident_builtin_on(void)
{
  int idx, s;

  debug0("Ident: Starting ident server.");
  for (idx = 0; idx < dcc_total; idx++)
    if (dcc[idx].type == &DCC_IDENTD)
      return;
  idx = new_dcc(&DCC_IDENTD, 0);
  if (idx < 0) {
    putlog(LOG_MISC, "*", "Ident error: could not get new dcc.");
    return;
  }
  s = open_listen(&ident_port);
  if (s == -2) {
    lostdcc(idx);
    putlog(LOG_MISC, "*", "Ident error: could not bind socket port %i.", ident_port);
    return;
  } else if (s == -1) {
    lostdcc(idx);
    putlog(LOG_MISC, "*", "Ident error: could not get socket.");
    return;
  }
  dcc[idx].sock = s;
  dcc[idx].port = ident_port;
  op_strlcpy(dcc[idx].nick, "(ident)", sizeof(dcc[idx].nick));
  add_builtins(H_raw, ident_raw);
}

static void ident_builtin_off(void)
{
  int idx;

  for (idx = 0; idx < dcc_total; idx++)
    if (dcc[idx].type == &DCC_IDENTD) {
      debug0("Ident: Stopping ident server.");
      killsock(dcc[idx].sock);
      lostdcc(idx);
      break;
    }
  rem_builtins(H_raw, ident_raw);
}

static void ident_ident(void)
{
  if (ident_method == IDENT_METHOD_OIDENT)
    ident_oidentd();
  else if (ident_method == IDENT_METHOD_BUILTIN)
    ident_builtin_on();
}

static cmd_t ident_event[] = {
  {"ident", "",   (IntFunc) ident_ident, "ident:ident"},
  {nullptr,    nullptr, nullptr,                  nullptr}
};

static char *ident_close(void)
{
  ident_builtin_off();
  rem_builtins(H_event, ident_event);
  rem_tcl_ints(identints);
  module_undepend(MODULE_NAME);
  return nullptr;
}

EXPORT_SCOPE char *ident_start(Function *global_funcs);

static Function ident_table[] = {
  (Function) ident_start,
  (Function) ident_close,
  nullptr,
  nullptr,
};

char *ident_start(Function *global_funcs)
{
  global = global_funcs;

  module_register(MODULE_NAME, ident_table, 1, 0);

  if (!module_depend(MODULE_NAME, "eggdrop", 109, 0)) {
    module_undepend(MODULE_NAME);
    return "This module requires Eggdrop 1.9.0 or later.";
  }
  if (!(server_funcs = module_depend(MODULE_NAME, "server", 1, 0))) {
    module_undepend(MODULE_NAME);
    return "This module requires server module 1.0 or later.";
  }

  add_builtins(H_event, ident_event);
  add_tcl_ints(identints);

  return nullptr;
}
