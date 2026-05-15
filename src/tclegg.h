/*
 * tclegg.h
 *   stuff used by tcl.c and tclhash.c
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

#ifndef _EGG_TCLEGG_H
#define _EGG_TCLEGG_H

#include "lush.h"   /* always: provides Tcl types or stubs */

#ifndef MAKING_MODS
#  include "proto.h"
#endif


/*
 * Wow, this is old...CMD_LEAVE goes back to before version 0.9.
 * This is for partyline and filesys 'quit'.
 */
#define CMD_LEAVE (Function)(-1)


/* Match types for check_tcl_bind(). */
constexpr int MATCH_PARTIAL = 0;
constexpr int MATCH_EXACT   = 1;
constexpr int MATCH_MASK    = 2;
constexpr int MATCH_CASE    = 3;
constexpr int MATCH_MODE    = 4;
constexpr int MATCH_CRON    = 5;

/*
 * Bitwise 'or' these:
 */

/* Check flags; make sure the user has the flags required. */
constexpr int BIND_USE_ATTR     = 0x010;

/* Bind is stackable; more than one bind can have the same name. */
constexpr int BIND_STACKABLE    = 0x020;

/* Additional flag checking; check for +d, +k, etc.
 * Currently used for dcc, fil, msg, and pub bind types.
 * Note that this just causes the flag checking to use flagrec_ok()
 * instead of flagrec_eq().
 */
constexpr int BIND_HAS_BUILTINS = 0x040;

/* Want return; we want to know if the proc returns 1.
 * Side effect: immediate return; don't do any further
 * processing of stacked binds.
 */
constexpr int BIND_WANTRET      = 0x080;

/* Alternate args; replace args with the return result from the Tcl proc. */
constexpr int BIND_ALTER_ARGS   = 0x100;

/* Stacked return; we want to know if any proc returns 1,
 * and also want to process all stacked binds.
 */
constexpr int BIND_STACKRET     = 0x200;


/* Return values. */
constexpr int BIND_NOMATCH   = 0;
constexpr int BIND_AMBIGUOUS = 1;
constexpr int BIND_MATCHED   = 2; /* But the proc couldn't be found */
constexpr int BIND_EXECUTED  = 3;
constexpr int BIND_EXEC_LOG  = 4; /* Proc returned 1 -> wants to be logged */
constexpr int BIND_QUIT      = 5; /* CMD_LEAVE 'quit' from partyline or filesys */

/* Extra commands are stored in Tcl hash tables (one hash table for each type
 * of command: msg, dcc, etc).
 */
typedef struct timer_str {
  struct timer_str *next;
  time_t fire_at;               /* Absolute wall-clock fire time        */
  unsigned int count;           /* Number of repeats (0 = infinite)     */
  unsigned int interval;        /* Original elapse in ticks             */
  int secs_per_tick;            /* 1 = utimer (seconds), 60 = timer (minutes) */
  char *cmd;                    /* Command linked to                    */
  unsigned long id;             /* Used to remove timers                */
  char *name;                   /* User-specified name for timer        */
  struct ev_entry *ev;          /* op_event handle                      */
} tcl_timer_t;


/* Used for Tcl stub functions — only meaningful when Tcl is present */
#ifdef HAVE_TCL

#define STDVAR (ClientData cd, Tcl_Interp *irp, int argc, char *argv[])

#define STDOBJVAR (ClientData cd, Tcl_Interp *irp, int objc, Tcl_Obj *const objv[])

#define BADARGS(nl, nh, example) do {                                   \
        if ((argc < (nl)) || ((argc > (nh)) && ((nh) != -1))) {         \
                Tcl_AppendResult(irp, "wrong # args: should be \"",     \
                                 argv[0], (example), "\"", nullptr);       \
                return TCL_ERROR;                                       \
        }                                                               \
} while (0)

#define BADOBJARGS(nl, nh, prefix, example) do {                        \
        if ((objc < (nl)) || ((objc > (nh)) && ((nh) != -1))) {         \
                Tcl_WrongNumArgs(irp, prefix, objv, example);           \
                return TCL_ERROR;                                       \
        }                                                               \
} while (0)

#define CHECKVALIDITY(a)        do {                                    \
        if (!check_validity(argv[0], (a))) {                            \
                Tcl_AppendResult(irp, "bad builtin command call!",      \
                                 nullptr);                                 \
                return TCL_ERROR;                                       \
        }                                                               \
} while (0)

#define tcl_dict_append(ds, key, val) do { \
  Tcl_DStringAppendElement((ds), (key));   \
  Tcl_DStringAppendElement((ds), (val));   \
} while (0)

#endif /* HAVE_TCL */

char * add_timer(tcl_timer_t **, int, int, char *, char *, unsigned long);
int find_timer(tcl_timer_t *, char *);
int remove_timer(tcl_timer_t **, char *);
void do_check_timers(tcl_timer_t **);
/* list_timers and wipe_timers take a Tcl_Interp * but compile in both
 * configurations because lush.h provides 'typedef void Tcl_Interp' when
 * Tcl is absent, making the parameter a plain void *.
 */
void list_timers(Tcl_Interp *, tcl_timer_t *);
void wipe_timers(Tcl_Interp *, tcl_timer_t **);

typedef struct _tcl_strings {
  char *name;
  char *buf;
  int length;
  int flags;
} tcl_strings;

typedef struct _tcl_int {
  char *name;
  int *val;
  int readonly;
} tcl_ints;

typedef struct _tcl_coups {
  char *name;
  int *lptr;
  int *rptr;
} tcl_coups;

typedef struct _tcl_cmds {
  char *name;
  IntFunc func;
} tcl_cmds;

typedef struct _cd_tcl_cmd {
  const char *name;
  IntFunc callback;
  void *cdata;
} cd_tcl_cmd;

void add_tcl_commands(tcl_cmds *);
void add_tcl_objcommands(tcl_cmds *);
void add_cd_tcl_cmds(cd_tcl_cmd *);
void rem_tcl_commands(tcl_cmds *);
void add_tcl_strings(tcl_strings *);
void rem_tcl_strings(tcl_strings *);
void add_tcl_coups(tcl_coups *);
void rem_tcl_coups(tcl_coups *);
void add_tcl_ints(tcl_ints *);
void rem_tcl_ints(tcl_ints *);
const char *tcl_resultstring(void);
int tcl_resultint(void);
int tcl_resultempty(void);
int tcl_threaded(void);
int fork_before_tcl(void);
/* get_expire_time takes Tcl_Interp * but compiles in both configurations
 * because lush.h provides a void typedef when Tcl is absent.
 */
time_t get_expire_time(Tcl_Interp *, const char *);

/* Variable registry helpers — write/read C globals through the
 * registered tcl_strings/ints/coups tables.  In Tcl builds these
 * delegate to Tcl_SetVar/Tcl_GetVar; in no-Tcl builds they walk
 * the tables directly.  Always available so callers need no ifdefs.
 */
void notcl_setvar(const char *name, const char *value);
const char *notcl_getvar(const char *name, char *buf, size_t bufsz);

#endif /* _EGG_TCLEGG_H */
