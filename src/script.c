/*
 * script.c -- lightweight scripting engine registry for no-TCL builds.
 *
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
#include "script.h"

/* -------------------------------------------------------------------------
 * Simple variable store.
 *
 * Module bind-helper functions call Tcl_SetVar(interp, "_msgN", value, 0)
 * before calling check_tcl_bind().  In no-TCL builds the Tcl_SetVar macro
 * (defined in lush.h) forwards to egg_setvar() so those values are captured
 * here.  check_tcl_bind() then calls egg_getvar() when it parses the param
 * string (e.g. " $_msg1 $_msg2 $_msg3 $_msg4") to reconstruct argv[].
 *
 * 64 slots is well above the deepest set of variables used in the tree.
 * ------------------------------------------------------------------------- */

constexpr int EGG_MAXVARS    = 64;
constexpr int EGG_VARNAME_MAX = 64;
constexpr int EGG_VARVAL_MAX  = 1024;

static struct {
  char name[EGG_VARNAME_MAX];
  char value[EGG_VARVAL_MAX];
  int  used;
} egg_vars[EGG_MAXVARS];

void egg_setvar(const char *name, const char *value)
{
  if (!name)
    return;
  /* Update existing slot first */
  for (int i = 0; i < EGG_MAXVARS; i++) {
    if (egg_vars[i].used && !strcmp(egg_vars[i].name, name)) {
      strlcpy(egg_vars[i].value, value ? value : "", EGG_VARVAL_MAX);
      return;
    }
  }
  /* Allocate a new slot */
  for (int i = 0; i < EGG_MAXVARS; i++) {
    if (!egg_vars[i].used) {
      strlcpy(egg_vars[i].name,  name,            EGG_VARNAME_MAX);
      strlcpy(egg_vars[i].value, value ? value : "", EGG_VARVAL_MAX);
      egg_vars[i].used = 1;
      return;
    }
  }
  /* Should never happen; silently drop if the table is full */
}

const char *egg_getvar(const char *name)
{
  if (!name)
    return "";
  for (int i = 0; i < EGG_MAXVARS; i++) {
    if (egg_vars[i].used && !strcmp(egg_vars[i].name, name))
      return egg_vars[i].value;
  }
  return "";
}

/* -------------------------------------------------------------------------
 * Script engine registry.
 *
 * A single engine (typically the Python module) registers at load time.
 * check_tcl_bind() calls script_call() for bind entries that carry a
 * script-created func_name (e.g. "*python:msg:deadbeef").
 *
 * script_load() is called by readscript() (chanprog.c / configtoml.c) to
 * source .py files; .tcl files are routed to the Tcl interpreter when
 * available, otherwise warned about and skipped.
 * ------------------------------------------------------------------------- */

static script_call_t engine_call = NULL;
static script_load_t engine_load = NULL;

void script_register(script_call_t call, script_load_t load)
{
  engine_call = call;
  engine_load = load;
}

void script_unregister(script_call_t call)
{
  if (engine_call == call) {
    engine_call = NULL;
    engine_load = NULL;
  }
}

int script_call(const char *name, int argc, const char **argv)
{
  if (!engine_call)
    return 0;
  return engine_call(name, argc, argv);
}

int script_load(const char *fname)
{
  if (!engine_load) {
    putlog(LOG_MISC, "*", "script: no script engine loaded, cannot source: %s", fname);
    return -1;
  }
  return engine_load(fname);
}
