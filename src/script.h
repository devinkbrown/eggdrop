/*
 * script.h -- lightweight scripting engine registry (no-TCL builds).
 *
 * When Tcl is present the existing Tcl bind machinery is used unchanged.
 * When Tcl is absent this header declares:
 *
 *   egg_setvar / egg_getvar
 *     A simple name→value store.  The Tcl_SetVar stubs in lush.h redirect
 *     to egg_setvar so that the "set args, call check_tcl_bind" pattern used
 *     in module bind-helper functions continues to work.
 *
 *   script_register / script_unregister / script_call / script_load
 *     A single-engine vtable.  The python module calls script_register() at
 *     startup and script_call() is invoked by check_tcl_bind() for every
 *     bind entry whose func_name starts with '*python:'.
 */

#ifndef _EGG_SCRIPT_H
#define _EGG_SCRIPT_H

/* Variable store — populated by Tcl_SetVar stubs, read by check_tcl_bind */
void        egg_setvar(const char *name, const char *value);
const char *egg_getvar(const char *name);

/* Script engine interface */
typedef int (*script_call_t)(const char *name, int argc, const char **argv);
typedef int (*script_load_t)(const char *fname);
typedef int (*script_eval_t)(const char *script);

void script_register(script_call_t call, script_load_t load);
void script_register_eval(script_eval_t eval);
void script_unregister(script_call_t call);
int  script_call(const char *name, int argc, const char **argv);
int  script_load(const char *fname);
int  script_eval(const char *script);
int  script_eval(const char *script);

/* -------------------------------------------------------------------------
 * Unified script evaluation.
 *
 * egg_eval() replaces direct Tcl_Eval / Tcl_VarEval calls in core code,
 * routing scripts to the Tcl interpreter when available or to the registered
 * script engine (Python) otherwise.
 *
 * After calling egg_eval(), use tcl_resultstring() / tcl_resultint() /
 * tcl_resultempty() to inspect the result (these work in both build modes).
 *
 * Returns: 0 on success, non-zero on error (mirrors TCL_OK / TCL_ERROR).
 * ------------------------------------------------------------------------- */
#ifndef MAKING_MODS
int  egg_eval(const char *script);
int  egg_eval_log(const char *context, const char *script);
#endif

#endif /* _EGG_SCRIPT_H */
