/*
 * python.c -- python interpreter handling for python.mod
 */

/*
 * Copyright (C) 2020 - 2025 Eggheads Development Team
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

#define MODULE_NAME "python"
#define MAKING_PYTHON
#define PY_SSIZE_T_CLEAN /* Not required for 3.13+ but here for back compat */

#define ARRAYCOUNT(x) (sizeof (x) / sizeof *(x))

#include "src/mod/module.h"
#undef interp
#define tclinterp (*(Tcl_Interp **)(global[128]))
#undef days
/* glibc features.h (pulled in via signal.h) defines _POSIX_C_SOURCE to a
 * newer value than Python's pyconfig.h expects; undef before Python headers
 * to suppress the redefinition warning. */
#undef _POSIX_C_SOURCE
#include <Python.h>
#include <datetime.h>
#include "src/mod/server.mod/server.h"
#include "src/mod/channels.mod/channels.h"
#include "src/mod/irc.mod/irc.h"
#include "python.h"
#ifndef HAVE_TCL
#  include "src/script.h"
#endif

static PyObject *pirp, *pglobals;

#undef global
static Function *global = NULL, *channels_funcs = NULL, *irc_funcs = NULL,
                *server_funcs = NULL;
static PyThreadState *_pythreadsave;
#include "pycmds.c"
#include "tclpython.c"

EXPORT_SCOPE char *python_start(Function *global_funcs);

static int python_expmem(void)
{
  /* Return the number of live Python heap blocks * sizeof(PyObject) as a
   * proxy for interpreter memory.  sys.getallocatedblocks() is the stable
   * public API for this; it does not include interpreter static overhead. */
  PyObject *sys, *result;
  Py_ssize_t blocks = 0;

  sys = PyImport_ImportModule("sys");
  if (sys) {
    result = PyObject_CallMethod(sys, "getallocatedblocks", NULL);
    if (result) {
      blocks = PyLong_AsSsize_t(result);
      Py_DECREF(result);
    }
    Py_DECREF(sys);
  }
  return (int)(blocks * (Py_ssize_t)sizeof(PyObject));
}

static int python_gil_unlock() {
  _pythreadsave = PyEval_SaveThread();
  return 0;
}

static int python_gil_lock() {
  PyEval_RestoreThread(_pythreadsave);
  return 0;
}

static char *init_python() {
  const char *venv;
  PyObject *pmodule;
  PyStatus status;
  PyConfig config;

  /* Force UTF-8 mode via PyPreConfig before touching PyConfig.
   * init_tcl1() calls setlocale(LC_CTYPE, "") before modules are loaded;
   * if the resulting locale has a non-UTF-8 encoding, Python 3.7+ attempts
   * a locale coercion (setlocale to "C.UTF-8").  On systems where that
   * locale is not installed the coercion fails with a *fatal* PyStatus,
   * which internally calls exit() before our PyStatus_Exception check on
   * Py_InitializeFromConfig can run, hard-crashing the process.
   * Py_PreInitialize with utf8_mode=1 skips the coercion step entirely and
   * is the correct behaviour for an embedded interpreter.
   * Note: utf8_mode lives in PyPreConfig for all Python versions (3.8+);
   * it was also mirrored in PyConfig through 3.13 but removed in 3.14. */
  {
    PyPreConfig preconfig;
    PyPreConfig_InitPythonConfig(&preconfig);
    preconfig.utf8_mode = 1;
    status = Py_PreInitialize(&preconfig);
    if (PyStatus_Exception(status))
      return "Python: Fatal error: Could not pre-initialize UTF-8 mode";
  }

  PyConfig_InitPythonConfig(&config);
  config.install_signal_handlers = 0;
  config.parse_argv = 0;
  if ((venv = getenv("VIRTUAL_ENV"))) {
    op_strbuf_t _b;
    op_strbuf_appendf(&_b, "%s/bin/python3", venv);
    const char *venvpython = op_strbuf_str(&_b);
    /* Validate the venv executable exists and is runnable before telling
     * Python to use it.  Py_InitializeFromConfig() issues a fatal (not just
     * exception) status for a missing executable, which internally calls
     * exit() before our PyStatus_Exception check can run, hard-crashing the
     * process with no useful message. */
    if (access(venvpython, X_OK) == 0) {
      status = PyConfig_SetBytesString(&config, &config.executable, venvpython);
      if (PyStatus_Exception(status)) {
        op_strbuf_free(&_b);
        PyConfig_Clear(&config);
        return "Python: Fatal error: Could not set venv executable";
      }
    }
    op_strbuf_free(&_b);
    /* else: venv executable is missing or broken; fall back to system Python */
  }
  status = PyConfig_SetBytesString(&config, &config.program_name, argv0);
  if (PyStatus_Exception(status)) {
    PyConfig_Clear(&config);
    return "Python: Fatal error: Could not set program base path";
  }
  if (PyImport_AppendInittab("eggdrop", &PyInit_eggdrop) == -1) {
    PyConfig_Clear(&config);
    return "Python: Error: could not extend in-built modules table";
  }
  status = Py_InitializeFromConfig(&config);
  if (PyStatus_Exception(status)) {
    PyConfig_Clear(&config);
    return "Python: Fatal error: Could not initialize config";
  }
  PyConfig_Clear(&config);
  /* PyDateTime_IMPORT expands to a PyCapsule_Import() call that can fail and
   * set a pending Python exception.  Clear any exception it leaves behind so
   * subsequent API calls are not short-circuited by a stale error indicator.
   * PyDateTimeAPI being NULL is caught when it is actually used (unlikely at
   * startup; the datetime module is always present in CPython). */
  PyDateTime_IMPORT;
  PyErr_Clear();
  pmodule = PyImport_ImportModule("eggdrop");
  if (!pmodule) {
    PyErr_Print();
    return "Error: could not import module 'eggdrop'";
  }

  pirp = PyImport_AddModule("__main__");
  if (!pirp) {
    /* Should never happen after a successful Py_InitializeFromConfig, but
     * guard anyway: PyModule_GetDict(NULL) is an immediate segfault. */
    Py_DECREF(pmodule);
    return "Python: Fatal error: could not get __main__ module";
  }
  pglobals = PyModule_GetDict(pirp);

  PyRun_SimpleString("import sys");
  /* Add the directory of the eggdrop binary to sys.path so that scripts
   * placed alongside the binary are importable regardless of CWD.
   * Use the C API directly rather than PyRun_SimpleString to avoid
   * constructing a Python string literal that could be malformed if argv0
   * contains characters like '"' or '\'. */
  {
    char eggdir[PATH_MAX];
    char *lastslash;
    PyObject *syspath, *dirobj;
    strlcpy(eggdir, argv0, sizeof eggdir);
    lastslash = strrchr(eggdir, '/');
    if (lastslash && lastslash != eggdir)
      *lastslash = '\0';
    else
      strlcpy(eggdir, ".", sizeof eggdir);
    syspath = PySys_GetObject("path"); /* borrowed reference */
    dirobj = PyUnicode_DecodeFSDefault(eggdir);
    if (syspath && dirobj)
      PyList_Append(syspath, dirobj);
    Py_XDECREF(dirobj);
  }
  PyRun_SimpleString("import eggdrop");
  PyRun_SimpleString("sys.displayhook = eggdrop.__displayhook__");

  return NULL;
}

static void python_report(int idx, int details)
{
  if (details) {
    /* Py_GetVersion() was deprecated in Python 3.13.  sys.version (via
     * PySys_GetObject) is the stable equivalent and won't be removed. */
    PyObject *pyver = PySys_GetObject("version"); /* borrowed reference */
    dprintf(idx, "    python version: %s (header version " PY_VERSION ")\n",
            pyver ? PyUnicode_AsUTF8(pyver) : PY_VERSION);
  }
}

static char *python_close(void)
{
  /* Forbid unloading, because:
   * - Reloading (Reexecuting PyDateTime_IMPORT) would crash
   * - Py_FinalizeEx() does not clean up everything
   * - Complexity regarding running python threads
   * see https://bugs.python.org/issue34309 for details
   */
  return "The " MODULE_NAME " module is not allowed to be unloaded.";
}

static Function python_table[] = {
  (Function) python_start,
  (Function) python_close,
  (Function) python_expmem,
  (Function) python_report
};

char *python_start(Function *global_funcs)
{
  char *s;

  /* Assign the core function table. After this point you use all normal
   * functions defined in src/mod/modules.h
   */
  if (global_funcs) {
    global = global_funcs;

    /* Register the module. */
    module_register(MODULE_NAME, python_table, 0, 1);
    if (!module_depend(MODULE_NAME, "eggdrop", 109, 0)) {
      module_undepend(MODULE_NAME);
      return "This module requires Eggdrop 1.9.0 or later.";
    }
    if ((s = init_python()))
      return s;
  }

  /* Require channels and server modules — the Python API exposes their
   * functions via macros that dereference these tables directly. */
  if (!(channels_funcs = module_depend(MODULE_NAME, "channels", 1, 1))) {
    module_undepend(MODULE_NAME);
    return "This module requires channels module 1.1 or later.";
  }
  if (!(server_funcs = module_depend(MODULE_NAME, "server", 1, 5))) {
    module_undepend(MODULE_NAME);
    return "This module requires server module 1.5 or later.";
  }
  {
    module_entry *me;
    me = module_find("irc", 0, 0);
    if (me)
      irc_funcs = me->funcs;
  }

  /* Add command table to bind list */
  add_builtins(H_dcc, mydcc);
#ifdef HAVE_TCL
  add_tcl_commands(my_tcl_cmds);
#else
  /* Register as the default script engine for no-Tcl builds */
  script_register(python_script_call, python_script_load);
  script_register_eval(python_script_eval);
  python_callbacks = PyDict_New();
#endif
  add_hook(HOOK_PRE_SELECT, (Function)python_gil_unlock);
  add_hook(HOOK_POST_SELECT, (Function)python_gil_lock);
  return NULL;
}
