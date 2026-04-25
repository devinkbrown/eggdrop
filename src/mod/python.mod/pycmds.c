/*
 * pycmds.c -- python.mod python functions
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
#define PY_SSIZE_T_CLEAN
#include <stdint.h>
#include <inttypes.h>

#ifdef HAVE_TCL
typedef struct {
  PyObject_HEAD
  char tclcmdname[128];
} TclFunc;

static PyTypeObject TclFuncType;
#endif /* HAVE_TCL */

typedef struct {
  PyObject_HEAD
  char tclcmdname[128];
  char *flags;
  char *mask;
  tcl_bind_list_t *bindtable;
  PyObject *callback;
} PythonBind;

static PyTypeObject PythonBindType;
static int eval_idx = -1;

static PyObject *EggdropError;      //create static Python Exception object

#ifndef HAVE_TCL
/* Dict mapping tclcmdname → PythonBind object for no-Tcl dispatch.
 * python_script_call() looks up entries here when check_tcl_bind() fires. */
static PyObject *python_callbacks;  /* {str: PythonBind} */
#endif

#ifdef HAVE_TCL
static Tcl_Obj *py_to_tcl_obj(PyObject *o); // generic conversion function
#endif

static PyObject *py_displayhook(PyObject *self, PyObject *o) {
  PyObject *pstr;

  if (o) {
    pstr = PyObject_Repr(o);
    if (pstr) {
      dprintf(eval_idx, "Python: %s\n", PyUnicode_AsUTF8(pstr));
      Py_DECREF(pstr);
    }
  }
  Py_RETURN_NONE;
}

static void cmd_python(struct userrec *u, int idx, char *par) {
  PyObject *pobj;
  PyObject *pystr, *module_name, *pymodule, *pyfunc, *pyval, *item;
  Py_ssize_t n;
  int i;

  if (!isowner(dcc[idx].nick) && must_be_owner) {
    dprintf(idx, "%s", MISC_NOSUCHCMD);
    return;
  }

  PyErr_Clear();

  // Expression output redirection via sys.displayhook
  eval_idx = idx;
  pobj = PyRun_String(par, Py_single_input, pglobals, pglobals);

  if (pobj) {
    // always None
    Py_DECREF(pobj);
  } else if (PyErr_Occurred()) {
#if PY_VERSION_HEX >= 0x030C0000
    /* Python 3.12+: PyErr_Fetch() was deprecated in 3.12 and removed in 3.14.
     * PyErr_GetRaisedException() returns the current exception (already
     * normalized) and clears the interpreter's error indicator. */
    PyObject *exc = PyErr_GetRaisedException();
    pystr = PyObject_Str(exc);
    // Get "pretty" error result
    dprintf(eval_idx, "Python Error: %s\n", PyUnicode_AsUTF8(pystr));
    Py_DECREF(pystr);
    module_name = PyUnicode_FromString("traceback");
    pymodule = PyImport_Import(module_name);
    Py_DECREF(module_name);
    // format backtrace and print (format_exception(exc) — single-arg form, Python 3.10+)
    pyfunc = PyObject_GetAttrString(pymodule, "format_exception");
    if (pyfunc && PyCallable_Check(pyfunc)) {
      pyval = PyObject_CallFunctionObjArgs(pyfunc, exc, NULL);
      // Check if traceback is a list and handle as such
      if (pyval && PyList_Check(pyval)) {
        n = PyList_Size(pyval);
        for (i = 0; i < n; i++) {
          item = PyList_GetItem(pyval, i);
          pystr = PyObject_Str(item);
          dprintf(idx, "%s", PyUnicode_AsUTF8(pystr));
        }
      } else {
        pystr = PyObject_Str(pyval);
        dprintf(idx, "%s", PyUnicode_AsUTF8(pystr));
      }
      Py_XDECREF(pyval);
    }
    Py_XDECREF(pyfunc);
    Py_DECREF(pymodule);
    Py_XDECREF(exc);
#else
    /* Python < 3.12: use the legacy three-component exception API. */
    PyObject *ptype, *pvalue, *ptraceback;
    PyErr_Fetch(&ptype, &pvalue, &ptraceback);
    pystr = PyObject_Str(pvalue);
    // Get "pretty" error result
    dprintf(eval_idx, "Python Error: %s\n", PyUnicode_AsUTF8(pystr));
    module_name = PyUnicode_FromString("traceback");
    pymodule = PyImport_Import(module_name);
    Py_DECREF(module_name);
    // format backtrace and print
    pyfunc = PyObject_GetAttrString(pymodule, "format_exception");
    if (pyfunc && PyCallable_Check(pyfunc)) {
      pyval = PyObject_CallFunctionObjArgs(pyfunc, ptype, pvalue, ptraceback, NULL);
      // Check if traceback is a list and handle as such
      if (pyval && PyList_Check(pyval)) {
        n = PyList_Size(pyval);
        for (i = 0; i < n; i++) {
          item = PyList_GetItem(pyval, i);
          pystr = PyObject_Str(item);
          dprintf(idx, "%s", PyUnicode_AsUTF8(pystr));
        }
      } else {
        pystr = PyObject_Str(pyval);
        dprintf(idx, "%s", PyUnicode_AsUTF8(pystr));
      }
      Py_XDECREF(pyval);
    }
    Py_XDECREF(ptype);
    Py_XDECREF(pvalue);
    Py_XDECREF(ptraceback);
#endif
  }
  return;
}

static PyObject *make_ircuser_dict(memberlist *m) {
  PyObject *result = PyDict_New();
  PyDict_SetItemString(result, "nick", PyUnicode_FromString(m->nick));
  PyDict_SetItemString(result, "host", PyUnicode_FromString(m->userhost));
  if (m->joined) {
    PyObject *tmp = PyTuple_New(1);
    PyTuple_SET_ITEM(tmp, 0, PyFloat_FromDouble((double)m->joined));
    PyDict_SetItemString(result, "joined", PyDateTime_FromTimestamp(tmp));
  }
  if (m->last) {
    PyObject *tmp = PyTuple_New(1);
    PyTuple_SET_ITEM(tmp, 0, PyFloat_FromDouble((double)m->last));
    PyDict_SetItemString(result, "lastseen", PyDateTime_FromTimestamp(tmp));
  }
  PyDict_SetItemString(result, "account", m->account[0] ? PyUnicode_FromString(m->account) : Py_None);
  return result;
}

static PyObject *py_findircuser(PyObject *self, PyObject *args) {
  char *nick, *chan = NULL;

  if (!PyArg_ParseTuple(args, "s|s", &nick, &chan)) {
    PyErr_SetString(EggdropError, "wrong number of args");
    return NULL;
  }
  for (struct chanset_t *ch = chan ? findchan_by_dname(chan) : chanset; ch; ch = chan ? NULL : ch->next) {
    memberlist *m = ismember(ch, nick);
    if (m) {
      return make_ircuser_dict(m);
    }
  }
  Py_RETURN_NONE;
}

#ifdef HAVE_TCL
static int tcl_call_python(ClientData cd, Tcl_Interp *irp, int objc, Tcl_Obj *const objv[])
{
  PyObject *args = PyTuple_New(objc > 1 ? objc - 1: 0);
  PythonBind *bind = cd;

  // objc[0] is procname
  for (int i = 1; i < objc; i++) {
    PyTuple_SET_ITEM(args, i - 1, Py_BuildValue("s", Tcl_GetStringFromObj(objv[i], NULL)));
  }
  if (!PyObject_Call(bind->callback, args, NULL)) {
    PyErr_Print();
    Tcl_SetResult(irp, "Error calling python code", TCL_STATIC);
    return TCL_ERROR;
  }
  return TCL_OK;
}
#else /* !HAVE_TCL */

/* Called by script_call() when check_tcl_bind() fires a Python bind entry.
 * argv[0..argc-1] are the string arguments for the bind type. */
static int python_script_call(const char *name, int argc, const char **argv)
{
  PyObject *pybind, *pyargs, *result;
  int i;

  if (!python_callbacks)
    return 0;
  pybind = PyDict_GetItemString(python_callbacks, name); /* borrowed */
  if (!pybind)
    return 0;

  pyargs = PyTuple_New(argc);
  for (i = 0; i < argc; i++)
    PyTuple_SET_ITEM(pyargs, i, PyUnicode_FromString(argv[i] ? argv[i] : ""));

  result = PyObject_Call(((PythonBind *)pybind)->callback, pyargs, NULL);
  Py_DECREF(pyargs);
  if (!result) {
    PyErr_Print();
    return 0;
  }
  Py_DECREF(result);
  return 0;
}

/* Called by script_load() to source .py files */
static int python_script_load(const char *fname)
{
  FILE *fp;
  int ret;

  fp = fopen(fname, "r");
  if (!fp) {
    putlog(LOG_MISC, "*", "python: cannot open script: %s", fname);
    return -1;
  }
  ret = PyRun_SimpleFile(fp, fname);
  fclose(fp);
  if (ret != 0) {
    putlog(LOG_MISC, "*", "python: error loading script: %s", fname);
    return -1;
  }
  putlog(LOG_MISC, "*", "Loaded Python script: %s", fname);
  return 0;
}
#endif /* HAVE_TCL */

#ifdef HAVE_TCL
static PyObject *py_parse_tcl_list(PyObject *self, PyObject *args) {
  Tcl_Size max;
  const char *str;
  Tcl_Obj *strobj;
  PyObject *result;

  if (!PyArg_ParseTuple(args, "s", &str)) {
    PyErr_SetString(PyExc_TypeError, "Argument is not a unicode string");
    return NULL;
  }
  strobj = Tcl_NewStringObj(str, -1);
  Tcl_IncrRefCount(strobj);
  if (Tcl_ListObjLength(tclinterp, strobj, &max) != TCL_OK) {
    Tcl_DecrRefCount(strobj);
    PyErr_SetString(EggdropError, "Supplied string is not a Tcl list");
    return NULL;  /* missing before: fell through to PyList_New(uninit max) */
  }
  result = PyList_New(max);
  for (int i = 0; i < max; i++) {
    Tcl_Obj *tclobj;
    const char *tclstr;
    Tcl_Size tclstrlen;

    Tcl_ListObjIndex(tclinterp, strobj, i, &tclobj);
    tclstr = Tcl_GetStringFromObj(tclobj, &tclstrlen);
    PyList_SetItem(result, i, PyUnicode_DecodeUTF8(tclstr, tclstrlen, NULL));
  }
  Tcl_DecrRefCount(strobj);
  return result;
}

static PyObject *py_parse_tcl_dict(PyObject *self, PyObject *args) {
  int done;
  const char *str;
  Tcl_Obj *strobj, *key, *value;
  Tcl_DictSearch search;
  PyObject *result;

  if (!PyArg_ParseTuple(args, "s", &str)) {
    PyErr_SetString(PyExc_TypeError, "Argument is not a unicode string");
    return NULL;
  }
  strobj = Tcl_NewStringObj(str, -1);
  if (Tcl_DictObjFirst(tclinterp, strobj, &search, &key, &value, &done) != TCL_OK) {
    PyErr_SetString(EggdropError, "Supplied string is not a Tcl dictionary");
    return NULL;
  }
  result = PyDict_New();
  while (!done) {
    Tcl_Size len;
    const char *valstr = Tcl_GetStringFromObj(value, &len);
    PyObject *pyval = PyUnicode_DecodeUTF8(valstr, len, NULL);
    PyDict_SetItemString(result, Tcl_GetString(key), pyval);
    Tcl_DictObjNext(&search, &key, &value, &done);
  }
  Tcl_DictObjDone(&search);
  return result;
}
#endif /* HAVE_TCL */

static PyObject *py_unbind(PyObject *self, PyObject *args) {
  PythonBind *bind;

  if (!PyObject_TypeCheck(self, &PythonBindType)) {
    PyErr_SetString(EggdropError, "Invalid argument for unbind method");
    return NULL;
  }

  bind = (PythonBind *)self;
  unbind_bind_entry(bind->bindtable, bind->flags, bind->mask, bind->tclcmdname);
#ifdef HAVE_TCL
  /* In Tcl builds cleanup happens in python_bind_destroyed when the Tcl
   * command is deleted. */
#else
  /* In no-Tcl builds clean up the callback dict entry and release refs */
  if (python_callbacks)
    PyDict_DelItemString(python_callbacks, bind->tclcmdname);
  Py_XDECREF(bind->callback);
  bind->callback = NULL;
  if (bind->mask)  { nfree(bind->mask);  bind->mask  = NULL; }
  if (bind->flags) { nfree(bind->flags); bind->flags = NULL; }
#endif
  Py_RETURN_NONE;
}

#ifdef HAVE_TCL
void python_bind_destroyed(ClientData cd) {
  PythonBind *bind = cd;

  Py_DECREF(bind->callback);
  nfree(bind->mask);
  nfree(bind->flags);
  Py_DECREF((PyObject *)bind);
}
#endif /* HAVE_TCL */

static PyObject *py_bind(PyObject *self, PyObject *args) {
  PyObject *callback;
  PythonBind *bind;
  Py_hash_t hash;
  char *bindtype, *mask, *flags;
  tcl_bind_list_t *tl;

  // type flags mask callback
  if (!PyArg_ParseTuple(args, "sssO", &bindtype, &flags, &mask, &callback) || !callback) {
    PyErr_SetString(EggdropError, "wrong arguments");
    return NULL;
  }
  if (!(tl = find_bind_table(bindtype))) {
    PyErr_SetString(EggdropError, "unknown bind type");
    return NULL;
  }
  if (callback == Py_None) {
    PyErr_SetString(EggdropError, "callback is None");
    return NULL;
  }
  if (!PyCallable_Check(callback)) {
    PyErr_SetString(EggdropError, "callback is not callable");
    return NULL;
  }
  Py_INCREF(callback);

  bind = PyObject_New(PythonBind, &PythonBindType);
  bind->mask = nstrdup(mask);
  bind->flags = nstrdup(flags);
  bind->bindtable = tl;
  bind->callback = callback;
  hash = PyObject_Hash((PyObject *)bind);
  snprintf(bind->tclcmdname, sizeof bind->tclcmdname, "*python:%s:%" PRIx64, bindtype, (int64_t)hash);

#ifdef HAVE_TCL
  Tcl_CreateObjCommand(tclinterp, bind->tclcmdname, tcl_call_python, bind, python_bind_destroyed);
#else
  /* No-Tcl: store the PythonBind in our callbacks dict so python_script_call
   * can find it when check_tcl_bind fires on this func_name. */
  if (!python_callbacks)
    python_callbacks = PyDict_New();
  Py_INCREF((PyObject *)bind);   /* dict holds a reference */
  PyDict_SetItemString(python_callbacks, bind->tclcmdname, (PyObject *)bind);
  Py_DECREF((PyObject *)bind);   /* release the extra ref from SetItem */
#endif

  bind_bind_entry(tl, flags, mask, bind->tclcmdname);

  Py_INCREF((PyObject *)bind);
  return (PyObject *)bind;
}

#ifdef HAVE_TCL
static Tcl_Obj *py_list_to_tcl_obj(PyObject *o) {
  int max = PyList_GET_SIZE(o);
  Tcl_Obj *result = Tcl_NewListObj(0, NULL);

  for (int i = 0; i < max; i++) {
    Tcl_ListObjAppendElement(tclinterp, result, py_to_tcl_obj(PyList_GET_ITEM(o, i)));
  }
  return result;
}

static Tcl_Obj *py_tuple_to_tcl_obj(PyObject *o) {
  int max = PyTuple_GET_SIZE(o);
  Tcl_Obj *result = Tcl_NewListObj(0, NULL);

  for (int i = 0; i < max; i++) {
    Tcl_ListObjAppendElement(tclinterp, result, py_to_tcl_obj(PyTuple_GET_ITEM(o, i)));
  }
  return result;
}

static Tcl_Obj *py_dict_to_tcl_obj(PyObject *o) {
  int max;
  Tcl_Obj *result = Tcl_NewDictObj();

  /* operate on list of (key, value) tuples instead */
  o = PyDict_Items(o);
  max = PyList_GET_SIZE(o);
  for (int i = 0; i < max; i++) {
    PyObject *key = PyTuple_GET_ITEM(PyList_GET_ITEM(o, i), 0);
    PyObject *val = PyTuple_GET_ITEM(PyList_GET_ITEM(o, i), 1);
    Tcl_Obj *keyobj = py_to_tcl_obj(key);
    Tcl_Obj *valobj = py_to_tcl_obj(val);
    Tcl_DictObjPut(tclinterp, result, keyobj, valobj);
  }
  return result;
}

static Tcl_Obj *py_str_to_tcl_obj(PyObject *o) {
  Tcl_Obj *ret;
  PyObject *strobj = PyObject_Str(o);

  if (strobj) {
    ret = Tcl_NewStringObj(PyUnicode_AsUTF8(strobj), -1);
    Py_DECREF(strobj);
  } else {
    ret = Tcl_NewObj();
  }
  return ret;
}

static Tcl_Obj *py_to_tcl_obj(PyObject *o) {
  if (PyList_Check(o)) {
    return py_list_to_tcl_obj(o);
  } else if (PyDict_Check(o)) {
    return py_dict_to_tcl_obj(o);
  } else if (PyTuple_Check(o)) {
    return py_tuple_to_tcl_obj(o);
  } else if (o == Py_None) {
    return Tcl_NewObj();
  } else {
    return py_str_to_tcl_obj(o);
  }
}

static PyObject *python_call_tcl(PyObject *self, PyObject *args, PyObject *kwargs) {
  TclFunc *tf = (TclFunc *)self;
  Py_ssize_t argc = PyTuple_Size(args);
  Tcl_DString ds;
  const char *result;
  int retcode;

  Tcl_DStringInit(&ds);
  Tcl_DStringAppendElement(&ds, tf->tclcmdname);
  for (int i = 0; i < argc; i++) {
    PyObject *o = PyTuple_GetItem(args, i);
    Tcl_DStringAppendElement(&ds, Tcl_GetString(py_to_tcl_obj(o)));
  }
  retcode = Tcl_Eval(tclinterp, Tcl_DStringValue(&ds));

  if (retcode != TCL_OK) {
    PyErr_Format(EggdropError, "Tcl error: %s", Tcl_GetStringResult(tclinterp));
    return NULL;
  }
  result = Tcl_GetStringResult(tclinterp);
  //putlog(LOG_MISC, "*", "Python called '%s' -> '%s'", Tcl_DStringValue(&ds), result);

  if (!*result) {
    // Empty string means okay
    Py_RETURN_NONE;
  }

  return PyUnicode_DecodeUTF8(result, strlen(result), NULL);
}

static PyObject *py_dir(PyObject *self, PyObject *args) {
  PyObject *py_list, *py_s;
  size_t i;
  int j;
  const char *info[] = {"info commands", "info procs"}, *s, *value;
  Tcl_Obj *tcl_list, **objv;
  Tcl_Size objc;

  py_list = PyList_New(0);
  for (i = 0; i < sizeof info / sizeof info[0]; i++) {
    s = info[i];
    if (Tcl_VarEval(tclinterp, s, NULL, NULL) == TCL_ERROR)
      putlog(LOG_MISC, "*", "python error: Tcl_VarEval(%s)", s);
    else {
      tcl_list = Tcl_GetObjResult(tclinterp);
      if (Tcl_ListObjGetElements(tclinterp, tcl_list, &objc, &objv) == TCL_ERROR)
        putlog(LOG_MISC, "*", "python error: Tcl_VarEval(%s)", s);
      else {
        for (j = 0; j < objc; j++) {
          value = Tcl_GetString(objv[j]);
          if (*value != '*') {
            py_s = PyUnicode_FromString(value);
            PyList_Append(py_list, py_s);
            Py_DECREF(py_s);
          }
        }
      }
    }
  }
  return py_list;
}

static PyObject *py_findtclfunc(PyObject *self, PyObject *args) {
  char *cmdname;
  TclFunc *result;

  if (!PyArg_ParseTuple(args, "s", &cmdname)) {
    PyErr_SetString(EggdropError, "wrong arguments");
    return NULL;
  }
  // TODO: filter a bit better what is available to Python, specify return types ("list of string"), etc.
  if (!(Tcl_FindCommand(tclinterp, cmdname, NULL, TCL_GLOBAL_ONLY))) {
    PyErr_SetString(PyExc_AttributeError, cmdname);
    return NULL;
  }
  result = PyObject_New(TclFunc, &TclFuncType);
  strlcpy(result->tclcmdname, cmdname, sizeof result->tclcmdname);
  return (PyObject *)result;
}
#endif /* HAVE_TCL */

/* ---- DNS helpers -------------------------------------------------------- */

#ifdef HAVE_TCL
/* dnsdot(*args) — configure DNS-over-TLS (RFC 7858).
 *
 * eggdrop.dnsdot()                       -> "off" | "on 1.1.1.1:853" | "connecting ..."
 * eggdrop.dnsdot("on", "1.1.1.1")        -> None
 * eggdrop.dnsdot("on", "1.1.1.1", 853)   -> None
 * eggdrop.dnsdot("on", "::1", 853, "-noverify") -> None
 * eggdrop.dnsdot("off")                  -> None
 *
 * Raises eggdrop.error on invalid arguments or if TLS is not compiled in. */
static PyObject *py_dnsdot(PyObject *self, PyObject *args)
{
  Py_ssize_t argc = PyTuple_Size(args);
  Tcl_DString ds;
  const char *result;
  int retcode;

  Tcl_DStringInit(&ds);
  Tcl_DStringAppendElement(&ds, "dnsdot");
  for (Py_ssize_t i = 0; i < argc; i++) {
    PyObject *o = PyTuple_GetItem(args, i);
    Tcl_DStringAppendElement(&ds, Tcl_GetString(py_to_tcl_obj(o)));
  }
  retcode = Tcl_Eval(tclinterp, Tcl_DStringValue(&ds));
  Tcl_DStringFree(&ds);

  if (retcode != TCL_OK) {
    PyErr_Format(EggdropError, "%s", Tcl_GetStringResult(tclinterp));
    return NULL;
  }
  result = Tcl_GetStringResult(tclinterp);
  if (!*result)
    Py_RETURN_NONE;
  return PyUnicode_FromString(result);
}
#endif /* HAVE_TCL */

/* ---- Core IRC output functions ----------------------------------------- */

/* putserv(text) — queue text to the server (normal queue) */
static PyObject *py_putserv(PyObject *self, PyObject *args)
{
  char *text, s[MSGMAX], *p;

  if (!PyArg_ParseTuple(args, "s", &text))
    return NULL;
  strlcpy(s, text, sizeof s);
  if ((p = strchr(s, '\n'))) *p = 0;
  if ((p = strchr(s, '\r'))) *p = 0;
  dprintf(DP_SERVER, "%s\n", s);
  Py_RETURN_NONE;
}

/* putquick(text) — queue text to the server (quick/mode queue) */
static PyObject *py_putquick(PyObject *self, PyObject *args)
{
  char *text, s[MSGMAX], *p;

  if (!PyArg_ParseTuple(args, "s", &text))
    return NULL;
  strlcpy(s, text, sizeof s);
  if ((p = strchr(s, '\n'))) *p = 0;
  if ((p = strchr(s, '\r'))) *p = 0;
  dprintf(DP_MODE, "%s\n", s);
  Py_RETURN_NONE;
}

/* putnow(text) — send text to server immediately (bypass queues) */
static PyObject *py_putnow(PyObject *self, PyObject *args)
{
  char *text, s[MSGMAX], *p;

  if (!PyArg_ParseTuple(args, "s", &text))
    return NULL;
  strlcpy(s, text, sizeof s);
  if ((p = strchr(s, '\n'))) *p = 0;
  if ((p = strchr(s, '\r'))) *p = 0;
  /* For putnow, use DP_MODE_NEXT which bypasses the normal queue */
  dprintf(DP_MODE_NEXT, "%s\n", s);
  Py_RETURN_NONE;
}

/* putdcc(idx, text) — send text to a DCC party (telnet/party) */
static PyObject *py_putdcc(PyObject *self, PyObject *args)
{
  int idx;
  char *text;

  if (!PyArg_ParseTuple(args, "is", &idx, &text))
    return NULL;
  dprintf(idx, "%s\n", text);
  Py_RETURN_NONE;
}

/* putlog(text, [loglevel, [channel]]) — write to eggdrop log
 * loglevel defaults to LOG_MISC; channel defaults to "*" */
static PyObject *py_putlog(PyObject *self, PyObject *args)
{
  char *text, *chan = "*";
  int lev = LOG_MISC;

  if (!PyArg_ParseTuple(args, "s|is", &text, &lev, &chan))
    return NULL;
  putlog(lev, chan, "%s", text);
  Py_RETURN_NONE;
}

/* isonchan(nick, chan) — return True if nick is on channel */
static PyObject *py_isonchan(PyObject *self, PyObject *args)
{
  char *nick, *chan;
  struct chanset_t *ch;

  if (!PyArg_ParseTuple(args, "ss", &nick, &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (ch && ismember(ch, nick))
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}

/* getchanhost(nick, chan) — return "user@host" of nick on channel, or None */
static PyObject *py_getchanhost(PyObject *self, PyObject *args)
{
  char *nick, *chan;
  struct chanset_t *ch;
  memberlist *m;

  if (!PyArg_ParseTuple(args, "ss", &nick, &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch)
    Py_RETURN_NONE;
  m = ismember(ch, nick);
  if (!m)
    Py_RETURN_NONE;
  return PyUnicode_FromString(m->userhost);
}

/* chanlist(chan) — return list of nick dicts for all members of channel */
static PyObject *py_chanlist(PyObject *self, PyObject *args)
{
  char *chan;
  struct chanset_t *ch;
  memberlist *m;
  PyObject *list;

  if (!PyArg_ParseTuple(args, "s", &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch) {
    PyErr_SetString(EggdropError, "channel not found");
    return NULL;
  }
  list = PyList_New(0);
  for (m = ch->channel.member; m && m->nick[0]; m = m->next)
    PyList_Append(list, make_ircuser_dict(m));
  return list;
}

/* botname() — return bot's current IRC nick */
static PyObject *py_botname(PyObject *self, PyObject *args)
{
  return PyUnicode_FromString(botname);
}

/* channels() — return list of channel name strings the bot is on */
static PyObject *py_channels(PyObject *self, PyObject *args)
{
  struct chanset_t *ch;
  PyObject *list = PyList_New(0);

  for (ch = chanset; ch; ch = ch->next)
    PyList_Append(list, PyUnicode_FromString(ch->dname));
  return list;
}

/* ---- Channel member status queries ------------------------------------ */

/* isop(nick, chan) — True if nick has channel operator status */
static PyObject *py_isop(PyObject *self, PyObject *args)
{
  char *nick, *chan;
  struct chanset_t *ch;
  memberlist *m;

  if (!PyArg_ParseTuple(args, "ss", &nick, &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch)
    Py_RETURN_FALSE;
  m = ismember(ch, nick);
  if (m && chan_hasop(m))
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}

/* ishalfop(nick, chan) — True if nick has channel half-operator status */
static PyObject *py_ishalfop(PyObject *self, PyObject *args)
{
  char *nick, *chan;
  struct chanset_t *ch;
  memberlist *m;

  if (!PyArg_ParseTuple(args, "ss", &nick, &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch)
    Py_RETURN_FALSE;
  m = ismember(ch, nick);
  if (m && chan_hashalfop(m))
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}

/* isvoice(nick, chan) — True if nick has channel voice status */
static PyObject *py_isvoice(PyObject *self, PyObject *args)
{
  char *nick, *chan;
  struct chanset_t *ch;
  memberlist *m;

  if (!PyArg_ParseTuple(args, "ss", &nick, &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch)
    Py_RETURN_FALSE;
  m = ismember(ch, nick);
  if (m && chan_hasvoice(m))
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}

/* isaway(nick, chan) — True if nick is marked away on IRC */
static PyObject *py_isaway(PyObject *self, PyObject *args)
{
  char *nick, *chan;
  struct chanset_t *ch;
  memberlist *m;

  if (!PyArg_ParseTuple(args, "ss", &nick, &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch)
    Py_RETURN_FALSE;
  m = ismember(ch, nick);
  if (m && (m->flags & IRCAWAY))
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}

/* botisop(chan) — True if the bot has operator status on chan */
static PyObject *py_botisop(PyObject *self, PyObject *args)
{
  char *chan;
  struct chanset_t *ch;
  memberlist *m;

  if (!PyArg_ParseTuple(args, "s", &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch)
    Py_RETURN_FALSE;
  m = ismember(ch, botname);
  if (m && chan_hasop(m))
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}

/* botishalfop(chan) — True if the bot has half-operator status on chan */
static PyObject *py_botishalfop(PyObject *self, PyObject *args)
{
  char *chan;
  struct chanset_t *ch;
  memberlist *m;

  if (!PyArg_ParseTuple(args, "s", &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch)
    Py_RETURN_FALSE;
  m = ismember(ch, botname);
  if (m && chan_hashalfop(m))
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}

/* botisvoice(chan) — True if the bot has voice status on chan */
static PyObject *py_botisvoice(PyObject *self, PyObject *args)
{
  char *chan;
  struct chanset_t *ch;
  memberlist *m;

  if (!PyArg_ParseTuple(args, "s", &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch)
    Py_RETURN_FALSE;
  m = ismember(ch, botname);
  if (m && chan_hasvoice(m))
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}

/* getaccount(nick, chan) — return IRC account name of nick, or None */
static PyObject *py_getaccount(PyObject *self, PyObject *args)
{
  char *nick, *chan;
  struct chanset_t *ch;
  memberlist *m;

  if (!PyArg_ParseTuple(args, "ss", &nick, &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch)
    Py_RETURN_NONE;
  m = ismember(ch, nick);
  if (!m || !m->account[0])
    Py_RETURN_NONE;
  return PyUnicode_FromString(m->account);
}

/* nick2hand(nick, chan) — return eggdrop handle for nick on chan, or None */
static PyObject *py_nick2hand(PyObject *self, PyObject *args)
{
  char *nick, *chan, hostbuf[UHOSTLEN + NICKLEN + 2];
  struct chanset_t *ch;
  memberlist *m;
  struct userrec *u;

  if (!PyArg_ParseTuple(args, "ss", &nick, &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch)
    Py_RETURN_NONE;
  m = ismember(ch, nick);
  if (!m)
    Py_RETURN_NONE;
  snprintf(hostbuf, sizeof hostbuf, "%s!%s", m->nick, m->userhost);
  u = get_user_by_host(hostbuf);
  if (!u)
    Py_RETURN_NONE;
  return PyUnicode_FromString(u->handle);
}

/* hand2nick(handle, chan) — return nick of user with handle on chan, or None */
static PyObject *py_hand2nick(PyObject *self, PyObject *args)
{
  char *handle, *chan, hostbuf[UHOSTLEN + NICKLEN + 2];
  struct chanset_t *ch;
  memberlist *m;
  struct userrec *u;

  if (!PyArg_ParseTuple(args, "ss", &handle, &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch)
    Py_RETURN_NONE;
  for (m = ch->channel.member; m && m->nick[0]; m = m->next) {
    snprintf(hostbuf, sizeof hostbuf, "%s!%s", m->nick, m->userhost);
    u = get_user_by_host(hostbuf);
    if (u && !strcasecmp(u->handle, handle))
      return PyUnicode_FromString(m->nick);
  }
  Py_RETURN_NONE;
}

/* isbotnick(nick) — True if nick matches the bot's current nickname */
static PyObject *py_isbotnick(PyObject *self, PyObject *args)
{
  char *nick;

  if (!PyArg_ParseTuple(args, "s", &nick))
    return NULL;
  if (!strcasecmp(nick, botname))
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}

/* ---- User database queries -------------------------------------------- */

/* countusers() — return number of users in the userlist */
static PyObject *py_countusers(PyObject *self, PyObject *args)
{
  return PyLong_FromLong(count_users(userlist));
}

/* validuser(handle) — True if handle exists in the userlist */
static PyObject *py_validuser(PyObject *self, PyObject *args)
{
  char *handle;

  if (!PyArg_ParseTuple(args, "s", &handle))
    return NULL;
  if (get_user_by_handle(userlist, handle))
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}

/* finduser(host) — return handle of user matching 'nick!user@host', or None */
static PyObject *py_finduser(PyObject *self, PyObject *args)
{
  char *host;
  struct userrec *u;

  if (!PyArg_ParseTuple(args, "s", &host))
    return NULL;
  u = get_user_by_host((char *)host);
  if (!u)
    Py_RETURN_NONE;
  return PyUnicode_FromString(u->handle);
}

/* userlist() — return list of all user handles in the userlist */
static PyObject *py_userlist(PyObject *self, PyObject *args)
{
  struct userrec *u;
  PyObject *list = PyList_New(0);

  for (u = userlist; u; u = u->next)
    PyList_Append(list, PyUnicode_FromString(u->handle));
  return list;
}

/* ---- Miscellaneous utilities ------------------------------------------ */

/* rand(n) — return a random integer in [0, n) */
static PyObject *py_rand(PyObject *self, PyObject *args)
{
  long n;

  if (!PyArg_ParseTuple(args, "l", &n))
    return NULL;
  if (n <= 0) {
    PyErr_SetString(PyExc_ValueError, "rand() argument must be positive");
    return NULL;
  }
  return PyLong_FromLong((long)(random() % n));
}

/* unixtime() — return current Unix timestamp as an integer */
static PyObject *py_unixtime(PyObject *self, PyObject *args)
{
  return PyLong_FromLong((long)time(NULL));
}

/* isbotnick already defined above */

/* duration(seconds) — convert seconds to human-readable string */
static PyObject *py_duration(PyObject *self, PyObject *args)
{
  char s[80];
  uint64_t sec, tmp;
  long n;

  if (!PyArg_ParseTuple(args, "l", &n))
    return NULL;
  if (n <= 0)
    return PyUnicode_FromString("0 seconds");
  sec = (uint64_t) n;
  s[0] = 0;
  if (sec >= 31536000) {
    tmp = sec / 31536000; sec -= tmp * 31536000;
    op_snprintf_append(s, sizeof s, "%" PRIu64 " year%s ", tmp, tmp == 1 ? "" : "s");
  }
  if (sec >= 604800) {
    tmp = sec / 604800; sec -= tmp * 604800;
    op_snprintf_append(s, sizeof s, "%" PRIu64 " week%s ", tmp, tmp == 1 ? "" : "s");
  }
  if (sec >= 86400) {
    tmp = sec / 86400; sec -= tmp * 86400;
    op_snprintf_append(s, sizeof s, "%" PRIu64 " day%s ", tmp, tmp == 1 ? "" : "s");
  }
  if (sec >= 3600) {
    tmp = sec / 3600; sec -= tmp * 3600;
    op_snprintf_append(s, sizeof s, "%" PRIu64 " hour%s ", tmp, tmp == 1 ? "" : "s");
  }
  if (sec >= 60) {
    tmp = sec / 60; sec -= tmp * 60;
    op_snprintf_append(s, sizeof s, "%" PRIu64 " minute%s ", tmp, tmp == 1 ? "" : "s");
  }
  if (sec > 0)
    op_snprintf_append(s, sizeof s, "%" PRIu64 " second%s", sec, sec == 1 ? "" : "s");
  else if (s[0] && s[strlen(s) - 1] == ' ')
    s[strlen(s) - 1] = 0;   /* strip trailing space */
  return PyUnicode_FromString(s);
}

/* maskhost(nick, userhost) — create a standard IRC hostmask from nick!user@host */
static PyObject *py_maskhost(PyObject *self, PyObject *args)
{
  char *userhost, *nick, buf[UHOSTLEN + 16], *at, *dot;

  if (!PyArg_ParseTuple(args, "ss", &nick, &userhost))
    return NULL;
  at = strchr(userhost, '@');
  if (!at) {
    /* If only host given, build !*@*.domain */
    dot = strchr(userhost, '.');
    if (dot)
      snprintf(buf, sizeof buf, "*!*@*%s", dot);
    else
      snprintf(buf, sizeof buf, "*!*@%s", userhost);
  } else {
    /* userhost is user@host */
    dot = strchr(at + 1, '.');
    if (dot)
      snprintf(buf, sizeof buf, "*!*@*%s", dot);
    else
      snprintf(buf, sizeof buf, "*!*@%s", at + 1);
  }
  (void)nick;  /* nick not used in default mask, kept for compat */
  return PyUnicode_FromString(buf);
}

/* isidentified(nick[, channel]) — True if nick is logged in to services
 * (account field is set and not "*"). Searches all channels if channel
 * is omitted. */
static PyObject *py_isidentified(PyObject *self, PyObject *args)
{
  char *nick, *chan = NULL;
  struct chanset_t *ch, *the_chan = NULL;
  memberlist *m;

  if (!PyArg_ParseTuple(args, "s|s", &nick, &chan))
    return NULL;
  if (chan) {
    the_chan = findchan_by_dname(chan);
    if (!the_chan)
      Py_RETURN_FALSE;
  }
  for (ch = chanset; ch; ch = ch->next) {
    if (the_chan && ch != the_chan)
      continue;
    m = ismember(ch, nick);
    if (m && strcmp(m->account, "*") && strcmp(m->account, ""))
      Py_RETURN_TRUE;
  }
  Py_RETURN_FALSE;
}

/* ---- IRCX commands (Microsoft IRC extensions / Ophion) --------------- */

/* ircxprop(target, propname[, value])
 * Get or set an IRCX property on a channel or user.
 * Without value: sends PROP target propname (server returns current value).
 * With value:    sends PROP target propname :value (sets the property). */
static PyObject *py_ircxprop(PyObject *self, PyObject *args)
{
  char *target, *prop, *value = NULL;

  if (!PyArg_ParseTuple(args, "ss|s", &target, &prop, &value))
    return NULL;
  if (value && value[0])
    dprintf(DP_SERVER, "PROP %s %s :%s\n", target, prop, value);
  else
    dprintf(DP_SERVER, "PROP %s %s\n", target, prop);
  Py_RETURN_NONE;
}

/* ircxaccess(channel, action[, level[, mask]])
 * Manage the IRCX access list for a channel.
 * action='list'            — retrieve access list (ACCESS channel LIST)
 * action='add', level, mask — add entry (ACCESS channel ADD level mask)
 * action='del', mask        — remove entry (ACCESS channel DEL mask) */
static PyObject *py_ircxaccess(PyObject *self, PyObject *args)
{
  char *channel, *action, *level = NULL, *mask = NULL;

  if (!PyArg_ParseTuple(args, "ss|ss", &channel, &action, &level, &mask))
    return NULL;
  if (!strcasecmp(action, "list")) {
    dprintf(DP_SERVER, "ACCESS %s LIST\n", channel);
  } else if (!strcasecmp(action, "add")) {
    if (!level || !mask) {
      PyErr_SetString(PyExc_TypeError, "ircxaccess 'add' requires level and mask");
      return NULL;
    }
    dprintf(DP_SERVER, "ACCESS %s ADD %s %s\n", channel, level, mask);
  } else if (!strcasecmp(action, "del")) {
    if (!mask) {
      PyErr_SetString(PyExc_TypeError, "ircxaccess 'del' requires mask");
      return NULL;
    }
    dprintf(DP_SERVER, "ACCESS %s DEL %s\n", channel, mask);
  } else {
    PyErr_SetString(PyExc_ValueError, "ircxaccess: action must be 'list', 'add', or 'del'");
    return NULL;
  }
  Py_RETURN_NONE;
}

/* ircxcreate(channel[, modes]) — send IRCX CREATE to create a channel */
static PyObject *py_ircxcreate(PyObject *self, PyObject *args)
{
  char *channel, *modes = NULL;

  if (!PyArg_ParseTuple(args, "s|s", &channel, &modes))
    return NULL;
  if (modes && modes[0])
    dprintf(DP_SERVER, "CREATE %s %s\n", channel, modes);
  else
    dprintf(DP_SERVER, "CREATE %s\n", channel);
  Py_RETURN_NONE;
}

/* ircxnegotiate() — send the IRCX negotiate command to enable IRCX mode */
static PyObject *py_ircxnegotiate(PyObject *self, PyObject *args)
{
  dprintf(DP_MODE, "IRCX\n");
  Py_RETURN_NONE;
}

/* ---- Bot management -------------------------------------------------- */

/* die([reason]) — shut down the bot with optional quit message */
static PyObject *py_die(PyObject *self, PyObject *args)
{
  char *reason = NULL, s[1024];

  if (!PyArg_ParseTuple(args, "|s", &reason))
    return NULL;
  if (reason && reason[0]) {
    snprintf(s, sizeof s, "BOT SHUTDOWN (%s)", reason);
    strlcpy(quit_msg, reason, 1024);
  } else {
    strlcpy(s, "BOT SHUTDOWN (No reason)", sizeof s);
    quit_msg[0] = 0;
  }
  kill_bot(s, quit_msg[0] ? quit_msg : "EXIT");
  Py_RETURN_NONE;
}

/* restart() — save userfile and restart the bot process */
static PyObject *py_restart(PyObject *self, PyObject *args)
{
  if (make_userfile) {
    putlog(LOG_MISC, "*", "No need for a new user file, skipping.");
    make_userfile = 0;
  }
  write_userfile(-1);
  putlog(LOG_MISC, "*", "Restarting.");
  do_restart = -1;
  Py_RETURN_NONE;
}

/* rehash() — save userfile and reload configuration (no full restart) */
static PyObject *py_rehash(PyObject *self, PyObject *args)
{
  if (make_userfile) {
    putlog(LOG_MISC, "*", "No need for a new user file, skipping.");
    make_userfile = 0;
  }
  write_userfile(-1);
  putlog(LOG_MISC, "*", "Rehashing.");
  do_restart = -2;
  Py_RETURN_NONE;
}

/* ---- User entry access (getuser / setuser) ---------------------------- */

/* getinfo(handle) — return the INFO string for handle, or None */
static PyObject *py_getinfo(PyObject *self, PyObject *args)
{
  char *handle;
  struct userrec *u;
  char *info;

  if (!PyArg_ParseTuple(args, "s", &handle))
    return NULL;
  u = get_user_by_handle(userlist, handle);
  if (!u)
    Py_RETURN_NONE;
  info = (char *)get_user(&USERENTRY_INFO, u);
  if (!info || !info[0])
    Py_RETURN_NONE;
  return PyUnicode_FromString(info);
}

/* setinfo(handle, info) — set the INFO string for handle */
static PyObject *py_setinfo(PyObject *self, PyObject *args)
{
  char *handle, *info;
  struct userrec *u;

  if (!PyArg_ParseTuple(args, "ss", &handle, &info))
    return NULL;
  u = get_user_by_handle(userlist, handle);
  if (!u) {
    PyErr_SetString(EggdropError, "no such user");
    return NULL;
  }
  set_user(&USERENTRY_INFO, u, info[0] ? info : NULL);
  Py_RETURN_NONE;
}

/* getcomment(handle) — return the COMMENT string for handle, or None */
static PyObject *py_getcomment(PyObject *self, PyObject *args)
{
  char *handle;
  struct userrec *u;
  char *comment;

  if (!PyArg_ParseTuple(args, "s", &handle))
    return NULL;
  u = get_user_by_handle(userlist, handle);
  if (!u)
    Py_RETURN_NONE;
  comment = (char *)get_user(&USERENTRY_COMMENT, u);
  if (!comment || !comment[0])
    Py_RETURN_NONE;
  return PyUnicode_FromString(comment);
}

/* setcomment(handle, comment) — set the COMMENT string for handle */
static PyObject *py_setcomment(PyObject *self, PyObject *args)
{
  char *handle, *comment;
  struct userrec *u;

  if (!PyArg_ParseTuple(args, "ss", &handle, &comment))
    return NULL;
  u = get_user_by_handle(userlist, handle);
  if (!u) {
    PyErr_SetString(EggdropError, "no such user");
    return NULL;
  }
  set_user(&USERENTRY_COMMENT, u, comment[0] ? comment : NULL);
  Py_RETURN_NONE;
}

/* gethosts(handle) — return list of hostmask strings for handle */
static PyObject *py_gethosts(PyObject *self, PyObject *args)
{
  char *handle;
  struct userrec *u;
  struct user_entry *e;
  struct list_type *x;
  PyObject *list, *s;

  if (!PyArg_ParseTuple(args, "s", &handle))
    return NULL;
  u = get_user_by_handle(userlist, handle);
  list = PyList_New(0);
  if (!u)
    return list;
  e = find_user_entry(&USERENTRY_HOSTS, u);
  if (!e)
    return list;
  for (x = e->u.list; x; x = x->next) {
    s = PyUnicode_FromString(x->extra);
    PyList_Append(list, s);
    Py_DECREF(s);
  }
  return list;
}

/* getaccount_str(handle) — return IRC account name from USERENTRY_ACCOUNT, or None */
static PyObject *py_getaccount_str(PyObject *self, PyObject *args)
{
  char *handle;
  struct userrec *u;
  char *acc;

  if (!PyArg_ParseTuple(args, "s", &handle))
    return NULL;
  u = get_user_by_handle(userlist, handle);
  if (!u)
    Py_RETURN_NONE;
  acc = (char *)get_user(&USERENTRY_ACCOUNT, u);
  if (!acc || !acc[0])
    Py_RETURN_NONE;
  return PyUnicode_FromString(acc);
}

/* ---- Channel setting queries ------------------------------------------ */

/* chanset(channel) — return dict of channel configuration settings */
static PyObject *py_chanset(PyObject *self, PyObject *args)
{
  char *chan;
  struct chanset_t *ch;
  PyObject *d;

  if (!PyArg_ParseTuple(args, "s", &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch) {
    PyErr_SetString(EggdropError, "channel not found");
    return NULL;
  }
  d = PyDict_New();
  /* Flood control */
  PyDict_SetItemString(d, "flood_pub_thr",   PyLong_FromLong(ch->flood_pub_thr));
  PyDict_SetItemString(d, "flood_pub_time",  PyLong_FromLong(ch->flood_pub_time));
  PyDict_SetItemString(d, "flood_join_thr",  PyLong_FromLong(ch->flood_join_thr));
  PyDict_SetItemString(d, "flood_join_time", PyLong_FromLong(ch->flood_join_time));
  PyDict_SetItemString(d, "flood_kick_thr",  PyLong_FromLong(ch->flood_kick_thr));
  PyDict_SetItemString(d, "flood_kick_time", PyLong_FromLong(ch->flood_kick_time));
  PyDict_SetItemString(d, "flood_deop_thr",  PyLong_FromLong(ch->flood_deop_thr));
  PyDict_SetItemString(d, "flood_deop_time", PyLong_FromLong(ch->flood_deop_time));
  PyDict_SetItemString(d, "flood_ctcp_thr",  PyLong_FromLong(ch->flood_ctcp_thr));
  PyDict_SetItemString(d, "flood_ctcp_time", PyLong_FromLong(ch->flood_ctcp_time));
  PyDict_SetItemString(d, "flood_nick_thr",  PyLong_FromLong(ch->flood_nick_thr));
  PyDict_SetItemString(d, "flood_nick_time", PyLong_FromLong(ch->flood_nick_time));
  /* Mask expiry times (in minutes) */
  PyDict_SetItemString(d, "ban_time",        PyLong_FromLong(ch->ban_time));
  PyDict_SetItemString(d, "invite_time",     PyLong_FromLong(ch->invite_time));
  PyDict_SetItemString(d, "exempt_time",     PyLong_FromLong(ch->exempt_time));
  /* Auto-op range */
  PyDict_SetItemString(d, "aop_min",         PyLong_FromLong(ch->aop_min));
  PyDict_SetItemString(d, "aop_max",         PyLong_FromLong(ch->aop_max));
  /* Misc settings */
  PyDict_SetItemString(d, "idle_kick",       PyLong_FromLong(ch->idle_kick));
  PyDict_SetItemString(d, "stopnethack_mode",PyLong_FromLong(ch->stopnethack_mode));
  PyDict_SetItemString(d, "revenge_mode",    PyLong_FromLong(ch->revenge_mode));
  PyDict_SetItemString(d, "ban_type",        PyLong_FromLong(ch->ban_type));
  /* Status flags (raw bitmask + individual booleans) */
  PyDict_SetItemString(d, "status",          PyLong_FromLong(ch->status));
  PyDict_SetItemString(d, "enforcebans",     PyBool_FromLong(ch->status & CHAN_ENFORCEBANS));
  PyDict_SetItemString(d, "dynamicbans",     PyBool_FromLong(ch->status & CHAN_DYNAMICBANS));
  PyDict_SetItemString(d, "userbans",        PyBool_FromLong(!(ch->status & CHAN_NOUSERBANS)));
  PyDict_SetItemString(d, "autoop",          PyBool_FromLong(ch->status & CHAN_OPONJOIN));
  PyDict_SetItemString(d, "bitch",           PyBool_FromLong(ch->status & CHAN_BITCH));
  PyDict_SetItemString(d, "greet",           PyBool_FromLong(ch->status & CHAN_GREET));
  PyDict_SetItemString(d, "protectops",      PyBool_FromLong(ch->status & CHAN_PROTECTOPS));
  PyDict_SetItemString(d, "revenge",         PyBool_FromLong(ch->status & CHAN_REVENGE));
  PyDict_SetItemString(d, "secret",          PyBool_FromLong(ch->status & CHAN_SECRET));
  PyDict_SetItemString(d, "autovoice",       PyBool_FromLong(ch->status & CHAN_AUTOVOICE));
  PyDict_SetItemString(d, "cycle",           PyBool_FromLong(ch->status & CHAN_CYCLE));
  PyDict_SetItemString(d, "dontkickops",     PyBool_FromLong(ch->status & CHAN_DONTKICKOPS));
  PyDict_SetItemString(d, "inactive",        PyBool_FromLong(ch->status & CHAN_INACTIVE));
  PyDict_SetItemString(d, "protectfriends",  PyBool_FromLong(ch->status & CHAN_PROTECTFRIENDS));
  PyDict_SetItemString(d, "shared",          PyBool_FromLong(ch->status & CHAN_SHARED));
  PyDict_SetItemString(d, "seen",            PyBool_FromLong(ch->status & CHAN_SEEN));
  PyDict_SetItemString(d, "revengebot",      PyBool_FromLong(ch->status & CHAN_REVENGEBOT));
  PyDict_SetItemString(d, "autohalfop",      PyBool_FromLong(ch->status & CHAN_AUTOHALFOP));
  PyDict_SetItemString(d, "protecthalfops",  PyBool_FromLong(ch->status & CHAN_PROTECTHALFOPS));
  /* IRC mode string (from channel.mode bitmask - returned as raw int) */
  PyDict_SetItemString(d, "mode",            PyLong_FromLong((long)ch->channel.mode));
  PyDict_SetItemString(d, "maxmembers",      PyLong_FromLong((long)ch->channel.maxmembers));
  PyDict_SetItemString(d, "members",         PyLong_FromLong((long)ch->channel.members));
  return d;
}

/* ---- Twitch extensions ----------------------------------------------- */

/* twitchmods(channel) — space-separated list of moderator nicks */
static PyObject *py_twitchmods(PyObject *self, PyObject *args)
{
  char *chan;
  module_entry *me;
  char *(*fn)(char *);
  char *result;

  if (!PyArg_ParseTuple(args, "s", &chan))
    return NULL;
  me = module_find("twitch", 0, 1);
  if (!me) {
    PyErr_SetString(EggdropError, "twitch module not loaded");
    return NULL;
  }
  fn = (char *(*)(char *))me->funcs[12];
  result = fn(chan);
  if (!result) {
    PyErr_SetString(EggdropError, "channel not found");
    return NULL;
  }
  return PyUnicode_FromString(result);
}

/* twitchvips(channel) — space-separated list of VIP nicks */
static PyObject *py_twitchvips(PyObject *self, PyObject *args)
{
  char *chan;
  module_entry *me;
  char *(*fn)(char *);
  char *result;

  if (!PyArg_ParseTuple(args, "s", &chan))
    return NULL;
  me = module_find("twitch", 0, 1);
  if (!me) {
    PyErr_SetString(EggdropError, "twitch module not loaded");
    return NULL;
  }
  fn = (char *(*)(char *))me->funcs[13];
  result = fn(chan);
  if (!result) {
    PyErr_SetString(EggdropError, "channel not found");
    return NULL;
  }
  return PyUnicode_FromString(result);
}

/* ismod(nick[, channel]) — True if nick is a Twitch moderator */
static PyObject *py_ismod(PyObject *self, PyObject *args)
{
  char *nick, *chan = NULL;
  module_entry *me;
  int (*fn)(char *, char *);
  int result;

  if (!PyArg_ParseTuple(args, "s|s", &nick, &chan))
    return NULL;
  me = module_find("twitch", 0, 1);
  if (!me) {
    PyErr_SetString(EggdropError, "twitch module not loaded");
    return NULL;
  }
  fn = (int (*)(char *, char *))me->funcs[14];
  result = fn(nick, chan);
  if (result < 0) {
    PyErr_SetString(EggdropError, "channel not found");
    return NULL;
  }
  return PyBool_FromLong(result);
}

/* isvip(nick[, channel]) — True if nick is a Twitch VIP */
static PyObject *py_isvip(PyObject *self, PyObject *args)
{
  char *nick, *chan = NULL;
  module_entry *me;
  int (*fn)(char *, char *);
  int result;

  if (!PyArg_ParseTuple(args, "s|s", &nick, &chan))
    return NULL;
  me = module_find("twitch", 0, 1);
  if (!me) {
    PyErr_SetString(EggdropError, "twitch module not loaded");
    return NULL;
  }
  fn = (int (*)(char *, char *))me->funcs[15];
  result = fn(nick, chan);
  if (result < 0) {
    PyErr_SetString(EggdropError, "channel not found");
    return NULL;
  }
  return PyBool_FromLong(result);
}

/* ---- User management ------------------------------------------------- */

/* adduser(handle[, hostmask]) — add a new user to the userlist.
 * Returns True on success, False if handle already exists or is invalid. */
static PyObject *py_adduser(PyObject *self, PyObject *args)
{
  char *handle, *host = NULL;
  unsigned char *p;
  char hbuf[HANDLEN + 1];

  if (!PyArg_ParseTuple(args, "s|s", &handle, &host))
    return NULL;
  strlcpy(hbuf, handle, sizeof hbuf);
  for (p = (unsigned char *)hbuf; *p; p++)
    if (*p <= 32 || *p == '@')
      *p = '?';
  if (hbuf[0] == '*' || strchr(BADHANDCHARS, hbuf[0]) ||
      get_user_by_handle(userlist, hbuf))
    Py_RETURN_FALSE;
  userlist = adduser(userlist, hbuf, host ? host : "none", "-", default_flags);
  Py_RETURN_TRUE;
}

/* deluser(handle) — remove a user from the userlist. Returns True if removed. */
static PyObject *py_deluser(PyObject *self, PyObject *args)
{
  char *handle;

  if (!PyArg_ParseTuple(args, "s", &handle))
    return NULL;
  if (handle[0] == '*')
    Py_RETURN_FALSE;
  return PyBool_FromLong(deluser(handle));
}

/* addhost(handle, hostmask) — add a hostmask to an existing user */
static PyObject *py_addhost(PyObject *self, PyObject *args)
{
  char *handle, *mask;

  if (!PyArg_ParseTuple(args, "ss", &handle, &mask))
    return NULL;
  if (!get_user_by_handle(userlist, handle)) {
    PyErr_SetString(EggdropError, "no such user");
    return NULL;
  }
  addhost_by_handle(handle, mask);
  Py_RETURN_NONE;
}

/* delhost(handle, hostmask) — remove a hostmask from a user. Returns True if removed. */
static PyObject *py_delhost(PyObject *self, PyObject *args)
{
  char *handle, *mask;

  if (!PyArg_ParseTuple(args, "ss", &handle, &mask))
    return NULL;
  if (!get_user_by_handle(userlist, handle)) {
    PyErr_SetString(EggdropError, "no such user");
    return NULL;
  }
  return PyBool_FromLong(delhost_by_handle(handle, mask));
}

/* chattr(handle[, changes[, channel]]) — get/set user flags.
 * With no changes: returns current flag string.
 * With changes like "+o-v": applies flag changes and returns new flags. */
static PyObject *py_chattr(PyObject *self, PyObject *args)
{
  char *handle, *chg = NULL, *chan = NULL;
  struct flag_record pls = {0}, mns = {0}, user = {0};
  struct userrec *u;
  char work[100];

  if (!PyArg_ParseTuple(args, "s|ss", &handle, &chg, &chan))
    return NULL;
  u = get_user_by_handle(userlist, handle);
  if (!u || handle[0] == '*') {
    Py_RETURN_NONE;
  }
  if (chan) {
    user.match = FR_GLOBAL | FR_CHAN;
    if (!findchan_by_dname(chan)) {
      PyErr_SetString(EggdropError, "no such channel");
      return NULL;
    }
  } else {
    user.match = FR_GLOBAL;
  }
  get_user_flagrec(u, &user, chan);
  if (chg) {
    pls.match = user.match;
    break_down_flags(chg, &pls, &mns);
    pls.global &= ~USER_BOT;
    mns.global &= ~USER_BOT;
    user.global  = (user.global  | pls.global)       & ~mns.global;
    user.udef_global = (user.udef_global | pls.udef_global) & ~mns.udef_global;
    if (chan) {
      user.chan  = (user.chan  | pls.chan)             & ~mns.chan;
      user.udef_chan = (user.udef_chan | pls.udef_chan)& ~mns.udef_chan;
    }
    set_user_flagrec(u, &user, chan);
  }
  build_flags(work, &user, NULL);
  return PyUnicode_FromString(work);
}

/* matchattr(handle, flags[, channel]) — True if user matches flag string */
static PyObject *py_matchattr(PyObject *self, PyObject *args)
{
  char *handle, *flags, *chan = NULL;
  struct flag_record plus = {0}, minus = {0}, user = {0};
  struct userrec *u;
  int ok = 0, nom = 0;

  if (!PyArg_ParseTuple(args, "ss|s", &handle, &flags, &chan))
    return NULL;
  u = get_user_by_handle(userlist, handle);
  if (u) {
    user.match = FR_GLOBAL | (chan ? FR_CHAN : 0) | FR_BOT;
    get_user_flagrec(u, &user, chan);
    plus.match = user.match;
    break_down_flags(flags, &plus, &minus);
    minus.match = plus.match ^ (FR_AND | FR_OR);
    if (!minus.global && !minus.udef_global && !minus.chan &&
        !minus.udef_chan && !minus.bot) {
      nom = 1;
      if (!plus.global && !plus.udef_global && !plus.chan &&
          !plus.udef_chan && !plus.bot)
        Py_RETURN_TRUE;   /* empty flags matches anyone */
    }
    if (flagrec_eq(&plus, &user)) {
      if (nom || !flagrec_eq(&minus, &user))
        ok = 1;
    }
  }
  return PyBool_FromLong(ok);
}

/* passwdok(handle, password) — True if password matches for handle */
static PyObject *py_passwdok(PyObject *self, PyObject *args)
{
  char *handle, *passwd;
  struct userrec *u;

  if (!PyArg_ParseTuple(args, "ss", &handle, &passwd))
    return NULL;
  u = get_user_by_handle(userlist, handle);
  if (u && u_pass_match(u, passwd))
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}

/* chhandle(oldhandle, newhandle) — rename a user. Returns True on success. */
static PyObject *py_chhandle(PyObject *self, PyObject *args)
{
  char *oldh, *newh;
  char newbuf[HANDLEN + 1];
  struct userrec *u;
  int i;

  if (!PyArg_ParseTuple(args, "ss", &oldh, &newh))
    return NULL;
  u = get_user_by_handle(userlist, oldh);
  if (!u)
    Py_RETURN_FALSE;
  strlcpy(newbuf, newh, sizeof newbuf);
  for (i = 0; newbuf[i]; i++)
    if (((unsigned char)newbuf[i] <= 32) || (newbuf[i] == '@'))
      newbuf[i] = '?';
  if (strchr(BADHANDCHARS, newbuf[0]) || !newbuf[0] ||
      newbuf[0] == '*' || get_user_by_handle(userlist, newbuf))
    Py_RETURN_FALSE;
  return PyBool_FromLong(change_handle(u, newbuf));
}

/* save() — write the userfile to disk */
static PyObject *py_save(PyObject *self, PyObject *args)
{
  write_userfile(-1);
  Py_RETURN_NONE;
}

/* ---- Ignore list ------------------------------------------------------ */

/* isignore(mask) — True if mask matches an active ignore entry */
static PyObject *py_isignore(PyObject *self, PyObject *args)
{
  char *mask;

  if (!PyArg_ParseTuple(args, "s", &mask))
    return NULL;
  return PyBool_FromLong(match_ignore(mask));
}

/* newignore(mask, creator, comment[, lifetime_seconds])
 * Add an ignore entry.  Omitting lifetime uses the default ignore_time. */
static PyObject *py_newignore(PyObject *self, PyObject *args)
{
  char *mask, *creator, *comment;
  long lifetime = -1;
  time_t expire_time;

  if (!PyArg_ParseTuple(args, "sss|l", &mask, &creator, &comment, &lifetime))
    return NULL;
  if (lifetime < 0)
    expire_time = (ignore_time > 0) ? (now + 60L * ignore_time) : 0;
  else if (lifetime == 0)
    expire_time = 0;   /* permanent */
  else
    expire_time = now + lifetime;
  addignore(mask, creator, comment, expire_time);
  Py_RETURN_NONE;
}

/* killignore(mask) — remove an ignore entry. Returns True if removed. */
static PyObject *py_killignore(PyObject *self, PyObject *args)
{
  char *mask;

  if (!PyArg_ParseTuple(args, "s", &mask))
    return NULL;
  return PyBool_FromLong(delignore(mask));
}

/* ignorelist() — return list of dicts with keys mask, creator, comment, expire, added */
static PyObject *py_ignorelist(PyObject *self, PyObject *args)
{
  struct igrec *ig;
  PyObject *list, *d;

  list = PyList_New(0);
  for (ig = global_ign; ig; ig = ig->next) {
    d = PyDict_New();
    PyDict_SetItemString(d, "mask",    PyUnicode_FromString(ig->igmask ? ig->igmask : ""));
    PyDict_SetItemString(d, "creator", PyUnicode_FromString(ig->user   ? ig->user   : ""));
    PyDict_SetItemString(d, "comment", PyUnicode_FromString(ig->msg    ? ig->msg    : ""));
    PyDict_SetItemString(d, "expire",  PyLong_FromLong((long)ig->expire));
    PyDict_SetItemString(d, "added",   PyLong_FromLong((long)ig->added));
    PyList_Append(list, d);
    Py_DECREF(d);
  }
  return list;
}

/* ---- DCC management --------------------------------------------------- */

/* hand2idx(handle) — return socket (idx) of first DCC chat for handle, or -1 */
static PyObject *py_hand2idx(PyObject *self, PyObject *args)
{
  char *handle;
  int i;

  if (!PyArg_ParseTuple(args, "s", &handle))
    return NULL;
  for (i = 0; i < dcc_total; i++)
    if ((dcc[i].type->flags & (DCT_SIMUL | DCT_BOT)) &&
        !strcasecmp(handle, dcc[i].nick))
      return PyLong_FromLong(dcc[i].sock);
  return PyLong_FromLong(-1L);
}

/* idx2hand(sock) — return nick/handle for a DCC socket, or None */
static PyObject *py_idx2hand(PyObject *self, PyObject *args)
{
  long sock;
  int i;

  if (!PyArg_ParseTuple(args, "l", &sock))
    return NULL;
  for (i = 0; i < dcc_total; i++)
    if (dcc[i].sock == sock)
      return PyUnicode_FromString(dcc[i].nick);
  Py_RETURN_NONE;
}

/* killdcc(sock[, reason]) — disconnect a DCC connection */
static PyObject *py_killdcc(PyObject *self, PyObject *args)
{
  long sock;
  char *reason = NULL;
  int i;

  if (!PyArg_ParseTuple(args, "l|s", &sock, &reason))
    return NULL;
  for (i = 0; i < dcc_total; i++) {
    if (dcc[i].sock == sock) {
      if (dcc[i].type->flags & DCT_CHAT) {
        dprintf(i, "Lost connection: %s\n", reason ? reason : "");
      }
      killsock(sock);
      lostdcc(i);
      Py_RETURN_NONE;
    }
  }
  PyErr_SetString(EggdropError, "invalid socket");
  return NULL;
}

/* dcclist([type]) — return list of dicts describing DCC connections */
static PyObject *py_dcclist(PyObject *self, PyObject *args)
{
  char *typefilter = NULL;
  int i;
  PyObject *list, *d;

  if (!PyArg_ParseTuple(args, "|s", &typefilter))
    return NULL;
  list = PyList_New(0);
  for (i = 0; i < dcc_total; i++) {
    if (!dcc[i].type)
      continue;
    if (typefilter && strcasecmp(dcc[i].type->name, typefilter))
      continue;
    d = PyDict_New();
    PyDict_SetItemString(d, "idx",    PyLong_FromLong(dcc[i].sock));
    PyDict_SetItemString(d, "nick",   PyUnicode_FromString(dcc[i].nick));
    PyDict_SetItemString(d, "host",   PyUnicode_FromString(dcc[i].host));
    PyDict_SetItemString(d, "type",   PyUnicode_FromString(dcc[i].type->name));
    PyDict_SetItemString(d, "time",   PyLong_FromLong((long)dcc[i].timeval));
    PyDict_SetItemString(d, "port",   PyLong_FromLong((long)dcc[i].port));
    PyList_Append(list, d);
    Py_DECREF(d);
  }
  return list;
}

/* dccused() — return number of active DCC connections */
static PyObject *py_dccused(PyObject *self, PyObject *args)
{
  return PyLong_FromLong((long)dcc_total);
}

/* ---- Channel extended queries ----------------------------------------- */

/* chanmasks_list(masklist) — helper to build Python list from masklist */
static PyObject *py_chanmasks_list(masklist *m)
{
  PyObject *list = PyList_New(0);
  PyObject *d;

  for (; m && m->mask && m->mask[0]; m = m->next) {
    d = PyDict_New();
    PyDict_SetItemString(d, "mask",  PyUnicode_FromString(m->mask));
    PyDict_SetItemString(d, "who",   PyUnicode_FromString(m->who ? m->who : ""));
    PyDict_SetItemString(d, "timer", PyLong_FromLong((long)(now - m->timer)));
    PyList_Append(list, d);
    Py_DECREF(d);
  }
  return list;
}

/* chanbans(channel) — return list of ban dicts {mask, who, timer} */
static PyObject *py_chanbans(PyObject *self, PyObject *args)
{
  char *chan;
  struct chanset_t *ch;

  if (!PyArg_ParseTuple(args, "s", &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch) {
    PyErr_SetString(EggdropError, "channel not found");
    return NULL;
  }
  return py_chanmasks_list(ch->channel.ban);
}

/* chanexempts(channel) — return list of exempt dicts {mask, who, timer} */
static PyObject *py_chanexempts(PyObject *self, PyObject *args)
{
  char *chan;
  struct chanset_t *ch;

  if (!PyArg_ParseTuple(args, "s", &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch) {
    PyErr_SetString(EggdropError, "channel not found");
    return NULL;
  }
  return py_chanmasks_list(ch->channel.exempt);
}

/* chaninvites(channel) — return list of invite dicts {mask, who, timer} */
static PyObject *py_chaninvites(PyObject *self, PyObject *args)
{
  char *chan;
  struct chanset_t *ch;

  if (!PyArg_ParseTuple(args, "s", &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch) {
    PyErr_SetString(EggdropError, "channel not found");
    return NULL;
  }
  return py_chanmasks_list(ch->channel.invite);
}

/* getchanidle(nick, channel) — return idle minutes for nick on channel, or -1 */
static PyObject *py_getchanidle(PyObject *self, PyObject *args)
{
  char *nick, *chan;
  struct chanset_t *ch;
  memberlist *m;

  if (!PyArg_ParseTuple(args, "ss", &nick, &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch)
    return PyLong_FromLong(-1L);
  m = ismember(ch, nick);
  if (!m)
    return PyLong_FromLong(-1L);
  return PyLong_FromLong((long)((now - m->last) / 60));
}

/* getchan_topic(channel) — return channel topic string, or None */
static PyObject *py_getchan_topic(PyObject *self, PyObject *args)
{
  char *chan;
  struct chanset_t *ch;

  if (!PyArg_ParseTuple(args, "s", &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch) {
    PyErr_SetString(EggdropError, "channel not found");
    return NULL;
  }
  if (!ch->channel.topic)
    Py_RETURN_NONE;
  return PyUnicode_FromString(ch->channel.topic);
}

/* botonchan([channel]) — True if the bot is on channel (or any channel if omitted) */
static PyObject *py_botonchan(PyObject *self, PyObject *args)
{
  char *chan = NULL;
  struct chanset_t *ch, *thechan = NULL;

  if (!PyArg_ParseTuple(args, "|s", &chan))
    return NULL;
  if (chan) {
    thechan = findchan_by_dname(chan);
    if (!thechan)
      Py_RETURN_FALSE;
    ch = thechan;
  } else {
    ch = chanset;
  }
  while (ch && (!thechan || thechan == ch)) {
    if (ismember(ch, botname))
      Py_RETURN_TRUE;
    ch = ch->next;
  }
  Py_RETURN_FALSE;
}

/* wasop(nick, channel) — True if nick was an op before a netsplit */
static PyObject *py_wasop(PyObject *self, PyObject *args)
{
  char *nick, *chan;
  struct chanset_t *ch;
  memberlist *m;

  if (!PyArg_ParseTuple(args, "ss", &nick, &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch)
    Py_RETURN_FALSE;
  m = ismember(ch, nick);
  if (m && chan_wasop(m))
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}

/* washalfop(nick, channel) — True if nick was a halfop before a netsplit */
static PyObject *py_washalfop(PyObject *self, PyObject *args)
{
  char *nick, *chan;
  struct chanset_t *ch;
  memberlist *m;

  if (!PyArg_ParseTuple(args, "ss", &nick, &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch)
    Py_RETURN_FALSE;
  m = ismember(ch, nick);
  if (m && chan_washalfop(m))
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}

/* isircbot(nick[, channel]) — True if nick is marked as a bot (IRCv3/005) */
static PyObject *py_isircbot(PyObject *self, PyObject *args)
{
  char *nick, *chan = NULL;
  struct chanset_t *ch, *thechan = NULL;
  memberlist *m;

  if (!PyArg_ParseTuple(args, "s|s", &nick, &chan))
    return NULL;
  if (chan) {
    thechan = findchan_by_dname(chan);
    if (!thechan)
      Py_RETURN_FALSE;
    ch = thechan;
  } else {
    ch = chanset;
  }
  while (ch && (!thechan || thechan == ch)) {
    m = ismember(ch, nick);
    if (m && chan_ircbot(m))
      Py_RETURN_TRUE;
    ch = ch->next;
  }
  Py_RETURN_FALSE;
}

/* account2nicks(account[, channel]) — return list of nicks with given IRC account */
static PyObject *py_account2nicks(PyObject *self, PyObject *args)
{
  char *account, *chan = NULL;
  struct chanset_t *ch, *thechan = NULL;
  memberlist *m;
  PyObject *list, *nick_str;
  int found, i;
  Py_ssize_t n;

  if (!PyArg_ParseTuple(args, "s|s", &account, &chan))
    return NULL;
  if (chan) {
    thechan = findchan_by_dname(chan);
    if (!thechan) {
      PyErr_SetString(EggdropError, "channel not found");
      return NULL;
    }
    ch = thechan;
  } else {
    ch = chanset;
  }
  list = PyList_New(0);
  while (ch && (!thechan || thechan == ch)) {
    for (m = ch->channel.member; m && m->nick[0]; m = m->next) {
      if (!rfc_casecmp(m->account, account)) {
        /* Deduplicate */
        found = 0;
        n = PyList_Size(list);
        for (i = 0; i < n; i++) {
          const char *s = PyUnicode_AsUTF8(PyList_GET_ITEM(list, i));
          if (s && !rfc_casecmp(m->nick, s)) { found = 1; break; }
        }
        if (!found) {
          nick_str = PyUnicode_FromString(m->nick);
          PyList_Append(list, nick_str);
          Py_DECREF(nick_str);
        }
      }
    }
    ch = ch->next;
  }
  return list;
}

/* hand2nicks(handle[, channel]) — return list of nicks for a given handle */
static PyObject *py_hand2nicks(PyObject *self, PyObject *args)
{
  char *handle, *chan = NULL;
  struct chanset_t *ch, *thechan = NULL;
  memberlist *m;
  struct userrec *u;
  PyObject *list, *nick_str;
  int found, i;
  Py_ssize_t n;

  if (!PyArg_ParseTuple(args, "s|s", &handle, &chan))
    return NULL;
  if (chan) {
    thechan = findchan_by_dname(chan);
    if (!thechan) {
      PyErr_SetString(EggdropError, "channel not found");
      return NULL;
    }
    ch = thechan;
  } else {
    ch = chanset;
  }
  list = PyList_New(0);
  while (ch && (!thechan || thechan == ch)) {
    for (m = ch->channel.member; m && m->nick[0]; m = m->next) {
      u = get_user_from_member(m);
      if (u && !strcasecmp(u->handle, handle)) {
        found = 0;
        n = PyList_Size(list);
        for (i = 0; i < n; i++) {
          const char *s = PyUnicode_AsUTF8(PyList_GET_ITEM(list, i));
          if (s && !rfc_casecmp(m->nick, s)) { found = 1; break; }
        }
        if (!found) {
          nick_str = PyUnicode_FromString(m->nick);
          PyList_Append(list, nick_str);
          Py_DECREF(nick_str);
        }
      }
    }
    ch = ch->next;
  }
  return list;
}

/* ---- Bot networking --------------------------------------------------- */

/* putbot(botnick, message) — send a zapf message to a linked bot */
static PyObject *py_putbot(PyObject *self, PyObject *args)
{
  char *botnick, *msg, msgbuf[401];
  int i;

  if (!PyArg_ParseTuple(args, "ss", &botnick, &msg))
    return NULL;
  i = nextbot(botnick);
  if (i < 0) {
    PyErr_SetString(EggdropError, "bot is not on the botnet");
    return NULL;
  }
  strlcpy(msgbuf, msg, sizeof msgbuf);
  botnet_send_zapf(i, botnetnick, botnick, msgbuf);
  Py_RETURN_NONE;
}

/* putallbots(message) — broadcast a zapf message to all linked bots */
static PyObject *py_putallbots(PyObject *self, PyObject *args)
{
  char *msg, msgbuf[401];

  if (!PyArg_ParseTuple(args, "s", &msg))
    return NULL;
  strlcpy(msgbuf, msg, sizeof msgbuf);
  botnet_send_zapf_broad(-1, botnetnick, NULL, msgbuf);
  Py_RETURN_NONE;
}

/* islinked(botnick) — True if named bot is linked to this bot */
static PyObject *py_islinked(PyObject *self, PyObject *args)
{
  char *botnick;

  if (!PyArg_ParseTuple(args, "s", &botnick))
    return NULL;
  return PyBool_FromLong(nextbot(botnick) >= 0);
}

/* bots() — return list of all linked bot names */
static PyObject *py_bots(PyObject *self, PyObject *args)
{
  tand_t *bot;
  PyObject *list = PyList_New(0);
  PyObject *s;

  for (bot = tandbot; bot; bot = bot->next) {
    s = PyUnicode_FromString(bot->bot);
    PyList_Append(list, s);
    Py_DECREF(s);
  }
  return list;
}

/* ---- String / text utilities ------------------------------------------ */

/* stripcodes(flags, text) — strip IRC formatting codes from text.
 * flags is a string like "cb" meaning strip color and bold.
 *   c=color  b=bold  r=reverse  u=underline  a=ansi  g=bell  o=ordinary
 *   i=italics  *=all
 * Returns cleaned text. */
static PyObject *py_stripcodes(PyObject *self, PyObject *args)
{
  char *flagstr, *text, *buf;
  int flags = 0;
  PyObject *result;
  const char *p;

  if (!PyArg_ParseTuple(args, "ss", &flagstr, &text))
    return NULL;
  for (p = flagstr; *p; p++)
    switch (*p) {
    case 'c': flags |= STRIP_COLOR;     break;
    case 'b': flags |= STRIP_BOLD;      break;
    case 'r': flags |= STRIP_REVERSE;   break;
    case 'u': flags |= STRIP_UNDERLINE; break;
    case 'a': flags |= STRIP_ANSI;      break;
    case 'g': flags |= STRIP_BELLS;     break;
    case 'o': flags |= STRIP_ORDINARY;  break;
    case 'i': flags |= STRIP_ITALICS;   break;
    case '*': flags |= STRIP_ALL;       break;
    default:
      PyErr_Format(PyExc_ValueError, "invalid strip flag: '%c'", *p);
      return NULL;
    }
  buf = nmalloc(strlen(text) + 1);
  strcpy(buf, text);
  strip_mirc_codes(flags, buf);
  result = PyUnicode_FromString(buf);
  nfree(buf);
  return result;
}

/* matchstr(pattern, string) — IRC glob match (?, *). Returns True if match. */
static PyObject *py_matchstr(PyObject *self, PyObject *args)
{
  char *pattern, *string;

  if (!PyArg_ParseTuple(args, "ss", &pattern, &string))
    return NULL;
  return PyBool_FromLong(wild_match_per(pattern, string));
}

/* ---- Server / network helpers ---------------------------------------- */

/* puthelp(text) — queue a raw IRC line to the help/notice queue */
static PyObject *py_puthelp(PyObject *self, PyObject *args)
{
  char *s;

  if (!PyArg_ParseTuple(args, "s", &s))
    return NULL;
  dprintf(DP_HELP, "%s\n", s);
  Py_RETURN_NONE;
}

/* tagmsg(tag, target) — send an IRCv3 TAGMSG with message-tag(s) */
static PyObject *py_tagmsg(PyObject *self, PyObject *args)
{
  char *tag, *target;

  if (!PyArg_ParseTuple(args, "ss", &tag, &target))
    return NULL;
  dprintf(DP_SERVER, "@%s TAGMSG %s\n", tag, target);
  Py_RETURN_NONE;
}

/* cap(action, arg) — send IRCv3 CAP commands
 * action='req', capability — send CAP REQ :capability
 * action='raw', subcmd    — send a raw CAP subcmd */
static PyObject *py_cap(PyObject *self, PyObject *args)
{
  char *action, *arg;

  if (!PyArg_ParseTuple(args, "ss", &action, &arg))
    return NULL;

  if (!strcasecmp(action, "req")) {
    dprintf(DP_SERVER, "CAP REQ :%s\n", arg);
    Py_RETURN_NONE;
  }
  if (!strcasecmp(action, "raw")) {
    dprintf(DP_SERVER, "CAP %s\n", arg);
    Py_RETURN_NONE;
  }
  PyErr_SetString(PyExc_ValueError, "cap: action must be 'req' or 'raw'");
  return NULL;
}

static PyMethodDef MyPyMethods[] = {
    {"bind", py_bind, METH_VARARGS, "register an eggdrop python bind"},
    {"findircuser", py_findircuser, METH_VARARGS, "find an IRC user by nickname and optional channel"},
    {"putserv",  py_putserv,  METH_VARARGS, "queue a raw IRC line to the server (normal queue)"},
    {"putquick", py_putquick, METH_VARARGS, "queue a raw IRC line to the server (quick queue)"},
    {"putnow",   py_putnow,   METH_VARARGS, "send a raw IRC line to the server immediately"},
    {"putdcc",   py_putdcc,   METH_VARARGS, "send text to a DCC party by index"},
    {"putlog",   py_putlog,   METH_VARARGS, "write to the eggdrop log (text[, loglevel[, channel]])"},
    {"isonchan", py_isonchan, METH_VARARGS, "return True if nick is on channel"},
    {"getchanhost", py_getchanhost, METH_VARARGS, "return user@host of nick on channel, or None"},
    {"chanlist", py_chanlist, METH_VARARGS, "return list of member dicts for a channel"},
    {"botname",  py_botname,  METH_NOARGS,  "return bot's current IRC nickname"},
    {"channels", py_channels, METH_NOARGS,  "return list of channels the bot is on"},
    /* Channel member status */
    {"isop",        py_isop,        METH_VARARGS, "return True if nick has op on channel"},
    {"ishalfop",    py_ishalfop,    METH_VARARGS, "return True if nick has halfop on channel"},
    {"isvoice",     py_isvoice,     METH_VARARGS, "return True if nick has voice on channel"},
    {"isaway",      py_isaway,      METH_VARARGS, "return True if nick is marked away on channel"},
    {"botisop",     py_botisop,     METH_VARARGS, "return True if bot has op on channel"},
    {"botishalfop", py_botishalfop, METH_VARARGS, "return True if bot has halfop on channel"},
    {"botisvoice",  py_botisvoice,  METH_VARARGS, "return True if bot has voice on channel"},
    {"getaccount",  py_getaccount,  METH_VARARGS, "return IRC account name of nick on channel, or None"},
    {"isidentified", py_isidentified, METH_VARARGS, "return True if nick is logged in to services"},
    /* Handle/nick resolution */
    {"nick2hand",   py_nick2hand,   METH_VARARGS, "return eggdrop handle for nick on channel, or None"},
    {"hand2nick",   py_hand2nick,   METH_VARARGS, "return nick of handle on channel, or None"},
    {"isbotnick",   py_isbotnick,   METH_VARARGS, "return True if nick matches the bot's nickname"},
    /* User database */
    {"countusers",  py_countusers,  METH_NOARGS,  "return number of users in the userlist"},
    {"validuser",   py_validuser,   METH_VARARGS, "return True if handle exists in userlist"},
    {"finduser",    py_finduser,    METH_VARARGS, "return handle matching nick!user@host, or None"},
    {"userlist",    py_userlist,    METH_NOARGS,  "return list of all user handles"},
    /* Miscellaneous */
    {"rand",        py_rand,        METH_VARARGS, "return random integer in [0, n)"},
    {"unixtime",    py_unixtime,    METH_NOARGS,  "return current Unix timestamp as integer"},
    {"duration",    py_duration,    METH_VARARGS, "convert seconds to human-readable string"},
    {"maskhost",    py_maskhost,    METH_VARARGS, "create IRC hostmask from nick and user@host"},
    /* User management */
    {"adduser",     py_adduser,     METH_VARARGS, "add a user to the userlist: adduser(handle[, hostmask])"},
    {"deluser",     py_deluser,     METH_VARARGS, "remove a user from the userlist: deluser(handle)"},
    {"addhost",     py_addhost,     METH_VARARGS, "add a hostmask to a user: addhost(handle, mask)"},
    {"delhost",     py_delhost,     METH_VARARGS, "remove a hostmask from a user: delhost(handle, mask)"},
    {"chattr",      py_chattr,      METH_VARARGS, "get/set user flags: chattr(handle[, changes[, channel]])"},
    {"matchattr",   py_matchattr,   METH_VARARGS, "test user flags: matchattr(handle, flags[, channel])"},
    {"passwdok",    py_passwdok,    METH_VARARGS, "test password: passwdok(handle, password)"},
    {"chhandle",    py_chhandle,    METH_VARARGS, "rename a user: chhandle(oldhandle, newhandle)"},
    {"save",        py_save,        METH_NOARGS,  "write the userfile to disk"},
    /* Ignore list */
    {"isignore",    py_isignore,    METH_VARARGS, "True if mask matches an ignore entry"},
    {"newignore",   py_newignore,   METH_VARARGS, "add an ignore: newignore(mask, creator, comment[, lifetime])"},
    {"killignore",  py_killignore,  METH_VARARGS, "remove an ignore entry: killignore(mask)"},
    {"ignorelist",  py_ignorelist,  METH_NOARGS,  "return list of ignore dicts"},
    /* DCC management */
    {"hand2idx",    py_hand2idx,    METH_VARARGS, "return socket for handle's DCC chat, or -1"},
    {"idx2hand",    py_idx2hand,    METH_VARARGS, "return nick for a DCC socket, or None"},
    {"killdcc",     py_killdcc,     METH_VARARGS, "disconnect a DCC connection: killdcc(sock[, reason])"},
    {"dcclist",     py_dcclist,     METH_VARARGS, "return list of DCC connection dicts: dcclist([type])"},
    {"dccused",     py_dccused,     METH_NOARGS,  "return number of active DCC connections"},
    /* Channel extended queries */
    {"chanbans",        py_chanbans,        METH_VARARGS, "return list of ban dicts for channel"},
    {"chanexempts",     py_chanexempts,     METH_VARARGS, "return list of exempt dicts for channel"},
    {"chaninvites",     py_chaninvites,     METH_VARARGS, "return list of invite dicts for channel"},
    {"getchanidle",     py_getchanidle,     METH_VARARGS, "return idle minutes for nick on channel, or -1"},
    {"getchan_topic",   py_getchan_topic,   METH_VARARGS, "return topic string for channel, or None"},
    {"botonchan",       py_botonchan,       METH_VARARGS, "True if bot is on channel (or any channel if omitted)"},
    {"wasop",           py_wasop,           METH_VARARGS, "True if nick was op before netsplit"},
    {"washalfop",       py_washalfop,       METH_VARARGS, "True if nick was halfop before netsplit"},
    {"isircbot",        py_isircbot,        METH_VARARGS, "True if nick is marked as a bot (IRCv3/005)"},
    {"account2nicks",   py_account2nicks,   METH_VARARGS, "list nicks with given IRC account: account2nicks(acct[, chan])"},
    {"hand2nicks",      py_hand2nicks,      METH_VARARGS, "list nicks for a handle: hand2nicks(handle[, chan])"},
    /* Bot networking */
    {"putbot",      py_putbot,      METH_VARARGS, "send zapf message to linked bot: putbot(botnick, msg)"},
    {"putallbots",  py_putallbots,  METH_VARARGS, "broadcast zapf message to all bots: putallbots(msg)"},
    {"islinked",    py_islinked,    METH_VARARGS, "True if named bot is currently linked"},
    {"bots",        py_bots,        METH_NOARGS,  "return list of all linked bot names"},
    /* Text / string utilities */
    {"stripcodes",  py_stripcodes,  METH_VARARGS, "strip IRC formatting: stripcodes(flags, text)"},
    {"matchstr",    py_matchstr,    METH_VARARGS, "IRC glob match: matchstr(pattern, string)"},
    /* IRCX — Microsoft IRC extensions / Ophion */
    {"ircxprop",      py_ircxprop,      METH_VARARGS, "get/set an IRCX property (PROP target prop [value])"},
    {"ircxaccess",    py_ircxaccess,    METH_VARARGS, "manage IRCX access list (channel, list|add|del, [level], [mask])"},
    {"ircxcreate",    py_ircxcreate,    METH_VARARGS, "create an IRCX channel (CREATE channel [modes])"},
    {"ircxnegotiate", py_ircxnegotiate, METH_NOARGS,  "send IRCX negotiate command to enable IRCX mode"},
    /* Server / network helpers */
    {"puthelp",  py_puthelp,  METH_VARARGS, "queue a raw IRC line to the help/notice queue"},
    {"tagmsg",   py_tagmsg,   METH_VARARGS, "send an IRCv3 TAGMSG (tag, target)"},
    {"cap",      py_cap,      METH_VARARGS, "send IRCv3 CAP command: cap('req', cap) or cap('raw', subcmd)"},
#ifdef HAVE_TCL
    {"parse_tcl_list", py_parse_tcl_list, METH_VARARGS, "convert a Tcl list string to a Python list"},
    {"parse_tcl_dict", py_parse_tcl_dict, METH_VARARGS, "convert a Tcl dict string to a Python dict"},
    /* DNS */
    {"dnsdot", py_dnsdot, METH_VARARGS,
     "configure DNS-over-TLS (RFC 7858): dnsdot([on, server[, port[, -noverify]]] | off)"},
#endif
    /* Bot management */
    {"die",         py_die,         METH_VARARGS, "shut down the bot: die([reason])"},
    {"restart",     py_restart,     METH_NOARGS,  "save userfile and restart bot"},
    {"rehash",      py_rehash,      METH_NOARGS,  "save userfile and rehash config"},
    /* User entry access */
    {"getinfo",        py_getinfo,        METH_VARARGS, "get INFO string for handle, or None"},
    {"setinfo",        py_setinfo,        METH_VARARGS, "set INFO string: setinfo(handle, info)"},
    {"getcomment",     py_getcomment,     METH_VARARGS, "get COMMENT string for handle, or None"},
    {"setcomment",     py_setcomment,     METH_VARARGS, "set COMMENT string: setcomment(handle, comment)"},
    {"gethosts",       py_gethosts,       METH_VARARGS, "return list of hostmasks for handle"},
    {"getaccount_str", py_getaccount_str, METH_VARARGS, "return IRC account for handle from userdb, or None"},
    /* Channel settings */
    {"chanset",     py_chanset,     METH_VARARGS, "return dict of channel configuration settings"},
    /* Twitch extensions */
    {"twitchmods",  py_twitchmods,  METH_VARARGS, "return mod list for Twitch channel"},
    {"twitchvips",  py_twitchvips,  METH_VARARGS, "return VIP list for Twitch channel"},
    {"ismod",       py_ismod,       METH_VARARGS, "True if nick is a Twitch mod: ismod(nick[, chan])"},
    {"isvip",       py_isvip,       METH_VARARGS, "True if nick is a Twitch VIP: isvip(nick[, chan])"},
    {"__displayhook__", py_displayhook, METH_O, "display hook for python expressions"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

#ifdef HAVE_TCL
static PyMethodDef EggTclMethods[] = {
    {"__dir__", py_dir, METH_VARARGS, ""},
    {"__getattr__", py_findtclfunc, METH_VARARGS, "fallback to call Tcl functions transparently"},
    {NULL, NULL, 0, NULL}
};
#endif /* HAVE_TCL */

static cmd_t mydcc[] = {
  /* command  flags  function     tcl-name */
  {"python",    "n",    (IntFunc) cmd_python,   NULL},
  {NULL,        NULL,   NULL,                   NULL}  /* Mark end. */
};

static struct PyModuleDef eggdrop = {
    PyModuleDef_HEAD_INIT,
    "eggdrop",      /* name of module */
    0,              /* module documentation, may be NULL */
    -1,             /* size of per-interpreter state of the module,
                    or -1 if the module keeps state in global variables. */
    MyPyMethods
};

#ifdef HAVE_TCL
static struct PyModuleDef eggdrop_tcl = { PyModuleDef_HEAD_INIT, "eggdrop.tcl", NULL, -1, EggTclMethods };

static PyTypeObject TclFuncType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "eggdrop.TclFunc",
    .tp_doc = "Tcl function that is callable from Python.",
    .tp_basicsize = sizeof(TclFunc),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = PyType_GenericNew,
    .tp_call = python_call_tcl,
};
#endif /* HAVE_TCL */

static PyMethodDef PythonBindMethods[] = {
    {"unbind", py_unbind, METH_VARARGS, "deregister an eggdrop python bind"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static PyTypeObject PythonBindType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "eggdrop.PythonBind",
    .tp_doc = "Eggdrop bind to a python callback",
    .tp_basicsize = sizeof(PythonBind),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = PyType_GenericNew,
    .tp_methods = PythonBindMethods
};

PyMODINIT_FUNC PyInit_eggdrop(void) {
  PyObject *pymodobj;

  pymodobj = PyModule_Create(&eggdrop);
  if (pymodobj == NULL)
    return NULL;

  EggdropError = PyErr_NewException("eggdrop.error", NULL, NULL);
  Py_INCREF(EggdropError);
  if (PyModule_AddObject(pymodobj, "error", EggdropError) < 0) {
    Py_DECREF(EggdropError);
    Py_CLEAR(EggdropError);
    Py_DECREF(pymodobj);
    return NULL;
  }

#ifdef HAVE_TCL
  {
    PyObject *eggtclmodobj, *pymoddict;
    eggtclmodobj = PyModule_Create(&eggdrop_tcl);
    PyModule_AddObject(pymodobj, "tcl", eggtclmodobj);

    pymoddict = PyModule_GetDict(pymodobj);
    PyDict_SetItemString(pymoddict, "tcl", eggtclmodobj);

    pymoddict = PyImport_GetModuleDict();
    PyDict_SetItemString(pymoddict, "eggdrop.tcl", eggtclmodobj);

    PyType_Ready(&TclFuncType);
  }
#endif /* HAVE_TCL */

  PyType_Ready(&PythonBindType);

  return pymodobj;
}
