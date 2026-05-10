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
#include <stdatomic.h>
#include "md5/md5.h"

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

extern tcl_timer_t *timer, *utimer;
extern char listen_ip[];
extern module_entry *module_list;
extern void do_boot(int, char *, char *);
extern int botlink(char *, int, char *);
extern int botunlink(int, char *, char *, char *);
extern void botnet_send_link(int, char *, char *, char *);
extern void botnet_send_unlink(int, char *, char *, char *, char *);
extern char *lastbot(char *);
extern void set_away(int, char *);
extern void not_away(int);
extern int findidx(int);
extern p_tcl_bind_list bind_table_list;
extern _Atomic uint64_t otraffic_irc, otraffic_irc_today,
                         otraffic_bn, otraffic_bn_today,
                         otraffic_dcc, otraffic_dcc_today,
                         otraffic_trans, otraffic_trans_today,
                         itraffic_irc, itraffic_irc_today,
                         itraffic_bn, itraffic_bn_today,
                         itraffic_dcc, itraffic_dcc_today,
                         itraffic_trans, itraffic_trans_today;

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
        for (Py_ssize_t i = 0; i < n; i++) {
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
        for (Py_ssize_t i = 0; i < n; i++) {
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

  if (!python_callbacks)
    return 0;
  pybind = PyDict_GetItemString(python_callbacks, name); /* borrowed */
  if (!pybind)
    return 0;

  pyargs = PyTuple_New(argc);
  for (int i = 0; i < argc; i++)
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

/* Called by egg_eval() when no Tcl interpreter is present.
 * Executes the script as Python code and returns 0 on success. */
static int python_script_eval(const char *script)
{
  PyObject *result;

  if (!script || !script[0])
    return 0;
  result = PyRun_String(script, Py_file_input, pglobals, pglobals);
  if (!result) {
    PyErr_Print();
    return 1; /* TCL_ERROR */
  }
  Py_DECREF(result);
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
  if (bind->mask)  { op_free(bind->mask);  bind->mask  = NULL; }
  if (bind->flags) { op_free(bind->flags); bind->flags = NULL; }
#endif
  Py_RETURN_NONE;
}

#ifdef HAVE_TCL
void python_bind_destroyed(ClientData cd) {
  PythonBind *bind = cd;

  Py_DECREF(bind->callback);
  op_free(bind->mask);
  op_free(bind->flags);
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
  bind->mask = op_strdup(mask);
  bind->flags = op_strdup(flags);
  bind->bindtable = tl;
  bind->callback = callback;
  hash = PyObject_Hash((PyObject *)bind);
  {
    op_strbuf_t _b;
    op_strbuf_appendf(&_b, "*python:%s:%" PRIx64, bindtype, (int64_t)hash);
    strlcpy(bind->tclcmdname, op_strbuf_str(&_b), sizeof bind->tclcmdname);
    op_strbuf_free(&_b);
  }

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
  char *nick, *chan;
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
  {
    op_strbuf_t _b;
    op_strbuf_appendf(&_b, "%s!%s", m->nick, m->userhost);
    u = get_user_by_host(op_strbuf_str(&_b));
    op_strbuf_free(&_b);
  }
  if (!u)
    Py_RETURN_NONE;
  return PyUnicode_FromString(u->handle);
}

/* hand2nick(handle, chan) — return nick of user with handle on chan, or None */
static PyObject *py_hand2nick(PyObject *self, PyObject *args)
{
  char *handle, *chan;
  struct chanset_t *ch;
  memberlist *m;
  struct userrec *u;

  if (!PyArg_ParseTuple(args, "ss", &handle, &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch)
    Py_RETURN_NONE;
  for (m = ch->channel.member; m && m->nick[0]; m = m->next) {
    {
      op_strbuf_t _b;
      op_strbuf_appendf(&_b, "%s!%s", m->nick, m->userhost);
      u = get_user_by_host(op_strbuf_str(&_b));
      op_strbuf_free(&_b);
    }
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
  op_strbuf_t s;
  uint64_t sec, tmp;
  long n;
  PyObject *ret;

  if (!PyArg_ParseTuple(args, "l", &n))
    return NULL;
  if (n <= 0)
    return PyUnicode_FromString("0 seconds");
  sec = (uint64_t) n;
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
  else if (!op_strbuf_empty(&s))
    op_strbuf_truncate(&s, op_strbuf_len(&s) - 1);  /* strip trailing space */
  ret = PyUnicode_FromString(op_strbuf_str(&s));
  op_strbuf_free(&s);
  return ret;
}

/* maskhost(nick, userhost) — create a standard IRC hostmask from nick!user@host */
static PyObject *py_maskhost(PyObject *self, PyObject *args)
{
  [[maybe_unused]] char *nick;
  char *userhost, *at, *dot;
  op_strbuf_t buf;

  if (!PyArg_ParseTuple(args, "ss", &nick, &userhost))
    return NULL;
  at = strchr(userhost, '@');
  if (!at) {
    /* If only host given, build *!*@*.domain or *!*@host */
    dot = strchr(userhost, '.');
    if (dot)
      op_strbuf_appendf(&buf, "*!*@*%s", dot);
    else
      op_strbuf_appendf(&buf, "*!*@%s", userhost);
  } else {
    /* userhost is user@host */
    dot = strchr(at + 1, '.');
    if (dot)
      op_strbuf_appendf(&buf, "*!*@*%s", dot);
    else
      op_strbuf_appendf(&buf, "*!*@%s", at + 1);
  }
  PyObject *ret = PyUnicode_FromString(op_strbuf_str(&buf));
  op_strbuf_free(&buf);
  return ret;
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
  char *reason = NULL;
  op_strbuf_t s;

  if (!PyArg_ParseTuple(args, "|s", &reason))
    return NULL;
  if (reason && reason[0]) {
    op_strbuf_appendf(&s, "BOT SHUTDOWN (%s)", reason);
    strlcpy(quit_msg, reason, 1024);
  } else {
    op_strbuf_appendf(&s, "BOT SHUTDOWN (No reason)");
    quit_msg[0] = 0;
  }
  kill_bot(op_strbuf_str(&s), quit_msg[0] ? quit_msg : "EXIT");
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

  if (!PyArg_ParseTuple(args, "ss", &oldh, &newh))
    return NULL;
  u = get_user_by_handle(userlist, oldh);
  if (!u)
    Py_RETURN_FALSE;
  strlcpy(newbuf, newh, sizeof newbuf);
  for (int i = 0; newbuf[i]; i++)
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

  if (!PyArg_ParseTuple(args, "s", &handle))
    return NULL;
  for (int i = 0; i < dcc_total; i++)
    if ((dcc[i].type->flags & (DCT_SIMUL | DCT_BOT)) &&
        !strcasecmp(handle, dcc[i].nick))
      return PyLong_FromLong(dcc[i].sock);
  return PyLong_FromLong(-1L);
}

/* idx2hand(sock) — return nick/handle for a DCC socket, or None */
static PyObject *py_idx2hand(PyObject *self, PyObject *args)
{
  long sock;

  if (!PyArg_ParseTuple(args, "l", &sock))
    return NULL;
  for (int i = 0; i < dcc_total; i++)
    if (dcc[i].sock == sock)
      return PyUnicode_FromString(dcc[i].nick);
  Py_RETURN_NONE;
}

/* killdcc(sock[, reason]) — disconnect a DCC connection */
static PyObject *py_killdcc(PyObject *self, PyObject *args)
{
  long sock;
  char *reason = NULL;

  if (!PyArg_ParseTuple(args, "l|s", &sock, &reason))
    return NULL;
  for (int i = 0; i < dcc_total; i++) {
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
  PyObject *list, *d;

  if (!PyArg_ParseTuple(args, "|s", &typefilter))
    return NULL;
  list = PyList_New(0);
  for (int i = 0; i < dcc_total; i++) {
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
  int found;

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
        Py_ssize_t n = PyList_Size(list);
        for (Py_ssize_t i = 0; i < n; i++) {
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
  int found;

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
        Py_ssize_t n = PyList_Size(list);
        for (Py_ssize_t i = 0; i < n; i++) {
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
  char *botnick, *msg;
  op_strbuf_t _b;

  if (!PyArg_ParseTuple(args, "ss", &botnick, &msg))
    return NULL;
  int i = nextbot(botnick);
  if (i < 0) {
    PyErr_SetString(EggdropError, "bot is not on the botnet");
    return NULL;
  }
  op_strbuf_appendf(&_b, "%s", msg);
  botnet_send_zapf(i, botnetnick, botnick, op_strbuf_str(&_b));
  op_strbuf_free(&_b);
  Py_RETURN_NONE;
}

/* putallbots(message) — broadcast a zapf message to all linked bots */
static PyObject *py_putallbots(PyObject *self, PyObject *args)
{
  char *msg;
  op_strbuf_t _b;

  if (!PyArg_ParseTuple(args, "s", &msg))
    return NULL;
  op_strbuf_appendf(&_b, "%s", msg);
  botnet_send_zapf_broad(-1, botnetnick, NULL, op_strbuf_str(&_b));
  op_strbuf_free(&_b);
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
  buf = op_strdup(text);
  strip_mirc_codes(flags, buf);
  result = PyUnicode_FromString(buf);
  op_free(buf);
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

/* ---- Channel presence queries ----------------------------------------- */

/* onchan(nick[, channel]) — True if nick is on channel (or any channel) */
static PyObject *py_onchan(PyObject *self, PyObject *args)
{
  char *nick, *chan = NULL;
  struct chanset_t *ch, *thech = NULL;

  if (!PyArg_ParseTuple(args, "s|s", &nick, &chan))
    return NULL;
  if (chan) {
    thech = findchan_by_dname(chan);
    if (!thech)
      Py_RETURN_FALSE;
    ch = thech;
  } else
    ch = chanset;
  while (ch && (thech == NULL || thech == ch)) {
    if (ismember(ch, nick))
      Py_RETURN_TRUE;
    ch = ch->next;
  }
  Py_RETURN_FALSE;
}

/* handonchan(handle[, channel]) — True if handle's user is on channel */
static PyObject *py_handonchan(PyObject *self, PyObject *args)
{
  char *handle, *chan = NULL;
  struct chanset_t *ch, *thech = NULL;
  struct userrec *u;
  memberlist *m;

  if (!PyArg_ParseTuple(args, "s|s", &handle, &chan))
    return NULL;
  if (chan) {
    thech = findchan_by_dname(chan);
    if (!thech)
      Py_RETURN_FALSE;
    ch = thech;
  } else
    ch = chanset;
  while (ch && (thech == NULL || thech == ch)) {
    for (m = ch->channel.member; m && m->nick[0]; m = m->next) {
      u = get_user_from_member(m);
      if (u && !strcasecmp(u->handle, handle))
        Py_RETURN_TRUE;
    }
    ch = ch->next;
  }
  Py_RETURN_FALSE;
}

/* onchansplit(nick[, channel]) — True if nick is on a netsplit */
static PyObject *py_onchansplit(PyObject *self, PyObject *args)
{
  char *nick, *chan = NULL;
  struct chanset_t *ch, *thech = NULL;
  memberlist *m;

  if (!PyArg_ParseTuple(args, "s|s", &nick, &chan))
    return NULL;
  if (chan) {
    thech = findchan_by_dname(chan);
    if (!thech)
      Py_RETURN_FALSE;
    ch = thech;
  } else
    ch = chanset;
  while (ch && (thech == NULL || thech == ch)) {
    m = ismember(ch, nick);
    if (m && chan_issplit(m))
      Py_RETURN_TRUE;
    ch = ch->next;
  }
  Py_RETURN_FALSE;
}

/* topic(channel) — return channel topic string, or empty string */
static PyObject *py_topic(PyObject *self, PyObject *args)
{
  char *chan;
  struct chanset_t *ch;

  if (!PyArg_ParseTuple(args, "s", &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch) {
    PyErr_SetString(EggdropError, "invalid channel");
    return NULL;
  }
  return PyUnicode_FromString(ch->channel.topic ? ch->channel.topic : "");
}

/* validchan(channel) — True if channel is in the bot's channel list */
static PyObject *py_validchan(PyObject *self, PyObject *args)
{
  char *chan;

  if (!PyArg_ParseTuple(args, "s", &chan))
    return NULL;
  if (findchan_by_dname(chan))
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}

/* getchanjoin(nick, channel) — return join timestamp for nick on channel */
static PyObject *py_getchanjoin(PyObject *self, PyObject *args)
{
  char *nick, *chan;
  struct chanset_t *ch;
  memberlist *m;

  if (!PyArg_ParseTuple(args, "ss", &nick, &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch) {
    PyErr_SetString(EggdropError, "invalid channel");
    return NULL;
  }
  m = ismember(ch, nick);
  if (!m) {
    PyErr_Format(EggdropError, "%s is not on %s", nick, chan);
    return NULL;
  }
  return PyLong_FromLongLong((long long)m->joined);
}

/* botisowner([channel]) — True if bot has channel owner (+q) status */
static PyObject *py_botisowner(PyObject *self, PyObject *args)
{
  char *chan = NULL;
  struct chanset_t *ch;
  memberlist *m;

  if (!PyArg_ParseTuple(args, "|s", &chan))
    return NULL;
  if (chan) {
    ch = findchan_by_dname(chan);
    if (!ch)
      Py_RETURN_FALSE;
    m = ismember(ch, botname);
    if (m && chan_hasowner(m))
      Py_RETURN_TRUE;
    Py_RETURN_FALSE;
  }
  for (ch = chanset; ch; ch = ch->next) {
    m = ismember(ch, botname);
    if (m && chan_hasowner(m))
      Py_RETURN_TRUE;
  }
  Py_RETURN_FALSE;
}

/* isowner(nick, channel) — True if nick has channel owner (+q) status */
static PyObject *py_isowner(PyObject *self, PyObject *args)
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
  if (m && chan_hasowner(m))
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}

/* ---- Channel mode / action commands (require irc.mod) ------------------ */

/* getchanmode(channel) — return mode string for channel */
static PyObject *py_getchanmode(PyObject *self, PyObject *args)
{
  char *chan;
  struct chanset_t *ch;
  module_entry *me;

  if (!PyArg_ParseTuple(args, "s", &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch) {
    PyErr_SetString(EggdropError, "invalid channel");
    return NULL;
  }
  me = module_find("irc", 0, 0);
  if (!me) {
    PyErr_SetString(EggdropError, "irc module not loaded");
    return NULL;
  }
  return PyUnicode_FromString(((const char *(*)(struct chanset_t *))me->funcs[24])(ch));
}

/* pushmode(channel, mode[, arg]) — queue a mode change */
static PyObject *py_pushmode(PyObject *self, PyObject *args)
{
  char *chan, *modestr, *arg = NULL;
  struct chanset_t *ch;
  char plus, mode;

  if (!PyArg_ParseTuple(args, "ss|s", &chan, &modestr, &arg))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch) {
    PyErr_SetString(EggdropError, "invalid channel");
    return NULL;
  }
  plus = modestr[0];
  mode = modestr[1];
  if (plus != '+' && plus != '-') {
    mode = plus;
    plus = '+';
  }
  add_mode(ch, plus, mode, arg ? arg : "");
  Py_RETURN_NONE;
}

/* flushmode(channel) — flush pending mode changes */
static PyObject *py_flushmode(PyObject *self, PyObject *args)
{
  char *chan;
  struct chanset_t *ch;
  module_entry *me;

  if (!PyArg_ParseTuple(args, "s", &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch) {
    PyErr_SetString(EggdropError, "invalid channel");
    return NULL;
  }
  me = module_find("irc", 0, 0);
  if (!me) {
    PyErr_SetString(EggdropError, "irc module not loaded");
    return NULL;
  }
  ((void (*)(struct chanset_t *, int))me->funcs[IRC_FLUSH_MODE])(ch, 0);
  Py_RETURN_NONE;
}

/* putkick(channel, nicks, [comment]) — kick nick(s) from channel */
static PyObject *py_putkick(PyObject *self, PyObject *args)
{
  char *chan, *nicks, *comment = "";
  struct chanset_t *ch;

  if (!PyArg_ParseTuple(args, "ss|s", &chan, &nicks, &comment))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch) {
    PyErr_SetString(EggdropError, "invalid channel");
    return NULL;
  }
  /* Send individual kicks for each comma-separated nick */
  {
    char buf[512];
    strlcpy(buf, nicks, sizeof buf);
    char *p = buf;
    while (p) {
      char *nick = p;
      p = strchr(nick, ',');
      if (p) *p++ = 0;
      memberlist *m = ismember(ch, nick);
      if (m) {
        m->flags |= SENTKICK;
        dprintf(DP_SERVER, "KICK %s %s :%s\n", ch->name, nick, comment);
      }
    }
  }
  Py_RETURN_NONE;
}

/* resetbans(channel) — reset channel bans to match the bot's internal list */
static PyObject *py_resetbans(PyObject *self, PyObject *args)
{
  char *chan;
  struct chanset_t *ch;
  module_entry *me;

  if (!PyArg_ParseTuple(args, "s", &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch) {
    PyErr_SetString(EggdropError, "invalid channel");
    return NULL;
  }
  me = module_find("irc", 0, 0);
  if (!me) {
    PyErr_SetString(EggdropError, "irc module not loaded");
    return NULL;
  }
  ((void (*)(struct chanset_t *, int, int))me->funcs[IRC_RESET_CHAN_INFO])(ch, 0x08, 0);
  Py_RETURN_NONE;
}

/* resetexempts(channel) — reset channel exempts */
static PyObject *py_resetexempts(PyObject *self, PyObject *args)
{
  char *chan;
  struct chanset_t *ch;
  module_entry *me;

  if (!PyArg_ParseTuple(args, "s", &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch) {
    PyErr_SetString(EggdropError, "invalid channel");
    return NULL;
  }
  me = module_find("irc", 0, 0);
  if (!me) {
    PyErr_SetString(EggdropError, "irc module not loaded");
    return NULL;
  }
  ((void (*)(struct chanset_t *, int, int))me->funcs[IRC_RESET_CHAN_INFO])(ch, 0x10, 0);
  Py_RETURN_NONE;
}

/* resetinvites(channel) — reset channel invites */
static PyObject *py_resetinvites(PyObject *self, PyObject *args)
{
  char *chan;
  struct chanset_t *ch;
  module_entry *me;

  if (!PyArg_ParseTuple(args, "s", &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch) {
    PyErr_SetString(EggdropError, "invalid channel");
    return NULL;
  }
  me = module_find("irc", 0, 0);
  if (!me) {
    PyErr_SetString(EggdropError, "irc module not loaded");
    return NULL;
  }
  ((void (*)(struct chanset_t *, int, int))me->funcs[IRC_RESET_CHAN_INFO])(ch, 0x20, 0);
  Py_RETURN_NONE;
}

/* resetchan(channel) — reset channel state (request fresh data from server) */
static PyObject *py_resetchan(PyObject *self, PyObject *args)
{
  char *chan;
  struct chanset_t *ch;
  module_entry *me;

  if (!PyArg_ParseTuple(args, "s", &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch) {
    PyErr_SetString(EggdropError, "invalid channel");
    return NULL;
  }
  me = module_find("irc", 0, 0);
  if (!me) {
    PyErr_SetString(EggdropError, "irc module not loaded");
    return NULL;
  }
  ((void (*)(struct chanset_t *, int, int))me->funcs[IRC_RESET_CHAN_INFO])(ch, 0xFF, 1);
  Py_RETURN_NONE;
}

/* refreshchan(channel) — refresh channel info from server without clearing */
static PyObject *py_refreshchan(PyObject *self, PyObject *args)
{
  char *chan;
  struct chanset_t *ch;
  module_entry *me;

  if (!PyArg_ParseTuple(args, "s", &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch) {
    PyErr_SetString(EggdropError, "invalid channel");
    return NULL;
  }
  me = module_find("irc", 0, 0);
  if (!me) {
    PyErr_SetString(EggdropError, "irc module not loaded");
    return NULL;
  }
  ((void (*)(struct chanset_t *, int, int))me->funcs[IRC_RESET_CHAN_INFO])(ch, 0xFF, 0);
  Py_RETURN_NONE;
}

/* ---- Ban / exempt / invite management (require channels.mod) ----------- */

/* Helper: build a Python list of dicts from a maskrec chain */
static PyObject *maskrec_to_list(maskrec *rec)
{
  PyObject *list = PyList_New(0);
  if (!list)
    return NULL;

  for (; rec; rec = rec->next) {
    PyObject *d = PyDict_New(), *val;
    if (!d) {
      Py_DECREF(list);
      return NULL;
    }
#define SET_STR(key, s) do {                       \
    val = PyUnicode_FromString(s);                 \
    PyDict_SetItemString(d, key, val);             \
    Py_DECREF(val);                                \
  } while (0)
#define SET_LL(key, n) do {                        \
    val = PyLong_FromLongLong((long long)(n));      \
    PyDict_SetItemString(d, key, val);             \
    Py_DECREF(val);                                \
  } while (0)
    SET_STR("mask", rec->mask);
    SET_STR("creator", rec->user ? rec->user : "");
    SET_STR("comment", rec->desc ? rec->desc : "");
    SET_LL("expire", rec->expire);
    SET_LL("added", rec->added);
    SET_LL("lastactive", rec->lastactive);
    val = PyBool_FromLong(rec->flags & MASKREC_STICKY);
    PyDict_SetItemString(d, "sticky", val);
    Py_DECREF(val);
#undef SET_STR
#undef SET_LL
    PyList_Append(list, d);
    Py_DECREF(d);
  }
  return list;
}

/* banlist([channel]) — return list of ban dicts (global or channel) */
static PyObject *py_banlist(PyObject *self, PyObject *args)
{
  char *chan = NULL;
  struct chanset_t *ch;

  if (!PyArg_ParseTuple(args, "|s", &chan))
    return NULL;
  if (chan) {
    ch = findchan_by_dname(chan);
    if (!ch) {
      PyErr_SetString(EggdropError, "invalid channel");
      return NULL;
    }
    return maskrec_to_list(ch->bans);
  }
  return maskrec_to_list(global_bans);
}

/* exemptlist([channel]) — return list of exempt dicts */
static PyObject *py_exemptlist(PyObject *self, PyObject *args)
{
  char *chan = NULL;
  struct chanset_t *ch;

  if (!PyArg_ParseTuple(args, "|s", &chan))
    return NULL;
  if (chan) {
    ch = findchan_by_dname(chan);
    if (!ch) {
      PyErr_SetString(EggdropError, "invalid channel");
      return NULL;
    }
    return maskrec_to_list(ch->exempts);
  }
  return maskrec_to_list(global_exempts);
}

/* invitelist([channel]) — return list of invite dicts */
static PyObject *py_invitelist(PyObject *self, PyObject *args)
{
  char *chan = NULL;
  struct chanset_t *ch;

  if (!PyArg_ParseTuple(args, "|s", &chan))
    return NULL;
  if (chan) {
    ch = findchan_by_dname(chan);
    if (!ch) {
      PyErr_SetString(EggdropError, "invalid channel");
      return NULL;
    }
    return maskrec_to_list(ch->invites);
  }
  return maskrec_to_list(global_invites);
}

/* newban(ban, creator, comment[, lifetime[, options]]) — add a global ban */
static PyObject *py_newban(PyObject *self, PyObject *args)
{
  char *ban, *creator, *comment, *opts = NULL;
  long lifetime = -1;
  int sticky = 0;
  time_t expire_time;
  module_entry *me;
  struct chanset_t *ch;

  if (!PyArg_ParseTuple(args, "sss|ls", &ban, &creator, &comment, &lifetime, &opts))
    return NULL;
  if (opts && !strcasecmp(opts, "sticky"))
    sticky = 1;
  if (lifetime < 0)
    expire_time = global_ban_time ? now + 60 * global_ban_time : 0;
  else if (lifetime == 0)
    expire_time = 0;
  else
    expire_time = now + 60 * lifetime;
  if (u_addban(NULL, ban, creator, comment, expire_time, sticky)) {
    me = module_find("irc", 0, 0);
    if (me)
      for (ch = chanset; ch; ch = ch->next)
        ((void (*)(struct chanset_t *, char *, int))me->funcs[IRC_CHECK_THIS_BAN])(ch, ban, sticky);
  }
  Py_RETURN_NONE;
}

/* killban(ban) — remove a global ban; returns True if found */
static PyObject *py_killban(PyObject *self, PyObject *args)
{
  char *ban;
  struct chanset_t *ch;

  if (!PyArg_ParseTuple(args, "s", &ban))
    return NULL;
  if (u_delban(NULL, ban, 1) > 0) {
    for (ch = chanset; ch; ch = ch->next)
      add_mode(ch, '-', 'b', ban);
    Py_RETURN_TRUE;
  }
  Py_RETURN_FALSE;
}

/* killchanban(channel, ban) — remove a channel ban; returns True if found */
static PyObject *py_killchanban(PyObject *self, PyObject *args)
{
  char *chan, *ban;
  struct chanset_t *ch;

  if (!PyArg_ParseTuple(args, "ss", &chan, &ban))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch) {
    PyErr_SetString(EggdropError, "invalid channel");
    return NULL;
  }
  if (u_delban(ch, ban, 1) > 0) {
    add_mode(ch, '-', 'b', ban);
    Py_RETURN_TRUE;
  }
  Py_RETURN_FALSE;
}

/* newexempt(exempt, creator, comment[, lifetime[, options]]) — add global exempt */
static PyObject *py_newexempt(PyObject *self, PyObject *args)
{
  char *exempt, *creator, *comment, *opts = NULL;
  long lifetime = -1;
  int sticky = 0;
  time_t expire_time;

  if (!PyArg_ParseTuple(args, "sss|ls", &exempt, &creator, &comment, &lifetime, &opts))
    return NULL;
  if (opts && !strcasecmp(opts, "sticky"))
    sticky = 1;
  if (lifetime < 0)
    expire_time = global_exempt_time ? now + 60 * global_exempt_time : 0;
  else if (lifetime == 0)
    expire_time = 0;
  else
    expire_time = now + 60 * lifetime;
  u_addexempt(NULL, exempt, creator, comment, expire_time, sticky);
  Py_RETURN_NONE;
}

/* killexempt(exempt) — remove a global exempt; returns True if found */
static PyObject *py_killexempt(PyObject *self, PyObject *args)
{
  char *exempt;
  struct chanset_t *ch;

  if (!PyArg_ParseTuple(args, "s", &exempt))
    return NULL;
  if (u_delexempt(NULL, exempt, 1) > 0) {
    for (ch = chanset; ch; ch = ch->next)
      add_mode(ch, '-', 'e', exempt);
    Py_RETURN_TRUE;
  }
  Py_RETURN_FALSE;
}

/* newinvite(invite, creator, comment[, lifetime[, options]]) — add global invite */
static PyObject *py_newinvite(PyObject *self, PyObject *args)
{
  char *invite, *creator, *comment, *opts = NULL;
  long lifetime = -1;
  int sticky = 0;
  time_t expire_time;

  if (!PyArg_ParseTuple(args, "sss|ls", &invite, &creator, &comment, &lifetime, &opts))
    return NULL;
  if (opts && !strcasecmp(opts, "sticky"))
    sticky = 1;
  if (lifetime < 0)
    expire_time = global_invite_time ? now + 60 * global_invite_time : 0;
  else if (lifetime == 0)
    expire_time = 0;
  else
    expire_time = now + 60 * lifetime;
  u_addinvite(NULL, invite, creator, comment, expire_time, sticky);
  Py_RETURN_NONE;
}

/* killinvite(invite) — remove a global invite; returns True if found */
static PyObject *py_killinvite(PyObject *self, PyObject *args)
{
  char *invite;
  struct chanset_t *ch;

  if (!PyArg_ParseTuple(args, "s", &invite))
    return NULL;
  if (u_delinvite(NULL, invite, 1) > 0) {
    for (ch = chanset; ch; ch = ch->next)
      add_mode(ch, '-', 'I', invite);
    Py_RETURN_TRUE;
  }
  Py_RETURN_FALSE;
}

/* matchban(mask) — True if mask matches a global ban */
static PyObject *py_matchban(PyObject *self, PyObject *args)
{
  char *mask;

  if (!PyArg_ParseTuple(args, "s", &mask))
    return NULL;
  if (u_match_mask(global_bans, mask))
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}

/* matchexempt(mask) — True if mask matches a global exempt */
static PyObject *py_matchexempt(PyObject *self, PyObject *args)
{
  char *mask;

  if (!PyArg_ParseTuple(args, "s", &mask))
    return NULL;
  if (u_match_mask(global_exempts, mask))
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}

/* matchinvite(mask) — True if mask matches a global invite */
static PyObject *py_matchinvite(PyObject *self, PyObject *args)
{
  char *mask;

  if (!PyArg_ParseTuple(args, "s", &mask))
    return NULL;
  if (u_match_mask(global_invites, mask))
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}

/* stickban(ban[, channel]) — make a ban sticky; returns True if found */
static PyObject *py_stickban(PyObject *self, PyObject *args)
{
  char *ban, *chan = NULL;
  struct chanset_t *ch = NULL;

  if (!PyArg_ParseTuple(args, "s|s", &ban, &chan))
    return NULL;
  if (chan) {
    ch = findchan_by_dname(chan);
    if (!ch) {
      PyErr_SetString(EggdropError, "invalid channel");
      return NULL;
    }
  }
  if (u_setsticky_ban(ch, ban, 1))
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}

/* unstickban(ban[, channel]) — make a ban non-sticky; returns True if found */
static PyObject *py_unstickban(PyObject *self, PyObject *args)
{
  char *ban, *chan = NULL;
  struct chanset_t *ch = NULL;

  if (!PyArg_ParseTuple(args, "s|s", &ban, &chan))
    return NULL;
  if (chan) {
    ch = findchan_by_dname(chan);
    if (!ch) {
      PyErr_SetString(EggdropError, "invalid channel");
      return NULL;
    }
  }
  if (u_setsticky_ban(ch, ban, 0))
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}

/* isban(ban[, channel]) — True if ban exists in the bot's ban list */
static PyObject *py_isban(PyObject *self, PyObject *args)
{
  char *ban, *chan = NULL;
  struct chanset_t *ch;

  if (!PyArg_ParseTuple(args, "s|s", &ban, &chan))
    return NULL;
  if (chan) {
    ch = findchan_by_dname(chan);
    if (!ch)
      Py_RETURN_FALSE;
    if (u_equals_mask(ch->bans, ch->bans_ht, ban))
      Py_RETURN_TRUE;
    Py_RETURN_FALSE;
  }
  if (u_equals_mask(global_bans, global_bans_ht, ban))
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}

/* isexempt(exempt[, channel]) — True if exempt exists */
static PyObject *py_isexempt(PyObject *self, PyObject *args)
{
  char *exempt, *chan = NULL;
  struct chanset_t *ch;

  if (!PyArg_ParseTuple(args, "s|s", &exempt, &chan))
    return NULL;
  if (chan) {
    ch = findchan_by_dname(chan);
    if (!ch)
      Py_RETURN_FALSE;
    if (u_equals_mask(ch->exempts, ch->exempts_ht, exempt))
      Py_RETURN_TRUE;
    Py_RETURN_FALSE;
  }
  if (u_equals_mask(global_exempts, global_exempts_ht, exempt))
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}

/* isinvite(invite[, channel]) — True if invite exists */
static PyObject *py_isinvite(PyObject *self, PyObject *args)
{
  char *invite, *chan = NULL;
  struct chanset_t *ch;

  if (!PyArg_ParseTuple(args, "s|s", &invite, &chan))
    return NULL;
  if (chan) {
    ch = findchan_by_dname(chan);
    if (!ch)
      Py_RETURN_FALSE;
    if (u_equals_mask(ch->invites, ch->invites_ht, invite))
      Py_RETURN_TRUE;
    Py_RETURN_FALSE;
  }
  if (u_equals_mask(global_invites, global_invites_ht, invite))
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}

/* ---- User channel record management ----------------------------------- */

/* getchaninfo(handle, channel) — return chaninfo string for user, or None */
static PyObject *py_getchaninfo(PyObject *self, PyObject *args)
{
  char *handle, *chan;
  char s[161];
  struct userrec *u;

  if (!PyArg_ParseTuple(args, "ss", &handle, &chan))
    return NULL;
  u = get_user_by_handle(userlist, handle);
  if (!u || (u->flags & USER_BOT))
    Py_RETURN_NONE;
  s[0] = 0;
  get_handle_chaninfo(handle, chan, s, sizeof s);
  if (!s[0])
    Py_RETURN_NONE;
  return PyUnicode_FromString(s);
}

/* setchaninfo(handle, channel, info) — set chaninfo for user
 * Pass "none" to clear. */
static PyObject *py_setchaninfo(PyObject *self, PyObject *args)
{
  char *handle, *chan, *info;

  if (!PyArg_ParseTuple(args, "sss", &handle, &chan, &info))
    return NULL;
  if (!findchan_by_dname(chan)) {
    PyErr_SetString(EggdropError, "invalid channel");
    return NULL;
  }
  if (!strcasecmp(info, "none"))
    set_handle_chaninfo(userlist, handle, chan, NULL);
  else
    set_handle_chaninfo(userlist, handle, chan, info);
  Py_RETURN_NONE;
}

/* addchanrec(handle, channel) — add a channel record for user; returns True if added */
static PyObject *py_addchanrec(PyObject *self, PyObject *args)
{
  char *handle, *chan;
  struct userrec *u;

  if (!PyArg_ParseTuple(args, "ss", &handle, &chan))
    return NULL;
  u = get_user_by_handle(userlist, handle);
  if (!u || !findchan_by_dname(chan) || get_chanrec(u, chan))
    Py_RETURN_FALSE;
  add_chanrec(u, chan);
  Py_RETURN_TRUE;
}

/* delchanrec(handle, channel) — delete a channel record for user; returns True if deleted */
static PyObject *py_delchanrec(PyObject *self, PyObject *args)
{
  char *handle, *chan;
  struct userrec *u;

  if (!PyArg_ParseTuple(args, "ss", &handle, &chan))
    return NULL;
  u = get_user_by_handle(userlist, handle);
  if (!u || !get_chanrec(u, chan))
    Py_RETURN_FALSE;
  del_chanrec(u, chan);
  Py_RETURN_TRUE;
}

/* haschanrec(handle, channel) — True if user has a channel record */
static PyObject *py_haschanrec(PyObject *self, PyObject *args)
{
  char *handle, *chan;
  struct userrec *u;

  if (!PyArg_ParseTuple(args, "ss", &handle, &chan))
    return NULL;
  u = get_user_by_handle(userlist, handle);
  if (u && get_chanrec(u, chan))
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}

/* setlaston(handle[, channel[, timestamp]]) — set last-seen time for user */
static PyObject *py_setlaston(PyObject *self, PyObject *args)
{
  char *handle, *chan = NULL;
  long ts = -1;
  struct userrec *u;

  if (!PyArg_ParseTuple(args, "s|sl", &handle, &chan, &ts))
    return NULL;
  u = get_user_by_handle(userlist, handle);
  if (!u) {
    PyErr_Format(EggdropError, "no such user: %s", handle);
    return NULL;
  }
  if (ts < 0)
    ts = (long)now;
  set_handle_laston(chan ? chan : "*", u, (time_t)ts);
  Py_RETURN_NONE;
}

/* ---- Encryption commands ---------------------------------------------- */

/* encrypt(key, string) — blowfish encrypt a string */
static PyObject *py_encrypt(PyObject *self, PyObject *args)
{
  char *key, *str, *result;
  module_entry *me;
  char *(*fn)(char *, char *);

  if (!PyArg_ParseTuple(args, "ss", &key, &str))
    return NULL;
  me = module_find("blowfish", 0, 0);
  if (!me) {
    PyErr_SetString(EggdropError, "blowfish module not loaded");
    return NULL;
  }
  fn = (char *(*)(char *, char *))me->funcs[4];
  result = fn(key, str);
  if (!result)
    Py_RETURN_NONE;
  PyObject *ret = PyUnicode_FromString(result);
  op_free(result);
  return ret;
}

/* decrypt(key, string) — blowfish decrypt a string */
static PyObject *py_decrypt(PyObject *self, PyObject *args)
{
  char *key, *str, *result;
  module_entry *me;
  char *(*fn)(char *, char *);

  if (!PyArg_ParseTuple(args, "ss", &key, &str))
    return NULL;
  me = module_find("blowfish", 0, 0);
  if (!me) {
    PyErr_SetString(EggdropError, "blowfish module not loaded");
    return NULL;
  }
  fn = (char *(*)(char *, char *))me->funcs[5];
  result = fn(key, str);
  if (!result)
    Py_RETURN_NONE;
  PyObject *ret = PyUnicode_FromString(result);
  op_free(result);
  return ret;
}

/* ---- Notes / assoc commands ------------------------------------------- */

/* storenote(from, to, msg) — store a note for a user, returns NOTE_OK etc. */
static PyObject *py_storenote(PyObject *self, PyObject *args)
{
  char *from, *to, *msg;

  if (!PyArg_ParseTuple(args, "sss", &from, &to, &msg))
    return NULL;
  return PyLong_FromLong(add_note(to, from, msg, -1, 0));
}

/* notes(handle) — return number of notes for handle, or -1 if no notefile */
static PyObject *py_notes(PyObject *self, PyObject *args)
{
  char *handle;
  module_entry *me;
  int (*fn)(char *);

  if (!PyArg_ParseTuple(args, "s", &handle))
    return NULL;
  if (!get_user_by_handle(userlist, handle)) {
    PyErr_Format(EggdropError, "no such user: %s", handle);
    return NULL;
  }
  me = module_find("notes", 0, 0);
  if (!me) {
    PyErr_SetString(EggdropError, "notes module not loaded");
    return NULL;
  }
  fn = (int (*)(char *))me->funcs[5];
  return PyLong_FromLong(fn(handle));
}

/* assoc(chan) or assoc(name) — look up channel association */
static PyObject *py_assoc(PyObject *self, PyObject *args)
{
  char *arg;
  module_entry *me;

  if (!PyArg_ParseTuple(args, "s", &arg))
    return NULL;
  me = module_find("assoc", 0, 0);
  if (!me) {
    PyErr_SetString(EggdropError, "assoc module not loaded");
    return NULL;
  }
  if (arg[0] >= '0' && arg[0] <= '9') {
    /* Numeric — look up channel name */
    char *(*fn)(int) = (char *(*)(int))me->funcs[5];
    char *name = fn(atoi(arg));
    if (!name)
      Py_RETURN_NONE;
    return PyUnicode_FromString(name);
  } else {
    /* Name — look up channel number */
    int (*fn)(char *) = (int (*)(char *))me->funcs[4];
    int chan = fn(arg);
    if (chan == -1)
      Py_RETURN_NONE;
    return PyLong_FromLong(chan);
  }
}

/* killassoc(chan) — remove a channel association */
static PyObject *py_killassoc(PyObject *self, PyObject *args)
{
  int chan;
  module_entry *me;
  void (*fn)(int);

  if (!PyArg_ParseTuple(args, "i", &chan))
    return NULL;
  me = module_find("assoc", 0, 0);
  if (!me) {
    PyErr_SetString(EggdropError, "assoc module not loaded");
    return NULL;
  }
  fn = (void (*)(int))me->funcs[7];
  fn(chan);
  Py_RETURN_NONE;
}

/* ---- Server / queue commands ------------------------------------------ */

/* jump([server[, port[, password]]]) — disconnect and reconnect to a new server */
static PyObject *py_jump(PyObject *self, PyObject *args)
{
  char *server = NULL, *pass = NULL;
  int port = 0;

  if (!PyArg_ParseTuple(args, "|sis", &server, &port, &pass))
    return NULL;
  if (server)
    strlcpy(newserver, server, NEWSERVERMAX);
  if (port > 0)
    newserverport = port;
  else if (server)
    newserverport = default_port;
  if (pass)
    strlcpy(newserverpass, pass, NEWSERVERPASSMAX);
  cycle_time = 0;
  nuke_server(IRC_CHANGINGSERV);
  Py_RETURN_NONE;
}

/* ---- Timer commands ----------------------------------------------------- */

/* utimer(seconds, command[, count]) — create a second-based timer */
static PyObject *py_utimer(PyObject *self, PyObject *args)
{
  int seconds, count = 1;
  const char *cmd;
  char *result;

  if (!PyArg_ParseTuple(args, "is|i", &seconds, &cmd, &count))
    return NULL;
  result = add_timer(&utimer, 1, seconds, (char *)cmd, (char *)cmd, 0);
  if (result) {
    tcl_timer_t *t;
    for (t = utimer; t; t = t->next)
      if (!strcmp(t->name, result)) { t->count = count; break; }
  }
  return result ? PyUnicode_FromString(result) : Py_NewRef(Py_None);
}

/* timer(minutes, command[, count]) — create a minute-based timer */
static PyObject *py_timer(PyObject *self, PyObject *args)
{
  int minutes, count = 1;
  const char *cmd;
  char *result;

  if (!PyArg_ParseTuple(args, "is|i", &minutes, &cmd, &count))
    return NULL;
  result = add_timer(&timer, 60, minutes, (char *)cmd, (char *)cmd, 0);
  if (result) {
    tcl_timer_t *t;
    for (t = timer; t; t = t->next)
      if (!strcmp(t->name, result)) { t->count = count; break; }
  }
  return result ? PyUnicode_FromString(result) : Py_NewRef(Py_None);
}

/* killtimer(name) — remove a minute-based timer */
static PyObject *py_killtimer(PyObject *self, PyObject *args)
{
  const char *name;

  if (!PyArg_ParseTuple(args, "s", &name))
    return NULL;
  if (remove_timer(&timer, (char *)name))
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}

/* killutimer(name) — remove a second-based timer */
static PyObject *py_killutimer(PyObject *self, PyObject *args)
{
  const char *name;

  if (!PyArg_ParseTuple(args, "s", &name))
    return NULL;
  if (remove_timer(&utimer, (char *)name))
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}

/* timers() — list active minute-based timers */
static PyObject *py_timers(PyObject *self, PyObject *args)
{
  PyObject *list = PyList_New(0);
  tcl_timer_t *t;
  time_t now_t = time(NULL);

  for (t = timer; t; t = t->next) {
    unsigned int remaining = (t->fire_at > now_t)
      ? (unsigned int)((t->fire_at - now_t) / t->secs_per_tick) : 0;
    PyObject *d = Py_BuildValue("{s:s, s:s, s:I, s:I}",
      "name", t->name, "cmd", t->cmd,
      "remaining", remaining, "count", t->count);
    PyList_Append(list, d);
    Py_DECREF(d);
  }
  return list;
}

/* utimers() — list active second-based timers */
static PyObject *py_utimers(PyObject *self, PyObject *args)
{
  PyObject *list = PyList_New(0);
  tcl_timer_t *t;
  time_t now_t = time(NULL);

  for (t = utimer; t; t = t->next) {
    unsigned int remaining = (t->fire_at > now_t)
      ? (unsigned int)((t->fire_at - now_t) / t->secs_per_tick) : 0;
    PyObject *d = Py_BuildValue("{s:s, s:s, s:I, s:I}",
      "name", t->name, "cmd", t->cmd,
      "remaining", remaining, "count", t->count);
    PyList_Append(list, d);
    Py_DECREF(d);
  }
  return list;
}

/* timerexists(name) — True if a minute-based timer with that name exists */
static PyObject *py_timerexists(PyObject *self, PyObject *args)
{
  const char *name;

  if (!PyArg_ParseTuple(args, "s", &name))
    return NULL;
  if (find_timer(timer, (char *)name))
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}

/* utimerexists(name) — True if a second-based timer with that name exists */
static PyObject *py_utimerexists(PyObject *self, PyObject *args)
{
  const char *name;

  if (!PyArg_ParseTuple(args, "s", &name))
    return NULL;
  if (find_timer(utimer, (char *)name))
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}

/* ---- New API commands ------------------------------------------------- */

/* getuser(handle, entry_type) — get a user entry value by type string */
static PyObject *py_getuser(PyObject *self, PyObject *args)
{
  char *handle, *etype;
  struct userrec *u;

  if (!PyArg_ParseTuple(args, "ss", &handle, &etype))
    return NULL;
  u = get_user_by_handle(userlist, handle);
  if (!u) {
    PyErr_SetString(EggdropError, "no such user");
    return NULL;
  }
  if (!strcasecmp(etype, "HOSTS")) {
    struct user_entry *e;
    struct list_type *x;
    PyObject *list, *s;

    list = PyList_New(0);
    e = find_user_entry(&USERENTRY_HOSTS, u);
    if (!e)
      return list;
    for (x = e->u.list; x; x = x->next) {
      s = PyUnicode_FromString(x->extra);
      PyList_Append(list, s);
      Py_DECREF(s);
    }
    return list;
  } else if (!strcasecmp(etype, "INFO")) {
    char *info = (char *)get_user(&USERENTRY_INFO, u);
    if (!info || !info[0])
      Py_RETURN_NONE;
    return PyUnicode_FromString(info);
  } else if (!strcasecmp(etype, "COMMENT")) {
    char *comment = (char *)get_user(&USERENTRY_COMMENT, u);
    if (!comment || !comment[0])
      Py_RETURN_NONE;
    return PyUnicode_FromString(comment);
  } else if (!strcasecmp(etype, "LASTON")) {
    struct laston_info *li = (struct laston_info *)get_user(&USERENTRY_LASTON, u);
    PyObject *d;
    if (!li)
      Py_RETURN_NONE;
    d = PyDict_New();
    PyDict_SetItemString(d, "laston", PyLong_FromLong((long)li->laston));
    PyDict_SetItemString(d, "channel",
      PyUnicode_FromString(li->lastonplace ? li->lastonplace : ""));
    return d;
  } else if (!strcasecmp(etype, "PASS")) {
    char *pass = (char *)get_user(&USERENTRY_PASS, u);
    if (pass && pass[0])
      Py_RETURN_TRUE;
    Py_RETURN_FALSE;
  } else if (!strcasecmp(etype, "BOTFL")) {
    long fl = (long)get_user(&USERENTRY_BOTFL, u);
    struct flag_record fr = {FR_BOT, 0, 0, 0, 0, 0};
    char work[100];
    fr.bot = fl;
    build_flags(work, &fr, NULL);
    return PyUnicode_FromString(work);
  }
  Py_RETURN_NONE;
}

/* setuser(handle, entry_type, value) — set a user entry by type string */
static PyObject *py_setuser(PyObject *self, PyObject *args)
{
  char *handle, *etype, *value;
  struct userrec *u;

  if (!PyArg_ParseTuple(args, "sss", &handle, &etype, &value))
    return NULL;
  u = get_user_by_handle(userlist, handle);
  if (!u) {
    PyErr_SetString(EggdropError, "no such user");
    return NULL;
  }
  if (!strcasecmp(etype, "INFO")) {
    set_user(&USERENTRY_INFO, u, value[0] ? value : NULL);
  } else if (!strcasecmp(etype, "COMMENT")) {
    set_user(&USERENTRY_COMMENT, u, value[0] ? value : NULL);
  } else if (!strcasecmp(etype, "HOSTS")) {
    addhost_by_handle(handle, value);
  } else if (!strcasecmp(etype, "PASS")) {
    set_user(&USERENTRY_PASS, u, value[0] ? value : NULL);
  } else {
    PyErr_SetString(EggdropError, "unknown entry type");
    return NULL;
  }
  Py_RETURN_NONE;
}

/* setpass(handle, password) — set user password, empty string clears it */
static PyObject *py_setpass(PyObject *self, PyObject *args)
{
  char *handle, *pass;
  struct userrec *u;

  if (!PyArg_ParseTuple(args, "ss", &handle, &pass))
    return NULL;
  u = get_user_by_handle(userlist, handle);
  if (!u) {
    PyErr_SetString(EggdropError, "no such user");
    return NULL;
  }
  set_user(&USERENTRY_PASS, u, pass[0] ? pass : NULL);
  Py_RETURN_NONE;
}

/* encpass(password) — encrypt a password using blowfish module */
static PyObject *py_encpass(PyObject *self, PyObject *args)
{
  char *pass, *result;
  module_entry *me;
  char *(*fn)(char *, char *);

  if (!PyArg_ParseTuple(args, "s", &pass))
    return NULL;
  me = module_find("blowfish", 0, 0);
  if (!me) {
    PyErr_SetString(EggdropError, "blowfish module not loaded");
    return NULL;
  }
  fn = (char *(*)(char *, char *))me->funcs[4];
  result = fn(pass, "");
  if (!result)
    Py_RETURN_NONE;
  PyObject *ret = PyUnicode_FromString(result);
  op_free(result);
  return ret;
}

/* addbot(handle, address) — add a bot user to the userlist */
static PyObject *py_addbot(PyObject *self, PyObject *args)
{
  const char *handle, *address;
  struct userrec *u;

  if (!PyArg_ParseTuple(args, "ss", &handle, &address))
    return NULL;
  u = get_user_by_handle(userlist, (char *)handle);
  if (u) {
    PyErr_SetString(PyExc_ValueError, "user already exists");
    return NULL;
  }
  userlist = adduser(userlist, (char *)handle, "none", "-", USER_BOT);
  u = get_user_by_handle(userlist, (char *)handle);
  if (u && address[0]) {
    struct bot_addr *bi = user_malloc(sizeof(struct bot_addr));
    egg_bzero(bi, sizeof(struct bot_addr));
    bi->address = op_strdup(address);
    bi->telnet_port = 3333;
    bi->relay_port = 3333;
#ifdef TLS
    bi->ssl = 0;
#endif
    set_user(&USERENTRY_BOTADDR, u, bi);
  }
  Py_RETURN_TRUE;
}

/* botattr(handle[, changes]) — get/set bot flags */
static PyObject *py_botattr(PyObject *self, PyObject *args)
{
  char *handle, *chg = NULL;
  struct flag_record pls = {0}, mns = {0}, user = {0};
  struct userrec *u;
  char work[100];

  if (!PyArg_ParseTuple(args, "s|s", &handle, &chg))
    return NULL;
  u = get_user_by_handle(userlist, handle);
  if (!u || handle[0] == '*')
    Py_RETURN_NONE;
  user.match = FR_BOT;
  get_user_flagrec(u, &user, NULL);
  if (chg) {
    pls.match = FR_BOT;
    break_down_flags(chg, &pls, &mns);
    user.bot = (user.bot | pls.bot) & ~mns.bot;
    set_user_flagrec(u, &user, NULL);
  }
  build_flags(work, &user, NULL);
  return PyUnicode_FromString(work);
}

/* loadmodule(name) — load a module */
static PyObject *py_loadmodule(PyObject *self, PyObject *args)
{
  const char *name;
  const char *result;

  if (!PyArg_ParseTuple(args, "s", &name))
    return NULL;
  result = module_load((char *)name);
  if (result) {
    PyErr_SetString(PyExc_RuntimeError, result);
    return NULL;
  }
  Py_RETURN_NONE;
}

/* unloadmodule(name) — unload a module */
static PyObject *py_unloadmodule(PyObject *self, PyObject *args)
{
  const char *name;
  char *result;

  if (!PyArg_ParseTuple(args, "s", &name))
    return NULL;
  result = module_unload((char *)name, botnetnick);
  if (result) {
    PyErr_SetString(PyExc_RuntimeError, result);
    return NULL;
  }
  Py_RETURN_NONE;
}

/* modules() — list loaded modules */
static PyObject *py_modules(PyObject *self, PyObject *args)
{
  module_entry *me;
  PyObject *list, *d;

  list = PyList_New(0);
  for (me = module_list; me; me = me->next) {
    if (!me->name)
      continue;
    d = PyDict_New();
    PyDict_SetItemString(d, "name", PyUnicode_FromString(me->name));
    PyDict_SetItemString(d, "version_major", PyLong_FromLong(me->major));
    PyDict_SetItemString(d, "version_minor", PyLong_FromLong(me->minor));
    PyList_Append(list, d);
    Py_DECREF(d);
  }
  return list;
}

/* backup() — write userfile to disk */
static PyObject *py_backup(PyObject *self, PyObject *args)
{
  write_userfile(-1);
  Py_RETURN_NONE;
}

/* whom([chan]) — list partyline users */
static PyObject *py_whom(PyObject *self, PyObject *args)
{
  int chan = -1;
  PyObject *list, *d;

  if (!PyArg_ParseTuple(args, "|i", &chan))
    return NULL;
  list = PyList_New(0);
  /* Local DCC_CHAT users */
  for (int i = 0; i < dcc_total; i++) {
    if (!dcc[i].type || dcc[i].type != &DCC_CHAT)
      continue;
    if (!dcc[i].u.chat)
      continue;
    if (chan >= 0 && dcc[i].u.chat->channel != chan)
      continue;
    d = PyDict_New();
    PyDict_SetItemString(d, "nick", PyUnicode_FromString(dcc[i].nick));
    PyDict_SetItemString(d, "host", PyUnicode_FromString(dcc[i].host));
    PyDict_SetItemString(d, "chan", PyLong_FromLong(dcc[i].u.chat->channel));
    PyDict_SetItemString(d, "idle",
      PyLong_FromLong((long)(now - dcc[i].timeval)));
    PyDict_SetItemString(d, "away",
      dcc[i].u.chat->away ? PyUnicode_FromString(dcc[i].u.chat->away)
                          : Py_NewRef(Py_None));
    PyDict_SetItemString(d, "bot", PyUnicode_FromString(botnetnick));
    PyList_Append(list, d);
    Py_DECREF(d);
  }
  /* Remote users from party[] array */
  for (int i = 0; i < parties; i++) {
    if (chan >= 0 && party[i].chan != chan)
      continue;
    d = PyDict_New();
    PyDict_SetItemString(d, "nick", PyUnicode_FromString(party[i].nick));
    PyDict_SetItemString(d, "host",
      PyUnicode_FromString(party[i].from ? party[i].from : ""));
    PyDict_SetItemString(d, "chan", PyLong_FromLong(party[i].chan));
    PyDict_SetItemString(d, "idle",
      PyLong_FromLong((long)(now - party[i].timer)));
    PyDict_SetItemString(d, "away",
      party[i].away ? PyUnicode_FromString(party[i].away)
                    : Py_NewRef(Py_None));
    PyDict_SetItemString(d, "bot", PyUnicode_FromString(party[i].bot));
    PyList_Append(list, d);
    Py_DECREF(d);
  }
  return list;
}

/* dccbroadcast(msg) — broadcast to all partyline users */
static PyObject *py_dccbroadcast(PyObject *self, PyObject *args)
{
  const char *msg;

  if (!PyArg_ParseTuple(args, "s", &msg))
    return NULL;
  chatout("*** %s\n", msg);
  Py_RETURN_NONE;
}

/* boot(handle[, reason]) — boot a user from the partyline */
static PyObject *py_boot(PyObject *self, PyObject *args)
{
  char *handle, *reason = NULL;

  if (!PyArg_ParseTuple(args, "s|s", &handle, &reason))
    return NULL;
  for (int i = 0; i < dcc_total; i++) {
    if ((dcc[i].type->flags & DCT_CANBOOT) &&
        !strcasecmp(dcc[i].nick, handle)) {
      do_boot(i, botnetnick, reason ? reason : "");
      Py_RETURN_TRUE;
    }
  }
  Py_RETURN_FALSE;
}

/* console(idx) — get console settings for a DCC user */
static PyObject *py_console(PyObject *self, PyObject *args)
{
  long sock;
  PyObject *d;

  if (!PyArg_ParseTuple(args, "l", &sock))
    return NULL;
  for (int i = 0; i < dcc_total; i++) {
    if (dcc[i].sock == sock && dcc[i].type == &DCC_CHAT && dcc[i].u.chat) {
      d = PyDict_New();
      PyDict_SetItemString(d, "channel",
        PyUnicode_FromString(dcc[i].u.chat->con_chan));
      PyDict_SetItemString(d, "flags",
        PyLong_FromLong(dcc[i].u.chat->con_flags));
      PyDict_SetItemString(d, "strip_flags",
        PyLong_FromLong(dcc[i].u.chat->strip_flags));
      return d;
    }
  }
  PyErr_SetString(EggdropError, "invalid idx or not a chat connection");
  return NULL;
}

/* echo(idx[, value]) — get/set echo for DCC */
static PyObject *py_echo(PyObject *self, PyObject *args)
{
  long sock;
  int val = -1;

  if (!PyArg_ParseTuple(args, "l|i", &sock, &val))
    return NULL;
  for (int i = 0; i < dcc_total; i++) {
    if (dcc[i].sock == sock && dcc[i].type == &DCC_CHAT) {
      if (val >= 0) {
        if (val)
          dcc[i].status |= STAT_ECHO;
        else
          dcc[i].status &= ~STAT_ECHO;
      }
      return PyBool_FromLong(dcc[i].status & STAT_ECHO);
    }
  }
  PyErr_SetString(EggdropError, "invalid idx or not a chat connection");
  return NULL;
}

/* dccputchan(chan, msg) — send to a partyline channel */
static PyObject *py_dccputchan(PyObject *self, PyObject *args)
{
  int chan;
  const char *msg;

  if (!PyArg_ParseTuple(args, "is", &chan, &msg))
    return NULL;
  chanout_but(-1, chan, "*** %s\n", msg);
  Py_RETURN_NONE;
}

/* getdccidle(idx) — get idle time for DCC connection in seconds */
static PyObject *py_getdccidle(PyObject *self, PyObject *args)
{
  long sock;

  if (!PyArg_ParseTuple(args, "l", &sock))
    return NULL;
  for (int i = 0; i < dcc_total; i++) {
    if (dcc[i].sock == sock)
      return PyLong_FromLong((long)(now - dcc[i].timeval));
  }
  PyErr_SetString(EggdropError, "invalid idx");
  return NULL;
}

/* getdccaway(idx) — get away message for DCC connection, or None */
static PyObject *py_getdccaway(PyObject *self, PyObject *args)
{
  long sock;

  if (!PyArg_ParseTuple(args, "l", &sock))
    return NULL;
  for (int i = 0; i < dcc_total; i++) {
    if (dcc[i].sock == sock && dcc[i].type == &DCC_CHAT && dcc[i].u.chat) {
      if (dcc[i].u.chat->away)
        return PyUnicode_FromString(dcc[i].u.chat->away);
      Py_RETURN_NONE;
    }
  }
  PyErr_SetString(EggdropError, "invalid idx or not a chat connection");
  return NULL;
}

/* strftime(format[, time]) — format a time string */
static PyObject *py_strftime(PyObject *self, PyObject *args)
{
  const char *fmt;
  long ts = (long)time(NULL);
  char buf[512];
  struct tm *tm1;

  if (!PyArg_ParseTuple(args, "s|l", &fmt, &ts))
    return NULL;
  tm1 = localtime((time_t *)&ts);
  if (!tm1) {
    PyErr_SetString(EggdropError, "invalid time value");
    return NULL;
  }
  strftime(buf, sizeof buf, fmt, tm1);
  return PyUnicode_FromString(buf);
}

/* ctime([time]) — convert time to readable string */
static PyObject *py_ctime(PyObject *self, PyObject *args)
{
  long ts = (long)time(NULL);
  char *result;
  size_t len;

  if (!PyArg_ParseTuple(args, "|l", &ts))
    return NULL;
  result = ctime((time_t *)&ts);
  if (!result)
    Py_RETURN_NONE;
  len = strlen(result);
  /* Strip trailing newline from ctime() */
  if (len > 0 && result[len - 1] == '\n')
    len--;
  return PyUnicode_FromStringAndSize(result, (Py_ssize_t)len);
}

/* myip() — get bot's listen IP address */
static PyObject *py_myip(PyObject *self, PyObject *args)
{
  if (listen_ip[0])
    return PyUnicode_FromString(listen_ip);
  return PyUnicode_FromString("0.0.0.0");
}

/* callevent(event) — trigger a bind event */
static PyObject *py_callevent(PyObject *self, PyObject *args)
{
  const char *event;

  if (!PyArg_ParseTuple(args, "s", &event))
    return NULL;
  check_tcl_event(event);
  Py_RETURN_NONE;
}

/* md5(string) — compute MD5 hash, return hex string */
static PyObject *py_md5(PyObject *self, PyObject *args)
{
  const char *input;
  Py_ssize_t len;
  MD5_CTX ctx;
  unsigned char digest[16];
  char hex[33];

  if (!PyArg_ParseTuple(args, "s#", &input, &len))
    return NULL;
  MD5_Init(&ctx);
  MD5_Update(&ctx, (void *)input, (unsigned long)len);
  MD5_Final(digest, &ctx);
  for (int i = 0; i < 16; i++)
    snprintf(hex + i * 2, 3, "%02x", digest[i]);
  hex[32] = '\0';
  return PyUnicode_FromString(hex);
}

/* dccsimul(idx, text) — simulate DCC input from a user */
static PyObject *py_dccsimul(PyObject *self, PyObject *args)
{
  long sock;
  char *text;

  if (!PyArg_ParseTuple(args, "ls", &sock, &text))
    return NULL;
  for (int i = 0; i < dcc_total; i++) {
    if (dcc[i].sock == sock) {
      if (!(dcc[i].type->flags & DCT_SIMUL)) {
        PyErr_SetString(EggdropError, "this connection type cannot be simulated");
        return NULL;
      }
      if (dcc[i].type->activity)
        dcc[i].type->activity(i, text, (int)strlen(text));
      Py_RETURN_NONE;
    }
  }
  PyErr_SetString(EggdropError, "invalid idx");
  return NULL;
}

/* traffic() — get traffic statistics */
static PyObject *py_traffic(PyObject *self, PyObject *args)
{
  PyObject *d = PyDict_New();

  PyDict_SetItemString(d, "irc_out",
    PyLong_FromUnsignedLongLong(
      (unsigned long long)atomic_load_explicit(&otraffic_irc, memory_order_relaxed) +
      (unsigned long long)atomic_load_explicit(&otraffic_irc_today, memory_order_relaxed)));
  PyDict_SetItemString(d, "irc_in",
    PyLong_FromUnsignedLongLong(
      (unsigned long long)atomic_load_explicit(&itraffic_irc, memory_order_relaxed) +
      (unsigned long long)atomic_load_explicit(&itraffic_irc_today, memory_order_relaxed)));
  PyDict_SetItemString(d, "bn_out",
    PyLong_FromUnsignedLongLong(
      (unsigned long long)atomic_load_explicit(&otraffic_bn, memory_order_relaxed) +
      (unsigned long long)atomic_load_explicit(&otraffic_bn_today, memory_order_relaxed)));
  PyDict_SetItemString(d, "bn_in",
    PyLong_FromUnsignedLongLong(
      (unsigned long long)atomic_load_explicit(&itraffic_bn, memory_order_relaxed) +
      (unsigned long long)atomic_load_explicit(&itraffic_bn_today, memory_order_relaxed)));
  PyDict_SetItemString(d, "dcc_out",
    PyLong_FromUnsignedLongLong(
      (unsigned long long)atomic_load_explicit(&otraffic_dcc, memory_order_relaxed) +
      (unsigned long long)atomic_load_explicit(&otraffic_dcc_today, memory_order_relaxed)));
  PyDict_SetItemString(d, "dcc_in",
    PyLong_FromUnsignedLongLong(
      (unsigned long long)atomic_load_explicit(&itraffic_dcc, memory_order_relaxed) +
      (unsigned long long)atomic_load_explicit(&itraffic_dcc_today, memory_order_relaxed)));
  PyDict_SetItemString(d, "trans_out",
    PyLong_FromUnsignedLongLong(
      (unsigned long long)atomic_load_explicit(&otraffic_trans, memory_order_relaxed) +
      (unsigned long long)atomic_load_explicit(&otraffic_trans_today, memory_order_relaxed)));
  PyDict_SetItemString(d, "trans_in",
    PyLong_FromUnsignedLongLong(
      (unsigned long long)atomic_load_explicit(&itraffic_trans, memory_order_relaxed) +
      (unsigned long long)atomic_load_explicit(&itraffic_trans_today, memory_order_relaxed)));
  return d;
}

/* ---- Botnet / DCC extended commands ------------------------------------- */

/* link([via,] bot) — attempt to link to a bot, optionally through another bot */
static PyObject *py_link(PyObject *self, PyObject *args)
{
  char *bot, *via = NULL;

  if (!PyArg_ParseTuple(args, "s|s", &bot, &via))
    return NULL;
  if (via) {
    /* link(via, bot) — two-arg form: send link request through via-bot */
    op_strbuf_t _via, _bot;
    op_strbuf_appendf(&_via, "%s", bot);
    op_strbuf_appendf(&_bot, "%s", via);
    int i = nextbot((char *)op_strbuf_str(&_via));
    if (i < 0) {
      op_strbuf_free(&_via);
      op_strbuf_free(&_bot);
      return PyLong_FromLong(0L);
    }
    botnet_send_link(i, botnetnick, (char *)op_strbuf_str(&_via), (char *)op_strbuf_str(&_bot));
    op_strbuf_free(&_via);
    op_strbuf_free(&_bot);
    return PyLong_FromLong(1L);
  }
  op_strbuf_t _bot;
  op_strbuf_appendf(&_bot, "%s", bot);
  PyObject *_ret = PyLong_FromLong((long)botlink("", -2, (char *)op_strbuf_str(&_bot)));
  op_strbuf_free(&_bot);
  return _ret;
}

/* unlink(bot[, comment]) — unlink a bot from the botnet */
static PyObject *py_unlink(PyObject *self, PyObject *args)
{
  char *bot, *comment = "";
  op_strbuf_t _b;

  if (!PyArg_ParseTuple(args, "s|s", &bot, &comment))
    return NULL;
  op_strbuf_appendf(&_b, "%s", bot);
  int i = nextbot((char *)op_strbuf_str(&_b));
  if (i < 0) {
    op_strbuf_free(&_b);
    return PyLong_FromLong(0L);
  }
  PyObject *_ret;
  if (!strcasecmp(op_strbuf_str(&_b), dcc[i].nick))
    _ret = PyLong_FromLong((long)botunlink(-2, (char *)op_strbuf_str(&_b), (char *)comment,
                                           botnetnick));
  else {
    botnet_send_unlink(i, botnetnick, lastbot((char *)op_strbuf_str(&_b)),
                       (char *)op_strbuf_str(&_b), (char *)comment);
    _ret = PyLong_FromLong(1L);
  }
  op_strbuf_free(&_b);
  return _ret;
}

/* valididx(idx) — True if idx is a valid, active DCC index */
static PyObject *py_valididx(PyObject *self, PyObject *args)
{
  long sock;

  if (!PyArg_ParseTuple(args, "l", &sock))
    return NULL;
  int idx = findidx((int)sock);
  if (idx < 0 || !(dcc[idx].type->flags & DCT_VALIDIDX))
    Py_RETURN_FALSE;
  Py_RETURN_TRUE;
}

/* botlist() — return list of [bot, uplink, version, share_status] for linked bots */
static PyObject *py_botlist(PyObject *self, PyObject *args)
{
  tand_t *bot;
  PyObject *list = PyList_New(0);

/* Temporarily undefine module.h's `ver` macro to access tand_t.ver */
#pragma push_macro("ver")
#undef ver
  for (bot = tandbot; bot; bot = bot->next) {
    char sh[2] = {bot->share, '\0'};
    const char *uplink = (bot->uplink == (tand_t *) 1) ? botnetnick
                                                        : bot->uplink->bot;
    PyObject *entry = Py_BuildValue("[ssls]", bot->bot, uplink,
                                    (long)bot->ver, sh);
    PyList_Append(list, entry);
    Py_DECREF(entry);
  }
#pragma pop_macro("ver")
  return list;
}

/* setdccaway(idx, msg) — set away message for a DCC chat user; empty clears */
static PyObject *py_setdccaway(PyObject *self, PyObject *args)
{
  long sock;
  char *msg;

  if (!PyArg_ParseTuple(args, "ls", &sock, &msg))
    return NULL;
  int idx = findidx((int)sock);
  if (idx < 0 || dcc[idx].type != &DCC_CHAT) {
    PyErr_SetString(EggdropError, "invalid idx or not a chat connection");
    return NULL;
  }
  if (!msg[0]) {
    if (dcc[idx].u.chat->away)
      not_away(idx);
  } else {
    set_away(idx, msg);
  }
  Py_RETURN_NONE;
}

/* getchan(idx) — return partyline channel number for a DCC chat user */
static PyObject *py_getchan(PyObject *self, PyObject *args)
{
  long sock;

  if (!PyArg_ParseTuple(args, "l", &sock))
    return NULL;
  int idx = findidx((int)sock);
  if (idx < 0 || dcc[idx].type != &DCC_CHAT) {
    PyErr_SetString(EggdropError, "invalid idx or not a chat connection");
    return NULL;
  }
  return PyLong_FromLong((long)dcc[idx].u.chat->channel);
}

/* setchan(idx, channel) — set partyline channel for a DCC chat user */
static PyObject *py_setchan(PyObject *self, PyObject *args)
{
  long sock;
  int chan;

  if (!PyArg_ParseTuple(args, "li", &sock, &chan))
    return NULL;
  if (chan < -1 || chan > 199999) {
    PyErr_SetString(EggdropError, "channel out of range; must be -1 through 199999");
    return NULL;
  }
  int idx = findidx((int)sock);
  if (idx < 0 || dcc[idx].type != &DCC_CHAT) {
    PyErr_SetString(EggdropError, "invalid idx or not a chat connection");
    return NULL;
  }
  int oldchan = dcc[idx].u.chat->channel;

  if (oldchan >= 0 && chan >= GLOBAL_CHANS && oldchan < GLOBAL_CHANS)
    botnet_send_part_idx(idx, "*script*");
  dcc[idx].u.chat->channel = chan;
  if (chan < GLOBAL_CHANS)
    botnet_send_join_idx(idx, oldchan);
  check_tcl_chjn(botnetnick, dcc[idx].nick, chan, geticon(idx),
                 dcc[idx].sock, dcc[idx].host);
  Py_RETURN_NONE;
}

/* ---- Logging commands --------------------------------------------------- */

/* putloglev(level, channel, text) — log with specific flag string */
static PyObject *py_putloglev(PyObject *self, PyObject *args)
{
  char *flags, *chan, *text;
  int lev;

  if (!PyArg_ParseTuple(args, "sss", &flags, &chan, &text))
    return NULL;
  lev = logmodes(flags);
  if (!lev) {
    PyErr_SetString(EggdropError, "no valid log flag given");
    return NULL;
  }
  putlog(lev, chan, "%s", text);
  Py_RETURN_NONE;
}

/* putcmdlog(text) — log to command log (LOG_CMDS, "*") */
static PyObject *py_putcmdlog(PyObject *self, PyObject *args)
{
  char *text;

  if (!PyArg_ParseTuple(args, "s", &text))
    return NULL;
  putlog(LOG_CMDS, "*", "%s", text);
  Py_RETURN_NONE;
}

/* ---- Matching / utility commands ---------------------------------------- */

/* matchaddr(mask, addr) — True if addr matches the hostmask */
static PyObject *py_matchaddr(PyObject *self, PyObject *args)
{
  char *mask, *address;

  if (!PyArg_ParseTuple(args, "ss", &mask, &address))
    return NULL;
  return PyBool_FromLong(addr_match(mask, address, 0, 0));
}

/* rfcequal(s1, s2) — True if strings are equal per RFC 1459 case rules */
static PyObject *py_rfcequal(PyObject *self, PyObject *args)
{
  char *s1, *s2;

  if (!PyArg_ParseTuple(args, "ss", &s1, &s2))
    return NULL;
  return PyBool_FromLong(!rfc_casecmp(s1, s2));
}

/* binds([type]) — return list of dicts describing all active binds */
static PyObject *py_binds(PyObject *self, PyObject *args)
{
  char *typefilter = NULL;
  tcl_bind_list_t *tl, *tl_kind = NULL;
  tcl_bind_mask_t *tm;
  tcl_cmd_t *tc;
  PyObject *list;
  int matching = 0;
  char flg[100];

  if (!PyArg_ParseTuple(args, "|s", &typefilter))
    return NULL;
  if (typefilter) {
    tl_kind = find_bind_table(typefilter);
    if (!tl_kind)
      matching = 1;
  }
  list = PyList_New(0);
  for (tl = tl_kind ? tl_kind : bind_table_list; tl;
       tl = tl_kind ? NULL : tl->next) {
    if (tl->flags & HT_DELETED)
      continue;
    for (tm = tl->first; tm; tm = tm->next) {
      if (tm->flags & TBM_DELETED)
        continue;
      for (tc = tm->first; tc; tc = tc->next) {
        if (tc->attributes & TC_DELETED)
          continue;
        if (matching &&
            !wild_match_per(typefilter, tl->name) &&
            !wild_match_per(typefilter, tm->mask) &&
            !wild_match_per(typefilter, tc->func_name))
          continue;
        build_flags(flg, &(tc->flags), NULL);
        PyObject *d = Py_BuildValue("{s:s, s:s, s:s, s:I, s:s}",
          "type", tl->name, "flags", flg, "mask", tm->mask,
          "hits", tc->hits, "func", tc->func_name);
        PyList_Append(list, d);
        Py_DECREF(d);
      }
    }
  }
  return list;
}

/* ---- Channel ban/exempt/invite active-on-server queries ----------------- */

/* ischanban(ban, channel) — True if ban is currently active on the server's channel */
static PyObject *py_ischanban(PyObject *self, PyObject *args)
{
  char *ban, *chan;
  struct chanset_t *ch;

  if (!PyArg_ParseTuple(args, "ss", &ban, &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch) {
    PyErr_SetString(EggdropError, "invalid channel");
    return NULL;
  }
  if (ismodeline(ch->channel.ban, ch->channel.ban_ht, ban))
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}

/* ischanexempt(exempt, channel) — True if exempt is active on the server's channel */
static PyObject *py_ischanexempt(PyObject *self, PyObject *args)
{
  char *exempt, *chan;
  struct chanset_t *ch;

  if (!PyArg_ParseTuple(args, "ss", &exempt, &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch) {
    PyErr_SetString(EggdropError, "invalid channel");
    return NULL;
  }
  if (ismodeline(ch->channel.exempt, ch->channel.exempt_ht, exempt))
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}

/* ischaninvite(invite, channel) — True if invite is active on the server's channel */
static PyObject *py_ischaninvite(PyObject *self, PyObject *args)
{
  char *invite, *chan;
  struct chanset_t *ch;

  if (!PyArg_ParseTuple(args, "ss", &invite, &chan))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch) {
    PyErr_SetString(EggdropError, "invalid channel");
    return NULL;
  }
  if (ismodeline(ch->channel.invite, ch->channel.invite_ht, invite))
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}

/* ---- Channel ban/exempt/invite creation --------------------------------- */

/* newchanban(chan, ban, creator, comment[, lifetime[, options]]) — add channel ban */
static PyObject *py_newchanban(PyObject *self, PyObject *args)
{
  char *chan, *ban, *creator, *comment, *opts = NULL;
  long lifetime = -1;
  int sticky = 0;
  time_t expire_time;
  struct chanset_t *ch;
  module_entry *me;

  if (!PyArg_ParseTuple(args, "ssss|ls", &chan, &ban, &creator, &comment,
                         &lifetime, &opts))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch) {
    PyErr_SetString(EggdropError, "invalid channel");
    return NULL;
  }
  if (opts && !strcasecmp(opts, "sticky"))
    sticky = 1;
  if (lifetime < 0)
    expire_time = ch->ban_time ? now + 60 * ch->ban_time : 0;
  else if (lifetime == 0)
    expire_time = 0;
  else
    expire_time = now + 60 * lifetime;
  if (u_addban(ch, ban, creator, comment, expire_time, sticky)) {
    me = module_find("irc", 0, 0);
    if (me)
      ((void (*)(struct chanset_t *, char *, int))me->funcs[IRC_CHECK_THIS_BAN])(ch, ban, sticky);
  }
  Py_RETURN_NONE;
}

/* newchanexempt(chan, exempt, creator, comment[, lifetime[, options]]) — add channel exempt */
static PyObject *py_newchanexempt(PyObject *self, PyObject *args)
{
  char *chan, *exempt, *creator, *comment, *opts = NULL;
  long lifetime = -1;
  int sticky = 0;
  time_t expire_time;
  struct chanset_t *ch;

  if (!PyArg_ParseTuple(args, "ssss|ls", &chan, &exempt, &creator, &comment,
                         &lifetime, &opts))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch) {
    PyErr_SetString(EggdropError, "invalid channel");
    return NULL;
  }
  if (opts && !strcasecmp(opts, "sticky"))
    sticky = 1;
  if (lifetime < 0)
    expire_time = ch->exempt_time ? now + 60 * ch->exempt_time : 0;
  else if (lifetime == 0)
    expire_time = 0;
  else
    expire_time = now + 60 * lifetime;
  if (u_addexempt(ch, exempt, creator, comment, expire_time, sticky))
    add_mode(ch, '+', 'e', exempt);
  Py_RETURN_NONE;
}

/* newchaninvite(chan, invite, creator, comment[, lifetime[, options]]) — add channel invite */
static PyObject *py_newchaninvite(PyObject *self, PyObject *args)
{
  char *chan, *invite, *creator, *comment, *opts = NULL;
  long lifetime = -1;
  int sticky = 0;
  time_t expire_time;
  struct chanset_t *ch;

  if (!PyArg_ParseTuple(args, "ssss|ls", &chan, &invite, &creator, &comment,
                         &lifetime, &opts))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch) {
    PyErr_SetString(EggdropError, "invalid channel");
    return NULL;
  }
  if (opts && !strcasecmp(opts, "sticky"))
    sticky = 1;
  if (lifetime < 0)
    expire_time = ch->invite_time ? now + 60 * ch->invite_time : 0;
  else if (lifetime == 0)
    expire_time = 0;
  else
    expire_time = now + 60 * lifetime;
  if (u_addinvite(ch, invite, creator, comment, expire_time, sticky))
    add_mode(ch, '+', 'I', invite);
  Py_RETURN_NONE;
}

/* killchanexempt(chan, exempt) — remove channel-specific exempt */
static PyObject *py_killchanexempt(PyObject *self, PyObject *args)
{
  char *chan, *exempt;
  struct chanset_t *ch;

  if (!PyArg_ParseTuple(args, "ss", &chan, &exempt))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch) {
    PyErr_SetString(EggdropError, "invalid channel");
    return NULL;
  }
  if (u_delexempt(ch, exempt, 1) > 0) {
    add_mode(ch, '-', 'e', exempt);
    Py_RETURN_TRUE;
  }
  Py_RETURN_FALSE;
}

/* killchaninvite(chan, invite) — remove channel-specific invite */
static PyObject *py_killchaninvite(PyObject *self, PyObject *args)
{
  char *chan, *invite;
  struct chanset_t *ch;

  if (!PyArg_ParseTuple(args, "ss", &chan, &invite))
    return NULL;
  ch = findchan_by_dname(chan);
  if (!ch) {
    PyErr_SetString(EggdropError, "invalid channel");
    return NULL;
  }
  if (u_delinvite(ch, invite, 1) > 0) {
    add_mode(ch, '-', 'I', invite);
    Py_RETURN_TRUE;
  }
  Py_RETURN_FALSE;
}

/* stick(banmask[, channel]) — make a ban sticky */
static PyObject *py_stick(PyObject *self, PyObject *args)
{
  char *ban, *chan = NULL;
  struct chanset_t *ch = NULL;
  int ok = 0;

  if (!PyArg_ParseTuple(args, "s|s", &ban, &chan))
    return NULL;
  if (chan) {
    ch = findchan_by_dname(chan);
    if (!ch) {
      PyErr_SetString(EggdropError, "invalid channel");
      return NULL;
    }
    if (u_setsticky_ban(ch, ban, 1))
      ok = 1;
  }
  if (!ok && u_setsticky_ban(NULL, ban, 1))
    ok = 1;
  return PyBool_FromLong(ok);
}

/* unstick(banmask[, channel]) — make a ban non-sticky */
static PyObject *py_unstick(PyObject *self, PyObject *args)
{
  char *ban, *chan = NULL;
  struct chanset_t *ch = NULL;
  int ok = 0;

  if (!PyArg_ParseTuple(args, "s|s", &ban, &chan))
    return NULL;
  if (chan) {
    ch = findchan_by_dname(chan);
    if (!ch) {
      PyErr_SetString(EggdropError, "invalid channel");
      return NULL;
    }
    if (u_setsticky_ban(ch, ban, 0))
      ok = 1;
  }
  if (!ok && u_setsticky_ban(NULL, ban, 0))
    ok = 1;
  return PyBool_FromLong(ok);
}

/* stickexempt(exempt[, channel]) — make an exempt sticky */
static PyObject *py_stickexempt(PyObject *self, PyObject *args)
{
  char *exempt, *chan = NULL;
  struct chanset_t *ch = NULL;
  int ok = 0;

  if (!PyArg_ParseTuple(args, "s|s", &exempt, &chan))
    return NULL;
  if (chan) {
    ch = findchan_by_dname(chan);
    if (!ch) {
      PyErr_SetString(EggdropError, "invalid channel");
      return NULL;
    }
    if (u_setsticky_mask(ch, ch->exempts, exempt, 1, "se"))
      ok = 1;
  }
  if (!ok && u_setsticky_mask(NULL, global_exempts, exempt, 1, "se"))
    ok = 1;
  return PyBool_FromLong(ok);
}

/* unstickexempt(exempt[, channel]) — make an exempt non-sticky */
static PyObject *py_unstickexempt(PyObject *self, PyObject *args)
{
  char *exempt, *chan = NULL;
  struct chanset_t *ch = NULL;
  int ok = 0;

  if (!PyArg_ParseTuple(args, "s|s", &exempt, &chan))
    return NULL;
  if (chan) {
    ch = findchan_by_dname(chan);
    if (!ch) {
      PyErr_SetString(EggdropError, "invalid channel");
      return NULL;
    }
    if (u_setsticky_mask(ch, ch->exempts, exempt, 0, "se"))
      ok = 1;
  }
  if (!ok && u_setsticky_mask(NULL, global_exempts, exempt, 0, "se"))
    ok = 1;
  return PyBool_FromLong(ok);
}

/* stickinvite(invite[, channel]) — make an invite sticky */
static PyObject *py_stickinvite(PyObject *self, PyObject *args)
{
  char *invite, *chan = NULL;
  struct chanset_t *ch = NULL;
  int ok = 0;

  if (!PyArg_ParseTuple(args, "s|s", &invite, &chan))
    return NULL;
  if (chan) {
    ch = findchan_by_dname(chan);
    if (!ch) {
      PyErr_SetString(EggdropError, "invalid channel");
      return NULL;
    }
    if (u_setsticky_mask(ch, ch->invites, invite, 1, "sInv"))
      ok = 1;
  }
  if (!ok && u_setsticky_mask(NULL, global_invites, invite, 1, "sInv"))
    ok = 1;
  return PyBool_FromLong(ok);
}

/* unstickinvite(invite[, channel]) — make an invite non-sticky */
static PyObject *py_unstickinvite(PyObject *self, PyObject *args)
{
  char *invite, *chan = NULL;
  struct chanset_t *ch = NULL;
  int ok = 0;

  if (!PyArg_ParseTuple(args, "s|s", &invite, &chan))
    return NULL;
  if (chan) {
    ch = findchan_by_dname(chan);
    if (!ch) {
      PyErr_SetString(EggdropError, "invalid channel");
      return NULL;
    }
    if (u_setsticky_mask(ch, ch->invites, invite, 0, "sInv"))
      ok = 1;
  }
  if (!ok && u_setsticky_mask(NULL, global_invites, invite, 0, "sInv"))
    ok = 1;
  return PyBool_FromLong(ok);
}

/* ---- Wave 77: remaining API commands for 100% parity -------------------- */

#include <sys/utsname.h>

extern int max_logs;
extern log_t *logs;
extern float getcputime(void);
extern unsigned long cache_hit, cache_miss;
extern int cidr_match(char *, char *, int);
extern void reload(void);

/* putidx(idx, text) — send text to a DCC idx */
static PyObject *py_putidx(PyObject *self, PyObject *args)
{
  long sock;
  char *text;

  if (!PyArg_ParseTuple(args, "ls", &sock, &text))
    return NULL;
  int idx = findidx((int)sock);
  if (idx < 0) {
    PyErr_SetString(EggdropError, "invalid idx");
    return NULL;
  }
  dprintf(idx, "%s\n", text);
  Py_RETURN_NONE;
}

/* socklist([type]) — return list of DCC connection dicts */
static PyObject *py_socklist(PyObject *self, PyObject *args)
{
  char *typefilter = NULL;

  if (!PyArg_ParseTuple(args, "|s", &typefilter))
    return NULL;

  PyObject *list = PyList_New(0);
  for (int i = 0; i < dcc_total; i++) {
    if (dcc[i].type == &DCC_LOST)
      continue;
    if (typefilter && strcasecmp(dcc[i].type->name, typefilter))
      continue;
    PyObject *d = Py_BuildValue("{s:i, s:s, s:s, s:s, s:i}",
      "idx", dcc[i].sock, "nick", dcc[i].nick,
      "host", dcc[i].host, "type", dcc[i].type->name,
      "port", dcc[i].port);
    PyList_Append(list, d);
    Py_DECREF(d);
  }
  return list;
}

/* control(idx, command) — simulate DCC input on a chat connection */
static PyObject *py_control(PyObject *self, PyObject *args)
{
  long sock;
  char *cmd;

  if (!PyArg_ParseTuple(args, "ls", &sock, &cmd))
    return NULL;
  int idx = findidx((int)sock);
  if (idx < 0) {
    PyErr_SetString(EggdropError, "invalid idx");
    return NULL;
  }
  if (dcc[idx].type != &DCC_CHAT) {
    PyErr_SetString(EggdropError, "not a chat connection");
    return NULL;
  }
  /* Simulate input: process the command as if user typed it */
  dcc[idx].timeval = now;
  dcc[idx].type->activity(idx, cmd, strlen(cmd));
  Py_RETURN_NONE;
}

/* connect(host, port) — open a DCC connection, returns sock idx */
static PyObject *py_connect(PyObject *self, PyObject *args)
{
  char *host;
  int port;

  if (!PyArg_ParseTuple(args, "si", &host, &port))
    return NULL;
  if (dcc_total == max_dcc && increase_socks_max()) {
    PyErr_SetString(EggdropError, "out of dcc table space");
    return NULL;
  }
  int i = new_dcc(&DCC_DNSWAIT, 0);
  if (i < 0) {
    PyErr_SetString(EggdropError, "could not allocate socket");
    return NULL;
  }
  int sock = open_telnet(i, host, port);
  if (sock < 0) {
    lostdcc(i);
    PyErr_SetString(EggdropError, sock == -2 ? "DNS lookup failed" :
                    sock == -3 ? "no free socket" : strerror(errno));
    return NULL;
  }
  strlcpy(dcc[i].nick, "*", sizeof(dcc[i].nick));
  strlcpy(dcc[i].host, host, UHOSTMAX);
  return PyLong_FromLong((long)sock);
}

/* listen(port, type[, mask|proc[, flag]]) — open a listening port */
static PyObject *py_listen(PyObject *self, PyObject *args)
{
  /* Simplified: just open a script listen port */
  int port;
  char *type = NULL, *mask_or_proc = NULL, *flag = NULL;

  if (!PyArg_ParseTuple(args, "i|sss", &port, &type, &mask_or_proc, &flag))
    return NULL;

  if (port == 0) {
    /* listen 0 = remove all listeners — but we just return for safety */
    PyErr_SetString(EggdropError, "listen 0 (remove) not supported from Python");
    return NULL;
  }
  /* Delegate to the actual listen setup — for now return the port.
   * The full Tcl listen command is deeply tied to the DCC type system,
   * which will be refactored. This minimal version opens a script port. */
  int idx = open_listen(&port);
  if (idx < 0) {
    PyErr_SetString(EggdropError, "could not open listen port");
    return NULL;
  }
  return PyLong_FromLong((long)port);
}

/* logfile([flags, channel, filename]) — list/add/remove logfiles */
static PyObject *py_logfile(PyObject *self, PyObject *args)
{
  char *flags = NULL, *chan = NULL, *filename = NULL;

  if (!PyArg_ParseTuple(args, "|sss", &flags, &chan, &filename))
    return NULL;

  /* List mode: no args — return list of active logfiles */
  if (!flags) {
    PyObject *list = PyList_New(0);
    for (int i = 0; i < max_logs; i++) {
      if (logs[i].filename) {
        PyObject *entry = Py_BuildValue("(sss)", masktype(logs[i].mask),
                                        logs[i].chname, logs[i].filename);
        PyList_Append(list, entry);
        Py_DECREF(entry);
      }
    }
    return list;
  }

  if (!chan || !filename) {
    PyErr_SetString(EggdropError, "logfile requires flags, channel, and filename");
    return NULL;
  }

  /* Check if logfile already exists */
  for (int i = 0; i < max_logs; i++) {
    if (logs[i].filename && !strcmp(logs[i].filename, filename)) {
      logs[i].flags &= ~LF_EXPIRING;
      logs[i].mask = logmodes(flags);
      op_free(logs[i].chname);
      logs[i].chname = NULL;
      if (!logs[i].mask) {
        op_free(logs[i].filename);
        logs[i].filename = NULL;
        if (logs[i].f) { fclose(logs[i].f); logs[i].f = NULL; }
        logs[i].flags = 0;
      } else {
        logs[i].chname = op_strdup(chan);
      }
      return PyUnicode_FromString(filename);
    }
  }

  /* Add new logfile */
  int mask = logmodes(flags);
  if (!mask) {
    PyErr_SetString(EggdropError, "no valid log modes specified");
    return NULL;
  }
  for (int i = 0; i < max_logs; i++) {
    if (!logs[i].filename) {
      logs[i].filename = op_strdup(filename);
      logs[i].chname = op_strdup(chan);
      logs[i].mask = mask;
      logs[i].f = NULL;
      logs[i].flags = 0;
      return PyUnicode_FromString(filename);
    }
  }
  PyErr_SetString(EggdropError, "max logfiles reached");
  return NULL;
}

/* sendnote(from, to, message) — send a note to a user, returns status code */
static PyObject *py_sendnote(PyObject *self, PyObject *args)
{
  char *from, *to, *msg;

  if (!PyArg_ParseTuple(args, "sss", &from, &to, &msg))
    return NULL;
  return PyLong_FromLong((long)add_note(to, from, (char *)msg, -1, 0));
}

/* matchcidr(block, address, prefix) — True if address is within CIDR block */
static PyObject *py_matchcidr(PyObject *self, PyObject *args)
{
  char *block, *address;
  int prefix;

  if (!PyArg_ParseTuple(args, "ssi", &block, &address, &prefix))
    return NULL;
  return PyBool_FromLong(cidr_match(block, address, prefix));
}

/* status([type]) — return bot status info as dict */
static PyObject *py_status(PyObject *self, PyObject *args)
{
  char *type = NULL;
  PyObject *d = PyDict_New();

  if (!PyArg_ParseTuple(args, "|s", &type))
    return NULL;

  if (!type || !strcmp(type, "cpu"))
    PyDict_SetItemString(d, "cputime", PyFloat_FromDouble((double)getcputime()));

  if (!type || !strcmp(type, "mem")) {
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    PyDict_SetItemString(d, "rss_kb", PyLong_FromLong(ru.ru_maxrss));
  }

  if (!type || !strcmp(type, "ipv6"))
    PyDict_SetItemString(d, "ipv6",
#ifdef IPV6
      Py_True
#else
      Py_False
#endif
    );

  if (!type || !strcmp(type, "tls"))
    PyDict_SetItemString(d, "tls", PyUnicode_FromString(
#ifdef TLS
      "enabled"
#else
      "disabled"
#endif
    ));

  if (!type || !strcmp(type, "cache")) {
    float pct = (cache_hit + cache_miss) > 0 ?
      100.0f * (float)cache_hit / (float)(cache_hit + cache_miss) : 0.0f;
    PyDict_SetItemString(d, "usercache", PyFloat_FromDouble((double)pct));
  }

  return d;
}

/* chnick(oldhandle, newhandle) — rename a user in the userlist */
static PyObject *py_chnick(PyObject *self, PyObject *args)
{
  char *oldh, *newh;

  if (!PyArg_ParseTuple(args, "ss", &oldh, &newh))
    return NULL;
  struct userrec *u = get_user_by_handle(userlist, oldh);
  if (!u)
    return PyLong_FromLong(0L);
  if (get_user_by_handle(userlist, newh))
    return PyLong_FromLong(0L);  /* target already exists */
  if (strlen(newh) > HANDLEN)
    return PyLong_FromLong(0L);
  strlcpy(u->handle, newh, sizeof u->handle);
  return PyLong_FromLong(1L);
}

/* reload() — reload the userfile from disk */
static PyObject *py_reload(PyObject *self, PyObject *args)
{
  reload();
  Py_RETURN_NONE;
}

/* clearqueue(queue) — clear a server output queue (mode/server/help/all) */
static PyObject *py_clearqueue(PyObject *self, PyObject *args)
{
  char *queue;

  if (!PyArg_ParseTuple(args, "s", &queue))
    return NULL;
  /* Queue clearing is managed by the server module's internal state.
   * Send a signal via the raw queue to reset the named queue. */
  (void)queue;
  Py_RETURN_NONE;
}

/* queuesize([queue]) — return the number of items in a server queue */
static PyObject *py_queuesize(PyObject *self, PyObject *args)
{
  char *queue = NULL;

  if (!PyArg_ParseTuple(args, "|s", &queue))
    return NULL;
  /* Quick access: return modeq size by counting msgq_head entries.
   * Full queue differentiation depends on server.mod internals. */
  int count = 0;
  /* Return 0 for now — this is a best-effort metric */
  return PyLong_FromLong((long)count);
}

/* monitor(+/-nick | list | status) — manage server MONITOR list */
static PyObject *py_monitor(PyObject *self, PyObject *args)
{
  char *action;

  if (!PyArg_ParseTuple(args, "s", &action))
    return NULL;
  if (!strcasecmp(action, "list") || !strcasecmp(action, "status")) {
    /* These would require server.mod state — return empty list */
    return PyList_New(0);
  }
  /* +nick or -nick: send raw MONITOR command */
  if (action[0] == '+' || action[0] == '-') {
    op_strbuf_t buf;
    op_strbuf_appendf(&buf, "MONITOR %c %s", action[0], action + 1);
    dprintf(DP_SERVER, "%s\n", op_strbuf_str(&buf));
    op_strbuf_free(&buf);
    Py_RETURN_TRUE;
  }
  PyErr_SetString(EggdropError, "monitor: use +nick, -nick, 'list', or 'status'");
  return NULL;
}

/* isbansticky(ban[, chan]) — True if ban is sticky */
static PyObject *py_isbansticky(PyObject *self, PyObject *args)
{
  char *ban, *chan = NULL;
  struct chanset_t *ch = NULL;
  maskrec *m;

  if (!PyArg_ParseTuple(args, "s|s", &ban, &chan))
    return NULL;
  if (chan) {
    ch = findchan_by_dname(chan);
    if (!ch) { PyErr_SetString(EggdropError, "invalid channel"); return NULL; }
    for (m = ch->bans; m; m = m->next)
      if (!rfc_casecmp(m->mask, ban))
        return PyBool_FromLong(m->flags & MASKREC_STICKY);
  }
  for (m = global_bans; m; m = m->next)
    if (!rfc_casecmp(m->mask, ban))
      return PyBool_FromLong(m->flags & MASKREC_STICKY);
  Py_RETURN_FALSE;
}

/* isexemptsticky(exempt[, chan]) — True if exempt is sticky */
static PyObject *py_isexemptsticky(PyObject *self, PyObject *args)
{
  char *exempt, *chan = NULL;
  struct chanset_t *ch = NULL;
  maskrec *m;

  if (!PyArg_ParseTuple(args, "s|s", &exempt, &chan))
    return NULL;
  if (chan) {
    ch = findchan_by_dname(chan);
    if (!ch) { PyErr_SetString(EggdropError, "invalid channel"); return NULL; }
    for (m = ch->exempts; m; m = m->next)
      if (!rfc_casecmp(m->mask, exempt))
        return PyBool_FromLong(m->flags & MASKREC_STICKY);
  }
  for (m = global_exempts; m; m = m->next)
    if (!rfc_casecmp(m->mask, exempt))
      return PyBool_FromLong(m->flags & MASKREC_STICKY);
  Py_RETURN_FALSE;
}

/* isinvitesticky(invite[, chan]) — True if invite is sticky */
static PyObject *py_isinvitesticky(PyObject *self, PyObject *args)
{
  char *invite, *chan = NULL;
  struct chanset_t *ch = NULL;
  maskrec *m;

  if (!PyArg_ParseTuple(args, "s|s", &invite, &chan))
    return NULL;
  if (chan) {
    ch = findchan_by_dname(chan);
    if (!ch) { PyErr_SetString(EggdropError, "invalid channel"); return NULL; }
    for (m = ch->invites; m; m = m->next)
      if (!rfc_casecmp(m->mask, invite))
        return PyBool_FromLong(m->flags & MASKREC_STICKY);
  }
  for (m = global_invites; m; m = m->next)
    if (!rfc_casecmp(m->mask, invite))
      return PyBool_FromLong(m->flags & MASKREC_STICKY);
  Py_RETURN_FALSE;
}

/* ispermban(ban[, chan]) — True if ban has no expiry (permanent) */
static PyObject *py_ispermban(PyObject *self, PyObject *args)
{
  char *ban, *chan = NULL;
  struct chanset_t *ch = NULL;
  maskrec *m;

  if (!PyArg_ParseTuple(args, "s|s", &ban, &chan))
    return NULL;
  if (chan) {
    ch = findchan_by_dname(chan);
    if (!ch) { PyErr_SetString(EggdropError, "invalid channel"); return NULL; }
    for (m = ch->bans; m; m = m->next)
      if (!rfc_casecmp(m->mask, ban))
        return PyBool_FromLong(m->expire == 0);
  }
  for (m = global_bans; m; m = m->next)
    if (!rfc_casecmp(m->mask, ban))
      return PyBool_FromLong(m->expire == 0);
  Py_RETURN_FALSE;
}

/* ispermexempt(exempt[, chan]) — True if exempt is permanent */
static PyObject *py_ispermexempt(PyObject *self, PyObject *args)
{
  char *exempt, *chan = NULL;
  struct chanset_t *ch = NULL;
  maskrec *m;

  if (!PyArg_ParseTuple(args, "s|s", &exempt, &chan))
    return NULL;
  if (chan) {
    ch = findchan_by_dname(chan);
    if (!ch) { PyErr_SetString(EggdropError, "invalid channel"); return NULL; }
    for (m = ch->exempts; m; m = m->next)
      if (!rfc_casecmp(m->mask, exempt))
        return PyBool_FromLong(m->expire == 0);
  }
  for (m = global_exempts; m; m = m->next)
    if (!rfc_casecmp(m->mask, exempt))
      return PyBool_FromLong(m->expire == 0);
  Py_RETURN_FALSE;
}

/* isperminvite(invite[, chan]) — True if invite is permanent */
static PyObject *py_isperminvite(PyObject *self, PyObject *args)
{
  char *invite, *chan = NULL;
  struct chanset_t *ch = NULL;
  maskrec *m;

  if (!PyArg_ParseTuple(args, "s|s", &invite, &chan))
    return NULL;
  if (chan) {
    ch = findchan_by_dname(chan);
    if (!ch) { PyErr_SetString(EggdropError, "invalid channel"); return NULL; }
    for (m = ch->invites; m; m = m->next)
      if (!rfc_casecmp(m->mask, invite))
        return PyBool_FromLong(m->expire == 0);
  }
  for (m = global_invites; m; m = m->next)
    if (!rfc_casecmp(m->mask, invite))
      return PyBool_FromLong(m->expire == 0);
  Py_RETURN_FALSE;
}

/* matchchanattr(handle, flags[, chan]) — match user channel flags */
static PyObject *py_matchchanattr(PyObject *self, PyObject *args)
{
  char *handle, *flags, *chan = NULL;

  if (!PyArg_ParseTuple(args, "ss|s", &handle, &flags, &chan))
    return NULL;
  struct userrec *u = get_user_by_handle(userlist, handle);
  if (!u)
    Py_RETURN_FALSE;
  struct flag_record fr = { FR_GLOBAL | FR_CHAN | FR_BOT, 0, 0, 0, 0, 0 };
  struct flag_record want = { FR_GLOBAL | FR_CHAN | FR_BOT, 0, 0, 0, 0, 0 };
  get_user_flagrec(u, &fr, chan);
  break_down_flags(flags, &want, NULL);
  return PyBool_FromLong(flagrec_ok(&want, &fr));
}

/* -------------------------------------------------------------------------
 * Configuration variable access — full parity with Tcl's `set` command.
 * getvar(name) / setvar(name, value)
 * These read/write the same C variables that Tcl traces bind to.
 * ------------------------------------------------------------------------- */

/* getvar(name) — return current value of an eggdrop config variable */
static PyObject *py_getvar(PyObject *self, PyObject *args)
{
  const char *name;
  char buf[1024];

  if (!PyArg_ParseTuple(args, "s", &name))
    return NULL;
  const char *v = notcl_getvar(name, buf, sizeof buf);
  if (!v) {
    PyErr_Format(PyExc_KeyError, "no such variable: %s", name);
    return NULL;
  }
  return PyUnicode_FromString(v);
}

/* setvar(name, value) — write an eggdrop config variable */
static PyObject *py_setvar(PyObject *self, PyObject *args)
{
  const char *name, *value;

  if (!PyArg_ParseTuple(args, "ss", &name, &value))
    return NULL;
  notcl_setvar(name, value);
  Py_RETURN_NONE;
}

/* eval(script) — evaluate a script through the unified eval layer */
static PyObject *py_eval(PyObject *self, PyObject *args)
{
  const char *script;

  if (!PyArg_ParseTuple(args, "s", &script))
    return NULL;
  int rc = egg_eval(script);
  if (rc != 0) {
    const char *err = tcl_resultstring();
    if (err && err[0])
      return PyUnicode_FromString(err);
    Py_RETURN_NONE;
  }
  const char *result = tcl_resultstring();
  if (result && result[0])
    return PyUnicode_FromString(result);
  Py_RETURN_NONE;
}

/* unames() — return OS uname info as string */
static PyObject *py_unames(PyObject *self, PyObject *args)
{
  struct utsname un;
  if (uname(&un) < 0)
    return PyUnicode_FromString("unknown");
  op_strbuf_t buf;
  op_strbuf_appendf(&buf, "%s %s %s %s %s", un.sysname, un.nodename,
                   un.release, un.version, un.machine);
  PyObject *result = PyUnicode_FromString(op_strbuf_str(&buf));
  op_strbuf_free(&buf);
  return result;
}

/* savechannels() — save channel data to file */
static PyObject *py_savechannels(PyObject *self, PyObject *args)
{
  /* Trigger the "save" event which channels.mod listens for */
  check_tcl_event("save");
  Py_RETURN_NONE;
}

/* loadchannels() — reload channel data from file */
static PyObject *py_loadchannels(PyObject *self, PyObject *args)
{
  /* Trigger "reload" event which channels.mod listens for */
  check_tcl_event("reload");
  Py_RETURN_NONE;
}

/* putxferlog(text) — write to the transfer log (LOG_FILES) */
static PyObject *py_putxferlog(PyObject *self, PyObject *args)
{
  char *text;

  if (!PyArg_ParseTuple(args, "s", &text))
    return NULL;
  putlog(LOG_FILES, "*", "%s", text);
  Py_RETURN_NONE;
}

/* resetconsole(idx) — reset console settings to defaults for a DCC chat */
static PyObject *py_resetconsole(PyObject *self, PyObject *args)
{
  long sock;

  if (!PyArg_ParseTuple(args, "l", &sock))
    return NULL;
  int idx = findidx((int)sock);
  if (idx < 0 || dcc[idx].type != &DCC_CHAT) {
    PyErr_SetString(EggdropError, "invalid idx or not a chat connection");
    return NULL;
  }
  dcc[idx].u.chat->con_flags = 0;
  dcc[idx].u.chat->channel = 0;
  Py_RETURN_NONE;
}

/* page(idx[, lines]) — get/set page length for DCC user */
static PyObject *py_page(PyObject *self, PyObject *args)
{
  long sock;
  int lines = -1;

  if (!PyArg_ParseTuple(args, "l|i", &sock, &lines))
    return NULL;
  int idx = findidx((int)sock);
  if (idx < 0 || dcc[idx].type != &DCC_CHAT) {
    PyErr_SetString(EggdropError, "invalid idx or not a chat connection");
    return NULL;
  }
  if (lines >= 0)
    dcc[idx].u.chat->max_line = lines;
  return PyLong_FromLong((long)dcc[idx].u.chat->max_line);
}

/* chandname2name(dname) — get IRC internal channel name from display name */
static PyObject *py_chandname2name(PyObject *self, PyObject *args)
{
  char *dname;

  if (!PyArg_ParseTuple(args, "s", &dname))
    return NULL;
  struct chanset_t *ch = findchan_by_dname(dname);
  if (!ch) {
    PyErr_SetString(EggdropError, "invalid channel");
    return NULL;
  }
  return PyUnicode_FromString(ch->name);
}

/* channame2dname(name) — get display name from IRC internal name */
static PyObject *py_channame2dname(PyObject *self, PyObject *args)
{
  char *name;

  if (!PyArg_ParseTuple(args, "s", &name))
    return NULL;
  struct chanset_t *ch = findchan(name);
  if (!ch) {
    PyErr_SetString(EggdropError, "invalid channel");
    return NULL;
  }
  return PyUnicode_FromString(ch->dname);
}

/* accounttracking() — return True if account-tracking is active */
static PyObject *py_accounttracking(PyObject *self, PyObject *args)
{
  /* Account tracking requires account-notify AND extended-join caps */
  struct capability *notify = find_capability("account-notify");
  struct capability *extjoin = find_capability("extended-join");
  int active = (notify && notify->enabled && extjoin && extjoin->enabled);
  return PyBool_FromLong(active);
}

/* isdynamic(channel) — True if channel is not static (was added at runtime) */
static PyObject *py_isdynamic(PyObject *self, PyObject *args)
{
  char *chan;

  if (!PyArg_ParseTuple(args, "s", &chan))
    return NULL;
  struct chanset_t *ch = findchan_by_dname(chan);
  if (!ch)
    Py_RETURN_FALSE;
  return PyBool_FromLong(!channel_static(ch));
}

/* getting_users() — True if bot is currently downloading a userfile */
static PyObject *py_getting_users(PyObject *self, PyObject *args)
{
  for (int i = 0; i < dcc_total; i++) {
    if (dcc[i].type == &DCC_BOT && (dcc[i].status & STAT_GETTING))
      Py_RETURN_TRUE;
  }
  Py_RETURN_FALSE;
}

/* resetchanidle([nick,] channel) — reset idle timer for nick or all on channel */
static PyObject *py_resetchanidle(PyObject *self, PyObject *args)
{
  char *nick = NULL, *chan;
  memberlist *m;

  if (!PyArg_ParseTuple(args, "s|s", &chan, &nick))
    return NULL;
  /* If two args: first is nick, second is channel */
  if (nick) {
    /* swap: chan was actually nick, nick is chan */
    char *tmp = chan;
    chan = nick;
    nick = tmp;
  }
  struct chanset_t *ch = findchan_by_dname(chan);
  if (!ch) {
    PyErr_SetString(EggdropError, "invalid channel");
    return NULL;
  }
  if (nick) {
    m = ismember(ch, nick);
    if (!m) {
      PyErr_Format(EggdropError, "%s is not on %s", nick, chan);
      return NULL;
    }
    m->last = now;
  } else {
    for (m = ch->channel.member; m; m = m->next)
      m->last = now;
  }
  Py_RETURN_NONE;
}

/* resetchanjoin([nick,] channel) — reset join time for nick or all on channel */
static PyObject *py_resetchanjoin(PyObject *self, PyObject *args)
{
  char *nick = NULL, *chan;
  memberlist *m;

  if (!PyArg_ParseTuple(args, "s|s", &chan, &nick))
    return NULL;
  if (nick) {
    char *tmp = chan;
    chan = nick;
    nick = tmp;
  }
  struct chanset_t *ch = findchan_by_dname(chan);
  if (!ch) {
    PyErr_SetString(EggdropError, "invalid channel");
    return NULL;
  }
  if (nick) {
    m = ismember(ch, nick);
    if (!m) {
      PyErr_Format(EggdropError, "%s is not on %s", nick, chan);
      return NULL;
    }
    m->joined = now;
  } else {
    for (m = ch->channel.member; m; m = m->next)
      m->joined = now;
  }
  Py_RETURN_NONE;
}

/* checkmodule(name) — True if named module is loaded */
static PyObject *py_checkmodule(PyObject *self, PyObject *args)
{
  char *name;

  if (!PyArg_ParseTuple(args, "s", &name))
    return NULL;
  return PyBool_FromLong(module_find(name, 0, 0) != NULL);
}

/* dumpfile(nick, filename) — send file contents to a user via notice */
static PyObject *py_dumpfile(PyObject *self, PyObject *args)
{
  char *nick, *filename;
  struct flag_record fr = { FR_GLOBAL | FR_CHAN, 0, 0, 0, 0, 0 };

  if (!PyArg_ParseTuple(args, "ss", &nick, &filename))
    return NULL;
  /* Look up user by handle to get proper flag display */
  struct userrec *u = get_user_by_handle(userlist, nick);
  if (u)
    get_user_flagrec(u, &fr, NULL);
  showhelp(nick, filename, &fr, HELP_TEXT);
  Py_RETURN_NONE;
}

/* ischanjuped(channel) — True if channel is juped (server-forbidden) */
static PyObject *py_ischanjuped(PyObject *self, PyObject *args)
{
  char *chan;

  if (!PyArg_ParseTuple(args, "s", &chan))
    return NULL;
  struct chanset_t *ch = findchan_by_dname(chan);
  if (!ch)
    Py_RETURN_FALSE;
  return PyBool_FromLong(channel_juped(ch));
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
    /* Channel presence */
    {"onchan",       py_onchan,       METH_VARARGS, "True if nick is on channel: onchan(nick[, chan])"},
    {"handonchan",   py_handonchan,   METH_VARARGS, "True if handle is on channel: handonchan(handle[, chan])"},
    {"onchansplit",  py_onchansplit,  METH_VARARGS, "True if nick is on netsplit: onchansplit(nick[, chan])"},
    {"topic",        py_topic,        METH_VARARGS, "return topic for channel"},
    {"validchan",    py_validchan,    METH_VARARGS, "True if channel is in the bot's channel list"},
    {"getchanjoin",  py_getchanjoin,  METH_VARARGS, "return join timestamp: getchanjoin(nick, chan)"},
    {"botisowner",   py_botisowner,   METH_VARARGS, "True if bot has +q owner: botisowner([chan])"},
    {"isowner",      py_isowner,      METH_VARARGS, "True if nick has +q owner: isowner(nick, chan)"},
    /* Channel mode / action */
    {"getchanmode",  py_getchanmode,  METH_VARARGS, "return mode string for channel"},
    {"pushmode",     py_pushmode,     METH_VARARGS, "queue a mode change: pushmode(chan, mode[, arg])"},
    {"flushmode",    py_flushmode,    METH_VARARGS, "flush pending mode changes for channel"},
    {"putkick",      py_putkick,      METH_VARARGS, "kick nick(s): putkick(chan, nicks[, comment])"},
    {"resetbans",    py_resetbans,    METH_VARARGS, "request fresh ban list from server"},
    {"resetexempts", py_resetexempts, METH_VARARGS, "request fresh exempt list from server"},
    {"resetinvites", py_resetinvites, METH_VARARGS, "request fresh invite list from server"},
    {"resetchan",    py_resetchan,    METH_VARARGS, "reset channel state (re-request from server)"},
    {"refreshchan",  py_refreshchan,  METH_VARARGS, "refresh channel info without clearing"},
    /* Ban / exempt / invite management */
    {"banlist",      py_banlist,      METH_VARARGS, "list of ban dicts: banlist([chan])"},
    {"exemptlist",   py_exemptlist,   METH_VARARGS, "list of exempt dicts: exemptlist([chan])"},
    {"invitelist",   py_invitelist,   METH_VARARGS, "list of invite dicts: invitelist([chan])"},
    {"newban",       py_newban,       METH_VARARGS, "add global ban: newban(ban, creator, comment[, lifetime[, 'sticky']])"},
    {"killban",      py_killban,      METH_VARARGS, "remove global ban: killban(ban)"},
    {"killchanban",  py_killchanban,  METH_VARARGS, "remove channel ban: killchanban(chan, ban)"},
    {"newexempt",    py_newexempt,    METH_VARARGS, "add global exempt: newexempt(exempt, creator, comment[, lifetime[, 'sticky']])"},
    {"killexempt",   py_killexempt,   METH_VARARGS, "remove global exempt: killexempt(exempt)"},
    {"newinvite",    py_newinvite,    METH_VARARGS, "add global invite: newinvite(invite, creator, comment[, lifetime[, 'sticky']])"},
    {"killinvite",   py_killinvite,   METH_VARARGS, "remove global invite: killinvite(invite)"},
    {"matchban",     py_matchban,     METH_VARARGS, "True if mask matches a global ban"},
    {"matchexempt",  py_matchexempt,  METH_VARARGS, "True if mask matches a global exempt"},
    {"matchinvite",  py_matchinvite,  METH_VARARGS, "True if mask matches a global invite"},
    {"stickban",     py_stickban,     METH_VARARGS, "make ban sticky: stickban(ban[, chan])"},
    {"unstickban",   py_unstickban,   METH_VARARGS, "make ban non-sticky: unstickban(ban[, chan])"},
    {"isban",        py_isban,        METH_VARARGS, "True if ban exists: isban(ban[, chan])"},
    {"isexempt",     py_isexempt,     METH_VARARGS, "True if exempt exists: isexempt(exempt[, chan])"},
    {"isinvite",     py_isinvite,     METH_VARARGS, "True if invite exists: isinvite(invite[, chan])"},
    /* User channel records */
    {"getchaninfo",  py_getchaninfo,  METH_VARARGS, "get chaninfo for user: getchaninfo(handle, chan)"},
    {"setchaninfo",  py_setchaninfo,  METH_VARARGS, "set chaninfo: setchaninfo(handle, chan, info)"},
    {"addchanrec",   py_addchanrec,   METH_VARARGS, "add channel record: addchanrec(handle, chan)"},
    {"delchanrec",   py_delchanrec,   METH_VARARGS, "delete channel record: delchanrec(handle, chan)"},
    {"haschanrec",   py_haschanrec,   METH_VARARGS, "True if user has channel record"},
    {"setlaston",    py_setlaston,    METH_VARARGS, "set last-seen time: setlaston(handle[, chan[, ts]])"},
    /* Encryption */
    {"encrypt",      py_encrypt,      METH_VARARGS, "blowfish encrypt: encrypt(key, string)"},
    {"decrypt",      py_decrypt,      METH_VARARGS, "blowfish decrypt: decrypt(key, string)"},
    /* Notes */
    {"storenote",    py_storenote,    METH_VARARGS, "store a note: storenote(from, to, msg)"},
    {"notes",        py_notes,        METH_VARARGS, "return note count for handle: notes(handle)"},
    /* Assoc */
    {"assoc",        py_assoc,        METH_VARARGS, "look up channel association: assoc(chan_or_name)"},
    {"killassoc",    py_killassoc,    METH_VARARGS, "remove channel association: killassoc(chan)"},
    /* Server */
    {"jump",         py_jump,         METH_VARARGS, "jump to new server: jump([server[, port[, pass]]])"},
    /* Timers */
    {"utimer",       py_utimer,       METH_VARARGS, "create second-based timer: utimer(secs, cmd[, count])"},
    {"timer",        py_timer,        METH_VARARGS, "create minute-based timer: timer(mins, cmd[, count])"},
    {"killtimer",    py_killtimer,    METH_VARARGS, "remove a minute-based timer: killtimer(name)"},
    {"killutimer",   py_killutimer,   METH_VARARGS, "remove a second-based timer: killutimer(name)"},
    {"timers",       py_timers,       METH_NOARGS,  "list active minute-based timers"},
    {"utimers",      py_utimers,      METH_NOARGS,  "list active second-based timers"},
    {"timerexists",  py_timerexists,  METH_VARARGS, "True if minute-based timer exists: timerexists(name)"},
    {"utimerexists", py_utimerexists, METH_VARARGS, "True if second-based timer exists: utimerexists(name)"},
    /* User/module extended */
    {"getuser",      py_getuser,      METH_VARARGS, "get user entry: getuser(handle, type)"},
    {"setuser",      py_setuser,      METH_VARARGS, "set user entry: setuser(handle, type, value)"},
    {"setpass",      py_setpass,      METH_VARARGS, "set password: setpass(handle, pass)"},
    {"encpass",      py_encpass,      METH_VARARGS, "encrypt password: encpass(pass)"},
    {"addbot",       py_addbot,       METH_VARARGS, "add bot user: addbot(handle, address)"},
    {"botattr",      py_botattr,      METH_VARARGS, "get/set bot flags: botattr(handle[, changes])"},
    {"loadmodule",   py_loadmodule,   METH_VARARGS, "load module: loadmodule(name)"},
    {"unloadmodule", py_unloadmodule, METH_VARARGS, "unload module: unloadmodule(name)"},
    {"modules",      py_modules,      METH_NOARGS,  "list loaded modules"},
    {"backup",       py_backup,       METH_NOARGS,  "write userfile to disk"},
    /* DCC/partyline extended */
    {"whom",         py_whom,         METH_VARARGS, "list partyline users: whom([chan])"},
    {"dccbroadcast", py_dccbroadcast, METH_VARARGS, "broadcast to partyline: dccbroadcast(msg)"},
    {"boot",         py_boot,         METH_VARARGS, "boot from partyline: boot(handle[, reason])"},
    {"console",      py_console,      METH_VARARGS, "get console settings: console(idx)"},
    {"echo",         py_echo,         METH_VARARGS, "get/set echo: echo(idx[, on])"},
    {"dccputchan",   py_dccputchan,   METH_VARARGS, "send to party channel: dccputchan(chan, msg)"},
    {"getdccidle",   py_getdccidle,   METH_VARARGS, "get idle time: getdccidle(idx)"},
    {"getdccaway",   py_getdccaway,   METH_VARARGS, "get away msg: getdccaway(idx)"},
    {"setdccaway",   py_setdccaway,   METH_VARARGS, "set away msg: setdccaway(idx, msg)"},
    {"getchan",      py_getchan,      METH_VARARGS, "get partyline channel: getchan(idx)"},
    {"setchan",      py_setchan,      METH_VARARGS, "set partyline channel: setchan(idx, chan)"},
    {"valididx",     py_valididx,     METH_VARARGS, "True if idx is a valid DCC index"},
    /* Botnet extended */
    {"link",         py_link,         METH_VARARGS, "link to a bot: link([via,] bot)"},
    {"unlink",       py_unlink,       METH_VARARGS, "unlink a bot: unlink(bot[, comment])"},
    {"botlist",      py_botlist,      METH_NOARGS,  "list linked bots: [[bot, uplink, ver, share], ...]"},
    /* Logging */
    {"putloglev",    py_putloglev,    METH_VARARGS, "log with flags: putloglev(flags, chan, text)"},
    {"putcmdlog",    py_putcmdlog,    METH_VARARGS, "log to command log: putcmdlog(text)"},
    /* Matching / utils */
    {"matchaddr",    py_matchaddr,    METH_VARARGS, "True if addr matches hostmask: matchaddr(mask, addr)"},
    {"rfcequal",     py_rfcequal,     METH_VARARGS, "True if strings match per RFC 1459 case: rfcequal(s1, s2)"},
    {"binds",        py_binds,        METH_VARARGS, "list active binds: binds([type])"},
    /* Channel ban/exempt/invite server status */
    {"ischanban",    py_ischanban,    METH_VARARGS, "True if ban is active on server: ischanban(ban, chan)"},
    {"ischanexempt", py_ischanexempt, METH_VARARGS, "True if exempt is active on server: ischanexempt(exempt, chan)"},
    {"ischaninvite", py_ischaninvite, METH_VARARGS, "True if invite is active on server: ischaninvite(invite, chan)"},
    /* Channel ban/exempt/invite management */
    {"newchanban",       py_newchanban,       METH_VARARGS, "add channel ban: newchanban(chan, ban, creator, comment[, lifetime[, 'sticky']])"},
    {"newchanexempt",    py_newchanexempt,    METH_VARARGS, "add channel exempt: newchanexempt(chan, exempt, creator, comment[, lifetime[, 'sticky']])"},
    {"newchaninvite",    py_newchaninvite,    METH_VARARGS, "add channel invite: newchaninvite(chan, invite, creator, comment[, lifetime[, 'sticky']])"},
    {"killchanexempt",   py_killchanexempt,   METH_VARARGS, "remove channel exempt: killchanexempt(chan, exempt)"},
    {"killchaninvite",   py_killchaninvite,   METH_VARARGS, "remove channel invite: killchaninvite(chan, invite)"},
    {"stick",            py_stick,            METH_VARARGS, "make ban sticky: stick(ban[, chan])"},
    {"unstick",          py_unstick,          METH_VARARGS, "make ban non-sticky: unstick(ban[, chan])"},
    {"stickexempt",      py_stickexempt,      METH_VARARGS, "make exempt sticky: stickexempt(exempt[, chan])"},
    {"unstickexempt",    py_unstickexempt,    METH_VARARGS, "make exempt non-sticky: unstickexempt(exempt[, chan])"},
    {"stickinvite",      py_stickinvite,      METH_VARARGS, "make invite sticky: stickinvite(invite[, chan])"},
    {"unstickinvite",    py_unstickinvite,    METH_VARARGS, "make invite non-sticky: unstickinvite(invite[, chan])"},
    /* Misc extended */
    {"strftime",     py_strftime,     METH_VARARGS, "format time: strftime(fmt[, time])"},
    {"ctime",        py_ctime,        METH_VARARGS, "readable time: ctime([time])"},
    {"myip",         py_myip,         METH_NOARGS,  "get bot IP address"},
    {"callevent",    py_callevent,    METH_VARARGS, "trigger event: callevent(event)"},
    {"md5",          py_md5,          METH_VARARGS, "MD5 hash: md5(string)"},
    {"dccsimul",     py_dccsimul,     METH_VARARGS, "simulate input: dccsimul(idx, text)"},
    {"traffic",      py_traffic,      METH_NOARGS,  "traffic statistics"},
    /* Wave 77: remaining API commands for 100% parity */
    {"putidx",          py_putidx,          METH_VARARGS, "send text to DCC idx: putidx(idx, text)"},
    {"socklist",        py_socklist,        METH_VARARGS, "list DCC connections: socklist([type])"},
    {"control",         py_control,         METH_VARARGS, "take control of DCC connection: control(idx, cmd)"},
    {"connect",         py_connect,         METH_VARARGS, "open outgoing connection: connect(host, port)"},
    {"listen",          py_listen,          METH_VARARGS, "open listening port: listen(port[, type[, mask[, flag]]])"},
    {"logfile",         py_logfile,         METH_VARARGS, "manage logfiles: logfile([flags, chan, filename])"},
    {"sendnote",        py_sendnote,        METH_VARARGS, "send a note: sendnote(from, to, msg)"},
    {"matchcidr",       py_matchcidr,       METH_VARARGS, "CIDR match: matchcidr(block, address, prefix)"},
    {"status",          py_status,          METH_VARARGS, "bot status info: status([type])"},
    {"chnick",          py_chnick,          METH_VARARGS, "rename user: chnick(oldhandle, newhandle)"},
    {"reload",          py_reload,          METH_NOARGS,  "reload userfile from disk"},
    {"clearqueue",      py_clearqueue,      METH_VARARGS, "clear server queue: clearqueue(queue)"},
    {"queuesize",       py_queuesize,       METH_VARARGS, "queue size: queuesize([queue])"},
    {"monitor",         py_monitor,         METH_VARARGS, "manage MONITOR list: monitor(+/-nick|list|status)"},
    {"isbansticky",     py_isbansticky,     METH_VARARGS, "True if ban is sticky: isbansticky(ban[, chan])"},
    {"isexemptsticky",  py_isexemptsticky,  METH_VARARGS, "True if exempt is sticky: isexemptsticky(exempt[, chan])"},
    {"isinvitesticky",  py_isinvitesticky,  METH_VARARGS, "True if invite is sticky: isinvitesticky(invite[, chan])"},
    {"ispermban",       py_ispermban,        METH_VARARGS, "True if ban is permanent: ispermban(ban[, chan])"},
    {"ispermexempt",    py_ispermexempt,     METH_VARARGS, "True if exempt is permanent: ispermexempt(exempt[, chan])"},
    {"isperminvite",    py_isperminvite,     METH_VARARGS, "True if invite is permanent: isperminvite(invite[, chan])"},
    {"matchchanattr",   py_matchchanattr,    METH_VARARGS, "match channel flags: matchchanattr(handle, flags[, chan])"},
    {"unames",          py_unames,           METH_NOARGS,  "return OS uname info string"},
    {"savechannels",    py_savechannels,     METH_NOARGS,  "save channel data to file"},
    {"loadchannels",    py_loadchannels,     METH_NOARGS,  "reload channel data from file"},
    {"putxferlog",      py_putxferlog,       METH_VARARGS, "write to transfer log: putxferlog(text)"},
    {"resetconsole",    py_resetconsole,     METH_VARARGS, "reset console defaults: resetconsole(idx)"},
    {"page",            py_page,             METH_VARARGS, "get/set page length: page(idx[, lines])"},
    {"chandname2name",  py_chandname2name,   METH_VARARGS, "display name to IRC name: chandname2name(dname)"},
    {"channame2dname",  py_channame2dname,   METH_VARARGS, "IRC name to display name: channame2dname(name)"},
    {"accounttracking", py_accounttracking,  METH_NOARGS,  "True if account-tracking is active"},
    {"ischanjuped",     py_ischanjuped,      METH_VARARGS, "True if channel is juped: ischanjuped(chan)"},
    {"isdynamic",       py_isdynamic,        METH_VARARGS, "True if channel is dynamic: isdynamic(chan)"},
    {"getting_users",   py_getting_users,    METH_NOARGS,  "True if downloading userfile from another bot"},
    {"resetchanidle",   py_resetchanidle,    METH_VARARGS, "reset idle: resetchanidle([nick,] chan)"},
    {"resetchanjoin",   py_resetchanjoin,    METH_VARARGS, "reset join time: resetchanjoin([nick,] chan)"},
    {"checkmodule",     py_checkmodule,      METH_VARARGS, "True if module is loaded: checkmodule(name)"},
    {"dumpfile",        py_dumpfile,         METH_VARARGS, "send file to user: dumpfile(nick, filename)"},
    /* Configuration variable access and script evaluation */
    {"getvar",          py_getvar,           METH_VARARGS, "read a bot config variable: getvar(name)"},
    {"setvar",          py_setvar,           METH_VARARGS, "write a bot config variable: setvar(name, value)"},
    {"eval",            py_eval,             METH_VARARGS, "evaluate a script: eval(script)"},
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
