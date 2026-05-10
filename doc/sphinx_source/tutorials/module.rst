Writing a Basic Eggdrop Module
==============================

An Eggdrop module is a C code component that can be loaded or unloaded at runtime. Unlike Tcl scripts, modules must be compiled and are more powerful—they can create new Tcl commands, binds, and extend Eggdrop's core functionality.

Examples:

- The ``server`` module creates the ``jump`` Tcl command
- The ``channels`` module provides channel management
- The ``pbkdf2`` module implements secure password hashing

Module Structure
----------------

Every module requires:

1. A module header (copyright/license)
2. Module registration code (startup/shutdown)
3. Function tables (exports to Eggdrop)
4. Optionally: partyline commands, Tcl commands, Tcl binds

Building Modules
----------------

Eggdrop uses **Meson** for building. Modules are compiled automatically if placed in the correct location.

Module Location
^^^^^^^^^^^^^^^

Create a directory in ``src/mod/`` with your module name::

  src/mod/mymodule/
  ├── meson.build
  └── mymodule.c

Sample ``meson.build``::

  mymodule = static_library('mymodule',
    'mymodule.c',
    include_directories: [includes],
    install: true,
    install_dir: get_option('prefix') / 'modules'
  )

Building
^^^^^^^^

Modules are compiled automatically with the main build::

  meson setup builddir
  ninja -C builddir
  meson install -C builddir --destdir=/path/to/eggdrop

Compiled modules are placed in the ``modules/`` directory of your Eggdrop installation.

Module Header
-------------

Begin your module with copyright and license information::

  /*
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

Required Code
-------------

Every module must include these elements. You don't need to understand every detail, but the code is required.

Module Name
^^^^^^^^^^^

Define your module's name::

  #define MODULE_NAME "mymodule"

Function Tables
^^^^^^^^^^^^^^^

Declare function tables and global scope::

  #undef global
  static Function *global = NULL, *server_funcs = NULL;
  EXPORT_SCOPE char *mymodule_start();

Memory Reporting Functions
^^^^^^^^^^^^^^^^^^^^^^^^^^

These functions are called by ``.status`` and ``.module`` commands::

  static int mymodule_expmem(void)
  {
    int size = 0;

    /* Count any allocated memory here */

    return size;
  }

  static void mymodule_report(int idx, int details)
  {
    if (details) {
      int size = mymodule_expmem();

      dprintf(idx, "    Using %d byte%s of memory\n", size,
              (size != 1) ? "s" : "");
    }
  }

Module Startup
^^^^^^^^^^^^^^

This function is called when Eggdrop loads the module::

  char *mymodule_start(Function *global_funcs)
  {
    global = global_funcs;

    /* Register the module */
    module_register(MODULE_NAME, mymodule_table, 1, 0);
    /*                                            ^--- minor version
     *                                         ^------ major version
     *                           ^-------------------- function table
     *              ^--------------------------------- module name
     */

    /* Declare dependencies */
    if (!module_depend(MODULE_NAME, "eggdrop", 110, 0)) {
      module_undepend(MODULE_NAME);
      return "This module requires Eggdrop 1.10.0 or later.";
    }

    return NULL;  /* Success */
  }

Module Shutdown
^^^^^^^^^^^^^^^

This function is called when Eggdrop unloads the module::

  static char *mymodule_close(void)
  {
    module_undepend(MODULE_NAME);
    return NULL;
  }

Function Export Table
^^^^^^^^^^^^^^^^^^^^^

Export functions available to Eggdrop and other modules::

  static Function mymodule_table[] = {
    (Function) mymodule_start,
    (Function) mymodule_close,
    (Function) mymodule_expmem,
    (Function) mymodule_report,
  };

At this point, you have a loadable but non-functional module. The following sections add features.

Adding Partyline Commands
--------------------------

A partyline command function accepts:

1. A user record (user details)
2. An idx (connection index)
3. Arguments string

Example::

  static int cmd_mycommand(struct userrec *u, int idx, char *par)
  {
    putlog(LOG_CMDS, "*", "#%s# mycommand", dcc[idx].nick);
    dprintf(idx, "Hello from mymodule!\n");
    return 0;
  }

Command Table
^^^^^^^^^^^^^

Register commands in a command table::

  static cmd_t mycommands[] = {
    /* name        flags  function        tcl-name   */
    {"mycommand",  "",    cmd_mycommand,  NULL},
    {NULL,         NULL,  NULL,           NULL}  /* End marker */
  };

The ``tcl-name`` field can link to a Tcl command name, or ``NULL`` for partyline-only.

Adding Tcl Commands
-------------------

Tcl commands extend functionality for scripts. Example::

  static int tcl_myfunction STDVAR
  {
    BADARGS(2, 2, " arg");

    if (strcmp(argv[1], "hello") == 0) {
      Tcl_AppendResult(irp, "Hello, world!", NULL);
      return TCL_OK;
    } else {
      Tcl_AppendResult(irp, "Unknown argument", NULL);
      return TCL_ERROR;
    }
  }

**BADARGS Macro**: Validates argument count:

- First arg: minimum arguments (including command name)
- Second arg: maximum arguments
- Third arg: help text

Example: ``BADARGS(2, 4, " name ?date? ?place?")`` requires 1-3 args.

Tcl Command Table
^^^^^^^^^^^^^^^^^

Register Tcl commands::

  static tcl_cmds mytcl[] = {
    {"myfunction",  tcl_myfunction},
    {NULL,          NULL}  /* End marker */
  };

Now scripts can call::

  myfunction hello

Adding Tcl Binds
----------------

Binds are triggered by specific IRC events (e.g., messages, joins). Binds allow scripts to react to events.

Declaring Bind Types
^^^^^^^^^^^^^^^^^^^^

First, declare a bind handle::

  static p_tcl_bind_list H_myevent;

Register it in ``mymodule_start()``::

  H_myevent = add_bind_table("myevent", HT_STACKABLE, myevent_2char);

And remove it in ``mymodule_close()``::

  del_bind_table(H_myevent);

**HT_STACKABLE**: Multiple binds of the same type are allowed. Use ``HT_NORMAL`` to allow only one.

Defining Bind Arguments
^^^^^^^^^^^^^^^^^^^^^^^

Create a function that defines what arguments the bind receives. For a 2-argument bind::

  static int myevent_2char STDVAR
  {
    Function F = (Function) cd;

    BADARGS(3, 3, " arg1 arg2");

    CHECKVALIDITY(myevent_2char);
    F(argv[1], argv[2]);
    return TCL_OK;
  }

For a 3-argument bind::

  static int myevent_3char STDVAR
  {
    Function F = (Function) cd;

    BADARGS(4, 4, " arg1 arg2 arg3");

    CHECKVALIDITY(myevent_3char);
    F(argv[1], argv[2], argv[3]);
    return TCL_OK;
  }

Calling the Bind
^^^^^^^^^^^^^^^^

When an event occurs that should trigger the bind, call it from module code::

  int check_tcl_myevent(char *arg1, char *arg2)
  {
    int x;
    char mask[1024];
    struct flag_record fr = { FR_GLOBAL | FR_CHAN, 0, 0, 0, 0, 0 };

    snprintf(mask, sizeof mask, "%s %s", arg1, arg2);
    Tcl_SetVar(interp, "_myevent1", arg1, 0);
    Tcl_SetVar(interp, "_myevent2", arg2, 0);
    x = check_tcl_bind(H_myevent, mask, &fr, " $_myevent1 $_myevent2",
          MATCH_MASK | BIND_STACKABLE);
    return (x == BIND_EXEC_LOG);
  }

Scripts can then bind to your event::

  bind myevent - * my_event_handler

  proc my_event_handler {arg1 arg2} {
    putlog "Event triggered: $arg1 $arg2"
  }

Compiling and Testing
---------------------

#. Place your module in ``src/mod/yourmodule/``
#. Rebuild Eggdrop::

     ninja -C builddir
     meson install -C builddir --destdir=/path/to/eggdrop

#. Load the module in ``eggdrop.toml``::

     [modules]
     load = ["yourmodule"]

#. Restart Eggdrop

#. Check that it loaded::

     .status

Example: Simple "Woobie" Module
-------------------------------

Here's a complete minimal module::

  #define MODULE_NAME "woobie"

  #undef global
  static Function *global = NULL;
  EXPORT_SCOPE char *woobie_start();

  static int woobie_expmem(void) { return 0; }
  static void woobie_report(int idx, int details) {}

  static int cmd_woobie(struct userrec *u, int idx, char *par)
  {
    putlog(LOG_CMDS, "*", "#%s# woobie", dcc[idx].nick);
    dprintf(idx, "WOOBIE!\n");
    return 0;
  }

  static cmd_t woobie_cmds[] = {
    {"woobie", "", cmd_woobie, NULL},
    {NULL, NULL, NULL, NULL}
  };

  char *woobie_start(Function *global_funcs)
  {
    global = global_funcs;
    module_register(MODULE_NAME, woobie_table, 1, 0);

    if (!module_depend(MODULE_NAME, "eggdrop", 110, 0)) {
      module_undepend(MODULE_NAME);
      return "Eggdrop 1.10+ required";
    }
    return NULL;
  }

  static char *woobie_close(void)
  {
    module_undepend(MODULE_NAME);
    return NULL;
  }

  static Function woobie_table[] = {
    (Function) woobie_start,
    (Function) woobie_close,
    (Function) woobie_expmem,
    (Function) woobie_report,
  };

Resources
---------

- `Module Internals <../modules/internals.html>`_ — advanced module topics
- `Tcl Commands <../using/tcl-commands.html>`_ — built-in Tcl command reference
- Eggdrop source ``src/mod/`` — example modules

Copyright (C) 1997 Robey Pointer
Copyright (C) 1999 - 2025 Eggheads Development Team
