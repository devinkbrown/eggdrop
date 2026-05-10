.. _writing_module:

Writing an Eggdrop Module
==========================

This guide shows how to create a simple Eggdrop module. Eggdrop 1.10 uses Meson for building modules.

Module Basics
-------------

An Eggdrop module is:

- A C code file (or multiple files)
- Compiled to a ``.so`` (shared object) or ``.a`` (static) file
- Loaded at runtime via configuration
- Can add Tcl commands, binds, partyline commands, and more

Module Structure
^^^^^^^^^^^^^^^

Minimal module setup::

  src/mod/mymodule/
  ├── meson.build
  └── mymodule.c

Step-by-Step: Create Your Module
---------------------------------

Step 1: Create the Directory
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Create a new module directory::

  mkdir -p src/mod/mymodule
  cd src/mod/mymodule

Step 2: Create meson.build
^^^^^^^^^^^^^^^^^^^^^^^^^^

Create ``src/mod/mymodule/meson.build``::

  mymodule = static_library('mymodule',
    'mymodule.c',
    include_directories: [includes],
    install: true,
    install_dir: get_option('prefix') / 'modules'
  )

**Variables**:

- ``mymodule`` — Arbitrary name (doesn't have to match module name)
- ``'mymodule.c'`` — Source file(s)
- ``includes`` — Eggdrop include directories (set by main meson.build)
- ``install: true`` — Install the compiled module
- ``install_dir`` — Where to install (modules/ directory)

For multiple source files::

  mymodule = static_library('mymodule',
    'mymodule.c',
    'helper.c',
    include_directories: [includes],
    install: true,
    install_dir: get_option('prefix') / 'modules'
  )

Step 3: Create Module Source Code
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Create ``src/mod/mymodule/mymodule.c``::

  #include "../module.h"
  #define MODULE_NAME "mymodule"

  #undef global
  static Function *global = NULL;
  EXPORT_SCOPE char *mymodule_start();

  /* Memory tracking */
  static int mymodule_expmem(void)
  {
    return 0;  /* Return total bytes allocated by module */
  }

  /* Status reporting */
  static void mymodule_report(int idx, int details)
  {
    if (details) {
      int size = mymodule_expmem();
      dprintf(idx, "    Using %d byte%s of memory\n", size,
              (size != 1) ? "s" : "");
    }
  }

  /* Partyline command example */
  static int cmd_hello(struct userrec *u, int idx, char *par)
  {
    putlog(LOG_CMDS, "*", "#%s# hello", dcc[idx].nick);
    dprintf(idx, "Hello from mymodule!\n");
    return 0;
  }

  /* Command table */
  static cmd_t hello_cmds[] = {
    {"hello", "", cmd_hello, NULL},
    {NULL, NULL, NULL, NULL}
  };

  /* Tcl command example */
  static int tcl_hello STDVAR
  {
    BADARGS(1, 1, "");
    Tcl_AppendResult(irp, "Hello from Tcl!", NULL);
    return TCL_OK;
  }

  /* Tcl command table */
  static tcl_cmds hello_tcl[] = {
    {"hello", tcl_hello},
    {NULL, NULL}
  };

  /* Module startup */
  char *mymodule_start(Function *global_funcs)
  {
    global = global_funcs;

    /* Register the module */
    module_register(MODULE_NAME, mymodule_table, 1, 0);
    /*                                            ^--- minor version
     *                                         ^------ major version
     */

    /* Declare dependencies */
    if (!module_depend(MODULE_NAME, "eggdrop", 110, 0)) {
      module_undepend(MODULE_NAME);
      return "This module requires Eggdrop 1.10.0 or later.";
    }

    return NULL;  /* Return NULL on success */
  }

  /* Module shutdown */
  static char *mymodule_close(void)
  {
    module_undepend(MODULE_NAME);
    return NULL;
  }

  /* Module export table */
  static Function mymodule_table[] = {
    (Function) mymodule_start,
    (Function) mymodule_close,
    (Function) mymodule_expmem,
    (Function) mymodule_report,
  };

Step 4: Build the Module
^^^^^^^^^^^^^^^^^^^^^^^^^

Meson automatically discovers modules. Rebuild Eggdrop::

  cd /path/to/eggdrop
  ninja -C builddir
  meson install -C builddir --destdir=/path/to/install

Your module is compiled and installed to ``modules/mymodule.so``.

Step 5: Load the Module
^^^^^^^^^^^^^^^^^^^^^^^

In ``eggdrop.toml``, add to the modules section::

  [modules]
  load = [
    "pbkdf2",
    "channels",
    "server",
    "irc",
    "mymodule",  # Your new module
  ]

Step 6: Test the Module
^^^^^^^^^^^^^^^^^^^^^^^

Start the bot in terminal mode::

  ./eggdrop -t eggdrop.toml

Check that your module loaded::

  .module

You should see ``mymodule`` listed.

Test your commands (if you added any):

::

  .hello                    # Test partyline command
  .tcl hello                # Test Tcl command

Module Template
---------------

Here's a minimal but complete module template::

  #include "../module.h"
  #define MODULE_NAME "mymodule"

  #undef global
  static Function *global = NULL;
  EXPORT_SCOPE char *mymodule_start();

  static int mymodule_expmem(void) { return 0; }
  static void mymodule_report(int idx, int details) { }

  char *mymodule_start(Function *global_funcs)
  {
    global = global_funcs;
    module_register(MODULE_NAME, mymodule_table, 1, 0);
    if (!module_depend(MODULE_NAME, "eggdrop", 110, 0)) {
      module_undepend(MODULE_NAME);
      return "Eggdrop 1.10+ required";
    }
    return NULL;
  }

  static char *mymodule_close(void)
  {
    module_undepend(MODULE_NAME);
    return NULL;
  }

  static Function mymodule_table[] = {
    (Function) mymodule_start,
    (Function) mymodule_close,
    (Function) mymodule_expmem,
    (Function) mymodule_report,
  };

Copy this, rename all occurrences of ``mymodule``, and add your features.

Adding Features
---------------

Partyline Commands
^^^^^^^^^^^^^^^^^^

A partyline command is called from ``.commandname`` on the partyline::

  static int cmd_mycommand(struct userrec *u, int idx, char *par)
  {
    putlog(LOG_CMDS, "*", "#%s# mycommand %s", dcc[idx].nick, par);
    dprintf(idx, "You called mycommand with: %s\n", par);
    return 0;
  }

  static cmd_t mycommands[] = {
    {"mycommand", "o", cmd_mycommand, NULL},
    {NULL, NULL, NULL, NULL}
  };

The second parameter is **flags required** to use the command (``o`` = op, ``m`` = master, ``""`` = everyone).

Tcl Commands
^^^^^^^^^^^^

A Tcl command is called from ``.tcl commandname`` or from scripts::

  static int tcl_mycommand STDVAR
  {
    BADARGS(2, 3, " required ?optional?");

    if (argc < 2) {
      Tcl_AppendResult(irp, "Wrong number of arguments", NULL);
      return TCL_ERROR;
    }

    Tcl_AppendResult(irp, "You passed: ", argv[1], NULL);
    return TCL_OK;
  }

  static tcl_cmds mytcl[] = {
    {"mycommand", tcl_mycommand},
    {NULL, NULL}
  };

**BADARGS macro**: Checks argument count and provides help text::

  BADARGS(min, max, "help text")

Tcl Binds
^^^^^^^^^

A bind is triggered by an IRC event::

  static p_tcl_bind_list H_myevent;

  static int myevent_2char STDVAR
  {
    Function F = (Function) cd;
    BADARGS(3, 3, " arg1 arg2");
    CHECKVALIDITY(myevent_2char);
    F(argv[1], argv[2]);
    return TCL_OK;
  }

  char *mymodule_start(Function *global_funcs)
  {
    global = global_funcs;
    module_register(MODULE_NAME, mymodule_table, 1, 0);
    H_myevent = add_bind_table("myevent", HT_STACKABLE, myevent_2char);
    return NULL;
  }

  static char *mymodule_close(void)
  {
    del_bind_table(H_myevent);
    module_undepend(MODULE_NAME);
    return NULL;
  }

Then trigger from C code::

  int check_tcl_myevent(char *arg1, char *arg2)
  {
    int x;
    struct flag_record fr = { FR_GLOBAL | FR_CHAN, 0, 0, 0, 0, 0 };
    Tcl_SetVar(interp, "_myevent1", arg1, 0);
    Tcl_SetVar(interp, "_myevent2", arg2, 0);
    x = check_tcl_bind(H_myevent, "mask", &fr, " $_myevent1 $_myevent2",
                       MATCH_MASK | BIND_STACKABLE);
    return (x == BIND_EXEC_LOG);
  }

And in Tcl scripts::

  bind myevent - * my_handler

  proc my_handler {arg1 arg2} {
    putlog "Event: $arg1 $arg2"
  }

Module Dependencies
-------------------

If your module requires another module, declare it::

  if (!module_depend(MODULE_NAME, "channels", 110, 0)) {
    module_undepend(MODULE_NAME);
    return "Requires channels module";
  }

Format: ``module_depend(name, required_module, major_version, minor_version)``

Common Dependencies
^^^^^^^^^^^^^^^^^^^

- **server** — IRC server support (almost always needed)
- **channels** — Channel management (if working with channels)
- **irc** — Basic IRC (if doing IRC operations)

Memory Management
-----------------

**Always report memory usage**::

  static int mymodule_expmem(void)
  {
    int size = 0;
    size += sizeof(my_structure) * num_items;
    return size;  /* Total bytes allocated */
  }

**Always clean up**::

  static char *mymodule_close(void)
  {
    /* Free all allocated memory */
    op_free(mydata);
    del_bind_table(H_mybind);
    module_undepend(MODULE_NAME);
    return NULL;
  }

Use libop utilities for memory::

  void *ptr = op_malloc(size);
  op_free(ptr);

Useful Include Files
--------------------

Available headers in ``src/``::

  #include "module.h"      /* Core module API */
  #include "main.h"        /* Core data structures */
  #include "misc.h"        /* Utility functions */
  #include "tcl.h"         /* Tcl interpreter */
  #include "lib/libop.h"   /* libop utilities */

Building and Testing
--------------------

**Compile**::

  ninja -C builddir
  meson install -C builddir --destdir=/path/to/eggdrop

**Check build output**::

  ninja -C builddir -v

**Test loading**::

  ./eggdrop -t eggdrop.toml
  .module

**View logs**::

  tail -f logs/eggdrop.log

**Debug with gdb**::

  gdb ./eggdrop
  (gdb) run -t eggdrop.toml

Common Module Pitfalls
----------------------

**Module won't load**

- Meson.build has syntax error
- Missing ``EXPORT_SCOPE`` on start function
- Missing function table
- Wrong include path

**Bot crashes on module load**

- Uninitialized global variable
- Missing NULL terminator in tables
- Bad pointer dereference

**Commands don't work**

- Command table not registered
- Wrong flags required
- Command function not in table

**Memory leaks**

- Forgetting to ``op_free()``
- Not reporting in ``expmem()``
- Not cleaning up in ``close()``

Examples
--------

See ``src/mod/`` for examples:

- **woobie.c** — Minimal example (recommended starting point)
- **server.c** — Complex module with binds
- **channels.c** — Full-featured module

Best Practices
--------------

1. **Start with the template** — Use minimal example as base
2. **Use libop** — Standard utilities for memory, strings, etc.
3. **Document your code** — Comments for non-obvious logic
4. **Test thoroughly** — Before distributing
5. **Follow style** — Consistent with Eggdrop codebase
6. **Clean up properly** — All allocated memory freed
7. **Report memory** — In ``expmem()`` function
8. **Declare dependencies** — Via ``module_depend()``

Next Steps
----------

- `Module Internals <internals.html>`_ — Detailed architecture reference
- `Included Modules <included.html>`_ — List of built-in modules
- Eggdrop source — ``src/mod/`` for real-world examples

See Also
--------

- `Tcl Commands <../using/tcl-commands.html>`_ — Tcl API reference
- `Core Settings <../using/core.html>`_ — Configuration reference

Resources
---------

- GitHub: https://github.com/eggheads/eggdrop
- #eggdrop on Libera.Chat

Copyright (C) 1999 - 2025 Eggheads Development Team
