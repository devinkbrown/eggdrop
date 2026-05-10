Module Internals and Bind Architecture
=======================================

This document describes how Eggdrop's module and bind system works. It's intended for C developers extending Eggdrop.

**Note**: This documentation applies to Eggdrop 1.10 with C23, libop utilities, and the Meson build system.

Module Architecture
-------------------

Eggdrop Modules are C code compiled into dynamically-linked ``.so`` files (or static ``.a`` files) that are loaded at runtime.

Module Structure
^^^^^^^^^^^^^^^^

Every module has:

1. **Module header** — Copyright/license information
2. **Module initialization** — Startup code registering with Eggdrop core
3. **Module table** — Exports functions to Eggdrop
4. **Feature implementations** — Commands, binds, hooks
5. **Module shutdown** — Cleanup code

Basic Module Template
^^^^^^^^^^^^^^^^^^^^^

::

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
      return "Eggdrop 1.10.0 or later required";
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

Build System Integration
------------------------

Eggdrop uses **Meson** for building. Modules are automatically detected and compiled.

Module Directory Structure
^^^^^^^^^^^^^^^^^^^^^^^^^^

::

  src/mod/mymodule/
  ├── meson.build        # Meson build file
  └── mymodule.c         # Source code

Example meson.build
^^^^^^^^^^^^^^^^^^^

::

  mymodule = static_library('mymodule',
    'mymodule.c',
    include_directories: [includes],
    install: true,
    install_dir: get_option('prefix') / 'modules'
  )

Building Modules
^^^^^^^^^^^^^^^^

Modules are built automatically with the main Eggdrop build::

  meson setup builddir
  ninja -C builddir
  meson install -C builddir --destdir=/path/to/eggdrop

Compiled modules appear in ``modules/`` directory of the install.

Bind System
-----------

Eggdrop's bind system is how IRC events trigger Tcl scripts. Binds connect C code to Tcl callbacks.

Bind Types
^^^^^^^^^^

Common built-in binds:

- **pub** — Public channel messages (non-bot commands)
- **msg** — Private messages from users
- **join** — User joins channel
- **part** — User leaves channel
- **kick** — User is kicked
- **mode** — Channel mode changes
- **topic** — Channel topic changes
- **account** — User authenticates
- **dcc** — Partyline commands
- **server** — Server messages

Creating a Custom Bind
^^^^^^^^^^^^^^^^^^^^^^

To create a bind in a module:

1. Declare a bind handle::

     static p_tcl_bind_list H_mybind;

2. Register the bind in startup::

     H_mybind = add_bind_table("mybind", HT_STACKABLE, mybind_2char);

3. Define the argument handler::

     static int mybind_2char STDVAR
     {
       Function F = (Function) cd;
       BADARGS(3, 3, " arg1 arg2");
       CHECKVALIDITY(mybind_2char);
       F(argv[1], argv[2]);
       return TCL_OK;
     }

4. Create a trigger function::

     int check_tcl_mybind(char *arg1, char *arg2)
     {
       struct flag_record fr = { FR_GLOBAL | FR_CHAN, 0, 0, 0, 0, 0 };
       Tcl_SetVar(interp, "_mybind1", arg1, 0);
       Tcl_SetVar(interp, "_mybind2", arg2, 0);
       return check_tcl_bind(H_mybind, "mask", &fr,
                             " $_mybind1 $_mybind2",
                             MATCH_MASK | BIND_STACKABLE);
     }

5. Call it from C code when event occurs::

     check_tcl_mybind(data1, data2);

6. Unregister in shutdown::

     del_bind_table(H_mybind);

Bind Flags
^^^^^^^^^^

When creating a bind table::

- **HT_STACKABLE** — Multiple binds per mask allowed
- **0** (default) — Only one bind per mask (overwrites previous)

When triggering a bind with ``check_tcl_bind()``::

- **BIND_STACKABLE** — Call all matching binds, not just first
- **BIND_WANTRET** — Bind can return a value to C code
- **BIND_USE_ATTR** — Use flag record for filtering
- **MATCH_MASK** — Use mask matching (wildcards)
- **MATCH_PARTIAL** — Partial matching allowed
- **BIND_HAS_BUILTINS** — Has built-in handler

Tcl Commands from Modules
--------------------------

Modules can add Tcl commands that scripts can call.

Adding a Tcl Command
^^^^^^^^^^^^^^^^^^^^

1. Create a Tcl command function::

     static int tcl_mycommand STDVAR
     {
       BADARGS(2, 3, " arg ?optional?");

       if (strcmp(argv[1], "test") == 0) {
         Tcl_AppendResult(irp, "Success!", NULL);
         return TCL_OK;
       }
       Tcl_AppendResult(irp, "Unknown subcommand", NULL);
       return TCL_ERROR;
     }

2. Create a command table::

     static tcl_cmds mytcl[] = {
       {"mycommand", tcl_mycommand},
       {NULL, NULL}
     };

3. Export in module table (module startup needs to register)

Using libop Utilities
---------------------

Eggdrop 1.10 uses **libop** for common operations. Prefer libop over raw C library functions.

Common libop Functions
^^^^^^^^^^^^^^^^^^^^^^

**String handling**::

  op_strbuf_t *sb = op_strbuf_new();
  op_strbuf_append(sb, "Hello");
  op_strbuf_append(sb, " World");
  char *result = op_strbuf_str(sb);
  op_strbuf_delete(sb);

**Memory management**::

  void *ptr = op_malloc(size);
  void *ptr2 = op_realloc(ptr, newsize);
  op_free(ptr);

**List operations**::

  op_list_t *list = op_list_new();
  op_list_append(list, data);
  op_list_foreach(list, cb);
  op_list_delete(list);

**Hash tables**::

  op_hash_t *hash = op_hash_new();
  op_hash_set(hash, key, value);
  char *val = op_hash_get(hash, key);
  op_hash_delete(hash);

Module Loading and Registration
--------------------------------

Module Lifecycle
^^^^^^^^^^^^^^^^

1. **Discovery** — Meson finds modules in src/mod/
2. **Compilation** — Module compiled to ``.so`` file
3. **Installation** — Module copied to modules/ directory
4. **Loading** — Eggdrop loads module on startup (if in config)
5. **Initialization** — Module's `*_start()` function called
6. **Runtime** — Module provides features to scripts/bot
7. **Shutdown** — Module's `*_close()` function called (on unload)

Module Dependency Declaration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Modules can depend on other modules::

  if (!module_depend(MODULE_NAME, "server", 110, 0)) {
    return "Requires server module";
  }

Format: ``module_depend(name, other_module, major_version, minor_version)``

Memory Management
-----------------

Eggdrop modules must properly manage memory:

**Rules**:

1. Always allocate via ``op_malloc()`` or ``op_realloc()``
2. Always free via ``op_free()``
3. Report memory usage in ``*_expmem()`` function
4. Clean up on module unload

**Example**::

  static int mymodule_expmem(void)
  {
    int size = 0;
    size += sizeof(my_structure) * num_items;
    return size;
  }

Thread Safety
-------------

Eggdrop 1.10 is **NOT thread-safe**. Modules must NOT:

- Create threads
- Use locks/mutexes
- Assume concurrent execution

All Eggdrop code runs in a single event loop.

Error Handling
--------------

Module API Functions
^^^^^^^^^^^^^^^^^^^^

**Return values**:

- Functions returning status use -1 for error, 0 for success
- Functions returning data return pointer or NULL on error
- Tcl commands return TCL_OK or TCL_ERROR

**Error messages**:

- Use ``Tcl_AppendResult()`` for Tcl errors
- Use ``putlog()`` for logging errors to bot log

Testing Modules
---------------

Test your module before deploying:

1. **Compile and install**::

     ninja -C builddir
     meson install -C builddir --destdir=/path/to/eggdrop

2. **Load in config**::

     [modules]
     load = ["mymodule"]

3. **Check loading**::

     ./eggdrop -t eggdrop.toml
     .module

4. **Test features**::

     # For Tcl commands
     .tcl mycommand test

     # For binds, trigger from IRC
     # For partyline commands, test on partyline

Debugging Modules
-----------------

**Enable debug build**::

  meson setup builddir -Dbuildtype=debug
  ninja -C builddir

**Use debugger**::

  gdb ./eggdrop
  (gdb) run -t eggdrop.toml

**Check logs**::

  tail -f logs/eggdrop.log

**Partyline debugging**::

  .module          # List loaded modules
  .status          # Check overall bot status
  .tcl puts "Test" # Execute Tcl code

Best Practices
--------------

1. **Use libop for common operations** — Consistency, safety, maintainability
2. **Follow code style** — See src/mod/ examples for Eggdrop style
3. **Document your code** — Comments explaining non-obvious logic
4. **Handle errors gracefully** — Don't crash the bot
5. **Memory cleanup** — Properly free all allocations
6. **Test thoroughly** — Before distributing
7. **Version correctly** — Use semantic versioning
8. **Declare dependencies** — Via ``module_depend()``

Example: Simple Timer Module
-----------------------------

::

  #define MODULE_NAME "mytimer"

  #undef global
  static Function *global = NULL;
  EXPORT_SCOPE char *mytimer_start();

  static int mytimer_expmem(void) { return 0; }
  static void mytimer_report(int idx, int details) { }

  static int tcl_timer STDVAR
  {
    BADARGS(2, 2, " seconds");
    int seconds = atoi(argv[1]);
    timer(seconds, NULL, NULL);
    Tcl_AppendResult(irp, "Timer set", NULL);
    return TCL_OK;
  }

  static tcl_cmds mytimer_cmds[] = {
    {"timer", tcl_timer},
    {NULL, NULL}
  };

  char *mytimer_start(Function *global_funcs)
  {
    global = global_funcs;
    module_register(MODULE_NAME, mytimer_table, 1, 0);
    if (!module_depend(MODULE_NAME, "eggdrop", 110, 0)) {
      module_undepend(MODULE_NAME);
      return "Eggdrop 1.10+ required";
    }
    return NULL;
  }

  static char *mytimer_close(void)
  {
    module_undepend(MODULE_NAME);
    return NULL;
  }

  static Function mytimer_table[] = {
    (Function) mytimer_start,
    (Function) mytimer_close,
    (Function) mytimer_expmem,
    (Function) mytimer_report,
  };

See Also
--------

- `Writing Modules <writing.html>`_ — Module creation guide
- `Core API <../using/tcl-commands.html>`_ — Tcl command reference
- Eggdrop source code — ``src/mod/`` directory for examples
- ``src/main.h`` — Core data structures and API

Resources
---------

- Eggdrop GitHub: https://github.com/eggheads/eggdrop
- Eggheads Forum: https://www.eggheads.org
- #eggdrop on Libera.Chat

Copyright (C) 1999 - 2025 Eggheads Development Team
