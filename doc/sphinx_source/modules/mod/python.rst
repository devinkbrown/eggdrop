Last revised: May 2026

.. _python:

=============
Python Module
=============

This module embeds a Python 3 interpreter into Eggdrop, allowing scripts
written in Python to run alongside (or instead of) Tcl scripts.

-------------------
System Requirements
-------------------

Python 3.8 or higher is required, including the development headers.  On
Debian/Ubuntu systems install::

  sudo apt-get install python3 python3-dev python3-is-python3

The module requires the Global Interpreter Lock (GIL).  Free-threaded
(GIL-disabled) builds of Python 3.13+ are not supported.

--------------
Loading Python
--------------

**Configuration** — add to your ``eggdrop.toml``::

  [modules]
  load = [
    ...
    "python",
  ]


To load a python script from your config file, place the .py file in the
scripts/ folder and add::

  pysource scripts/myscript.py

The python module cannot be unloaded once loaded.

------------------
Partyline Commands
------------------

^^^^^^^^^^^^^^^^^^^
python <expression>
^^^^^^^^^^^^^^^^^^^

Evaluate a Python expression or statement from the partyline::

  .python eggdrop.botname()
  Python: 'MyBot'
  .python eggdrop.putserv("PRIVMSG #chan :hello!")

^^^^^^^^^^^^^
.binds python
^^^^^^^^^^^^^

The python module extends the core ``.binds`` partyline command by adding a
``python`` mask.  This command will list all binds registered by Python scripts.

------------------
Script commands
------------------

^^^^^^^^^^^^^^^^^^^^^^^
pysource <path/to/file>
^^^^^^^^^^^^^^^^^^^^^^^

Load a Python script into Eggdrop.  Analogous to the Tcl ``source`` command.
The path is relative to the Eggdrop home directory.

This command is available as a config-file directive and also as a TCL command
(when Tcl is enabled).

---------------------
Python eggdrop module
---------------------

Python scripts access Eggdrop functionality through the built-in ``eggdrop``
C extension module.  For a complete reference of all available functions see
:doc:`/using/python`.

The companion library ``scripts/eggtools.py`` provides high-level Pythonic
wrappers, type annotations, and decorator-based bind registration.

Example::

  import eggdrop
  import eggtools

  @eggtools.on_pub("*", "!hello")
  def cmd_hello(nick, host, handle, channel, text):
      eggtools.privmsg(channel, f"Hello, {nick}!")

For a step-by-step tutorial see :doc:`/tutorials/pythonscript`.

Copyright (C) 2020 - 2025 Eggheads Development Team
