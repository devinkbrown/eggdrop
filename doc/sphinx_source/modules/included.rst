Modules Included with Eggdrop
=============================

Eggdrop 1.10 includes a comprehensive set of modules providing core functionality and optional features. Modules are loaded in the ``[modules]`` section of ``eggdrop.toml``.

.. toctree::

    mod/assoc
    mod/blowfish
    mod/channels
    mod/compress
    mod/console
    mod/ctcp
    mod/dns
    mod/filesys
    mod/ident
    mod/irc
    mod/notes
    mod/pbkdf2
    mod/python
    mod/seen
    mod/server
    mod/share
    mod/transfer
    mod/twitch
    mod/woobie
    mod/uptime

Core Modules (Always Load These)
---------------------------------

:ref:`server`
    **Required for IRC connections.**
    Provides core IRC server protocol support. Without this, the bot cannot connect to IRC networks. Must be loaded.

:ref:`irc`
    **Required for IRC functionality.**
    Provides basic IRC protocol handling (JOIN, PART, PRIVMSG, etc.). Must be loaded for IRC operation.

:ref:`channels`
    **Recommended.**
    Enables channel management, channel-specific user files, and channel settings (protectops, enforcebans, etc.). Required if you want the bot to manage channels properly.

:ref:`ctcp`
    **Recommended.**
    Provides CTCP (Client-to-Client Protocol) responses (VERSION, TIME, PING). Enables DCC CHAT. Recommended for normal operation.

Password Hashing Module (Load One)
-----------------------------------

**Choose either PBKDF2 (recommended) or Blowfish (legacy).**

:ref:`pbkdf2`
    **Recommended for password hashing.**
    Modern password hashing using PBKDF2-SHA256. Provides secure password storage with salt and multiple rounds. Recommended for all new installations. Can work alongside Blowfish for gradual migration from old userfiles.

:ref:`blowfish`
    **Legacy password support (deprecated).**
    Old password hashing algorithm. Still needed if: (1) you're migrating from 1.8/1.9 userfiles, or (2) you use Tcl to encrypt/decrypt strings. Not recommended for new bots. Can be removed once all passwords are migrated to PBKDF2.

**Configuration**: Load PBKDF2 for modern bots. For migration, load both temporarily::

  [modules]
  load = [
    "pbkdf2",      # Modern hashing
    "blowfish",    # Legacy support (temporary)
    ...
  ]

Optional Feature Modules
------------------------

:ref:`notes`
    **Recommended for user-friendly bots.**
    Stores offline messages. Users can leave notes for others who aren't currently online. Notes are stored and delivered when the recipient logs in.

:ref:`console`
    **Recommended.**
    Persists partyline console settings (channels joined, format preferences) across bot restarts. Without it, console settings reset on restart.

:ref:`compress`
    **Optional, requires zlib.**
    Enables file compression for DCC file transfers and userfile transfers. Reduces bandwidth. Only load if you use transfer module and want compression.

:ref:`transfer`
    **Optional for DCC file transfers.**
    Provides DCC SEND/GET file transfer support and userfile transfer between linked bots. Required for ``share`` module.

:ref:`share`
    **Optional for botnet userfile sharing.**
    Enables userfile sharing between linked bots in a botnet. Requires ``transfer`` module. Allows botnets to sync user lists.

:ref:`filesys`
    **Optional for built-in file server.**
    Provides a built-in file server allowing users to upload/download files. Creates a "file area" accessible via DCC or partyline. Useful for distributing scripts, configs, etc.

:ref:`uptime`
    **Optional reporting.**
    Reports bot uptime statistics to the Eggheads uptime website (https://www.eggheads.org/uptime). Fun tracking of bot longevity. Takes about 9 hours to appear on the website.

Advanced/Specialized Modules
-----------------------------

:ref:`assoc`
    **Optional for botnet.**
    Provides channel naming on botnets. Allows linking multiple channels with the same name across different networks via different bots. Advanced feature.

:ref:`ident`
    **Optional ident daemon.**
    Enables Eggdrop to either run its own ident daemon (oident service) or interface with an external ident daemon. Useful if your shell/ISP blocks ident on certain ports.

:ref:`dns`
    **Optional DNS optimization.**
    Provides asynchronous DNS resolution. Prevents bot from hanging while resolving hostnames. Useful on slow systems or with DNS delays.

:ref:`python`
    **Optional Python scripting (requires Python 3.8+).**
    Adds a Python interpreter to Eggdrop, enabling Python scripts alongside Tcl scripts. Requires Python 3.8 or newer on your system.

:ref:`twitch`
    **Optional Twitch gaming support.**
    Adds specialized support for connecting to Twitch (the gaming streaming platform). Handles Twitch IRC modifications and features. Read ``doc/TWITCH`` for details.

:ref:`seen`
    **Optional basic seen command.**
    Provides simple !seen command to show when a user was last seen. Limited functionality. For advanced seen commands, see external modules like gseen.

Example Module Configurations
------------------------------

**Minimal Configuration** (just core):

::

  [modules]
  load = [
    "pbkdf2",
    "server",
    "ctcp",
    "irc",
  ]

**Standard Configuration** (recommended):

::

  [modules]
  load = [
    "pbkdf2",
    "blowfish",      # For migration support
    "channels",
    "server",
    "ctcp",
    "irc",
    "notes",
    "console",
    "uptime",
  ]

**Advanced Configuration** (with file server and botnet):

::

  [modules]
  load = [
    "pbkdf2",
    "blowfish",
    "channels",
    "server",
    "ctcp",
    "irc",
    "notes",
    "console",
    "transfer",
    "compress",
    "share",
    "filesys",
    "uptime",
  ]

**Twitch Configuration**:

::

  [modules]
  load = [
    "pbkdf2",
    "server",
    "ctcp",
    "irc",
    "notes",
    "console",
    "twitch",
  ]

**Python Support Configuration**:

::

  [modules]
  load = [
    "pbkdf2",
    "channels",
    "server",
    "ctcp",
    "irc",
    "notes",
    "console",
    "python",
  ]

Module Dependencies
-------------------

Some modules require others:

- **share** requires **transfer**
- **transfer** requires **channels** (for userfile)
- **compress** optional for **transfer** (speeds up transfers)
- **python** optional standalone (Python scripting)
- **twitch** replaces **server** for Twitch-only bots

Recommended load order (as shown above):

1. Password hashing (pbkdf2/blowfish)
2. Core protocol (server, irc, ctcp)
3. Channel management (channels)
4. Storage (notes, console)
5. Optional transfers (transfer, compress, share)
6. Optional specialized (filesys, python, twitch)

Disabling Modules
-----------------

To disable a module, remove it from the ``load`` list::

  [modules]
  load = [
    "pbkdf2",
    "channels",
    "server",
    "ctcp",
    "irc",
    # "notes",       # Disabled
    # "console",     # Disabled
    "uptime",
  ]

Modules are not loaded if not listed. Comment out or remove lines to disable.

Custom/Third-Party Modules
---------------------------

To add custom modules:

1. Place source code in ``src/mod/yourmodule/``
2. Include a ``meson.build`` file
3. Rebuild::

     ninja -C builddir
     meson install -C builddir --destdir=/path/to/eggdrop

4. Add to ``[modules]`` load list in ``eggdrop.toml``

See `Writing Modules <writing.html>`_ for details.

Troubleshooting Module Loading
-------------------------------

**Module load failed - not found**
  Ensure the module is in the modules/ directory and the name is correct.

**Module incompatible version**
  Module was compiled for a different Eggdrop version. Rebuild the module.

**Module segfault**
  Module has a bug. Check logs and contact the module author.

**Bot won't start without X module**
  Some modules are required (check error message). Load them or fix dependency.

Module Status
^^^^^^^^^^^^^

Check loaded modules on the partyline::

  .module

See currently loaded modules and their version.

See Also
--------

- `Installing Eggdrop <../install/install.html>`_ — Build and install modules
- `Writing Modules <writing.html>`_ — Create custom modules
- `Module Internals <internals.html>`_ — Advanced module API reference
- `Core Settings <../using/core.html>`_ — Configuration reference

Copyright (C) 1999 - 2025 Eggheads Development Team
