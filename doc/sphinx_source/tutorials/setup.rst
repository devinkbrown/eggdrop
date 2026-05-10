Setting Up Eggdrop
==================

*This guide is based on the setup information from egghelp.org and has been updated for Eggdrop 1.10 with Meson build system and TOML configuration.*

Prerequisites
-------------

Before installing Eggdrop, ensure you have:

1. **Tcl Development Library** (8.5.0 or newer)

   - On Debian/Ubuntu::

       sudo apt-get install tcl tcl-dev

   - On Fedora/RHEL::

       sudo dnf install tcl tcl-devel

   - On macOS::

       brew install tcl-tk

   - Verify with::

       tclsh

     If you see a ``%`` prompt, Tcl is installed. Type ``exit`` to quit.

2. **Meson and Ninja**

   - On Debian/Ubuntu::

       sudo apt-get install meson ninja-build

   - On Fedora/RHEL::

       sudo dnf install meson ninja-build

   - On macOS::

       brew install meson ninja

3. **Python 3.8+** (optional, only for Python scripting module)

4. **zlib** (optional, only for compression module)

**TLS Support**: Eggdrop includes opssl, a custom TLS library bundled in the source. No external library installation needed.

Quick Start (5 Minutes)
-----------------------

If you just want a working bot quickly:

#. Download the source::

     wget https://github.com/eggheads/eggdrop/archive/refs/heads/main.tar.gz
     tar xzf main.tar.gz && cd eggdrop-main

#. Build and install::

     meson setup builddir
     ninja -C builddir
     meson install -C builddir --destdir=$HOME/mybot
     cd $HOME/mybot

#. Generate a config file (interactive wizard)::

     ./eggdrop --setup eggdrop.toml

#. Create a user file::

     ./eggdrop -m eggdrop.toml

#. Start the bot::

     ./eggdrop eggdrop.toml

#. On IRC, introduce yourself to the bot::

     /msg <botnick> hello

You now have a working Eggdrop! Read the sections below for detailed explanations.

Detailed Installation
---------------------

Getting the Source
^^^^^^^^^^^^^^^^^^

Download locations:

- **Stable Release**: https://geteggdrop.com or https://github.com/eggheads/eggdrop/releases
- **FTP Mirror**: https://ftp.eggheads.org/pub/eggdrop/source
- **Git (Development)**: ``git clone https://github.com/eggheads/eggdrop.git``

For a stable release::

  wget https://github.com/eggheads/eggdrop/archive/refs/tags/v1.10.1.tar.gz
  tar xzf v1.10.1.tar.gz
  cd eggdrop-1.10.1

For the latest development version::

  git clone https://github.com/eggheads/eggdrop.git
  cd eggdrop

Building Eggdrop
^^^^^^^^^^^^^^^^

#. Enter the source directory::

     cd eggdrop-1.10.1

#. Set up the Meson build system::

     meson setup builddir

   Meson will automatically detect Tcl and other dependencies. If Tcl is not found, verify installation (see Prerequisites above).

#. Compile the bot::

     ninja -C builddir

   On some systems, use ``ninja-build`` instead of ``ninja``. This compiles Eggdrop and all enabled modules.

#. Install to your desired location::

     meson install -C builddir --destdir=$HOME/mybot

   Or install to a custom location::

     meson install -C builddir --destdir=/home/username/eggdrop-botname

   The ``--destdir`` flag specifies where to install. Use absolute paths or ``$HOME``.

#. (Optional) Remove the source directory::

     cd ~
     rm -rf eggdrop-1.10.1

Configuration
-------------

Eggdrop 1.10 uses **TOML format** for configuration files. The easiest way to create a config is to use the interactive setup wizard.

Using the Setup Wizard
^^^^^^^^^^^^^^^^^^^^^^

The interactive wizard guides you through essential settings::

  cd /path/to/installed/eggdrop
  ./eggdrop --setup mybot.toml

This creates a minimal but functional configuration file. Answer the prompts for:

- Bot nickname
- Alternate nickname
- Real name (GECOS)
- Owner nick(s)
- IRC network name
- IRC servers to connect to
- Channels to join

Manual Configuration
^^^^^^^^^^^^^^^^^^^^

If you prefer to edit the config file manually:

#. Copy the sample configuration::

     cp eggdrop.toml.sample eggdrop.toml

#. Edit with your text editor (nano, vim, etc.)::

     nano eggdrop.toml

#. At minimum, set these values:

   - **[bot]** section:

     - ``owner = "YourNick"`` — Your bot owner nick(s)
     - ``nick = "BotNick"`` — Bot's IRC nickname
     - ``altnick = "BotAlt?"`` — Alternate nick (? becomes random digit)

   - **[servers]** section:

     - ``list = ["irc.example.com:6667", "irc2.example.com:+6697"]`` — IRC servers

   - **[channels]** section:

     - ``list = ["#channel1", "#channel2"]`` — Channels to join

   See `Core Settings <../using/core.html>`_ for the complete configuration reference.

#. Save the file.

Common Configuration Options
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

These are frequently used settings in the ``[bot]`` section:

- **nick**: Bot's nickname on IRC
- **altnick**: Alternate nick if primary is taken
- **username**: Bot's username/ident (for systems without identd)
- **realname**: Bot's "real name" / GECOS field
- **admin**: Admin contact information
- **owner**: List of owner nicks (set this!)
- **notify-newusers**: Who gets notified of new user registrations
- **timezone**: Timezone name for timestamps (e.g., "EST", "UTC")
- **offset**: UTC offset in hours

Modules
^^^^^^^

By default, Eggdrop loads commonly-used modules in the ``[modules]`` section::

  [modules]
  load = [
    "pbkdf2",     # Password hashing
    "blowfish",   # Legacy password support
    "channels",   # Channel management
    "server",     # IRC protocol
    "ctcp",       # CTCP support
    "irc",        # Basic IRC
    "notes",      # Offline messages
    "console",    # Partyline settings
    "uptime",     # Uptime reporting
  ]

To enable optional modules, uncomment them or add them to the list:

- ``transfer`` — DCC file transfers
- ``filesys`` — File server
- ``compress`` — Compression support
- ``python`` — Python scripting
- ``twitch`` — Twitch support

See `Modules <../modules/included.html>`_ for details.

Starting Your Bot
-----------------

Initial Start (Create User File)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For the very first start, use the ``-m`` flag to create a user file::

  ./eggdrop -m eggdrop.toml

This creates an empty user file with owner flags assigned to the first person who introduces themselves to the bot. It will also perform a /SQUIT before exiting (to ensure the bot doesn't hang around waiting to disconnect).

The bot should connect to IRC within a few moments.

Introducing Yourself
^^^^^^^^^^^^^^^^^^^^

Once your bot appears on IRC, introduce yourself to it::

  /msg <botnick> hello

This adds you to the bot's user list with owner privileges (if ``notify-newusers`` is configured).

Set a password::

  /msg <botnick> pass MySecurePassword

You can now DCC chat to the bot or use partyline commands.

Normal Starts
^^^^^^^^^^^^^

For future starts, simply::

  ./eggdrop eggdrop.toml

The bot will background itself and run as a daemon. To run in foreground (useful for debugging)::

  ./eggdrop -t eggdrop.toml

This drops you into an interactive partyline session. Type ``.help`` for commands.

Troubleshooting
---------------

Bot Doesn't Appear on IRC
^^^^^^^^^^^^^^^^^^^^^^^^^^

Check the log file for errors::

  tail -f logs/eggdrop.log

Common issues:

- **Tcl not found**: Verify Tcl development library is installed
- **Server list empty**: Edit config and add servers to ``[servers]`` section
- **Config syntax error**: TOML is strict about formatting; check for mismatched brackets or quotes
- **Connection refused**: Check server address and port

No Show (Advanced Debug)
^^^^^^^^^^^^^^^^^^^^^^^^

If the bot still doesn't connect:

#. Kill any running bot::

     kill $(cat pid.botnickname)

#. Restart in terminal mode with extended logging::

     ./eggdrop -t eggdrop.toml

#. Watch for error messages. Type ``.help`` for commands.

#. If you need support, capture output and ask in #eggdrop on Libera with error details.

Can't Introduce Myself
^^^^^^^^^^^^^^^^^^^^^^

- Make sure you're using the correct command format: ``/msg <botnick> hello``
- Check that the bot's nick is correctly set in config
- Check that ``learn-users`` is enabled in the config (default is enabled)
- Review the bot's log file for rejection reasons

Forgot My Password
^^^^^^^^^^^^^^^^^^

You'll need to either:

- Use partyline commands (if you have owner access) to reset the password
- Delete the user file and restart with ``./eggdrop -m eggdrop.toml`` (loses all users)
- Use the bot owner's PASS file capabilities (advanced)

Next Steps
----------

Now that your bot is running:

1. **Learn bot commands**: See `First Steps <firststeps.html>`_
2. **Configure channels**: See `Core Settings <../using/core.html>`_
3. **Write scripts**: See `First Script <firstscript.html>`_
4. **Set up TLS**: See `TLS Setup <tlssetup.html>`_
5. **Join the community**: #eggdrop on Libera.Chat

Copyright (C) 1997 Robey Pointer
Copyright (C) 1999 - 2025 Eggheads Development Team
