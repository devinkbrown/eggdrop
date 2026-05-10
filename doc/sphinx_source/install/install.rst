.. _installing_eggdrop:

=======================================
Installing Eggdrop
=======================================

This is the quick install guide. If you are new to Eggdrop or UNIX-like systems, **READ the README file first**. This guide assumes familiarity with command-line tools.

For advanced topics, see the README file and the build system documentation.

Prerequisites
-------------

Before installing Eggdrop, ensure you have:

1. **Tcl Development Library** (8.5.0 or newer)
   - Includes both the Tcl runtime and development headers
   - Install via your system package manager (e.g., ``tcl-dev`` on Debian, ``tcl-devel`` on Fedora)
   - Verify with: ``tclsh`` (should give you a ``%`` prompt; type ``exit`` to quit)

2. **Meson and Ninja** (build tools)
   - Install via your system package manager (e.g., ``meson ninja-build`` on Debian)

3. **Python 3.8+** (optional, only if you want the Python module)

4. **zlib** (optional, only if you want the compression module)

**TLS Support Note**: Eggdrop includes opssl, a custom bundled TLS library that supports TLS 1.2 and 1.3. No external library installation is needed. TLS can be disabled at build time if desired.

Quick Build and Install
-----------------------

1. Extract the Eggdrop source code

   From a release tarball::

     tar xzf eggdrop-1.10.1.tar.gz
     cd eggdrop-1.10.1

   Or from git::

     git clone https://github.com/eggheads/eggdrop.git
     cd eggdrop

2. Configure the build with Meson

   From the Eggdrop source directory, run::

     meson setup builddir

   This creates a build directory and detects your system configuration. Meson will automatically find Tcl and other required libraries.

   To customize the build, use options like::

     meson setup builddir -Dtls=disabled    # Disable TLS support
     meson setup builddir -Dpython=enabled  # Enable Python module

   To see all available options::

     meson setup builddir --help

3. Compile Eggdrop

   From the source directory::

     ninja -C builddir

   This compiles the bot and all enabled modules. The build output is in ``builddir/``.

4. Install to a destination directory

   Default installation (to your home directory under ``eggdrop/``)::

     meson install -C builddir

   Install to a custom location::

     meson install -C builddir --destdir=/path/to/install

   For example::

     meson install -C builddir --destdir=$HOME/mybot

5. Generate TLS certificates (optional but recommended)

   If you plan to use TLS for botnet links or IRC connections, generate certificates::

     cd /path/to/installed/eggdrop
     ./scripts/genssl.sh

   This creates ``eggdrop.crt`` and ``eggdrop.key`` in the install directory.

   For scripted/non-interactive generation::

     ./scripts/genssl.sh -s

   Read `TLS Setup <../tutorials/tlssetup.html>`_ for more information.

6. Edit your configuration file

   A sample configuration file is provided at ``eggdrop.toml.sample``. Copy and customize it::

     cp eggdrop.toml.sample eggdrop.toml
     # Edit eggdrop.toml with your text editor

   See `Core Settings <../using/core.html>`_ for a complete guide to configuration options.

7. Create a user file (first run)

   Start the bot with the ``-m`` flag to create a user file::

     ./eggdrop -m eggdrop.toml

   This creates the user file with the owner(s) specified in the configuration.

8. Start the bot normally

   From future runs, simply::

     ./eggdrop eggdrop.toml

   Or run in foreground/terminal mode for debugging::

     ./eggdrop -t eggdrop.toml

9. Set up automatic restarts (optional)

   Eggdrop includes a helper script to set up systemd or crontab monitoring::

     ./scripts/autobotchk eggdrop.toml -systemd

   Or for crontab::

     ./scripts/autobotchk eggdrop.toml

   See the README file for more autobotchk options.

Build Options Reference
-----------------------

Common Meson build options for Eggdrop:

+------------------+---------------------+------------------------------------------+
| Option           | Default             | Description                              |
+==================+=====================+==========================================+
| ``-Dtls``        | ``enabled``         | TLS 1.2/1.3 support (opssl bundled)      |
+------------------+---------------------+------------------------------------------+
| ``-Dpython``     | ``disabled``        | Python 3.8+ module support               |
+------------------+---------------------+------------------------------------------+
| ``-Dcompression``| ``disabled``        | Zlib compression module                  |
+------------------+---------------------+------------------------------------------+
| ``-Dwebui``      | ``disabled``        | Web UI module (requires TLS)             |
+------------------+---------------------+------------------------------------------+

To enable an option::

  meson setup builddir -Doption=enabled

Cygwin/Windows Requirements
---------------------------

Eggdrop can be compiled on Windows via Cygwin. Install the following packages via the Cygwin installer:

::

  Interpreters: tcl, tcl-devel
  Devel:        gcc-core, git, make, meson, ninja
  Libs:         zlib-devel

Then follow the standard build instructions above.

Modules
-------

Modules are optional feature components that can be loaded at runtime via the configuration file. They are compiled during the normal build process.

**Built-in modules** (always compiled):

- ``pbkdf2`` — Generation-2 userfile encryption
- ``blowfish`` — Legacy userfile encryption support
- ``channels`` — Channel tracking and management
- ``server`` — Core IRC server support
- ``ctcp`` — CTCP protocol support
- ``irc`` — Basic IRC functionality
- ``notes`` — Offline message storage
- ``console`` — Partyline settings persistence
- ``uptime`` — Uptime reporting

**Optional modules** (enable in ``eggdrop.toml``):

- ``transfer`` — DCC SEND/GET and userfile transfer
- ``share`` — Userfile sharing between botnets
- ``compress`` — Compression for file transfer
- ``filesys`` — Built-in file server
- ``seen`` — !seen command functionality
- ``assoc`` — Party-line channel naming
- ``ident`` — Ident daemon support
- ``twitch`` — Twitch gaming service support
- ``python`` — Python 3.8+ scripting
- ``webui`` — Browser-based administration UI

To load modules, edit the ``[modules]`` section in your ``eggdrop.toml``.

Custom Modules
^^^^^^^^^^^^^^

Third-party modules can be added to the ``src/mod/`` directory before building. Meson will automatically detect and compile them. Modules must include proper Meson build integration.

Advanced Build Topics
---------------------

Rebuilding
^^^^^^^^^^

To rebuild after changing source code or configuration options::

  ninja -C builddir
  meson install -C builddir --destdir=/path/to/install

Static vs. Dynamic Builds
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Eggdrop uses dynamic modules by default (modules are separate ``.so`` files loaded at runtime). This provides flexibility and smaller binary size. Dynamic builds are recommended for most users.

If you need a static build, use::

  meson setup builddir -Ddefault_library=static

Debug Builds
^^^^^^^^^^^^

For debug builds with additional logging and debugging symbols::

  meson setup builddir -Dbuildtype=debug
  ninja -C builddir

This produces larger binaries but helps the Eggdrop developers track down and fix issues. Please include debug information when reporting crashes.

Troubleshooting
---------------

Build fails with "tcl.h not found"
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Install the Tcl development headers. On Debian/Ubuntu::

  sudo apt-get install tcl-dev

On Fedora/RHEL::

  sudo dnf install tcl-devel

On macOS::

  brew install tcl-tk

Build fails with "Meson not found"
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Install Meson. On most systems::

  sudo apt-get install meson        # Debian/Ubuntu
  sudo dnf install meson            # Fedora/RHEL
  brew install meson                # macOS

Build fails with other dependency errors
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Run ``meson setup builddir --wipe`` to clear the build directory and start fresh::

  rm -rf builddir
  meson setup builddir

Then try again. If the issue persists, check that all prerequisites are installed.

Uninstalling
------------

To remove Eggdrop, simply delete the installation directory::

  rm -rf /path/to/installed/eggdrop

User files and configuration files are not deleted automatically.

Next Steps
----------

After installation, see:

- `First Steps with Eggdrop <../tutorials/firststeps.html>`_ — basic setup and commands
- `Core Settings <../using/core.html>`_ — configuration reference
- `TLS Setup <../tutorials/tlssetup.html>`_ — secure connections
- `Writing Scripts <../tutorials/firstscript.html>`_ — Tcl/Python scripting

Copyright (C) 1997 Robey Pointer
Copyright (C) 1999 - 2025 Eggheads Development Team
