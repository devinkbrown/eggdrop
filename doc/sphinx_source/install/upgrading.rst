Upgrading Eggdrop
=================

Upgrading Eggdrop to a newer version is straightforward. We recommend reading the NEWS file in the source distribution to understand changes since your last upgrade. Most configuration files, user files, and channel files are compatible across 1.8, 1.9, and 1.10.x releases.

For support, visit us on Libera #eggdrop or https://www.eggheads.org.

Backup Before Upgrading
-----------------------

Before upgrading, back up your existing Eggdrop installation:

- ``.toml`` configuration file (or ``.conf`` if upgrading from older versions)
- ``.user`` user file
- ``.chan`` channel file
- ``.db`` LMDB database files (if using LMDB storage)

These files are generally not overwritten during installation, but backups prevent accidental data loss.

How to Upgrade
--------------

1. **Review changes**

   Read the NEWS file in the source distribution to identify breaking changes and new configuration options that may apply to your setup.

2. **Back up your files** (as described above)

3. **Download and extract the new source**

   From release tarball::

     tar xzf eggdrop-1.10.1.tar.gz
     cd eggdrop-1.10.1

   Or from git::

     git clone https://github.com/eggheads/eggdrop.git
     cd eggdrop

4. **Build with Meson** (see `Installing Eggdrop <install.html>`_)

   ::

     meson setup builddir
     ninja -C builddir
     meson install -C builddir --destdir=/path/to/install

5. **Update your configuration file**

   Review the sample ``eggdrop.toml.sample`` or your old config file and make any necessary updates. See `Core Settings <../using/core.html>`_ for the complete configuration reference.

6. **Restart Eggdrop**

   Stop your running bot and start the new version::

     ./eggdrop eggdrop.toml

7. **Verify operation**

   Check logs and verify the bot is connecting and behaving as expected.

Major Changes in Eggdrop 1.10
-----------------------------

Configuration File Format
^^^^^^^^^^^^^^^^^^^^^^^^^^

Eggdrop 1.10 uses **TOML format** for configuration files (``eggdrop.toml``), replacing the old ``.conf`` format.

**Migration from 1.8/1.9 .conf files:**

- The bot does NOT automatically convert old .conf files
- Use the ``--setup`` wizard to generate a new TOML config interactively::

    ./eggdrop --setup mybot.toml

- Or manually review a sample TOML file and recreate your settings

See `Core Settings <../using/core.html>`_ for the complete TOML configuration reference.

Userfile Encryption
^^^^^^^^^^^^^^^^^^^

Eggdrop 1.10 uses **PBKDF2** for password hashing, replacing the older Blowfish module.

**If upgrading from 1.8 or 1.9:**

- Existing Blowfish-encrypted userfiles are still supported (the ``blowfish`` module is available for backward compatibility)
- **Migration to PBKDF2 is recommended** for better security
- See `PBKDF2 Info <../using/pbkdf2info.html>`_ for step-by-step migration instructions

**Never perform password migration carelessly**—improper handling can render userfiles inaccessible.

Build System
^^^^^^^^^^^^

Eggdrop 1.10 uses **Meson and Ninja** for building, replacing the older autoconf/configure system.

**Build steps are now:**

::

  meson setup builddir
  ninja -C builddir
  meson install -C builddir --destdir=/path/to/install

See `Installing Eggdrop <install.html>`_ for full build instructions.

TLS Library
^^^^^^^^^^^

Eggdrop 1.10 includes **opssl**, a custom bundled TLS library (TLS 1.2 and 1.3 support).

- No external OpenSSL or wolfSSL installation needed
- TLS certificates can still be generated with ``./scripts/genssl.sh``
- See `TLS Setup <../tutorials/tlssetup.html>`_ for details

Module System
^^^^^^^^^^^^^

**Loading modules:**

Modules are now specified in the ``[modules]`` section of ``eggdrop.toml``:

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
    "uptime",
  ]

Third-party modules from Eggdrop 1.6, 1.8, and 1.9 should generally work with 1.10 if they do not contain version-checking code. See `Modules <../modules/included.html>`_ for a list of included modules.

Scripts and Tcl Commands
^^^^^^^^^^^^^^^^^^^^^^^^

- All Tcl scripts from Eggdrop 1.6 and later should work with 1.10
- Consult `Tcl Commands <../using/tcl-commands.html>`_ for command reference
- No action required unless you use deprecated commands (see NEWS file)

Botnet Links
^^^^^^^^^^^^

- TLS/SSL botnet links require explicitly enabling with a ``+`` prefix on the port
- Plaintext botnet links still work but are not recommended
- Use ``.chaddr`` to update port prefixes if needed

IRCv3 and SASL
^^^^^^^^^^^^^^

Eggdrop 1.10 supports modern IRCv3 capabilities and multiple SASL mechanisms:

- SASL PLAIN
- SASL ECDSA-NIST256P-CHALLENGE
- SASL EXTERNAL
- SASL SCRAM-SHA-256
- SASL SCRAM-SHA-512
- SASL ECDH-X25519-CHALLENGE

See `Accounts <../using/accounts.html>`_ for configuration.

Troubleshooting Upgrades
------------------------

Old config file format not working?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Use ``./eggdrop --setup`` to generate a new TOML config, or manually convert settings using the sample ``eggdrop.toml.sample`` as a template.

Userfile passwords invalid after upgrade?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

See `PBKDF2 Info <../using/pbkdf2info.html>`_ for migration instructions. If you skipped the blowfish module, install it temporarily to migrate passwords.

Bot crashes or won't start?
^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. Try starting in foreground mode to see error messages::

     ./eggdrop -t eggdrop.toml

2. Check the config file syntax (TOML files are strict about formatting)
3. Ensure all required settings are present (see sample config)
4. Check file permissions (config and user files should be readable by the bot)

Next Steps
----------

After upgrading, review:

- `Core Settings <../using/core.html>`_ — configuration reference
- `First Steps <../tutorials/firststeps.html>`_ — getting started guide
- `Features <../using/features.html>`_ — available functionality

Copyright (C) 1997 Robey Pointer
Copyright (C) 1999 - 2025 Eggheads Development Team
