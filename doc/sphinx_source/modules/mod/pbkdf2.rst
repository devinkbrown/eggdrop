Last revised: May 2026

.. _pbkdf2:

===============
PBKDF2 Module
===============

Eggdrop encrypts its userfile, so users can have secure passwords.
Eggdrop will not start without an encryption module.

As of Eggdrop 1.9.0, the PBKDF2 module was added as the recommended
password hashing algorithm. It works alongside the blowfish module to make
migration easier. For new bots, load only the PBKDF2 module. When migrating
from Eggdrop 1.8 or earlier, load both — Eggdrop will silently upgrade old
blowfish hashes to PBKDF2 on first login, allowing you to eventually drop
the blowfish module.

This module requires: none

**Configuration** — add to your ``eggdrop.toml``::

  [modules]
  load = [
    "pbkdf2",
    # "blowfish",   # Load alongside pbkdf2 only when migrating from 1.8 userfiles
    ...
  ]

  [pbkdf2]
  method = "SHA256"   # Hash function (SHA256 recommended)
  rounds = 1600       # Iteration count — higher is slower but more brute-force resistant

Settings
--------

``method``
  Cryptographic hash function used for PBKDF2. Supported values depend on the
  hash algorithms available in opssl (the bundled TLS library). Recommended: ``SHA256``.

``rounds``
  Number of PBKDF2 iterations. Higher values increase brute-force resistance at
  the cost of hashing speed. Default: ``1600``. NIST recommends 600,000+ for
  SHA-256 in high-security contexts; for IRC bots the default is a reasonable
  balance.

Migration from Blowfish
-----------------------

To migrate an existing 1.8/1.9 userfile to PBKDF2:

1. Load both modules in ``eggdrop.toml``::

     [modules]
     load = ["pbkdf2", "blowfish", ...]

2. Users' passwords are automatically rehashed to PBKDF2 on next login.

3. After all users have logged in at least once, you can remove ``"blowfish"``
   from the load list and restart.

Copyright (C) 2000 - 2025 Eggheads Development Team
