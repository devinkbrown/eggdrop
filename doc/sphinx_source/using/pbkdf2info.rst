Password Hashing with PBKDF2 and Blowfish
==========================================

Eggdrop 1.10 uses PBKDF2 (Password-Based Key Derivation Function 2) for password hashing. The older Blowfish module is still supported for backward compatibility but is deprecated.

Overview
--------

**PBKDF2** — Modern, recommended password hashing algorithm

- Uses salt + multiple rounds for security
- Maximum password length: 30 characters (vs. 15 with Blowfish)
- Slower to compute (intentional, prevents brute force)
- Available since Eggdrop 1.9.0

**Blowfish** — Legacy cipher support

- Still available for reading old passwords
- NOT recommended for new installations
- Can be phased out through hybrid migration

The default Eggdrop 1.10 configuration loads both modules to support seamless migration.

PBKDF2 Fundamentals
-------------------

PBKDF2 is a one-way hashing function that:

1. Takes a password (string)
2. Adds a salt (random value, ensures identical passwords hash differently)
3. Applies many rounds of hashing (computational cost discourages brute force)
4. Produces a hash (stored in userfile, cannot be reversed)

**Important**: A hash cannot be reversed to get the password. To authenticate, Eggdrop hashes the user's input and compares it to the stored hash.

Password Format
^^^^^^^^^^^^^^^

PBKDF2 hashes are stored as::

  $pbkdf2_sha256$rounds=50000$salt$hash

Example::

  $pbkdf2_sha256$rounds=50000$abcd1234$ef567890ghijk

- ``pbkdf2_sha256`` — Algorithm used
- ``50000`` — Number of rounds
- ``abcd1234`` — Salt value
- ``ef567890ghijk`` — Resulting hash

Recommended Configuration
-------------------------

For new Eggdrop installations, use PBKDF2 only:

In ``eggdrop.toml``::

  [modules]
  load = [
    "pbkdf2",    # Modern password hashing
    # "blowfish"  # Commented out - legacy only
    ... other modules ...
  ]

For existing installations, migrate gradually (see below).

Migrating from Blowfish to PBKDF2
----------------------------------

Two approaches:

**Approach 1: Hybrid (Recommended)**
  - Load both modules
  - Users' passwords convert automatically on first login
  - No forced password resets

**Approach 2: Solo**
  - Load PBKDF2 only
  - Requires all users to set new passwords
  - Use only if you're starting fresh

Hybrid Migration (Recommended)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Hybrid allows gradual migration without password resets.

**Setup**:

1. Back up your userfile (the file ending in ``.user``):

   ::

     cp mybot.user mybot.user.backup

2. Load both modules in ``eggdrop.toml``:

   ::

     [modules]
     load = [
       "pbkdf2",
       "blowfish",
       ... other modules ...
     ]

3. Start Eggdrop:

   ::

     ./eggdrop eggdrop.toml

4. Users log in normally (using their old Blowfish passwords)

5. **On first successful login**, the pbkdf2 module updates the password to PBKDF2 format

6. Future logins use the PBKDF2 hash

**Result**: Passwords gradually migrate from Blowfish to PBKDF2 as users log in.

**Timeline**: All passwords will be PBKDF2 after all users log in once. You can track progress via ``.status``:

::

  .status

Check the message output for password conversion progress.

**Completing hybrid migration**: Once all passwords are migrated (or after a reasonable time), disable Blowfish:

::

  [modules]
  load = [
    "pbkdf2",
    # "blowfish",  # Now disabled
    ... other modules ...
  ]

Solo Migration (Fresh Start)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Use solo only if you're starting a new bot or willing to reset all passwords.

**Setup**:

1. Back up your userfile (important):

   ::

     cp mybot.user mybot.user.backup

2. Load PBKDF2 only in ``eggdrop.toml``:

   ::

     [modules]
     load = [
       "pbkdf2",
       # "blowfish",  # Commented out
       ... other modules ...
     ]

3. Start Eggdrop:

   ::

     ./eggdrop eggdrop.toml

4. Announce password reset to users: "Please set a new password with `/msg <bot> PASS newpassword`"

5. Users can also change passwords via partyline: `.chpass <newpassword>`

**Security note**: Without Blowfish, existing users have no password. Any user matching their hostmask could set a password and gain access. **Require immediate password resets**.

PBKDF2 Configuration
--------------------

PBKDF2 has optional tuning settings in ``eggdrop.toml``:

``pbkdf2-rounds = 50000``
  Number of hashing rounds. Higher = slower (more secure against brute force).
  Default: 50000 (reasonable balance).

``pbkdf2-method = "sha256"``
  Hashing algorithm. Options: ``sha256`` (recommended), ``sha512`` (stronger).
  Default: ``sha256``.

Example::

  [pbkdf2]
  rounds = 50000
  method = "sha256"

**Tuning guidance**:

- Modern systems (2020+): 50000-100000 rounds is good
- Older systems: Start at 20000 and adjust based on login speed
- Higher rounds = slower logins but better security

Using PBKDF2 in Tcl Scripts
----------------------------

The PBKDF2 module adds the ``encpass2`` Tcl command:

::

  set hash [encpass2 "mypassword"]
  puts $hash
  # Output: $pbkdf2_sha256$rounds=50000$...$...

This creates a PBKDF2 hash suitable for storing in the userfile.

**Example script: Manual password setting**

::

  proc set_user_password {handle password} {
    set hash [encpass2 $password]
    setuser $handle pass $hash
    putlog "Password updated for $handle"
  }

  # Usage
  set_user_password "myhandle" "mynewpassword"

Checking Password Hashes
^^^^^^^^^^^^^^^^^^^^^^^^^

To see what format a user's password is in, use `.userinfo`:

::

  .userinfo <handle>

Look at the "passwd" field. It will start with:

- ``$pbkdf2_sha256$`` — PBKDF2 (good)
- ``$2a$`` or similar — Blowfish (legacy)
- Empty — No password set

Troubleshooting
---------------

"User authentication failed" after migration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- User's password hasn't been converted yet (hybrid mode) — they'll be converted on next login
- Blowfish module was removed too early — re-enable it temporarily
- User set wrong password — use `.chpass` to reset from partyline

Forgot password
^^^^^^^^^^^^^^^

Owner can reset via partyline:

::

  .chpass <handle> <newpassword>

Or the user can set via /msg:

::

  /msg <bot> PASS mynewpassword

Both use PBKDF2 for the new password.

Password too long (over 30 characters)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

PBKDF2 limits passwords to 30 characters. If a user has a longer password:

1. Temporarily allow longer (edit source, rebuild)
2. Reset to 30 characters or less
3. User's old password becomes invalid

**Better approach**: Just reset to 30-char password.

Reverting from PBKDF2 to Blowfish
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Not recommended**. Once migrated, PBKDF2 hashes cannot be converted back to Blowfish format.

If you must revert:

1. Restore your backup userfile (from before PBKDF2 migration)
2. Load Blowfish only
3. Users will need to re-migrate later

Botnet Password Considerations
-------------------------------

When linking bots via botnet:

- Hub and leaf must use the same password modules
- If hub uses PBKDF2, leaf must also load PBKDF2
- Both must load both modules for hybrid migration

Recommended botnet setup:

All bots in the botnet should have:

::

  [modules]
  load = [
    "pbkdf2",
    "blowfish",  # For compatibility during migration
    ... other modules ...
  ]

Botnet passwords are set via ``.link`` and ``.link accept`` commands on the partyline.

Performance Considerations
--------------------------

PBKDF2 is intentionally slower than Blowfish (provides better security):

- Password hashing on user login: ~100ms-200ms (normal delay)
- Botnet authentication: ~100ms-200ms per bot link
- Large botnets: May add seconds to full authentication

**Tuning**:

If logins are too slow:

1. Reduce ``pbkdf2-rounds`` (trade security for speed)
2. Monitor system load during peak usage
3. Consider network latency (botnet links)

If you have security concerns:

1. Increase ``pbkdf2-rounds`` (trade speed for security)
2. Use stronger ``pbkdf2-method`` (sha512)

Best Practices
--------------

1. **Always back up before migrating** — Restore from backup if something goes wrong
2. **Use hybrid migration** — Easier transition than solo
3. **Announce migration to users** — Let them know passwords are being updated
4. **Verify all users migrated** — Check userfile for remaining Blowfish hashes
5. **Disable Blowfish after migration** — Reduces module load
6. **Use strong passwords** — PBKDF2 protects against brute force, but strong passwords are still best
7. **Rotate passwords periodically** — Even with PBKDF2
8. **Keep userfile backed up** — Store backups offline

See Also
--------

- `User Management <users.html>`_ — User commands and flags
- `Core Settings <core.html>`_ — Configuration reference
- `Accounts <accounts.html>`_ — Account tracking and SASL

Standards
---------

- RFC 2898 — PBKDF2 specification
- `OWASP password storage guidance <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>`_

Copyright (C) 2000 - 2025 Eggheads Development Team
