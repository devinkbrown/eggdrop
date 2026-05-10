Account Tracking and SASL
==========================

Eggdrop 1.10 provides two account-related features:

1. **Account Tracking** — Associate IRC users with their authenticated accounts
2. **SASL** — Authenticate the bot itself with NickServ or other services

Account Tracking
----------------

Account tracking allows Eggdrop to know which user on IRC is logged into which service account. This is useful for scripts that react to authenticated users.

Requirements
^^^^^^^^^^^^

Account tracking requires the IRC server to support three features:

1. **extended-join** (IRCv3)
   - Adds account name to JOIN messages
   - Allows Eggdrop to know account on user join

2. **account-notify** (IRCv3)
   - Notifies when users authenticate/deauthenticate
   - Allows Eggdrop to update account status in real-time

3. **WHOX**
   - Custom WHO responses
   - Allows Eggdrop to query accounts for existing channel members

All three are required for full accuracy. Modern networks (Libera.Chat, DALnet, etc.) support all three.

Enabling Account Tracking
^^^^^^^^^^^^^^^^^^^^^^^^^^

Eggdrop requests account tracking capabilities by default. In your ``eggdrop.toml``, you can control this:

::

  # Request extended-join capability
  extended-join = true

  # Request account-notify capability
  account-notify = true

Set these to ``false`` to disable (not recommended unless the server doesn't support them).

Checking Account Tracking Status
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

On the partyline, type::

  .status

Look for a line like::

  Account tracking: Enabled

If account tracking is not enabled, you'll see::

  Account tracking: Best-effort (Missing capabilities: extended-join, account-notify)

**Full account tracking** = server supports all three features, Eggdrop has requested them

**Best-effort** = server supports some but not all features. Eggdrop updates account info when it sees it, but cannot guarantee completeness.

Best-Effort Account Tracking
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If the server doesn't fully support all three features, Eggdrop runs in "best-effort" mode:

- **No extended-join**: Can't determine account when user joins; updates with WHOX later
- **No account-notify**: Can't track authentication; updates with WHOX later
- **No WHOX**: Can't query existing channel members; updates when they talk

**Supplementary: account-tag**

The ``account-tag`` capability attaches account info to every message. Enable it for better accuracy in best-effort mode::

  account-tag = true

This updates Eggdrop's account tracking every time a user talks, improving accuracy.

Using Accounts in Scripts
^^^^^^^^^^^^^^^^^^^^^^^^^

The ``ACCOUNT`` bind is triggered when a user's account status changes:

::

  bind account * * handle_account

  proc handle_account {account nick host handle chan} {
    putlog "User $nick authenticated as $account in $chan"
  }

**Important**: ACCOUNT bind triggers for status **changes**, not user joins. Pair it with a JOIN bind to catch both:

::

  bind join * * handle_join
  bind account * * handle_account

  proc handle_join {nick host handle chan} {
    putlog "User $nick (account: [getchanuser $nick $chan]) joined $chan"
  }

  proc handle_account {account nick host handle chan} {
    putlog "User $nick authenticated as $account in $chan"
  }

Checking Accounts in Scripts
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Get a user's account in a script:

::

  # Get account for a user in a channel
  set account [getchanuser $nick $chan account]
  if {$account ne ""} {
    putlog "User $nick is authenticated as $account"
  } else {
    putlog "User $nick is not authenticated"
  }

SASL Authentication
-------------------

SASL (Simple Authentication and Security Layer) allows the bot to authenticate itself with a service (NickServ) when connecting to IRC.

Supported SASL Mechanisms
^^^^^^^^^^^^^^^^^^^^^^^^^^

Eggdrop 1.10 supports:

- **PLAIN** — Simple username/password (use only over TLS)
- **SCRAM-SHA-256** — Secure salted password hashing (recommended)
- **SCRAM-SHA-512** — Stronger version of SCRAM-SHA-256
- **EXTERNAL** — Certificate-based authentication
- **ECDSA-NIST256P-CHALLENGE** — Elliptic curve challenge
- **ECDH-X25519-CHALLENGE** — Elliptic curve Diffie-Hellman

**Recommendation**: Use SCRAM-SHA-256 or SCRAM-SHA-512. PLAIN is only safe over TLS.

Configuring SASL
^^^^^^^^^^^^^^^^

SASL is configured per-network. Most networks use the same mechanism for all connections, but some allow multiple mechanisms.

In ``eggdrop.toml``, configuration is typically in a ``[sasl]`` section or network-specific settings. Check your config file for SASL settings.

**Example: SCRAM-SHA-256**::

  # In your Tcl script or config
  sasl-mechanism SCRAM-SHA-256
  sasl-username "botnick"
  sasl-password "mypassword"

**Example: EXTERNAL (certificate-based)**::

  sasl-mechanism EXTERNAL
  # Requires TLS certs (eggdrop.crt, eggdrop.key)

SASL Authentication Flow
^^^^^^^^^^^^^^^^^^^^^^^^^

1. Bot connects to IRC server via TLS (recommended)
2. Server announces SASL support via CAP
3. Eggdrop sends AUTHENTICATE message
4. Server responds with challenge (depends on mechanism)
5. Eggdrop sends authentication response
6. Server grants access or denies

If SASL succeeds, the bot is identified immediately, before joining channels.

Common SASL Configurations
^^^^^^^^^^^^^^^^^^^^^^^^^^

**Libera.Chat with SCRAM-SHA-256**::

  [bot]
  nick = "MyBot"

  [servers]
  list = ["irc.libera.chat:+6697"]

  # SASL settings (add to config as appropriate)
  # mechanism: SCRAM-SHA-256
  # account: MyBot
  # password: <your-password>

**DALnet with EXTERNAL (certificate auth)**::

  [bot]
  nick = "MyBot"

  [servers]
  list = ["irc.dalnet.net:+6697"]

  [tls]
  privatekey = "eggdrop.key"
  certificate = "eggdrop.crt"

  # SASL settings
  # mechanism: EXTERNAL
  # (no password needed)

Troubleshooting SASL
^^^^^^^^^^^^^^^^^^^^

**SASL authentication failed**

- Wrong password: Verify the password matches NickServ records
- Wrong username: Check that the account name matches
- Server doesn't support the mechanism: Try PLAIN or SCRAM-SHA-256
- TLS connection required: Ensure you're connecting via TLS (port prefixed with ``+``)

**Bot connects but isn't identified**

- SASL not configured: Add SASL settings to config
- SASL mechanism not supported by server: Try a different mechanism
- Network doesn't use SASL: Some networks use only NickServ commands

**How to manually identify if SASL fails**

If SASL fails, you can manually identify via partyline:

::

  .msg NickServ identify <password>

Or use a Tcl script to identify after connecting:

::

  proc identify {} {
    putserv "PRIVMSG NickServ :IDENTIFY <password>"
  }

  bind evnt * "connected" identify

Account Differences: SASL vs. Account Tracking
-----------------------------------------------

**SASL** = Bot authentication (bot logs into its account)

- Happens at connection time
- Bot becomes "identified" on the network
- Grants ops or special privileges to the bot

**Account Tracking** = User authentication tracking (knowing which user is logged in)

- Happens during channel operation
- Eggdrop tracks which users are logged into accounts
- Scripts can react to user authentication

Both are independent features. You can use:

- SASL only (bot is identified, but doesn't track users)
- Account tracking only (tracks users, but bot doesn't identify itself)
- Both (bot is identified AND user authentication is tracked)

Best Practices
--------------

1. **Use TLS for SASL connections** — PLAIN mechanism requires TLS
2. **Prefer SCRAM-SHA-256 or SCRAM-SHA-512** — More secure than PLAIN
3. **Use EXTERNAL if server supports it** — Certificate-based, most secure
4. **Enable account tracking** — Useful for scripts that need to know account status
5. **Pair ACCOUNT and JOIN binds** — Catch both join and authentication events
6. **Store passwords securely** — Don't hardcode in scripts; use config file

See Also
--------

- `Accounts Tutorial <../tutorials/firststeps.html>`_ — Practical account setup
- `TLS Setup <tlssetup.html>`_ — TLS certificate configuration
- `Core Settings <core.html>`_ — Configuration reference
- `Tcl Commands <tcl-commands.html>`_ — Scripting reference

IRC Standards
-------------

- `IRCv3 SASL <https://ircv3.net/specs/extensions/sasl-3.1>`_
- `IRCv3 extended-join <https://ircv3.net/specs/extensions/extended-join>`_
- `IRCv3 account-notify <https://ircv3.net/specs/extensions/account-notify>`_
- `IRCv3 account-tag <https://ircv3.net/specs/extensions/account-tag>`_
- `WHOX <https://ircv3.net/specs/extensions/whox>`_

Copyright (C) 1999 - 2025 Eggheads Development Team
