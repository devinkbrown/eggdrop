First Steps with Eggdrop
========================

Congratulations! Your Eggdrop is running. Now it's time to learn the basic commands and set it up for your channels.

Connecting to the Partyline
----------------------------

The **partyline** is your command interface with the bot. You can connect via:

1. **Telnet** (command line):

   ::

     telnet <bot-ip> <listen-port>

   Example::

     telnet 192.168.1.100 3333

   Find the listen port in your bot's startup message (e.g., "Listening for telnet connections on ...").

2. **DCC Chat** (IRC client):

   ::

     /dcc chat <botnick>

   Or::

     /ctcp <botnick> chat

3. **First time setup**:

   When you first start the bot, it tells you how to introduce yourself::

     STARTING BOT IN USERFILE CREATION MODE.
     Telnet to the bot and enter 'NEW' as your nickname.
     OR go to IRC and type: /msg BotNick hello

   Choose one method to introduce yourself as the master/owner.

Introducing Yourself
^^^^^^^^^^^^^^^^^^^^

**Via IRC** (easiest):

::

  /msg <botnick> hello

This adds you as the owner of the bot. You'll get a note confirming it worked.

**Via Partyline**:

1. Telnet or DCC chat to the bot
2. When prompted for a nickname, type ``NEW``
3. You'll be added as the owner

**Set a Password**:

Once you're recognized as the owner, set a password::

  /msg <botnick> pass mypassword

Or on the partyline::

  .chpass mypassword

Basic Partyline Commands
------------------------

Type ``.help`` for a list of commands. Common first commands:

::

  .help                    # List all commands
  .help <command>          # Help for a specific command
  .status                  # Show bot status
  .join #channel           # Join a channel
  .part #channel           # Leave a channel
  .+chan #channel          # Add a channel (permanent)
  .-chan #channel          # Remove a channel
  .+user <handle>          # Add a user
  .-user <handle>          # Remove a user
  .+host <handle> mask     # Add a hostmask to a user
  .chattr <handle> +flag   # Set user flags
  .chanset #channel opt    # Configure a channel
  .op #channel nick        # Op a user in a channel
  .deop #channel nick      # Remove op from a user

Common First Steps
------------------

Join Your First Channel
^^^^^^^^^^^^^^^^^^^^^^^

Tell the bot to join a channel::

  .+chan #mychannel

The bot will join the channel and remember it between restarts (if you use ``.+chan`` instead of ``.join``).

Check the bot is there::

  /join #mychannel

Add Your First User
^^^^^^^^^^^^^^^^^^^

Add a user with a handle (nickname for the bot to track them)::

  .+user YourHandle

Grant Yourself Op Flag
^^^^^^^^^^^^^^^^^^^^^^^

To give yourself channel op ability, add the ``o`` flag::

  .chattr YourHandle +o

Other useful flags:

- ``o`` — Channel op
- ``m`` — Master (high privilege)
- ``n`` — Owner (highest privilege)
- ``v`` — Voice
- ``f`` — Friend (won't be kicked)
- ``b`` — Bot user (can link botnets)
- ``h`` — Help file access
- ``p`` — Partyline access

See ``.help whois`` for the full flag list.

Add Your Hostmask
^^^^^^^^^^^^^^^^^

The bot recognizes users by hostmask (nick!ident@host). Add yours so the bot knows who you are::

  /whois YourNick

Find your hostmask (looks like ``YourNick!ident@example.com``), then::

  .+host YourHandle *!*@example.com

Or use a pattern to match your ISP::

  .+host YourHandle *!ident@*.isp.com

Configure Channel Settings
^^^^^^^^^^^^^^^^^^^^^^^^^^

The bot can enforce channel modes and protect ops. Configure a channel with::

  .chanset #mychannel protectops 1

Useful channel settings:

- ``protectops 1`` — Re-op users with ``+o`` flag if deopped (recommended)
- ``enforcebans 1`` — Kick users matching bans
- ``dynamicbans 1`` — Only activate bans when needed (cleaner)
- ``autoop 1`` — Auto-op users with ``+o`` flag (risky, use protectops instead)

Advanced: Bans and Exempts
^^^^^^^^^^^^^^^^^^^^^^^^^^

Ban a user from the channel::

  .ban #mychannel *!*@badhost.com

Remove a ban::

  .unban #mychannel *!*@badhost.com

Exempt a hostmask from bans::

  .exempt #mychannel *!*@goodhost.com

Auto-Restart on Crash/Reboot
-----------------------------

Eggdrop includes a helper script to set up automatic restarts.

**Systemd** (recommended for modern Linux):

::

  ./scripts/autobotchk eggdrop.toml -systemd

Then control the bot with::

  systemctl --user start <botnick>.service     # Start
  systemctl --user stop <botnick>.service      # Stop
  systemctl --user restart <botnick>.service   # Restart
  systemctl --user enable <botnick>.service    # Auto-start on boot
  systemctl --user disable <botnick>.service   # Don't auto-start

**Crontab** (older systems):

::

  ./scripts/autobotchk eggdrop.toml

This runs the botchk script every 10 minutes and restarts the bot if it crashed.

Verify with::

  crontab -l

SASL Authentication
-------------------

SASL allows the bot to authenticate with NickServ before joining channels. This is useful if your network requires identification.

**Setup**:

In your ``eggdrop.toml``, add SASL configuration (check your config for SASL section):

::

  [sasl]
  mechanism = "SCRAM-SHA-256"
  username = "YourBotNick"
  password = "your-password"

**Mechanisms** (in order of recommendation):

1. **SCRAM-SHA-256** — Secure, recommended
2. **SCRAM-SHA-512** — Stronger version
3. **EXTERNAL** — Certificate-based (requires TLS certs)
4. **ECDH-X25519-CHALLENGE** — Elliptic curve
5. **PLAIN** — Simple (use only over TLS)

**For Libera.Chat**:

Most users use SCRAM-SHA-256 with their registered account. Set ``username`` to your registered bot nick and ``password`` to your NickServ password.

**Testing SASL**:

Check the bot's status::

  .status

Look for "Authenticated" in the output. If SASL worked, the bot is identified immediately on connect.

Basic Scripting
---------------

Eggdrop uses Tcl for scripting. Here's a simple example:

**File: ``greet.tcl``**::

  proc greet_user {nick host handle chan} {
    putserv "PRIVMSG $chan :Welcome $nick!"
  }

  bind join - * greet_user

**To load**:

1. Save as ``scripts/greet.tcl``
2. Add to ``eggdrop.toml``:

   ::

     [scripts]
     files = ["greet.tcl"]

3. Restart bot or type ``.reload`` on partyline

**What it does**: Greets users when they join the channel.

See `Writing Scripts <firstscript.html>`_ for more examples.

Common Issues
-------------

Bot Doesn't Appear in Channel
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- Bot is not online: Check ``.status`` on partyline
- Bot not joined channel: Use ``.+chan #channel`` to add
- Bot has no op: Bot can't enforce bans/kicks without op
- Server rejected bot: Check bot logs

Can't Connect to Partyline
^^^^^^^^^^^^^^^^^^^^^^^^^^

- Wrong port: Check listen port in startup message
- Firewall blocking: Ensure port is open
- Wrong IP: Use bot's hostname or IP from ``ifconfig``
- Bot crashed: Check logs, restart bot

Users Not Getting Op
^^^^^^^^^^^^^^^^^^^^

- User doesn't have ``+o`` flag: Use ``.chattr handle +o``
- User hostmask doesn't match: Use ``.+host`` to add their mask
- ``protectops`` not enabled: Use ``.chanset #channel protectops 1``
- Bot needs channel op to give op

Forgot Your Password
^^^^^^^^^^^^^^^^^^^^

If you're still owner:

::

  .chpass YourHandle newpassword

If you lost owner access:

1. Stop the bot
2. Delete or rename the user file
3. Restart with ``./eggdrop -m eggdrop.toml``
4. Introduce yourself again as the new owner

Next Steps
----------

- `Core Configuration <../using/core.html>`_ — Full config reference
- `User Management <../using/users.html>`_ — User flags and permissions
- `Channel Management <../using/features.html>`_ — Channel features
- `Writing Scripts <firstscript.html>`_ — Tcl scripting guide
- `TLS Setup <tlssetup.html>`_ — Secure connections
- `Botnet Configuration <../using/botnet.html>`_ — Link multiple bots

Key Concepts
------------

**Handle**: Bot's name for a user (tracks by hostmask, not nickname)

**Flags**: Permissions assigned to users (``o`` = op, ``m`` = master, etc.)

**Hostmask**: Pattern identifying a user (``nick!ident@host``)

**Partyline**: Command interface with the bot (telnet/DCC chat)

**Chanset**: Per-channel settings (protectops, enforcebans, etc.)

**Module**: Optional feature loaded at startup (channels, server, notes, etc.)

**Script**: Tcl code that extends bot functionality

Getting Help
------------

If you're stuck:

1. Type ``.help <command>`` on the partyline
2. Check the documentation (this site)
3. Ask in #eggdrop on Libera.Chat
4. Check bot logs: ``tail logs/eggdrop.log``

Be ready to provide:

- Bot version: ``.version``
- Channel info: ``.chanset #channel``
- User info: ``.userinfo <handle>``
- Any error messages from the log

Copyright (C) 1999 - 2025 Eggheads Development Team
