Eggdrop Core Settings
=====================

This document describes the TOML configuration format for Eggdrop 1.10. The configuration file (typically ``eggdrop.toml``) contains all settings needed to run your bot.

**Note**: Eggdrop 1.10 uses TOML format, not the older ``.conf`` format. See `Upgrading <../install/upgrading.html>`_ if migrating from 1.8 or 1.9.

Configuration File Format
--------------------------

Eggdrop 1.10 uses TOML (Tom's Obvious, Minimal Language), a human-readable configuration format.

**Quick TOML Syntax**:

- Sections are enclosed in square brackets: ``[section-name]``
- Key-value pairs: ``key = "value"`` or ``key = 123``
- Arrays (lists): ``key = ["item1", "item2"]``
- Comments start with ``#``

Example::

  # This is a comment
  [bot]
  nick = "MyBot"
  owner = "YourNick"

  [servers]
  list = [
    "irc.example.com:6667",
    "irc2.example.com:+6697",
  ]

Getting Started
---------------

**To generate a configuration interactively**::

  ./eggdrop --setup eggdrop.toml

**To use a sample configuration**::

  cp eggdrop.toml.sample eggdrop.toml
  # Edit with your text editor

**Then start the bot**::

  ./eggdrop eggdrop.toml

Core Sections
-------------

[bot] — Bot Identity
^^^^^^^^^^^^^^^^^^^^^

``nick = "Lamestbot"``
  Primary nickname used on IRC and botnet.

``altnick = "Llamab?t"``
  Alternate nickname if the primary is taken. ``?`` is replaced with a random digit.

``realname = "/msg Lamestbot hello"``
  Bot's "real name" / GECOS field shown on IRC.

``username = "lamest"``
  Bot's username/ident. Only used if no ident daemon is running.

``admin = "Lamer <email: lamer@example.com>"``
  Contact information shown in ``.status`` output. Include email and preferred contact method.

``network = "MyNetwork"``
  IRC network name (informational). Shared with other botnets.

``timezone = "EST"``
  Timezone name (3+ letters). Examples: ``EST``, ``UTC``, ``PST``, ``CET``.
  Used for timestamps in logs and scripts.

``offset = "5"``
  UTC offset in hours. Positive if west of prime meridian, negative if east.
  Example: ``EST`` is UTC-5, so offset is ``5``.

``owner = "YourNick, OtherNick"``
  **REQUIRED**. Comma-separated list of bot owner nicks. On first run, these users receive owner flags.
  Set this before starting the bot for the first time.

``botnet_nick = "BotNetNick"``
  Separate botnet nick. Defaults to IRC nick if unset.

``pidfile = "pid.MyBot"``
  Path to PID file (process ID). Used for tracking running processes.
  Defaults to ``pid.<botnetnick>`` if unset.

``notify-newusers = "$owner"``
  Who receives a note when a new user is added. Common value: ``$owner`` (bot owner).

``default-flags = "hp"``
  Default flags for new users (via ``.adduser`` or ``hello`` command).
  ``h`` = has help, ``p`` = partyline access. See `Users <users.html>`_.

``whois-fields = "url birthday"``
  Custom whois fields displayed in ``.whois`` output.

[servers] — IRC Servers
^^^^^^^^^^^^^^^^^^^^^^^

``list = ["host:port", "host:+port", "host:port:password"]``
  List of IRC servers to connect to. Format options:

  - ``irc.example.com:6667`` — plain connection
  - ``irc.example.com:+6697`` — TLS connection (``+`` enables TLS)
  - ``irc.example.com:6667:password`` — server password
  - ``2001:db8::1:6667`` — IPv6 address in brackets

  The bot cycles through this list when disconnected. **You must edit this list.**

Example::

  [servers]
  list = [
    "irc.libera.chat:+6697",
    "irc2.libera.chat:+6697",
    "irc.efnet.org:+6697",
  ]

[channels] — Channels to Join
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``list = ["#channel1", "#channel2"]``
  List of channels the bot automatically joins at startup.

Per-channel settings are configured with ``[[chanset]]`` blocks (see below).

Example::

  [channels]
  list = ["#eggdrop", "#egghelp", "#bottest"]

[[chanset]] — Per-Channel Settings
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Each ``[[chanset]]`` block configures a single channel. The channel must be listed in ``[channels]`` above.

Basic structure::

  [[chanset]]
  channel = "#mychannel"
  # ... settings below ...

Common channel settings:

``autoop = true/false``
  Automatically op users with ``+o`` flag on join. Default: ``false``.

``autohalfop = true/false``
  Automatically halfop users with ``+l`` flag. Default: ``false``.

``autovoice = true/false``
  Automatically voice users with ``+v`` flag. Default: ``false``.

``protectops = true/false``
  Re-op users with ``+o`` flag if deopped. Default: ``true``. **Recommended**.

``protectfriends = true/false``
  Re-op users with ``+f`` flag if deopped. Default: ``false``.

``bitch = true/false``
  Only allow users with ``+o`` flag to hold ops. Default: ``false``.

``cycle = true/false``
  Part and rejoin if the channel has no ops. Default: ``false``.

``enforcebans = true/false``
  Kick users matching bans when the ban is set. Default: ``false``.

``dynamicbans = true/false``
  Only activate bans when needed (reduces ban list noise). Default: ``false``.

``greet = true/false``
  Announce user info when they join. Default: ``false``.

``secret = true/false``
  Hide from botnet listings. Default: ``false``.

``nodesynch = true/false``
  Allow non-ops to set modes (prevents fighting with services). Default: ``true``.

``inactive = true/false``
  Do not join this channel (preserves settings). Default: ``false``.

Example::

  [[chanset]]
  channel = "#eggdrop"
  protectops = true
  enforcebans = true
  dynamicbans = true

  [[chanset]]
  channel = "#bottest"
  protectops = true

[modules] — Load Modules
^^^^^^^^^^^^^^^^^^^^^^^^

``load = ["module1", "module2"]``
  List of modules to load at startup. Modules are C extensions that add functionality.

**Built-in modules** (commonly used):

- ``pbkdf2`` — Generation-2 password hashing (recommended)
- ``blowfish`` — Legacy password hashing support
- ``channels`` — Channel tracking and management
- ``server`` — Core IRC server support
- ``ctcp`` — CTCP protocol (VERSION, TIME, PING, etc.)
- ``irc`` — Basic IRC functionality
- ``notes`` — Offline message storage
- ``console`` — Persist console settings
- ``uptime`` — Uptime reporting to eggheads.org

**Optional modules**:

- ``transfer`` — DCC SEND/GET and userfile transfer
- ``share`` — Userfile sharing between botnets
- ``compress`` — Zlib compression for transfers
- ``filesys`` — Built-in file server
- ``seen`` — `!seen` command
- ``assoc`` — Party-line channel naming
- ``ident`` — Ident daemon support
- ``twitch`` — Twitch gaming support
- ``python`` — Python 3.8+ scripting
- ``webui`` — Web-based administration UI

Example::

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

[listen] — Partyline Listening Ports
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``ports = ["port spec", ...]``
  Ports the bot listens on for partyline/telnet connections and DCC.

Format: ``"port network"`` or ``"+port network"``

- ``"3333 all"`` — listen on port 3333, all IP addresses
- ``"+3333 all"`` — listen on port 3333 with TLS
- ``"3333 127.0.0.1"`` — listen only on localhost
- ``"3333 2001:db8::1"`` — listen on specific IPv6 address

Example::

  [listen]
  ports = [
    "3333 all",        # Plain telnet on 3333
    "+3334 all",       # TLS on 3334 (requires certificates)
  ]

[tls] — TLS/SSL Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Prerequisites**: Generate certificates with ``./scripts/genssl.sh``

``privatekey = "eggdrop.key"``
  Path to private key file. Required if bot listens on TLS ports or accepts TLS DCC.

``certificate = "eggdrop.crt"``
  Path to certificate file. Required if bot listens on TLS ports or accepts TLS DCC.

``verify-depth = 10``
  Maximum certificate chain depth. Typically 10.

``verify-server = 0``
  Verify IRC server certificates. 0 = no verification (default), 1 = full, 2 = allow self-signed.

``verify-bots = 0``
  Verify botnet peer certificates. 0 = no, 1 = full, 2 = allow self-signed.

``verify-clients = 0``
  Verify partyline client certificates. 0 = no, 1 = full, 2 = allow self-signed.

``verify-dcc = 0``
  Verify DCC certificates. Same values as above.

``cert-auth = 0``
  Enable TLS certificate authentication. 0 = disabled, 1 = optional, 2 = required.

Example::

  [tls]
  privatekey = "eggdrop.key"
  certificate = "eggdrop.crt"
  verify-bots = 2  # Allow self-signed botnet certs

[botnet] — Botnet Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Botnet allows multiple Eggdrops to connect and share data.

Configure botnet connections via partyline commands like ``.+bot`` rather than config file settings. See `Botnet Configuration <botnet.html>`_ for details.

[dcc] — Direct Client Connection Settings
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``timeout = 300``
  DCC timeout in seconds. Default: 300.

``blocksize = 0``
  Block size for DCC transfers. 0 = turbo (fast), 1024 = slower but safer. Default: 0.

``use-ssl = false``
  Enable TLS for DCC connections. Default: ``false``.

[storage] — User/Channel Data Storage
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``backend = "lmdb"``
  Storage backend for user/channel data. Options: ``lmdb`` (recommended) or ``flatfile``.
  Default: ``lmdb``.

``lmdb-path = "data/"``
  Path to LMDB database directory. Default: ``data/``.

[paths] — Directory Paths
^^^^^^^^^^^^^^^^^^^^^^^^^

``temp = "tmp"``
  Temporary directory for operations. Default: ``tmp/``.

``scripts = "scripts"``
  Directory for Tcl scripts. Default: ``scripts/``.

``modules = "modules"``
  Directory for compiled modules. Default: ``modules/``.

``data = "data"``
  Data directory for databases, logs, etc. Default: ``data/``.

[scripts] — Load Tcl Scripts
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``files = ["script1.tcl", "script2.tcl"]``
  List of Tcl scripts to load at startup. Paths are relative to the scripts directory.

Example::

  [scripts]
  files = [
    "alltools.tcl",
    "myscript.tcl",
  ]

Logging Configuration
---------------------

[logs] — Log File Settings
^^^^^^^^^^^^^^^^^^^^^^^^^^

Logging captures bot activity for debugging and auditing.

``max-logs = 20``
  Maximum concurrent open log files. Default: 20.

``[logs.channel]``
  Channel activity logging.

``[logs.botnet]``
  Botnet activity logging.

``[logs.server]``
  Server activity logging.

Advanced Usage
--------------

Variable Substitution
^^^^^^^^^^^^^^^^^^^^^

In some settings, you can use ``$owner`` to refer to the bot owner(s):

Example::

  [bot]
  owner = "MyNick, OtherNick"
  notify-newusers = "$owner"

Conditional Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^

TOML does not support conditionals. For conditional settings, use Tcl scripts in the ``[scripts]`` section.

Example in a Tcl script::

  if {[string match "*libera*" [botnet-info name]]} {
    putcmdlog "Connected to Libera"
  }

Validation
----------

Before starting your bot, ensure:

- All required settings are present (especially ``[bot]`` section)
- TOML syntax is valid (square brackets, quotes, commas)
- File paths are accessible and readable
- Server list is not empty
- Owner is specified
- No die/quit commands in scripts

To check syntax without starting::

  ./eggdrop -h eggdrop.toml

Common Configurations
---------------------

Minimal Configuration
^^^^^^^^^^^^^^^^^^^^^

::

  [bot]
  nick = "MyBot"
  owner = "MyNick"

  [servers]
  list = ["irc.libera.chat:+6697"]

  [channels]
  list = ["#mychannel"]

  [modules]
  load = ["pbkdf2", "blowfish", "channels", "server", "ctcp", "irc"]

Production Configuration
^^^^^^^^^^^^^^^^^^^^^^^^

::

  [bot]
  nick = "ProductionBot"
  owner = "Admin1, Admin2"
  admin = "Admin <email@example.com>"
  network = "MyNetwork"

  [servers]
  list = [
    "irc.libera.chat:+6697",
    "irc2.libera.chat:+6697",
  ]

  [channels]
  list = ["#main", "#ops", "#help"]

  [[chanset]]
  channel = "#main"
  protectops = true
  enforcebans = true

  [modules]
  load = [
    "pbkdf2", "blowfish", "channels", "server",
    "ctcp", "irc", "notes", "console", "uptime"
  ]

  [listen]
  ports = ["+3333 all"]

  [tls]
  privatekey = "eggdrop.key"
  certificate = "eggdrop.crt"

  [scripts]
  files = ["alltools.tcl"]

Troubleshooting Configuration
-----------------------------

Invalid TOML Syntax
^^^^^^^^^^^^^^^^^^^

Error: ``TOML parse error``

- Check for mismatched quotes
- Verify array syntax: ``["item1", "item2"]``
- Ensure section headers have square brackets: ``[section]``

Server List Empty
^^^^^^^^^^^^^^^^^

Error: ``No servers configured``

Add servers to ``[servers]`` section::

  [servers]
  list = ["irc.example.com:6667"]

Owner Not Specified
^^^^^^^^^^^^^^^^^^^

Error: ``No owner specified``

Set owner in ``[bot]`` section::

  [bot]
  owner = "YourNick"

Certificate Not Found
^^^^^^^^^^^^^^^^^^^^^

Error: ``Cannot find TLS certificate``

1. Generate certificates::

     ./scripts/genssl.sh

2. Verify file paths are correct in ``[tls]`` section
3. Check file permissions (files must be readable)

See Also
--------

- `Setting Up Eggdrop <../tutorials/setup.html>`_ — Getting started guide
- `Upgrading <../install/upgrading.html>`_ — Migration from 1.8/1.9
- `Users <users.html>`_ — User management and flags
- `Botnet Configuration <botnet.html>`_ — Multi-bot networks
- `Tcl Commands <tcl-commands.html>`_ — Scripting reference

Sample Files
^^^^^^^^^^^^

- ``eggdrop.toml.sample`` — Full sample with all options documented
- ``eggdrop-basic.toml`` — Minimal working configuration

Copyright (C) 1997 Robey Pointer
Copyright (C) 1999 - 2025 Eggheads Development Team
