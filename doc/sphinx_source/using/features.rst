================
Eggdrop Features
================

Eggdrop is the most advanced open-source IRC bot available. It has been under
active development since December 1993 and is still regularly updated. Eggdrop
1.10 is a major modernization release, rewriting core subsystems for
performance, security, and reliability while preserving full backward
compatibility.

IRC Protocol Support
--------------------

* **IRCv3 capabilities** — account-notify, account-tag, away-notify, cap-notify,
  chghost, echo-message, extended-join, invite-notify, message-tags, monitor,
  SASL, server-time, setname, WHOX, and +typing.

* **TLS/SSL connections** — TLS 1.2 and 1.3 via the bundled opssl library. No
  external OpenSSL installation required.

* **IPv6 support** — full dual-stack connectivity to IRC servers and botnets.

* **SASL authentication** — PLAIN, SCRAM-SHA-256, SCRAM-SHA-512, EXTERNAL (X.509),
  ECDSA-NIST256P-CHALLENGE, and ECDH-X25519-CHALLENGE.

* **Twitch** — specialized support for Twitch's IRC protocol extensions.

Channel Management
------------------

* **Per-channel user lists** — equivalent to having a separate bot for each channel.

* **Automatic enforcement** — protectops, enforcebans, dynamicbans, autoop, and
  dozens of configurable per-channel settings.

* **Ban/exempt/invite lists** — global and per-channel, with wildcard and CIDR
  notation support.

* **Botnet** — link multiple Eggdrops to share user lists, ban lists, and
  channel management. Includes cryptographically secure bot authentication.

Scripting
---------

* **Tcl scripting** — the full Eggdrop Tcl API for custom commands, event binds,
  timers, and bot-to-bot communication.

* **Python 3.8+ scripting** — 100% API parity with the Tcl interface using
  Python decorators::

    from eggtools import on_pub, putchan

    @on_pub()
    def greet(nick, uhost, hand, chan, text):
        if text.startswith("!hello"):
            putchan(chan, f"Hello, {nick}!")

User Management
---------------

* **User records** — persistent handle-based user database with hostmask matching,
  channel flags, access levels, and optional passwords.

* **PBKDF2 password hashing** — PBKDF2-SHA256 with cryptographically random salt
  via ``getrandom(2)``. Legacy Blowfish hashing supported for migration.

* **User file sharing** — sync user and ban lists across a botnet (requires
  share + transfer modules).

* **LMDB storage backend** — optional Lightning Memory-Mapped Database for
  crash-safe atomic writes alongside the standard flat-file format.

Administration Interfaces
--------------------------

* **Partyline** — command interface accessible via DCC chat or telnet with multiple
  channels, letting you talk to people and control the bot without IRC influence.

* **Web dashboard (webui module)** — HTTPS browser interface with real-time log
  streaming, REST API, and WebSocket push. Manage the bot from any device.

* **Console mode** — view each channel in DCC chat with selective filtering for
  joins, parts, mode changes, and channel conversation.

Performance
-----------

* **io_uring / epoll / kqueue** — platform-optimal I/O with zero-copy on Linux 5.1+.

* **Async file I/O** — userfiles, notefiles, and channel files are written via a
  background worker pool with tmpfile + fsync + atomic rename. The main loop
  never blocks on disk.

* **O(1) data structures** — hash tables for user lookup, channel member lookup,
  ban matching, and socket dispatch (replaced all O(n) linear scans).

* **CIDR ban matching** — Patricia trie for O(k) lookups (k = address bits).

* **Block heap allocator** — slab allocator for hot-path objects reduces malloc
  overhead by ~80%.

* **LTO + PIE** — link-time optimization and position-independent executable
  enabled by default.

Security
--------

* **Build hardening** — stack protector, FORTIFY_SOURCE, full RELRO, no-PLT, and
  position-independent executable (with ``-Dhardening=true``).

* **CSPRNG everywhere** — ``getrandom(2)`` or ``arc4random_buf`` replaces all
  ``random()`` / ``srandom()`` call sites (password salts, DNS query IDs, etc.).

* **Safe string handling** — all ``strcpy``, ``sprintf``, ``strcat``, ``strtok``,
  ``gets``, and unbounded ``sscanf %s`` replaced with bounds-safe alternatives.

* **Memory-safe strings** — ``op_strbuf_t`` dynamic string builder eliminates
  fixed-buffer truncation risks throughout the codebase.

Modules and Extensibility
--------------------------

* **Module system** — add or remove features at runtime by loading or unloading
  ``.so`` modules from your TOML configuration.

* **21 built-in modules** — covering IRC protocol, CTCP, channels, file transfer,
  DNS, authentication, notes, scripting, web UI, and more.

* **Third-party modules** — place source in ``src/mod/yourmodule/`` and Meson
  picks it up automatically.

Build System
------------

* **Meson + Ninja** — fast, parallel, dependency-detecting build replacing the
  legacy autoconf/automake system.

* **Self-contained TLS** — opssl (custom TLS 1.2/1.3 library) is bundled as a
  Meson subproject. No external SSL library required.

* **C23 codebase** — gnu23 standard with ``_Generic``, ``constexpr``, and
  variable-at-first-use declarations throughout.

Copyright (C) 1997 Robey Pointer

Copyright (C) 2000 - 2025 Eggheads Development Team
