Last revised: May 2026

.. _webui:

============
WebUI Module
============

The webui module provides a browser-based administration dashboard and REST API
for managing your Eggdrop bot without connecting via DCC or telnet.

This module requires: TLS (opssl)

Configuration
-------------

Add to your ``eggdrop.toml``::

  [modules]
  load = [
    ...
    "webui",
  ]

  [webui]
  port     = 8080         # HTTPS port to listen on (default 8080)
  password = "secret"     # Bearer token password for the dashboard

The webui module only accepts HTTPS connections. HTTP clients receive a TLS
alert and are disconnected. The bot must have TLS certificates configured.

**Generating certificates** (if you haven't already)::

  ./scripts/genssl.sh

This creates ``eggdrop.crt`` and ``eggdrop.key`` in your bot directory.

Features
--------

**Dashboard**
  A single-page web application accessible at ``https://<bot-host>:<port>/``.
  Displays real-time log output, bot status, connected users, and active channels.

**REST API**
  JSON API endpoints under ``/api/``:

  - ``GET /api/status`` — bot version, uptime, channel count, user count
  - ``GET /api/logs`` — last 200 log lines (ring buffer)
  - ``GET /api/channels`` — list of joined channels with member counts
  - ``GET /api/users`` — user list with flags
  - ``POST /api/command`` — send a partyline command (owner only)

**WebSocket push**
  Connecting to ``wss://<bot-host>:<port>/ws`` receives real-time log lines and
  status updates as they happen. Up to 8 simultaneous WebSocket connections are
  supported.

Authentication
--------------

All requests require a bearer token matching the configured ``password``:

- **HTTP header**: ``Authorization: Bearer <password>``
- **Query parameter**: ``?token=<password>`` (for browser links)

The dashboard login page handles authentication automatically.

Security Notes
--------------

- Always use a strong, unique password in the ``[webui]`` section.
- The dashboard is served over HTTPS only; plain HTTP is rejected.
- The port should be firewalled to trusted IP ranges when possible.
- The ``POST /api/command`` endpoint executes partyline commands — restrict access accordingly.

Partyline Commands
------------------

::

  .webui status      Display webui listen port and connection count
  .webui reload      Reload the dashboard HTML from disk (dev mode)

Example Configuration
---------------------

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
    "webui",
  ]

  [webui]
  port     = 8443
  password = "change-me-to-something-strong"

After starting the bot, open ``https://localhost:8443/`` in your browser.

Copyright (C) 1999 - 2025 Eggheads Development Team
