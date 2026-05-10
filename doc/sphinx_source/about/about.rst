About Eggdrop
=============

History
-------

Eggdrop was created in December 1993 to stop channel wars on #gayteen. It evolved from an earlier project called "Unrest" that was designed to answer help requests. The first public release was version 0.6, and it has grown to become the world's most popular IRC bot.

Today, Eggdrop remains actively maintained and continues to add modern features while preserving backward compatibility with older configurations and scripts.

What is Eggdrop?
----------------

Eggdrop is a free, open-source IRC bot released under the GNU General Public License v2. It is feature-rich and designed to be easily used and extended by IRC users of all skill levels.

An IRC bot is a program that:

- Sits on IRC channels as a normal user
- Performs automated tasks
- Responds to commands
- Protects channels from abuse

Common Eggdrop Functions
^^^^^^^^^^^^^^^^^^^^^^^^

- **Channel Protection** — Ban spammers and abusers, manage op/voice status
- **User Management** — Maintain access lists, flags, and permissions
- **Automated Tasks** — Greet users, log events, provide information
- **Channel Linking** — Form botnets to manage multiple channels across networks
- **Scripting** — Extend functionality with Tcl and Python scripts
- **Games and Fun** — Host games, fun commands, entertainment

What Makes Eggdrop Stand Out
-----------------------------

1. **Extensibility**
   - Tcl scripting for ease of customization
   - Python scripting for advanced users
   - Module system for C-based extensions
   - Large community with ready-made scripts

2. **Flexibility**
   - Botnets allow multiple bots to work together
   - Userfile sharing across bots
   - Per-channel settings and customization
   - Works on any Unix-like system

3. **Stability and Compatibility**
   - 30+ years of active development
   - Production-ready for mission-critical channels
   - Scripts from 1.6 still work in 1.10
   - Smooth migration path between versions

4. **Modern Features**
   - TLS 1.2 and 1.3 support (opssl)
   - IRCv3 capabilities
   - SASL authentication
   - IPv6 support
   - Python 3.8+ integration

5. **Community**
   - Active development team
   - Responsive to feature requests
   - Helpful community on #eggdrop (Libera.Chat)
   - Extensive documentation

System Requirements
-------------------

To run Eggdrop, you need:

**Essential**:

- Unix-like operating system (Linux, BSD, macOS, etc.)
- Tcl 8.5.0 or newer (with development headers)
- 5-10 MB of disk space (much less than historical versions)
- Basic knowledge of Unix and IRC

**Recommended**:

- Modern Linux distribution (Ubuntu, Debian, Fedora, etc.)
- 50-100 MB disk space for databases, logs, and scripts
- TLS certificates for secure connections
- Python 3.8+ if using Python scripts

**Optional**:

- zlib for compression support
- Python 3.8+ for Python scripting
- A dedicated shell account or VPS

Platform Support
----------------

Eggdrop officially supports:

- **Linux** (primary platform, all distributions)
- **macOS** (Intel and Apple Silicon)
- **BSD** (FreeBSD, OpenBSD, NetBSD)
- **Cygwin** (Windows via Cygwin layer)
- **Docker** (official Docker image available)

Licensing
---------

Eggdrop is released under the **GNU General Public License v2 (GPL v2)**.

This means:

- **Free to use** — No licensing fees
- **Free to modify** — Change the source code
- **Free to distribute** — Share with others
- **Required to share changes** — If you distribute modified versions, you must provide source

For the complete license, see the LICENSE file in the source distribution.

Getting Started
---------------

**Minimum Setup** (5 minutes):

1. Install Tcl and Meson
2. Download and build Eggdrop
3. Run ``./eggdrop --setup mybot.toml`` (interactive wizard)
4. Start the bot: ``./eggdrop mybot.toml``
5. Introduce yourself: ``/msg mybot hello``

**Full Setup** (30-60 minutes):

1. Review the documentation (this site)
2. Configure your bot's settings
3. Add Tcl scripts
4. Set up channels and user permissions
5. Test and deploy

Version History
---------------

**Current Series (1.10.x)**: Feature-complete production release with modern architecture

- **1.10.1** (May 2026) — Latest stable
- **1.10.0** (April 2026) — Major release with feature completion

**Previous Series**:

- **1.9.x** — SASL, IRCv3, Meson build system
- **1.8.x** — TLS support, IPv6 support
- **1.6.21** — Legacy version, no longer maintained

**EOL Versions**: 1.6 and earlier are end-of-life and not supported.

Eggdrop Community
-----------------

**Official Channels**:

- **#eggdrop** on Libera.Chat — Official support channel
- **#eggheads** on Libera.Chat — Development discussion
- **GitHub** — https://github.com/eggheads/eggdrop (issues, PRs, discussions)
- **Website** — https://www.eggheads.org

**Help**:

When asking for help:

- Read the documentation first
- Check GitHub issues for similar problems
- Provide error messages and relevant config details
- Follow IRC etiquette (no CAPS, no spam, no excessive messages)

Contributing
------------

Eggheads welcomes contributions:

- **Bug reports** — GitHub Issues
- **Feature requests** — GitHub Discussions
- **Code contributions** — GitHub Pull Requests
- **Documentation improvements** — GitHub PRs to doc/sphinx_source/
- **Scripts and modules** — Share on forums or GitHub

See the CONTRIBUTING file in the source distribution for guidelines.

Credits
-------

Eggdrop was created by **Robey Pointer** in 1993 and is now maintained by the **Eggheads Development Team**.

Original concept and design: Robey Pointer

Current active maintainers and contributors: See the source repository and git history at https://github.com/eggheads/eggdrop

Thousands of users and script authors have contributed to Eggdrop's success over three decades.

Next Steps
----------

- `Installation Guide <../install/install.html>`_ — Get Eggdrop running
- `First Steps <../tutorials/firststeps.html>`_ — Basic commands and setup
- `Core Settings <../using/core.html>`_ — Configuration reference
- `IRC Bot Concepts <../tutorials/setup.html>`_ — Understand IRC botting

Copyright (C) 1997 Robey Pointer
Copyright (C) 1999 - 2025 Eggheads Development Team
