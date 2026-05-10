Eggdrop, an open source IRC bot
===============================

Eggdrop is a free, open source IRC bot that has been actively maintained since 1993. It was designed to be easily used and expanded via Tcl and Python scripting. Eggdrop can join IRC channels and perform automated tasks such as protecting the channel from abuse, managing user access, providing information and greetings, hosting games, and much more.

Features
--------

Eggdrop includes a comprehensive set of features:

* `Channel Management <using/users.html>`_ — op/voice/ban/kick automation
* `Tcl and Python Scripting <tutorials/firstscript.html>`_ — extend functionality with custom scripts
* `IRCv3 Support <using/ircv3.html>`_ — integration with modern IRC capabilities
* `Botnets <using/botnet.html>`_ — link multiple Eggdrops and share userfiles
* `TLS/SSL Support <using/tls.html>`_ — secure connections to IRC networks and botnets
* `IPv6 Support <using/ipv6.html>`_ — full IPv6 connectivity
* `Twitch Gaming <using/twitchinfo.html>`_ — specialized Twitch IRC support
* `LMDB or Flat-File Storage <using/users.html>`_ — persistent user databases
* `SASL Authentication <using/accounts.html>`_ — secure account authentication
* `Module System <modules/included.html>`_ — loadable feature modules

Obtaining Eggdrop
-----------------

The Eggdrop source code is available at https://github.com/eggheads/eggdrop. Clone via git or download a snapshot from https://geteggdrop.com. Official information is at https://www.eggheads.org.

Quick Start
-----------

Prerequisites
^^^^^^^^^^^^^

Eggdrop requires:

* **Tcl Development Library** (8.5.0 or higher) — the Tcl interpreter and headers
* **Meson and Ninja** — the build system
* **Python 3.8+** (optional) — if using the Python module

**TLS Support**: Eggdrop includes opssl, a custom bundled TLS library. No external library installation needed.

Installation
^^^^^^^^^^^^

See `Installing Eggdrop <install/install.html>`_ for detailed installation instructions.

Where to find more help
-----------------------

The Eggheads development team can be found lurking on #eggdrop on the Libera network (irc.libera.chat).

.. toctree::
    :caption: Installing Eggdrop
    :maxdepth: 2

    install/readme
    install/install
    install/upgrading

.. toctree::
    :caption: Using Eggdrop
    :maxdepth: 2

    using/features
    using/core
    using/partyline
    using/autoscripts
    using/users
    using/bans
    using/botnet
    using/ipv6
    using/tls
    using/ircv3
    using/accounts
    using/pbkdf2info
    using/python
    using/twitchinfo
    using/tricks
    using/text-sub
    using/tcl-commands
    using/twitch-tcl-commands
    using/patch

.. toctree::
    :caption: Tutorials
    :maxdepth: 2

    tutorials/setup
    tutorials/firststeps
    tutorials/tlssetup
    tutorials/userfilesharing
    tutorials/firstscript
    tutorials/module

.. toctree::
    :caption: Eggdrop Modules
    :maxdepth: 2

    modules/index
    modules/included
    modules/writing
    modules/internals.rst

.. toctree::
    :caption: About Eggdrop
    :maxdepth: 2

    about/about
    about/legal
