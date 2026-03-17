=======================
Using the Python Module
=======================

Eggdrop includes a Python module that allows scripts written in Python 3 to run
inside the bot alongside (or instead of) Tcl scripts.  The Python interpreter is
embedded directly — no external process is spawned.

-------------------
System Requirements
-------------------

Python 3.8 or newer is required, including the development headers.  On
Debian/Ubuntu systems install::

  sudo apt-get install python3 python3-dev python3-is-python3

The ``python3-is-python3`` package updates the ``python3`` symlink so the
build system can locate the interpreter automatically.

The Global Interpreter Lock (GIL) is required and must not be disabled even on
Python 3.13+ free-threaded builds.

--------------
Loading Python
--------------

Add the following line to your Eggdrop configuration file::

  loadmodule python

To load a Python script place the ``.py`` file in the ``scripts/`` folder and
add::

  pysource scripts/myscript.py

If you need to install third-party packages we recommend Python virtual
environments.  See https://docs.python.org/3/library/venv.html for details.

Create a virtual environment once::

  cd eggdrop && python3 -m venv .venv

Install a package into it (example: the ``requests`` library)::

  cd eggdrop && source .venv/bin/activate && pip install requests

Start Eggdrop with the activated venv (required each session)::

  cd eggdrop && source .venv/bin/activate && ./eggdrop

------------------------
Reloading Python Scripts
------------------------

Unlike Tcl, Python scripts cannot be fully reloaded by ``.rehash`` because the
Python interpreter does not cleanly unload modules.  You should restart the bot
when scripts change.

Scripts that register binds should clean up existing binds before registering
new ones so that a ``.rehash`` does not create duplicates::

  if 'MY_BINDS' in globals():
    for b in MY_BINDS:
      b.unbind()
    del MY_BINDS

  MY_BINDS = []
  MY_BINDS.append(eggdrop.bind("join", "*", "*", my_handler))

------------------------
Multithreading and async
------------------------

``pysource`` loads scripts in the main Eggdrop thread.  Scripts may freely use
``asyncio`` and Python threads, but all calls into the ``eggdrop`` C module must
be made from the main thread (the GIL handles serialisation).

-----------------------
Eggdrop Python Commands
-----------------------

Python scripts access Eggdrop functionality through the built-in ``eggdrop``
module, which exposes a native Python API.  Import it as::

  import eggdrop

or import individual functions::

  from eggdrop import bind, putserv, putlog, chanlist

All functions are documented below grouped by category.  A high-level wrapper
library ``eggtools.py`` is shipped in the ``scripts/`` folder and provides
Pythonic helpers, type hints, and convenience wrappers around every function in
this section.

^^^^^^^^^^^^^^^
Bind management
^^^^^^^^^^^^^^^

``bind(type, flags, mask, callback)``
  Register *callback* (a Python callable) as a bind of *type* triggered by
  *mask* for users matching *flags*.  Returns a ``PythonBind`` object with an
  ``unbind()`` method.  Example::

    def greet(nick, host, handle, channel, **kw):
        eggdrop.putserv(f"PRIVMSG {channel} :Hello {nick}!")

    b = eggdrop.bind("join", "*", "*", greet)
    # later: b.unbind()

^^^^^^^^^^^^^^^^^^^^^^^^^
Server / network commands
^^^^^^^^^^^^^^^^^^^^^^^^^

``putserv(text)``
  Queue a raw IRC line using the normal (low-priority) server queue.

``putquick(text)``
  Queue a raw IRC line using the high-priority (quick) queue.

``putnow(text)``
  Send a raw IRC line to the server immediately, bypassing all queues.

``puthelp(text)``
  Queue a raw IRC line on the help/notice queue.

``tagmsg(tag, target)``
  Send an IRCv3 TAGMSG with *tag* to *target*.

``cap(subcmd, cap)``
  Send an IRCv3 CAP command.  ``subcmd`` is ``'req'`` (request a capability)
  or ``'raw'`` (send a raw CAP line with *cap* as the rest of the string).

``botname()``
  Return the bot's current IRC nickname as a string.

^^^^^^^^^^^^^^^^^^
Channel operations
^^^^^^^^^^^^^^^^^^

``isonchan(nick, channel)``
  Return ``True`` if *nick* is currently on *channel*.

``getchanhost(nick, channel)``
  Return the ``user@host`` string of *nick* on *channel*, or ``None``.

``chanlist(channel[, flags])``
  Return a list of member dicts for *channel*.  Each dict has keys
  ``nick``, ``userhost``, ``account``, ``joined``, ``flags``, ``last``.
  If *flags* is given only members matching those flags are returned.

``channels()``
  Return a list of channel names the bot is currently on.

``isop(nick, channel)``
  Return ``True`` if *nick* has op (+o) on *channel*.

``ishalfop(nick, channel)``
  Return ``True`` if *nick* has half-op (+h) on *channel*.

``isvoice(nick, channel)``
  Return ``True`` if *nick* has voice (+v) on *channel*.

``isaway(nick, channel)``
  Return ``True`` if *nick* is marked away on *channel*.

``botisop(channel)``
  Return ``True`` if the bot has op on *channel*.

``botishalfop(channel)``
  Return ``True`` if the bot has half-op on *channel*.

``botisvoice(channel)``
  Return ``True`` if the bot has voice on *channel*.

``botonchan([channel])``
  Return ``True`` if the bot is on *channel*, or on any channel if omitted.

``getaccount(nick, channel)``
  Return the IRCv3 account name of *nick* on *channel*, or ``None``.

``isidentified(nick, channel)``
  Return ``True`` if *nick* is logged in to IRC services.

``wasop(nick, channel)``
  Return ``True`` if *nick* was an op before the most recent netsplit.

``washalfop(nick, channel)``
  Return ``True`` if *nick* was a half-op before the most recent netsplit.

``isircbot(nick[, channel])``
  Return ``True`` if *nick* is marked as a bot (IRCv3/005 ISBOT).

``isbotnick(nick)``
  Return ``True`` if *nick* matches the bot's own nickname.

``getchanidle(nick, channel)``
  Return the number of minutes *nick* has been idle on *channel*, or ``-1``.

``getchan_topic(channel)``
  Return the current topic string for *channel*, or ``None``.

``chanbans(channel)``
  Return a list of ban dicts for *channel*.  Each dict has keys
  ``mask``, ``who``, ``time``.

``chanexempts(channel)``
  Return a list of exempt dicts for *channel* (same format as bans).

``chaninvites(channel)``
  Return a list of invite dicts for *channel* (same format as bans).

``chanset(channel)``
  Return a dict of channel configuration settings including flood thresholds,
  mask expiry times, auto-op range, status booleans, and raw mode bitmask.

``account2nicks(account[, channel])``
  Return a list of nicks that are authenticated with the given IRC *account*.

``hand2nicks(handle[, channel])``
  Return a list of nicks currently on IRC for the given eggdrop *handle*.

^^^^^^^^^^^^^^^^^^^^^
Handle / nick lookups
^^^^^^^^^^^^^^^^^^^^^

``nick2hand(nick, channel)``
  Return the eggdrop handle for *nick* on *channel*, or ``None``.

``hand2nick(handle, channel)``
  Return the current nick of *handle* on *channel*, or ``None``.

^^^^^^^^^^^^^^^^^
User database
^^^^^^^^^^^^^^^^^

``countusers()``
  Return the total number of users in the userlist.

``validuser(handle)``
  Return ``True`` if *handle* exists in the userlist.

``finduser(mask)``
  Return the handle matching ``nick!user@host`` *mask*, or ``None``.

``userlist()``
  Return a list of all user handles.

``adduser(handle[, hostmask])``
  Add a new user.  Returns ``True`` on success.

``deluser(handle)``
  Remove a user.  Returns ``True`` on success.

``addhost(handle, mask)``
  Add a hostmask to a user's record.

``delhost(handle, mask)``
  Remove a hostmask from a user's record.

``chattr(handle[, changes[, channel]])``
  Get or modify user flags.  Pass *changes* (e.g. ``'+o-v'``) to modify.
  Returns the current flag string.

``matchattr(handle, flags[, channel])``
  Return ``True`` if *handle* has all flags in *flags*.

``passwdok(handle, password)``
  Return ``True`` if *password* matches the stored hash for *handle*.

``chhandle(oldhandle, newhandle)``
  Rename a user.  Returns ``True`` on success.

``save()``
  Write the userlist to disk immediately.

^^^^^^^^^^^^^^^^^^^^^^^^^^
User entry fields
^^^^^^^^^^^^^^^^^^^^^^^^^^

``getinfo(handle)``
  Return the INFO line for *handle*, or ``None``.

``setinfo(handle, info)``
  Set the INFO line for *handle*.  Pass ``""`` to clear it.

``getcomment(handle)``
  Return the COMMENT field for *handle*, or ``None``.

``setcomment(handle, comment)``
  Set the COMMENT field for *handle*.  Pass ``""`` to clear it.

``gethosts(handle)``
  Return a list of hostmask strings recorded for *handle*.

``getaccount_str(handle)``
  Return the IRC account name stored in the user database for *handle*, or
  ``None``.

^^^^^^^^^^^^^
Ignore list
^^^^^^^^^^^^^

``isignore(mask)``
  Return ``True`` if *mask* matches an active ignore entry.

``newignore(mask, creator, comment[, lifetime])``
  Add an ignore entry.  *lifetime* is in minutes (0 = permanent).

``killignore(mask)``
  Remove an ignore entry.  Returns ``True`` if found.

``ignorelist()``
  Return a list of ignore dicts (keys: ``mask``, ``who``, ``comment``,
  ``expire``, ``time``).

^^^^^^^^^^
DCC
^^^^^^^^^^

``hand2idx(handle)``
  Return the socket number for *handle*'s active DCC chat, or ``-1``.

``idx2hand(sock)``
  Return the nick for DCC socket *sock*, or ``None``.

``killdcc(sock[, reason])``
  Disconnect a DCC connection.

``dcclist([type])``
  Return a list of DCC connection dicts.  If *type* is given (``'chat'``,
  ``'bot'``, ``'simul'``) only connections of that type are returned.

``dccused()``
  Return the number of currently active DCC connections.

``putdcc(sock, text)``
  Send *text* to a DCC party by socket number.

^^^^^^^^^^^^^^^^^^^
Bot networking
^^^^^^^^^^^^^^^^^^^

``putbot(botnick, msg)``
  Send a zapf message to the directly linked bot *botnick*.

``putallbots(msg)``
  Broadcast a zapf message to all linked bots.

``islinked(botnick)``
  Return ``True`` if *botnick* is currently linked.

``bots()``
  Return a list of all linked bot names.

^^^^^^^^^^^^^^^^^^
Bot management
^^^^^^^^^^^^^^^^^^

``die([reason])``
  Shut down the bot with an optional reason string.

``restart()``
  Write the userfile and restart the bot process.

``rehash()``
  Write the userfile and reload the configuration file without restarting.

^^^^^^^^^^^^^^^^^^^^^^^^^
Text / string utilities
^^^^^^^^^^^^^^^^^^^^^^^^^

``stripcodes(flags, text)``
  Strip IRC formatting codes from *text*.  *flags* is a string of characters
  selecting what to strip: ``c`` color, ``b`` bold, ``r`` reverse,
  ``u`` underline, ``a`` ANSI, ``g`` bells, ``i`` italics, ``*`` all.

``matchstr(pattern, string)``
  Return ``True`` if *string* matches IRC glob *pattern* (``?`` and ``*``).

``maskhost(nick, userhost)``
  Create an IRC hostmask from *nick* and ``user@host`` string.

``rand(n)``
  Return a random integer in ``[0, n)``.

``unixtime()``
  Return the current Unix timestamp as an integer.

``duration(seconds)``
  Convert *seconds* to a human-readable string (e.g. ``"2 days, 3 hours"``).

``putlog(text[, loglevel[, channel]])``
  Write *text* to the eggdrop log.  Default loglevel is ``LOG_MISC``.

^^^^^^^^^^^^^^^^^^^
DNS configuration
^^^^^^^^^^^^^^^^^^^

*(Tcl builds only — requires the* ``dns`` *module and TLS support.)*

``dnsdot([action[, server[, port[, "-noverify"]]]])``
  Query or configure DNS-over-TLS (DoT, RFC 7858).

  Called with no arguments, returns the current DoT status as a string:
  ``"off"``, ``"on 1.1.1.1:853"``, or ``"connecting 1.1.1.1:853"``.

  Called with ``"on"`` and a numeric IP *server*, enables DoT on port 853
  (or the optional *port*).  Pass ``"-noverify"`` as the final argument to
  skip certificate verification (private resolvers only).

  Called with ``"off"``, reverts to plain UDP DNS.

  Raises ``eggdrop.error`` on invalid arguments or when TLS is unavailable.

  Examples::

    eggdrop.dnsdot()                            # → "off" / "on 1.1.1.1:853"
    eggdrop.dnsdot("on", "1.1.1.1")            # Cloudflare, default port 853
    eggdrop.dnsdot("on", "9.9.9.9")            # Quad9
    eggdrop.dnsdot("on", "1.1.1.1", 853)       # explicit port
    eggdrop.dnsdot("on", "::1", 853, "-noverify")  # private resolver
    eggdrop.dnsdot("off")                       # revert to plain UDP

^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
IRCX / Ophion / IRCv3 extended commands
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``ircxprop(target, prop[, value])``
  Get or set an IRCX property (sends a ``PROP`` command).

``ircxaccess(channel, list|add|del[, level][, mask])``
  Manage an IRCX channel access list.

``ircxcreate(channel[, modes])``
  Create an IRCX channel.

``ircxnegotiate()``
  Send the IRCX negotiate command to enable IRCX mode on the current server.

--------------------
eggtools.py wrappers
--------------------

The file ``scripts/eggtools.py`` ships with Eggdrop and provides high-level,
Pythonic wrappers around every ``eggdrop`` module function listed above.  It
adds:

* Full type annotations
* ``@on_pub``, ``@on_join``, ``@on_msg``, ``@on_rawt``, ``@on_monitor`` and
  many other decorator factories for registering binds
* ``privmsg()``, ``notice()``, ``action()`` helpers
* ``ctcp()``, ``ctcreply()`` helpers
* ``op()``, ``deop()``, ``voice()``, ``devoice()``, ``kick()``, ``ban()``
  channel management helpers
* ``timer()``, ``utimer()``, ``reptimer()``, ``killtimer()`` — a pure-Python
  timer system with 1-minute granularity
* ``monitor_add()``, ``monitor_del()``, ``monitor_list()`` — MONITOR helpers
* Twitch wrappers: ``twitchmods()``, ``twitchvips()``, ``ismod()``, ``isvip()``
* String utilities compatible with ``alltools.tcl`` names

Example using ``eggtools``::

  import eggtools

  @eggtools.on_pub("*", "!hello")
  def cmd_hello(nick, host, handle, channel, text):
      eggtools.privmsg(channel, f"Hello, {nick}!")

  @eggtools.on_join()
  def on_join(nick, host, handle, channel):
      eggtools.privmsg(channel, f"Welcome, {nick}!")

  # Schedule a one-shot reminder in 5 minutes
  eggtools.timer(lambda: eggtools.privmsg("#mychan", "5 minutes are up!"), 5)

--------------------------------
Writing an Eggdrop Python script
--------------------------------

For a step-by-step tutorial see :doc:`/tutorials/pythonscript`.

.. _bind_types:

For a full description of bind types and their callback signatures see the
eggdrop TCL commands reference at :doc:`/using/tcl-commands` (the bind types
and signatures are identical for Python).


Copyright (C) 2000 - 2025 Eggheads Development Team
