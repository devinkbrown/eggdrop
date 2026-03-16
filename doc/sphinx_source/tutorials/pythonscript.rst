================================
Writing an Eggdrop Python Script
================================

This guide walks through writing a Python script for Eggdrop.  It assumes you
have already installed and configured Eggdrop and have the Python module loaded
(``loadmodule python`` in your config file).

------
Basics
------

Python scripts access Eggdrop through the built-in ``eggdrop`` module.  The
higher-level ``eggtools`` library (``scripts/eggtools.py``) provides convenient
wrappers and decorator-style bind registration.

A minimal script that greets users as they join::

  import eggtools

  @eggtools.on_join()
  def greet(nick, host, handle, channel):
      eggtools.privmsg(channel, f"Hello {nick}, welcome to {channel}!")

Save it as e.g. ``scripts/greet.py`` and add ``pysource scripts/greet.py`` to
your config file.

------------------
Using bind directly
------------------

If you need fine-grained control you can call ``eggdrop.bind`` directly::

  import eggdrop

  def greet(nick, host, handle, channel, **kw):
      eggdrop.putserv(f"PRIVMSG {channel} :Hello {nick}!")

  b = eggdrop.bind("join", "*", "*", greet)

``bind`` returns a ``PythonBind`` object.  Call ``b.unbind()`` to remove the bind.

-------------------------------
Handling re-source / rehash
-------------------------------

If the script is re-sourced (e.g. after ``.rehash``) existing binds must be
removed before new ones are registered, otherwise they accumulate::

  import eggtools

  if 'MY_BINDS' in globals():
    for b in MY_BINDS:
      b.unbind()
    del MY_BINDS

  MY_BINDS = []

  @eggtools.on_pub("*", "!hello")
  def cmd_hello(nick, host, handle, channel, text):
      eggtools.privmsg(channel, f"Hi, {nick}!")
      MY_BINDS.append(eggdrop.bind.__self__)  # track if using low-level bind

The ``eggtools`` decorator factories already return the ``PythonBind`` object;
collect them from the decorated function's ``__bind__`` attribute when needed.

-----------------
Sending IRC lines
-----------------

Use the ``putserv`` / ``putquick`` / ``putnow`` functions for raw IRC lines::

  eggdrop.putserv("PRIVMSG #chan :Hello world!")
  eggdrop.putquick("PONG :server")

Or use the helpers in ``eggtools``::

  eggtools.privmsg("#chan", "Hello world!")
  eggtools.notice("nick", "This is a notice")
  eggtools.action("#chan", "waves")

------------------
Timers (scheduled)
------------------

``eggtools`` provides a pure-Python timer system::

  import eggtools

  def announce():
      eggtools.privmsg("#chan", "Announcement!")

  # fire once after 10 minutes
  tid = eggtools.timer(announce, 10)

  # fire once after 30 seconds (±60 s granularity)
  utid = eggtools.utimer(announce, 30)

  # repeating every 60 seconds
  rtid = eggtools.reptimer(announce, 60)

  # cancel
  eggtools.killtimer(tid)

  # list pending timers
  print(eggtools.timers())

-------------------
User database access
-------------------

::

  # Check flags
  flags = eggdrop.chattr("SomeHandle")      # returns flag string
  eggdrop.chattr("SomeHandle", "+o")        # grant global op flag

  # User info fields
  eggdrop.setinfo("SomeHandle", "A friendly bot user")
  info = eggdrop.getinfo("SomeHandle")

  # Host list
  hosts = eggdrop.gethosts("SomeHandle")

-------------------
Channel information
-------------------

::

  # List channel members
  for m in eggdrop.chanlist("#chan"):
      print(m['nick'], m['userhost'], m['flags'])

  # Channel settings
  settings = eggdrop.chanset("#chan")
  print(settings['bitch'], settings['flood_pub_thr'])

  # Bans / exempts / invites
  for ban in eggdrop.chanbans("#chan"):
      print(ban['mask'], ban['who'])

-------------------------------
IRCv3 / Ophion extended events
-------------------------------

Use ``@eggtools.on_rawt`` to receive server messages with their IRCv3 tag dict,
or ``@eggtools.on_monitor`` for MONITOR presence notifications::

  @eggtools.on_rawt(mask="PRIVMSG")
  def tagged_privmsg(from_mask, keyword, text, tags):
      msgid = tags.get("msgid", "")
      print(f"[{msgid}] {from_mask}: {text}")

  @eggtools.on_monitor()
  def monitor_event(nick, status):
      # status is "online" or "offline"
      print(f"{nick} is now {status}")

  # Add/remove nicks from MONITOR
  eggtools.monitor_add("friend1", "friend2")
  eggtools.monitor_del("friend1")

-------------------------------------------
Twitch support (requires twitch module)
-------------------------------------------

::

  # Who are the mods?
  mods = eggtools.twitchmods("#channelname")
  print(mods)   # "mod1 mod2 mod3"

  # Is this nick a moderator?
  if eggtools.ismod("somenick", "#channelname"):
      eggtools.privmsg("#channelname", "Hello, mod!")

  # Is this nick a VIP?
  if eggtools.isvip("somenick"):
      eggtools.privmsg("#channelname", "Hello, VIP!")

---------
Debugging
---------

From the partyline you can run Python expressions directly::

  .python eggdrop.botname()
  .python eggdrop.chanlist("#chan")
  .python eggtools.timers()

Use ``eggdrop.putlog(msg)`` to write to the bot's log file.


Copyright (C) 2003 - 2025 Eggheads Development Team
