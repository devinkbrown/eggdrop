Last revised: 2025

.. _twitch:

=============
Twitch Module
=============

This module provides connectivity with the Twitch gaming platform via its IRC
gateway.  Because Twitch's IRC gateway is a non-standard overlay (not RFC
compliant), many traditional Eggdrop features are unavailable.  The module
focuses on:

* Logging general and Twitch-specific events (raids, bits, host, etc.)
* Tracking userstate and roomstate values per channel
* Providing bind types for Twitch-specific IRC events
* Exposing moderator and VIP lists to scripts

This module requires: ``server.mod``

Put this line into your Eggdrop configuration file to load the twitch module::

  loadmodule twitch

and set ``net-type "Twitch"`` in your config file.

-----------
Limitations
-----------

* Twitch does not broadcast JOINs or PARTs for channels over 1,000 users,
  making user tracking unreliable.
* Twitch does not broadcast MODE changes for moderator status; use the
  ``twitchmods`` / ``ismod`` commands described below instead.
* Twitch stores bans on its own servers and does not accept ``MODE +b``.
* Twitch does not allow clients to issue ``MODE +o/-o`` commands.

------------------
Partyline commands
------------------

* ``userstate`` — list current userstate for a channel
* ``roomstate`` — list current roomstate for a channel
* ``twcmd`` — issue a Twitch web-interface command (``/ban``, ``/host``, etc.)

-------
Tcl API
-------

This module adds bind types for the following Twitch events (when Tcl is
enabled):

* ``ccht`` — CLEARCHAT
* ``cmsg`` — CLEARMSG
* ``htgt`` — HOSTTARGET
* ``wspr`` — WHISPER (incoming)
* ``wspm`` — WHISPER (outgoing)
* ``rmst`` — ROOMSTATE
* ``usst`` — USERSTATE
* ``usrntc`` — USERNOTICE

Additional Tcl commands (Tcl builds only): ``twcmd``, ``userstate``,
``roomstate``, ``twitchmods``, ``twitchvips``, ``ismod``, ``isvip``.

----------
Python API
----------

When the python module is also loaded, the following functions are available
via the built-in ``eggdrop`` module (or through ``eggtools`` wrappers):

``eggdrop.twitchmods(channel)``
  Return a space-separated string of moderator nicks for *channel*.
  Raises ``EggdropError`` if the channel is not found.

``eggdrop.twitchvips(channel)``
  Return a space-separated string of VIP nicks for *channel*.
  Raises ``EggdropError`` if the channel is not found.

``eggdrop.ismod(nick[, channel])``
  Return ``True`` if *nick* is a moderator.  If *channel* is omitted all
  Twitch channels are searched.  Raises ``EggdropError`` if *channel* is given
  but not found.

``eggdrop.isvip(nick[, channel])``
  Return ``True`` if *nick* is a VIP.  Same channel semantics as ``ismod``.

``eggtools`` wrappers (from ``scripts/eggtools.py``)::

  import eggtools

  mods = eggtools.twitchmods("#channel")
  vips = eggtools.twitchvips("#channel")

  if eggtools.ismod("somenick", "#channel"):
      eggtools.privmsg("#channel", "Hi mod!")

  if eggtools.isvip("somenick"):
      eggtools.privmsg("#channel", "Hi VIP!")

Copyright (C) 2020 - 2025 Eggheads Development Team
