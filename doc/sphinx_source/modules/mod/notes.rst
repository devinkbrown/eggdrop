Last revised: May 2026

.. _notes:

============
Notes Module
============

The notes module stores offline messages between users. When a user is not
online, other users can leave notes for them. The notes are delivered
automatically when the recipient next logs in (via DCC or partyline).

Real-time note delivery (for users currently online) is handled by the core
and does not require this module.

This module requires: none

Configuration
-------------

Add to your ``eggdrop.toml``::

  [modules]
  load = [
    ...
    "notes",
  ]

  [notes]
  notefile      = "LamestBot.notes"  # File to store notes (default: <botnick>.notes)
  max-notes     = 50                 # Max notes per user (prevent flooding)
  note-life     = 60                 # Days to keep notes before expiring (0 = forever)
  allow-fwd     = 0                  # Allow forwarding to another bot account
  notify-users  = 1                  # Notify hourly if a user has pending notes
  notify-onjoin = 1                  # Notify on partyline join if notes exist

Settings
--------

``notefile``
  Path to the file where notes are stored. Relative to the bot's home directory.
  Defaults to ``<botnick>.notes`` if not specified.

``max-notes``
  Maximum number of notes stored per user. Prevents a single user from being
  flooded with notes. Default: 50.

``note-life``
  Number of days to keep unread notes before automatically expiring them. Set to
  ``0`` to never expire notes. Default: 60.

``allow-fwd``
  If set to ``1``, users can configure a forwarding address to route their notes
  to an account on another bot in the botnet. Default: ``0``.

``notify-users``
  If set to ``1``, the bot notifies users on the partyline hourly if they have
  pending notes. Default: ``1``.

``notify-onjoin``
  If set to ``1``, users are notified immediately when they connect to the
  partyline if they have any unread notes. Default: ``1``.

Partyline Commands
------------------

::

  .notes                  List your notes
  .notes <handle>         List notes for another user (master+)
  .notes erase <nums>     Erase notes by number (e.g. ".notes erase 1 3 5")
  .notes erase all        Erase all your notes
  .notes fwd <bot:handle> Forward incoming notes to another bot's user (requires allow-fwd)
  .notes fwd off          Disable forwarding

IRC Commands (MSG)
------------------

::

  /msg <botnick> note <handle> <message>   Leave a note for a user
  /msg <botnick> notes                     Check your notes

Implementation Notes
--------------------

In Eggdrop 1.10, the notes module uses **asynchronous file I/O**. When notes
are written (on send, expire, or erase), the bot serializes the notes buffer
in memory, then hands it to a background worker thread for atomic disk write
(tmpfile → fsync → rename). The main IRC event loop never blocks on disk.

An in-memory **count cache** tracks how many notes each user has. This cache
is rebuilt from the in-memory buffer immediately after each write, avoiding
stale-read races that would occur by re-reading the file from disk.

Copyright (C) 2000 - 2025 Eggheads Development Team
