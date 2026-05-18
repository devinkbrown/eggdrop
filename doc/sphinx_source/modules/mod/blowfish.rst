Last revised: May 2026

.. _blowfish:

===============
Blowfish Module
===============

  Eggdrop can encrypt your userfile, so users can have secure passwords.
  Please note that when you change your encryption method later (i.e. using
  other modules like a md5 module), you can't use your current userfile
  anymore. Eggdrop will not start without an encryption module.

  This module requires: none

  **Configuration** — add to your ``eggdrop.toml``::

  [modules]
  load = [
    ...
    "blowfish",
  ]


  Copyright (C) 2000 - 2025 Eggheads Development Team
