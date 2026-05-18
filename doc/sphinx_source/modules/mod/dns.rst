Last revised: May 2026

.. _dns:

==========
DNS Module
==========

This module provides asynchronous dns support. This will avoid long periods
where the bot just hangs there, waiting for a hostname to resolve, which will
often let it timeout on all other connections.

This module requires: none

**Configuration** — add to your ``eggdrop.toml``::

  [modules]
  load = [
    ...
    "dns",
  ]


There are also some variables you can set in your config file:

  set dns-servers "8.8.8.8 8.8.4.4"
    In case your bot has trouble finding dns servers or you want to use
    specific ones, you can set them here. The value is a list of dns servers.
    The relative order doesn't matter. You can also specify a non-standard
    port.
    The default is to use the system specified dns servers. You don't need to
    modify this normally.

  set dns-cache 86400
    Specify how long should the DNS module cache replies at maximum. The
    value must be in seconds.
    Note that it will respect the TTL of the reply and this is just an upper
    boundary.

  set dns-negcache 600
    Specify how long should the DNS module cache negative replies (NXDOMAIN,
    DNS Lookup failed). The value must be in seconds.

  set dns-maxsends 4
    How many times should the DNS module resend the query for a given domain
    if it receives no reply?

  set dns-retrydelay 3
    Specify how long should the DNS module wait for a reply before resending
    the query. The value must be in seconds.

-----------------------
DNS-over-TLS (DoT)
-----------------------

When Eggdrop is built with TLS support (``-Dtls=enabled``), all DNS queries
can be sent over an encrypted TLS/TCP connection to a DoT resolver (RFC 7858)
instead of plain UDP.

Configuration in the Tcl config or ``[tcl]`` commands block::

  dnsdot on 1.1.1.1          # Cloudflare — fast, privacy-respecting (default port 853)
  dnsdot on 9.9.9.9          # Quad9 — malware-blocking, privacy-focused
  dnsdot on 1.1.1.1 853      # explicit port
  dnsdot on ::1 853 -noverify  # allow self-signed certificate
  dnsdot off                 # revert to plain UDP
  dnsdot                     # query current status

The ``dnsdot`` command is also available to Python scripts (Tcl builds) via
``eggdrop.dnsdot(...)`` — see :doc:`/using/python`.

DoT connections are persistent and automatically reconnected on disconnect.
The connection is made immediately when ``dnsdot on`` is called; queries issued
before the TLS handshake completes are queued and replayed over DoT once the
connection is established.

If TLS is not compiled in, ``dnsdot`` returns an error string rather than
raising an exception.


Copyright (C) 2000 - 2025 Eggheads Development Team
