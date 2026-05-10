TLS/SSL Support
===============

This document describes TLS (Transport Layer Security) support in Eggdrop, available since version 1.8.0.

Overview
--------

Eggdrop supports TLS encryption via **opssl**, a custom bundled TLS library supporting TLS 1.2 and 1.3. No external library installation is needed.

TLS protects communication for:

- **IRC connections** to TLS-enabled IRC servers
- **Botnet links** between Eggdrops
- **Partyline/DCC** chat connections
- **Scripts** via the starttls command

Building with TLS
-----------------

TLS is enabled by default and built automatically::

  meson setup builddir
  ninja -C builddir

To disable TLS (not recommended)::

  meson setup builddir -Dtls=disabled

If TLS is disabled, you cannot connect to TLS ports or secure botnet links.

Usage Overview
--------------

As of Eggdrop 1.9.0, TLS must be explicitly enabled. Use a ``+`` prefix on port numbers to enable TLS::

  # IRC server with TLS (port 6697)
  irc.example.com:+6697

  # Botnet listener with TLS (port 5556)
  listen +5556 all

  # Connect to bot with TLS (port +5555)
  .+bot HubBot 1.2.3.4 +5555

The ``+`` prefix is **required** to enable TLS. Without it, the connection is plaintext.

**Important**: Prior to 1.9.0, Eggdrop automatically attempted STARTTLS upgrades. This no longer happens—you must explicitly enable TLS.

IRC Server Connections
----------------------

Connecting to a TLS-Protected Server
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To connect to an IRC server on a TLS port, prefix the port with ``+`` in your configuration:

In ``eggdrop.toml``::

  [servers]
  list = [
    "irc.libera.chat:+6697",
    "irc.libera.chat:+6669",
    "irc.efnet.org:+6697",
  ]

At runtime via partyline::

  .jump irc.libera.chat +6697

Eggdrop automatically uses TLS for the connection.

Certificate Authentication (NickServ)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Some IRC networks allow authentication using TLS client certificates instead of passwords.

To use certificate authentication:

1. Configure your certificate in ``eggdrop.toml``::

     [tls]
     privatekey = "eggdrop.key"
     certificate = "eggdrop.crt"

2. The bot automatically presents the certificate when connecting via TLS

3. NickServ recognizes the certificate and authenticates automatically

No additional configuration needed.

Botnet Links (Bot-to-Bot)
-------------------------

Overview
^^^^^^^^

Botnets link multiple Eggdrops together. TLS encryption protects this hub-to-leaf communication.

**Hub bot**: Listens on a TLS port (acts as server)

**Leaf bot**: Connects to the hub (acts as client)

Hub Bot Configuration
^^^^^^^^^^^^^^^^^^^^^

The hub bot must listen on a TLS port and have TLS certificates.

1. Generate certificates::

     cd /path/to/eggdrop
     ./scripts/genssl.sh

   This creates ``eggdrop.crt`` and ``eggdrop.key``.

2. Configure listening in ``eggdrop.toml``::

     [listen]
     ports = [
       "+5556 all"  # TLS on port 5556
     ]

3. Ensure ``eggdrop.crt`` and ``eggdrop.key`` are in the bot's directory

4. Restart the hub bot

Leaf Bot Configuration
^^^^^^^^^^^^^^^^^^^^^^

The leaf bot connects to the hub. Add the hub with a ``+`` port prefix::

  .+bot HubBot 1.2.3.4 +5556

Or in config before starting (if you have access)::

  # In bot configuration under botnet settings
  .+bot HubBot 1.2.3.4 +5556

Verify the connection with::

  .status

Port Matching Rules
^^^^^^^^^^^^^^^^^^^

TLS connections require matching port types:

+---------------------+----------------------+---------------------+
| Leaf Bot Setting    | Hub Listening Port   | Result              |
+=====================+======================+=====================+
| 5555                | 5555                 | Plain connection    |
+---------------------+----------------------+---------------------+
| 5555                | +5556                | **Fails** (mismatch)|
+---------------------+----------------------+---------------------+
| +5556               | +5556                | TLS connection      |
+---------------------+----------------------+---------------------+
| +5556               | 5555                 | **Fails** (mismatch)|
+---------------------+----------------------+---------------------+

**Key rule**: Both sides must use matching TLS settings (either both use ``+`` or neither).

Certificate Generation
----------------------

Generating Self-Signed Certificates
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For botnet use, self-signed certificates are ideal. From your Eggdrop installation directory::

  ./scripts/genssl.sh

The script prompts for certificate details and generates:

- ``eggdrop.crt`` — public certificate
- ``eggdrop.key`` — private key

Valid for 10 years.

Non-Interactive Certificate Generation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For scripted installations::

  ./scripts/genssl.sh -s

Uses pre-configured values without prompts.

CA-Signed Certificates
^^^^^^^^^^^^^^^^^^^^^^

For production systems, use a Certificate Authority-signed certificate:

1. Generate a Certificate Signing Request (CSR) from your self-signed cert
2. Submit to a CA (Let's Encrypt, DigiCert, etc.)
3. Replace ``eggdrop.crt`` with the CA-signed certificate
4. Keep the private key (``eggdrop.key``)

From Eggdrop's perspective, the implementation is identical.

Secure DCC (Deprecated)
-----------------------

Eggdrop supports SDCC (Secure DCC), allowing encrypted DCC connections.

**Note**: Only KVIrc IRC client supports SDCC. Modern alternatives include:

- DCC over TLS (if your IRC client supports it)
- Direct client-to-bot TLS connections

To enable DCC over TLS in configuration, set TLS DCC options. Check your config file for DCC settings.

Script Connections
------------------

Scripts can open TLS connections in several ways:

Connecting to a TLS Port
^^^^^^^^^^^^^^^^^^^^^^^

Use the standard socket command with a ``+`` prefix (Tcl 8.5+)::

  set s [socket -server tls irc.example.com +6697]

Upgrading Plaintext to TLS
^^^^^^^^^^^^^^^^^^^^^^^^^^

Establish a plaintext connection and upgrade with STARTTLS::

  set s [socket irc.example.com 6667]
  starttls $s

The ``starttls`` command upgrades the socket to TLS. Both sides must support this (rarely used).

TLS Configuration Settings
--------------------------

Core TLS Settings
^^^^^^^^^^^^^^^^^^

These settings are typically in the ``[tls]`` section of ``eggdrop.toml``:

**privatekey** — File containing Eggdrop's private key

- Required if the bot will accept TLS connections (hub, listener)
- Default location: ``eggdrop.key`` in bot's directory
- Use absolute path if not in bot directory

Example::

  [tls]
  privatekey = "eggdrop.key"

**certificate** — File containing Eggdrop's certificate

- Required if the bot will accept TLS connections
- Default location: ``eggdrop.crt`` in bot's directory

Example::

  [tls]
  certificate = "eggdrop.crt"

Certificate Verification
^^^^^^^^^^^^^^^^^^^^^^^^^

These settings control how strictly to verify peer certificates:

**verify-depth** — Maximum certificate chain depth

- Default: Usually 10
- Higher values allow longer certificate chains

**cafile** — Path to CA certificates file

- Used to verify peer certificates
- Optional; if not set, peer certificates may not verify

**capath** — Path to directory of CA certificates

- Alternative to cafile
- Directory must use OpenSSL hash naming

**verify-server** — Verify IRC server certificates

- 0 = No verification (default, faster)
- 1 = Full verification (stricter)
- 2+ = Allow self-signed certificates

**verify-bots** — Verify bot (botnet) certificates

- 0 = No verification (default)
- 1 = Full verification
- 2+ = Allow self-signed certificates

**verify-clients** — Verify partyline/DCC client certificates

- 0 = No verification
- 1 = Full verification
- 2+ = Allow self-signed certificates

**verify-dcc** — Verify DCC peer certificates

- 0 = No verification
- 1 = Full verification
- 2+ = Allow self-signed certificates

Example (allow self-signed bot certs)::

  [tls]
  verify-bots = 2

Certificate Authentication
^^^^^^^^^^^^^^^^^^^^^^^^^^

**cert-auth** — Enable TLS certificate authentication for partyline/botnet

- 0 = Disabled (use passwords only)
- 1 = Optional (use cert if available, fall back to password)
- 2 = Required (reject users without valid certs)

When enabled, users can authenticate by TLS certificate fingerprint instead of password.

To set a user's certificate fingerprint::

  .fprint <SHA1-fingerprint>

Or to auto-detect from current TLS connection::

  .fprint +

Example configuration::

  [tls]
  cert-auth = 1

Cipher Control
^^^^^^^^^^^^^^

**ciphers** — List of allowed TLS ciphers

- Advanced setting, usually left at default
- Syntax is OpenSSL cipher list format
- Only change if you have specific requirements

Example::

  [tls]
  ciphers = "HIGH:!aNULL:!MD5"

Troubleshooting
---------------

"TLS support is disabled"
^^^^^^^^^^^^^^^^^^^^^^^^^

The bot was compiled without TLS (with ``-Dtls=disabled``). Recompile without that flag::

  meson setup builddir
  ninja -C builddir
  meson install -C builddir --destdir=/path/to/eggdrop

Cannot connect to TLS server
^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. Verify the port number is correct
2. Verify the ``+`` prefix is present in the configuration
3. Check bot logs for error messages
4. Verify your system time is accurate (certificate validity checks fail with wrong time)

Botnet TLS connection fails
^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. Verify hub bot has certificates (``eggdrop.crt``, ``eggdrop.key``)
2. Verify hub is listening on TLS port (check with ``.status``)
3. Verify leaf is connecting with ``+`` port prefix
4. Check that both sides use the same TLS setting (both use ``+`` or neither)
5. Review bot logs for specific error messages

Certificate verification errors
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you see "certificate verification failed":

1. Check that certificate files exist and are readable
2. If using CA verification, ensure CA certificates are configured
3. For botnet use, consider relaxing verification (set to 2 instead of 1)
4. Check system time (certificate validity depends on correct time)

Common Issues
^^^^^^^^^^^^^

**Self-signed certificate warnings**: Normal and expected. Clients can ignore them.

**Mismatched TLS settings**: One side uses ``+port``, other doesn't. Fix by matching both sides.

**Certificate expired**: Regenerate new certificates with ``./scripts/genssl.sh``

**Wrong IP/hostname in certificate**: Self-signed certificates don't validate hostname anyway. CA-signed certs check the hostname.

Best Practices
--------------

1. **Always use TLS for botnet links** — Protects against eavesdropping on your bot control network

2. **Use TLS for IRC when available** — Most modern networks offer TLS ports

3. **Keep certificates secure** — Protect ``eggdrop.key`` file permissions (should be 0600)

4. **Rotate certificates periodically** — Self-signed certs typically valid 10 years, CA-signed per CA policy

5. **Use CA-signed certs for production** — Self-signed is fine for internal botnets

6. **Test TLS before deploying** — Verify connections work before relying on them

See Also
--------

- `TLS Setup Tutorial <../tutorials/tlssetup.html>`_ — Practical TLS setup guide
- `Botnet Configuration <botnet.html>`_ — Full botnet setup guide
- `Core Settings <core.html>`_ — Complete configuration reference

Copyright (C) 2010 - 2025 Eggheads Development Team
