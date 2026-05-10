Enabling TLS Security on Eggdrop
================================

TLS (Transport Layer Security) encrypts communication between your Eggdrop and IRC servers, other bots, and clients. This guide shows how to set up TLS protection for various scenarios.

**Note**: The terms "SSL" and "TLS" are often used interchangeably. SSL is deprecated; Eggdrop uses TLS 1.2 and 1.3.

Prerequisites
-------------

**TLS Library**: Eggdrop includes opssl, a custom bundled TLS library (TLS 1.2 and 1.3 support). No external library installation needed.

To verify your Eggdrop has TLS support, join the partyline and type::

  .status

You should see::

  TLS support is enabled.

If TLS was disabled at build time (with ``-Dtls=disabled``), you'll see "TLS support is disabled."

Connecting to TLS-Protected IRC Servers
---------------------------------------

Most modern IRC servers offer TLS-protected connection ports. To connect to a TLS port, prefix the port number with a ``+`` in your configuration.

**In eggdrop.toml**::

  [servers]
  list = [
    "irc.example.com:+6697",        # TLS on port 6697
    "irc.example.com:+7000:password",  # TLS with server password
  ]

Example servers:

- Libera.Chat: ``irc.libera.chat:+6697``
- EFnet: ``irc.efnet.org:+6697``
- DALnet: ``irc.dalnet.net:+6697``

Eggdrop will automatically use TLS for ports prefixed with ``+``. No other configuration needed.

Protecting Botnet Communications (Bot-to-Bot)
----------------------------------------------

Eggdrop can use TLS to encrypt connections between bots in a botnet. This requires generating TLS certificates.

Generating TLS Certificates
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

From your **installed Eggdrop directory** (not the source), run::

  ./scripts/genssl.sh

This interactive script generates a self-signed certificate suitable for botnet encryption:

- ``eggdrop.crt`` — public certificate
- ``eggdrop.key`` — private key

For non-interactive generation (useful in scripts)::

  ./scripts/genssl.sh -s

The script generates a certificate valid for 10 years. For CA-signed certificates, the process is similar but you'll use your CA's certificate instead.

**Note**: Self-signed certificates are fine for botnets. Certificate warnings are expected and normal.

Configuring Botnet TLS Listening
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To accept TLS connections from other bots, configure the listen port with a ``+`` prefix in ``eggdrop.toml``:

::

  [listen]
  ports = [
    "5555 all",         # Plain text on port 5555
    "+5556 all",        # TLS on port 5556
  ]

Also ensure the certificate and key are configured (usually in the ``[tls]`` section, or check your config for TLS settings).

Connecting to a Botnet Hub with TLS
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To connect a leaf bot to a hub using TLS, use the ``.chaddr`` command from the partyline::

  .chaddr <hub-bot-name> <ip> +<port>

For example::

  .chaddr HubBot 1.2.3.4 +5556

The ``+`` prefix tells Eggdrop to use TLS for this connection.

Or, in the configuration file, prefix the botnet hub port with ``+``::

  .+bot HubBot 1.2.3.4 +5556

This automatically uses TLS when connecting.

TLS Certificate Management
--------------------------

Self-Signed Certificates
^^^^^^^^^^^^^^^^^^^^^^^^^

**Pros**: No external dependency, suitable for botnets, fast to generate

**Cons**: Clients show security warnings (normal and expected)

For botnet use, self-signed certificates are ideal.

CA-Signed Certificates
^^^^^^^^^^^^^^^^^^^^^^

For production systems or external clients connecting to your bot:

1. Generate a Certificate Signing Request (CSR) from your existing certificate
2. Submit to a Certificate Authority (Let's Encrypt, DigiCert, etc.)
3. Replace the certificate file with the CA-signed version
4. Keep the private key file

The implementation is identical to self-signed certificates from Eggdrop's perspective.

Certificate Verification
^^^^^^^^^^^^^^^^^^^^^^^^^

TLS connections are encrypted whether certificates are self-signed or CA-signed. For botnets, certificate verification is not critical. For public-facing services, CA-signed certificates are recommended.

Common TLS Scenarios
--------------------

Scenario 1: IRC Server with TLS
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Goal**: Connect securely to an IRC network that offers TLS.

**Steps**:

1. Find a TLS port for your IRC network (usually port 6697 or 7000)
2. Add to ``eggdrop.toml`` with ``+`` prefix::

     [servers]
     list = ["irc.libera.chat:+6697"]

3. Restart the bot

**Done!** The bot connects securely to IRC.

Scenario 2: Botnet with TLS
^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Goal**: Create a botnet with encrypted hub-to-leaf communication.

**Hub bot setup**:

1. Generate certificate::

     ./scripts/genssl.sh

2. Configure listening port in ``eggdrop.toml``::

     [listen]
     ports = ["+5556 all"]

3. Restart hub bot

**Leaf bot setup**:

1. Add hub connection with ``+`` port::

     .+bot HubBot 1.2.3.4 +5556

2. Verify connection with ``.status``

**Done!** Hub and leaf communicate via TLS.

Scenario 3: DCC Chat with TLS (Advanced)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Users can DCC chat with your bot securely. This requires TLS support on the client side (most modern IRC clients support SSLTS DCC).

To enable::

  [dcc]
  use-ssl = true

Then users can DCC chat normally; the connection is automatically encrypted.

Troubleshooting
---------------

"TLS support is disabled"
^^^^^^^^^^^^^^^^^^^^^^^^^

You built Eggdrop with ``-Dtls=disabled``. Rebuild without that flag::

  meson setup builddir      # Remove -Dtls=disabled
  ninja -C builddir
  meson install -C builddir --destdir=/path/to/eggdrop

"Cannot find certificate file"
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Check that:

1. ``eggdrop.crt`` and ``eggdrop.key`` exist in the bot's directory
2. File paths in config are correct (absolute paths recommended)
3. Files are readable by the bot user

Certificate warnings in DCC chat
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**This is normal** with self-signed certificates. Clients display a warning but the connection is still encrypted. Users can ignore or accept the warning.

For production services, use a CA-signed certificate.

Botnet connection fails with TLS
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. Verify hub bot has certificate files (``eggdrop.crt``, ``eggdrop.key``)
2. Verify hub is listening on the TLS port (check with ``.status``)
3. Verify leaf is connecting with ``+`` prefix on port (check with ``.chaddr``)
4. Check logs for error messages

IRC server rejects TLS connection
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. Verify the server actually supports TLS on that port
2. Check that the port is prefixed with ``+`` in the config
3. Try a different TLS port if available

Next Steps
----------

- `Core Settings <../using/core.html>`_ — full configuration reference
- `TLS Technical Details <../using/tls.html>`_ — advanced TLS topics
- `Botnet Configuration <../using/botnet.html>`_ — complete botnet guide

Copyright (C) 1997 Robey Pointer
Copyright (C) 1999 - 2025 Eggheads Development Team
