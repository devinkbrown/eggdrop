# opssl

opssl is a security-focused TLS library built for the ophion IRC server.  It
provides TLS 1.2 and TLS 1.3, a full suite of cryptographic primitives, X.509
certificate handling, and first-class Linux kernel TLS (kTLS) offload for live
migration.

opssl has **zero external dependencies** beyond a C23 compiler, POSIX threads,
and libm.  All cryptographic primitives are implemented from scratch with
constant-time guarantees where security requires it.

## Build

```bash
meson setup builddir
ninja -C builddir
meson test -C builddir
```

### Build options

| Option | Default | Description |
|--------|---------|-------------|
| `ktls` | `auto` | Linux kernel TLS offload (requires `linux/tls.h`) |
| `postquantum` | `enabled` | ML-KEM (Kyber) post-quantum key exchange |
| `session_export` | `enabled` | TLS session state export/import for live migration |
| `tests` | `true` | Build test suite |

```bash
meson setup builddir -Dktls=enabled -Dpostquantum=enabled
```

### As a Meson subproject

When used as a subproject of ophion, libop is resolved as a sibling subproject.
For standalone builds, opssl uses header-only libop from `subprojects/libop/include/`
with stub implementations in `compat/`.

## Architecture

```
include/opssl/
  opssl.h        umbrella header
  types.h        core types, enums, callback typedefs
  ctx.h          TLS context configuration
  conn.h         per-connection TLS operations
  crypto.h       cryptographic primitives
  cert.h         X.509 certificate operations
  ktls.h         kernel TLS offload
  cbs.h          BoringSSL-style CBS/CBB wire format parser
  err.h          error codes and ring buffer
  platform.h     platform abstraction (includes op_lib.h)

src/
  init.c         library lifecycle (opssl_init / opssl_cleanup)
  err.c          per-thread error ring buffer
  ctx.c          TLS context (certificate loading, SNI table, cipher config)

src/crypto/
  sha1.c         SHA-1 (fingerprint compat only)
  sha256.c       SHA-256
  sha512.c       SHA-384, SHA-512
  sha3.c         SHA-3 (Keccak), SHAKE-128/256
  hmac.c         HMAC-SHA-256/384/512
  hkdf.c         HKDF extract/expand/expand-label (RFC 5869)
  pbkdf2.c       PBKDF2-HMAC (RFC 2898)
  aes.c          AES-128/256 (software)
  aes_gcm.c      AES-GCM seal/open
  aes_ccm.c      AES-CCM seal/open (full and truncated tag)
  camellia.c     Camellia block cipher + Camellia-GCM AEAD
  aes_ni.c       AES-NI / PCLMULQDQ acceleration
  chacha20.c     ChaCha20 stream cipher
  poly1305.c     Poly1305 MAC
  chacha20_poly1305.c   ChaCha20-Poly1305 AEAD
  bignum.c       multi-precision arithmetic (64-bit limbs)
  ecc.c          P-256, P-384 (Montgomery field, complete addition)
  x25519.c       X25519 key exchange (5x51-bit limbs, Montgomery ladder)
  ed25519.c      Ed25519 sign/verify (extended twisted Edwards)
  rsa.c          RSA (CRT, blinding, PKCS#1 v1.5, PSS)
  dh.c           Finite-field DH (FFDHE-2048/3072/4096)
  mlkem.c        ML-KEM-512/768/1024 (FIPS 203, NTT-based, post-quantum)
  mldsa.c        ML-DSA-65 (FIPS 204, post-quantum digital signatures)
  argon2id.c     Argon2id password hashing (RFC 9106)
  blake2b.c      BLAKE2b hash function (RFC 7693)
  cpuid.c        CPU feature detection (AES-NI, AVX2, SHA-NI, ARM crypto)
  random.c       CSPRNG (getrandom/getentropy/arc4random)
  constant_time.c   constant-time comparison and selection
  cbs.c          CBS/CBB wire format parser/builder
  platform.c     platform abstraction

src/tls/
  record.c       TLS record layer (encrypt/decrypt)
  handshake.c    handshake dispatcher and conn.h implementations
  tls12.c        TLS 1.2 state machine
  tls13.c        TLS 1.3 state machine
  extensions.c   TLS extension parsing (SNI, ALPN, key_share, etc.)
  ciphersuite.c  cipher suite negotiation
  keysched.c     TLS 1.3 key schedule
  ktls.c         kernel TLS promotion and key extraction
  dtls.c         DTLS record layer

src/x509/
  cert.c         X.509 certificate parsing
  chain.c        certificate chain building and verification
  pem.c          PEM decode/encode
  fingerprint.c  certificate fingerprinting (SHA1/256/512, SHA3, SPKI)
  asn1.c         ASN.1 DER parser
  pkey.c         private key loading (RSA, EC, Ed25519)
  trust_store.c  trusted CA store for chain validation

src/io/
  bio.c          BIO abstraction for custom I/O
  export.c       TLS session export/import for live migration
```

## Crypto primitives

All primitives are real implementations, not wrappers around another library.

| Category | Algorithms |
|----------|------------|
| Hash | SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512, SHAKE-128/256, BLAKE2b |
| MAC | HMAC-SHA-256/384/512 |
| KDF | HKDF (RFC 5869), PBKDF2 (RFC 2898), Argon2id (RFC 9106) |
| AEAD | AES-128/256-GCM, ChaCha20-Poly1305, AES-128/256-CCM, AES-128/256-CCM_8, Camellia-128/256-GCM |
| Key exchange | X25519, P-256, P-384, FFDHE-2048/3072/4096 |
| Signatures | Ed25519, ECDSA (P-256/P-384), RSA (PKCS#1 v1.5, PSS), ML-DSA-65 (FIPS 204) |
| Post-quantum | ML-KEM-768/1024 (FIPS 203), ML-DSA-65 (FIPS 204) |
| X.509 | DER/PEM parsing, chain verification, CRL, OCSP, fingerprinting |
| Encoding | Base64 (standard + URL-safe) |

### Security properties

- **Constant-time**: all secret-dependent operations (HMAC, AEAD tag check,
  ECC scalar multiply, RSA blinding) use constant-time primitives
- **No RSA key exchange**: only ephemeral ECDHE/DHE/X25519
- **No TLS < 1.2**: minimum protocol version is TLS 1.2
- **Complete formulas**: ECC point operations handle all degenerate cases
- **Fixed-window exponentiation**: no sliding window (prevents Hamming weight leaks)
- **Deterministic nonces**: RFC 6979 for ECDSA, RFC 8032 for Ed25519
- **Key blinding**: RSA base + exponent blinding on every private operation
- **Secure cleanup**: `explicit_bzero` / `memset_explicit` for all key material

## TLS features

### Protocol support

- TLS 1.2 with AEAD cipher suites only (no CBC)
- TLS 1.3 with full key schedule
- Non-blocking I/O with WANT_READ/WANT_WRITE return codes
- SNI with up to 64 per-hostname contexts
- ALPN negotiation (IRC, HTTP/1.1, DNS-over-TLS)
- Certificate fingerprinting (SHA1/256/512, SHA3-256/512, SPKI variants)
- Keying material export (RFC 5705 / RFC 8446 section 7.5)
- Post-handshake key update (TLS 1.3)
- Post-quantum hybrid key exchange (X25519+ML-KEM-768)

### Cipher suites

TLS 1.3 (9 cipher suites):
- `TLS_AES_256_GCM_SHA384`
- `TLS_CHACHA20_POLY1305_SHA256`
- `TLS_AES_128_GCM_SHA256`
- `TLS_AES_128_CCM_SHA256`
- `TLS_AES_128_CCM_8_SHA256`
- `TLS_AES_256_CCM_SHA384` (opssl extended)
- `TLS_AES_256_CCM_8_SHA384` (opssl extended)
- `TLS_CAMELLIA_128_GCM_SHA256` (opssl extended)
- `TLS_CAMELLIA_256_GCM_SHA384` (opssl extended)

TLS 1.2 (ECDHE / DHE):
- `ECDHE-RSA-AES128-GCM-SHA256`
- `ECDHE-RSA-AES256-GCM-SHA384`
- `ECDHE-ECDSA-AES128-GCM-SHA256`
- `ECDHE-ECDSA-AES256-GCM-SHA384`
- `ECDHE-RSA-CHACHA20-POLY1305`
- `ECDHE-ECDSA-CHACHA20-POLY1305`
- `DHE-RSA-AES128-GCM-SHA256`
- `DHE-RSA-AES256-GCM-SHA384`
- `DHE-RSA-CHACHA20-POLY1305`
- `ECDHE-ECDSA-AES128-CCM`
- `ECDHE-ECDSA-AES256-CCM`
- `DHE-RSA-AES128-CCM`
- `DHE-RSA-AES256-CCM`
- `ECDHE-ECDSA-AES128-CCM_8`
- `ECDHE-ECDSA-AES256-CCM_8`
- `DHE-RSA-AES128-CCM_8`
- `DHE-RSA-AES256-CCM_8`
- `ECDHE-ECDSA-CAMELLIA128-GCM` (RFC 6367)
- `ECDHE-ECDSA-CAMELLIA256-GCM`
- `ECDHE-RSA-CAMELLIA128-GCM`
- `ECDHE-RSA-CAMELLIA256-GCM`
- `DHE-RSA-CAMELLIA128-GCM`
- `DHE-RSA-CAMELLIA256-GCM`

### Kernel TLS (kTLS)

After a successful handshake with an AEAD cipher, opssl can promote the
connection to Linux kernel TLS via `opssl_ktls_promote()`.  The kernel handles
encryption/decryption transparently, and the socket FD can be transferred to
another process via `SCM_RIGHTS` for zero-downtime live migration.

Supported kTLS ciphers: AES-GCM-128, AES-GCM-256, ChaCha20-Poly1305.

Prerequisite: `sudo modprobe tls` (or `CONFIG_TLS=y`).

### Session export/import

For live migration when kTLS is unavailable, opssl can serialize the complete
TLS session state (keys, IVs, sequence numbers, cipher suite) into a buffer
for transfer alongside the socket FD.  The new process reconstructs the TLS
session without re-handshake.

## API overview

### Library lifecycle

```c
#include <opssl/opssl.h>

opssl_init();      /* call once at startup */
opssl_cleanup();   /* call once at shutdown */
```

### Context setup

```c
opssl_ctx_t *ctx = opssl_ctx_new(OPSSL_TLS_1_2);
opssl_ctx_use_certificate_chain_file(ctx, "server.pem");
opssl_ctx_use_private_key_file(ctx, "server.key");
opssl_ctx_check_private_key(ctx);
opssl_ctx_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");
```

### Server handshake (non-blocking)

```c
opssl_conn_t *conn = opssl_conn_new(ctx, client_fd, OPSSL_DIR_INBOUND);

opssl_result_t r;
while ((r = opssl_accept(conn)) != OPSSL_OK) {
    if (r == OPSSL_WANT_READ)  { /* wait for POLLIN */  }
    if (r == OPSSL_WANT_WRITE) { /* wait for POLLOUT */ }
    if (r == OPSSL_ERROR)      { /* handle error */     }
}

/* promote to kTLS if possible */
opssl_ktls_promote(conn);
```

### Data transfer

```c
ssize_t n = opssl_read(conn, buf, sizeof(buf));
ssize_t w = opssl_write(conn, data, data_len);
```

### Crypto (standalone)

```c
uint8_t hash[OPSSL_SHA256_DIGEST_LEN];
opssl_sha256(data, data_len, hash);

uint8_t mac[OPSSL_HMAC_MAX_DIGEST_LEN];
size_t mac_len;
opssl_hmac(OPSSL_HMAC_SHA256, key, key_len, data, data_len, mac, &mac_len);

uint8_t pub[OPSSL_X25519_KEY_LEN], priv[OPSSL_X25519_KEY_LEN];
opssl_x25519_keygen(priv, pub);
```

## Tests

Three test suites:

- `test_crypto` — SHA-256/512, SHA-1, SHA3-256/512, SHAKE-128/256, BLAKE2b, HMAC, HKDF, PBKDF2, Argon2id, AEAD (AES-GCM, ChaCha20-Poly1305, AES-CCM, Camellia-GCM), X25519, Ed25519, ECDSA, ECDH, RSA, ML-DSA-65, ML-KEM, FFDHE, Base64, constant-time ops, hardware acceleration
- `test_tls` — TLS protocol handshake and record layer
- `test_x509` — certificate parsing, chain verification, fingerprinting

```bash
meson test -C builddir --verbose
```

## Return conventions

- Functions returning `int`: **1 = success, 0 = failure** (not 0 = success)
- Functions returning `opssl_result_t`: `OPSSL_OK` (1) on success
- Functions returning `ssize_t`: bytes transferred, or negative on error
- `OPSSL_WANT_READ` / `OPSSL_WANT_WRITE`: non-blocking I/O needs retry

## License

GPL-2.0-or-later
