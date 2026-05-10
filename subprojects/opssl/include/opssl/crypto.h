/*
 * opssl/crypto.h — cryptographic primitives.
 *
 * Clean interface to the crypto layer. All operations are constant-time
 * where security requires it. Key material is always in secure memory.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef OPSSL_CRYPTO_H
#define OPSSL_CRYPTO_H

#include <opssl/types.h>
#include <opssl/platform.h>

/* ─── Hash Functions ─────────────────────────────────────────────────── */

#define OPSSL_SHA256_DIGEST_LEN  32
#define OPSSL_SHA384_DIGEST_LEN  48
#define OPSSL_SHA512_DIGEST_LEN  64
#define OPSSL_SHA3_256_DIGEST_LEN 32
#define OPSSL_SHA3_512_DIGEST_LEN 64
#define OPSSL_SHA1_DIGEST_LEN    20

typedef struct opssl_sha256_ctx opssl_sha256_ctx_t;
typedef struct opssl_sha512_ctx opssl_sha512_ctx_t;
typedef struct opssl_sha3_ctx   opssl_sha3_ctx_t;

/* SHA-256 */
void opssl_sha256_init(opssl_sha256_ctx_t *ctx);
void opssl_sha256_update(opssl_sha256_ctx_t *ctx, const void *data, size_t len);
void opssl_sha256_final(opssl_sha256_ctx_t *ctx, uint8_t out[OPSSL_SHA256_DIGEST_LEN]);
void opssl_sha256(const void *data, size_t len, uint8_t out[OPSSL_SHA256_DIGEST_LEN]);

/* SHA-384 / SHA-512 */
void opssl_sha384_init(opssl_sha512_ctx_t *ctx);
void opssl_sha384_final(opssl_sha512_ctx_t *ctx, uint8_t out[OPSSL_SHA384_DIGEST_LEN]);
void opssl_sha384(const void *data, size_t len, uint8_t out[OPSSL_SHA384_DIGEST_LEN]);

void opssl_sha512_init(opssl_sha512_ctx_t *ctx);
void opssl_sha512_update(opssl_sha512_ctx_t *ctx, const void *data, size_t len);
void opssl_sha512_final(opssl_sha512_ctx_t *ctx, uint8_t out[OPSSL_SHA512_DIGEST_LEN]);
void opssl_sha512(const void *data, size_t len, uint8_t out[OPSSL_SHA512_DIGEST_LEN]);

/* SHA-3 */
void opssl_sha3_256_init(opssl_sha3_ctx_t *ctx);
void opssl_sha3_256_update(opssl_sha3_ctx_t *ctx, const void *data, size_t len);
void opssl_sha3_256_final(opssl_sha3_ctx_t *ctx, uint8_t out[OPSSL_SHA3_256_DIGEST_LEN]);
void opssl_sha3_256(const void *data, size_t len, uint8_t out[OPSSL_SHA3_256_DIGEST_LEN]);

void opssl_sha3_512_init(opssl_sha3_ctx_t *ctx);
void opssl_sha3_512_update(opssl_sha3_ctx_t *ctx, const void *data, size_t len);
void opssl_sha3_512_final(opssl_sha3_ctx_t *ctx, uint8_t out[OPSSL_SHA3_512_DIGEST_LEN]);
void opssl_sha3_512(const void *data, size_t len, uint8_t out[OPSSL_SHA3_512_DIGEST_LEN]);

/* SHAKE (extendable output functions) */
void opssl_shake128(uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len);
void opssl_shake256(uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len);

/* SHA-1 (fingerprint compat only — not for security) */
typedef struct {
    uint32_t h[5];         /* Hash state */
    uint8_t  block[64];    /* 512-bit message block */
    uint64_t bitcount;     /* Total bits processed */
    size_t   block_len;    /* Current block length */
} opssl_sha1_ctx_t;

void opssl_sha1_init(opssl_sha1_ctx_t *ctx);
void opssl_sha1_update(opssl_sha1_ctx_t *ctx, const void *data, size_t len);
void opssl_sha1_final(opssl_sha1_ctx_t *ctx, uint8_t out[OPSSL_SHA1_DIGEST_LEN]);
void opssl_sha1(const void *data, size_t len, uint8_t out[OPSSL_SHA1_DIGEST_LEN]);

/* ─── HMAC ───────────────────────────────────────────────────────────── */

#define OPSSL_HMAC_MAX_DIGEST_LEN 64

typedef struct opssl_hmac_ctx opssl_hmac_ctx_t;

typedef enum {
    OPSSL_HMAC_SHA256,
    OPSSL_HMAC_SHA384,
    OPSSL_HMAC_SHA512,
} opssl_hmac_algo_t;

int  opssl_hmac_init(opssl_hmac_ctx_t *ctx, opssl_hmac_algo_t algo,
                     const uint8_t *key, size_t key_len);
void opssl_hmac_update(opssl_hmac_ctx_t *ctx, const void *data, size_t len);
int  opssl_hmac_final(opssl_hmac_ctx_t *ctx, uint8_t *out, size_t *out_len);
void opssl_hmac_cleanup(opssl_hmac_ctx_t *ctx);

/* One-shot */
int opssl_hmac(opssl_hmac_algo_t algo,
               const uint8_t *key, size_t key_len,
               const void *data, size_t data_len,
               uint8_t *out, size_t *out_len);

/* ─── HKDF (RFC 5869) ───────────────────────────────────────────────── */

int opssl_hkdf_extract(opssl_hmac_algo_t algo,
                       const uint8_t *salt, size_t salt_len,
                       const uint8_t *ikm, size_t ikm_len,
                       uint8_t *prk, size_t *prk_len);

int opssl_hkdf_expand(opssl_hmac_algo_t algo,
                      const uint8_t *prk, size_t prk_len,
                      const uint8_t *info, size_t info_len,
                      uint8_t *okm, size_t okm_len);

int opssl_hkdf_expand_label(opssl_hmac_algo_t algo,
                            const uint8_t *secret, size_t secret_len,
                            const char *label,
                            const uint8_t *context, size_t context_len,
                            uint8_t *out, size_t out_len);

/* ─── PBKDF2 (RFC 2898) ────────────────────────────────────────────── */

int opssl_pbkdf2(opssl_hmac_algo_t algo,
                 const uint8_t *password, size_t password_len,
                 const uint8_t *salt, size_t salt_len,
                 uint32_t iterations,
                 uint8_t *out, size_t out_len);

/* ─── AEAD Ciphers ───────────────────────────────────────────────────── */

#define OPSSL_AES_128_KEY_LEN   16
#define OPSSL_AES_256_KEY_LEN   32
#define OPSSL_AES_GCM_IV_LEN   12
#define OPSSL_AES_GCM_TAG_LEN  16
#define OPSSL_AES_CCM_IV_LEN   12
#define OPSSL_AES_CCM_TAG_LEN  16

#define OPSSL_CHACHA20_KEY_LEN  32
#define OPSSL_CHACHA20_IV_LEN   12
#define OPSSL_POLY1305_TAG_LEN  16

typedef struct opssl_aead_ctx opssl_aead_ctx_t;

typedef enum {
    OPSSL_AEAD_AES_128_GCM,
    OPSSL_AEAD_AES_256_GCM,
    OPSSL_AEAD_CHACHA20_POLY1305,
    OPSSL_AEAD_AES_128_CCM,
    OPSSL_AEAD_AES_256_CCM,
} opssl_aead_algo_t;

/* AEAD context lifecycle */
opssl_aead_ctx_t *opssl_aead_new(opssl_aead_algo_t algo);
int  opssl_aead_set_key(opssl_aead_ctx_t *ctx, const uint8_t *key, size_t key_len);
void opssl_aead_free(opssl_aead_ctx_t *ctx);

/* Seal (encrypt + authenticate) */
int opssl_aead_seal(opssl_aead_ctx_t *ctx,
                    uint8_t *out, size_t *out_len, size_t max_out,
                    const uint8_t *nonce, size_t nonce_len,
                    const uint8_t *plaintext, size_t plaintext_len,
                    const uint8_t *aad, size_t aad_len);

/* Open (decrypt + verify) — constant-time tag check */
int opssl_aead_open(opssl_aead_ctx_t *ctx,
                    uint8_t *out, size_t *out_len, size_t max_out,
                    const uint8_t *nonce, size_t nonce_len,
                    const uint8_t *ciphertext, size_t ciphertext_len,
                    const uint8_t *aad, size_t aad_len);

/* Per-algorithm properties */
size_t opssl_aead_key_len(opssl_aead_algo_t algo);
size_t opssl_aead_nonce_len(opssl_aead_algo_t algo);
size_t opssl_aead_tag_len(opssl_aead_algo_t algo);

/* ─── Key Exchange ───────────────────────────────────────────────────── */

/* X25519 */
#define OPSSL_X25519_KEY_LEN     32
#define OPSSL_X25519_SHARED_LEN  32

int opssl_x25519_keygen(uint8_t priv[OPSSL_X25519_KEY_LEN],
                        uint8_t pub[OPSSL_X25519_KEY_LEN]);
int opssl_x25519_derive(uint8_t shared[OPSSL_X25519_SHARED_LEN],
                        const uint8_t priv[OPSSL_X25519_KEY_LEN],
                        const uint8_t peer_pub[OPSSL_X25519_KEY_LEN]);

/* ECDH (NIST curves) */
typedef struct opssl_ecdh_ctx opssl_ecdh_ctx_t;

typedef enum {
    OPSSL_CURVE_P256,
    OPSSL_CURVE_P384,
    OPSSL_CURVE_P521,
} opssl_curve_t;

opssl_ecdh_ctx_t *opssl_ecdh_new(opssl_curve_t curve);
int  opssl_ecdh_keygen(opssl_ecdh_ctx_t *ctx);
int  opssl_ecdh_get_public(opssl_ecdh_ctx_t *ctx, uint8_t *pub, size_t *pub_len);
int  opssl_ecdh_derive(opssl_ecdh_ctx_t *ctx,
                       const uint8_t *peer_pub, size_t peer_pub_len,
                       uint8_t *shared, size_t *shared_len);
void opssl_ecdh_free(opssl_ecdh_ctx_t *ctx);

/* Finite Field DH (FFDHE groups) */
typedef struct opssl_ffdh_ctx opssl_ffdh_ctx_t;

typedef enum {
    OPSSL_FFDHE_2048,
    OPSSL_FFDHE_3072,
    OPSSL_FFDHE_4096,
} opssl_ffdhe_group_t;

opssl_ffdh_ctx_t *opssl_ffdh_new(opssl_ffdhe_group_t group);
int  opssl_ffdh_keygen(opssl_ffdh_ctx_t *ctx);
int  opssl_ffdh_get_public(opssl_ffdh_ctx_t *ctx, uint8_t *pub, size_t *pub_len);
int  opssl_ffdh_derive(opssl_ffdh_ctx_t *ctx,
                       const uint8_t *peer_pub, size_t peer_pub_len,
                       uint8_t *shared, size_t *shared_len);
void opssl_ffdh_free(opssl_ffdh_ctx_t *ctx);

/* ML-KEM (post-quantum hybrid) */
#define OPSSL_MLKEM768_PK_LEN    1184
#define OPSSL_MLKEM768_SK_LEN    2400
#define OPSSL_MLKEM768_CT_LEN    1088
#define OPSSL_MLKEM768_SS_LEN    32

#define OPSSL_MLKEM1024_PK_LEN   1568
#define OPSSL_MLKEM1024_SK_LEN   3168
#define OPSSL_MLKEM1024_CT_LEN   1568
#define OPSSL_MLKEM1024_SS_LEN   32

typedef enum {
    OPSSL_MLKEM_768,
    OPSSL_MLKEM_1024,
} opssl_mlkem_level_t;

typedef struct opssl_mlkem_ctx opssl_mlkem_ctx_t;

opssl_mlkem_ctx_t *opssl_mlkem_new(opssl_mlkem_level_t level);
int  opssl_mlkem_keygen(opssl_mlkem_ctx_t *ctx);
int  opssl_mlkem_encaps(opssl_mlkem_ctx_t *ctx,
                        const uint8_t *pk, size_t pk_len,
                        uint8_t *ct, size_t *ct_len,
                        uint8_t *ss, size_t *ss_len);
int  opssl_mlkem_decaps(opssl_mlkem_ctx_t *ctx,
                        const uint8_t *ct, size_t ct_len,
                        uint8_t *ss, size_t *ss_len);
int  opssl_mlkem_get_public(opssl_mlkem_ctx_t *ctx, uint8_t *pk, size_t *pk_len);
void opssl_mlkem_free(opssl_mlkem_ctx_t *ctx);

/* ─── Digital Signatures ─────────────────────────────────────────────── */

/* Ed25519 */
#define OPSSL_ED25519_PK_LEN    32
#define OPSSL_ED25519_SK_LEN    64
#define OPSSL_ED25519_SIG_LEN   64

int opssl_ed25519_keygen(uint8_t pk[OPSSL_ED25519_PK_LEN],
                         uint8_t sk[OPSSL_ED25519_SK_LEN]);
int opssl_ed25519_sign(uint8_t sig[OPSSL_ED25519_SIG_LEN],
                       const uint8_t *msg, size_t msg_len,
                       const uint8_t sk[OPSSL_ED25519_SK_LEN]);
int opssl_ed25519_verify(const uint8_t sig[OPSSL_ED25519_SIG_LEN],
                         const uint8_t *msg, size_t msg_len,
                         const uint8_t pk[OPSSL_ED25519_PK_LEN]);

/* ECDSA */
typedef struct opssl_ecdsa_ctx opssl_ecdsa_ctx_t;

opssl_ecdsa_ctx_t *opssl_ecdsa_new(opssl_curve_t curve);
int  opssl_ecdsa_keygen(opssl_ecdsa_ctx_t *ctx);
int  opssl_ecdsa_sign(opssl_ecdsa_ctx_t *ctx,
                      const uint8_t *digest, size_t digest_len,
                      uint8_t *sig, size_t *sig_len);
int  opssl_ecdsa_verify(opssl_ecdsa_ctx_t *ctx,
                        const uint8_t *digest, size_t digest_len,
                        const uint8_t *sig, size_t sig_len);
int  opssl_ecdsa_set_public(opssl_ecdsa_ctx_t *ctx, const uint8_t *pub, size_t pub_len);
int  opssl_ecdsa_set_private(opssl_ecdsa_ctx_t *ctx, const uint8_t *priv, size_t priv_len);
void opssl_ecdsa_free(opssl_ecdsa_ctx_t *ctx);

/* RSA */
typedef struct opssl_rsa_ctx opssl_rsa_ctx_t;

typedef enum {
    OPSSL_RSA_PKCS1_V15,
    OPSSL_RSA_PSS,
} opssl_rsa_padding_t;

opssl_rsa_ctx_t *opssl_rsa_new(void);
int  opssl_rsa_load_private_key(opssl_rsa_ctx_t *ctx, const uint8_t *der, size_t len);
int  opssl_rsa_load_public_key(opssl_rsa_ctx_t *ctx, const uint8_t *der, size_t len);
int  opssl_rsa_sign(opssl_rsa_ctx_t *ctx, opssl_rsa_padding_t pad,
                    opssl_hmac_algo_t hash,
                    const uint8_t *digest, size_t digest_len,
                    uint8_t *sig, size_t *sig_len);
int  opssl_rsa_verify(opssl_rsa_ctx_t *ctx, opssl_rsa_padding_t pad,
                      opssl_hmac_algo_t hash,
                      const uint8_t *digest, size_t digest_len,
                      const uint8_t *sig, size_t sig_len);
size_t opssl_rsa_size(const opssl_rsa_ctx_t *ctx);
void opssl_rsa_free(opssl_rsa_ctx_t *ctx);

/* ─── Base64 Encoding ───────────────────────────────────────────────── */

int opssl_base64_encode(const uint8_t *in, size_t in_len, char *out, size_t *out_len);
int opssl_base64_decode(const char *in, size_t in_len, uint8_t *out, size_t *out_len);

#endif /* OPSSL_CRYPTO_H */
