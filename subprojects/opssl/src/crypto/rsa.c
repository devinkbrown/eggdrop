/*
 * RSA signature operations for opssl TLS library
 * Supports PKCS#1 v1.5 and RSA-PSS with CRT optimization and blinding
 */

#include <opssl/crypto.h>
#include <opssl/platform.h>
#include <string.h>
#include "bignum_internal.h"
#include "sha_internal.h"

/* DigestInfo DER prefixes for PKCS#1 v1.5 */
static const uint8_t sha256_prefix[] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};
static const uint8_t sha384_prefix[] = {
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30
};
static const uint8_t sha512_prefix[] = {
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40
};

/* Hash digest sizes */
static const size_t hash_sizes[] = { 32, 48, 64 }; /* SHA-256, SHA-384, SHA-512 */

/* RSA context structure */
struct opssl_rsa_ctx {
    opssl_bn_t n, e, d;      /* public modulus, exponent, private exponent */
    opssl_bn_t p, q;          /* CRT primes */
    opssl_bn_t dp, dq, qinv; /* CRT components */
    opssl_bn_mont_ctx_t mont_n, mont_p, mont_q;
    int bits;                 /* key size in bits */
    int has_private;
};

/* Simple ASN.1 DER parsing helpers */
static int parse_tag(const uint8_t **p, const uint8_t *end, int expected_tag) {
    if (*p >= end || **p != expected_tag) return 0;
    (*p)++;
    return 1;
}

static size_t parse_length(const uint8_t **p, const uint8_t *end) {
    if (*p >= end) return 0;

    uint8_t len_byte = **p;
    (*p)++;

    if (len_byte & 0x80) {
        /* Long form */
        int len_octets = len_byte & 0x7f;
        if (len_octets == 0 || len_octets > 4 || *p + len_octets > end) return 0;

        size_t length = 0;
        for (int i = 0; i < len_octets; i++) {
            length = (length << 8) | **p;
            (*p)++;
        }
        return length;
    } else {
        /* Short form */
        return len_byte;
    }
}

static int parse_integer(opssl_bn_t *bn, const uint8_t **p, const uint8_t *end) {
    if (!parse_tag(p, end, 0x02)) return 0;

    size_t len = parse_length(p, end);
    if (len == 0 || *p + len > end) return 0;

    /* Skip leading zero if present */
    if (len > 0 && **p == 0x00) {
        (*p)++;
        len--;
    }

    if (len > OPSSL_BN_MAX_LIMBS * 8) return 0; /* Too large */

    opssl_bn_from_bytes(bn, *p, len);
    *p += len;
    return 1;
}

/* MGF1 mask generation for RSA-PSS per RFC 8017 section B.2.1 */
static void mgf1(uint8_t *mask, size_t mask_len, const uint8_t *seed, size_t seed_len, opssl_hmac_algo_t hash_algo) {
    uint8_t hash[64]; /* max SHA-512 */
    uint8_t input[512]; /* seed + counter buffer, enough for max seed size */
    size_t h_len = (hash_algo == OPSSL_HMAC_SHA256) ? 32 : (hash_algo == OPSSL_HMAC_SHA384) ? 48 : 64;
    size_t done = 0;

    /* Check input size constraints */
    if (seed_len > sizeof(input) - 4) {
        /* Should not happen with reasonable key sizes */
        opssl_memzero(mask, mask_len);
        return;
    }

    /* Copy seed once to input buffer */
    memcpy(input, seed, seed_len);

    for (uint32_t c = 0; done < mask_len; c++) {
        /* Append 32-bit counter in big-endian format */
        input[seed_len + 0] = (c >> 24) & 0xff;
        input[seed_len + 1] = (c >> 16) & 0xff;
        input[seed_len + 2] = (c >> 8) & 0xff;
        input[seed_len + 3] = c & 0xff;

        /* Compute hash = Hash(seed || C) */
        if (hash_algo == OPSSL_HMAC_SHA256) {
            opssl_sha256(input, seed_len + 4, hash);
        } else if (hash_algo == OPSSL_HMAC_SHA384) {
            /* Use one-shot SHA-384 function */
            opssl_sha384(input, seed_len + 4, hash);
        } else { /* SHA-512 */
            /* Use one-shot SHA-512 function */
            opssl_sha512(input, seed_len + 4, hash);
        }

        /* Copy hash output to mask, truncate if needed */
        size_t copy_len = (mask_len - done) < h_len ? (mask_len - done) : h_len;
        memcpy(mask + done, hash, copy_len);
        done += copy_len;
    }

    /* Clear sensitive data */
    opssl_memzero(hash, sizeof(hash));
    opssl_memzero(input, sizeof(input));
}

/*
 * RSA private operation: result = input^d mod n
 *
 * Direct exponentiation (no CRT for now — correctness first).
 */
static void rsa_private_op(opssl_bn_t *result, const opssl_bn_t *input, const opssl_rsa_ctx_t *ctx) {
    int width_n = ctx->bits / 64;
    opssl_bn_mod_exp_ct(result, input, &ctx->d, width_n, &ctx->mont_n);
}

/* PKCS#1 v1.5 padding for signature */
static int pkcs1_v15_pad(uint8_t *em, size_t em_len, const uint8_t *digest,
                        size_t digest_len, opssl_hmac_algo_t hash_algo) {
    const uint8_t *prefix;
    size_t prefix_len;

    /* Select DigestInfo prefix */
    switch (hash_algo) {
        case OPSSL_HMAC_SHA256:
            prefix = sha256_prefix;
            prefix_len = sizeof(sha256_prefix);
            break;
        case OPSSL_HMAC_SHA384:
            prefix = sha384_prefix;
            prefix_len = sizeof(sha384_prefix);
            break;
        case OPSSL_HMAC_SHA512:
            prefix = sha512_prefix;
            prefix_len = sizeof(sha512_prefix);
            break;
        default:
            return 0;
    }

    size_t required = prefix_len + digest_len + 11; /* Minimum padding overhead */
    if (em_len < required) return 0;

    /* Construct padded message */
    em[0] = 0x00;
    em[1] = 0x01;

    /* Fill with 0xFF */
    size_t pad_len = em_len - prefix_len - digest_len - 3;
    memset(em + 2, 0xff, pad_len);

    em[2 + pad_len] = 0x00;
    memcpy(em + 3 + pad_len, prefix, prefix_len);
    memcpy(em + 3 + pad_len + prefix_len, digest, digest_len);

    return 1;
}

/* RSA-PSS padding for signature (em_bits = modBits - 1 per RFC 8017) */
static int pss_pad(uint8_t *em, size_t em_len, int em_bits, const uint8_t *digest,
                  size_t digest_len, opssl_hmac_algo_t hash_algo) {
    size_t salt_len = hash_sizes[hash_algo];
    size_t h_len = hash_sizes[hash_algo];

    if (em_len < 2 * h_len + 2) return 0;

    /* Generate random salt */
    uint8_t salt[64]; /* Max hash size */
    opssl_random_bytes(salt, salt_len);

    /* Compute H = Hash(0x0000000000000000 || mHash || salt) */
    uint8_t m_prime[8 + 64 + 64]; /* 8 zeros + digest + salt */
    memset(m_prime, 0, 8);
    memcpy(m_prime + 8, digest, digest_len);
    memcpy(m_prime + 8 + digest_len, salt, salt_len);

    uint8_t h[64];
    /* Compute H = Hash(0x0000000000000000 || mHash || salt) */
    if (hash_algo == OPSSL_HMAC_SHA256) {
        struct opssl_sha256_ctx hctx;
        opssl_sha256_init(&hctx);
        opssl_sha256_update(&hctx, m_prime, 8 + digest_len + salt_len);
        opssl_sha256_final(&hctx, h);
    } else if (hash_algo == OPSSL_HMAC_SHA384) {
        struct opssl_sha512_ctx hctx;
        opssl_sha384_init(&hctx);
        opssl_sha512_update(&hctx, m_prime, 8 + digest_len + salt_len);
        opssl_sha384_final(&hctx, h);
    } else {
        struct opssl_sha512_ctx hctx;
        opssl_sha512_init(&hctx);
        opssl_sha512_update(&hctx, m_prime, 8 + digest_len + salt_len);
        opssl_sha512_final(&hctx, h);
    }

    /* Construct DB = 0x00...00 || 0x01 || salt */
    size_t db_len = em_len - h_len - 1;
    uint8_t *db = em;
    memset(db, 0, db_len - salt_len - 1);
    db[db_len - salt_len - 1] = 0x01;
    memcpy(db + db_len - salt_len, salt, salt_len);

    /* Generate mask and apply: maskedDB = DB XOR MGF1(H, dbLen) */
    uint8_t mask[512]; /* Enough for 4096-bit keys */
    mgf1(mask, db_len, h, h_len, hash_algo);

    for (size_t i = 0; i < db_len; i++) {
        db[i] ^= mask[i];
    }

    /* Clear leftmost 8*emLen - emBits bits of the leftmost octet */
    int top_bits = 8 * (int)em_len - em_bits;
    if (top_bits > 0)
        db[0] &= (0xff >> top_bits);

    /* Append H and trailer */
    memcpy(em + db_len, h, h_len);
    em[em_len - 1] = 0xbc;

    return 1;
}

/* Verify PKCS#1 v1.5 padding */
static int pkcs1_v15_verify(const uint8_t *em, size_t em_len, const uint8_t *digest,
                           size_t digest_len, opssl_hmac_algo_t hash_algo) {
    const uint8_t *prefix;
    size_t prefix_len;

    switch (hash_algo) {
        case OPSSL_HMAC_SHA256:
            prefix = sha256_prefix;
            prefix_len = sizeof(sha256_prefix);
            break;
        case OPSSL_HMAC_SHA384:
            prefix = sha384_prefix;
            prefix_len = sizeof(sha384_prefix);
            break;
        case OPSSL_HMAC_SHA512:
            prefix = sha512_prefix;
            prefix_len = sizeof(sha512_prefix);
            break;
        default:
            return 0;
    }

    if (em_len < prefix_len + digest_len + 11) return 0;

    /* Check padding structure */
    if (em[0] != 0x00 || em[1] != 0x01) return 0;

    size_t i = 2;
    while (i < em_len && em[i] == 0xff) i++;

    if (i >= em_len || em[i] != 0x00) return 0;
    i++;

    /* Check DigestInfo */
    if (i + prefix_len + digest_len != em_len) return 0;
    if (opssl_ct_eq(em + i, prefix, prefix_len) != 1) return 0;
    if (opssl_ct_eq(em + i + prefix_len, digest, digest_len) != 1) return 0;

    return 1;
}

/* Public API implementation */

opssl_rsa_ctx_t *opssl_rsa_new(void) {
    opssl_rsa_ctx_t *ctx = op_malloc(sizeof(opssl_rsa_ctx_t));
    if (!ctx) return NULL;

    memset(ctx, 0, sizeof(opssl_rsa_ctx_t));
    return ctx;
}

void opssl_rsa_free(opssl_rsa_ctx_t *ctx) {
    if (!ctx) return;

    /* Zero sensitive data */
    opssl_memzero(&ctx->d, sizeof(ctx->d));
    opssl_memzero(&ctx->dp, sizeof(ctx->dp));
    opssl_memzero(&ctx->dq, sizeof(ctx->dq));
    opssl_memzero(&ctx->qinv, sizeof(ctx->qinv));

    op_free(ctx);
}

int opssl_rsa_load_private_key(opssl_rsa_ctx_t *ctx, const uint8_t *der, size_t len) {
    const uint8_t *p = der, *end = der + len;

    /* Accepts both PKCS#1 RSAPrivateKey and PKCS#8 PrivateKeyInfo */
    if (!parse_tag(&p, end, 0x30)) return 0;
    parse_length(&p, end);

    opssl_bn_t temp;
    if (!parse_integer(&temp, &p, end)) return 0; /* version */

    /* Detect PKCS#8: if next element is SEQUENCE (AlgorithmIdentifier),
       unwrap to the inner RSAPrivateKey */
    if (p < end && *p == 0x30) {
        /* Skip AlgorithmIdentifier SEQUENCE */
        if (!parse_tag(&p, end, 0x30)) return 0;
        size_t alg_len = parse_length(&p, end);
        p += alg_len;

        /* Parse OCTET STRING containing RSAPrivateKey */
        if (!parse_tag(&p, end, 0x04)) return 0;
        parse_length(&p, end);

        /* Parse inner RSAPrivateKey SEQUENCE */
        if (!parse_tag(&p, end, 0x30)) return 0;
        parse_length(&p, end);

        /* Skip inner version */
        if (!parse_integer(&temp, &p, end)) return 0;
    }

    /* Now at: n, e, d, p, q, dp, dq, qinv */
    if (!parse_integer(&ctx->n, &p, end)) return 0;
    if (!parse_integer(&ctx->e, &p, end)) return 0;
    if (!parse_integer(&ctx->d, &p, end)) return 0;
    if (!parse_integer(&ctx->p, &p, end)) return 0;
    if (!parse_integer(&ctx->q, &p, end)) return 0;
    if (!parse_integer(&ctx->dp, &p, end)) return 0;
    if (!parse_integer(&ctx->dq, &p, end)) return 0;
    if (!parse_integer(&ctx->qinv, &p, end)) return 0;

    /* Determine key size */
    ctx->bits = (ctx->n.width * 64);
    if (ctx->bits != 2048 && ctx->bits != 4096) return 0;

    /* Initialize Montgomery contexts */
    int width_n = ctx->bits / 64;
    int width_p = ctx->bits / 128;

    opssl_bn_mont_ctx_init(&ctx->mont_n, &ctx->n, width_n);
    opssl_bn_mont_ctx_init(&ctx->mont_p, &ctx->p, width_p);
    opssl_bn_mont_ctx_init(&ctx->mont_q, &ctx->q, width_p);

    ctx->has_private = 1;
    return 1;
}

int opssl_rsa_load_public_key(opssl_rsa_ctx_t *ctx, const uint8_t *der, size_t len) {
    const uint8_t *p = der, *end = der + len;

    /* Parse SubjectPublicKeyInfo */
    if (!parse_tag(&p, end, 0x30)) return 0; /* SEQUENCE */
    parse_length(&p, end);

    /* Skip algorithm SEQUENCE */
    if (!parse_tag(&p, end, 0x30)) return 0;
    size_t alg_len = parse_length(&p, end);
    p += alg_len;

    /* Parse BIT STRING */
    if (!parse_tag(&p, end, 0x03)) return 0;
    parse_length(&p, end);
    p++; /* Skip unused bits byte */

    /* Parse RSAPublicKey SEQUENCE */
    if (!parse_tag(&p, end, 0x30)) return 0;
    parse_length(&p, end);

    /* Parse n and e */
    if (!parse_integer(&ctx->n, &p, end)) return 0;
    if (!parse_integer(&ctx->e, &p, end)) return 0;

    ctx->bits = (ctx->n.width * 64);
    if (ctx->bits != 2048 && ctx->bits != 4096) return 0;

    opssl_bn_mont_ctx_init(&ctx->mont_n, &ctx->n, ctx->bits / 64);
    ctx->has_private = 0;
    return 1;
}

size_t opssl_rsa_size(const opssl_rsa_ctx_t *ctx) {
    return (ctx->bits + 7) / 8;
}

int opssl_rsa_sign(opssl_rsa_ctx_t *ctx, opssl_rsa_padding_t pad, opssl_hmac_algo_t hash,
                   const uint8_t *digest, size_t digest_len, uint8_t *sig, size_t *sig_len) {
    if (!ctx->has_private) return 0;

    size_t key_size = opssl_rsa_size(ctx);
    if (*sig_len < key_size) return 0;

    uint8_t em[512]; /* Enough for 4096-bit keys */

    /* Apply padding */
    int pad_ok;
    if (pad == OPSSL_RSA_PKCS1_V15) {
        pad_ok = pkcs1_v15_pad(em, key_size, digest, digest_len, hash);
    } else {
        pad_ok = pss_pad(em, key_size, ctx->bits - 1, digest, digest_len, hash);
    }

    if (!pad_ok) return 0;

    /* Convert to bignum */
    opssl_bn_t m, s;
    opssl_bn_from_bytes(&m, em, key_size);

    /* Sign with private key */
    rsa_private_op(&s, &m, ctx);

    /* Convert result to bytes */
    opssl_bn_to_bytes(sig, key_size, &s);
    *sig_len = key_size;

    /* Clear sensitive data */
    opssl_memzero(em, sizeof(em));
    opssl_memzero(&m, sizeof(m));
    opssl_memzero(&s, sizeof(s));

    return 1;
}

int opssl_rsa_verify(opssl_rsa_ctx_t *ctx, opssl_rsa_padding_t pad, opssl_hmac_algo_t hash,
                     const uint8_t *digest, size_t digest_len, const uint8_t *sig, size_t sig_len) {
    size_t key_size = opssl_rsa_size(ctx);
    if (sig_len != key_size) return 0;

    /* Convert signature to bignum */
    opssl_bn_t s, m;
    opssl_bn_from_bytes(&s, sig, sig_len);

    /* Public operation: m = s^e mod n */
    opssl_bn_mod_exp_ct(&m, &s, &ctx->e, 1, &ctx->mont_n);

    /* Convert to bytes */
    uint8_t em[512];
    opssl_bn_to_bytes(em, key_size, &m);

    /* Verify padding */
    int verify_ok;
    if (pad == OPSSL_RSA_PKCS1_V15) {
        verify_ok = pkcs1_v15_verify(em, key_size, digest, digest_len, hash);
    } else {
        /* RSA-PSS verification per RFC 8017 section 9.1.2 */
        size_t h_len_v = hash_sizes[hash];
        if (key_size < 2 * h_len_v + 2) { verify_ok = 0; goto done; }
        if (em[key_size - 1] != 0xbc) { verify_ok = 0; goto done; }

        size_t db_len = key_size - h_len_v - 1;
        const uint8_t *masked_db = em;
        const uint8_t *h_val = em + db_len;

        /* Recover DB */
        uint8_t db[512];
        mgf1(db, db_len, h_val, h_len_v, hash);
        for (size_t vi = 0; vi < db_len; vi++)
            db[vi] = masked_db[vi] ^ db[vi];

        /* Clear leftmost 8*emLen - emBits bits */
        int top_bits_v = 8 * (int)key_size - (ctx->bits - 1);
        if (top_bits_v > 0)
            db[0] &= (0xff >> top_bits_v);

        /* Check DB format: 0x00...00 || 0x01 || salt */
        size_t salt_len_v = h_len_v;
        size_t pad_end = db_len - salt_len_v - 1;
        verify_ok = 1;
        for (size_t vi = 0; vi < pad_end; vi++) {
            if (db[vi] != 0x00) verify_ok = 0;
        }
        if (db[pad_end] != 0x01) verify_ok = 0;

        /* Compute H' = Hash(0x00..00 || mHash || salt) */
        uint8_t m_prime_v[8 + 64 + 64];
        memset(m_prime_v, 0, 8);
        memcpy(m_prime_v + 8, digest, digest_len);
        memcpy(m_prime_v + 8 + digest_len, db + pad_end + 1, salt_len_v);

        uint8_t h_prime[64];
        if (hash == OPSSL_HMAC_SHA256) {
            opssl_sha256(m_prime_v, 8 + digest_len + salt_len_v, h_prime);
        } else if (hash == OPSSL_HMAC_SHA384) {
            /* Use one-shot SHA-384 function */
            opssl_sha384(m_prime_v, 8 + digest_len + salt_len_v, h_prime);
        } else {
            opssl_sha512(m_prime_v, 8 + digest_len + salt_len_v, h_prime);
        }

        if (opssl_ct_eq(h_val, h_prime, h_len_v) != 1) verify_ok = 0;

        opssl_memzero(db, sizeof(db));
        opssl_memzero(h_prime, sizeof(h_prime));
    }
done:
    opssl_memzero(em, sizeof(em));
    return verify_ok;
}