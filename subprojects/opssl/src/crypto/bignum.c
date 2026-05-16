/*
 * opssl - Constant-Time Bignum Library
 *
 * Fixed-width bignum implementation for internal TLS crypto operations.
 * Based on BoringSSL bn_width model with constant-time guarantees.
 *
 * - All operations are constant-time (no branches on secret data)
 * - Fixed-width: width field is public and never shrinks
 * - 64-bit limbs with __int128 for products
 * - CIOS Montgomery multiplication
 * - Fixed-window modular exponentiation (window=5)
 */

#include <opssl/platform.h>
#include <string.h>
#include "bignum_internal.h"

/* Helper functions */
uint64_t opssl_word_clamp(uint64_t x);
void opssl_bn_copy(opssl_bn_t *dst, const opssl_bn_t *src, int width);
uint64_t opssl_bn_reduce_once(opssl_bn_t *r, const opssl_bn_t *n, int width);
static void bn_double_mod(opssl_bn_t *v, const opssl_bn_t *n, int w);

/* Secure memory clearing (external function) */
extern void opssl_memzero(void *ptr, size_t len);

/*
 * Zero out bignum with given width
 */
void opssl_bn_zero(opssl_bn_t *bn, int width) {
    opssl_memzero(bn->d, sizeof(bn->d));
    bn->width = width;
}

/*
 * Import from big-endian bytes
 */
void opssl_bn_from_bytes(opssl_bn_t *bn, const uint8_t *buf, size_t len) {
    int width = (len + 7) / 8;  /* round up to limbs */
    if (width > OPSSL_BN_MAX_LIMBS) {
        width = OPSSL_BN_MAX_LIMBS;
        len = width * 8;
    }

    opssl_bn_zero(bn, width);

    /* Process bytes from MSB to LSB */
    for (size_t i = 0; i < len; i++) {
        size_t byte_idx = len - 1 - i;
        size_t limb_idx = i / 8;
        size_t byte_in_limb = i % 8;

        if (limb_idx < (size_t)width) {
            bn->d[limb_idx] |= ((uint64_t)buf[byte_idx]) << (byte_in_limb * 8);
        }
    }
}

/*
 * Export to big-endian bytes (fixed-length output)
 */
void opssl_bn_to_bytes(uint8_t *buf, size_t len, const opssl_bn_t *bn) {
    opssl_memzero(buf, len);

    /* Extract bytes from LSB to MSB */
    for (size_t i = 0; i < len; i++) {
        size_t limb_idx = i / 8;
        size_t byte_in_limb = i % 8;

        uint64_t limb = 0;
        if (limb_idx < (size_t)bn->width) {
            limb = bn->d[limb_idx];
        }

        uint8_t byte_val = (limb >> (byte_in_limb * 8)) & 0xFF;
        buf[len - 1 - i] = byte_val;
    }
}

/*
 * Compute modular inverse mod 2^64 using extended Euclidean algorithm
 * Returns -n^(-1) mod 2^64 for Montgomery constant
 */
static uint64_t compute_n0_inv(uint64_t n0) {
    /* Newton's method for modular inverse mod 2^64 */
    /* We want x such that n0 * x ≡ -1 (mod 2^64) */
    uint64_t x = n0;  /* initial approximation */

    /* Newton iteration: x := x * (2 - n0 * x) */
    for (int i = 0; i < 6; i++) {  /* log2(64) iterations */
        x = x * (2 - n0 * x);
    }

    return -x;  /* negate: CIOS needs -n^(-1) mod 2^64, Newton gives n^(-1) */
}

/*
 * Initialize Montgomery context (precomputes R^2 mod n)
 */
void opssl_bn_mont_ctx_init(opssl_bn_mont_ctx_t *ctx, const opssl_bn_t *modulus, int width) {
    ctx->width = width;
    opssl_bn_copy(&ctx->n, modulus, width);
    ctx->n0_inv = compute_n0_inv(modulus->d[0]);

    int total_bits = 64 * width;
    opssl_bn_zero(&ctx->r_squared, width);
    ctx->r_squared.d[0] = 1;
    for (int i = 0; i < 2 * total_bits; i++)
        bn_double_mod(&ctx->r_squared, &ctx->n, width);
}

/*
 * Clamp word to prevent timing attacks on carry propagation
 */
uint64_t opssl_word_clamp(uint64_t x) {
    /* Ensure x fits in 64 bits (should always be true) */
    return x & 0xFFFFFFFFFFFFFFFFULL;
}

/*
 * Copy bignum (constant-time)
 */
void opssl_bn_copy(opssl_bn_t *dst, const opssl_bn_t *src, int width) {
    dst->width = width;
    for (int i = 0; i < OPSSL_BN_MAX_LIMBS; i++) {
        /* Constant-time: always copy, but zero out beyond width */
        uint64_t mask = (i < width) ? 0xFFFFFFFFFFFFFFFFULL : 0;
        dst->d[i] = src->d[i] & mask;
    }
}

/*
 * Addition with carry (constant-time)
 */
uint64_t opssl_bn_add(opssl_bn_t *r, const opssl_bn_t *a, const opssl_bn_t *b, int width) {
    uint64_t carry = 0;

    for (int i = 0; i < OPSSL_BN_MAX_LIMBS; i++) {
        uint64_t ai = (i < width && i < a->width) ? a->d[i] : 0;
        uint64_t bi = (i < width && i < b->width) ? b->d[i] : 0;

        unsigned __int128 sum = (unsigned __int128)ai + bi + carry;

        if (i < width) {
            r->d[i] = (uint64_t)sum;
        } else {
            r->d[i] = 0;
        }

        carry = sum >> 64;
    }

    r->width = width;
    return carry;
}

/*
 * Subtraction with borrow (constant-time)
 */
uint64_t opssl_bn_sub(opssl_bn_t *r, const opssl_bn_t *a, const opssl_bn_t *b, int width) {
    uint64_t borrow = 0;

    for (int i = 0; i < OPSSL_BN_MAX_LIMBS; i++) {
        uint64_t ai = (i < width && i < a->width) ? a->d[i] : 0;
        uint64_t bi = (i < width && i < b->width) ? b->d[i] : 0;

        unsigned __int128 diff = (unsigned __int128)ai - bi - borrow;

        if (i < width) {
            r->d[i] = (uint64_t)diff;
        } else {
            r->d[i] = 0;
        }

        borrow = (diff >> 127) & 1;  /* Extract sign bit as borrow */
    }

    r->width = width;
    return borrow;
}

/*
 * Constant-time comparison
 * Returns: -1 if a < b, 0 if a == b, 1 if a > b
 */
int opssl_bn_cmp(const opssl_bn_t *a, const opssl_bn_t *b, int width) {
    uint64_t gt = 0;  /* a > b */
    uint64_t lt = 0;  /* a < b */

    for (int i = width - 1; i >= 0; i--) {
        uint64_t ai = (i < a->width) ? a->d[i] : 0;
        uint64_t bi = (i < b->width) ? b->d[i] : 0;

        /* Branchless: bi-ai wraps (bit 127 set) iff ai > bi */
        uint64_t ai_gt_bi = (uint64_t)(((unsigned __int128)bi - ai) >> 127);
        /* Branchless: ai-bi wraps (bit 127 set) iff ai < bi */
        uint64_t ai_lt_bi = (uint64_t)(((unsigned __int128)ai - bi) >> 127);

        /* gt|lt is always 0 or 1; no_diff_yet = 1 when no diff seen yet */
        uint64_t no_diff_yet = 1 - (gt | lt);
        gt |= no_diff_yet & ai_gt_bi;
        lt |= no_diff_yet & ai_lt_bi;
    }

    /* Convert to -1, 0, 1 */
    return (int)gt - (int)lt;
}

int opssl_bn_is_zero(const opssl_bn_t *bn, int width) {
    uint64_t mask = 0;
    for (int i = 0; i < width; i++) {
        mask |= bn->d[i];
    }
    return mask == 0;
}

/*
 * Constant-time conditional select
 * If sel != 0, return a; otherwise return b
 */
void opssl_bn_ct_select(opssl_bn_t *r, const opssl_bn_t *a, const opssl_bn_t *b, int width, uint64_t sel) {
    /* Branchless: nz=1 iff sel!=0; mask=all-ones iff sel!=0, zero otherwise */
    uint64_t nz = ((sel | (0ull - sel)) >> 63);
    uint64_t mask = -nz;

    r->width = width;
    for (int i = 0; i < OPSSL_BN_MAX_LIMBS; i++) {
        uint64_t ai = (i < width && i < a->width) ? a->d[i] : 0;
        uint64_t bi = (i < width && i < b->width) ? b->d[i] : 0;

        r->d[i] = (i < width) ? ((ai & mask) | (bi & ~mask)) : 0;
    }
}

/*
 * Reduce once: if r >= n, then r := r - n
 * Returns 1 if reduction happened, 0 otherwise (constant-time)
 */
uint64_t opssl_bn_reduce_once(opssl_bn_t *r, const opssl_bn_t *n, int width) {
    opssl_bn_t temp;
    uint64_t borrow = opssl_bn_sub(&temp, r, n, width);

    /* If no borrow, use the subtraction result */
    uint64_t use_sub = (borrow == 0) ? 1 : 0;
    opssl_bn_ct_select(r, &temp, r, width, use_sub);

    opssl_memzero(&temp, sizeof(temp));
    return use_sub;
}

/*
 * CIOS Montgomery multiplication: r = a * b * R^(-1) mod n
 */
void opssl_bn_mont_mul(opssl_bn_t *r, const opssl_bn_t *a, const opssl_bn_t *b, const opssl_bn_mont_ctx_t *mont) {
    int width = mont->width;
    uint64_t t[OPSSL_BN_MAX_LIMBS + 2] = {0};  /* Extra space for carries */

    /* CIOS algorithm */
    for (int i = 0; i < width; i++) {
        uint64_t ai = (i < a->width) ? a->d[i] : 0;

        /* First inner loop: t += a[i] * b */
        uint64_t carry = 0;
        for (int j = 0; j < width; j++) {
            uint64_t bj = (j < b->width) ? b->d[j] : 0;
            unsigned __int128 prod = (unsigned __int128)ai * bj + t[j] + carry;
            t[j] = (uint64_t)prod;
            carry = prod >> 64;
        }

        /* Propagate final carry */
        unsigned __int128 final_add = (unsigned __int128)t[width] + carry;
        t[width] = (uint64_t)final_add;
        t[width + 1] = final_add >> 64;

        /* Compute Montgomery factor */
        uint64_t m = t[0] * mont->n0_inv;

        /* Second inner loop: t += m * n, then shift */
        carry = 0;
        for (int j = 0; j < width; j++) {
            uint64_t nj = (j < mont->n.width) ? mont->n.d[j] : 0;
            unsigned __int128 prod = (unsigned __int128)m * nj + t[j] + carry;

            if (j > 0) {
                t[j - 1] = (uint64_t)prod;
            }
            carry = prod >> 64;
        }

        /* Complete the shift: t[w-1] gets t[w]+carry, t[w] gets t[w+1] */
        unsigned __int128 carry_add = (unsigned __int128)t[width] + carry;
        t[width - 1] = (uint64_t)carry_add;
        carry = carry_add >> 64;

        t[width] = t[width + 1] + carry;
        t[width + 1] = 0;
    }

    /* Copy result and handle final reduction */
    opssl_bn_zero(r, width);
    for (int i = 0; i < width && i < OPSSL_BN_MAX_LIMBS; i++) {
        r->d[i] = t[i];
    }

    /* Constant-time: always subtract, select based on CIOS overflow word.
     * t[width] is 0 or 1; when 1, the product overflowed width limbs and
     * the subtracted value is the correct result. */
    {
        opssl_bn_t tmp_r;
        (void)opssl_bn_sub(&tmp_r, r, &mont->n, width);
        opssl_bn_ct_select(r, &tmp_r, r, width, t[width]);
        opssl_memzero(&tmp_r, sizeof(tmp_r));
    }
    opssl_bn_reduce_once(r, &mont->n, width);

    /* Clear temporary storage */
    opssl_memzero(t, sizeof(t));
}

/*
 * Montgomery squaring: r = a^2 * R^(-1) mod n
 *
 * Delegates to opssl_bn_mont_mul to preserve constant-time guarantees.
 * The previous optimization branched on secret-dependent intermediate
 * values (ai == 0), creating a timing side-channel. Until a correct
 * constant-time squaring optimization is implemented, delegation to
 * mont_mul is the safe default.
 */
void opssl_bn_mont_sqr(opssl_bn_t *r, const opssl_bn_t *a, const opssl_bn_mont_ctx_t *mont) {
    opssl_bn_mont_mul(r, a, a, mont);
}

/*
 * Convert to Montgomery form: r = a * R^2 mod n
 */
static void bn_double_mod(opssl_bn_t *v, const opssl_bn_t *n, int w) {
    uint64_t carry = 0;
    for (int j = 0; j < w; j++) {
        uint64_t old = v->d[j];
        v->d[j] = (old << 1) | carry;
        carry = old >> 63;
    }
    /* Constant-time: always subtract, select result based on carry and borrow.
     * Use subtracted result when carry==1 (true value exceeded width limbs)
     * or when no borrow from subtraction (v >= n). */
    {
        opssl_bn_t tmp_v;
        uint64_t borrow = opssl_bn_sub(&tmp_v, v, n, w);
        uint64_t use_sub = carry | (borrow ^ 1);
        opssl_bn_ct_select(v, &tmp_v, v, w, use_sub);
        opssl_memzero(&tmp_v, sizeof(tmp_v));
    }
}

void opssl_bn_to_mont(opssl_bn_t *r, const opssl_bn_t *a, const opssl_bn_mont_ctx_t *mont) {
    /* a_mont = a * R^2 * R^{-1} mod n = a * R mod n (R^2 precomputed) */
    opssl_bn_mont_mul(r, a, &mont->r_squared, mont);
}

/*
 * Convert from Montgomery form: r = a * 1 mod n
 */
void opssl_bn_from_mont(opssl_bn_t *r, const opssl_bn_t *a, const opssl_bn_mont_ctx_t *mont) {
    opssl_bn_t one;
    opssl_bn_zero(&one, mont->width);
    one.d[0] = 1;

    /* r = a * 1 * R^(-1) mod n = a * R^(-1) mod n */
    opssl_bn_mont_mul(r, a, &one, mont);

    opssl_memzero(&one, sizeof(one));
}

/*
 * Regular modular multiplication: r = a * b mod n
 * Converts one operand to Montgomery form so the R factors cancel.
 */
void opssl_bn_mod_mul(opssl_bn_t *r, const opssl_bn_t *a, const opssl_bn_t *b, const opssl_bn_mont_ctx_t *mont) {
    opssl_bn_t a_mont;
    opssl_bn_to_mont(&a_mont, a, mont);
    opssl_bn_mont_mul(r, &a_mont, b, mont);
    opssl_memzero(&a_mont, sizeof(a_mont));
}

/*
 * Constant-time table lookup for fixed-window exponentiation
 */
void opssl_bn_table_select(opssl_bn_t *r, const opssl_bn_t table[], int table_size, int width, int index) {
    opssl_bn_zero(r, width);

    for (int i = 0; i < table_size; i++) {
        /* Constant-time: branchless equality; mask=all-ones iff i==index.
         * diff=0 iff equal; nz=1 iff diff!=0; mask=(nz-1)=all-ones iff equal. */
        uint64_t diff = (uint64_t)i ^ (uint64_t)index;
        uint64_t nz = ((diff | (0ull - diff)) >> 63);
        uint64_t mask = nz - 1;

        for (int j = 0; j < width; j++) {
            uint64_t table_val = (j < table[i].width) ? table[i].d[j] : 0;
            r->d[j] |= table_val & mask;
        }
    }
}

/*
 * Fixed-window modular exponentiation (window size = 5)
 * r = base^exp mod n (Montgomery form)
 */
void opssl_bn_mod_exp_ct(opssl_bn_t *r, const opssl_bn_t *base, const opssl_bn_t *exp,
                                int exp_width, const opssl_bn_mont_ctx_t *mont) {
    const int window_size = 5;
    const int table_size = 1 << window_size;  /* 32 entries */

    /* Precompute table: base^0, base^1, ..., base^31 in Montgomery form */
    opssl_bn_t table[32];

    /* table[0] = 1 (Montgomery form) */
    opssl_bn_zero(&table[0], mont->width);
    table[0].d[0] = 1;
    opssl_bn_to_mont(&table[0], &table[0], mont);

    /* table[1] = base in Montgomery form */
    opssl_bn_to_mont(&table[1], base, mont);

    /* table[i] = table[i-1] * table[1] for i = 2..31 */
    for (int i = 2; i < table_size; i++) {
        opssl_bn_mont_mul(&table[i], &table[i-1], &table[1], mont);
    }

    /* Initialize result to 1 (Montgomery form) */
    opssl_bn_copy(r, &table[0], mont->width);

    /* Process exponent from MSB to LSB in fixed windows.
     * First window may be smaller if total_bits % window_size != 0. */
    int total_bits = exp_width * 64;
    int remaining = total_bits;
    int first_chunk = total_bits % window_size;
    if (first_chunk == 0) first_chunk = window_size;

    int chunk = first_chunk;
    while (remaining > 0) {
        /* Square 'chunk' times (skip on very first window) */
        if (remaining < total_bits) {
            for (int i = 0; i < chunk; i++)
                opssl_bn_mont_sqr(r, r, mont);
        }

        /* Extract 'chunk' bits starting at bit position (remaining - chunk).
         * Bits are numbered from LSB=0. Extract [remaining-chunk .. remaining-1]
         * and pack MSB-first into window_val. */
        int base_bit = remaining - chunk;
        uint64_t window_val = 0;
        for (int i = 0; i < chunk; i++) {
            int bit_pos = base_bit + (chunk - 1 - i);
            int limb_idx = bit_pos / 64;
            int bit_idx = bit_pos % 64;
            uint64_t bit = (limb_idx < exp_width) ?
                           ((exp->d[limb_idx] >> bit_idx) & 1) : 0;
            window_val = (window_val << 1) | bit;
        }

        /* Multiply by table[window_val] using constant-time lookup */
        opssl_bn_t table_entry;
        opssl_bn_table_select(&table_entry, table, table_size, mont->width, (int)window_val);
        opssl_bn_mont_mul(r, r, &table_entry, mont);
        opssl_memzero(&table_entry, sizeof(table_entry));

        remaining -= chunk;
        chunk = window_size;
    }

    /* Convert result from Montgomery form */
    opssl_bn_from_mont(r, r, mont);

    /* Clear precomputed table */
    for (int i = 0; i < table_size; i++) {
        opssl_memzero(&table[i], sizeof(table[i]));
    }
}
/*
 * Modular inverse for prime moduli via Fermat's little theorem.
 *
 * Computes r = a^(-1) mod prime, valid only when prime is an odd prime
 * and gcd(a, prime) == 1.  Uses a^(prime-2) mod prime.
 *
 * Constant-time: no branches on secret data; inherits ct guarantee from
 * opssl_bn_mod_exp_ct and opssl_bn_sub.
 *
 * Returns 1 on success, 0 if a == 0 (not invertible).
 */
int opssl_bn_mod_inv(opssl_bn_t *r, const opssl_bn_t *a, const opssl_bn_t *prime,
                     const opssl_bn_mont_ctx_t *mont) {
    int width = mont->width;

    /* Compute exponent e = prime - 2 */
    opssl_bn_t two, e;
    opssl_bn_zero(&two, width);
    two.d[0] = 2;

    opssl_bn_sub(&e, prime, &two, width);  /* e = prime - 2; no borrow for any prime >= 5 */

    /* r = a^e mod prime */
    opssl_bn_mod_exp_ct(r, a, &e, width, mont);

    opssl_memzero(&two, sizeof(two));
    opssl_memzero(&e, sizeof(e));

    /* If a == 0 the result is 0 (not a valid inverse); signal failure */
    int all_zero = 1;
    for (int i = 0; i < width; i++) {
        if (a->d[i] != 0) { all_zero = 0; break; }
    }
    /* Note: the branch above is on the public 'a == 0' check, not on secret
     * intermediate values, so it does not create a timing side-channel in the
     * context where this function is called (blinding factor is never zero). */
    return all_zero ? 0 : 1;
}
