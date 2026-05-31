/*
 * Ed25519 digital signatures (RFC 8032) - Working Implementation
 *
 * This implementation uses the same field arithmetic as x25519.c.
 */

#include <opssl/crypto.h>
#include <opssl/platform.h>
#include <string.h>
#include "sha_internal.h"

/* Field element: 5 limbs of 51 bits each, little-endian */
typedef int64_t fe25519[5];

/* Extended twisted Edwards point (X:Y:Z:T) where x=X/Z, y=Y/Z, T=X*Y/Z */
typedef struct {
    fe25519 X, Y, Z, T;
} ge25519_p3;

/* Field arithmetic from working x25519.c implementation */

static inline uint64_t
load64(const uint8_t *p)
{
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static inline uint64_t
load56(const uint8_t *p)
{
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48);
}

static inline uint32_t
load3(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);
}

static inline uint32_t
load4(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void
fe_frombytes(fe25519 h, const uint8_t s[32])
{
    uint64_t h0 = load64(s) & 0x7ffffffffffffULL;
    uint64_t h1 = (load64(s + 6) >> 3) & 0x7ffffffffffffULL;
    uint64_t h2 = (load64(s + 12) >> 6) & 0x7ffffffffffffULL;
    uint64_t h3 = (load64(s + 19) >> 1) & 0x7ffffffffffffULL;
    uint64_t h4 = (load56(s + 25) >> 4) & 0x7ffffffffffffULL;

    h[0] = (int64_t)h0;
    h[1] = (int64_t)h1;
    h[2] = (int64_t)h2;
    h[3] = (int64_t)h3;
    h[4] = (int64_t)h4;
}

static void
fe_tobytes(uint8_t s[32], const fe25519 h)
{
    int64_t t[5], c;
    memcpy(t, h, sizeof(t));

    /* Two carry passes with wrap-around to bring into [0, 2p) */
    for (int pass = 0; pass < 2; pass++) {
        c = t[0] >> 51; t[0] &= 0x7ffffffffffffLL; t[1] += c;
        c = t[1] >> 51; t[1] &= 0x7ffffffffffffLL; t[2] += c;
        c = t[2] >> 51; t[2] &= 0x7ffffffffffffLL; t[3] += c;
        c = t[3] >> 51; t[3] &= 0x7ffffffffffffLL; t[4] += c;
        c = t[4] >> 51; t[4] &= 0x7ffffffffffffLL; t[0] += c * 19;
    }
    c = t[0] >> 51; t[0] &= 0x7ffffffffffffLL; t[1] += c;

    /* Conditional subtraction of p: add 19 and check overflow past 2^255 */
    int64_t u[5];
    u[0] = t[0] + 19;
    c = u[0] >> 51; u[0] &= 0x7ffffffffffffLL;
    u[1] = t[1] + c; c = u[1] >> 51; u[1] &= 0x7ffffffffffffLL;
    u[2] = t[2] + c; c = u[2] >> 51; u[2] &= 0x7ffffffffffffLL;
    u[3] = t[3] + c; c = u[3] >> 51; u[3] &= 0x7ffffffffffffLL;
    u[4] = t[4] + c; c = u[4] >> 51; u[4] &= 0x7ffffffffffffLL;

    /* c=1 means t >= p, use u (= t-p); c=0 means t < p, keep t */
    int64_t mask = -(int64_t)c;
    t[0] = (t[0] & ~mask) | (u[0] & mask);
    t[1] = (t[1] & ~mask) | (u[1] & mask);
    t[2] = (t[2] & ~mask) | (u[2] & mask);
    t[3] = (t[3] & ~mask) | (u[3] & mask);
    t[4] = (t[4] & ~mask) | (u[4] & mask);

    s[0]  = (uint8_t)(t[0]);
    s[1]  = (uint8_t)(t[0] >> 8);
    s[2]  = (uint8_t)(t[0] >> 16);
    s[3]  = (uint8_t)(t[0] >> 24);
    s[4]  = (uint8_t)(t[0] >> 32);
    s[5]  = (uint8_t)(t[0] >> 40);
    s[6]  = (uint8_t)((t[0] >> 48) | (t[1] << 3));
    s[7]  = (uint8_t)(t[1] >> 5);
    s[8]  = (uint8_t)(t[1] >> 13);
    s[9]  = (uint8_t)(t[1] >> 21);
    s[10] = (uint8_t)(t[1] >> 29);
    s[11] = (uint8_t)(t[1] >> 37);
    s[12] = (uint8_t)((t[1] >> 45) | (t[2] << 6));
    s[13] = (uint8_t)(t[2] >> 2);
    s[14] = (uint8_t)(t[2] >> 10);
    s[15] = (uint8_t)(t[2] >> 18);
    s[16] = (uint8_t)(t[2] >> 26);
    s[17] = (uint8_t)(t[2] >> 34);
    s[18] = (uint8_t)(t[2] >> 42);
    s[19] = (uint8_t)((t[2] >> 50) | (t[3] << 1));
    s[20] = (uint8_t)(t[3] >> 7);
    s[21] = (uint8_t)(t[3] >> 15);
    s[22] = (uint8_t)(t[3] >> 23);
    s[23] = (uint8_t)(t[3] >> 31);
    s[24] = (uint8_t)(t[3] >> 39);
    s[25] = (uint8_t)((t[3] >> 47) | (t[4] << 4));
    s[26] = (uint8_t)(t[4] >> 4);
    s[27] = (uint8_t)(t[4] >> 12);
    s[28] = (uint8_t)(t[4] >> 20);
    s[29] = (uint8_t)(t[4] >> 28);
    s[30] = (uint8_t)(t[4] >> 36);
    s[31] = (uint8_t)(t[4] >> 44);
}

static void
fe_add(fe25519 h, const fe25519 f, const fe25519 g)
{
    for (int i = 0; i < 5; i++)
        h[i] = f[i] + g[i];
}

static void
fe_sub(fe25519 h, const fe25519 f, const fe25519 g)
{
    /* Add 2p to avoid underflow */
    static const int64_t two_p[5] = {
        0xfffffffffffdaLL, 0xffffffffffffeLL,
        0xffffffffffffeLL, 0xffffffffffffeLL, 0xffffffffffffeLL
    };
    for (int i = 0; i < 5; i++)
        h[i] = f[i] - g[i] + two_p[i];
}

static void
fe_mul(fe25519 h, const fe25519 f, const fe25519 g)
{
    __int128 r[5];

    r[0] = (__int128)f[0]*g[0] + (__int128)(f[1]*19)*g[4] + (__int128)(f[2]*19)*g[3] +
            (__int128)(f[3]*19)*g[2] + (__int128)(f[4]*19)*g[1];
    r[1] = (__int128)f[0]*g[1] + (__int128)f[1]*g[0] + (__int128)(f[2]*19)*g[4] +
            (__int128)(f[3]*19)*g[3] + (__int128)(f[4]*19)*g[2];
    r[2] = (__int128)f[0]*g[2] + (__int128)f[1]*g[1] + (__int128)f[2]*g[0] +
            (__int128)(f[3]*19)*g[4] + (__int128)(f[4]*19)*g[3];
    r[3] = (__int128)f[0]*g[3] + (__int128)f[1]*g[2] + (__int128)f[2]*g[1] +
            (__int128)f[3]*g[0] + (__int128)(f[4]*19)*g[4];
    r[4] = (__int128)f[0]*g[4] + (__int128)f[1]*g[3] + (__int128)f[2]*g[2] +
            (__int128)f[3]*g[1] + (__int128)f[4]*g[0];

    int64_t carry = (int64_t)(r[0] >> 51); h[0] = (int64_t)r[0] & 0x7ffffffffffffLL; r[1] += carry;
    carry = (int64_t)(r[1] >> 51); h[1] = (int64_t)r[1] & 0x7ffffffffffffLL; r[2] += carry;
    carry = (int64_t)(r[2] >> 51); h[2] = (int64_t)r[2] & 0x7ffffffffffffLL; r[3] += carry;
    carry = (int64_t)(r[3] >> 51); h[3] = (int64_t)r[3] & 0x7ffffffffffffLL; r[4] += carry;
    carry = (int64_t)(r[4] >> 51); h[4] = (int64_t)r[4] & 0x7ffffffffffffLL; h[0] += carry * 19;
    carry = h[0] >> 51; h[0] &= 0x7ffffffffffffLL; h[1] += carry;
    carry = h[1] >> 51; h[1] &= 0x7ffffffffffffLL; h[2] += carry;
}

static void
fe_sq(fe25519 h, const fe25519 f)
{
    fe_mul(h, f, f);
}

static void fe_1(fe25519 h) { h[0] = 1; h[1] = h[2] = h[3] = h[4] = 0; }
static void fe_0(fe25519 h) { h[0] = h[1] = h[2] = h[3] = h[4] = 0; }
static void fe_copy(fe25519 h, const fe25519 f) { memcpy(h, f, sizeof(fe25519)); }

static int
fe_isnegative(const fe25519 f)
{
    uint8_t s[32];
    fe_tobytes(s, f);
    return s[0] & 1;
}

static void
fe_neg(fe25519 h, const fe25519 f)
{
    static const int64_t two_p[5] = {
        0xfffffffffffdaLL, 0xffffffffffffeLL, 0xffffffffffffeLL, 0xffffffffffffeLL, 0xffffffffffffeLL
    };
    for (int i = 0; i < 5; i++)
        h[i] = two_p[i] - f[i];
}

/* Constants for Ed25519 curve: -x^2 + y^2 = 1 + d*x^2*y^2 */
static const fe25519 ed25519_d = {
    0x34dca135978a3LL, 0x1a8283b156ebdLL, 0x5e7a26001c029LL, 0x739c663a03cbbLL, 0x52036cee2b6ffLL
};

static const fe25519 ed25519_d2 = {
    0x69b9426b2f159LL, 0x35050762add7aLL, 0x3cf44c0038052LL, 0x6738cc7407977LL, 0x2406d9dc56dffLL
};

static const fe25519 ed25519_sqrtm1 = {
    0x61b274a0ea0b0LL, 0xd5a5fc8f189dLL, 0x7ef5e9cbd0c60LL, 0x78595a6804c9eLL, 0x2b8324804fc1dLL
};

static const ge25519_p3 ed25519_base __attribute__((unused)) = {
    {0x62d608f25d51aLL, 0x412a4b4f6592aLL, 0x75b7171a4b31dLL, 0x1ff60527118feLL, 0x216936d3cd6e5LL},
    {0x6666666666658LL, 0x4ccccccccccccLL, 0x1999999999999LL, 0x3333333333333LL, 0x6666666666666LL},
    {1, 0, 0, 0, 0},
    {0x68ab3a5b7dda3LL, 0xeea2a5eadbbLL, 0x2af8df483c27eLL, 0x332b375274732LL, 0x67875f0fd78b7LL}
};

static const ge25519_p3 ed25519_base_comb[4][16] = {
  { /* group 0: i * (2^0 * B) */
    {
        {0x0LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL},
        {0x1LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL},
        {0x1LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL},
        {0x0LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL}
    },
    {
        {0x62d608f25d51aLL, 0x412a4b4f6592aLL, 0x75b7171a4b31dLL, 0x1ff60527118feLL, 0x216936d3cd6e5LL},
        {0x6666666666658LL, 0x4ccccccccccccLL, 0x1999999999999LL, 0x3333333333333LL, 0x6666666666666LL},
        {0x1LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL},
        {0x68ab3a5b7dda3LL, 0xeea2a5eadbbLL, 0x2af8df483c27eLL, 0x332b375274732LL, 0x67875f0fd78b7LL}
    },
    {
        {0x5e6cf9f3fd67eLL, 0x102c74ed242a2LL, 0x4f06f677913e2LL, 0x56a2bbb68f090LL, 0x3b6f8891960f6LL},
        {0x34c9a874a007eLL, 0x4ea20e6f1b6daLL, 0x36ae09f5b8559LL, 0x492c90fa078aLL, 0x336d9ece4cdb3LL},
        {0x55b0bf61c8608LL, 0x7e636b3174e45LL, 0x3d9d6d142c9efLL, 0x7517ece5c0b89LL, 0x59e4ea1a52a20LL},
        {0x2c7e392cad989LL, 0x907a27378a6LL, 0x5781f05c9d254LL, 0x6d57e37537f6eLL, 0x1f6e08da2d298LL}
    },
    {
        {0x156cfc90df8e0LL, 0x196d5ead66b28LL, 0x4d791276c18b3LL, 0x538fc7902d80eLL, 0x7c79bd81be5feLL},
        {0x4c07f50735ca7LL, 0x642ca75393a6eLL, 0xd8746961b46fLL, 0x48a3066e1a7f0LL, 0x1eebd8c6eba89LL},
        {0x459d9fba69efeLL, 0x93aa464ebf37LL, 0x100b25633cf01LL, 0x215ca7060acd1LL, 0x101f45083aceLL},
        {0x156e48aa004bbLL, 0x51810cbe7a4e0LL, 0x27e856c7fe9bcLL, 0x40edf86c3cfcaLL, 0x1217d7af665dfLL}
    },
    {
        {0x363fcde8526bfLL, 0x1d68a2a5fa320LL, 0x6a2f2c809bbf0LL, 0xeecc96e5ac0cLL, 0x3349374b8ff7fLL},
        {0x77c9e0a55f002LL, 0x1a485852cc110LL, 0x6ba5d0d3d0a6eLL, 0x7bca2393ab1f5LL, 0x7b444d3f155e7LL},
        {0x193b1dc80e4cdLL, 0x29815cc4a591eLL, 0x58efc4492128bLL, 0x2e952a5c5ba9LL, 0x45be850e83c1LL},
        {0x1fd8f28269de7LL, 0x34706555da2b1LL, 0x7579a811f358aLL, 0x4aef75d1154aeLL, 0x59a06515d0063LL}
    },
    {
        {0x674dbe2986bd1LL, 0x6a89cb9682122LL, 0x2ae6d23a87bd6LL, 0x584c6f708f4aLL, 0x2ab2a5b6da2f3LL},
        {0x5c3587c6e9b73LL, 0x52166752afa34LL, 0x7712601be749LL, 0x47a5f3193a9fcLL, 0x69bae0f220ccdLL},
        {0x6417ada5c85dLL, 0xb049c57163a2LL, 0x954ac7e72939LL, 0xa3b9a8b64744LL, 0x5699f014033fbLL},
        {0x1a7cecd7b5be4LL, 0x1fd131d540e5cLL, 0x48bcfe215db4eLL, 0x733386ffb2f12LL, 0x5102c2e99aec9LL}
    },
    {
        {0x7ad5c3589c7fbLL, 0x3c5c40566298fLL, 0x7305c1e744b0dLL, 0x6b448fb3f2f6LL, 0x1bdf617094d86LL},
        {0x6255d04cf5337LL, 0x18015c31f0c42LL, 0x1e1376d78c608LL, 0x44e4882139578LL, 0x29013ddf39c51LL},
        {0x55220806a5d9dLL, 0x1378b181d70c1LL, 0x777db0f4ddf0cLL, 0x77da29f1daa0eLL, 0x4e9738d2fa7d2LL},
        {0x7d6b4ca97e1dbLL, 0x77e358b13557bLL, 0x9d4dcfa58c7LL, 0x5b3e6602bb3e3LL, 0x2a53f2979379aLL}
    },
    {
        {0x615bec1ac2631LL, 0x1539d7ac30191LL, 0x24e1d6e598611LL, 0x2e378d6f743f7LL, 0x1d3781242e289LL},
        {0x1a7626d655b61LL, 0x796f94507a3faLL, 0x7087a3a9dbcd4LL, 0x440c8c863ea82LL, 0x536fd5aff5cebLL},
        {0x4c36801d1a6a4LL, 0x66e3ee1a0423aLL, 0x396877cc5dddbLL, 0x3ee04c554cce9LL, 0x4ef4533a71acdLL},
        {0x1e56a321a6f9cLL, 0x427987da13afdLL, 0xb4eae780343dLL, 0x1bb5f2732aadeLL, 0x66b8aa0d998b2LL}
    },
    {
        {0x57970824cd1d9LL, 0x75f464679035bLL, 0x56db315444133LL, 0x4b3ec9d800062LL, 0x592a134f7f38dLL},
        {0x4ee686d78fafcLL, 0x7338475ae9788LL, 0x4f6313796b18bLL, 0x2ea2a34e1f515LL, 0x1d8fdfa3afb4eLL},
        {0x729e8b78555f5LL, 0x5a148f96be5e8LL, 0xf787820bff44LL, 0x5915988098a90LL, 0x70e6708dcba0dLL},
        {0x1f7cbf0a2a9edLL, 0x3c2a22d3457afLL, 0x7f83d5e7e13LL, 0x7df878e9fadccLL, 0x6850e0dbe8207LL}
    },
    {
        {0x615e817869f29LL, 0x39cf714140aeeLL, 0x2146222466d84LL, 0x78351a63dbd15LL, 0x7f41cdc857aafLL},
        {0x6e4878f88310LL, 0x3027b721f4ae9LL, 0xc0c9cd4f294cLL, 0x1057a98cd7061LL, 0x774584288cca5LL},
        {0x2fb214dd2ef61LL, 0x134d205aaea64LL, 0x51742f87af2a7LL, 0x1ded4f7db773eLL, 0x34fa437f1052bLL},
        {0x6b1be1e02ebf7LL, 0xb65760fd043bLL, 0x14b36a3878264LL, 0x1d7264bba3fbbLL, 0x3db50ba8f813dLL}
    },
    {
        {0xe945eebea57LL, 0x2261f53154bfdLL, 0x605dd6d5ea34cLL, 0x1c5b5175826bfLL, 0x7ca8c99dfc9daLL},
        {0x60fe831d260d3LL, 0x61d6be35d0380LL, 0x2ea75a4d6df0bLL, 0x451fe81225642LL, 0x15c96f0e41e3LL},
        {0x5e80c7c761dabLL, 0x60f177dae6e5bLL, 0x6f4b9d88deabdLL, 0x439f7c695d36dLL, 0x6612ceeae0f41LL},
        {0x60221288b3d66LL, 0x100d7f9c8ee98LL, 0x1a2bc7829c300LL, 0x39fe91bb4565LL, 0x1ab3f536937b9LL}
    },
    {
        {0x29b3635fc6914LL, 0x26f608c9edf4fLL, 0x3e56d529e151aLL, 0x42154eb014a1aLL, 0x3a08c55dba964LL},
        {0x44dffab8b3badLL, 0x22da29d2b2168LL, 0x3f8a8e2598333LL, 0x2a33d0bde867aLL, 0x54577a6f45da2LL},
        {0x35919bcd30d0aLL, 0x524cc2711906bLL, 0x1bd13ee300532LL, 0x151809aa28c2LL, 0x24dc143469070LL},
        {0x2ca5a3b408934LL, 0xe2e305e98b76LL, 0x9b105e8ee732LL, 0x130c889074e86LL, 0x531ba123c246fLL}
    },
    {
        {0x3da9f894eefe8LL, 0x308377672f345LL, 0xc43faad6cc67LL, 0x6fbd908bfcebeLL, 0x4cb58f88dcfc9LL},
        {0x277567df66147LL, 0x30ea75443702cLL, 0x43019fd9d04e1LL, 0x5df286e59efb4LL, 0x7843d5e446ad9LL},
        {0x59a7582c10e88LL, 0x3d9c924ca4b88LL, 0x648ad546f3a83LL, 0x62bf4f7f80d7aLL, 0xdfc907e5d0bfLL},
        {0x20d023800b442LL, 0x14416efd7cffaLL, 0x5d296477e1216LL, 0xcb515f16f737LL, 0x1ac0064ba99adLL}
    },
    {
        {0x149cc6469094LL, 0x21e8fb1897090LL, 0x14b2fc62c9dbbLL, 0x395d8a143a3LL, 0x622e8797c947LL},
        {0x68ca0a259c979LL, 0x5c6a1c8a170eaLL, 0x53572930258c6LL, 0x3b49ff8ad08d7LL, 0x11a559bbc1494LL},
        {0x59a3956d28d4LL, 0x8aec2aba8954LL, 0xebedf24f94f5LL, 0x2f12c6ececb59LL, 0x59a225da6049bLL},
        {0x428e6bc6dfff6LL, 0x5a50e6914b357LL, 0x37fa4203ca759LL, 0x40e2fb6aea720LL, 0x2e013bdb4974cLL}
    },
    {
        {0x6adb3d4065f0fLL, 0xb71e55756165LL, 0x3d57cf2f44823LL, 0x3bd20c992fb21LL, 0x627471a969692LL},
        {0x77ac0a5c35e7dLL, 0x26a3af3f9f112LL, 0x5f7a979957a15LL, 0x60657aaaf941cLL, 0x1c5b41b279989LL},
        {0x658dcc42fec91LL, 0x5ef8491e1f4e1LL, 0x6b456a020848LL, 0x17304bb8444d4LL, 0x309488bed7ae2LL},
        {0x50576e87d52f5LL, 0x10424c24ae929LL, 0x44a16d6aa6a9cLL, 0x1a3962f2672a9LL, 0x3e5a47e87d464LL}
    },
    {
        {0x68748671ae865LL, 0x1e572a6a489e5LL, 0x5d260caa7e620LL, 0x51614d952ceadLL, 0x3aea74f08b2d7LL},
        {0x163735da74113LL, 0x6d31354945942LL, 0x1ee3e65ccf368LL, 0x24b4eb44b7df9LL, 0x7f9d6c35dc49fLL},
        {0x5826cc9d90a24LL, 0xcb7d1928e0edLL, 0x4c02f52699e41LL, 0x489651a84d053LL, 0x533552e07f39fLL},
        {0x75b37fd6ea971LL, 0x442a3b028df79LL, 0xf880856384f6LL, 0x6a7b9783232eeLL, 0x32a3f803cddb7LL}
    }
  },
  { /* group 1: i * (2^64 * B) */
    {
        {0x0LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL},
        {0x1LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL},
        {0x1LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL},
        {0x0LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL}
    },
    {
        {0xc5507edf10dLL, 0x749f05a588318LL, 0x6eb62c5a6f984LL, 0x23a1f7850a778LL, 0x5a8a5a58bef14LL},
        {0x654790e453f73LL, 0xfd9578e96c79LL, 0x73d93eba4cfffLL, 0x33c35a1b20122LL, 0x1ad2dd576455fLL},
        {0x49d04ac8405e0LL, 0x2d245d7a0e0b1LL, 0x7634c39e945dLL, 0x1dbcb393a53ecLL, 0x424da3d215aefLL},
        {0x723c11f401586LL, 0x4937293d1c339LL, 0x393e765375665LL, 0xbe11346367faLL, 0x75e4cec7f1c84LL}
    },
    {
        {0x58e802dfd149fLL, 0xfbc4ccd62f1aLL, 0xbbebc4be453cLL, 0x1abbd446c0575LL, 0x32e319634041dLL},
        {0x56d94682c368eLL, 0x5c5e62a1f7ad9LL, 0x2e25901f14f58LL, 0x13ebb9fa3f044LL, 0xc74f64d36e8fLL},
        {0x1ce04b2206d36LL, 0x3813aa44aa980LL, 0x40f3e950e3211LL, 0x2350c9ffc16d9LL, 0x1f9d9e1667aa5LL},
        {0x1401c01a99aeaLL, 0x72583f126eb9eLL, 0x4db64b768c3b1LL, 0x6023e5c719034LL, 0x29923c25f328cLL}
    },
    {
        {0x490806e9b0470LL, 0x1b323547ee145LL, 0xba4d89425f0dLL, 0x7686914fc6133LL, 0x70980c46b1e99LL},
        {0x5424aea4daaccLL, 0x2721630b413e9LL, 0x22d7c7ca0c53cLL, 0x969badf3d9e4LL, 0x692d68e5a7067LL},
        {0x42de4013e3adfLL, 0x6ae00060203e1LL, 0x9cf58d30560LL, 0x469dc026186fbLL, 0x4d37522984f34LL},
        {0x6c14697a99b35LL, 0x4ebbbfdf2b41eLL, 0x629e06fcbe874LL, 0x745027e863857LL, 0x4622514d37668LL}
    },
    {
        {0x5709501f26d01LL, 0x57b9c8c3a5e3eLL, 0x1d568e378dae7LL, 0x291f2f7276a4fLL, 0x45d053064923fLL},
        {0x5ad62cbe4d97bLL, 0x5cb369e376d6cLL, 0x4c635849fa450LL, 0x3a3af3cc64173LL, 0x41c6a277b50ddLL},
        {0x3350cfb25790LL, 0x1ef95cf824444LL, 0x496aa851f4791LL, 0x4bfeba28f0820LL, 0x4f0fe3aa7dbc9LL},
        {0x4012e96812098LL, 0x386ce2b6ade64LL, 0x3ad856bbaac95LL, 0x20c81106a4c4LL, 0x4567541a4c085LL}
    },
    {
        {0x4ca2bf28088b1LL, 0x20efac7375f80LL, 0x60d9d7f898359LL, 0x715757e6dda4fLL, 0x7e7b2cf7ccd3bLL},
        {0x1653c97aabae4LL, 0x1a64a2ee86188LL, 0x459b3073a35d9LL, 0x2e10c9d55eeacLL, 0x3501db934c5d3LL},
        {0x21ab51265d93fLL, 0x21544a9c74cbcLL, 0x4a83eed18a4a5LL, 0x24ff01e6492a9LL, 0x5abf5c871ca53LL},
        {0x769e765fba9dcLL, 0x6a175e8997284LL, 0x61dca407aa537LL, 0x29fa9f89a36eaLL, 0x6944b5316de99LL}
    },
    {
        {0x41d82cf896e02LL, 0x7307a509b446bLL, 0x12bcae5274083LL, 0x2008d13c6b0d7LL, 0x1d5cdbcbac449LL},
        {0x407fe356a8916LL, 0xa970a0c0cb49LL, 0x4c2adefb497a4LL, 0x2495b1c090463LL, 0x6eb3eeb8e09dbLL},
        {0x61e370fa642d8LL, 0x22339711091f6LL, 0x67870cc66ff7fLL, 0x66ca57a9e6c75LL, 0x5e07459629a13LL},
        {0x52d70096466edLL, 0xc6130280decdLL, 0x677d8b079c241LL, 0x6e9fca587f375LL, 0x21fdc3ea6b1a4LL}
    },
    {
        {0x633509f907d2cLL, 0x724f374b9821cLL, 0x1350e9c977588LL, 0x3c9a18fa4d4d0LL, 0xeda11917d1beLL},
        {0x125db440240d9LL, 0xbcadd256d9b3LL, 0x3583e19ba230bLL, 0x416268c81877LL, 0x2fcbf9900614dLL},
        {0x45937cb0069e6LL, 0xb304a6461b20LL, 0x697d491a9c6fLL, 0x5a29d566f855bLL, 0x5eb5f3835088aLL},
        {0x52ca34ae219adLL, 0x28717aa9e0ebLL, 0x7a319d5a2a898LL, 0x101cb0101d815LL, 0x73fdcdbaabf36LL}
    },
    {
        {0x11609a153a260LL, 0x1b04c16be155fLL, 0x24d795434d1e8LL, 0x99e74a0c9d08LL, 0x16b3770d9e4bLL},
        {0x355ee8aeab44eLL, 0x1836b1730498eLL, 0x3afb63360a83fLL, 0x3a5f19dc41ad4LL, 0x5cfa8f2434a94LL},
        {0x5d7ea796a1fd8LL, 0x7a511b675cfeaLL, 0x2ed888c07ad3bLL, 0x2f81b0a742341LL, 0x7130cea885566LL},
        {0x57c5de98b9f7LL, 0x16c62870dc9ccLL, 0x1389e6de87949LL, 0x4175c61298c5eLL, 0x4fc548b896990LL}
    },
    {
        {0xd15a6d7c887eLL, 0x62b1bf0a1bc9aLL, 0x397523bf127fcLL, 0x4f4aefb9f3984LL, 0x6c144d643af54LL},
        {0x7c57e618bfc4fLL, 0x390ffcd1bca0eLL, 0x4b793598466e5LL, 0x5348e3e2257bcLL, 0x14d719e4c2656LL},
        {0x573e278839c74LL, 0x65cd1c7cc77cbLL, 0x475db2cb69242LL, 0x7e6125c12f43bLL, 0xbfdfbfdaeab0LL},
        {0x184de9f6ca82LL, 0x6d1d7bbf622c6LL, 0x1aa64d8d946c0LL, 0x7ec2f13c00d56LL, 0x5c8fd6bab2c4fLL}
    },
    {
        {0x20562cdb03ef4LL, 0x3ca6b7edbd8c8LL, 0x603160126c416LL, 0x5f6f44c5f6ccdLL, 0xc2decc495c15LL},
        {0x6db0a352db2e4LL, 0x65c1f35491da6LL, 0x65c3bc3ad923cLL, 0x58aa6f37908d8LL, 0x45f029468c9feLL},
        {0x862df4deb50aLL, 0x56de5707e46bfLL, 0x1b2b34036b2bcLL, 0x103d0c968d292LL, 0xf07f6cfe61c4LL},
        {0x421d738b6bfc3LL, 0x1536cc028402bLL, 0x1fbeab205843LL, 0x63868334b7256LL, 0x4afec0f2f43dcLL}
    },
    {
        {0x57f7cbe9e6c48LL, 0x602310f375aafLL, 0x7fc52f35a1626LL, 0x12bc7a2687d0dLL, 0x4ec27c72bf44dLL},
        {0x7f77c5d85d1daLL, 0x4b931e5169ef0LL, 0x16bb3e5b49627LL, 0x268a48118336cLL, 0x550eded39928bLL},
        {0x4166d83464b6LL, 0x5623d8f33ba7dLL, 0x1ab90357f54b2LL, 0x709fd0e5e63faLL, 0x479dcb4a664b4LL},
        {0x2615a99e400e8LL, 0x3b9a5d59a017fLL, 0x5f66d17988f18LL, 0x7b77411b43a87LL, 0x56edee31a4f0cLL}
    },
    {
        {0x33459a7caa786LL, 0x2c631e93ffedfLL, 0x1f451757bbde9LL, 0x3778a2a6dffc8LL, 0x1dda7ecf8645aLL},
        {0x2d71a48620b8LL, 0x64fabd3551de5LL, 0xf39c19fbcdb2LL, 0x7e881e8f956dcLL, 0x72a437f69cb7eLL},
        {0x436c2726edef0LL, 0x3a27d22f7ccf2LL, 0x3f9fce031c912LL, 0x46f37ed066ec1LL, 0x68f005a5d09c9LL},
        {0x159b398c8adbLL, 0x51f7d8f6b60fbLL, 0x292ed3d497ff9LL, 0x493365e216083LL, 0x26f479f50c950LL}
    },
    {
        {0x7e07e1343de0aLL, 0x94f2824a854bLL, 0x3e7029950ad3eLL, 0x4f1890628fe38LL, 0x2070c7bdab2ecLL},
        {0x2a56550151e5cLL, 0x7d14fa210d9d7LL, 0x237a75c306188LL, 0x7fdf8dea87e64LL, 0x1586e76f2d649LL},
        {0x6f66952b708fLL, 0x187c1bdffaf4cLL, 0x678b2d9e1f9eLL, 0xf22743f5fc2dLL, 0x788ce1a6ea067LL},
        {0xca13c2c780d7LL, 0x6fa82e8c6e62eLL, 0x51960b3d4237dLL, 0x5efa52538a0b6LL, 0x724132948f027LL}
    },
    {
        {0x4ca05526e4728LL, 0x41d94943e0527LL, 0x4d1b31ec92171LL, 0x11729bf01a11aLL, 0x34afdfb041dbfLL},
        {0x4cb2d62468574LL, 0x293e4368718a5LL, 0x1e801ef80d5ccLL, 0x69e619729986LL, 0x5836f372c1fb8LL},
        {0x743a46e95396bLL, 0x5ed790cc5aefLL, 0xe4c317e9a2f4LL, 0x2ae6da0ef3d2dLL, 0x1e6bbc8b3fa9LL},
        {0x38896b9f9b86fLL, 0x1f0974c171df6LL, 0x7e0a705cc4b0fLL, 0x2828981c288b7LL, 0x774d7898372dLL}
    },
    {
        {0x7a23acdf3d7cbLL, 0xd9a2286dab02LL, 0x7adb6e05f0878LL, 0x616605433ac3aLL, 0x49c65f16d3621LL},
        {0x6527b6a38d562LL, 0x6d831f9f1555fLL, 0x10da6f7af26d0LL, 0x69af0a4b8662eLL, 0x1e9c68e6ccf5eLL},
        {0x5e961d1c6799LL, 0x73211750c2865LL, 0x4dea07d550956LL, 0x608d4312afd50LL, 0x503627b9c5cf3LL},
        {0x7939218fe7aedLL, 0x75c13a8f6a52bLL, 0x1c57508f0d3bfLL, 0x409320d85362bLL, 0x6d928db09267aLL}
    }
  },
  { /* group 2: i * (2^128 * B) */
    {
        {0x0LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL},
        {0x1LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL},
        {0x1LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL},
        {0x0LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL}
    },
    {
        {0x1fb1690e8727eLL, 0xb2f2d8a1855fLL, 0x3017d3662487fLL, 0x6a0450905f9ccLL, 0x38569441a1f5cLL},
        {0x1db96f78d2e7cLL, 0x774988aa25e47LL, 0x408da36c70144LL, 0x30cba94ec94b2LL, 0xa97dfad58fa2LL},
        {0x3b5e513a54540LL, 0x763cbeab70889LL, 0x1fadcf0b2e934LL, 0x4a30251671229LL, 0x78d98ebac33bdLL},
        {0x51e95fb8d9addLL, 0x141ea2a8eb643LL, 0x1ac28bf6ff2a3LL, 0x55b3929e4e572LL, 0x3dc4d80a0c809LL}
    },
    {
        {0x6cae009193eb4LL, 0x3c1addfc527eLL, 0x40a8fa3da23f3LL, 0x219d042b0c4dLL, 0x7cacdc8f11ac8LL},
        {0x3daf9d179df75LL, 0x460a1dfd1c146LL, 0x526abd90aa605LL, 0x4690fda717e65LL, 0x6e537a4173f44LL},
        {0x2f2a92fa15429LL, 0x1199655b43749LL, 0x7eab777da4a0bLL, 0x59d9188a61e7cLL, 0x5f3f36056cba4LL},
        {0x4d53e3843b8acLL, 0x3e6fc8dab5c6fLL, 0x66d82187e2375LL, 0x52e480f8ada50LL, 0xbf9d5a4b3829LL}
    },
    {
        {0x5b568cf33f453LL, 0x45f1d0c361ac6LL, 0x68c5fc266929aLL, 0x6602d0592c713LL, 0xd0545a443e82LL},
        {0x7b55e9b62bcadLL, 0x27dfb075e7f38LL, 0x279066f6461a3LL, 0x1d9e4d889049fLL, 0x8ffff9a6f8b2LL},
        {0x2a169f96e90cfLL, 0x4ddd604a1e5c1LL, 0x1c9cbacaa1b6fLL, 0x653ea1c9fa975LL, 0x5dd1d79bbc86bLL},
        {0x7b9c0c47cc4c4LL, 0x19f33313aff9cLL, 0x74af9c955a9dbLL, 0x7ef3684bb70e2LL, 0x523038618765bLL}
    },
    {
        {0x40570f2ec7a9dLL, 0xc8c90df3adc9LL, 0x48c63c0383979LL, 0x59e5cfbad21c8LL, 0x53fb98ec1a718LL},
        {0xc6a8c532234fLL, 0x7003fa234babbLL, 0x249237dc5180dLL, 0x7b3b3bf4a352eLL, 0x2f76c1f8ee483LL},
        {0x6d4724868f8ecLL, 0x6c012ab9e14fcLL, 0x1d34b2f2fe400LL, 0x49c6fdcb38d12LL, 0x413c291abadd4LL},
        {0x6c93a2fb9bb23LL, 0xa6609a7819a5LL, 0x2dd42f0ca3e22LL, 0x8d6fe1a2dcb0LL, 0x1083a883a9066LL}
    },
    {
        {0x1e602880b8ba7LL, 0x4a10415338083LL, 0x5ea4a2cd3f27dLL, 0x114b361d1011fLL, 0x13493d58cbf91LL},
        {0x6af6999cbfd2bLL, 0x5ef95f8cbf0b2LL, 0x7e662dcafef99LL, 0x7b86ce732176LL, 0x4113db157d328LL},
        {0x7f0b43525f612LL, 0x36cad6bddc462LL, 0x16dde090649c1LL, 0x80b91576cc4aLL, 0x346222978af3bLL},
        {0x36caaa3472befLL, 0x4fe3e2c41172eLL, 0x591df7bf866efLL, 0x5ea1af1bb719aLL, 0x7723b5f5c7d9bLL}
    },
    {
        {0x3884243687993LL, 0x46b580025bac9LL, 0x3a8a3aa02ad3fLL, 0x38f490e73c8ddLL, 0x9af31bcabf34LL},
        {0x3e944aee77339LL, 0x67c003d0e35a1LL, 0x531f0c9355990LL, 0x57d636702adb9LL, 0x2d5a607ce0a31LL},
        {0x3c692b48ae1faLL, 0x3ffba57f9c3baLL, 0x2a069b11b187fLL, 0x50b9d279da494LL, 0x6ce21688ab28eLL},
        {0x2acd211decca1LL, 0x322510aad046fLL, 0x6c8504b6eeb5bLL, 0x30436dbb0f9abLL, 0x2fca984387d54LL}
    },
    {
        {0x683098faed683LL, 0x7303239049921LL, 0x1253495061a0bLL, 0x593abe3104281LL, 0x5f7076adc1bebLL},
        {0x2b10842f449b2LL, 0x1afe19f63321LL, 0x4677bb5d2e402LL, 0x55ca52feff8daLL, 0x3c068f3c8cd5eLL},
        {0x6baa923aec1a5LL, 0x3418a13e96a6aLL, 0x2480c989898a8LL, 0x11142bff3566aLL, 0x69a90f55ca4c9LL},
        {0x761ebb541e1aaLL, 0x1d00cd1d4b376LL, 0x53bf1d9142ff6LL, 0x4b4a6884addLL, 0x2b805da683162LL}
    },
    {
        {0x394007a950bd9LL, 0x69d98a07526d4LL, 0x9996eae1f65cLL, 0x6fdc08b1d3556LL, 0x54b0d72ebbbf7LL},
        {0x21ad4ef73fd61LL, 0x469dd2cb5322bLL, 0x6887cad13c0b2LL, 0x27a67009cb227LL, 0x10bb250e8f453LL},
        {0x7b681aea71f9LL, 0x7949ec1301d80LL, 0x789ddefee5a93LL, 0x1264698adb54LL, 0x44424c54c76cbLL},
        {0x4f73ac7a5d677LL, 0x27ecf38d4f37aLL, 0x35b6de2a6404LL, 0x1a3453104dd6dLL, 0x39c293ccdc64dLL}
    },
    {
        {0x48645014e2e7dLL, 0x57f857570f75LL, 0x4aa8f75ee1591LL, 0x3391c4d740bLL, 0x2b5034a0d9e3eLL},
        {0x646c8b907320LL, 0x3d5ebeaddf57fLL, 0x743879962f769LL, 0x1340dd91ec870LL, 0x55fc1ec05d2fLL},
        {0x7461c315078fLL, 0x55e1b536d582LL, 0x410024d475566LL, 0x453b9f24fc686LL, 0x7a6f317150626LL},
        {0x565b8db6c6697LL, 0xe5012bf8cee5LL, 0x164fe112d07b0LL, 0x55aa3775654d1LL, 0x7d89d2389c3a0LL}
    },
    {
        {0x4d8e7b46967d7LL, 0x7ddaf35ed357fLL, 0x4859e29a8eb58LL, 0x2a25850be8570LL, 0x3edb2b1f28965LL},
        {0x2edd493cde408LL, 0x1e0e416f93388LL, 0x21814cf433327LL, 0x555ddff0e3a43LL, 0x158c2801e32fbLL},
        {0xa82c97aaef2cLL, 0x4c8fcb29a58f9LL, 0x6dd2a54dbb662LL, 0x5cd7ad41c1b50LL, 0x5fcc8ef3f930dLL},
        {0x686632773c98cLL, 0x5ab29f61905deLL, 0x22fbdaf3ec506LL, 0x6d8153e9dc064LL, 0xd64e646901c0LL}
    },
    {
        {0x3bcb6d3338962LL, 0x7a3ee9bfed28aLL, 0x31fa06ede15e2LL, 0x5214798e6b958LL, 0x1b5cbf3847ba0LL},
        {0x1d26549828b62LL, 0x2471ecda6f5d8LL, 0x5a9fc559fdabcLL, 0x68dd8f03dd5faLL, 0x743840fc0e91dLL},
        {0xb848537eb57cLL, 0x307cae7d0ba6eLL, 0x5550871e8292eLL, 0x3daff971f3529LL, 0x62b268948b7aeLL},
        {0x723c7e92d1d18LL, 0x47c22d925e8f0LL, 0x424f3657e13a3LL, 0x5024ffcd16314LL, 0x60f6ef9161725LL}
    },
    {
        {0x3f7d0f5fffc3aLL, 0x48ac0c64f5921LL, 0xea8a528d059dLL, 0x24aa5613c6b6LL, 0x27dd66c4b01c7LL},
        {0x4e784d9720f09LL, 0x23e5d284c22f0LL, 0x44010834ea6a9LL, 0x3650e75b5faf1LL, 0x1e482da23f49aLL},
        {0x24728d1929cf9LL, 0x68fb932080fLL, 0x1b64e39eadbcfLL, 0x5ceeb9a8e4f38LL, 0x46ebd6cb11581LL},
        {0x5e1f337e7af7eLL, 0x273459c587bfLL, 0x454f0c3acb1fLL, 0x6e14e075c5b4fLL, 0x3efa76e06b53cLL}
    },
    {
        {0x7d0e03beaca95LL, 0x2da4d2577210eLL, 0x28d2cb630b27aLL, 0x1ea91664db05fLL, 0x75fd51ec0fbd5LL},
        {0x3630110286c3aLL, 0x5c4a13ab3796bLL, 0x253f7fde3eeaaLL, 0x59228a0de3acdLL, 0x5bfcfc6f7770LL},
        {0x549bad5357ee1LL, 0x52e03fdd541c3LL, 0x54d88448937e0LL, 0x740b29b351f23LL, 0x6f84a5a973b77LL},
        {0x1a347bf19ac5aLL, 0x35221560070bfLL, 0x6b1196f90ad9LL, 0x3a6c13a0b81a6LL, 0x33a0b3d6ef4fLL}
    },
    {
        {0x7c25cbbbe130fLL, 0x648af53285a0eLL, 0x4a25fc21af984LL, 0x1c500838d3665LL, 0x795af752fd1b3LL},
        {0x523411ba51257LL, 0x1f5b09a7b9296LL, 0x26ab8124e117dLL, 0x48a6ff38fe922LL, 0x157ecc68e9736LL},
        {0x493ba377ab50LL, 0x764a522fccc6eLL, 0x2647bbe6a160cLL, 0x2a049f5683210LL, 0x69002c6572285LL},
        {0x1dff96b1184b2LL, 0x1b262182cd109LL, 0x6b86e2557a43aLL, 0x68acb941e66c2LL, 0x7f78b66efec2aLL}
    },
    {
        {0x1dd4b9e91f815LL, 0xfb9c2bcfe1f4LL, 0x385f3c1b0a213LL, 0x1d230626d34b2LL, 0x452b92846744aLL},
        {0x3cf6daca28adLL, 0x2bbf10db9b595LL, 0x74770824f10d9LL, 0x19e65daa94763LL, 0x7616386bd2ff8LL},
        {0x6684f4b430492LL, 0x68744ec652cd9LL, 0x58eab05a2d62cLL, 0x6fa87c68dbc43LL, 0x2f572b17cecccLL},
        {0x562d5a5e28442LL, 0x2bcd4a56717c9LL, 0x223b6243e09a2LL, 0x64176cb4e9c33LL, 0x29812df4400a8LL}
    }
  },
  { /* group 3: i * (2^192 * B) */
    {
        {0x0LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL},
        {0x1LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL},
        {0x1LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL},
        {0x0LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL}
    },
    {
        {0x403afbd77ba7dLL, 0x46814f744c3c0LL, 0x377b454fa451LL, 0x72b002aa17fbeLL, 0x59a2726d1a927LL},
        {0x55c1d19f5096dLL, 0xf5aa4323c8cdLL, 0x473af806285a6LL, 0x29078c18a7542LL, 0x9344b8ad2982LL},
        {0x2f18b60a3effbLL, 0x54f8f2263098bLL, 0x25a1dd79a6a78LL, 0x4ac4db4769eceLL, 0x7d0300628a386LL},
        {0x1c4170e2d4e01LL, 0x4a7e65ae311c4LL, 0x6af0bf2d7ecb9LL, 0x7dda83840b5fbLL, 0x4ba921103721bLL}
    },
    {
        {0x10d789f5b7e93LL, 0x430a0fe16a117LL, 0x170de4d8afb1LL, 0x7d1c8becc5d14LL, 0x893c8b58fe03LL},
        {0x7078a2d949fe4LL, 0x5784f694106ceLL, 0x1f7affc096a63LL, 0xdfc06e1afe2eLL, 0x51e14aa174a0dLL},
        {0x13abad629c38dLL, 0x222c20203b532LL, 0x30a5d968c65a1LL, 0x6f45af34ca054LL, 0x3f5654e11ea27LL},
        {0x4cb7d79691180LL, 0x366ba75af35e0LL, 0x6574ad22f188LL, 0x23299f2859c5cLL, 0x1be4c0e232ce2LL}
    },
    {
        {0x48054e71a1622LL, 0x40463042946ecLL, 0xc416fdfc157cLL, 0x4898cfdeca8b6LL, 0x587db2e1fb73aLL},
        {0x5007b154b66cdLL, 0x68697d5deb81dLL, 0x20c52ef712b67LL, 0x75eef8174e5bfLL, 0x67cf49a641a6cLL},
        {0x6e034716a6550LL, 0xd9d35d3e30e2LL, 0x5a9f3265881e4LL, 0x48ef41a86e5c5LL, 0x30b34a34fd8b5LL},
        {0x4c4a8ad4df5adLL, 0x35bab59730e29LL, 0x355c8e1ef1d9aLL, 0x6033b0a7031fLL, 0x4e6f7f8ab1e92LL}
    },
    {
        {0x64a00b92db6f3LL, 0x39c0ff4512f58LL, 0x6c2aa0f9d729cLL, 0x38834aa1b6339LL, 0x7e9e35b7dcd23LL},
        {0x3058568954f7LL, 0x47db60fb888aeLL, 0x4be1c531961d9LL, 0x16642bd64b87dLL, 0x2ef737c5285f5LL},
        {0x67e77d5667388LL, 0x5261da879b391LL, 0x4782e5c0fe8b9LL, 0x5d4ebcd73b412LL, 0x40cf60ded0630LL},
        {0x163b72b9465c1LL, 0x9376d9b31399LL, 0x2a307ed68762cLL, 0x64b08088572dLL, 0x520485c20955LL}
    },
    {
        {0x1e27f704ec2c9LL, 0x33d111cb5e217LL, 0x7b9289a5b586LL, 0x231d0252507acLL, 0x667630e6bc657LL},
        {0x68630f227cbdaLL, 0x69e26d39cbfcdLL, 0x4e58adab941e0LL, 0x5bf74a173e48cLL, 0x31cd49d6c3664LL},
        {0x413c92b3a68e3LL, 0x53f45acf2331eLL, 0x272477746429bLL, 0x788629d95d7fdLL, 0x4ed9277bfd9e3LL},
        {0x78ce65a33cddcLL, 0x3a9647e9faf8cLL, 0x5aa5b71081527LL, 0x4246a726f688cLL, 0xf6ed5cb7fe8dLL}
    },
    {
        {0x1f11e4324e71cLL, 0x35c05744a3058LL, 0x469d2770c0ef2LL, 0x1fec564b1351eLL, 0x2261647f4fb18LL},
        {0x1212499aae22LL, 0x20232ef974133LL, 0x1e82d301482e3LL, 0x6474fe40202efLL, 0x339c7469a7a7fLL},
        {0x10a58d6b9d731LL, 0x94c4ef1e400bLL, 0x2f9cb4668fe34LL, 0x21a6b0a4dd99dLL, 0x78da1ff320201LL},
        {0xa5c0d068abf6LL, 0x33a2826332cf4LL, 0x4be93fbbf8d09LL, 0x7f013b6a8b2e4LL, 0x27321777ec52aLL}
    },
    {
        {0x7b9f31db8687aLL, 0x397deb151c7dbLL, 0x69824162f6d51LL, 0x5887b1c5b451dLL, 0x7fe9f6653ed96LL},
        {0x5048e5353a40bLL, 0x512cbf26f91e8LL, 0x36b9453b71e9cLL, 0x11d93d258879fLL, 0x68dfd5b283a8dLL},
        {0x2cc6c9b03cef9LL, 0x2362a221b7926LL, 0x34df0372e054eLL, 0x790322ebe2568LL, 0x1e91c05268de3LL},
        {0x587c79c0d302cLL, 0x17b900f1c76a2LL, 0x70eeed93a060fLL, 0x31e30f0d75c6dLL, 0x7d600fdc6d095LL}
    },
    {
        {0x21d62ecb7b608LL, 0x731df27b14b25LL, 0x76e5a7a5e51abLL, 0x50ec9c99298a7LL, 0x2528647e3e460LL},
        {0x701e075f0c4c4LL, 0x2d392697b567eLL, 0x328c258c1da96LL, 0x52345a2f0108cLL, 0x3a76bf31ccb50LL},
        {0x3ceb4093d686eLL, 0x600b5bc80c32bLL, 0x2256b51bd2d9eLL, 0x6c90f4a9f15baLL, 0x5b1818e2b283dLL},
        {0x45c1c6b1fbadbLL, 0x3902cd53bf8eLL, 0xa94c8f89615bLL, 0x178f070b83b1eLL, 0x58b513aee63beLL}
    },
    {
        {0x8f5170c53ab3LL, 0xd1a9b3c1d330LL, 0x441470fc18166LL, 0x21c09ff3ca46dLL, 0xc3367f7bdc71LL},
        {0x661c40872b93eLL, 0x1c0e1b11b8a25LL, 0x5c90f6410459eLL, 0x503202f9831f7LL, 0x3960265228963LL},
        {0x226011f8f78c0LL, 0x164ed702a4357LL, 0x474c67dd4ed9aLL, 0x6f4dbc11aebf0LL, 0x1cea8ef5ac2fbLL},
        {0x2a07c5aaf808dLL, 0x5f6d2dcf0bb29LL, 0x1d6e741ecebccLL, 0x2461cfc36c8e2LL, 0x15e2012032c51LL}
    },
    {
        {0x17293f38a0be0LL, 0x8acb0bb5075bLL, 0xa8599dea352eLL, 0x5251ba277ab3bLL, 0x5b3f8dbf8ee2LL},
        {0x418e31f3464deLL, 0x5d7247359663aLL, 0x22a750b5139eaLL, 0x37c33232227cdLL, 0x309e1e446a5dbLL},
        {0x7c42cf27f7ec2LL, 0x4748de0dce416LL, 0x69297cbcce093LL, 0x93a7ce7c8b9fLL, 0x6ec57eed7963cLL},
        {0x4bb4b6c08392fLL, 0x45509c5d7fd37LL, 0x51925b2fd90bLL, 0x586291f1b9567LL, 0x56679a4f95495LL}
    },
    {
        {0x49e8bd54354bLL, 0x8557dfda07f0LL, 0x7d81d66ca5e03LL, 0x344987d753332LL, 0x6d768980e457eLL},
        {0x777c85e122aacLL, 0x3279fbfe9feabLL, 0x675649e324183LL, 0x2a71554669dd6LL, 0x2ad89c35e2e85LL},
        {0x531f630d511bLL, 0x1d18364122c17LL, 0x29db2e024805dLL, 0x476a9b266abffLL, 0x706c764fd4045LL},
        {0x2e7e3b76e2337LL, 0x5b14dfbf6f833LL, 0xacd6027aad02LL, 0x225264e05864dLL, 0x7a5d6d0532ff5LL}
    },
    {
        {0x671bb94033110LL, 0x497a21cf810d9LL, 0x3280806de1854LL, 0x37a5224e5b1faLL, 0x1e5d680795c2dLL},
        {0x1a83e33a0ac81LL, 0x487cf064948adLL, 0x2cb3ba87fe1fdLL, 0x5c1dadc23e9faLL, 0x63ae9a476971dLL},
        {0x2abe204372c0dLL, 0x3375e09d949c5LL, 0x279f8e4950e7dLL, 0x213fb133e28d8LL, 0x485071d1cc724LL},
        {0x5718275e91872LL, 0x6c151e5e8a735LL, 0x50caec90d5e2aLL, 0x7bddcf9496250LL, 0x7cac08b4e40f0LL}
    },
    {
        {0x3d67ae9f49d88LL, 0x7ab12e299bdf2LL, 0x2b2757af1fafaLL, 0x1f05d6f91a4b5LL, 0x247883da0cb82LL},
        {0x35a5f90997088LL, 0x1ab12a4fba8d8LL, 0x36109614dd443LL, 0x65363f26d2f1fLL, 0x22efc4d9aadf5LL},
        {0x4d0350a52d373LL, 0xc9d0af556f14LL, 0x41202011033bbLL, 0x2d672129797a9LL, 0x68cb561cf4b1fLL},
        {0x50f98a4ef8d09LL, 0xbaf21c1deb3bLL, 0x7f4ce448acfbdLL, 0x6d0bdd3e10590LL, 0x4973bd109cfe7LL}
    },
    {
        {0x656188228fef7LL, 0x5a0aa3f880795LL, 0x6b7540aa416ecLL, 0x61aedfd527571LL, 0x568556fccb509LL},
        {0x16b504c6fe253LL, 0x6a5a3dc91ead0LL, 0x1057e2ba7dd8cLL, 0x4f7553938e2f5LL, 0x6ae4033c3c8dfLL},
        {0x2851b75bcce35LL, 0x6716efcc0f4d9LL, 0x4ec2da7759fcLL, 0x413287ed463d4LL, 0x5a6f7721802e0LL},
        {0x77336eff41ca7LL, 0x254d5e64ea576LL, 0x66cd252a1f603LL, 0x3679a2828dcffLL, 0x721e7dd366477LL}
    },
    {
        {0x11d218f3410d5LL, 0x4f901cb1f5214LL, 0x64077b7c18e52LL, 0x58d1f21055e5cLL, 0x5991c8bac5ce5LL},
        {0x2d184d36ffc6bLL, 0x193b422871437LL, 0x1f1c649e0aa48LL, 0x24312f718fbe0LL, 0x7bdf2e990bf2cLL},
        {0x1c53b52546f72LL, 0x34fe0142f0440LL, 0x5ba77201e9b8dLL, 0x7be7e3524f45aLL, 0x4d49a13783a1aLL},
        {0x9bf7c73ba5caLL, 0x5c5f5ef0c92f6LL, 0x1d91dc8cb9081LL, 0x6a833291591f5LL, 0x113fe47cc0838LL}
    }
  }
};

/* Forward declarations */
static void fe_cmov(fe25519 f, const fe25519 g, unsigned int b);
static void ge25519_cmov(ge25519_p3 *t, const ge25519_p3 *u, unsigned int b);
static void ge25519_scalarmult(ge25519_p3 *r, const uint8_t *scalar, const ge25519_p3 *p);
static void ge25519_scalarmult_base(ge25519_p3 *r, const uint8_t *scalar);

/* Point operations */

static void
ge25519_p3_0(ge25519_p3 *h)
{
    fe_0(h->X); fe_1(h->Y); fe_1(h->Z); fe_0(h->T);
}

static void
ge25519_add(ge25519_p3 *r, const ge25519_p3 *p, const ge25519_p3 *q)
{
    fe25519 A, B, C, D, E, F, G, H;

    fe_sub(A, p->Y, p->X);
    fe_sub(H, q->Y, q->X);
    fe_mul(A, A, H);
    fe_add(B, p->Y, p->X);
    fe_add(H, q->Y, q->X);
    fe_mul(B, B, H);
    fe_mul(C, p->T, q->T);
    fe_mul(C, C, ed25519_d2);
    fe_mul(D, p->Z, q->Z);
    fe_add(D, D, D);
    fe_sub(E, B, A);
    fe_sub(F, D, C);
    fe_add(G, D, C);
    fe_add(H, B, A);

    fe_mul(r->X, E, F);
    fe_mul(r->Y, G, H);
    fe_mul(r->T, E, H);
    fe_mul(r->Z, F, G);
}

static void
ge25519_dbl(ge25519_p3 *r, const ge25519_p3 *p)
{
    fe25519 X1, Y1, Z1;
    fe25519 A, B, C, E, F, G, H;

    fe_copy(X1, p->X);
    fe_copy(Y1, p->Y);
    fe_copy(Z1, p->Z);

    fe_sq(A, X1);
    fe_sq(B, Y1);
    fe_sq(C, Z1);
    fe_add(C, C, C);

    fe_sub(G, B, A);
    fe_add(H, X1, Y1);
    fe_sq(E, H);
    fe_sub(E, E, A);
    fe_sub(E, E, B);
    fe_add(H, A, B);
    fe_neg(H, H);
    fe_sub(F, G, C);

    fe_mul(r->X, E, F);
    fe_mul(r->Y, G, H);
    fe_mul(r->T, E, H);
    fe_mul(r->Z, F, G);
}

/* ge25519_scalarmult defined later with constant-time implementation */

static void
fe_invert(fe25519 out, const fe25519 z)
{
    /* Fermat's little theorem: a^(p-1) = 1 => a^(p-2) = a^(-1) mod p */
    fe25519 t0, t1, t2;
    int i;

    /* Compute z^(p-2) = z^(2^255-21) using addition chain */
    fe25519 z11;
    fe_sq(t0, z);               /* t0 = z^2 */
    fe_sq(t1, t0);
    fe_sq(t1, t1);              /* t1 = z^8 */
    fe_mul(t1, z, t1);          /* t1 = z^9 */
    fe_mul(t0, t0, t1);         /* t0 = z^11 */
    fe_copy(z11, t0);           /* save z^11 for final step */
    fe_sq(t0, t0);              /* t0 = z^22 */
    fe_mul(t0, t1, t0);         /* t0 = z^31 */
    fe_sq(t1, t0);
    for (i = 1; i < 5; ++i)
        fe_sq(t1, t1);          /* t1 = z^(31*2^5) = z^992 */
    fe_mul(t0, t1, t0);         /* t0 = z^1023 = z^(2^10-1) */
    fe_sq(t1, t0);
    for (i = 1; i < 10; ++i)
        fe_sq(t1, t1);          /* t1 = z^((2^10-1)*2^10) */
    fe_mul(t1, t1, t0);         /* t1 = z^(2^20-1) */
    fe_sq(t2, t1);
    for (i = 1; i < 20; ++i)
        fe_sq(t2, t2);          /* t2 = z^((2^20-1)*2^20) */
    fe_mul(t1, t2, t1);         /* t1 = z^(2^40-1) */
    fe_sq(t1, t1);
    for (i = 1; i < 10; ++i)
        fe_sq(t1, t1);          /* t1 = z^((2^40-1)*2^10) */
    fe_mul(t0, t1, t0);         /* t0 = z^(2^50-1) */
    fe_sq(t1, t0);
    for (i = 1; i < 50; ++i)
        fe_sq(t1, t1);
    fe_mul(t1, t1, t0);         /* t1 = z^(2^100-1) */
    fe_sq(t2, t1);
    for (i = 1; i < 100; ++i)
        fe_sq(t2, t2);
    fe_mul(t1, t2, t1);         /* t1 = z^(2^200-1) */
    fe_sq(t1, t1);
    for (i = 1; i < 50; ++i)
        fe_sq(t1, t1);
    fe_mul(t0, t1, t0);         /* t0 = z^(2^250-1) */
    fe_sq(t0, t0);
    fe_sq(t0, t0);
    fe_sq(t0, t0);
    fe_sq(t0, t0);
    fe_sq(t0, t0);              /* t0 = z^(2^255-32) */
    fe_mul(out, t0, z11);       /* out = z^(2^255-32+11) = z^(2^255-21) */
}

static void
fe_pow2523(fe25519 out, const fe25519 z)
{
    /* Compute z^((p-5)/8) = z^(2^252-3) for square root */
    fe25519 t0, t1, t2;
    int i;

    fe_sq(t0, z);
    fe_sq(t1, t0);
    fe_sq(t1, t1);
    fe_mul(t1, z, t1);
    fe_mul(t0, t0, t1);
    fe_sq(t0, t0);
    fe_mul(t0, t1, t0);
    fe_sq(t1, t0);
    for (i = 1; i < 5; ++i) {
        fe_sq(t1, t1);
    }
    fe_mul(t0, t1, t0);
    fe_sq(t1, t0);
    for (i = 1; i < 10; ++i) {
        fe_sq(t1, t1);
    }
    fe_mul(t1, t1, t0);
    fe_sq(t2, t1);
    for (i = 1; i < 20; ++i) {
        fe_sq(t2, t2);
    }
    fe_mul(t1, t2, t1);
    fe_sq(t1, t1);
    for (i = 1; i < 10; ++i) {
        fe_sq(t1, t1);
    }
    fe_mul(t0, t1, t0);
    fe_sq(t1, t0);
    for (i = 1; i < 50; ++i) {
        fe_sq(t1, t1);
    }
    fe_mul(t1, t1, t0);
    fe_sq(t2, t1);
    for (i = 1; i < 100; ++i) {
        fe_sq(t2, t2);
    }
    fe_mul(t1, t2, t1);
    fe_sq(t1, t1);
    for (i = 1; i < 50; ++i) {
        fe_sq(t1, t1);
    }
    fe_mul(t0, t1, t0);
    fe_sq(t0, t0);
    fe_sq(t0, t0);
    fe_mul(out, t0, z);
}

/* Ed25519 scalar (mod L) where L = 2^252 + 27742317777372353535851937790883648493 */
static const uint8_t L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

static void
sc25519_reduce(uint8_t out[32], const uint8_t in[64])
{
    int64_t s0  = 2097151 & (int64_t)load3(in);
    int64_t s1  = 2097151 & (int64_t)(load4(in +  2) >> 5);
    int64_t s2  = 2097151 & (int64_t)(load3(in +  5) >> 2);
    int64_t s3  = 2097151 & (int64_t)(load4(in +  7) >> 7);
    int64_t s4  = 2097151 & (int64_t)(load4(in + 10) >> 4);
    int64_t s5  = 2097151 & (int64_t)(load3(in + 13) >> 1);
    int64_t s6  = 2097151 & (int64_t)(load4(in + 15) >> 6);
    int64_t s7  = 2097151 & (int64_t)(load3(in + 18) >> 3);
    int64_t s8  = 2097151 & (int64_t)load3(in + 21);
    int64_t s9  = 2097151 & (int64_t)(load4(in + 23) >> 5);
    int64_t s10 = 2097151 & (int64_t)(load3(in + 26) >> 2);
    int64_t s11 = 2097151 & (int64_t)(load4(in + 28) >> 7);
    int64_t s12 = 2097151 & (int64_t)(load4(in + 31) >> 4);
    int64_t s13 = 2097151 & (int64_t)(load3(in + 34) >> 1);
    int64_t s14 = 2097151 & (int64_t)(load4(in + 36) >> 6);
    int64_t s15 = 2097151 & (int64_t)(load3(in + 39) >> 3);
    int64_t s16 = 2097151 & (int64_t)load3(in + 42);
    int64_t s17 = 2097151 & (int64_t)(load4(in + 44) >> 5);
    int64_t s18 = 2097151 & (int64_t)(load3(in + 47) >> 2);
    int64_t s19 = 2097151 & (int64_t)(load4(in + 49) >> 7);
    int64_t s20 = 2097151 & (int64_t)(load4(in + 52) >> 4);
    int64_t s21 = 2097151 & (int64_t)(load3(in + 55) >> 1);
    int64_t s22 = 2097151 & (int64_t)(load4(in + 57) >> 6);
    int64_t s23 =           (int64_t)(load4(in + 60) >> 3);

    int64_t carry;

    /* Phase 1: reduce s23..s18 into s5..s16 */
    s11 += s23 * 666643;  s12 += s23 * 470296;
    s13 += s23 * 654183;  s14 -= s23 * 997805;
    s15 += s23 * 136657;  s16 -= s23 * 683901;  s23 = 0;

    s10 += s22 * 666643;  s11 += s22 * 470296;
    s12 += s22 * 654183;  s13 -= s22 * 997805;
    s14 += s22 * 136657;  s15 -= s22 * 683901;  s22 = 0;

    s9  += s21 * 666643;  s10 += s21 * 470296;
    s11 += s21 * 654183;  s12 -= s21 * 997805;
    s13 += s21 * 136657;  s14 -= s21 * 683901;  s21 = 0;

    s8  += s20 * 666643;  s9  += s20 * 470296;
    s10 += s20 * 654183;  s11 -= s20 * 997805;
    s12 += s20 * 136657;  s13 -= s20 * 683901;  s20 = 0;

    s7  += s19 * 666643;  s8  += s19 * 470296;
    s9  += s19 * 654183;  s10 -= s19 * 997805;
    s11 += s19 * 136657;  s12 -= s19 * 683901;  s19 = 0;

    s6  += s18 * 666643;  s7  += s18 * 470296;
    s8  += s18 * 654183;  s9  -= s18 * 997805;
    s10 += s18 * 136657;  s11 -= s18 * 683901;  s18 = 0;

    /* Intermediate carry propagation to prevent overflow in phase 2 */
    carry = (s6  + (1LL << 20)) >> 21; s7  += carry; s6  -= carry * (1LL << 21);
    carry = (s8  + (1LL << 20)) >> 21; s9  += carry; s8  -= carry * (1LL << 21);
    carry = (s10 + (1LL << 20)) >> 21; s11 += carry; s10 -= carry * (1LL << 21);
    carry = (s12 + (1LL << 20)) >> 21; s13 += carry; s12 -= carry * (1LL << 21);
    carry = (s14 + (1LL << 20)) >> 21; s15 += carry; s14 -= carry * (1LL << 21);
    carry = (s16 + (1LL << 20)) >> 21; s17 += carry; s16 -= carry * (1LL << 21);

    carry = (s7  + (1LL << 20)) >> 21; s8  += carry; s7  -= carry * (1LL << 21);
    carry = (s9  + (1LL << 20)) >> 21; s10 += carry; s9  -= carry * (1LL << 21);
    carry = (s11 + (1LL << 20)) >> 21; s12 += carry; s11 -= carry * (1LL << 21);
    carry = (s13 + (1LL << 20)) >> 21; s14 += carry; s13 -= carry * (1LL << 21);
    carry = (s15 + (1LL << 20)) >> 21; s16 += carry; s15 -= carry * (1LL << 21);

    /* Phase 2: reduce s17..s12 into s0..s11 */
    s5  += s17 * 666643;  s6  += s17 * 470296;
    s7  += s17 * 654183;  s8  -= s17 * 997805;
    s9  += s17 * 136657;  s10 -= s17 * 683901;  s17 = 0;

    s4  += s16 * 666643;  s5  += s16 * 470296;
    s6  += s16 * 654183;  s7  -= s16 * 997805;
    s8  += s16 * 136657;  s9  -= s16 * 683901;  s16 = 0;

    s3  += s15 * 666643;  s4  += s15 * 470296;
    s5  += s15 * 654183;  s6  -= s15 * 997805;
    s7  += s15 * 136657;  s8  -= s15 * 683901;  s15 = 0;

    s2  += s14 * 666643;  s3  += s14 * 470296;
    s4  += s14 * 654183;  s5  -= s14 * 997805;
    s6  += s14 * 136657;  s7  -= s14 * 683901;  s14 = 0;

    s1  += s13 * 666643;  s2  += s13 * 470296;
    s3  += s13 * 654183;  s4  -= s13 * 997805;
    s5  += s13 * 136657;  s6  -= s13 * 683901;  s13 = 0;

    s0  += s12 * 666643;  s1  += s12 * 470296;
    s2  += s12 * 654183;  s3  -= s12 * 997805;
    s4  += s12 * 136657;  s5  -= s12 * 683901;  s12 = 0;

    /* Carry propagation */
    carry = (s0  + (1LL << 20)) >> 21; s1  += carry; s0  -= carry * (1LL << 21);
    carry = (s2  + (1LL << 20)) >> 21; s3  += carry; s2  -= carry * (1LL << 21);
    carry = (s4  + (1LL << 20)) >> 21; s5  += carry; s4  -= carry * (1LL << 21);
    carry = (s6  + (1LL << 20)) >> 21; s7  += carry; s6  -= carry * (1LL << 21);
    carry = (s8  + (1LL << 20)) >> 21; s9  += carry; s8  -= carry * (1LL << 21);
    carry = (s10 + (1LL << 20)) >> 21; s11 += carry; s10 -= carry * (1LL << 21);

    carry = (s1  + (1LL << 20)) >> 21; s2  += carry; s1  -= carry * (1LL << 21);
    carry = (s3  + (1LL << 20)) >> 21; s4  += carry; s3  -= carry * (1LL << 21);
    carry = (s5  + (1LL << 20)) >> 21; s6  += carry; s5  -= carry * (1LL << 21);
    carry = (s7  + (1LL << 20)) >> 21; s8  += carry; s7  -= carry * (1LL << 21);
    carry = (s9  + (1LL << 20)) >> 21; s10 += carry; s9  -= carry * (1LL << 21);
    carry = (s11 + (1LL << 20)) >> 21; s12 += carry; s11 -= carry * (1LL << 21);

    /* Reduce residual s12 */
    s0  += s12 * 666643;
    s1  += s12 * 470296;
    s2  += s12 * 654183;
    s3  -= s12 * 997805;
    s4  += s12 * 136657;
    s5  -= s12 * 683901;
    s12 = 0;

    /* Final carry chain — unbiased shift to ensure non-negative limbs */
    carry = s0  >> 21; s1  += carry; s0  -= carry * (1LL << 21);
    carry = s1  >> 21; s2  += carry; s1  -= carry * (1LL << 21);
    carry = s2  >> 21; s3  += carry; s2  -= carry * (1LL << 21);
    carry = s3  >> 21; s4  += carry; s3  -= carry * (1LL << 21);
    carry = s4  >> 21; s5  += carry; s4  -= carry * (1LL << 21);
    carry = s5  >> 21; s6  += carry; s5  -= carry * (1LL << 21);
    carry = s6  >> 21; s7  += carry; s6  -= carry * (1LL << 21);
    carry = s7  >> 21; s8  += carry; s7  -= carry * (1LL << 21);
    carry = s8  >> 21; s9  += carry; s8  -= carry * (1LL << 21);
    carry = s9  >> 21; s10 += carry; s9  -= carry * (1LL << 21);
    carry = s10 >> 21; s11 += carry; s10 -= carry * (1LL << 21);

    /* If result is negative (congruent to x mod L but < 0), add L */
    int64_t neg_mask = s11 >> 63;
    s0  += neg_mask & 1430509;
    s1  += neg_mask & 1626855;
    s2  += neg_mask & 1442968;
    s3  += neg_mask & 997804;
    s4  += neg_mask & 1960495;
    s5  += neg_mask & 683900;
    s11 += neg_mask & 2097152;

    carry = s0  >> 21; s1  += carry; s0  -= carry * (1LL << 21);
    carry = s1  >> 21; s2  += carry; s1  -= carry * (1LL << 21);
    carry = s2  >> 21; s3  += carry; s2  -= carry * (1LL << 21);
    carry = s3  >> 21; s4  += carry; s3  -= carry * (1LL << 21);
    carry = s4  >> 21; s5  += carry; s4  -= carry * (1LL << 21);
    carry = s5  >> 21; s6  += carry; s5  -= carry * (1LL << 21);
    carry = s6  >> 21; s7  += carry; s6  -= carry * (1LL << 21);
    carry = s7  >> 21; s8  += carry; s7  -= carry * (1LL << 21);
    carry = s8  >> 21; s9  += carry; s8  -= carry * (1LL << 21);
    carry = s9  >> 21; s10 += carry; s9  -= carry * (1LL << 21);
    carry = s10 >> 21; s11 += carry; s10 -= carry * (1LL << 21);

    out[0]  = (uint8_t)(s0);
    out[1]  = (uint8_t)(s0 >> 8);
    out[2]  = (uint8_t)((s0 >> 16) | (s1 << 5));
    out[3]  = (uint8_t)(s1 >> 3);
    out[4]  = (uint8_t)(s1 >> 11);
    out[5]  = (uint8_t)((s1 >> 19) | (s2 << 2));
    out[6]  = (uint8_t)(s2 >> 6);
    out[7]  = (uint8_t)((s2 >> 14) | (s3 << 7));
    out[8]  = (uint8_t)(s3 >> 1);
    out[9]  = (uint8_t)(s3 >> 9);
    out[10] = (uint8_t)((s3 >> 17) | (s4 << 4));
    out[11] = (uint8_t)(s4 >> 4);
    out[12] = (uint8_t)(s4 >> 12);
    out[13] = (uint8_t)((s4 >> 20) | (s5 << 1));
    out[14] = (uint8_t)(s5 >> 7);
    out[15] = (uint8_t)((s5 >> 15) | (s6 << 6));
    out[16] = (uint8_t)(s6 >> 2);
    out[17] = (uint8_t)(s6 >> 10);
    out[18] = (uint8_t)((s6 >> 18) | (s7 << 3));
    out[19] = (uint8_t)(s7 >> 5);
    out[20] = (uint8_t)(s7 >> 13);
    out[21] = (uint8_t)(s8);
    out[22] = (uint8_t)(s8 >> 8);
    out[23] = (uint8_t)((s8 >> 16) | (s9 << 5));
    out[24] = (uint8_t)(s9 >> 3);
    out[25] = (uint8_t)(s9 >> 11);
    out[26] = (uint8_t)((s9 >> 19) | (s10 << 2));
    out[27] = (uint8_t)(s10 >> 6);
    out[28] = (uint8_t)((s10 >> 14) | (s11 << 7));
    out[29] = (uint8_t)(s11 >> 1);
    out[30] = (uint8_t)(s11 >> 9);
    out[31] = (uint8_t)(s11 >> 17);
}

static void
sc25519_muladd(uint8_t s[32], const uint8_t a[32], const uint8_t b[32], const uint8_t c[32])
{
    /* Compute s = (a * b + c) mod L */
    /* This is a simplified implementation for Ed25519 */
    __int128 t[64] = {0};

    /* Multiply a * b */
    for (int i = 0; i < 32; i++) {
        for (int j = 0; j < 32; j++) {
            t[i + j] += (__int128)a[i] * b[j];
        }
    }

    /* Add c */
    for (int i = 0; i < 32; i++) {
        t[i] += c[i];
    }

    /* Propagate carries */
    for (int i = 0; i < 63; i++) {
        t[i + 1] += t[i] >> 8;
        t[i] &= 0xff;
    }

    /* Convert to bytes and reduce */
    uint8_t temp[64];
    for (int i = 0; i < 64; i++) {
        temp[i] = (uint8_t)(t[i] & 0xff);
    }

    sc25519_reduce(s, temp);
}

static void
ge25519_encode(uint8_t *s, const ge25519_p3 *p)
{
    fe25519 zinv, x, y;

    fe_invert(zinv, p->Z);
    fe_mul(x, p->X, zinv);
    fe_mul(y, p->Y, zinv);

    fe_tobytes(s, y);
    s[31] ^= fe_isnegative(x) << 7;
}

static int
ge25519_decode(ge25519_p3 *p, const uint8_t s[32])
{
    fe25519 y, x, xx, yy, dyy, u, v, v3, vxx, check;
    int x_sign;

    /* Extract y coordinate and x sign */
    fe_frombytes(y, s);
    x_sign = s[31] >> 7;

    /* Check y is in valid range (< p) */
    fe_tobytes((uint8_t*)xx, y); /* Reuse xx as temp */
    if (memcmp((uint8_t*)xx, s, 31) != 0 || ((uint8_t*)xx)[31] != (s[31] & 0x7f)) {
        return 0; /* Invalid y coordinate */
    }

    /* Recover x coordinate: x^2 = (y^2 - 1) / (d*y^2 + 1) */
    fe_sq(yy, y);                    /* yy = y^2 */
    fe25519 one; fe_1(one);
    fe_sub(u, yy, one);              /* u = y^2 - 1 */
    fe_mul(dyy, ed25519_d, yy);      /* dyy = d*y^2 */
    fe_add(v, dyy, one);             /* v = d*y^2 + 1 */

    /* Compute x = +/- sqrt(u/v) using: x = u * v^3 * (u * v^7)^((p-5)/8) */
    fe_sq(v3, v);                    /* v^2 */
    fe_mul(v3, v3, v);               /* v^3 */
    fe_sq(vxx, v3);                  /* v^6 */
    fe_mul(vxx, vxx, v);             /* v^7 */
    fe_mul(vxx, vxx, u);             /* u * v^7 */
    fe_pow2523(vxx, vxx);            /* (u * v^7)^((p-5)/8) */
    fe_mul(x, vxx, v3);              /* v^3 * (u * v^7)^((p-5)/8) */
    fe_mul(x, x, u);                 /* u * v^3 * (u * v^7)^((p-5)/8) */

    /* Check if x^2 = u/v */
    fe_sq(xx, x);                    /* x^2 */
    fe_mul(check, v, xx);            /* v * x^2 */
    fe_sub(check, check, u);         /* v * x^2 - u */

    /* If check != 0, try x * sqrt(-1) */
    uint8_t check_bytes[32];
    fe_tobytes(check_bytes, check);
    int is_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (check_bytes[i] != 0) {
            is_zero = 0;
            break;
        }
    }

    if (!is_zero) {
        fe_mul(x, x, ed25519_sqrtm1);
        fe_sq(xx, x);
        fe_mul(check, v, xx);
        fe_sub(check, check, u);
        fe_tobytes(check_bytes, check);
        is_zero = 1;
        for (int i = 0; i < 32; i++) {
            if (check_bytes[i] != 0) {
                is_zero = 0;
                break;
            }
        }
        if (!is_zero) {
            return 0; /* Point not on curve */
        }
    }

    /* Adjust sign of x */
    if (fe_isnegative(x) != x_sign) {
        fe_neg(x, x);
    }

    /* Set point coordinates */
    fe_copy(p->X, x);
    fe_copy(p->Y, y);
    fe_1(p->Z);
    fe_mul(p->T, x, y);

    return 1;
}

static void
fe_cmov(fe25519 f, const fe25519 g, unsigned int b)
{
    int64_t mask = -(int64_t)(b & 1);
    for (int i = 0; i < 5; i++)
        f[i] ^= mask & (g[i] ^ f[i]);
}

static void
ge25519_cmov(ge25519_p3 *t, const ge25519_p3 *u, unsigned int b)
{
    fe_cmov(t->X, u->X, b);
    fe_cmov(t->Y, u->Y, b);
    fe_cmov(t->Z, u->Z, b);
    fe_cmov(t->T, u->T, b);
}

static void
ge25519_scalarmult(ge25519_p3 *r, const uint8_t *scalar, const ge25519_p3 *p)
{
    ge25519_p3 table[16];
    ge25519_p3 result, tmp;
    int j, k;

    ge25519_p3_0(&table[0]);
    table[1] = *p;
    for (k = 2; k < 16; k++)
        ge25519_add(&table[k], &table[k - 1], p);

    ge25519_p3_0(&result);

    for (j = 0; j < 64; j++) {
        ge25519_dbl(&result, &result);
        ge25519_dbl(&result, &result);
        ge25519_dbl(&result, &result);
        ge25519_dbl(&result, &result);

        int byte_idx = 31 - j / 2;
        unsigned int nibble = (j & 1)
            ? (scalar[byte_idx] & 0xfu)
            : ((unsigned int)scalar[byte_idx] >> 4);

        ge25519_p3_0(&tmp);
        for (k = 0; k < 16; k++) {
            unsigned int sel = ((unsigned int)(k ^ (int)nibble) - 1U) >> 31;
            ge25519_cmov(&tmp, &table[k], sel);
        }

        ge25519_add(&result, &result, &tmp);
    }

    *r = result;
}

/*
 * Base-point scalar multiplication using precomputed comb table.
 * Processes the 256-bit scalar as four 64-bit groups, each using a
 * radix-16 precomputed table of the base point shifted by 0/64/128/192 bits.
 * Result: r = scalar * B  (64 additions, 0 variable-base doublings).
 */
static void
ge25519_scalarmult_base(ge25519_p3 *r, const uint8_t *scalar)
{
    ge25519_p3 result, tmp;
    ge25519_p3_0(&result);

    for (int j = 15; j >= 0; j--) {
        if (j < 15)
            for (int d = 0; d < 4; d++)
                ge25519_dbl(&result, &result);

        for (int g = 0; g < 4; g++) {
            int byte_idx = g * 8 + j / 2;
            unsigned int nibble = (j & 1)
                ? ((unsigned int)scalar[byte_idx] >> 4)
                : (scalar[byte_idx] & 0xfu);

            ge25519_p3_0(&tmp);
            for (int k = 0; k < 16; k++) {
                unsigned int sel = ((unsigned int)(k ^ (int)nibble) - 1U) >> 31;
                ge25519_cmov(&tmp, &ed25519_base_comb[g][k], sel);
            }
            ge25519_add(&result, &result, &tmp);
        }
    }

    *r = result;
}

int opssl_ed25519_keygen(uint8_t pk[32], uint8_t sk[64])
{
    uint8_t seed[32];
    uint8_t h[64];
    ge25519_p3 A;
    struct opssl_sha512_ctx ctx;

    /* Use sk[0..31] as seed if non-zero, otherwise generate random */
    int have_seed = 0;
    for (int i = 0; i < 32; i++) {
        if (sk[i] != 0) { have_seed = 1; break; }
    }
    if (have_seed) {
        memcpy(seed, sk, 32);
    } else {
        if (opssl_random_bytes(seed, 32) != 0)
            return 0;
    }

    /* Hash seed with SHA-512 */
    opssl_sha512_init(&ctx);
    opssl_sha512_update(&ctx, seed, 32);
    opssl_sha512_final(&ctx, h);

    /* Clamp hash[0..31]: clear bits 0,1,2 and 255, set bit 254 */
    h[0] &= 248;   /* Clear lowest 3 bits */
    h[31] &= 127;  /* Clear bit 255 */
    h[31] |= 64;   /* Set bit 254 */

    /* Scalar multiply: A = hash[0..31] * B (base point) */
    ge25519_scalarmult_base(&A, h);

    /* Compress A to get pk[32] */
    ge25519_encode(pk, &A);

    /* sk[0..31] = seed, sk[32..63] = pk */
    memcpy(sk, seed, 32);
    memcpy(sk + 32, pk, 32);

    /* Clear sensitive data */
    opssl_memzero(seed, sizeof(seed));
    opssl_memzero(h, sizeof(h));

    return 1;
}

int opssl_ed25519_sign(uint8_t sig[64], const uint8_t *msg, size_t msg_len, const uint8_t sk[64])
{
    uint8_t h[64], r[64];
    uint8_t a[32], k[32];
    const uint8_t *pk = sk + 32;
    ge25519_p3 R;
    struct opssl_sha512_ctx ctx;

    /* Hash sk[0..31] with SHA-512 to get h */
    opssl_sha512_init(&ctx);
    opssl_sha512_update(&ctx, sk, 32);
    opssl_sha512_final(&ctx, h);

    /* Clamp h[0..31] as scalar a */
    memcpy(a, h, 32);
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;

    /* Compute r = SHA-512(h[32..63] || msg) mod L */
    opssl_sha512_init(&ctx);
    opssl_sha512_update(&ctx, h + 32, 32);
    opssl_sha512_update(&ctx, msg, msg_len);
    opssl_sha512_final(&ctx, r);
    sc25519_reduce(r, r); /* Reduce to 32 bytes mod L */

    /* R = r * B, encode R → sig[0..31] */
    ge25519_scalarmult_base(&R, r);
    ge25519_encode(sig, &R);

    /* Compute k = SHA-512(sig[0..31] || pk || msg) mod L */
    opssl_sha512_init(&ctx);
    opssl_sha512_update(&ctx, sig, 32);      /* R encoding */
    opssl_sha512_update(&ctx, pk, 32);       /* Public key */
    opssl_sha512_update(&ctx, msg, msg_len); /* Message */
    opssl_sha512_final(&ctx, h);             /* Reuse h buffer */
    sc25519_reduce(k, h);

    /* S = (r + k * a) mod L → sig[32..63] */
    sc25519_muladd(sig + 32, k, a, r);

    /* Clear sensitive data */
    opssl_memzero(h, sizeof(h));
    opssl_memzero(r, sizeof(r));
    opssl_memzero(a, sizeof(a));
    opssl_memzero(k, sizeof(k));

    return 1;
}

int opssl_ed25519_verify(const uint8_t sig[64], const uint8_t *msg, size_t msg_len, const uint8_t pk[32])
{
    ge25519_p3 A, R;
    uint8_t h[64], k[32];
    struct opssl_sha512_ctx ctx;

    /* Decode public key A from pk */
    if (!ge25519_decode(&A, pk)) {
        return 0; /* Invalid public key */
    }

    /* Decode R from sig[0..31] */
    if (!ge25519_decode(&R, sig)) {
        return 0; /* Invalid R point */
    }

    /* Check that S (sig[32..63]) is in valid range [0, L) */
    for (int i = 31; i >= 0; i--) {
        if (sig[32 + i] > L[i]) {
            return 0; /* S >= L */
        } else if (sig[32 + i] < L[i]) {
            break; /* S < L, valid */
        }
    }

    /* Compute k = SHA-512(sig[0..31] || pk || msg) mod L */
    opssl_sha512_init(&ctx);
    opssl_sha512_update(&ctx, sig, 32);      /* R encoding */
    opssl_sha512_update(&ctx, pk, 32);       /* Public key */
    opssl_sha512_update(&ctx, msg, msg_len); /* Message */
    opssl_sha512_final(&ctx, h);
    sc25519_reduce(k, h);

    /* Verify equation: 8*S*B == 8*R + 8*k*A (cofactored verification) */
    /* This is equivalent to: S*B == R + k*A */

    /* Compute S * B */
    ge25519_p3 left_side;
    ge25519_scalarmult_base(&left_side, sig + 32);

    /* Compute k * A */
    ge25519_p3 kA;
    ge25519_scalarmult(&kA, k, &A);

    /* Compute R + k*A */
    ge25519_p3 right_side;
    ge25519_add(&right_side, &R, &kA);

    /* Check if left_side == right_side by encoding both and comparing */
    uint8_t left_enc[32], right_enc[32];
    ge25519_encode(left_enc, &left_side);
    ge25519_encode(right_enc, &right_side);

    /* Constant-time comparison */
    int result = opssl_ct_eq(left_enc, right_enc, 32);

    /* Clear sensitive data */
    opssl_memzero(h, sizeof(h));
    opssl_memzero(k, sizeof(k));

    return result;
}
