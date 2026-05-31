/*
 * OpenSSL-compatible TLS library - Extension parsing and building
 * Copyright (c) 2024 OpSSL Project
 *
 * This file implements TLS extension parsing and building for ClientHello
 * and ServerHello messages.
 */

#include <opssl/platform.h>
#include <opssl/crypto.h>
#include <opssl/cbs.h>
#include <opssl/err.h>
#include <opssl/types.h>
#include <opssl/ctx.h>
#include <string.h>
#include <stdlib.h>

/* Extension type constants (RFC 8446 / IANA) */
#define EXT_SERVER_NAME 0
#define EXT_STATUS_REQUEST 5
#define EXT_SUPPORTED_GROUPS 10
#define EXT_SIGNATURE_ALGORITHMS 13
#define EXT_ALPN 16
#define EXT_SIGNED_CERT_TIMESTAMP 18
#define EXT_EXTENDED_MASTER_SECRET 23
#define EXT_COMPRESS_CERTIFICATE 27
#define EXT_PRE_SHARED_KEY 41
#define EXT_EARLY_DATA 42
#define EXT_SUPPORTED_VERSIONS 43
#define EXT_COOKIE 44
#define EXT_PSK_KEY_EXCHANGE_MODES 45
#define EXT_CERTIFICATE_AUTHORITIES 47
#define EXT_POST_HANDSHAKE_AUTH 49
#define EXT_SIGNATURE_ALGORITHMS_CERT 50
#define EXT_KEY_SHARE 51

/* Server name types */
#define SNI_HOST_NAME 0

/* RFC 8701: GREASE values have the form 0x?A?A where both nibbles match.
 * Receivers MUST ignore them. */
static inline bool ext_is_grease(uint16_t v)
{
    return ((v & 0x0f0f) == 0x0a0a) && (((v >> 8) & 0xff) == (v & 0xff));
}

/* Track seen extensions to reject duplicates per RFC 8446 §4.2.
 * Uses a small hash set; extension types are 16-bit but only a handful
 * are accepted, so linear scan is fine. */
#define EXT_SEEN_MAX 32
typedef struct {
    uint16_t types[EXT_SEEN_MAX];
    size_t n;
} ext_seen_t;

static int ext_seen_add(ext_seen_t *s, uint16_t t)
{
    for (size_t i = 0; i < s->n; i++) {
        if (s->types[i] == t)
            return 0; /* duplicate */
    }
    if (s->n >= EXT_SEEN_MAX)
        return 0;
    s->types[s->n++] = t;
    return 1;
}

/* Structure to hold parsed extension data */
typedef struct {
    /* SNI */
    const uint8_t *sni;
    size_t sni_len;

    /* Supported groups */
    opssl_named_group_t groups[16];
    size_t ngroups;

    /* Signature algorithms */
    opssl_sig_algo_t sigalgs[16];
    size_t nsigalgs;

    /* Key share */
    opssl_named_group_t ks_group;
    const uint8_t *ks_data;
    size_t ks_len;

    /* ALPN */
    const char *alpn_protos[8];
    size_t alpn_lens[8];
    size_t nalpn;

    /* Supported versions */
    uint16_t versions[4];
    size_t nversions;

    /* Extended master secret */
    bool extended_master_secret;
} opssl_parsed_exts_t;

/* Forward declarations for internal helpers */
static int parse_server_name_ext(opssl_cbs_t *ext_data, opssl_parsed_exts_t *parsed);
static int parse_supported_groups_ext(opssl_cbs_t *ext_data, opssl_parsed_exts_t *parsed);
static int parse_signature_algorithms_ext(opssl_cbs_t *ext_data, opssl_parsed_exts_t *parsed);
static int parse_alpn_ext(opssl_cbs_t *ext_data, opssl_parsed_exts_t *parsed);
static int parse_supported_versions_ext(opssl_cbs_t *ext_data, opssl_parsed_exts_t *parsed);
static int parse_key_share_ext(opssl_cbs_t *ext_data, opssl_parsed_exts_t *parsed);
static const char *select_alpn_protocol(opssl_ctx_t *ctx, const opssl_parsed_exts_t *client_exts);

static int build_server_name_ext(opssl_cbb_t *ext, const char *sni);
static int build_supported_groups_ext(opssl_cbb_t *ext, opssl_named_group_t *groups, size_t ngroups);
static int build_signature_algorithms_ext(opssl_cbb_t *ext);
static int build_alpn_ext(opssl_cbb_t *ext, const char **protos, size_t nprotos);
static int build_supported_versions_ext(opssl_cbb_t *ext, bool is_client);
static int build_key_share_ext(opssl_cbb_t *ext, opssl_named_group_t group,
                              const uint8_t *key_share, size_t ks_len, bool is_client);

int opssl_ext_parse_client_hello(opssl_cbs_t *exts, opssl_parsed_exts_t *parsed)
{
    if (!exts || !parsed) {
        return 0;
    }

    /* Initialize parsed structure */
    memset(parsed, 0, sizeof(*parsed));

    ext_seen_t seen = {0};

    /* Parse each extension */
    while (opssl_cbs_len(exts) > 0) {
        uint16_t ext_type;
        opssl_cbs_t ext_data;

        /* Read extension type and data */
        if (!opssl_cbs_get_u16(exts, &ext_type) ||
            !opssl_cbs_get_u16_length_prefixed(exts, &ext_data)) {
            return 0;
        }

        /* RFC 8701: silently ignore GREASE-typed extensions. */
        if (ext_is_grease(ext_type)) {
            continue;
        }

        /* RFC 8446 §4.2: reject duplicate extensions. */
        if (!ext_seen_add(&seen, ext_type)) {
            return 0;
        }

        switch (ext_type) {
            case EXT_SERVER_NAME:
                if (!parse_server_name_ext(&ext_data, parsed)) {
                    return 0;
                }
                break;

            case EXT_SUPPORTED_GROUPS:
                if (!parse_supported_groups_ext(&ext_data, parsed)) {
                    return 0;
                }
                break;

            case EXT_SIGNATURE_ALGORITHMS:
                if (!parse_signature_algorithms_ext(&ext_data, parsed)) {
                    return 0;
                }
                break;

            case EXT_ALPN:
                if (!parse_alpn_ext(&ext_data, parsed)) {
                    return 0;
                }
                break;

            case EXT_SUPPORTED_VERSIONS:
                if (!parse_supported_versions_ext(&ext_data, parsed)) {
                    return 0;
                }
                break;

            case EXT_KEY_SHARE:
                if (!parse_key_share_ext(&ext_data, parsed)) {
                    return 0;
                }
                break;

            case EXT_EXTENDED_MASTER_SECRET:
                /* EMS extension has no data */
                if (opssl_cbs_len(&ext_data) != 0) {
                    return 0;
                }
                parsed->extended_master_secret = true;
                break;

            default:
                /* Skip unknown extensions (includes psk_key_exchange_modes,
                 * pre_shared_key, early_data, cookie which are not yet
                 * negotiated here; tls13.c handles those). */
                break;
        }
    }

    return 1;
}

int opssl_ext_parse_server_hello(opssl_cbs_t *exts, opssl_parsed_exts_t *parsed)
{
    if (!exts || !parsed) {
        return 0;
    }

    /* Initialize parsed structure */
    memset(parsed, 0, sizeof(*parsed));

    ext_seen_t seen = {0};

    /* Parse each extension */
    while (opssl_cbs_len(exts) > 0) {
        uint16_t ext_type;
        opssl_cbs_t ext_data;

        /* Read extension type and data */
        if (!opssl_cbs_get_u16(exts, &ext_type) ||
            !opssl_cbs_get_u16_length_prefixed(exts, &ext_data)) {
            return 0;
        }

        /* RFC 8701: silently ignore GREASE; RFC 8446: reject duplicates. */
        if (ext_is_grease(ext_type)) {
            continue;
        }
        if (!ext_seen_add(&seen, ext_type)) {
            return 0;
        }

        switch (ext_type) {
            case EXT_ALPN:
                if (!parse_alpn_ext(&ext_data, parsed)) {
                    return 0;
                }
                break;

            case EXT_SUPPORTED_VERSIONS:
                /* ServerHello version is just a single version */
                if (opssl_cbs_len(&ext_data) != 2) {
                    return 0;
                }
                if (!opssl_cbs_get_u16(&ext_data, &parsed->versions[0])) {
                    return 0;
                }
                parsed->nversions = 1;
                break;

            case EXT_KEY_SHARE:
                if (!parse_key_share_ext(&ext_data, parsed)) {
                    return 0;
                }
                break;

            case EXT_EXTENDED_MASTER_SECRET:
                /* EMS extension has no data */
                if (opssl_cbs_len(&ext_data) != 0) {
                    return 0;
                }
                parsed->extended_master_secret = true;
                break;

            default:
                /* Skip unknown extensions */
                break;
        }
    }

    return 1;
}

int opssl_ext_build_client_hello(opssl_cbb_t *exts, const char *sni,
                                 opssl_named_group_t *groups, size_t ngroups,
                                 const uint8_t *key_share, size_t ks_len,
                                 opssl_named_group_t ks_group, opssl_ctx_t *ctx)
{
    if (!exts) {
        return 0;
    }

    /* Build server name extension */
    if (sni) {
        opssl_cbb_t ext_cbb;
        if (!opssl_cbb_add_u16(exts, EXT_SERVER_NAME) ||
            !opssl_cbb_add_u16_length_prefixed(exts, &ext_cbb) ||
            !build_server_name_ext(&ext_cbb, sni) ||
            !opssl_cbb_flush(exts)) {
            return 0;
        }
    }

    /* Build supported groups extension */
    if (groups && ngroups > 0) {
        opssl_cbb_t ext_cbb;
        if (!opssl_cbb_add_u16(exts, EXT_SUPPORTED_GROUPS) ||
            !opssl_cbb_add_u16_length_prefixed(exts, &ext_cbb) ||
            !build_supported_groups_ext(&ext_cbb, groups, ngroups) ||
            !opssl_cbb_flush(exts)) {
            return 0;
        }
    }

    /* Build signature algorithms extension */
    {
        opssl_cbb_t ext_cbb;
        if (!opssl_cbb_add_u16(exts, EXT_SIGNATURE_ALGORITHMS) ||
            !opssl_cbb_add_u16_length_prefixed(exts, &ext_cbb) ||
            !build_signature_algorithms_ext(&ext_cbb) ||
            !opssl_cbb_flush(exts)) {
            return 0;
        }
    }

    /* Build ALPN extension if protocols are configured */
    if (ctx) {
        size_t alpn_count;
        const char **alpn_protos = opssl_ctx_get_alpn_protos(ctx, &alpn_count);

        if (alpn_protos && alpn_count > 0) {
            opssl_cbb_t ext_cbb;
            if (!opssl_cbb_add_u16(exts, EXT_ALPN) ||
                !opssl_cbb_add_u16_length_prefixed(exts, &ext_cbb) ||
                !build_alpn_ext(&ext_cbb, alpn_protos, alpn_count) ||
                !opssl_cbb_flush(exts)) {
                return 0;
            }
        }
    }

    /* Build supported versions extension */
    {
        opssl_cbb_t ext_cbb;
        if (!opssl_cbb_add_u16(exts, EXT_SUPPORTED_VERSIONS) ||
            !opssl_cbb_add_u16_length_prefixed(exts, &ext_cbb) ||
            !build_supported_versions_ext(&ext_cbb, true) ||
            !opssl_cbb_flush(exts)) {
            return 0;
        }
    }

    /* Build key share extension */
    if (key_share && ks_len > 0) {
        opssl_cbb_t ext_cbb;
        if (!opssl_cbb_add_u16(exts, EXT_KEY_SHARE) ||
            !opssl_cbb_add_u16_length_prefixed(exts, &ext_cbb) ||
            !build_key_share_ext(&ext_cbb, ks_group, key_share, ks_len, true) ||
            !opssl_cbb_flush(exts)) {
            return 0;
        }
    }

    /* Build extended master secret extension */
    {
        if (!opssl_cbb_add_u16(exts, EXT_EXTENDED_MASTER_SECRET) ||
            !opssl_cbb_add_u16(exts, 0)) { /* no data */
            return 0;
        }
    }

    return 1;
}

int opssl_ext_build_server_hello(opssl_cbb_t *exts, opssl_named_group_t group,
                                 const uint8_t *key_share, size_t ks_len,
                                 opssl_ctx_t *ctx, const opssl_parsed_exts_t *client_exts,
                                 char *selected_alpn, size_t *selected_alpn_len)
{
    if (!exts) {
        return 0;
    }

    /* Build supported versions extension (TLS 1.3 only) */
    {
        opssl_cbb_t ext_cbb;
        if (!opssl_cbb_add_u16(exts, EXT_SUPPORTED_VERSIONS) ||
            !opssl_cbb_add_u16_length_prefixed(exts, &ext_cbb) ||
            !build_supported_versions_ext(&ext_cbb, false) ||
            !opssl_cbb_flush(exts)) {
            return 0;
        }
    }

    /* ALPN protocol selection and response */
    if (ctx && client_exts && selected_alpn && selected_alpn_len) {
        const char *selected_proto = select_alpn_protocol(ctx, client_exts);
        if (selected_proto) {
            size_t proto_len = strlen(selected_proto);

            /* Store selected protocol for the connection */
            if (proto_len < *selected_alpn_len) {
                memcpy(selected_alpn, selected_proto, proto_len);
                *selected_alpn_len = proto_len;

                /* Build ALPN extension with selected protocol */
                opssl_cbb_t ext_cbb;
                const char *proto_array[1] = { selected_proto };
                if (!opssl_cbb_add_u16(exts, EXT_ALPN) ||
                    !opssl_cbb_add_u16_length_prefixed(exts, &ext_cbb) ||
                    !build_alpn_ext(&ext_cbb, proto_array, 1) ||
                    !opssl_cbb_flush(exts)) {
                    return 0;
                }
            } else {
                /* Buffer too small for selected protocol */
                return 0;
            }
        }
    }

    /* Build key share extension */
    if (key_share && ks_len > 0) {
        opssl_cbb_t ext_cbb;
        if (!opssl_cbb_add_u16(exts, EXT_KEY_SHARE) ||
            !opssl_cbb_add_u16_length_prefixed(exts, &ext_cbb) ||
            !build_key_share_ext(&ext_cbb, group, key_share, ks_len, false) ||
            !opssl_cbb_flush(exts)) {
            return 0;
        }
    }

    /* Build extended master secret extension */
    {
        if (!opssl_cbb_add_u16(exts, EXT_EXTENDED_MASTER_SECRET) ||
            !opssl_cbb_add_u16(exts, 0)) { /* no data */
            return 0;
        }
    }

    return 1;
}

/* Internal helper functions */

static int parse_server_name_ext(opssl_cbs_t *ext_data, opssl_parsed_exts_t *parsed)
{
    opssl_cbs_t server_name_list;
    if (!opssl_cbs_get_u16_length_prefixed(ext_data, &server_name_list)) {
        return 0;
    }
    /* RFC 6066 §3: list MUST NOT be empty and MUST be fully consumed. */
    if (opssl_cbs_len(&server_name_list) == 0 || opssl_cbs_len(ext_data) != 0) {
        return 0;
    }

    bool got_host = false;
    while (opssl_cbs_len(&server_name_list) > 0) {
        uint8_t name_type;
        opssl_cbs_t hostname;

        if (!opssl_cbs_get_u8(&server_name_list, &name_type) ||
            !opssl_cbs_get_u16_length_prefixed(&server_name_list, &hostname)) {
            return 0;
        }

        if (name_type == SNI_HOST_NAME) {
            /* RFC 6066 §3: HostName MUST NOT be empty, and only one
             * host_name entry is allowed per server_name list. */
            if (got_host || opssl_cbs_len(&hostname) == 0 ||
                opssl_cbs_len(&hostname) > 255) {
                return 0;
            }
            parsed->sni = opssl_cbs_data(&hostname);
            parsed->sni_len = opssl_cbs_len(&hostname);
            got_host = true;
        }
    }

    return 1;
}

static int parse_supported_groups_ext(opssl_cbs_t *ext_data, opssl_parsed_exts_t *parsed)
{
    opssl_cbs_t groups_list;
    if (!opssl_cbs_get_u16_length_prefixed(ext_data, &groups_list)) {
        return 0;
    }
    /* RFC 8446 §4.2.7: list MUST NOT be empty; outer extension fully consumed. */
    if (opssl_cbs_len(&groups_list) == 0 ||
        (opssl_cbs_len(&groups_list) % 2) != 0 ||
        opssl_cbs_len(ext_data) != 0) {
        return 0;
    }

    while (opssl_cbs_len(&groups_list) > 0) {
        uint16_t group;
        if (!opssl_cbs_get_u16(&groups_list, &group)) {
            return 0;
        }
        /* RFC 8701: ignore GREASE group codepoints silently. */
        if (ext_is_grease(group)) {
            continue;
        }
        if (parsed->ngroups >= sizeof(parsed->groups) / sizeof(parsed->groups[0])) {
            /* Out of table space — accept remaining as unknown (skip). */
            continue;
        }

        /* Convert to internal group enum */
        switch (group) {
            case 0x001d: parsed->groups[parsed->ngroups] = OPSSL_GROUP_X25519; break;
            case 0x0017: parsed->groups[parsed->ngroups] = OPSSL_GROUP_SECP256R1; break;
            case 0x0018: parsed->groups[parsed->ngroups] = OPSSL_GROUP_SECP384R1; break;
            case 0x0019: parsed->groups[parsed->ngroups] = OPSSL_GROUP_SECP521R1; break;
            case 0x001e: parsed->groups[parsed->ngroups] = OPSSL_GROUP_X448; break;
            case 0x6399: parsed->groups[parsed->ngroups] = OPSSL_GROUP_X25519_MLKEM768; break;
            case 0x639A: parsed->groups[parsed->ngroups] = OPSSL_GROUP_SECP256R1_MLKEM768; break;
            case 0x639B: parsed->groups[parsed->ngroups] = OPSSL_GROUP_SECP384R1_MLKEM1024; break;
            default: continue;
        }

        parsed->ngroups++;
    }

    return 1;
}

static int parse_signature_algorithms_ext(opssl_cbs_t *ext_data, opssl_parsed_exts_t *parsed)
{
    opssl_cbs_t sigalgs_list;
    if (!opssl_cbs_get_u16_length_prefixed(ext_data, &sigalgs_list)) {
        return 0;
    }
    /* RFC 8446 §4.2.3: list MUST NOT be empty; entries are 2 bytes each. */
    if (opssl_cbs_len(&sigalgs_list) == 0 ||
        (opssl_cbs_len(&sigalgs_list) % 2) != 0 ||
        opssl_cbs_len(ext_data) != 0) {
        return 0;
    }

    while (opssl_cbs_len(&sigalgs_list) > 0) {
        uint16_t sigalg;
        if (!opssl_cbs_get_u16(&sigalgs_list, &sigalg)) {
            return 0;
        }
        if (ext_is_grease(sigalg)) {
            continue;
        }
        if (parsed->nsigalgs >= sizeof(parsed->sigalgs) / sizeof(parsed->sigalgs[0])) {
            continue;
        }

        /* Convert to internal sigalg enum */
        switch (sigalg) {
            case 0x0201: parsed->sigalgs[parsed->nsigalgs] = OPSSL_SIG_RSA_PKCS1_SHA1; break;
            case 0x0401: parsed->sigalgs[parsed->nsigalgs] = OPSSL_SIG_RSA_PKCS1_SHA256; break;
            case 0x0501: parsed->sigalgs[parsed->nsigalgs] = OPSSL_SIG_RSA_PKCS1_SHA384; break;
            case 0x0601: parsed->sigalgs[parsed->nsigalgs] = OPSSL_SIG_RSA_PKCS1_SHA512; break;
            case 0x0804: parsed->sigalgs[parsed->nsigalgs] = OPSSL_SIG_RSA_PSS_SHA256; break;
            case 0x0805: parsed->sigalgs[parsed->nsigalgs] = OPSSL_SIG_RSA_PSS_SHA384; break;
            case 0x0806: parsed->sigalgs[parsed->nsigalgs] = OPSSL_SIG_RSA_PSS_SHA512; break;
            case 0x0203: parsed->sigalgs[parsed->nsigalgs] = OPSSL_SIG_ECDSA_SHA1; break;
            case 0x0403: parsed->sigalgs[parsed->nsigalgs] = OPSSL_SIG_ECDSA_SECP256R1; break;
            case 0x0503: parsed->sigalgs[parsed->nsigalgs] = OPSSL_SIG_ECDSA_SECP384R1; break;
            case 0x0603: parsed->sigalgs[parsed->nsigalgs] = OPSSL_SIG_ECDSA_SECP521R1; break;
            case 0x0807: parsed->sigalgs[parsed->nsigalgs] = OPSSL_SIG_ED25519; break;
            case 0x0808: parsed->sigalgs[parsed->nsigalgs] = OPSSL_SIG_ED448; break;
            default: continue; /* Skip unknown signature algorithms */
        }

        parsed->nsigalgs++;
    }

    return 1;
}

static int parse_alpn_ext(opssl_cbs_t *ext_data, opssl_parsed_exts_t *parsed)
{
    opssl_cbs_t protocol_list;
    if (!opssl_cbs_get_u16_length_prefixed(ext_data, &protocol_list)) {
        return 0;
    }
    /* RFC 7301 §3.1: list MUST NOT be empty; outer fully consumed. */
    if (opssl_cbs_len(&protocol_list) == 0 || opssl_cbs_len(ext_data) != 0) {
        return 0;
    }

    while (opssl_cbs_len(&protocol_list) > 0) {
        opssl_cbs_t protocol;
        if (!opssl_cbs_get_u8_length_prefixed(&protocol_list, &protocol)) {
            return 0;
        }
        /* RFC 7301: ProtocolName MUST NOT be empty. */
        if (opssl_cbs_len(&protocol) == 0) {
            return 0;
        }
        if (parsed->nalpn >= sizeof(parsed->alpn_protos) / sizeof(parsed->alpn_protos[0])) {
            /* Table full — drop remaining client-offered names rather than fail. */
            continue;
        }

        parsed->alpn_protos[parsed->nalpn] = (const char *)opssl_cbs_data(&protocol);
        parsed->alpn_lens[parsed->nalpn] = opssl_cbs_len(&protocol);
        parsed->nalpn++;
    }

    return 1;
}

static int parse_supported_versions_ext(opssl_cbs_t *ext_data, opssl_parsed_exts_t *parsed)
{
    opssl_cbs_t versions_list;
    if (!opssl_cbs_get_u8_length_prefixed(ext_data, &versions_list)) {
        return 0;
    }
    /* RFC 8446 §4.2.1: list MUST NOT be empty, MUST be even-length, and the
     * outer extension data MUST be fully consumed. */
    if (opssl_cbs_len(&versions_list) == 0 ||
        (opssl_cbs_len(&versions_list) % 2) != 0 ||
        opssl_cbs_len(ext_data) != 0) {
        return 0;
    }

    while (opssl_cbs_len(&versions_list) > 0) {
        uint16_t version;
        if (!opssl_cbs_get_u16(&versions_list, &version)) {
            return 0;
        }
        if (ext_is_grease(version)) {
            continue;
        }
        if (parsed->nversions >= sizeof(parsed->versions) / sizeof(parsed->versions[0])) {
            continue;
        }

        parsed->versions[parsed->nversions] = version;
        parsed->nversions++;
    }

    return 1;
}

/*
 * Parse a single KeyShareEntry { group(2) | key_exchange<1..2^16-1> } from
 * the cursor `entries`, populating `parsed` only if the group is recognized
 * and not already set. Returns 0 on malformed input.
 */
static int parse_one_key_share_entry(opssl_cbs_t *entries, opssl_parsed_exts_t *parsed)
{
    uint16_t group;
    opssl_cbs_t key_exchange;

    if (!opssl_cbs_get_u16(entries, &group) ||
        !opssl_cbs_get_u16_length_prefixed(entries, &key_exchange)) {
        return 0;
    }
    /* RFC 8446 §4.2.8: key_exchange MUST NOT be empty. */
    if (opssl_cbs_len(&key_exchange) == 0) {
        return 0;
    }
    /* GREASE entries: silently ignored. */
    if (ext_is_grease(group)) {
        return 1;
    }

    /* Skip if we already locked onto a usable group earlier in the list. */
    if (parsed->ks_data != NULL) {
        return 1;
    }

    switch (group) {
        case 0x001d: parsed->ks_group = OPSSL_GROUP_X25519; break;
        case 0x0017: parsed->ks_group = OPSSL_GROUP_SECP256R1; break;
        case 0x0018: parsed->ks_group = OPSSL_GROUP_SECP384R1; break;
        case 0x0019: parsed->ks_group = OPSSL_GROUP_SECP521R1; break;
        case 0x001e: parsed->ks_group = OPSSL_GROUP_X448; break;
        case 0x6399: parsed->ks_group = OPSSL_GROUP_X25519_MLKEM768; break;
        case 0x639A: parsed->ks_group = OPSSL_GROUP_SECP256R1_MLKEM768; break;
        case 0x639B: parsed->ks_group = OPSSL_GROUP_SECP384R1_MLKEM1024; break;
        default: return 1; /* unrecognized — skip per RFC 8446 §4.2.8 */
    }

    parsed->ks_data = opssl_cbs_data(&key_exchange);
    parsed->ks_len = opssl_cbs_len(&key_exchange);
    return 1;
}

static int parse_key_share_ext(opssl_cbs_t *ext_data, opssl_parsed_exts_t *parsed)
{
    /*
     * RFC 8446 §4.2.8:
     *   ClientHello / HelloRetryRequest payload is
     *     KeyShareEntry client_shares<0..2^16-1>;
     *   ServerHello payload is a single KeyShareEntry (no outer length).
     *
     * We can disambiguate by peeking: if the first u16 plausibly equals the
     * remaining length minus 2, treat it as a length-prefixed list. Otherwise
     * treat it as a bare entry. Probing a u16 length prefix and then resetting
     * is undefined behavior with the CBS API, so we duplicate the cursor.
     */
    opssl_cbs_t cursor;
    if (opssl_cbs_len(ext_data) < 2) {
        /* Empty (HRR-style "no shares") is allowed in some flows. */
        return 1;
    }

    /* Try ClientHello list format first by snapshotting the cursor. */
    cursor = *ext_data;
    opssl_cbs_t client_shares;
    if (opssl_cbs_get_u16_length_prefixed(&cursor, &client_shares) &&
        opssl_cbs_len(&cursor) == 0) {
        /* Valid CH list framing: length prefix exactly equals remaining bytes. */
        while (opssl_cbs_len(&client_shares) > 0) {
            if (!parse_one_key_share_entry(&client_shares, parsed)) {
                return 0;
            }
        }
        return 1;
    }

    /* Otherwise treat as a single ServerHello KeyShareEntry. */
    cursor = *ext_data;
    if (!parse_one_key_share_entry(&cursor, parsed)) {
        return 0;
    }
    /* SH entry MUST fully consume the extension. */
    if (opssl_cbs_len(&cursor) != 0) {
        return 0;
    }
    return 1;
}

static int build_server_name_ext(opssl_cbb_t *ext, const char *sni)
{
    opssl_cbb_t server_name_list, server_name;
    size_t sni_len = strlen(sni);

    if (!opssl_cbb_add_u16_length_prefixed(ext, &server_name_list) ||
        !opssl_cbb_add_u8(&server_name_list, SNI_HOST_NAME) ||
        !opssl_cbb_add_u16_length_prefixed(&server_name_list, &server_name) ||
        !opssl_cbb_add_bytes(&server_name, (const uint8_t *)sni, sni_len)) {
        return 0;
    }

    return 1;
}

static int build_supported_groups_ext(opssl_cbb_t *ext, opssl_named_group_t *groups, size_t ngroups)
{
    opssl_cbb_t groups_list;

    if (!opssl_cbb_add_u16_length_prefixed(ext, &groups_list)) {
        return 0;
    }

    for (size_t i = 0; i < ngroups; i++) {
        uint16_t wire_group;

        /* Convert internal enum to wire format */
        switch (groups[i]) {
            case OPSSL_GROUP_X25519: wire_group = 0x001d; break;
            case OPSSL_GROUP_SECP256R1: wire_group = 0x0017; break;
            case OPSSL_GROUP_SECP384R1: wire_group = 0x0018; break;
            case OPSSL_GROUP_SECP521R1: wire_group = 0x0019; break;
            case OPSSL_GROUP_X448: wire_group = 0x001e; break;
            case OPSSL_GROUP_X25519_MLKEM768: wire_group = 0x6399; break;
            case OPSSL_GROUP_SECP256R1_MLKEM768: wire_group = 0x639A; break;
            case OPSSL_GROUP_SECP384R1_MLKEM1024: wire_group = 0x639B; break;
            default: continue;
        }

        if (!opssl_cbb_add_u16(&groups_list, wire_group)) {
            return 0;
        }
    }

    return 1;
}

static int build_signature_algorithms_ext(opssl_cbb_t *ext)
{
    opssl_cbb_t sigalgs_list;

    if (!opssl_cbb_add_u16_length_prefixed(ext, &sigalgs_list)) {
        return 0;
    }

    /* Add commonly supported signature algorithms */
    uint16_t supported_sigalgs[] = {
        0x0403, /* ecdsa_secp256r1_sha256 */
        0x0503, /* ecdsa_secp384r1_sha384 */
        0x0603, /* ecdsa_secp521r1_sha512 */
        0x0807, /* ed25519 */
        0x0808, /* ed448 */
        0x0804, /* rsa_pss_rsae_sha256 */
        0x0805, /* rsa_pss_rsae_sha384 */
        0x0806, /* rsa_pss_rsae_sha512 */
        0x0201, /* rsa_pkcs1_sha1 */
        0x0401, /* rsa_pkcs1_sha256 */
        0x0501, /* rsa_pkcs1_sha384 */
        0x0601, /* rsa_pkcs1_sha512 */
        0x0203, /* ecdsa_sha1 */
    };

    for (size_t i = 0; i < sizeof(supported_sigalgs) / sizeof(supported_sigalgs[0]); i++) {
        if (!opssl_cbb_add_u16(&sigalgs_list, supported_sigalgs[i])) {
            return 0;
        }
    }

    return 1;
}

static int build_alpn_ext(opssl_cbb_t *ext, const char **protos, size_t nprotos)
{
    opssl_cbb_t protocol_list;

    if (!opssl_cbb_add_u16_length_prefixed(ext, &protocol_list)) {
        return 0;
    }

    for (size_t i = 0; i < nprotos; i++) {
        opssl_cbb_t protocol;
        size_t proto_len = strlen(protos[i]);

        if (!opssl_cbb_add_u8_length_prefixed(&protocol_list, &protocol) ||
            !opssl_cbb_add_bytes(&protocol, (const uint8_t *)protos[i], proto_len)) {
            return 0;
        }
    }

    return 1;
}

static int build_supported_versions_ext(opssl_cbb_t *ext, bool is_client)
{
    if (is_client) {
        /* ClientHello: list of supported versions */
        opssl_cbb_t versions_list;

        if (!opssl_cbb_add_u8_length_prefixed(ext, &versions_list)) {
            return 0;
        }

        /* Prefer TLS 1.3, fall back to TLS 1.2 */
        if (!opssl_cbb_add_u16(&versions_list, 0x0304) || /* TLS 1.3 */
            !opssl_cbb_add_u16(&versions_list, 0x0303)) {  /* TLS 1.2 */
            return 0;
        }
    } else {
        /* ServerHello: single selected version */
        if (!opssl_cbb_add_u16(ext, 0x0304)) { /* TLS 1.3 */
            return 0;
        }
    }

    return 1;
}

static int build_key_share_ext(opssl_cbb_t *ext, opssl_named_group_t group,
                              const uint8_t *key_share, size_t ks_len, bool is_client)
{
    uint16_t wire_group;

    /* Convert internal group to wire format */
    switch (group) {
        case OPSSL_GROUP_X25519: wire_group = 0x001d; break;
        case OPSSL_GROUP_SECP256R1: wire_group = 0x0017; break;
        case OPSSL_GROUP_SECP384R1: wire_group = 0x0018; break;
        case OPSSL_GROUP_SECP521R1: wire_group = 0x0019; break;
        case OPSSL_GROUP_X448: wire_group = 0x001e; break;
        default: return 0; /* Unknown group */
    }

    if (is_client) {
        /* ClientHello: list of key shares */
        opssl_cbb_t key_shares, key_exchange;

        if (!opssl_cbb_add_u16_length_prefixed(ext, &key_shares) ||
            !opssl_cbb_add_u16(&key_shares, wire_group) ||
            !opssl_cbb_add_u16_length_prefixed(&key_shares, &key_exchange) ||
            !opssl_cbb_add_bytes(&key_exchange, key_share, ks_len)) {
            return 0;
        }
    } else {
        /* ServerHello: single key share */
        opssl_cbb_t key_exchange;

        if (!opssl_cbb_add_u16(ext, wire_group) ||
            !opssl_cbb_add_u16_length_prefixed(ext, &key_exchange) ||
            !opssl_cbb_add_bytes(&key_exchange, key_share, ks_len)) {
            return 0;
        }
    }

    return 1;
}

/* ALPN protocol selection for server */
static const char *select_alpn_protocol(opssl_ctx_t *ctx, const opssl_parsed_exts_t *client_exts)
{
    if (!ctx || !client_exts || client_exts->nalpn == 0) {
        return NULL;
    }

    /* Get server's supported protocols */
    size_t server_count;
    const char **server_protos = opssl_ctx_get_alpn_protos(ctx, &server_count);

    if (!server_protos || server_count == 0) {
        return NULL;
    }

    /* Select the first server protocol that matches any client protocol */
    for (size_t i = 0; i < server_count; i++) {
        for (size_t j = 0; j < client_exts->nalpn; j++) {
            size_t server_len = strlen(server_protos[i]);
            size_t client_len = client_exts->alpn_lens[j];

            if (server_len == client_len &&
                memcmp(server_protos[i], client_exts->alpn_protos[j], server_len) == 0) {
                return server_protos[i];
            }
        }
    }

    return NULL; /* No match found */
}
