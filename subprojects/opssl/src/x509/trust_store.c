/*
 * opssl/x509/trust_store.c - trusted root CA store with SHA-256 keyed hash table.
 *
 * Each entry is keyed by SHA-256(SubjectDN_raw || SPKI_DER). Stable across
 * re-encodings that preserve Subject DN and public key.
 *
 * Open-addressing hash table with linear probing, 75% load cap.
 * Table size is always power of two for O(1) index masking.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/cert.h>
#include <opssl/crypto.h>
#include <opssl/platform.h>
#include <opssl/err.h>
#include "asn1_internal.h"

#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>

extern int opssl_pem_decode_multi(const char *pem, size_t pem_len,
                                  uint8_t **ders, size_t *der_lens,
                                  size_t *count, size_t max_count);

/*
 * System trust bundle locations, probed in priority order.
 *
 * Linux (Debian/Ubuntu/Arch):   /etc/ssl/certs/ca-certificates.crt
 * Linux (Fedora/RHEL):          /etc/pki/tls/certs/ca-bundle.crt
 * Linux (SUSE):                 /etc/ssl/ca-bundle.pem
 * Linux (Alpine/OpenWrt):       /etc/ssl/cert.pem
 * Linux (legacy extracted):     /etc/ca-certificates/extracted/tls-ca-bundle.pem
 * FreeBSD/NetBSD:               /usr/local/share/certs/ca-root-nss.crt
 *                               /etc/ssl/cert.pem (NetBSD/OpenBSD)
 * macOS (Homebrew openssl):     /usr/local/etc/openssl@3/cert.pem
 *                               /opt/homebrew/etc/openssl@3/cert.pem (Apple Silicon)
 * macOS (system keychain):      export via security(1); not parsed here.
 */
static const char *const system_trust_paths[] = {
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/ca-certificates/extracted/tls-ca-bundle.pem",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/ssl/cert.pem",
    "/usr/local/share/certs/ca-root-nss.crt",
    "/usr/local/etc/openssl@3/cert.pem",
    "/opt/homebrew/etc/openssl@3/cert.pem",
    "/etc/openssl/certs/ca-certificates.crt",
    NULL
};

/* Optional per-distro trust hash directories — last resort fallback. */
static const char *const system_trust_dirs[] = {
    "/etc/ssl/certs",
    "/etc/pki/ca-trust/source/anchors",
    "/usr/local/share/ca-certificates",
    NULL
};

typedef struct {
    uint8_t key[32];
    bool    occupied;
} ts_slot_t;

struct opssl_trust_store {
    ts_slot_t *slots;
    size_t     cap;
    size_t     count;
};

#define TS_INIT_CAP  64u
#define TS_LOAD_NUM  3u
#define TS_LOAD_DEN  4u

static int
extract_subject_spki(const uint8_t *cert_der, size_t cert_der_len,
                     const uint8_t **subject_out, size_t *subject_len_out,
                     const uint8_t **spki_out,    size_t *spki_len_out)
{
    opssl_cbs_t cbs, cert_seq, tbs;
    uint8_t tag;

    opssl_cbs_init(&cbs, cert_der, cert_der_len);
    if (!opssl_asn1_get_sequence(&cbs, &cert_seq))  return 0;
    if (!opssl_asn1_get_sequence(&cert_seq, &tbs))  return 0;

    if (opssl_cbs_len(&tbs) > 0 &&
        opssl_cbs_peek_u8(&tbs, &tag) && tag == 0xA0) {
        opssl_cbs_t ver_ctx;
        if (!opssl_asn1_get_element(&tbs, 0xA0, &ver_ctx)) return 0;
    }

    opssl_cbs_t serial;
    if (!opssl_asn1_get_integer(&tbs, &serial)) return 0;

    opssl_cbs_t sig_alg;
    if (!opssl_asn1_get_sequence(&tbs, &sig_alg)) return 0;

    if (!opssl_asn1_skip_element(&tbs)) return 0;  /* issuer */
    if (!opssl_asn1_skip_element(&tbs)) return 0;  /* validity */

    const uint8_t *subject_start = opssl_cbs_data(&tbs);
    opssl_cbs_t subject_seq;
    if (!opssl_asn1_get_sequence(&tbs, &subject_seq)) return 0;
    size_t subject_len = (size_t)(opssl_cbs_data(&tbs) - subject_start);

    const uint8_t *spki_start = opssl_cbs_data(&tbs);
    opssl_cbs_t spki_seq;
    if (!opssl_asn1_get_sequence(&tbs, &spki_seq)) return 0;
    size_t spki_len = (size_t)(opssl_cbs_data(&tbs) - spki_start);

    *subject_out     = subject_start;
    *subject_len_out = subject_len;
    *spki_out        = spki_start;
    *spki_len_out    = spki_len;
    return 1;
}

/*
 * cert_key - compute SHA-256(SubjectDN || SPKI) for a DER cert.
 *
 * We concatenate the two DER fields into a temporary buffer and call the
 * one-shot opssl_sha256() to avoid depending on the opaque sha256 context.
 */
static int
cert_key(const uint8_t *cert_der, size_t cert_der_len, uint8_t key_out[32])
{
    const uint8_t *subject, *spki;
    size_t subject_len, spki_len;

    if (!extract_subject_spki(cert_der, cert_der_len,
                              &subject, &subject_len,
                              &spki, &spki_len))
        return 0;

    size_t combined_len = subject_len + spki_len;
    uint8_t *buf = op_malloc(combined_len);
    memcpy(buf, subject, subject_len);
    memcpy(buf + subject_len, spki, spki_len);
    opssl_sha256(buf, combined_len, key_out);
    op_free(buf);
    return 1;
}

static void
ts_rehash(opssl_trust_store_t *store, size_t new_cap)
{
    ts_slot_t *new_slots = op_calloc(new_cap, sizeof(ts_slot_t));

    for (size_t i = 0; i < store->cap; i++) {
        if (!store->slots[i].occupied) continue;
        const uint8_t *k = store->slots[i].key;
        uint32_t h = (uint32_t)k[0] << 24 | (uint32_t)k[1] << 16 |
                     (uint32_t)k[2] << 8  | (uint32_t)k[3];
        size_t idx = (size_t)(h & (uint32_t)(new_cap - 1));
        while (new_slots[idx].occupied)
            idx = (idx + 1) & (new_cap - 1);
        new_slots[idx] = store->slots[i];
    }

    op_free(store->slots);
    store->slots = new_slots;
    store->cap   = new_cap;
}

static void
ts_insert_key(opssl_trust_store_t *store, const uint8_t key[32])
{
    if (store->count * TS_LOAD_DEN >= store->cap * TS_LOAD_NUM)
        ts_rehash(store, store->cap * 2);

    const uint32_t h = (uint32_t)key[0] << 24 | (uint32_t)key[1] << 16 |
                       (uint32_t)key[2] << 8  | (uint32_t)key[3];
    size_t idx = (size_t)(h & (uint32_t)(store->cap - 1));

    while (store->slots[idx].occupied) {
        if (memcmp(store->slots[idx].key, key, 32) == 0) return;
        idx = (idx + 1) & (store->cap - 1);
    }

    memcpy(store->slots[idx].key, key, 32);
    store->slots[idx].occupied = true;
    store->count++;
}

#define TS_MAX_BUNDLE 512

static int
load_pem_bundle(opssl_trust_store_t *store, const char *pem_data, size_t pem_len)
{
    uint8_t *ders[TS_MAX_BUNDLE];
    size_t   der_lens[TS_MAX_BUNDLE];
    size_t   count = 0;
    int      added = 0;

    if (!opssl_pem_decode_multi(pem_data, pem_len,
                                ders, der_lens, &count, TS_MAX_BUNDLE))
        return 0;

    for (size_t i = 0; i < count; i++) {
        if (opssl_trust_store_add_cert(store, ders[i], der_lens[i]) == 1)
            added++;
        op_free(ders[i]);
    }
    return added;
}

opssl_trust_store_t *
opssl_trust_store_new(void)
{
    opssl_trust_store_t *store = op_calloc(1, sizeof(*store));
    store->slots = op_calloc(TS_INIT_CAP, sizeof(ts_slot_t));
    store->cap   = TS_INIT_CAP;
    store->count = 0;
    return store;
}

void
opssl_trust_store_free(opssl_trust_store_t *store)
{
    if (!store) return;
    op_free(store->slots);
    op_free(store);
}

int
opssl_trust_store_add_cert(opssl_trust_store_t *store, const uint8_t *der, size_t len)
{
    if (!store || !der || len == 0) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT,
                        "trust_store_add_cert: invalid arguments");
        return 0;
    }

    /*
     * Reject expired root certificates. A trust anchor whose notAfter is in
     * the past is poison: it can sign anything but no peer will trust the
     * resulting chain. Parsing the cert is cheap relative to the SHA-256 we
     * are already about to do, and it gives us a clean rejection point.
     *
     * If the cert fails to parse at all, we silently skip it: bundle files
     * sometimes contain stray garbage and we want load_default() to be
     * resilient rather than aborting on the first malformed entry.
     */
    opssl_x509_t *cert = opssl_x509_from_der(der, len);
    if (!cert) {
        return 0;
    }
    if (opssl_x509_is_expired(cert)) {
        opssl_x509_free(cert);
        return 0;
    }
    opssl_x509_free(cert);

    uint8_t key[32];
    if (!cert_key(der, len, key)) return 0;
    ts_insert_key(store, key);
    return 1;
}

int
opssl_trust_store_contains(const opssl_trust_store_t *store,
                           const uint8_t *cert_der, size_t cert_len)
{
    if (!store || !cert_der || cert_len == 0) return 0;
    uint8_t key[32];
    if (!cert_key(cert_der, cert_len, key)) return 0;
    const uint32_t h = (uint32_t)key[0] << 24 | (uint32_t)key[1] << 16 |
                       (uint32_t)key[2] << 8  | (uint32_t)key[3];
    size_t idx = (size_t)(h & (uint32_t)(store->cap - 1));
    while (store->slots[idx].occupied) {
        if (memcmp(store->slots[idx].key, key, 32) == 0) return 1;
        idx = (idx + 1) & (store->cap - 1);
    }
    return 0;
}

int
opssl_trust_store_load_file(opssl_trust_store_t *store, const char *path)
{
    if (!store || !path) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT,
                        "trust_store_load_file: invalid arguments");
        return 0;
    }
    FILE *fp = fopen(path, "r");
    if (!fp) {
        opssl_set_error(OPSSL_ERR_FILE_READ, "cannot open trust bundle file");
        return 0;
    }
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return 0; }
    long fsize = ftell(fp);
    if (fsize <= 0 || fsize > 16L * 1024L * 1024L) {
        fclose(fp);
        opssl_set_error(OPSSL_ERR_FILE_READ, "trust bundle is empty or too large");
        return 0;
    }
    rewind(fp);
    char *pem_data = op_malloc((size_t)fsize + 1);
    size_t nread = fread(pem_data, 1, (size_t)fsize, fp);
    fclose(fp);
    pem_data[nread] = 0;
    int added = load_pem_bundle(store, pem_data, nread);
    op_free(pem_data);
    return added;
}

int
opssl_trust_store_load_dir(opssl_trust_store_t *store, const char *path)
{
    if (!store || !path) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT,
                        "trust_store_load_dir: invalid arguments");
        return 0;
    }
    DIR *dir = opendir(path);
    if (!dir) {
        opssl_set_error(OPSSL_ERR_FILE_READ, "cannot open trust cert directory");
        return 0;
    }
    int total = 0;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.') continue;  /* skip hidden entries */
        const char *ext = strrchr(ent->d_name, '.');
        if (!ext || (strcmp(ext, ".pem") != 0 &&
                     strcmp(ext, ".crt") != 0 &&
                     strcmp(ext, ".cer") != 0))
            continue;
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", path, ent->d_name);
        struct stat st;
        if (stat(full, &st) != 0 || !S_ISREG(st.st_mode)) continue;
        int n = opssl_trust_store_load_file(store, full);
        if (n > 0) total += n;
    }
    closedir(dir);
    return total;
}

int
opssl_trust_store_load_default(opssl_trust_store_t *store)
{
    if (!store) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT,
                        "trust_store_load_default: invalid arguments");
        return 0;
    }
    for (int i = 0; system_trust_paths[i] != NULL; i++) {
        struct stat st;
        if (stat(system_trust_paths[i], &st) == 0 && S_ISREG(st.st_mode)) {
            int n = opssl_trust_store_load_file(store, system_trust_paths[i]);
            if (n > 0) return n;
        }
    }

    /* No single-bundle file worked; fall back to per-cert hash directories. */
    for (int i = 0; system_trust_dirs[i] != NULL; i++) {
        struct stat st;
        if (stat(system_trust_dirs[i], &st) == 0 && S_ISDIR(st.st_mode)) {
            int n = opssl_trust_store_load_dir(store, system_trust_dirs[i]);
            if (n > 0) return n;
        }
    }

    opssl_set_error(OPSSL_ERR_FILE_READ, "no system trust bundle found");
    return 0;
}

/*
 * opssl_trust_store_load_crl - load a CRL file (PEM or DER) and stage it for
 * later x509_store consumption. The trust store itself does not perform
 * revocation checking; this entry point exists so callers can load a CRL
 * path uniformly with cert bundles. URI/HTTP fetch is intentionally out of
 * scope — pass a local path only.
 *
 * Returns 1 on successful parse, 0 on any failure. On success the CRL object
 * is returned via *crl_out and the caller owns the lifetime.
 */
int
opssl_trust_store_load_crl(const char *path, opssl_crl_t **crl_out)
{
    if (!path || !crl_out) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT,
                        "trust_store_load_crl: invalid arguments");
        return 0;
    }
    *crl_out = NULL;

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        opssl_set_error(OPSSL_ERR_FILE_READ, "cannot open CRL file");
        return 0;
    }
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return 0; }
    long fsize = ftell(fp);
    if (fsize <= 0 || fsize > 16L * 1024L * 1024L) {
        fclose(fp);
        opssl_set_error(OPSSL_ERR_FILE_READ, "CRL file empty or oversize");
        return 0;
    }
    rewind(fp);
    uint8_t *buf = op_malloc((size_t)fsize + 1);
    size_t nread = fread(buf, 1, (size_t)fsize, fp);
    fclose(fp);
    buf[nread] = 0;

    /* PEM banner sniff: "-----BEGIN" — otherwise treat as raw DER. */
    opssl_crl_t *crl;
    if (nread >= 10 && memcmp(buf, "-----BEGIN", 10) == 0) {
        crl = opssl_crl_from_pem((const char *)buf, nread);
    } else {
        crl = opssl_crl_from_der(buf, nread);
    }
    op_free(buf);

    if (!crl) {
        opssl_set_error(OPSSL_ERR_X509, "CRL parse failed");
        return 0;
    }
    *crl_out = crl;
    return 1;
}
