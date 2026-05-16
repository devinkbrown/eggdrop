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

static const char *const system_trust_paths[] = {
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/ca-certificates/extracted/tls-ca-bundle.pem",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/ssl/cert.pem",
    "/usr/local/share/certs/ca-root-nss.crt",
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
        if (ent->d_name[0] == 46) continue;  /* skip dot-files: 46 == . */
        const char *ext = strrchr(ent->d_name, 46);
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
    opssl_set_error(OPSSL_ERR_FILE_READ, "no system trust bundle found");
    return 0;
}
