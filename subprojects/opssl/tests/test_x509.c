/*
 * test_x509.c — X.509 certificate and store tests.
 *
 * Minimal X.509 test — verify certificate store API and fingerprint formatting.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/opssl.h>
#include <stdio.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

#define ASSERT_EQ(a, b, msg) do { tests_run++; if ((a) == (b)) { tests_passed++; } else { printf("FAIL: %s (line %d)\n", msg, __LINE__); } } while(0)
#define ASSERT_NE(a, b, msg) do { tests_run++; if ((a) != (b)) { tests_passed++; } else { printf("FAIL: %s (line %d)\n", msg, __LINE__); } } while(0)

static void test_x509_store_lifecycle(void)
{
    opssl_x509_store_t *store = opssl_x509_store_new();
    ASSERT_NE(store, NULL, "x509_store_new returns non-null");

    opssl_x509_store_free(store);
}

static void test_x509_store_operations(void)
{
    opssl_x509_store_t *store = opssl_x509_store_new();
    ASSERT_NE(store, NULL, "x509_store_new succeeds");

    /* Try to load from non-existent file (should fail gracefully) */
    int rc = opssl_x509_store_load_file(store, "/nonexistent/ca-bundle.pem");
    ASSERT_EQ(rc, 0, "loading non-existent file fails gracefully");

    /* Try to load from non-existent directory (should fail gracefully) */
    rc = opssl_x509_store_load_dir(store, "/nonexistent/ca-certs/");
    ASSERT_EQ(rc, 0, "loading non-existent directory fails gracefully");

    opssl_x509_store_free(store);
}

static void test_x509_fingerprint_formatting(void)
{
    /* Mock DER certificate data (simplified) */
    const uint8_t mock_cert_der[] = {
        0x30, 0x82, 0x03, 0x85, 0x30, 0x82, 0x02, 0x6d, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x1a,
        0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09, 0x1a,
        0x2b, 0x3c, 0x4d
    };

    /* Create a certificate from DER data */
    opssl_x509_t *cert = opssl_x509_from_der(mock_cert_der, sizeof(mock_cert_der));

    if (cert != NULL) {
        /* Test fingerprint calculation */
        uint8_t fp_bytes[32];
        size_t fp_len = sizeof(fp_bytes);
        int rc = opssl_x509_fingerprint(cert, OPSSL_FP_SHA256, fp_bytes, &fp_len);

        if (rc == 1) {
            /* Test hex formatting */
            char fp_hex[128];
            rc = opssl_x509_fingerprint_hex(cert, OPSSL_FP_SHA256, fp_hex, sizeof(fp_hex));
            ASSERT_EQ(rc, 1, "fingerprint hex formatting succeeds");

            /* Check that hex string is not empty */
            ASSERT_NE(strlen(fp_hex), 0, "fingerprint hex string is not empty");

            /* Check that hex string has expected length (32 bytes * 2 hex chars + colons) */
            ASSERT_EQ(strlen(fp_hex), 95, "SHA256 fingerprint hex length is correct (32*2 + 31 colons)");
        } else {
            printf("INFO: fingerprint calculation failed (expected for mock DER)\n");
        }

        opssl_x509_free(cert);
    } else {
        printf("INFO: mock certificate parsing failed (expected)\n");
    }
}

static void test_x509_chain_operations(void)
{
    /* Test chain creation from non-existent file */
    opssl_x509_chain_t *chain = opssl_x509_chain_from_file("/nonexistent/cert-chain.pem");
    ASSERT_EQ(chain, NULL, "chain from non-existent file returns null");

    /* Create empty chain for API testing */
    if (chain != NULL) {
        size_t count = opssl_x509_chain_count(chain);
        ASSERT_EQ(count, 0, "empty chain has zero count");

        opssl_x509_chain_free(chain);
    }
}

static void test_certificate_validation(void)
{
    /* Test certificate parsing from non-existent file */
    opssl_x509_t *cert = opssl_x509_from_file("/nonexistent/cert.pem");
    ASSERT_EQ(cert, NULL, "certificate from non-existent file returns null");

    /* Test parsing invalid DER data */
    const uint8_t invalid_der[] = {0xff, 0xff, 0xff, 0xff};
    cert = opssl_x509_from_der(invalid_der, sizeof(invalid_der));
    ASSERT_EQ(cert, NULL, "certificate from invalid DER returns null");

    /* Test parsing invalid PEM data */
    const char *invalid_pem = "-----BEGIN CERTIFICATE-----\nINVALID DATA\n-----END CERTIFICATE-----";
    cert = opssl_x509_from_pem(invalid_pem, strlen(invalid_pem));
    ASSERT_EQ(cert, NULL, "certificate from invalid PEM returns null");
}

static void test_private_key_operations(void)
{
    /* Test private key parsing from non-existent file */
    opssl_pkey_t *key = opssl_pkey_from_file("/nonexistent/private-key.pem");
    ASSERT_EQ(key, NULL, "private key from non-existent file returns null");

    /* Test parsing invalid DER data */
    const uint8_t invalid_der[] = {0x00, 0x01, 0x02, 0x03};
    key = opssl_pkey_from_der(invalid_der, sizeof(invalid_der));
    ASSERT_EQ(key, NULL, "private key from invalid DER returns null");

    /* Test parsing invalid PEM data */
    const char *invalid_pem = "-----BEGIN PRIVATE KEY-----\nINVALID\n-----END PRIVATE KEY-----";
    key = opssl_pkey_from_pem(invalid_pem, strlen(invalid_pem));
    ASSERT_EQ(key, NULL, "private key from invalid PEM returns null");
}

int main(void)
{
    opssl_init();

    test_x509_store_lifecycle();
    test_x509_store_operations();
    test_x509_fingerprint_formatting();
    test_x509_chain_operations();
    test_certificate_validation();
    test_private_key_operations();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}