/*
 * opssl_cli.c — OpSSL command-line utility.
 *
 * Provides a subset of OpenSSL-like commands for key generation,
 * certificate management, and TLS diagnostics.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/opssl.h>
#include <opssl/platform.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

static void usage(void) {
    fprintf(stderr, "OpSSL CLI Utility\n");
    fprintf(stderr, "Usage: opssl <command> [options]\n\n");
    fprintf(stderr, "Commands:\n");
    fprintf(stderr, "  genpkey   Generate a private key\n");
    fprintf(stderr, "  req       Create a certificate signing request (CSR)\n");
    fprintf(stderr, "  x509      Certificate display and signing utility\n");
    fprintf(stderr, "  s_client  TLS client diagnostic tool\n");
    fprintf(stderr, "  s_server  TLS server diagnostic tool\n");
    fprintf(stderr, "  version   Display version information\n");
}

static int do_version(int argc, char **argv) {
    printf("OpSSL 1.0.0 (built May 2026)\n");
    return 0;
}

static int do_genpkey(int argc, char **argv) {
    const char *algo = "ed25519";
    const char *out_path = "key.pem";

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-algorithm") == 0 && i + 1 < argc) {
            algo = argv[++i];
        } else if (strcmp(argv[i], "-out") == 0 && i + 1 < argc) {
            out_path = argv[++i];
        }
    }

    printf("Generating %s private key...\n", algo);

    if (strcmp(algo, "ed25519") == 0) {
        uint8_t pub[32], priv[64];
        if (!opssl_ed25519_keygen(pub, priv)) {
            fprintf(stderr, "Error: Key generation failed\n");
            return 1;
        }

        opssl_pkey_t *pkey = opssl_pkey_from_ed25519_raw(priv, pub);
        if (!pkey) {
            fprintf(stderr, "Error: Failed to create pkey object\n");
            return 1;
        }

        if (!opssl_pkey_save_pem(pkey, out_path)) {
            fprintf(stderr, "Error: Failed to save key to %s\n", out_path);
            opssl_pkey_free(pkey);
            return 1;
        }
        opssl_pkey_free(pkey);
        printf("Key saved to %s\n", out_path);
        return 0;
    }

    fprintf(stderr, "Error: Unsupported algorithm '%s'\n", algo);
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage();
        return 1;
    }

    opssl_init();

    const char *cmd = argv[1];
    int rc = 1;

    if (strcmp(cmd, "version") == 0) {
        rc = do_version(argc - 2, argv + 2);
    } else if (strcmp(cmd, "genpkey") == 0) {
        rc = do_genpkey(argc - 2, argv + 2);
    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        usage();
    }

    opssl_cleanup();
    return rc;
}
