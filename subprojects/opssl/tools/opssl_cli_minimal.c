/*
 * opssl_cli_minimal.c — minimal CLI tool demonstrating core opssl crypto functions.
 *
 * This is a proof-of-concept CLI tool that showcases the main cryptographic
 * primitives available in opssl without depending on complex TLS or X.509 functionality.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/time.h>
#include <getopt.h>
#include <ctype.h>

/* Forward declare only the functions we need from opssl */

/* Version and initialization */
extern int opssl_init(void);
extern void opssl_cleanup(void);
extern const char *opssl_version_string(void);

/* Hash functions - lengths */
#define SHA1_DIGEST_LEN    20
#define SHA256_DIGEST_LEN  32
#define SHA384_DIGEST_LEN  48
#define SHA512_DIGEST_LEN  64
#define SHA3_256_DIGEST_LEN 32
#define SHA3_512_DIGEST_LEN 64

/* One-shot hash functions */
extern void opssl_sha1(const void *data, size_t len, uint8_t out[SHA1_DIGEST_LEN]);
extern void opssl_sha256(const void *data, size_t len, uint8_t out[SHA256_DIGEST_LEN]);
extern void opssl_sha384(const void *data, size_t len, uint8_t out[SHA384_DIGEST_LEN]);
extern void opssl_sha512(const void *data, size_t len, uint8_t out[SHA512_DIGEST_LEN]);
extern void opssl_sha3_256(const void *data, size_t len, uint8_t out[SHA3_256_DIGEST_LEN]);
extern void opssl_sha3_512(const void *data, size_t len, uint8_t out[SHA3_512_DIGEST_LEN]);

/* SHAKE functions */
extern void opssl_shake128(uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len);
extern void opssl_shake256(uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len);

/* Base64 functions */
extern int opssl_base64_encode(const uint8_t *in, size_t in_len, char *out, size_t *out_len);
extern int opssl_base64_decode(const char *in, size_t in_len, uint8_t *out, size_t *out_len);

/* Random bytes */
extern int opssl_random_bytes(void *buf, size_t len);

/* HMAC */
typedef enum {
    HMAC_SHA256 = 0,
    HMAC_SHA384 = 1,
    HMAC_SHA512 = 2,
} hmac_algo_t;

extern int opssl_hmac(hmac_algo_t algo, const uint8_t *key, size_t key_len,
                      const void *data, size_t data_len, uint8_t *out, size_t *out_len);

#define BUFFER_SIZE 65536

/* Utility functions */

static void print_hex(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
}


static int hex_to_bytes(const char *hex, uint8_t *bytes, size_t max_bytes)
{
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return 0;

    size_t byte_len = hex_len / 2;
    if (byte_len > max_bytes) return 0;

    for (size_t i = 0; i < byte_len; i++) {
        int hi = hex[2*i];
        int lo = hex[2*i + 1];

        if (!isxdigit(hi) || !isxdigit(lo)) return 0;

        hi = hi >= 'a' ? hi - 'a' + 10 : (hi >= 'A' ? hi - 'A' + 10 : hi - '0');
        lo = lo >= 'a' ? lo - 'a' + 10 : (lo >= 'A' ? lo - 'A' + 10 : lo - '0');

        bytes[i] = (hi << 4) | lo;
    }
    return byte_len;
}

static FILE *safe_fopen(const char *path, const char *mode)
{
    if (!path || strcmp(path, "-") == 0) {
        return (mode[0] == 'r') ? stdin : stdout;
    }
    return fopen(path, mode);
}

static void safe_fclose(FILE *f)
{
    if (f && f != stdin && f != stdout && f != stderr) {
        fclose(f);
    }
}

static char *read_file_to_string(const char *path, size_t *len_out)
{
    FILE *f = safe_fopen(path, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buf = malloc(size + 1);
    if (!buf) {
        safe_fclose(f);
        return NULL;
    }

    size_t read_size = fread(buf, 1, size, f);
    buf[read_size] = '\0';
    safe_fclose(f);

    if (len_out) *len_out = read_size;
    return buf;
}

/* Commands */

static int cmd_version(int argc, char **argv)
{
    (void)argc; (void)argv;
    printf("opssl minimal CLI\n");
    printf("Version: %s\n", opssl_version_string());
    return 0;
}

static int cmd_dgst(int argc, char **argv)
{
    const char *algo = "sha256";
    int first_file = 1;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != '-') { first_file = i; break; }
        if (strcmp(argv[i], "-sha1") == 0)     { algo = "sha1"; }
        else if (strcmp(argv[i], "-sha256") == 0)  { algo = "sha256"; }
        else if (strcmp(argv[i], "-sha384") == 0)  { algo = "sha384"; }
        else if (strcmp(argv[i], "-sha512") == 0)  { algo = "sha512"; }
        else if (strcmp(argv[i], "-sha3-256") == 0) { algo = "sha3-256"; }
        else if (strcmp(argv[i], "-sha3-512") == 0) { algo = "sha3-512"; }
        else {
            fprintf(stderr, "Usage: opssl dgst [-sha1|-sha256|-sha384|-sha512|-sha3-256|-sha3-512] [file...]\n");
            return 1;
        }
        first_file = i + 1;
    }

    uint8_t digest[64]; /* largest */
    size_t digest_len = 0;

    if (strcmp(algo, "sha1") == 0) digest_len = SHA1_DIGEST_LEN;
    else if (strcmp(algo, "sha256") == 0) digest_len = SHA256_DIGEST_LEN;
    else if (strcmp(algo, "sha384") == 0) digest_len = SHA384_DIGEST_LEN;
    else if (strcmp(algo, "sha512") == 0) digest_len = SHA512_DIGEST_LEN;
    else if (strcmp(algo, "sha3-256") == 0) digest_len = SHA3_256_DIGEST_LEN;
    else if (strcmp(algo, "sha3-512") == 0) digest_len = SHA3_512_DIGEST_LEN;

    int file_count = argc - first_file;
    char **files = argv + first_file;

    if (file_count == 0) {
        /* Read from stdin */
        char *data = malloc(BUFFER_SIZE);
        size_t capacity = BUFFER_SIZE, total = 0;
        uint8_t buffer[BUFFER_SIZE];

        ssize_t bytes;
        while ((bytes = fread(buffer, 1, sizeof(buffer), stdin)) > 0) {
            if (total + bytes > capacity) {
                capacity *= 2;
                data = realloc(data, capacity);
            }
            memcpy(data + total, buffer, bytes);
            total += bytes;
        }

        if (strcmp(algo, "sha1") == 0) {
            opssl_sha1(data, total, digest);
        } else if (strcmp(algo, "sha256") == 0) {
            opssl_sha256(data, total, digest);
        } else if (strcmp(algo, "sha384") == 0) {
            opssl_sha384(data, total, digest);
        } else if (strcmp(algo, "sha512") == 0) {
            opssl_sha512(data, total, digest);
        } else if (strcmp(algo, "sha3-256") == 0) {
            opssl_sha3_256(data, total, digest);
        } else if (strcmp(algo, "sha3-512") == 0) {
            opssl_sha3_512(data, total, digest);
        }

        printf("%s(stdin)= ", algo);
        print_hex(digest, digest_len);
        printf("\n");
        free(data);
    } else {
        /* Process files */
        for (int i = 0; i < file_count; i++) {
            size_t file_len;
            char *data = read_file_to_string(files[i], &file_len);
            if (!data) {
                fprintf(stderr, "Error reading file %s\n", files[i]);
                continue;
            }

            if (strcmp(algo, "sha1") == 0) {
                opssl_sha1(data, file_len, digest);
            } else if (strcmp(algo, "sha256") == 0) {
                opssl_sha256(data, file_len, digest);
            } else if (strcmp(algo, "sha384") == 0) {
                opssl_sha384(data, file_len, digest);
            } else if (strcmp(algo, "sha512") == 0) {
                opssl_sha512(data, file_len, digest);
            } else if (strcmp(algo, "sha3-256") == 0) {
                opssl_sha3_256(data, file_len, digest);
            } else if (strcmp(algo, "sha3-512") == 0) {
                opssl_sha3_512(data, file_len, digest);
            }

            printf("%s(%s)= ", algo, files[i]);
            print_hex(digest, digest_len);
            printf("\n");

            free(data);
        }
    }

    return 0;
}

static int cmd_rand(int argc, char **argv)
{
    int opt;

    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
            case 'h': break;
            default:
                fprintf(stderr, "Usage: opssl rand [-hex] <num_bytes>\n");
                return 1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Error: number of bytes required\n");
        return 1;
    }

    int num_bytes = atoi(argv[optind]);
    if (num_bytes <= 0 || num_bytes > 65536) {
        fprintf(stderr, "Error: invalid number of bytes (1-65536)\n");
        return 1;
    }

    uint8_t *random_data = malloc(num_bytes);
    if (!random_data) {
        fprintf(stderr, "Error: memory allocation failed\n");
        return 1;
    }

    if (opssl_random_bytes(random_data, num_bytes) != 0) {
        fprintf(stderr, "Error: failed to generate random bytes\n");
        free(random_data);
        return 1;
    }

    print_hex(random_data, num_bytes);
    printf("\n");

    free(random_data);
    return 0;
}

static int cmd_base64(int argc, char **argv)
{
    int opt;
    int decode = 0;
    const char *input_file = NULL, *output_file = NULL;

    while ((opt = getopt(argc, argv, "di:o:")) != -1) {
        switch (opt) {
            case 'd': decode = 1; break;
            case 'i': input_file = optarg; break;
            case 'o': output_file = optarg; break;
            default:
                fprintf(stderr, "Usage: opssl base64 [-d] [-in file] [-out file]\n");
                return 1;
        }
    }

    FILE *in = safe_fopen(input_file, "rb");
    FILE *out = safe_fopen(output_file, "wb");

    if (!in || !out) {
        fprintf(stderr, "Error opening files\n");
        return 1;
    }

    uint8_t buffer[BUFFER_SIZE];
    size_t bytes_read;

    if (decode) {
        /* Read all input */
        size_t total = 0;
        char *input_data = malloc(BUFFER_SIZE);
        size_t capacity = BUFFER_SIZE;

        while ((bytes_read = fread(buffer, 1, sizeof(buffer), in)) > 0) {
            if (total + bytes_read > capacity) {
                capacity *= 2;
                input_data = realloc(input_data, capacity);
            }
            memcpy(input_data + total, buffer, bytes_read);
            total += bytes_read;
        }

        input_data[total] = '\0';

        uint8_t *decoded = malloc(total);
        size_t decoded_len = total;

        if (opssl_base64_decode(input_data, total, decoded, &decoded_len)) {
            fwrite(decoded, 1, decoded_len, out);
        } else {
            fprintf(stderr, "Error: invalid base64 input\n");
        }

        free(decoded);
        free(input_data);
    } else {
        /* Encode */
        while ((bytes_read = fread(buffer, 1, sizeof(buffer), in)) > 0) {
            size_t encoded_len = ((bytes_read + 2) / 3) * 4 + 1;
            char *encoded = malloc(encoded_len);

            if (opssl_base64_encode(buffer, bytes_read, encoded, &encoded_len)) {
                fwrite(encoded, 1, encoded_len, out);
            }
            free(encoded);
        }
    }

    safe_fclose(in);
    safe_fclose(out);
    return 0;
}

static int cmd_shake(int argc, char **argv)
{
    int opt;
    int bits = 128;
    int length = 32;

    while ((opt = getopt(argc, argv, "12l:")) != -1) {
        switch (opt) {
            case '1': bits = 128; break;
            case '2': bits = 256; break;
            case 'l': length = atoi(optarg); break;
            default:
                fprintf(stderr, "Usage: opssl shake [-1|-2] [-l num] [file...]\n");
                return 1;
        }
    }

    if (length <= 0 || length > 8192) {
        fprintf(stderr, "Error: invalid output length\n");
        return 1;
    }

    uint8_t *output = malloc(length);
    if (!output) {
        fprintf(stderr, "Error: memory allocation failed\n");
        return 1;
    }

    if (optind >= argc) {
        /* Read from stdin */
        char *data = malloc(BUFFER_SIZE);
        size_t capacity = BUFFER_SIZE, total = 0;
        uint8_t buffer[BUFFER_SIZE];

        ssize_t bytes;
        while ((bytes = fread(buffer, 1, sizeof(buffer), stdin)) > 0) {
            if (total + bytes > capacity) {
                capacity *= 2;
                data = realloc(data, capacity);
            }
            memcpy(data + total, buffer, bytes);
            total += bytes;
        }

        if (bits == 128) {
            opssl_shake128(output, length, (uint8_t*)data, total);
        } else {
            opssl_shake256(output, length, (uint8_t*)data, total);
        }

        print_hex(output, length);
        printf("\n");
        free(data);
    } else {
        /* Process files */
        for (int i = optind; i < argc; i++) {
            size_t file_len;
            char *data = read_file_to_string(argv[i], &file_len);
            if (!data) continue;

            if (bits == 128) {
                opssl_shake128(output, length, (uint8_t*)data, file_len);
            } else {
                opssl_shake256(output, length, (uint8_t*)data, file_len);
            }

            printf("SHAKE%d(%s)= ", bits, argv[i]);
            print_hex(output, length);
            printf("\n");
            free(data);
        }
    }

    free(output);
    return 0;
}

static int cmd_hmac(int argc, char **argv)
{
    int opt;
    const char *algo_str = "sha256";
    const char *key_hex = NULL;
    hmac_algo_t algo = HMAC_SHA256;

    while ((opt = getopt(argc, argv, "k:a:")) != -1) {
        switch (opt) {
            case 'k': key_hex = optarg; break;
            case 'a': algo_str = optarg; break;
            default:
                fprintf(stderr, "Usage: opssl hmac [-a sha256|sha384|sha512] -k hex_key [file...]\n");
                return 1;
        }
    }

    if (strcmp(algo_str, "sha256") == 0) algo = HMAC_SHA256;
    else if (strcmp(algo_str, "sha384") == 0) algo = HMAC_SHA384;
    else if (strcmp(algo_str, "sha512") == 0) algo = HMAC_SHA512;

    if (!key_hex) {
        fprintf(stderr, "Error: key required\n");
        return 1;
    }

    uint8_t key[64];
    int key_len = hex_to_bytes(key_hex, key, sizeof(key));
    if (key_len == 0) {
        fprintf(stderr, "Error: invalid key format\n");
        return 1;
    }

    uint8_t hmac[64];
    size_t hmac_len = sizeof(hmac);

    if (optind >= argc) {
        /* Read from stdin */
        char *data = malloc(BUFFER_SIZE);
        size_t capacity = BUFFER_SIZE, total = 0;
        uint8_t buffer[BUFFER_SIZE];

        ssize_t bytes;
        while ((bytes = fread(buffer, 1, sizeof(buffer), stdin)) > 0) {
            if (total + bytes > capacity) {
                capacity *= 2;
                data = realloc(data, capacity);
            }
            memcpy(data + total, buffer, bytes);
            total += bytes;
        }

        if (opssl_hmac(algo, key, key_len, data, total, hmac, &hmac_len)) {
            print_hex(hmac, hmac_len);
            printf("\n");
        }
        free(data);
    } else {
        /* Process files */
        for (int i = optind; i < argc; i++) {
            size_t file_len;
            char *data = read_file_to_string(argv[i], &file_len);
            if (!data) continue;

            hmac_len = sizeof(hmac);
            if (opssl_hmac(algo, key, key_len, data, file_len, hmac, &hmac_len)) {
                printf("%s: ", argv[i]);
                print_hex(hmac, hmac_len);
                printf("\n");
            }
            free(data);
        }
    }

    return 0;
}

/* Main command dispatch */

struct cmd {
    const char *name;
    int (*func)(int argc, char **argv);
    const char *help;
};

static struct cmd commands[] = {
    {"version", cmd_version, "Show version info"},
    {"dgst", cmd_dgst, "Hash files or stdin"},
    {"rand", cmd_rand, "Generate random bytes"},
    {"base64", cmd_base64, "Base64 encode/decode"},
    {"shake", cmd_shake, "SHAKE extendable output function"},
    {"hmac", cmd_hmac, "Compute HMAC"},
    {NULL, NULL, NULL}
};

static void show_help(void)
{
    printf("opssl minimal CLI - Crypto operations using opssl library\n\n");
    printf("Available commands:\n");

    for (struct cmd *c = commands; c->name; c++) {
        printf("  %-12s %s\n", c->name, c->help);
    }

    printf("\nNote: This is a minimal demo. Full TLS and X.509 features require complete build.\n");
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        show_help();
        return 1;
    }

    const char *cmd_name = argv[1];

    /* Initialize opssl library */
    if (!opssl_init()) {
        fprintf(stderr, "Error: failed to initialize opssl\n");
        return 1;
    }

    /* Find and execute command */
    int ret = 1;
    for (struct cmd *c = commands; c->name; c++) {
        if (strcmp(cmd_name, c->name) == 0) {
            /* Shift arguments */
            ret = c->func(argc - 1, argv + 1);
            break;
        }
    }

    if (ret == 1 && strcmp(cmd_name, commands[0].name) != 0) {
        fprintf(stderr, "Error: unknown command '%s'\n", cmd_name);
    }

    opssl_cleanup();
    return ret;
}