/*
 * asn1_internal.h — internal ASN.1 function declarations for x509 module.
 */

#ifndef OPSSL_ASN1_INTERNAL_H
#define OPSSL_ASN1_INTERNAL_H

#include <opssl/cbs.h>
#include <stdbool.h>
#include <stdint.h>

int opssl_asn1_get_tag(opssl_cbs_t *cbs, uint8_t *tag);
int opssl_asn1_get_length(opssl_cbs_t *cbs, size_t *len);
int opssl_asn1_get_element(opssl_cbs_t *cbs, uint8_t expected_tag, opssl_cbs_t *content);
int opssl_asn1_get_integer(opssl_cbs_t *cbs, opssl_cbs_t *value);
int opssl_asn1_get_sequence(opssl_cbs_t *cbs, opssl_cbs_t *content);
int opssl_asn1_get_set(opssl_cbs_t *cbs, opssl_cbs_t *content);
int opssl_asn1_get_bit_string(opssl_cbs_t *cbs, opssl_cbs_t *content, uint8_t *unused_bits);
int opssl_asn1_get_octet_string(opssl_cbs_t *cbs, opssl_cbs_t *content);
int opssl_asn1_get_oid(opssl_cbs_t *cbs, opssl_cbs_t *oid);
int opssl_asn1_get_boolean(opssl_cbs_t *cbs, bool *value);
int opssl_asn1_oid_equal(const opssl_cbs_t *oid, const uint8_t *expected, size_t len);
int opssl_asn1_get_time(opssl_cbs_t *cbs, int64_t *epoch);
int opssl_asn1_get_string(opssl_cbs_t *cbs, char *out, size_t out_len);
int opssl_asn1_skip_element(opssl_cbs_t *cbs);

#endif /* OPSSL_ASN1_INTERNAL_H */
