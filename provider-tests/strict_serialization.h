#ifndef ED301V2_STRICT_SERIALIZATION_H
#define ED301V2_STRICT_SERIALIZATION_H

/*
 * Project-owned, complete-buffer import boundary for the test-only PKI
 * profile.  The PKI artifact exposes encoders but no OSSL_DECODER.  The TLS
 * integration artifact reuses the same exact DER contract through its
 * transactional PKCS#8 and SPKI decoders.
 */

#include <openssl/pem.h>

#include "harness_common.h"

#ifdef X301_CODEC_TEST
# include "../provider/common/generated_x301_profile.h"
# define ED301V2_PKCS8_PREFIX X301V2_PKCS8_PREFIX
# define ED301V2_SPKI_PREFIX X301V2_SPKI_PREFIX
# define ED301V2_OID_TLV_BYTES X301V2_OID_TLV_BYTES
#else
# include "../provider/common/generated_ed301_profile.h"
#endif
#define CODEC_OID_LEAF (ED301V2_PKCS8_PREFIX[19])
#define ED301V2_PKCS8_DER_BYTES \
    (sizeof(ED301V2_PKCS8_PREFIX) + ED301V2_SEED_BYTES)
#define ED301V2_SPKI_DER_BYTES \
    (sizeof(ED301V2_SPKI_PREFIX) + ED301V2_PUB_BYTES)

_Static_assert(ED301V2_PKCS8_DER_BYTES == 62,
    "v2 PKCS#8 must be exactly 62 bytes");
_Static_assert(ED301V2_SPKI_DER_BYTES == 58,
    "v2 SPKI must be exactly 58 bytes");

static inline EVP_PKEY *ed301v2_strict_der_import(
    OSSL_LIB_CTX *libctx,
    const unsigned char *data,
    size_t data_length,
    int is_public)
{
    const unsigned char *prefix = is_public
        ? ED301V2_SPKI_PREFIX : ED301V2_PKCS8_PREFIX;
    const size_t prefix_length = is_public
        ? sizeof(ED301V2_SPKI_PREFIX) : sizeof(ED301V2_PKCS8_PREFIX);
    const size_t expected_length = prefix_length + ED301V2_SEED_BYTES;

    if (data == NULL || data_length != expected_length
            || CRYPTO_memcmp(data, prefix, prefix_length) != 0)
        return NULL;
    if (is_public)
        return ed301v2_key_from_public(
            libctx, data + prefix_length, ED301V2_PUB_BYTES);
    return ed301v2_key_from_seed(libctx, data + prefix_length);
}

static inline EVP_PKEY *ed301v2_strict_pem_import(
    OSSL_LIB_CTX *libctx,
    const unsigned char *data,
    size_t data_length,
    int is_public)
{
    BIO *bio = NULL;
    char *name = NULL;
    char *header = NULL;
    unsigned char *der = NULL;
    long der_length = 0;
    EVP_PKEY *key = NULL;
    unsigned char trailing;
    const char *expected_name = is_public ? PEM_STRING_PUBLIC
        : PEM_STRING_PKCS8INF;

    if (data == NULL || data_length > INT_MAX)
        return NULL;
    bio = BIO_new_mem_buf(data, (int)data_length);
    if (bio == NULL
            || PEM_read_bio(bio, &name, &header, &der, &der_length) != 1
            || name == NULL || strcmp(name, expected_name) != 0
            || header == NULL || header[0] != '\0'
            || der_length < 0
            || BIO_read(bio, &trailing, 1) > 0)
        goto cleanup;
    key = ed301v2_strict_der_import(
        libctx, der, (size_t)der_length, is_public);

cleanup:
    if (der != NULL)
        OPENSSL_clear_free(der, der_length < 0 ? 0 : (size_t)der_length);
    OPENSSL_free(header);
    OPENSSL_free(name);
    BIO_free(bio);
    return key;
}

#endif
