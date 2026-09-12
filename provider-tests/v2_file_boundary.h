#ifndef CURVE301_V2_FILE_BOUNDARY_H
#define CURVE301_V2_FILE_BOUNDARY_H

#include <openssl/decoder.h>
#include <openssl/pkcs12.h>
#include "strict_serialization.h"

/* A decoder consumes one object in a chain; a key FILE has a stronger
 * contract. Keep that boundary explicit, including the complete decrypted
 * PrivateKeyInfo. ASN.1 parsing, PEM and decryption are all OpenSSL-owned.
 * This test integration deliberately decrypts twice: once for the exact
 * file precheck, then through the real generic OSSL_DECODER chain.
 */
static inline int ed301v2_file_plain_der_is_exact(
    const unsigned char *der, size_t length, int is_public)
{
    const unsigned char *prefix = is_public ? ED301V2_SPKI_PREFIX : ED301V2_PKCS8_PREFIX;
    size_t prefix_length = is_public ? sizeof(ED301V2_SPKI_PREFIX) : sizeof(ED301V2_PKCS8_PREFIX);

    return der != NULL && length == prefix_length + 38
        && CRYPTO_memcmp(der, prefix, prefix_length) == 0;
}

static inline int ed301v2_file_encrypted_der_is_exact(OSSL_LIB_CTX *libctx,
    const unsigned char *der, size_t length,
    const unsigned char *password, size_t password_length)
{
    const unsigned char *cursor = der;
    X509_SIG *encrypted = NULL;
    const X509_ALGOR *algorithm = NULL;
    const ASN1_OCTET_STRING *ciphertext = NULL;
    unsigned char *canonical = NULL;
    unsigned char *plain = NULL;
    int canonical_length = 0;
    int plain_length = 0;
    int ok = 0;

    if (libctx == NULL || der == NULL || length > LONG_MAX
            || password == NULL || password_length > INT_MAX)
        return 0;
    encrypted = d2i_X509_SIG(NULL, &cursor, (long)length);
    if (encrypted == NULL || cursor != der + length)
        goto done;
    canonical_length = i2d_X509_SIG(encrypted, &canonical);
    if (canonical_length <= 0 || (size_t)canonical_length != length
            || CRYPTO_memcmp(canonical, der, length) != 0)
        goto done;
    X509_SIG_get0(encrypted, &algorithm, &ciphertext);
    if (algorithm == NULL || ciphertext == NULL
            || PKCS12_pbe_crypt_ex(algorithm, (const char *)password,
                (int)password_length, ASN1_STRING_get0_data(ciphertext),
                ASN1_STRING_length(ciphertext), &plain, &plain_length,
                0, libctx, NULL) == NULL || plain_length < 0)
        goto done;
    ok = ed301v2_file_plain_der_is_exact(plain, (size_t)plain_length, 0);
done:
    OPENSSL_clear_free(plain, plain_length > 0 ? (size_t)plain_length : 0);
    OPENSSL_free(canonical);
    X509_SIG_free(encrypted);
    return ok;
}

static inline int ed301v2_keyfile_preflight(OSSL_LIB_CTX *libctx,
    const unsigned char *input, size_t length, const char *format, int is_public,
    const unsigned char *password, size_t password_length)
{
    BIO *bio = NULL;
    char *name = NULL;
    char *header = NULL;
    unsigned char *decoded = NULL;
    long decoded_length = 0;
    const unsigned char *der = input;
    size_t der_length = length;
    int encrypted = 0;
    int ok = 0;

    if (libctx == NULL || input == NULL || format == NULL || length > INT_MAX)
        return 0;
    if (strcmp(format, "PEM") == 0) {
        if (length < 11 || memcmp(input, "-----BEGIN ", 11) != 0)
            return 0;
        bio = BIO_new_mem_buf(input, (int)length);
        if (bio == NULL || PEM_read_bio(bio, &name, &header, &decoded, &decoded_length) != 1
                || name == NULL || header == NULL || header[0] != '\0'
                || decoded_length <= 0 || BIO_ctrl_pending(bio) != 0)
            goto done;
        encrypted = strcmp(name, PEM_STRING_PKCS8) == 0;
        if ((is_public && strcmp(name, PEM_STRING_PUBLIC) != 0)
                || (!is_public && !encrypted && strcmp(name, PEM_STRING_PKCS8INF) != 0))
            goto done;
        der = decoded;
        der_length = (size_t)decoded_length;
    } else if (strcmp(format, "DER") != 0) {
        goto done;
    }
    if (!encrypted && ed301v2_file_plain_der_is_exact(der, der_length, is_public))
        ok = 1;
    else if (!is_public && (encrypted || strcmp(format, "DER") == 0))
        ok = ed301v2_file_encrypted_der_is_exact(libctx, der, der_length, password, password_length);
done:
    OPENSSL_clear_free(decoded, decoded_length > 0 ? (size_t)decoded_length : 0);
    OPENSSL_free(header);
    OPENSSL_free(name);
    BIO_free(bio);
    return ok;
}

static inline EVP_PKEY *ed301v2_keyfile_decode(OSSL_LIB_CTX *libctx,
    const unsigned char *input, size_t length, const char *format, int is_public,
    const unsigned char *password, size_t password_length)
{
    EVP_PKEY *key = NULL;
    OSSL_DECODER_CTX *decoder = NULL;
    const unsigned char *cursor = input;
    size_t remaining = length;
    const OSSL_PROVIDER *owner;

    if (!ed301v2_keyfile_preflight(libctx, input, length, format, is_public, password, password_length))
        return NULL;
    decoder = OSSL_DECODER_CTX_new_for_pkey(&key, format, NULL, ED301V2_ALG,
        is_public ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR, libctx, NULL);
    if (decoder == NULL
            || (password != NULL && OSSL_DECODER_CTX_set_passphrase(decoder, password, password_length) != 1)
            || OSSL_DECODER_from_data(decoder, &cursor, &remaining) != 1
            || remaining != 0 || key == NULL
            || (owner = EVP_PKEY_get0_provider(key)) == NULL
            || strcmp(OSSL_PROVIDER_get0_name(owner), ED301V2_TLS_PROVIDER) != 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    OSSL_DECODER_CTX_free(decoder);
    return key;
}

#endif
