/* PBES2 work-factor and legacy-import contract for both v2 providers. */
#include <stdint.h>
#include <time.h>

#include <openssl/encoder.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>

#include "harness_common.h"
#include "strict_serialization.h"
#include "../provider/common/encoder_params.h"

static int iterations_match(const X509_SIG *encrypted, uint64_t expected)
{
    const X509_ALGOR *algorithm;
    const ASN1_OBJECT *object;
    const void *value;
    const unsigned char *cursor;
    const unsigned char *end;
    PBE2PARAM *pbe = NULL;
    PBKDF2PARAM *pbkdf = NULL;
    uint64_t iterations = 0;
    int type;
    int ok = 0;

    if (encrypted == NULL)
        return 0;
    X509_SIG_get0(encrypted, &algorithm, NULL);
    X509_ALGOR_get0(&object, &type, &value, algorithm);
    if (OBJ_obj2nid(object) != NID_pbes2 || type != V_ASN1_SEQUENCE)
        goto done;
    cursor = ASN1_STRING_get0_data(value);
    end = cursor + ASN1_STRING_length(value);
    pbe = d2i_PBE2PARAM(NULL, &cursor, end - cursor);
    if (pbe == NULL || cursor != end)
        goto done;
    X509_ALGOR_get0(&object, &type, &value, pbe->keyfunc);
    if (OBJ_obj2nid(object) != NID_id_pbkdf2 || type != V_ASN1_SEQUENCE)
        goto done;
    cursor = ASN1_STRING_get0_data(value);
    end = cursor + ASN1_STRING_length(value);
    pbkdf = d2i_PBKDF2PARAM(NULL, &cursor, end - cursor);
    if (pbkdf == NULL || cursor != end || pbkdf->prf == NULL
            || ASN1_INTEGER_get_uint64(&iterations, pbkdf->iter) != 1)
        goto done;
    X509_ALGOR_get0(&object, NULL, NULL, pbkdf->prf);
    ok = iterations == expected && OBJ_obj2nid(object) == NID_hmacWithSHA256;
done:
    PBKDF2PARAM_free(pbkdf);
    PBE2PARAM_free(pbe);
    return ok;
}

static OSSL_ENCODER_CTX *encoder(EVP_PKEY *key, const char *format,
    const char *structure, const char *properties)
{
    OSSL_ENCODER_CTX *ctx = OSSL_ENCODER_CTX_new_for_pkey(
        key, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, format, structure, properties);

    if (ctx != NULL && OSSL_ENCODER_CTX_set_passphrase(
            ctx, (const unsigned char *)"review-only", 11) != 1) {
        OSSL_ENCODER_CTX_free(ctx);
        ctx = NULL;
    }
    return ctx;
}

static X509_SIG *encrypted_output(OSSL_ENCODER_CTX *ctx, const char *format)
{
    unsigned char *data = NULL;
    const unsigned char *cursor;
    size_t length = 0;
    X509_SIG *result = NULL;
    BIO *bio = NULL;

    if (ctx == NULL || OSSL_ENCODER_to_data(ctx, &data, &length) != 1
            || length > INT_MAX)
        goto done;
    if (strcmp(format, "PEM") == 0) {
        bio = BIO_new_mem_buf(data, (int)length);
        if (bio != NULL)
            result = PEM_read_bio_PKCS8(bio, NULL, NULL, NULL);
    } else {
        cursor = data;
        result = d2i_X509_SIG(NULL, &cursor, (long)length);
        if (cursor != data + length) {
            X509_SIG_free(result);
            result = NULL;
        }
    }
done:
    BIO_free(bio);
    OPENSSL_free(data);
    return result;
}

static int private_matches(PKCS8_PRIV_KEY_INFO *plain, const unsigned char expected[38])
{
    unsigned char *der = NULL;
    int length = plain == NULL ? -1 : i2d_PKCS8_PRIV_KEY_INFO(plain, &der);
    int ok = length == 62
        && CRYPTO_memcmp(der, ED301V2_PKCS8_PREFIX, sizeof(ED301V2_PKCS8_PREFIX)) == 0
        && CRYPTO_memcmp(der + sizeof(ED301V2_PKCS8_PREFIX), expected, 38) == 0;

    OPENSSL_clear_free(der, length > 0 ? (size_t)length : 0);
    return ok;
}

static int no_output(OSSL_ENCODER_CTX *ctx)
{
    unsigned char *data = NULL;
    size_t length = 0;
    int result = OSSL_ENCODER_to_data(ctx, &data, &length);
    int ok = result != 1 && data == NULL && length == 0;

    OPENSSL_clear_free(data, length);
    ERR_clear_error();
    return ok;
}

static void check_module(const char *module, const char *properties)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *provider = NULL;
    EVP_PKEY *key = NULL;
    unsigned char seed[38] = { 1 };
    const char *formats[] = { "DER", "PEM" };
    const char *structures[] = { "PrivateKeyInfo", "EncryptedPrivateKeyInfo" };
    size_t f, s;

    if (libctx != NULL) {
        deflt = OSSL_PROVIDER_load(libctx, "default");
        provider = OSSL_PROVIDER_load(libctx, module);
        key = EVP_PKEY_new_raw_private_key_ex(libctx, ED301V2_ALG,
            properties, seed, sizeof(seed));
    }
    ED301V2_CHECK(deflt != NULL && provider != NULL && key != NULL,
        "password-policy provider and key load");
    if (key == NULL)
        goto done;
    for (f = 0; f < 2; f++) {
        for (s = 0; s < 2; s++) {
            OSSL_ENCODER_CTX *ctx = encoder(key, formats[f], structures[s], properties);
            X509_SIG *encrypted = NULL;
            PKCS8_PRIV_KEY_INFO *plain = NULL;
            PKCS8_PRIV_KEY_INFO *wrong = NULL;
            unsigned int custom = 12345;
            OSSL_PARAM parameters[] = {
                OSSL_PARAM_END, OSSL_PARAM_END
            };
            struct timespec start, end;
            int set_ok = ctx != NULL && OSSL_ENCODER_CTX_set_cipher(
                ctx, "AES-256-CBC", "provider=default") == 1;

            clock_gettime(CLOCK_MONOTONIC, &start);
            if (set_ok)
                encrypted = encrypted_output(ctx, formats[f]);
            clock_gettime(CLOCK_MONOTONIC, &end);
            printf("password_cost module=%s format=%s structure=%s iterations=1000000 seconds=%.6f\n",
                module, formats[f], structures[s],
                (double)(end.tv_sec - start.tv_sec)
                    + (double)(end.tv_nsec - start.tv_nsec) / 1000000000.0);
            ED301V2_CHECK(iterations_match(encrypted, 1000000),
                "default PBES2 uses one million PBKDF2-HMAC-SHA256 iterations");
            X509_SIG_free(encrypted);
            OSSL_ENCODER_CTX_free(ctx);

            ctx = encoder(key, formats[f], structures[s], properties);
            parameters[0] = OSSL_PARAM_construct_uint(
                CURVE301_ENCODER_PARAM_PBKDF2_ITERATIONS, &custom);
            set_ok = ctx != NULL && OSSL_ENCODER_CTX_set_params(ctx, parameters) == 1
                && OSSL_ENCODER_CTX_set_cipher(ctx, "AES-256-CBC", NULL) == 1;
            encrypted = set_ok ? encrypted_output(ctx, formats[f]) : NULL;
            ED301V2_CHECK(iterations_match(encrypted, custom),
                "password cost set before cipher is encoded exactly");
            if (encrypted != NULL) {
                plain = PKCS8_decrypt_ex(encrypted, "review-only", 11, libctx, NULL);
                wrong = PKCS8_decrypt_ex(encrypted, "wrong", 5, libctx, NULL);
            }
            ED301V2_CHECK(private_matches(plain, seed) && wrong == NULL,
                "custom-cost output preserves raw private bytes and rejects wrong password");
            PKCS8_PRIV_KEY_INFO_free(wrong);
            PKCS8_PRIV_KEY_INFO_free(plain);
            X509_SIG_free(encrypted);
            ERR_clear_error();

            custom = 23456;
            set_ok = ctx != NULL && OSSL_ENCODER_CTX_set_params(ctx, parameters) == 1;
            encrypted = set_ok ? encrypted_output(ctx, formats[f]) : NULL;
            ED301V2_CHECK(iterations_match(encrypted, custom),
                "parameter-only update changes an existing encoder cost");
            X509_SIG_free(encrypted);
            OSSL_ENCODER_CTX_free(ctx);
        }
    }
    for (f = 0; f < 2; f++) {
        OSSL_ENCODER_CTX *ctx = encoder(key, formats[f], "EncryptedPrivateKeyInfo", properties);
        ED301V2_CHECK(ctx != NULL
                && OSSL_ENCODER_CTX_set_cipher(ctx, "AES-256-CBC", NULL) == 1
                && OSSL_ENCODER_CTX_set_cipher(ctx, NULL, NULL) == 1
                && no_output(ctx),
            "cleared cipher cannot downgrade explicit encrypted DER or PEM output");
        OSSL_ENCODER_CTX_free(ctx);
    }
    for (unsigned int bad = 0; bad < 5; bad++) {
        OSSL_ENCODER_CTX *ctx = encoder(key, "DER", "PrivateKeyInfo", properties);
        unsigned int value = bad == 0 ? 0 : 10000001;
        int negative = -1;
        uint64_t overflow = UINT64_MAX;
        char text[] = "1000000";
        OSSL_PARAM parameters[2];
        int ok = ctx != NULL && OSSL_ENCODER_CTX_set_cipher(
            ctx, "AES-256-CBC", NULL) == 1;

        parameters[0] = OSSL_PARAM_construct_uint(
            CURVE301_ENCODER_PARAM_PBKDF2_ITERATIONS, &value);
        if (bad == 2)
            parameters[0] = OSSL_PARAM_construct_int(
                CURVE301_ENCODER_PARAM_PBKDF2_ITERATIONS, &negative);
        if (bad == 3)
            parameters[0] = OSSL_PARAM_construct_uint64(
                CURVE301_ENCODER_PARAM_PBKDF2_ITERATIONS, &overflow);
        if (bad == 4)
            parameters[0] = OSSL_PARAM_construct_utf8_string(
                CURVE301_ENCODER_PARAM_PBKDF2_ITERATIONS, text, 0);
        parameters[1] = OSSL_PARAM_construct_end();
        ED301V2_CHECK(ok && OSSL_ENCODER_CTX_set_params(ctx, parameters) != 1
                && no_output(ctx), "invalid password cost rejects without output");
        ED301V2_CHECK(ok && OSSL_ENCODER_CTX_set_cipher(ctx, "AES-256-CBC", NULL) == 1
                && no_output(ctx), "cipher-only update cannot hide an invalid password cost");
        value = 2048;
        parameters[0] = OSSL_PARAM_construct_uint(
            CURVE301_ENCODER_PARAM_PBKDF2_ITERATIONS, &value);
        ok = ok && OSSL_ENCODER_CTX_set_params(ctx, parameters) == 1;
        X509_SIG *encrypted = ok ? encrypted_output(ctx, "DER") : NULL;
        PKCS8_PRIV_KEY_INFO *plain = encrypted == NULL ? NULL
            : PKCS8_decrypt_ex(encrypted, "review-only", 11, libctx, NULL);
        ED301V2_CHECK(iterations_match(encrypted, 2048)
                && private_matches(plain, seed),
            "explicit cost restores context and legacy 2048-iteration files remain readable");
        PKCS8_PRIV_KEY_INFO_free(plain);
        X509_SIG_free(encrypted);
        OSSL_ENCODER_CTX_free(ctx);
    }
    {
        OSSL_ENCODER_CTX *ctx = encoder(key, "DER", "PrivateKeyInfo", properties);
        unsigned int iterations = 12345;
        OSSL_PARAM combined[3] = {
            OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END
        };
        X509_SIG *encrypted;
        int ok;

        combined[0] = OSSL_PARAM_construct_uint(
            CURVE301_ENCODER_PARAM_PBKDF2_ITERATIONS, &iterations);
        combined[1] = OSSL_PARAM_construct_utf8_string(
            OSSL_ENCODER_PARAM_CIPHER, "AES-256-CBC", 0);
        ok = ctx != NULL && OSSL_ENCODER_CTX_set_params(ctx, combined) == 1;
        encrypted = ok ? encrypted_output(ctx, "DER") : NULL;
        ED301V2_CHECK(iterations_match(encrypted, iterations),
            "cipher and password cost can be set atomically");
        X509_SIG_free(encrypted);
        combined[1] = combined[0];
        ED301V2_CHECK(ok && OSSL_ENCODER_CTX_set_params(ctx, combined) != 1
                && no_output(ctx), "duplicate password cost is rejected");

        combined[1] = OSSL_PARAM_construct_end();
        ok = ok && OSSL_ENCODER_CTX_set_params(ctx, combined) == 1
            && OSSL_ENCODER_CTX_set_cipher(ctx, "CURVE301-NO-SUCH-CIPHER", NULL) != 1;
        ED301V2_CHECK(ok && OSSL_ENCODER_CTX_set_params(ctx, combined) == 1
                && no_output(ctx), "valid cost alone cannot revive an invalid cipher");
        ok = ok && OSSL_ENCODER_CTX_set_cipher(ctx, NULL, NULL) == 1;
        unsigned char *plain_bytes = NULL;
        const unsigned char *cursor;
        size_t plain_length = 0;
        PKCS8_PRIV_KEY_INFO *plain = NULL;
        if (ok && OSSL_ENCODER_to_data(ctx, &plain_bytes, &plain_length) == 1
                && plain_length <= LONG_MAX) {
            cursor = plain_bytes;
            plain = d2i_PKCS8_PRIV_KEY_INFO(NULL, &cursor, (long)plain_length);
        }
        ED301V2_CHECK(plain_length == 62 && private_matches(plain, seed),
            "explicit cipher reset recovers canonical unencrypted output");
        PKCS8_PRIV_KEY_INFO_free(plain);
        OPENSSL_clear_free(plain_bytes, plain_length);
        ok = ok && OSSL_ENCODER_CTX_set_cipher(ctx, "AES-256-CBC", NULL) == 1;
        encrypted = ok ? encrypted_output(ctx, "DER") : NULL;
        ED301V2_CHECK(iterations_match(encrypted, 1000000),
            "explicit cipher reset restores the default password cost");
        X509_SIG_free(encrypted);
        OSSL_ENCODER_CTX_free(ctx);
        ERR_clear_error();
    }
done:
    EVP_PKEY_free(key);
    OSSL_PROVIDER_unload(provider);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
}

int main(void)
{
    ED301V2_REQUIRE_RUNTIME_BINDING();
    check_module(ED301V2_PKI_PROVIDER, ED301V2_PKI_PROP);
    check_module(ED301V2_TLS_PROVIDER, ED301V2_TLS_PROP);
    return ed301v2_summary("provider_password_policy");
}
