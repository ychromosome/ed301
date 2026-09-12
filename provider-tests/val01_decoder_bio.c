/*
 * VAL-01: decoder isolation and transactional TLS-test decoding.
 *
 * The ordinary and PKI artifacts expose no OSSL_DECODER.  The private-use
 * TLS artifact exposes strict DER decoders for SPKI and PKCS#8
 * PrivateKeyInfo.  Before reading, each decoder proves that the core BIO is
 * rewindable; short reads and all pre-OID mismatches restore the original
 * position.
 */

#include <openssl/buffer.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/core_object.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>

#include "harness_common.h"
#include "strict_serialization.h"
#include "v2_file_boundary.h"
#ifdef X301_CODEC_TEST
# include "generated/x301_contract_vectors.h"
# define CODEC_TEST_SEED SECRET_A
# define CODEC_TEST_PUBLIC PUBLIC_A
#else
# include "vectors.h"
# define CODEC_TEST_SEED POSITIVE_CASES[0].seed
# define CODEC_TEST_PUBLIC POSITIVE_CASES[0].public_key
#endif

#define ED301V2_TLS_PKCS8_DECODER_PROP \
    "provider=" ED301V2_TLS_PROVIDER ",input=der,structure=PrivateKeyInfo"
#define ED301V2_TLS_SPKI_DECODER_PROP \
    "provider=" ED301V2_TLS_PROVIDER ",input=der,structure=SubjectPublicKeyInfo"
#define ED301V2_COLLIDER_PKCS8_DECODER_PROP \
    "provider=ed301_eddsa_v2_tls_collider,input=der,structure=PrivateKeyInfo"
#define ED301V2_COLLIDER_SPKI_DECODER_PROP \
    "provider=ed301_eddsa_v2_tls_collider,input=der,structure=SubjectPublicKeyInfo"

static unsigned char *make_der(
    OSSL_LIB_CTX *libctx,
    int is_public,
    size_t *der_length)
{
    EVP_PKEY *key = ed301v2_key_from_seed(libctx, CODEC_TEST_SEED);
    OSSL_ENCODER_CTX *encoder = key == NULL ? NULL
        : OSSL_ENCODER_CTX_new_for_pkey(
            key,
            is_public ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR,
            "DER",
            is_public ? "SubjectPublicKeyInfo" : "PrivateKeyInfo",
            ED301V2_PKI_PROP);
    unsigned char *der = NULL;

    *der_length = 0;
    if (encoder == NULL
            || OSSL_ENCODER_to_data(encoder, &der, der_length) != 1) {
        OPENSSL_free(der);
        der = NULL;
    }
    OSSL_ENCODER_CTX_free(encoder);
    EVP_PKEY_free(key);
    return der;
}

static OSSL_DECODER_CTX *tls_decoder_context(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY **key,
    int is_public)
{
    return OSSL_DECODER_CTX_new_for_pkey(
        key,
        "DER",
        is_public ? "SubjectPublicKeyInfo" : "PrivateKeyInfo",
        ED301V2_ALG,
        is_public ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR,
        libctx,
        ED301V2_TLS_PROP);
}

static EVP_PKEY *tls_decode_data(
    OSSL_LIB_CTX *libctx,
    const unsigned char *data,
    size_t data_length,
    int is_public)
{
    EVP_PKEY *key = NULL;
    OSSL_DECODER_CTX *decoder = tls_decoder_context(
        libctx, &key, is_public);
    const unsigned char *cursor = data;
    size_t remaining = data_length;

    if (decoder == NULL
            || OSSL_DECODER_from_data(decoder, &cursor, &remaining) != 1
            || remaining != 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    OSSL_DECODER_CTX_free(decoder);
    ERR_clear_error();
    return key;
}

static unsigned char *pem_from_der(
    const unsigned char *der,
    size_t der_length,
    size_t *pem_length)
{
    BIO *bio = BIO_new(BIO_s_mem());
    BUF_MEM *memory = NULL;
    unsigned char *pem = NULL;
    int write_result;
    long memory_result;

    *pem_length = 0;
    write_result = bio != NULL && der != NULL && der_length <= LONG_MAX
        ? PEM_write_bio(bio, PEM_STRING_PKCS8INF, "", der,
            (long)der_length)
        : 0;
    memory_result = write_result > 0 ? BIO_get_mem_ptr(bio, &memory) : 0;
    if (write_result > 0 && memory_result > 0 && memory != NULL
            && memory->length != 0) {
        pem = OPENSSL_memdup(memory->data, memory->length);
        if (pem != NULL)
            *pem_length = memory->length;
    }
    BIO_free(bio);
    return pem;
}

static int decoder_password(
    char *buffer,
    int buffer_length,
    int reading,
    void *argument)
{
    const char *password = argument;
    size_t password_length;

    (void)reading;
    if (buffer == NULL || buffer_length <= 0 || password == NULL)
        return -1;
    password_length = strlen(password);
    if (password_length > (size_t)buffer_length)
        return -1;
    memcpy(buffer, password, password_length);
    return (int)password_length;
}

static unsigned char *encrypted_pem_from_der(
    OSSL_LIB_CTX *libctx,
    const unsigned char *der,
    size_t der_length,
    const char *password,
    size_t *pem_length)
{
    const unsigned char *cursor = der;
    PKCS8_PRIV_KEY_INFO *private_key_info = NULL;
    EVP_CIPHER *cipher = NULL;
    X509_SIG *encrypted = NULL;
    BIO *bio = NULL;
    BUF_MEM *memory = NULL;
    unsigned char *pem = NULL;

    *pem_length = 0;
    if (der == NULL || der_length > LONG_MAX || password == NULL)
        return NULL;
    private_key_info = d2i_PKCS8_PRIV_KEY_INFO(
        NULL, &cursor, (long)der_length);
    cipher = EVP_CIPHER_fetch(libctx, "AES-256-CBC", "provider=default");
    if (private_key_info != NULL && cursor == der + der_length
            && cipher != NULL)
        encrypted = PKCS8_encrypt_ex(-1, cipher, password,
            (int)strlen(password), NULL, 0, 2048, private_key_info,
            libctx, "provider=default");
    bio = encrypted == NULL ? NULL : BIO_new(BIO_s_mem());
    if (bio != NULL && PEM_write_bio_PKCS8(bio, encrypted) > 0
            && BIO_get_mem_ptr(bio, &memory) > 0 && memory != NULL
            && memory->length != 0) {
        pem = OPENSSL_memdup(memory->data, memory->length);
        if (pem != NULL)
            *pem_length = memory->length;
    }
    BIO_free(bio);
    X509_SIG_free(encrypted);
    EVP_CIPHER_free(cipher);
    PKCS8_PRIV_KEY_INFO_free(private_key_info);
    return pem;
}

static EVP_PKEY *pem_decode_private(
    OSSL_LIB_CTX *libctx,
    const unsigned char *pem,
    size_t pem_length,
    const char *password)
{
    BIO *bio = pem_length > INT_MAX ? NULL
        : BIO_new_mem_buf(pem, (int)pem_length);
    EVP_PKEY *key = bio == NULL ? NULL
        : PEM_read_bio_PrivateKey_ex(bio, NULL,
            password == NULL ? NULL : decoder_password,
            (void *)password, libctx, NULL);

    BIO_free(bio);
    return key;
}

static void complete_file_cases(OSSL_LIB_CTX *libctx,
    const unsigned char *pkcs8, size_t pkcs8_length,
    const unsigned char *spki, size_t spki_length,
    const unsigned char *pem, size_t pem_length,
    const unsigned char *encrypted_pem, size_t encrypted_pem_length)
{
    static const unsigned char password[] = "ed301-decoder-test";
    const struct {
        const unsigned char *input;
        size_t length;
        const char *format;
        int is_public;
        const unsigned char *password;
    } cases[] = {
        { pkcs8, pkcs8_length, "DER", 0, NULL },
        { spki, spki_length, "DER", 1, NULL },
        { pem, pem_length, "PEM", 0, NULL },
        { encrypted_pem, encrypted_pem_length, "PEM", 0, password },
    };
    BIO *bio = NULL;
    X509_SIG *encrypted = NULL;
    char *name = NULL;
    char *header = NULL;
    unsigned char *encrypted_der = NULL;
    long encrypted_length = 0;
    const unsigned char *cursor;

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        EVP_PKEY *key;
        unsigned char public_key[38];
        size_t public_length = sizeof(public_key);
        size_t password_length = cases[i].password == NULL ? 0 : sizeof(password) - 1;
        unsigned char *with_tail = cases[i].input == NULL ? NULL
            : OPENSSL_malloc(cases[i].length + 1);

        key = ed301v2_keyfile_decode(libctx, cases[i].input, cases[i].length,
            cases[i].format, cases[i].is_public, cases[i].password, password_length);
        ED301V2_CHECK(key != NULL
                && EVP_PKEY_get_raw_public_key(key, public_key, &public_length) == 1
                && public_length == sizeof(public_key)
                && CRYPTO_memcmp(public_key, CODEC_TEST_PUBLIC, sizeof(public_key)) == 0,
            "complete-file boundary case %zu imports through the real decoder chain", i);
        EVP_PKEY_free(key);
        if (with_tail != NULL) {
            memcpy(with_tail, cases[i].input, cases[i].length);
            with_tail[cases[i].length] = 0xa5;
        }
        key = with_tail == NULL ? NULL : ed301v2_keyfile_decode(libctx, with_tail,
            cases[i].length + 1, cases[i].format, cases[i].is_public,
            cases[i].password, password_length);
        ED301V2_CHECK(with_tail != NULL && key == NULL,
            "complete-file boundary case %zu rejects outer trailing bytes", i);
        EVP_PKEY_free(key);
        OPENSSL_clear_free(with_tail, cases[i].length + 1);
    }

    /* Reuse the OpenSSL-generated PBES2 parameters to encrypt exactly the
     * bytes under test. No ASN.1 parser or encryption primitive is replaced. */
    bio = encrypted_pem_length > INT_MAX ? NULL
        : BIO_new_mem_buf(encrypted_pem, (int)encrypted_pem_length);
    if (bio != NULL && PEM_read_bio(bio, &name, &header, &encrypted_der,
            &encrypted_length) == 1 && encrypted_length > 0) {
        cursor = encrypted_der;
        encrypted = d2i_X509_SIG(NULL, &cursor, encrypted_length);
    }
    ED301V2_CHECK(encrypted != NULL, "OpenSSL encrypted-container fixture for inner-file controls");
    if (encrypted != NULL && pkcs8_length == ED301V2_PKCS8_DER_BYTES) {
        X509_ALGOR *algorithm = NULL;
        ASN1_OCTET_STRING *ciphertext = NULL;

        X509_SIG_getm(encrypted, &algorithm, &ciphertext);
        for (size_t variant = 0; variant < 5; variant++) {
            unsigned char plain[ED301V2_PKCS8_DER_BYTES + 2];
            size_t plain_length = pkcs8_length;
            unsigned char *new_ciphertext = NULL;
            unsigned char *new_der = NULL;
            int new_ciphertext_length = 0;
            int new_der_length = 0;
            EVP_PKEY *key = NULL;
            int prepared;

            memcpy(plain, pkcs8, pkcs8_length);
            if (variant == 1) {
                plain[plain_length++] = 0;
            } else if (variant == 2) {
                memmove(plain + 3, plain + 2, plain_length - 2);
                plain[2] = plain[1];
                plain[1] = 0x81; /* non-minimal DER sequence length */
                plain_length++;
            } else if (variant == 3) {
                plain[4] = 1; /* unsupported OneAsymmetricKey version */
            } else if (variant == 4) {
                plain[1] += 2;
                plain[plain_length++] = 0xa0;
                plain[plain_length++] = 0; /* unsupported attributes */
            }
            prepared = algorithm != NULL && ciphertext != NULL
                && PKCS12_pbe_crypt_ex(algorithm, (const char *)password,
                    sizeof(password) - 1, plain, (int)plain_length,
                    &new_ciphertext, &new_ciphertext_length, 1, libctx, NULL) != NULL
                && ASN1_OCTET_STRING_set(ciphertext, new_ciphertext, new_ciphertext_length) == 1
                && (new_der_length = i2d_X509_SIG(encrypted, &new_der)) > 0;
            if (prepared)
                key = ed301v2_keyfile_decode(libctx, new_der, (size_t)new_der_length,
                    "DER", 0, password, sizeof(password) - 1);
            ED301V2_CHECK(prepared && (variant == 0 ? key != NULL : key == NULL),
                "encrypted complete-file variant %zu: positive control or strict inner rejection", variant);
            EVP_PKEY_free(key);
            OPENSSL_cleanse(plain, sizeof(plain));
            OPENSSL_clear_free(new_ciphertext,
                new_ciphertext_length > 0 ? (size_t)new_ciphertext_length : 0);
            OPENSSL_free(new_der);
        }
    }
    X509_SIG_free(encrypted);
    OPENSSL_clear_free(encrypted_der, encrypted_length > 0 ? (size_t)encrypted_length : 0);
    OPENSSL_free(header);
    OPENSSL_free(name);
    BIO_free(bio);
}

static int private_key_matches_vector(EVP_PKEY *key)
{
    const OSSL_PROVIDER *provider = key == NULL ? NULL
        : EVP_PKEY_get0_provider(key);
    unsigned char seed[ED301V2_SEED_BYTES] = { 0 };
    unsigned char public_key[ED301V2_PUB_BYTES] = { 0 };
    size_t seed_length = sizeof(seed);
    size_t public_length = sizeof(public_key);

    return key != NULL && provider != NULL
        && strcmp(OSSL_PROVIDER_get0_name(provider), ED301V2_TLS_PROVIDER) == 0
        && EVP_PKEY_is_a(key, ED301V2_ALG) == 1
        && EVP_PKEY_get_raw_private_key(key, seed, &seed_length) == 1
        && seed_length == sizeof(seed)
        && CRYPTO_memcmp(seed, CODEC_TEST_SEED, sizeof(seed)) == 0
        && EVP_PKEY_get_raw_public_key(
            key, public_key, &public_length) == 1
        && public_length == sizeof(public_key)
        && CRYPTO_memcmp(public_key, CODEC_TEST_PUBLIC,
            sizeof(public_key)) == 0;
}

static int private_key_operates_for_public(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *private_key,
    EVP_PKEY *public_key)
{
#ifdef X301_CODEC_TEST
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_pkey(
        libctx, private_key, ED301V2_TLS_PROP);
    unsigned char shared[38];
    size_t length = sizeof(shared);
    int ok = context != NULL && EVP_PKEY_derive_init(context) == 1
        && EVP_PKEY_derive_set_peer(context, public_key) == 1
        && EVP_PKEY_derive(context, shared, &length) == 1
        && length == sizeof(shared)
        && CRYPTO_memcmp(shared, SHARED_AA, sizeof(shared)) == 0;
    OPENSSL_cleanse(shared, sizeof(shared));
    EVP_PKEY_CTX_free(context);
    return ok;
#else
    unsigned char signature[ED301V2_SIG_BYTES];

    return ed301v2_digest_sign(libctx, private_key,
            POSITIVE_CASES[0].message, POSITIVE_CASES[0].message_len,
            signature)
        && CRYPTO_memcmp(signature, POSITIVE_CASES[0].signature,
            sizeof(signature)) == 0
        && ed301v2_digest_verify(libctx, public_key,
            POSITIVE_CASES[0].message, POSITIVE_CASES[0].message_len,
            signature, sizeof(signature));
#endif
}

static int record_construct(
    OSSL_DECODER_INSTANCE *decoder_instance,
    const OSSL_PARAM *parameters,
    void *construct_argument)
{
    int *constructed = construct_argument;
    const OSSL_PARAM *data_type = OSSL_PARAM_locate_const(
        parameters, OSSL_OBJECT_PARAM_DATA_TYPE);

    (void)decoder_instance;
    if (constructed == NULL || data_type == NULL || data_type->data == NULL
            || strcmp(data_type->data, ED301V2_ALG) != 0)
        return 0;
    *constructed = 1;
    return 1;
}

static int reject_construct(
    OSSL_DECODER_INSTANCE *decoder_instance,
    const OSSL_PARAM *parameters,
    void *construct_argument)
{
    int *called = construct_argument;
    const OSSL_PARAM *data_type = OSSL_PARAM_locate_const(
        parameters, OSSL_OBJECT_PARAM_DATA_TYPE);

    (void)decoder_instance;
    if (called == NULL || data_type == NULL || data_type->data == NULL
            || strcmp(data_type->data, ED301V2_ALG) != 0)
        return 0;
    *called = 1;
    return 0;
}

static OSSL_DECODER_CTX *single_tls_decoder_context_with_construct(
    OSSL_LIB_CTX *libctx,
    int is_public,
    OSSL_DECODER_CONSTRUCT *construct,
    void *construct_data,
    OSSL_DECODER **decoder_out)
{
    OSSL_DECODER_CTX *context = OSSL_DECODER_CTX_new();
    OSSL_DECODER *decoder = OSSL_DECODER_fetch(
        libctx,
        ED301V2_ALG,
        is_public ? ED301V2_TLS_SPKI_DECODER_PROP
                  : ED301V2_TLS_PKCS8_DECODER_PROP);

    *decoder_out = decoder;
    if (context == NULL || decoder == NULL || construct == NULL
            || OSSL_DECODER_CTX_add_decoder(context, decoder) != 1
            || OSSL_DECODER_CTX_set_selection(
                context,
                is_public ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR) != 1
            || OSSL_DECODER_CTX_set_input_type(context, "DER") != 1
            || OSSL_DECODER_CTX_set_input_structure(
                context,
                is_public ? "SubjectPublicKeyInfo"
                          : "PrivateKeyInfo") != 1
            || OSSL_DECODER_CTX_set_construct(context, construct) != 1
            || OSSL_DECODER_CTX_set_construct_data(
                context, construct_data) != 1) {
        OSSL_DECODER_CTX_free(context);
        context = NULL;
    }
    return context;
}

static OSSL_DECODER_CTX *single_tls_decoder_context(
    OSSL_LIB_CTX *libctx,
    int is_public,
    int *constructed,
    OSSL_DECODER **decoder_out)
{
    *constructed = 0;
    return single_tls_decoder_context_with_construct(
        libctx, is_public, record_construct, constructed, decoder_out);
}

static int rejected_input_is_unconsumed(
    OSSL_LIB_CTX *libctx,
    const unsigned char *data,
    size_t data_length,
    int is_public)
{
    OSSL_DECODER *implementation = NULL;
    int constructed = 0;
    OSSL_DECODER_CTX *decoder = single_tls_decoder_context(
        libctx, is_public, &constructed, &implementation);
    BIO *input = BIO_new_mem_buf(data, (int)data_length);
    int result;
    long remaining;
    int no_provider_error;
    unsigned long errors[ED301V2_ERROR_QUEUE_CAPACITY];
    size_t error_count;

    if (decoder == NULL || input == NULL) {
        OSSL_DECODER_CTX_free(decoder);
        OSSL_DECODER_free(implementation);
        BIO_free(input);
        return 0;
    }
    ed301v2_seed_error_sentinel();
    result = OSSL_DECODER_from_bio(decoder, input);
    remaining = BIO_ctrl_pending(input);
    error_count = ed301v2_drain_error_queue(
        errors, ED301V2_ERROR_QUEUE_CAPACITY);
    no_provider_error = error_count == 3
        && ERR_GET_LIB(errors[0]) == ERR_LIB_USER
        && ERR_GET_REASON(errors[0]) == ED301V2_CALLER_SENTINEL_A
        && ERR_GET_LIB(errors[1]) == ERR_LIB_USER
        && ERR_GET_REASON(errors[1]) == ED301V2_CALLER_SENTINEL_B
        && ERR_GET_LIB(errors[2]) == ERR_LIB_OSSL_DECODER;
    OSSL_DECODER_CTX_free(decoder);
    OSSL_DECODER_free(implementation);
    BIO_free(input);
    return result != 1 && !constructed
        && remaining == (long)data_length && no_provider_error;
}

static int hard_failure_is_consumed_and_reported(
    OSSL_LIB_CTX *libctx,
    const unsigned char *data,
    size_t data_length,
    int is_public,
    size_t expected_remaining)
{
    OSSL_DECODER *implementation = NULL;
    int constructed = 0;
    OSSL_DECODER_CTX *decoder = single_tls_decoder_context(
        libctx, is_public, &constructed, &implementation);
    BIO *input = BIO_new_mem_buf(data, (int)data_length);
    int result;
    long remaining;
    unsigned long error;
    const char *error_data;
    int error_flags;
    int algorithm_reported = 0;
    int wrong_algorithm = 0;

    if (decoder == NULL || input == NULL) {
        OSSL_DECODER_CTX_free(decoder);
        OSSL_DECODER_free(implementation);
        BIO_free(input);
        return 0;
    }
    ERR_clear_error();
    result = OSSL_DECODER_from_bio(decoder, input);
    remaining = BIO_ctrl_pending(input);
    error = ERR_peek_error();
    while (ERR_get_error_all(NULL, NULL, NULL, &error_data, &error_flags) != 0) {
        if ((error_flags & ERR_TXT_STRING) != 0 && error_data != NULL) {
            algorithm_reported |= strstr(error_data, ED301V2_ALG) != NULL;
#ifdef X301_CODEC_TEST
            wrong_algorithm |= strstr(error_data, "Ed301-EdDSA") != NULL;
#endif
        }
    }
    OSSL_DECODER_CTX_free(decoder);
    OSSL_DECODER_free(implementation);
    BIO_free(input);
    ERR_clear_error();
    return result != 1 && !constructed
        && remaining == (long)expected_remaining && error != 0
        && algorithm_reported && !wrong_algorithm;
}

static int callback_rejection_consumes_reference(
    OSSL_LIB_CTX *libctx,
    const unsigned char *data,
    size_t data_length,
    int is_public)
{
    OSSL_DECODER *implementation = NULL;
    int called = 0;
    OSSL_DECODER_CTX *decoder =
        single_tls_decoder_context_with_construct(
            libctx, is_public, reject_construct, &called, &implementation);
    BIO *input = BIO_new_mem_buf(data, (int)data_length);
    int result;
    long remaining;

    if (decoder == NULL || input == NULL) {
        OSSL_DECODER_CTX_free(decoder);
        OSSL_DECODER_free(implementation);
        BIO_free(input);
        return 0;
    }
    ERR_clear_error();
    result = OSSL_DECODER_from_bio(decoder, input);
    remaining = BIO_ctrl_pending(input);
    OSSL_DECODER_CTX_free(decoder);
    OSSL_DECODER_free(implementation);
    BIO_free(input);
    ERR_clear_error();

    /* The existing focused Valgrind lane checks the rejected reference. */
    return result != 1 && called == 1 && remaining == 0;
}

static int retry_every_split(
    OSSL_LIB_CTX *libctx,
    const unsigned char *data,
    size_t data_length,
    int is_public)
{
    size_t split;

    for (split = 1; split < data_length; split++) {
        OSSL_DECODER *implementation = NULL;
        int constructed = 0;
        OSSL_DECODER_CTX *decoder = single_tls_decoder_context(
            libctx, is_public, &constructed, &implementation);
        BIO *reader = NULL;
        BIO *writer = NULL;
        int ok = decoder != NULL
            && BIO_new_bio_pair(&reader, 0, &writer, 0) == 1
            && BIO_write(writer, data, (int)split) == (int)split;

        if (ok) {
            ok = BIO_ctrl_pending(reader) == split
                && OSSL_DECODER_from_bio(decoder, reader) != 1
                && !constructed
                && BIO_ctrl_pending(reader) == split;
            if (!ok)
                fprintf(stderr,
                    "retry split %zu/%zu consumed an incomplete prefix\n",
                    split, data_length);
            ERR_clear_error();
        }
        if (ok) {
            ok = BIO_write(
                    writer,
                    data + split,
                    (int)(data_length - split))
                    == (int)(data_length - split)
                && OSSL_DECODER_from_bio(decoder, reader) == 1
                && constructed;
            if (!ok)
                fprintf(stderr,
                    "retry split %zu/%zu did not resume exact decoding\n",
                    split, data_length);
        }
        OSSL_DECODER_CTX_free(decoder);
        OSSL_DECODER_free(implementation);
        BIO_free(reader);
        BIO_free(writer);
        ERR_clear_error();
        if (!ok)
            return 0;
    }
    return 1;
}

static int wrong_selection_is_unconsumed(
    OSSL_LIB_CTX *libctx,
    const unsigned char *data,
    size_t data_length)
{
    OSSL_DECODER *implementation = NULL;
    int constructed = 0;
    OSSL_DECODER_CTX *decoder = single_tls_decoder_context_with_construct(
        libctx, 0, record_construct, &constructed, &implementation);
    BIO *input = BIO_new_mem_buf(data, (int)data_length);
    int result;
    long remaining;

    if (decoder == NULL || input == NULL
            || OSSL_DECODER_CTX_set_selection(
                decoder, EVP_PKEY_PUBLIC_KEY) != 1) {
        OSSL_DECODER_CTX_free(decoder);
        OSSL_DECODER_free(implementation);
        BIO_free(input);
        return 0;
    }
    ERR_clear_error();
    result = OSSL_DECODER_from_bio(decoder, input);
    remaining = BIO_ctrl_pending(input);
    OSSL_DECODER_CTX_free(decoder);
    OSSL_DECODER_free(implementation);
    BIO_free(input);
    ERR_clear_error();
    return result != 1 && !constructed
        && remaining == (long)data_length;
}

static int fresh_context_private_load(
    const unsigned char *pem,
    size_t pem_length,
    int rounds)
{
    int round;

    for (round = 0; round < rounds; round++) {
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        OSSL_PROVIDER *deflt = NULL;
        OSSL_PROVIDER *tls = libctx == NULL ? NULL
            : ed301v2_load_named(
                libctx, &deflt, ED301V2_TLS_PROVIDER);
        EVP_PKEY *key = tls == NULL ? NULL
            : pem_decode_private(libctx, pem, pem_length, NULL);
        int ok = private_key_matches_vector(key)
            && private_key_operates_for_public(libctx, key, key);

        EVP_PKEY_free(key);
        OSSL_PROVIDER_unload(tls);
        OSSL_PROVIDER_unload(deflt);
        OSSL_LIB_CTX_free(libctx);
        ERR_clear_error();
        if (!ok)
            return 0;
    }
    return 1;
}

static EVP_PKEY *make_foreign_key(OSSL_LIB_CTX *libctx, const char *name)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_name(
        libctx, name, "provider=default");
    EVP_PKEY *key = NULL;
    int ok = context != NULL && EVP_PKEY_keygen_init(context) == 1;

    if (ok && strcmp(name, "RSA") == 0)
        ok = EVP_PKEY_CTX_set_rsa_keygen_bits(context, 2048) == 1;
    if (ok && strcmp(name, "EC") == 0)
        ok = EVP_PKEY_CTX_set_group_name(context, "prime256v1") == 1;
    if (!ok || EVP_PKEY_generate(context, &key) != 1) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(context);
    return key;
}

static unsigned char *encode_foreign_key(
    EVP_PKEY *key,
    int is_public,
    size_t *encoded_length)
{
    OSSL_ENCODER_CTX *encoder = key == NULL ? NULL
        : OSSL_ENCODER_CTX_new_for_pkey(
            key,
            is_public ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR,
            "DER",
            is_public ? "SubjectPublicKeyInfo" : "PrivateKeyInfo",
            "provider=default");
    unsigned char *encoded = NULL;

    *encoded_length = 0;
    if (encoder == NULL
            || OSSL_ENCODER_to_data(
                encoder, &encoded, encoded_length) != 1) {
        OPENSSL_free(encoded);
        encoded = NULL;
    }
    OSSL_ENCODER_CTX_free(encoder);
    return encoded;
}

static int generic_decode_is(
    OSSL_LIB_CTX *libctx,
    const unsigned char *data,
    size_t data_length,
    int is_public,
    const char *expected_type)
{
    EVP_PKEY *key = NULL;
    OSSL_DECODER_CTX *decoder = OSSL_DECODER_CTX_new_for_pkey(
        &key,
        "DER",
        is_public ? "SubjectPublicKeyInfo" : "PrivateKeyInfo",
        NULL,
        is_public ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR,
        libctx,
        NULL);
    const unsigned char *cursor = data;
    size_t remaining = data_length;
    int ok;
    int queue_unchanged;

    ed301v2_seed_error_sentinel();
    ok = decoder != NULL
        && OSSL_DECODER_from_data(decoder, &cursor, &remaining) == 1
        && remaining == 0 && key != NULL
        && EVP_PKEY_is_a(key, expected_type) == 1;
    queue_unchanged = ed301v2_queue_is_sentinel_only();

    OSSL_DECODER_CTX_free(decoder);
    EVP_PKEY_free(key);
    return ok && queue_unchanged;
}

int main(void)
{
    ED301V2_REQUIRE_RUNTIME_BINDING();
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_LIB_CTX *reverse_libctx = NULL;
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *v1 = NULL;
    OSSL_PROVIDER *tls = NULL;
    OSSL_PROVIDER *collider = NULL;
    OSSL_PROVIDER *reverse_tls = NULL;
    OSSL_PROVIDER *reverse_default = NULL;
    OSSL_DECODER *decoder;
    unsigned char *pkcs8 = NULL;
    unsigned char *spki = NULL;
    unsigned char *rsa_pkcs8 = NULL;
    unsigned char *rsa_spki = NULL;
    unsigned char *ec_pkcs8 = NULL;
    unsigned char *ec_spki = NULL;
    unsigned char *ed25519_pkcs8 = NULL;
    unsigned char *ed448_pkcs8 = NULL;
    unsigned char *pkcs8_pem = NULL;
    unsigned char *encrypted_pkcs8_pem = NULL;
    size_t pkcs8_length = 0;
    size_t spki_length = 0;
    size_t rsa_pkcs8_length = 0;
    size_t rsa_spki_length = 0;
    size_t ec_pkcs8_length = 0;
    size_t ec_spki_length = 0;
    size_t ed25519_pkcs8_length = 0;
    size_t ed448_pkcs8_length = 0;
    size_t pkcs8_pem_length = 0;
    size_t encrypted_pkcs8_pem_length = 0;
    EVP_PKEY *key = NULL;
    EVP_PKEY *public_key = NULL;
    EVP_PKEY *rsa = NULL;
    EVP_PKEY *ec = NULL;
    EVP_PKEY *ed25519 = NULL;
    EVP_PKEY *ed448 = NULL;
    unsigned char foreign[ED301V2_PKCS8_DER_BYTES + 1] = { 0 };
    unsigned char malformed[160] = { 0 };

    ed301v2_property = ED301V2_PKI_PROP;
    v1 = ed301v2_load_named(libctx, &deflt, ED301V2_PKI_PROVIDER);
    ED301V2_CHECK(libctx != NULL && v1 != NULL,
        "test-only PKI provider loads through the host integration gate");

    decoder = OSSL_DECODER_fetch(libctx, ED301V2_ALG, ED301V2_PKI_PROP);
    ED301V2_CHECK(decoder == NULL,
        "PKI artifact exposes no provider decoder operation");
    OSSL_DECODER_free(decoder);
    ERR_clear_error();

    pkcs8 = make_der(libctx, 0, &pkcs8_length);
    spki = make_der(libctx, 1, &spki_length);
    ED301V2_CHECK(pkcs8 != NULL && pkcs8_length == ED301V2_PKCS8_DER_BYTES,
        "exact PKCS#8 test object produced");
    ED301V2_CHECK(spki != NULL && spki_length == ED301V2_SPKI_DER_BYTES,
        "exact SPKI test object produced");

    key = ed301v2_strict_der_import(libctx, pkcs8, pkcs8_length, 0);
    ED301V2_CHECK(key != NULL,
        "complete-buffer PKCS#8 import succeeds after explicit selection");
    EVP_PKEY_free(key);
    key = NULL;

    key = ed301v2_strict_der_import(libctx, spki, spki_length, 1);
    ED301V2_CHECK(key != NULL,
        "complete-buffer SPKI import succeeds after explicit selection");
    EVP_PKEY_free(key);
    key = NULL;

    if (pkcs8 != NULL) {
        memcpy(foreign, pkcs8, pkcs8_length);
        foreign[10] ^= 1;
        ED301V2_CHECK(ed301v2_strict_der_import(
                libctx, foreign, pkcs8_length, 0) == NULL,
            "foreign OID is rejected before any key import");
        ED301V2_CHECK(ed301v2_strict_der_import(
                libctx, pkcs8, pkcs8_length - 1, 0) == NULL,
            "partial input is rejected without a streaming state");
        foreign[10] ^= 1;
        foreign[pkcs8_length] = 0;
        ED301V2_CHECK(ed301v2_strict_der_import(
                libctx, foreign, pkcs8_length + 1, 0) == NULL,
            "trailing bytes are rejected at the complete-buffer boundary");
    }

    tls = ed301v2_load_named(libctx, NULL, ED301V2_TLS_PROVIDER);
    ED301V2_CHECK(tls != NULL,
        "TLS artifact loads after the exact host registry preflight");
    ed301v2_property = ED301V2_TLS_PROP;
    decoder = OSSL_DECODER_fetch(
        libctx, ED301V2_ALG, ED301V2_TLS_SPKI_DECODER_PROP);
    ED301V2_CHECK(decoder != NULL,
        "TLS artifact exposes the transactional SPKI DER decoder");
    OSSL_DECODER_free(decoder);
    decoder = OSSL_DECODER_fetch(
        libctx, ED301V2_ALG, ED301V2_TLS_PKCS8_DECODER_PROP);
    ED301V2_CHECK(decoder != NULL,
        "TLS artifact exposes the strict PKCS#8 DER decoder");
    OSSL_DECODER_free(decoder);
    decoder = OSSL_DECODER_fetch(
        libctx, ED301V2_OID_TEXT, ED301V2_TLS_PKCS8_DECODER_PROP);
    ED301V2_CHECK(decoder != NULL,
        "canonical v2 OID resolves to the TLS PKCS#8 decoder");
    OSSL_DECODER_free(decoder);
    decoder = OSSL_DECODER_fetch(libctx,
        "1.3.6.1.4.1.66282.301.3", ED301V2_TLS_PKCS8_DECODER_PROP);
    ED301V2_CHECK(decoder == NULL,
        "historical Ed301 OID is not a decoder alias");
    OSSL_DECODER_free(decoder);
    decoder = OSSL_DECODER_fetch(libctx,
        "1.3.6.1.4.1.66282.301.2", ED301V2_TLS_PKCS8_DECODER_PROP);
    ED301V2_CHECK(decoder == NULL,
        "X301 OID is not an Ed301 decoder alias");
    OSSL_DECODER_free(decoder);
    ERR_clear_error();

#ifndef X301_CODEC_TEST
    collider = ed301v2_load_named(
        libctx, NULL, ED301V2_TLS_COLLIDER_PROVIDER);
    decoder = collider == NULL ? NULL : OSSL_DECODER_fetch(
        libctx, ED301V2_ALG, ED301V2_COLLIDER_PKCS8_DECODER_PROP);
    ED301V2_CHECK(collider != NULL && decoder == NULL,
        "TLS collider remains without a private-key decoder");
    OSSL_DECODER_free(decoder);
    decoder = collider == NULL ? NULL : OSSL_DECODER_fetch(
        libctx, ED301V2_ALG, ED301V2_COLLIDER_SPKI_DECODER_PROP);
    ED301V2_CHECK(decoder != NULL,
        "TLS collider retains its SPKI-only decoder surface");
    OSSL_DECODER_free(decoder);
    OSSL_PROVIDER_unload(collider);
    collider = NULL;
    ERR_clear_error();
#endif

    if (tls != NULL && pkcs8 != NULL && spki != NULL) {
        unsigned int oid_leaf;

        for (oid_leaf = 1; oid_leaf <= 6; oid_leaf++) {
            if (oid_leaf == CODEC_OID_LEAF)
                continue;
            memcpy(foreign, pkcs8, pkcs8_length);
            foreign[19] = (unsigned char)oid_leaf;
            ED301V2_CHECK(rejected_input_is_unconsumed(
                    libctx, foreign, pkcs8_length, 0),
                "foreign profile OID leaf %u cannot select the private decoder",
                oid_leaf);
            memcpy(foreign, spki, spki_length);
            foreign[16] = (unsigned char)oid_leaf;
            ED301V2_CHECK(rejected_input_is_unconsumed(
                    libctx, foreign, spki_length, 1),
                "foreign profile OID leaf %u cannot select the public decoder",
                oid_leaf);
        }
        memcpy(malformed, pkcs8, pkcs8_length);
        malformed[1] += 2;
        malformed[pkcs8_length] = 0xa0; /* [0] IMPLICIT empty Attributes */
        malformed[pkcs8_length + 1] = 0;
        key = tls_decode_data(libctx, malformed, pkcs8_length + 2, 0);
        ED301V2_CHECK(key == NULL, "PKCS#8 version 0 with attributes is rejected");
        EVP_PKEY_free(key);
        key = NULL;

#ifdef X301_CODEC_TEST
        {
            size_t index;

            for (index = 0; index < 64; index++) {
                unsigned char *weak_pem;
                size_t weak_pem_length = 0;

                memcpy(malformed, pkcs8, pkcs8_length);
                memcpy(malformed + sizeof(ED301V2_PKCS8_PREFIX),
                    WEAK_SECRETS[index], ED301V2_SEED_BYTES);
                key = tls_decode_data(libctx, malformed, pkcs8_length, 0);
                ED301V2_CHECK(key == NULL, "weak alias %zu rejected from PKCS#8 DER", index);
                EVP_PKEY_free(key);
                weak_pem = encrypted_pem_from_der(libctx, malformed, pkcs8_length,
                    "d2-weak-test", &weak_pem_length);
                key = weak_pem == NULL ? NULL : pem_decode_private(libctx,
                    weak_pem, weak_pem_length, "d2-weak-test");
                ED301V2_CHECK(weak_pem != NULL && key == NULL,
                    "weak alias %zu rejected after generic PKCS#8 decryption", index);
                EVP_PKEY_free(key);
                key = NULL;
                OPENSSL_clear_free(weak_pem, weak_pem_length);
            }
            for (index = 0; index < 3; index++) {
                EVP_PKEY_CTX *exchange;
                unsigned char output[38];
                unsigned char canary[38];
                size_t length = sizeof(output);

                memcpy(malformed, spki, spki_length);
                memcpy(malformed + sizeof(ED301V2_SPKI_PREFIX), SMALL_ORDER_U[index], 38);
                public_key = tls_decode_data(libctx, malformed, spki_length, 1);
                key = tls_decode_data(libctx, pkcs8, pkcs8_length, 0);
                exchange = key == NULL ? NULL : EVP_PKEY_CTX_new_from_pkey(
                    libctx, key, ED301V2_TLS_PROP);
                memset(output, 0xa5, sizeof(output));
                memcpy(canary, output, sizeof(canary));
                ED301V2_CHECK(public_key != NULL && exchange != NULL
                        && EVP_PKEY_derive_init(exchange) == 1
                        && EVP_PKEY_derive_set_peer(exchange, public_key) == 1
                        && EVP_PKEY_derive(exchange, output, &length) != 1
                        && CRYPTO_memcmp(output, canary, sizeof(output)) == 0,
                    "canonical low-order SPKI %zu imports; derive rejects without output", index);
                EVP_PKEY_CTX_free(exchange);
                EVP_PKEY_free(key);
                EVP_PKEY_free(public_key);
                key = NULL;
                public_key = NULL;
            }
        }
#endif
        key = tls_decode_data(libctx, pkcs8, pkcs8_length, 0);
        public_key = tls_decode_data(libctx, spki, spki_length, 1);
        ED301V2_CHECK(private_key_matches_vector(key),
            "TLS decoder imports the exact PKCS#8 seed and public key");
        ED301V2_CHECK(public_key != NULL
                && private_key_operates_for_public(libctx, key, public_key),
            "PKCS#8-loaded private key signs for the decoded public key");
        EVP_PKEY_free(key);
        key = NULL;
        EVP_PKEY_free(public_key);
        public_key = NULL;

        pkcs8_pem = pem_from_der(
            pkcs8, pkcs8_length, &pkcs8_pem_length);
        key = pkcs8_pem == NULL ? NULL : pem_decode_private(
            libctx, pkcs8_pem, pkcs8_pem_length, NULL);
        ED301V2_CHECK(private_key_matches_vector(key),
            "generic OpenSSL PEM chain reaches the TLS PKCS#8 decoder");
        EVP_PKEY_free(key);
        key = NULL;

        encrypted_pkcs8_pem = encrypted_pem_from_der(libctx,
            pkcs8, pkcs8_length, "ed301-decoder-test",
            &encrypted_pkcs8_pem_length);
        key = encrypted_pkcs8_pem == NULL ? NULL : pem_decode_private(
            libctx, encrypted_pkcs8_pem, encrypted_pkcs8_pem_length,
            "ed301-decoder-test");
        ED301V2_CHECK(private_key_matches_vector(key),
            "generic EncryptedPrivateKeyInfo chain reaches the TLS decoder");
        EVP_PKEY_free(key);
        key = NULL;
        key = encrypted_pkcs8_pem == NULL ? NULL : pem_decode_private(
            libctx, encrypted_pkcs8_pem, encrypted_pkcs8_pem_length,
            "wrong-password");
        ED301V2_CHECK(key == NULL,
            "encrypted PKCS#8 rejects the wrong password");
        EVP_PKEY_free(key);
        key = NULL;

        complete_file_cases(libctx, pkcs8, pkcs8_length, spki, spki_length,
            pkcs8_pem, pkcs8_pem_length, encrypted_pkcs8_pem, encrypted_pkcs8_pem_length);

        key = tls_decode_data(libctx, spki, spki_length, 1);
        ED301V2_CHECK(key != NULL,
            "TLS decoder imports one exact SPKI object");
        EVP_PKEY_free(key);
        key = NULL;

        ED301V2_CHECK(retry_every_split(
                libctx, spki, spki_length, 1),
            "SPKI retry source remains untouched at every split");
        ED301V2_CHECK(retry_every_split(
                libctx, pkcs8, pkcs8_length, 0),
            "PKCS#8 retry source remains untouched at every split");

        memcpy(foreign, spki, spki_length);
        foreign[8] ^= 1;
        ED301V2_CHECK(rejected_input_is_unconsumed(
                libctx, foreign, spki_length, 1),
            "foreign SPKI OID is a soft non-match without consumption");
        ED301V2_CHECK(rejected_input_is_unconsumed(
                libctx, spki, spki_length - 1, 1),
            "partial SPKI is a soft non-match before consuming its prefix");

        memcpy(foreign, pkcs8, pkcs8_length);
        foreign[19] = 0x01;
        ED301V2_CHECK(rejected_input_is_unconsumed(
                libctx, foreign, pkcs8_length, 0),
            "historical Ed301 PKCS#8 OID is a soft non-match");
        foreign[19] = 0x02;
        ED301V2_CHECK(rejected_input_is_unconsumed(
                libctx, foreign, pkcs8_length, 0),
            "X301 PKCS#8 OID is a soft non-match");
        ED301V2_CHECK(rejected_input_is_unconsumed(
                libctx, pkcs8, pkcs8_length - 1, 0),
            "partial PKCS#8 is retryable without input or error damage");
        ED301V2_CHECK(wrong_selection_is_unconsumed(
                libctx, pkcs8, pkcs8_length),
            "PKCS#8 decoder rejects a public-only selection unconsumed");

        memcpy(foreign, spki, spki_length);
        foreign[2] ^= 1;
        ED301V2_CHECK(hard_failure_is_consumed_and_reported(
                libctx, foreign, spki_length, 1, 0),
            "malformed confirmed-OID SPKI is a consuming hard failure");

        memcpy(foreign, spki, spki_length);
        foreign[0] = 0x31;
        ED301V2_CHECK(hard_failure_is_consumed_and_reported(
                libctx, foreign, spki_length, 1, 0),
            "wrong outer tag reports the selected algorithm");

        memcpy(foreign, spki, spki_length);
        memcpy(foreign + sizeof(ED301V2_SPKI_PREFIX),
#ifdef X301_CODEC_TEST
            FIELD_MODULUS, ED301V2_PUB_BYTES);
#else
            POINT_CASES[2].encoding, ED301V2_PUB_BYTES); /* identity */
#endif
        ED301V2_CHECK(hard_failure_is_consumed_and_reported(
                libctx, foreign, spki_length, 1, 0),
            "confirmed-OID SPKI with invalid key material is a consuming "
            "hard failure");

        ED301V2_CHECK(callback_rejection_consumes_reference(
                libctx, spki, spki_length, 1),
            "construct-callback rejection consumes the matched object; "
            "Valgrind checks reference release");

        memcpy(malformed, pkcs8, pkcs8_length);
        malformed[2] ^= 1;
        ED301V2_CHECK(hard_failure_is_consumed_and_reported(
                libctx, malformed, pkcs8_length, 0, 0),
            "malformed confirmed-OID PKCS#8 is a consuming hard failure");

        memcpy(malformed, pkcs8, pkcs8_length);
        malformed[4] = 0x01;
        ED301V2_CHECK(hard_failure_is_consumed_and_reported(
                libctx, malformed, pkcs8_length, 0, 0),
            "OneAsymmetricKey version is a consuming hard failure");

        memcpy(malformed, pkcs8, pkcs8_length);
        malformed[21] = 0x27;
        ED301V2_CHECK(hard_failure_is_consumed_and_reported(
                libctx, malformed, pkcs8_length, 0, 0),
            "wrong outer private OCTET STRING length is a hard failure");
        memcpy(malformed, pkcs8, pkcs8_length);
        malformed[22] = 0x03;
        ED301V2_CHECK(hard_failure_is_consumed_and_reported(
                libctx, malformed, pkcs8_length, 0, 0),
            "wrong private-key nesting is a consuming hard failure");
        memcpy(malformed, pkcs8, pkcs8_length);
        malformed[23] = 0x25;
        ED301V2_CHECK(hard_failure_is_consumed_and_reported(
                libctx, malformed, pkcs8_length, 0, 0),
            "wrong seed length is a consuming hard failure");

        memcpy(malformed, pkcs8, pkcs8_length);
        malformed[1] = 0x3d;
        malformed[pkcs8_length] = 0x00;
        ED301V2_CHECK(hard_failure_is_consumed_and_reported(
                libctx, malformed, pkcs8_length + 1, 0,
                1),
            "additional PKCS#8 content is a hard failure");

        memset(malformed, 0, sizeof(malformed));
        malformed[0] = 0x30;
        malformed[1] = 0x3e;
        malformed[2] = 0x02;
        malformed[3] = 0x01;
        malformed[4] = 0x00;
        malformed[5] = 0x30;
        malformed[6] = 0x0f;
        memcpy(malformed + 7, pkcs8 + 7, ED301V2_OID_TLV_BYTES);
        malformed[20] = 0x05;
        malformed[21] = 0x00;
        memcpy(malformed + 22, pkcs8 + 20, pkcs8_length - 20);
        ED301V2_CHECK(hard_failure_is_consumed_and_reported(
                libctx, malformed, pkcs8_length + 2, 0,
                2),
            "PKCS#8 NULL parameters are a hard failure");
        malformed[20] = 0x04;
        ED301V2_CHECK(hard_failure_is_consumed_and_reported(
                libctx, malformed, pkcs8_length + 2, 0,
                2),
            "PKCS#8 explicit parameters are a hard failure");

        memcpy(malformed, pkcs8, pkcs8_length);
        malformed[1] = 0x3b;
        malformed[21] = 0x27;
        malformed[23] = 0x25;
        ED301V2_CHECK(rejected_input_is_unconsumed(
                libctx, malformed, pkcs8_length - 1, 0),
            "37-byte seed form remains retryable and is not imported");

        memcpy(malformed, pkcs8, pkcs8_length);
        malformed[1] = 0x3d;
        malformed[21] = 0x29;
        malformed[23] = 0x27;
        malformed[pkcs8_length] = 0x00;
        ED301V2_CHECK(hard_failure_is_consumed_and_reported(
                libctx, malformed, pkcs8_length + 1, 0,
                1),
            "39-byte seed form is not partially imported");

        memcpy(malformed, pkcs8, 20);
        malformed[0] = 0x30;
        malformed[1] = 0x3d;
        malformed[20] = 0x04;
        malformed[21] = 0x81;
        malformed[22] = 0x28;
        memcpy(malformed + 23, pkcs8 + 22, pkcs8_length - 22);
        ED301V2_CHECK(hard_failure_is_consumed_and_reported(
                libctx, malformed, pkcs8_length + 1, 0,
                1),
            "non-minimal inner DER length is a hard failure");

        malformed[0] = 0x30;
        malformed[1] = 0x81;
        malformed[2] = pkcs8[1];
        memcpy(malformed + 3, pkcs8 + 2, pkcs8_length - 2);
        ED301V2_CHECK(rejected_input_is_unconsumed(
                libctx, malformed, pkcs8_length + 1, 0),
            "non-minimal outer DER length is rejected without chain damage");

        ED301V2_CHECK(callback_rejection_consumes_reference(
                libctx, pkcs8, pkcs8_length, 0),
            "private construct rejection releases the matched reference");
    }

    rsa = make_foreign_key(libctx, "RSA");
    ec = make_foreign_key(libctx, "EC");
    ed25519 = make_foreign_key(libctx, "ED25519");
    ed448 = make_foreign_key(libctx, "ED448");
    rsa_pkcs8 = encode_foreign_key(rsa, 0, &rsa_pkcs8_length);
    rsa_spki = encode_foreign_key(rsa, 1, &rsa_spki_length);
    ec_pkcs8 = encode_foreign_key(ec, 0, &ec_pkcs8_length);
    ec_spki = encode_foreign_key(ec, 1, &ec_spki_length);
    ed25519_pkcs8 = encode_foreign_key(
        ed25519, 0, &ed25519_pkcs8_length);
    ed448_pkcs8 = encode_foreign_key(ed448, 0, &ed448_pkcs8_length);
    ED301V2_CHECK(rsa_pkcs8 != NULL && rsa_spki != NULL
            && ec_pkcs8 != NULL && ec_spki != NULL
            && ed25519_pkcs8 != NULL && ed448_pkcs8 != NULL,
        "foreign RSA, EC, Ed25519 and Ed448 controls are available");

    if (rsa_pkcs8 != NULL && rsa_spki != NULL
            && ec_pkcs8 != NULL && ec_spki != NULL
            && ed25519_pkcs8 != NULL && ed448_pkcs8 != NULL) {
        ED301V2_CHECK(generic_decode_is(libctx, rsa_pkcs8,
                rsa_pkcs8_length, 0, "RSA")
                && generic_decode_is(libctx, rsa_spki,
                    rsa_spki_length, 1, "RSA")
                && generic_decode_is(libctx, ec_pkcs8,
                    ec_pkcs8_length, 0, "EC")
                && generic_decode_is(libctx, ec_spki,
                    ec_spki_length, 1, "EC")
                && generic_decode_is(libctx, ed25519_pkcs8,
                    ed25519_pkcs8_length, 0, "ED25519")
                && generic_decode_is(libctx, ed448_pkcs8,
                    ed448_pkcs8_length, 0, "ED448"),
            "generic foreign-key decoding survives default-first order");

        reverse_libctx = OSSL_LIB_CTX_new();
        reverse_tls = reverse_libctx == NULL ? NULL
            : OSSL_PROVIDER_load(reverse_libctx, ED301V2_TLS_PROVIDER);
        reverse_default = reverse_libctx == NULL ? NULL
            : OSSL_PROVIDER_load(reverse_libctx, "default");
        ED301V2_CHECK(reverse_tls != NULL && reverse_default != NULL,
            "reverse-order TLS/default providers load");
        ED301V2_CHECK(reverse_tls != NULL && reverse_default != NULL
                && generic_decode_is(reverse_libctx, rsa_pkcs8,
                    rsa_pkcs8_length, 0, "RSA")
                && generic_decode_is(reverse_libctx, rsa_spki,
                    rsa_spki_length, 1, "RSA")
                && generic_decode_is(reverse_libctx, ec_pkcs8,
                    ec_pkcs8_length, 0, "EC")
                && generic_decode_is(reverse_libctx, ec_spki,
                    ec_spki_length, 1, "EC")
                && generic_decode_is(reverse_libctx, ed25519_pkcs8,
                    ed25519_pkcs8_length, 0, "ED25519")
                && generic_decode_is(reverse_libctx, ed448_pkcs8,
                    ed448_pkcs8_length, 0, "ED448"),
            "generic foreign-key decoding survives TLS-first order");
    }

    ED301V2_CHECK(pkcs8_pem != NULL
            && fresh_context_private_load(pkcs8_pem, pkcs8_pem_length, 8),
        "PKCS#8 PEM reloads in fresh library contexts");

    OSSL_PROVIDER_unload(tls);
    tls = OSSL_PROVIDER_load(libctx, ED301V2_TLS_PROVIDER);
    key = tls == NULL || pkcs8_pem == NULL ? NULL
        : pem_decode_private(libctx, pkcs8_pem, pkcs8_pem_length, NULL);
    ED301V2_CHECK(tls != NULL && private_key_matches_vector(key),
        "PKCS#8 decoder reloads without retaining an old key reference");
    EVP_PKEY_free(key);
    key = NULL;

    OPENSSL_clear_free(pkcs8, pkcs8_length);
    OPENSSL_free(spki);
    OPENSSL_clear_free(rsa_pkcs8, rsa_pkcs8_length);
    OPENSSL_free(rsa_spki);
    OPENSSL_clear_free(ec_pkcs8, ec_pkcs8_length);
    OPENSSL_free(ec_spki);
    OPENSSL_clear_free(ed25519_pkcs8, ed25519_pkcs8_length);
    OPENSSL_clear_free(ed448_pkcs8, ed448_pkcs8_length);
    OPENSSL_clear_free(pkcs8_pem, pkcs8_pem_length);
    OPENSSL_clear_free(
        encrypted_pkcs8_pem, encrypted_pkcs8_pem_length);
    EVP_PKEY_free(rsa);
    EVP_PKEY_free(ec);
    EVP_PKEY_free(ed25519);
    EVP_PKEY_free(ed448);
    OSSL_PROVIDER_unload(reverse_default);
    OSSL_PROVIDER_unload(reverse_tls);
    OSSL_LIB_CTX_free(reverse_libctx);
    OSSL_PROVIDER_unload(collider);
    OSSL_PROVIDER_unload(tls);
    OSSL_PROVIDER_unload(v1);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    return ed301v2_summary("val01_transactional_tls_decoder");
}
