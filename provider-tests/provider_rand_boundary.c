/* Distinguish parent RAND configuration from mirrored provider properties. */
#include <openssl/encoder.h>
#include <openssl/rand.h>

#include "harness_common.h"
#include "../provider/common/encoder_params.h"

static void check_parent_rand_boundary(int policy)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *provider = NULL;
    EVP_PKEY_CTX *keygen = NULL;
    EVP_PKEY *key = NULL;
    OSSL_ENCODER_CTX *encoder = NULL;
    unsigned char parent_bytes[38] = { 0 };
    unsigned char private_bytes[38] = { 0 };
    unsigned char *encoded = NULL;
    size_t private_length = sizeof(private_bytes);
    size_t encoded_length = 0;
    unsigned int iterations = 12345;
    OSSL_PARAM parameters[2];
    int parent_result = 0;

    if (libctx != NULL)
        deflt = OSSL_PROVIDER_load(libctx, "default");
    ED301V2_CHECK(deflt != NULL, "parent default provider loads");
    if (deflt == NULL)
        goto done;
    if (policy == 1) {
        ED301V2_CHECK(RAND_set_DRBG_type(libctx,
                "CURVE301-NO-SUCH-DRBG", NULL, NULL, NULL) == 1,
            "parent accepts an explicitly selected unavailable DRBG");
    } else if (policy == 2) {
        ED301V2_CHECK(RAND_set_seed_source_type(libctx,
                "CURVE301-NO-SUCH-SEED-SOURCE", NULL) == 1,
            "parent accepts an explicitly selected unavailable seed source");
    }
    parent_result = RAND_priv_bytes_ex(libctx, parent_bytes, sizeof(parent_bytes), 149);
    if (policy != 2)
        ED301V2_CHECK(policy == 1 ? parent_result != 1 : parent_result == 1,
            "parent RAND observes its own DRBG configuration");
    /* A missing seed source can fall back in older OpenSSL. Record that
     * result separately; the unavailable-DRBG case is the rejection control. */
    ERR_clear_error();

    provider = OSSL_PROVIDER_load(libctx, ED301V2_TLS_PROVIDER);
    keygen = EVP_PKEY_CTX_new_from_name(libctx, ED301V2_ALG, ED301V2_TLS_PROP);
    ED301V2_CHECK(provider != NULL && keygen != NULL
            && EVP_PKEY_keygen_init(keygen) == 1
            && EVP_PKEY_generate(keygen, &key) == 1
            && EVP_PKEY_get_raw_private_key(key, private_bytes, &private_length) == 1
            && private_length == sizeof(private_bytes),
        "direct provider keygen uses the independent child-context RAND configuration");

    if (key != NULL)
        encoder = OSSL_ENCODER_CTX_new_for_pkey(key, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
            "DER", "EncryptedPrivateKeyInfo", ED301V2_TLS_PROP);
    parameters[0] = OSSL_PARAM_construct_uint(
        CURVE301_ENCODER_PARAM_PBKDF2_ITERATIONS, &iterations);
    parameters[1] = OSSL_PARAM_construct_end();
    ED301V2_CHECK(encoder != NULL
            && OSSL_ENCODER_CTX_set_params(encoder, parameters) == 1
            && OSSL_ENCODER_CTX_set_cipher(encoder, "AES-256-CBC", NULL) == 1
            && OSSL_ENCODER_CTX_set_passphrase(encoder,
                (const unsigned char *)"review-only", 11) == 1
            && OSSL_ENCODER_to_data(encoder, &encoded, &encoded_length) == 1
            && encoded != NULL && encoded_length > 62,
        "provider-generated PKCS8 salt and IV share the child RAND boundary");
    printf("rand_boundary algorithm=%s parent_policy=%s parent_rand=%d\n",
        ED301V2_ALG, policy == 0 ? "default"
            : policy == 1 ? "unavailable-drbg" : "unavailable-seed", parent_result);
done:
    OPENSSL_cleanse(parent_bytes, sizeof(parent_bytes));
    OPENSSL_cleanse(private_bytes, sizeof(private_bytes));
    OPENSSL_free(encoded);
    OSSL_ENCODER_CTX_free(encoder);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(keygen);
    OSSL_PROVIDER_unload(provider);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
}

int main(void)
{
    ED301V2_REQUIRE_RUNTIME_BINDING();
    check_parent_rand_boundary(0);
    check_parent_rand_boundary(1);
    check_parent_rand_boundary(2);
    return ed301v2_summary("provider_rand_boundary");
}
