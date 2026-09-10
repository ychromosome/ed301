/* Deterministic hybrid-glue KAT. X bytes come from frozen Phase-B vectors.
 * ML-KEM reference operations use a separate default-only private libctx,
 * with OpenSSL's documented seed and ikme test parameters. This is not an
 * independent ML-KEM implementation or a replacement for its native KATs.
 */
#include "../harness_common.h"
#include "generated/x301_contract_vectors.h"

#define X301_BYTES 38U
#include "test_rand.h"

#define HYBRID "X301MLKEM1024"
#define HYBRID_PROP "provider=x301_v2_tls_test"

static unsigned char ml_seed[64];
static unsigned char ml_entropy[32];
static const unsigned char *recipient_secret;
static const unsigned char *sender_secret;
static unsigned int draw;

static int kat_random(unsigned char *output, size_t length)
{
    const unsigned char *source = NULL;
    size_t expected = 0;

    switch (draw++) {
    case 0: source = recipient_secret; expected = 38; break;
    case 1: source = ml_seed; expected = 64; break;
    case 2: source = ml_entropy; expected = 32; break;
    case 3: source = sender_secret; expected = 38; break;
    default: break;
    }
    if (source == NULL || expected != length) {
        fprintf(stderr, "unexpected KAT RNG draw %u length %zu (expected %zu)\n",
            draw, length, expected);
        return 0;
    }
    memcpy(output, source, length);
    return 1;
}

static EVP_PKEY *generate_hybrid(OSSL_LIB_CTX *libctx, int parameters_only)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(libctx, HYBRID, HYBRID_PROP);
    EVP_PKEY *key = NULL;
    int initialized = ctx != NULL && (parameters_only
        ? EVP_PKEY_paramgen_init(ctx) : EVP_PKEY_keygen_init(ctx)) == 1;

    if (!initialized || EVP_PKEY_generate(ctx, &key) != 1) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static void run_kat(OSSL_LIB_CTX *libctx, OSSL_LIB_CTX *reference, unsigned int index)
{
    EVP_PKEY_CTX *mlgen = NULL;
    EVP_PKEY_CTX *mlenc = NULL;
    EVP_PKEY_CTX *mldec = NULL;
    EVP_PKEY_CTX *enc = NULL;
    EVP_PKEY_CTX *dec = NULL;
    EVP_PKEY *mlkey = NULL;
    EVP_PKEY *hybrid = NULL;
    EVP_PKEY *public_key = NULL;
    unsigned char ml_public[1568];
    unsigned char ml_ciphertext[1568];
    unsigned char ml_shared[32];
    unsigned char *public_bytes = NULL;
    unsigned char ciphertext[1606];
    unsigned char encapsulated[70];
    unsigned char decapsulated[70];
    size_t public_length;
    size_t length = sizeof(ml_public);
    size_t ciphertext_length = sizeof(ml_ciphertext);
    size_t secret_length = sizeof(ml_shared);
    const unsigned char *recipient_public = index % 2 ? PUBLIC_B : PUBLIC_A;
    const unsigned char *sender_public = index % 2 ? PUBLIC_A : PUBLIC_B;
    OSSL_PARAM seed_params[2];
    OSSL_PARAM entropy_params[2];
    int ok;

    recipient_secret = index % 2 ? SECRET_B : SECRET_A;
    sender_secret = index % 2 ? SECRET_A : SECRET_B;
    for (size_t i = 0; i < sizeof(ml_seed); i++)
        ml_seed[i] = (unsigned char)(17U * index + i);
    for (size_t i = 0; i < sizeof(ml_entropy); i++)
        ml_entropy[i] = (unsigned char)(31U * index + i + 0xa0U);
    seed_params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_ML_KEM_SEED, ml_seed, sizeof(ml_seed));
    seed_params[1] = OSSL_PARAM_construct_end();
    entropy_params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_KEM_PARAM_IKME, ml_entropy, sizeof(ml_entropy));
    entropy_params[1] = OSSL_PARAM_construct_end();

    mlgen = EVP_PKEY_CTX_new_from_name(reference, "ML-KEM-1024", "provider=default");
    ok = mlgen != NULL && EVP_PKEY_keygen_init(mlgen) == 1
        && EVP_PKEY_CTX_set_params(mlgen, seed_params) == 1
        && EVP_PKEY_generate(mlgen, &mlkey) == 1
        && EVP_PKEY_get_octet_string_param(mlkey, OSSL_PKEY_PARAM_PUB_KEY,
            ml_public, sizeof(ml_public), &length) == 1 && length == sizeof(ml_public);
    ED301V2_CHECK(ok, "KAT %u: explicit seed generates reference ML-KEM key", index);
    if (!ok)
        goto done;
    mlenc = EVP_PKEY_CTX_new_from_pkey(reference, mlkey, "provider=default");
    mldec = EVP_PKEY_CTX_new_from_pkey(reference, mlkey, "provider=default");
    ok = mlenc != NULL && mldec != NULL
        && EVP_PKEY_encapsulate_init(mlenc, entropy_params) == 1
        && EVP_PKEY_decapsulate_init(mldec, NULL) == 1
        && EVP_PKEY_encapsulate(mlenc, ml_ciphertext, &ciphertext_length,
            ml_shared, &secret_length) == 1
        && ciphertext_length == sizeof(ml_ciphertext)
        && secret_length == sizeof(ml_shared);
    ED301V2_CHECK(ok, "KAT %u: explicit ikme fixes reference ciphertext and secret", index);
    if (!ok)
        goto done;

    draw = rand_generate_calls = 0;
    rand_poisoned = 0;
    hybrid = generate_hybrid(libctx, 0);
    public_length = hybrid == NULL ? 0
        : EVP_PKEY_get1_encoded_public_key(hybrid, &public_bytes);
    ok = hybrid != NULL && public_bytes != NULL && public_length == 1606
        && draw == 2 && rand_generate_calls == 2
        && memcmp(public_bytes, ml_public, sizeof(ml_public)) == 0
        && memcmp(public_bytes + 1568, recipient_public, 38) == 0;
    ED301V2_CHECK(ok, "KAT %u: 1606-byte public = exact ML-KEM ek || frozen X public", index);
    if (!ok)
        goto done;
    public_key = generate_hybrid(libctx, 1);
    ok = public_key != NULL && EVP_PKEY_set1_encoded_public_key(public_key,
        public_bytes, public_length) == 1;
    ED301V2_CHECK(ok, "KAT %u: public-only hybrid import", index);
    if (!ok)
        goto done;
    enc = EVP_PKEY_CTX_new_from_pkey(libctx, public_key, HYBRID_PROP);
    dec = EVP_PKEY_CTX_new_from_pkey(libctx, hybrid, HYBRID_PROP);
    ciphertext_length = sizeof(ciphertext);
    secret_length = sizeof(encapsulated);
    ok = enc != NULL && dec != NULL
        && EVP_PKEY_encapsulate_init(enc, NULL) == 1
        && EVP_PKEY_decapsulate_init(dec, NULL) == 1
        && EVP_PKEY_encapsulate(enc, ciphertext, &ciphertext_length,
            encapsulated, &secret_length) == 1
        && ciphertext_length == sizeof(ciphertext)
        && secret_length == sizeof(encapsulated)
        && draw == 4 && rand_generate_calls == 4;
    ED301V2_CHECK(ok, "KAT %u: full encapsulation uses exactly the four prescribed draws", index);
    if (!ok)
        goto done;
    ED301V2_CHECK(memcmp(ciphertext, ml_ciphertext, sizeof(ml_ciphertext)) == 0
            && memcmp(ciphertext + 1568, sender_public, 38) == 0
            && CRYPTO_memcmp(encapsulated, ml_shared, sizeof(ml_shared)) == 0
            && CRYPTO_memcmp(encapsulated + 32, SHARED_AB, 38) == 0,
        "KAT %u: exact 1606-byte ct and 70-byte shared secret, ML-KEM first, no KDF", index);

    rand_poisoned = 1;
    secret_length = sizeof(decapsulated);
    ED301V2_CHECK(EVP_PKEY_decapsulate(dec, decapsulated, &secret_length,
            ciphertext, sizeof(ciphertext)) == 1
            && secret_length == sizeof(decapsulated)
            && CRYPTO_memcmp(encapsulated, decapsulated, sizeof(encapsulated)) == 0
            && rand_generate_calls == 4,
        "KAT %u: deterministic decapsulation with poisoned RNG", index);
    ciphertext[0] ^= 1;
    length = sizeof(ml_shared);
    secret_length = sizeof(decapsulated);
    ED301V2_CHECK(EVP_PKEY_decapsulate(mldec, ml_shared, &length,
            ciphertext, sizeof(ml_ciphertext)) == 1 && length == sizeof(ml_shared)
            && EVP_PKEY_decapsulate(dec, decapsulated, &secret_length,
                ciphertext, sizeof(ciphertext)) == 1
            && secret_length == sizeof(decapsulated)
            && CRYPTO_memcmp(decapsulated, ml_shared, 32) == 0
            && CRYPTO_memcmp(decapsulated, encapsulated, 32) != 0
            && CRYPTO_memcmp(decapsulated + 32, SHARED_AB, 38) == 0
            && rand_generate_calls == 4,
        "KAT %u: delegated implicit rejection changes only the ML-KEM component", index);
done:
    rand_poisoned = 0;
    EVP_PKEY_CTX_free(dec);
    EVP_PKEY_CTX_free(enc);
    EVP_PKEY_CTX_free(mldec);
    EVP_PKEY_CTX_free(mlenc);
    EVP_PKEY_CTX_free(mlgen);
    EVP_PKEY_free(public_key);
    EVP_PKEY_free(hybrid);
    EVP_PKEY_free(mlkey);
    OPENSSL_free(public_bytes);
    OPENSSL_cleanse(encapsulated, sizeof(encapsulated));
    OPENSSL_cleanse(decapsulated, sizeof(decapsulated));
    OPENSSL_cleanse(ml_shared, sizeof(ml_shared));
}

int main(void)
{
    OSSL_LIB_CTX *libctx;
    OSSL_LIB_CTX *reference;
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *reference_default = NULL;
    OSSL_PROVIDER *rand_provider = NULL;
    OSSL_PROVIDER *x = NULL;
    int ready;

    ED301V2_REQUIRE_RUNTIME_BINDING();
    libctx = OSSL_LIB_CTX_new();
    reference = OSSL_LIB_CTX_new();
    test_rand_output = kat_random;
    ready = libctx != NULL && reference != NULL
        && (reference_default = OSSL_PROVIDER_load(reference, "default")) != NULL
        && (deflt = OSSL_PROVIDER_load(libctx, "default")) != NULL
        && OSSL_PROVIDER_add_builtin(libctx, TEST_RAND_PROVIDER, test_rand_provider_init) == 1
        && (rand_provider = OSSL_PROVIDER_load(libctx, TEST_RAND_PROVIDER)) != NULL
        && (x = OSSL_PROVIDER_load(libctx, "x301_v2_tls_test")) != NULL
        && EVP_set_default_properties(libctx, "?" TEST_RAND_PROPERTY) == 1
        && RAND_set_DRBG_type(libctx, "CTR-DRBG", TEST_RAND_PROPERTY, NULL, NULL) == 1;
    ED301V2_CHECK(ready, "separate private contexts: hybrid test-RAND and default-only ML-KEM reference");
    if (ready)
        for (unsigned int i = 0; i < 4; i++)
            run_kat(libctx, reference, i);
    OSSL_PROVIDER_unload(x);
    OSSL_PROVIDER_unload(rand_provider);
    OSSL_PROVIDER_unload(deflt);
    OSSL_PROVIDER_unload(reference_default);
    OSSL_LIB_CTX_free(libctx);
    OSSL_LIB_CTX_free(reference);
    ED301V2_CHECK(OSSL_PROVIDER_available(NULL, "x301_v2_tls_test") == 0
            && OSSL_PROVIDER_available(NULL, TEST_RAND_PROVIDER) == 0,
        "test providers absent from the default libctx");
    return ed301v2_summary("provider_x301_hybrid_kat");
}
