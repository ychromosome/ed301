/* Provider/FFI secret-taint regression. Test-only; run under Valgrind. */

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>

#include "../harness_common.h"
#include "generated/x301_contract_vectors.h"

#define X301_BYTES 38U
#define MLKEM_BYTES 1568U
#define HYBRID_PUBLIC_BYTES (MLKEM_BYTES + X301_BYTES)
#define HYBRID_SECRET_BYTES 70U
#define X301_NAME "X301"
#define HYBRID_NAME "X301MLKEM1024"
#define X301_PROPERTIES "provider=x301_v2_tls"

extern void ed301_vg_make_mem_undefined(void *address, size_t length);
extern unsigned int ed301_vg_running_on_valgrind(void);
extern unsigned int ed301_vg_get_vbits(
    const void *address, unsigned char *vbits, size_t length);
extern void ed301_vg_make_mem_defined(void *address, size_t length);
static int consume_secret(unsigned char *value, size_t length, int expected_taint)
{
    unsigned char vbits[HYBRID_SECRET_BYTES] = { 0 };
    size_t index;
    int tainted = 0;

    if (length > sizeof(vbits)
            || ed301_vg_get_vbits(value, vbits, length) != 1U)
        return 0;
    ed301_vg_make_mem_defined(vbits, length);
    for (index = 0; index < length; index++)
        tainted |= vbits[index] != 0;
    ed301_vg_make_mem_defined(value, length);
    return tainted == expected_taint;
}

static EVP_PKEY *hybrid_public_key(
    OSSL_LIB_CTX *libctx, unsigned char public_key[HYBRID_PUBLIC_BYTES])
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(
        libctx, HYBRID_NAME, X301_PROPERTIES);
    EVP_PKEY *key = NULL;

    if (ctx == NULL || EVP_PKEY_paramgen_init(ctx) <= 0
            || EVP_PKEY_generate(ctx, &key) <= 0
            || EVP_PKEY_set1_encoded_public_key(
                key, public_key, HYBRID_PUBLIC_BYTES) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *deflt = NULL, *x301 = NULL;
    EVP_PKEY *private_key = NULL, *peer = NULL;
    EVP_PKEY *hybrid_private = NULL, *hybrid_public = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char input_seed[X301_BYTES];
    unsigned char input_vbits[X301_BYTES];
    unsigned char exported_vbits[X301_BYTES];
    unsigned char raw_secret[X301_BYTES] = { 0 };
    unsigned char imported_seed[X301_BYTES] = { 0 };
    unsigned char hybrid_public_bytes[HYBRID_PUBLIC_BYTES];
    unsigned char ciphertext[HYBRID_PUBLIC_BYTES];
    unsigned char hybrid_secret_a[HYBRID_SECRET_BYTES] = { 0 };
    unsigned char hybrid_secret_b[HYBRID_SECRET_BYTES] = { 0 };
    unsigned char *encoded_public = NULL;
    size_t length, ciphertext_length, secret_length;
    const char *stage = "arguments";
    const char *mode = argc == 3 ? argv[2] : "tainted";
    int tainted = strcmp(mode, "tainted") == 0;
    int ok = 0;

    ED301V2_REQUIRE_RUNTIME_BINDING();
    memcpy(input_seed, SECRET_A, sizeof(input_seed));
    if ((argc != 2 && argc != 3)
            || (!tainted && strcmp(mode, "defined") != 0)
            || ed301_vg_running_on_valgrind() == 0)
        goto done;
    stage = "provider load";
    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL
            || !OSSL_PROVIDER_set_default_search_path(libctx, argv[1])
            || (deflt = OSSL_PROVIDER_load(libctx, "default")) == NULL
            || (x301 = OSSL_PROVIDER_load(libctx, "x301_v2_tls")) == NULL)
        goto done;

    stage = "input taint activation";
    if (tainted)
        ed301_vg_make_mem_undefined(input_seed, sizeof(input_seed));
    if (ed301_vg_get_vbits(input_seed, input_vbits, sizeof(input_seed)) != 1U)
        goto done;
    for (size_t i = 0; i < sizeof(input_vbits); i++)
        if (input_vbits[i] != (tainted ? 0xffU : 0U))
            goto done;
    stage = "raw X301 private import and export shadow state";
    private_key = EVP_PKEY_new_raw_private_key_ex(
        libctx, X301_NAME, X301_PROPERTIES, input_seed, sizeof(input_seed));
    length = sizeof(imported_seed);
    if (private_key == NULL
            || EVP_PKEY_get_raw_private_key(private_key, imported_seed, &length) <= 0
            || length != sizeof(imported_seed)
            || ed301_vg_get_vbits(imported_seed, exported_vbits, length) != 1U
            || CRYPTO_memcmp(exported_vbits, input_vbits, length) != 0
            || !consume_secret(imported_seed, length, tainted)
            || CRYPTO_memcmp(imported_seed, SECRET_A, length) != 0)
        goto done;
    stage = "raw X301 derive preserves imported shadow state";
    peer = EVP_PKEY_new_raw_public_key_ex(
        libctx, X301_NAME, X301_PROPERTIES, PUBLIC_B, sizeof(PUBLIC_B));
    ctx = private_key == NULL ? NULL
        : EVP_PKEY_CTX_new_from_pkey(libctx, private_key, X301_PROPERTIES);
    length = sizeof(raw_secret);
    if (ctx == NULL || peer == NULL || EVP_PKEY_derive_init(ctx) <= 0
            || EVP_PKEY_derive_set_peer(ctx, peer) <= 0
            || EVP_PKEY_derive(ctx, raw_secret, &length) <= 0
            || length != sizeof(raw_secret)
            || !consume_secret(raw_secret, length, tainted)
            || CRYPTO_memcmp(raw_secret, SHARED_AB, length) != 0)
        goto done;
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    stage = "hybrid key generation";
    hybrid_private = EVP_PKEY_Q_keygen(
        libctx, X301_PROPERTIES, HYBRID_NAME);
    length = hybrid_private == NULL ? 0
        : EVP_PKEY_get1_encoded_public_key(hybrid_private, &encoded_public);
    if (length != HYBRID_PUBLIC_BYTES)
        goto done;
    memcpy(hybrid_public_bytes, encoded_public, length);
    hybrid_public = hybrid_public_key(libctx, hybrid_public_bytes);
    stage = "hybrid encapsulation";
    ctx = hybrid_public == NULL ? NULL
        : EVP_PKEY_CTX_new_from_pkey(libctx, hybrid_public, X301_PROPERTIES);
    ciphertext_length = sizeof(ciphertext);
    secret_length = sizeof(hybrid_secret_a);
    if (ctx == NULL || EVP_PKEY_encapsulate_init(ctx, NULL) <= 0
            || EVP_PKEY_encapsulate(ctx, ciphertext, &ciphertext_length,
                hybrid_secret_a, &secret_length) <= 0
            || ciphertext_length != sizeof(ciphertext)
            || secret_length != sizeof(hybrid_secret_a)
            || !consume_secret(hybrid_secret_a, secret_length, 1))
        goto done;
    EVP_PKEY_CTX_free(ctx);
    stage = "hybrid decapsulation";
    ctx = EVP_PKEY_CTX_new_from_pkey(
        libctx, hybrid_private, X301_PROPERTIES);
    secret_length = sizeof(hybrid_secret_b);
    if (ctx == NULL || EVP_PKEY_decapsulate_init(ctx, NULL) <= 0
            || EVP_PKEY_decapsulate(ctx, hybrid_secret_b, &secret_length,
                ciphertext, ciphertext_length) <= 0
            || secret_length != sizeof(hybrid_secret_b)
            || !consume_secret(hybrid_secret_b, secret_length, 1)
            || CRYPTO_memcmp(hybrid_secret_a, hybrid_secret_b,
                secret_length) != 0)
        goto done;
    ok = 1;

done:
    ed301_vg_make_mem_defined(input_seed, sizeof(input_seed));
    OPENSSL_cleanse(input_seed, sizeof(input_seed));
    OPENSSL_cleanse(hybrid_secret_b, sizeof(hybrid_secret_b));
    OPENSSL_cleanse(hybrid_secret_a, sizeof(hybrid_secret_a));
    OPENSSL_cleanse(raw_secret, sizeof(raw_secret));
    OPENSSL_cleanse(imported_seed, sizeof(imported_seed));
    OPENSSL_free(encoded_public);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(hybrid_public);
    EVP_PKEY_free(hybrid_private);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(private_key);
    OSSL_PROVIDER_unload(x301);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    if (ok) {
        printf("provider_x301_secret_taint: mode=%s import_propagation=1 rng_taint=1 PASS\n", mode);
    } else {
        fprintf(stderr, "provider_x301_secret_taint: FAIL at %s\n", stage);
        ERR_print_errors_fp(stderr);
    }
    return ok ? 0 : 1;
}
