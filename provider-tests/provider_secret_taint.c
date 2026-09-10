/*
 * Secret-taint lane across EVP -> provider shim -> Rust FFI -> Ed301 core.
 *
 * The instrumented test module declassifies only reviewed public outputs.
 * Memcheck therefore reports any secret-dependent branch or address reached
 * from the undefined 38-byte seed. A clean run is evidence for the exercised
 * binary/toolchain/path, not a general constant-time proof.
 */

#include <stdint.h>

#include <openssl/encoder.h>

#include <valgrind/memcheck.h>
#include <valgrind/valgrind.h>

#include "harness_common.h"
#include "../provider/common/generated_ed301_profile.h"
#include "vectors.h"

static int vbits_match(const unsigned char *bytes, size_t length,
    int expect_undefined, const char *label)
{
    unsigned char vbits[ED301V2_MAX_ENCODED_KEY_BYTES];
    size_t index;

    if (bytes == NULL || length == 0 || length > sizeof(vbits)
            || VALGRIND_GET_VBITS(bytes, vbits, length) != 1) {
        fprintf(stderr, "Valgrind V-bit query failed\n");
        return 0;
    }
    for (index = 0; index < length; index++) {
        unsigned char expected = expect_undefined ? 0xffU : 0x00U;

        if (vbits[index] != expected) {
            fprintf(stderr,
                "%s V-bit mismatch at byte %zu: got=0x%02x expected=0x%02x\n",
                label, index, (unsigned int)vbits[index], (unsigned int)expected);
            return 0;
        }
    }
    return 1;
}

/* Observe exported shadow bits before checking known test-vector bytes.
 * Only a separate harness comparison copy is defined, never the provider's
 * key, input seed, exported parameter, or encoded private output. */
static int private_bytes_match(const unsigned char *bytes, size_t length,
    int tainted, const POSITIVE_CASE *test_case, const char *label)
{
    unsigned char comparison[ED301V2_SEED_BYTES];
    int ok;

    if (length != sizeof(comparison)
            || !vbits_match(bytes, length, tainted, label))
        return 0;
    memcpy(comparison, bytes, sizeof(comparison));
    VALGRIND_MAKE_MEM_DEFINED(comparison, sizeof(comparison));
    ok = memcmp(comparison, test_case->seed, sizeof(comparison)) == 0;
    OPENSSL_cleanse(comparison, sizeof(comparison));
    return ok;
}

static int private_exports(EVP_PKEY *key, int tainted,
    const POSITIVE_CASE *test_case)
{
    unsigned char raw[ED301V2_SEED_BYTES];
    size_t length = 0;
    const int selections[] = {
        OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_KEYPAIR
    };
    size_t index;
    int ok = 0;

    if (EVP_PKEY_get_raw_private_key(key, NULL, &length) != 1
            || length != sizeof(raw))
        goto cleanup;
    if (EVP_PKEY_get_raw_private_key(key, raw, &length) != 1
            || !private_bytes_match(raw, length, tainted, test_case,
                "raw-private-export"))
        goto cleanup;
    length = 0;
    if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PRIV_KEY,
            raw, sizeof(raw), &length) != 1
            || !private_bytes_match(raw, length, tainted, test_case,
                "private-get-param"))
        goto cleanup;
    for (index = 0; index < sizeof(selections) / sizeof(selections[0]); index++) {
        OSSL_PARAM *parameters = NULL;
        const OSSL_PARAM *private_param;
        const OSSL_PARAM *public_param;
        int exported = EVP_PKEY_todata(key, selections[index], &parameters) == 1;

        private_param = parameters == NULL ? NULL
            : OSSL_PARAM_locate_const(parameters, OSSL_PKEY_PARAM_PRIV_KEY);
        public_param = parameters == NULL ? NULL
            : OSSL_PARAM_locate_const(parameters, OSSL_PKEY_PARAM_PUB_KEY);
        exported = exported && private_param != NULL
            && private_param->data_type == OSSL_PARAM_OCTET_STRING
            && private_bytes_match(private_param->data, private_param->data_size,
                tainted, test_case, "keymgmt-private-export");
        if (index == 0) {
            exported = exported && public_param == NULL;
        } else {
            exported = exported && public_param != NULL
                && public_param->data_type == OSSL_PARAM_OCTET_STRING
                && public_param->data_size == ED301V2_PUB_BYTES
                && vbits_match(public_param->data, public_param->data_size,
                    0, "keymgmt-public-export")
                && memcmp(public_param->data, test_case->public_key,
                    ED301V2_PUB_BYTES) == 0;
        }
        OSSL_PARAM_free(parameters);
        if (!exported)
            goto cleanup;
    }
    ok = 1;
cleanup:
    OPENSSL_cleanse(raw, sizeof(raw));
    return ok;
}

static int pkcs8_bytes_match(const unsigned char *der, size_t length,
    int tainted, int positive_control, const POSITIVE_CASE *test_case)
{
    const size_t prefix_length = sizeof(ED301V2_PKCS8_PREFIX);

    if (length != prefix_length + ED301V2_SEED_BYTES
            || !vbits_match(der, prefix_length, 0, "pkcs8-public-prefix")
            || memcmp(der, ED301V2_PKCS8_PREFIX, prefix_length) != 0
            || !private_bytes_match(der + prefix_length, ED301V2_SEED_BYTES,
                tainted, test_case, "pkcs8-private-seed"))
        return 0;
    if (positive_control) {
        /* Deliberately consume one bit of the actual still-tainted DER seed.
         * This isolated harness control must produce Memcheck exit 99. */
        volatile unsigned char table[2] = { 17, 29 };
        volatile unsigned char observed = table[der[prefix_length] & 1U];

        VALGRIND_MAKE_MEM_DEFINED((void *)&observed, sizeof(observed));
        (void)observed;
        puts("private_export_positive_control=triggered");
    }
    return 1;
}

static int private_pkcs8(EVP_PKEY *key, int tainted, int positive_control,
    const POSITIVE_CASE *test_case)
{
    const int selections[] = {
        OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_KEYPAIR
    };
    size_t index;
    int use_bio;

    for (index = 0; index < sizeof(selections) / sizeof(selections[0]); index++) {
        for (use_bio = 0; use_bio <= 1; use_bio++) {
            OSSL_ENCODER_CTX *ctx = OSSL_ENCODER_CTX_new_for_pkey(key,
                selections[index], "DER", "PrivateKeyInfo", ED301V2_PKI_PROP);
            unsigned char *data = NULL;
            size_t length = 0;
            BIO *bio = NULL;
            int ok = ctx != NULL && OSSL_ENCODER_CTX_get_num_encoders(ctx) > 0;

            if (use_bio) {
                char *contents = NULL;
                long size = 0;

                bio = BIO_new(BIO_s_mem());
                ok = ok && bio != NULL && OSSL_ENCODER_to_bio(ctx, bio) == 1;
                if (ok)
                    size = BIO_get_mem_data(bio, &contents);
                ok = ok && size > 0 && pkcs8_bytes_match(
                    (const unsigned char *)contents, (size_t)size,
                    tainted, positive_control, test_case);
                if (size > 0)
                    OPENSSL_cleanse(contents, (size_t)size);
            } else {
                ok = ok && OSSL_ENCODER_to_data(ctx, &data, &length) == 1
                    && pkcs8_bytes_match(data, length, tainted,
                        positive_control, test_case);
            }
            OPENSSL_clear_free(data, length);
            BIO_free(bio);
            OSSL_ENCODER_CTX_free(ctx);
            if (!ok)
                return 0;
        }
    }
    return 1;
}

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *v2 = NULL;
    OSSL_PROVIDER *encoder_provider = NULL;
    const POSITIVE_CASE *test_case = &POSITIVE_CASES[0];
    unsigned char seed[ED301V2_SEED_BYTES];
    unsigned char public_key[ED301V2_PUB_BYTES];
    unsigned char signature[ED301V2_SIG_BYTES];
    unsigned char repeated[ED301V2_SIG_BYTES];
    size_t public_len = 0;
    EVP_PKEY *pkey = NULL;
    const char *path;
    const char *key_provider;
    int tainted;
    int positive_control;
    int encode_private;
    int ok = 0;

    ED301V2_REQUIRE_RUNTIME_BINDING();
    if (RUNNING_ON_VALGRIND == 0) {
        fprintf(stderr, "provider_secret_taint requires Valgrind\n");
        return 2;
    }
    if ((argc != 2 && argc != 3 && argc != 4)
            || (strcmp(argv[1], "defined") != 0
                && strcmp(argv[1], "tainted") != 0)) {
        fprintf(stderr, "usage: %s <defined|tainted> [normal|pki|bridge] [export-control]\n", argv[0]);
        return 2;
    }
    path = argc >= 3 ? argv[2] : "normal";
    tainted = strcmp(argv[1], "tainted") == 0;
    positive_control = argc == 4;
    encode_private = strcmp(path, "normal") != 0;
    if ((strcmp(path, "normal") != 0 && strcmp(path, "pki") != 0
            && strcmp(path, "bridge") != 0)
            || (positive_control && (!tainted || !encode_private
                || strcmp(argv[3], "export-control") != 0)))
        return 2;
    key_provider = strcmp(path, "pki") == 0
        ? ED301V2_PKI_PROVIDER : ED301V2_PROVIDER;
    ed301v2_property = strcmp(path, "pki") == 0
        ? ED301V2_PKI_PROP : ED301V2_PROP;
    libctx = OSSL_LIB_CTX_new();
    v2 = ed301v2_load_named(libctx, &deflt, key_provider);
    if (v2 == NULL) {
        fprintf(stderr, "instrumented provider load failed\n");
        goto cleanup;
    }
    if (strcmp(path, "bridge") == 0) {
        encoder_provider = ed301v2_load_named(libctx, NULL, ED301V2_PKI_PROVIDER);
        if (encoder_provider == NULL)
            goto cleanup;
        /* Only the PKI provider exposes Ed301 encoders. A key in the normal
         * provider therefore uses OpenSSL's real KEYMGMT export/import bridge. */
    }

    memcpy(seed, test_case->seed, sizeof(seed));
    if (tainted) {
        VALGRIND_MAKE_MEM_UNDEFINED(seed, sizeof(seed));
    } else {
        VALGRIND_MAKE_MEM_DEFINED(seed, sizeof(seed));
    }
    /* GET_VBITS observes shadow state; it does not define the seed. Thus the
     * tainted lane still carries undefined V-bits into EVP key import. */
    if (!vbits_match(seed, sizeof(seed), tainted, "seed")) {
        VALGRIND_MAKE_MEM_DEFINED(seed, sizeof(seed));
        fprintf(stderr, "provider secret-taint activation check failed\n");
        goto cleanup;
    }
    pkey = ed301v2_key_from_seed(libctx, seed);
    if (pkey == NULL) {
        fprintf(stderr, "seed import failed\n");
        goto cleanup;
    }

    ok = EVP_PKEY_get0_provider(pkey) == v2
        && private_exports(pkey, tainted, test_case)
        && (!encode_private
            || private_pkcs8(pkey, tainted, positive_control, test_case))
        && vbits_match(seed, sizeof(seed), tainted, "seed-after-private-export")
        && EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
            public_key, sizeof(public_key), &public_len) == 1
        && public_len == sizeof(public_key)
        && memcmp(public_key, test_case->public_key, sizeof(public_key)) == 0
        && ed301v2_digest_sign(libctx, pkey, test_case->message,
            test_case->message_len, signature)
        && memcmp(signature, test_case->signature, sizeof(signature)) == 0
        && ed301v2_digest_sign(libctx, pkey, test_case->message,
            test_case->message_len, repeated)
        && memcmp(repeated, signature, sizeof(repeated)) == 0;
    VALGRIND_MAKE_MEM_DEFINED(seed, sizeof(seed));
    if (!ok) {
        fprintf(stderr, "taint-path private export, KAT or determinism failure\n");
    }

cleanup:
    OPENSSL_cleanse(seed, sizeof(seed));
    EVP_PKEY_free(pkey);
    OSSL_PROVIDER_unload(encoder_provider);
    OSSL_PROVIDER_unload(v2);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    if (ok)
        printf("provider_secret_taint: mode=%s path=%s private_export=1 pkcs8_der=%d pass=1\n",
            argv[1], path, encode_private);
    return ok ? 0 : 2;
}
