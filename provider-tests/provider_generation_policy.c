/* G02 integration policy. Never deliberately co-load both generations.
 * Optional argv[1] is a separately bound directory containing real v1
 * ordinary modules; that lane proves v1-first rejection before a v2 load.
 */
#include "harness_common.h"

static const OSSL_DISPATCH empty_dispatch[] = { { 0, NULL } };

static int sentinel_init(const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *input, const OSSL_DISPATCH **output, void **context)
{
    (void)handle;
    (void)input;
    *output = empty_dispatch;
    *context = NULL;
    return 1;
}

int main(int argc, char **argv)
{
    static const char *const rejected_names[] = {
        "ed301_eddsa_v1", "ed301_eddsa_v1_pki_test",
        "ed301_eddsa_v1_tls_test", "ed301_eddsa_v1_tls_collider",
        "ed301_eddsa_v1_failpoint", "ed301", "x301", "x301_failpoint",
        "x301_tls_test", "ed301_eddsa_v2.so", "x301_v2.so",
        "ed301_eddsa_v2_tls_test", "x301_v2_tls_test",
        "./ed301_eddsa_v2", "/tmp/ed301_eddsa_v2", "unbound-provider"
    };
    OSSL_LIB_CTX *libctx;
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *v2 = NULL;
    OSSL_PROVIDER *sentinel = NULL;

    ED301V2_REQUIRE_RUNTIME_BINDING();
    if (argc > 2)
        return 2;
    ED301V2_CHECK(curve301_v2_load_checked(NULL, ED301V2_PROVIDER) == NULL,
        "checked loader rejects the default libctx");
    libctx = OSSL_LIB_CTX_new();
    v2 = ed301v2_load(libctx, &deflt);
    ED301V2_CHECK(v2 != NULL && curve301_v2_generation_policy_ok(libctx),
        "checked ordinary v2 load succeeds in a private v2-only context");
    if (v2 != NULL) {
        for (size_t i = 0; i < sizeof(rejected_names) / sizeof(rejected_names[0]); i++) {
            OSSL_PROVIDER *rejected;

            ed301v2_seed_error_sentinel();
            rejected = curve301_v2_load_checked(libctx, rejected_names[i]);
            ED301V2_CHECK(rejected == NULL && ed301v2_queue_is_sentinel_only()
                    && OSSL_PROVIDER_available(libctx, rejected_names[i]) == 0,
                "v2-first rejects legacy/unbound module without attempting a load: %s",
                rejected_names[i]);
            OSSL_PROVIDER_unload(rejected);
        }
    }
    OSSL_PROVIDER_unload(v2);
    OSSL_PROVIDER_unload(deflt);
    deflt = NULL;
    OSSL_LIB_CTX_free(libctx);

    /* Unknown preloaded modules are not silently assumed to be v2-safe.
     * This sentinel has no algorithms and is not a legacy cryptosystem. */
    libctx = OSSL_LIB_CTX_new();
    if (libctx != NULL && OSSL_PROVIDER_add_builtin(libctx,
            "unbound-provider", sentinel_init) == 1)
        sentinel = OSSL_PROVIDER_load(libctx, "unbound-provider");
    v2 = curve301_v2_load_checked(libctx, ED301V2_PROVIDER);
    ED301V2_CHECK(sentinel != NULL && v2 == NULL
            && OSSL_PROVIDER_available(libctx, ED301V2_PROVIDER) == 0,
        "unknown-module-first blocks v2 before loading it");
    OSSL_PROVIDER_unload(v2);
    OSSL_PROVIDER_unload(sentinel);
    OSSL_LIB_CTX_free(libctx);

    if (argc == 2) {
        const char *const legacy[] = { "ed301_eddsa_v1", "x301" };
        const char *const algorithm[] = { "Ed301-EdDSA-v1", "X301" };
        const char *const properties[] = { "provider=ed301_eddsa_v1", "provider=x301" };

        for (size_t i = 0; i < 2; i++) {
            OSSL_PROVIDER *old = NULL;
            EVP_KEYMGMT *keymgmt = NULL;

            libctx = OSSL_LIB_CTX_new();
            if (libctx != NULL && OSSL_PROVIDER_set_default_search_path(libctx, argv[1]) == 1) {
                deflt = OSSL_PROVIDER_load(libctx, "default");
                old = OSSL_PROVIDER_load(libctx, legacy[i]);
                keymgmt = EVP_KEYMGMT_fetch(libctx, algorithm[i], properties[i]);
            }
            v2 = curve301_v2_load_checked(libctx, ED301V2_PROVIDER);
            ED301V2_CHECK(old != NULL && keymgmt != NULL && v2 == NULL
                    && !curve301_v2_generation_policy_ok(libctx)
                    && OSSL_PROVIDER_available(libctx, ED301V2_PROVIDER) == 0,
                "actual %s-first blocks a later v2 load", legacy[i]);
            EVP_KEYMGMT_free(keymgmt);
            OSSL_PROVIDER_unload(v2);
            OSSL_PROVIDER_unload(old);
            OSSL_PROVIDER_unload(deflt);
            deflt = NULL;
            OSSL_LIB_CTX_free(libctx);
        }
    } else {
        printf("actual-v1-first lane: NOT RUN (requires bound v1 module directory)\n");
    }
    ED301V2_CHECK(OSSL_PROVIDER_available(NULL, ED301V2_PROVIDER) == 0,
        "ordinary v2 provider absent from the default libctx");
    return ed301v2_summary("provider_generation_policy");
}
