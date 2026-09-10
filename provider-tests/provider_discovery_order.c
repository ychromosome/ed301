/* Missing/late provider discovery is checked before any network operation. */
#include <openssl/ssl.h>
#include "harness_common.h"

int main(void)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *ed = NULL;
    OSSL_PROVIDER *x = NULL;
    SSL_CTX *early = NULL;
    SSL_CTX *fresh = NULL;

    ED301V2_REQUIRE_RUNTIME_BINDING();
    ED301V2_REQUIRE_TLS_RUNTIME_BINDING();
    libctx = OSSL_LIB_CTX_new();
    if (libctx != NULL)
        deflt = curve301_v2_load_checked(libctx, "default");
    if (deflt != NULL)
        early = SSL_CTX_new_ex(libctx, NULL, TLS_client_method());
    ED301V2_CHECK(early != NULL, "default-only private TLS context");
    if (early == NULL)
        goto done;
    ED301V2_CHECK(SSL_CTX_set1_groups_list(early, "X25519") == 1
            && SSL_CTX_set1_sigalgs_list(early, "ed25519") == 1,
        "built-in group and signature configure without custom providers");
    ED301V2_CHECK(SSL_CTX_set1_groups_list(early, "X301MLKEM1024") == 0
            && SSL_CTX_set1_groups_list(early, "X301") == 0,
        "missing X301 provider cannot configure either private-use group");
    ED301V2_CHECK(SSL_CTX_set1_sigalgs_list(early, "Ed301-EdDSA") == 0,
        "missing Ed301 provider cannot configure FE85");
    ed = ed301v2_load_named(libctx, NULL, ED301V2_TLS_PROVIDER);
    x = curve301_v2_load_checked(libctx, "x301_v2_tls_test");
    ED301V2_CHECK(ed != NULL && x != NULL, "both v2 providers load into the same private context");
    if (ed == NULL || x == NULL)
        goto done;
    ED301V2_CHECK(SSL_CTX_set1_groups_list(early, "X301MLKEM1024") == 0
            && SSL_CTX_set1_groups_list(early, "X301") == 0,
        "late X301 load does not repair an already-created SSL_CTX group cache");
    ED301V2_CHECK(SSL_CTX_set1_sigalgs_list(early, "Ed301-EdDSA") == 0,
        "late Ed301 load does not repair an already-created SSL_CTX signature cache");
    fresh = SSL_CTX_new_ex(libctx, NULL, TLS_client_method());
    ED301V2_CHECK(fresh != NULL && SSL_CTX_set1_groups_list(fresh, "X301MLKEM1024") == 1
            && SSL_CTX_set1_sigalgs_list(fresh, "Ed301-EdDSA") == 1,
        "a fresh SSL_CTX after both provider loads admits the exact hybrid/signature policy");
    ED301V2_CHECK(fresh != NULL && SSL_CTX_set1_groups_list(fresh, "X301") == 1,
        "the fresh context separately admits explicit raw test selection");
done:
    SSL_CTX_free(fresh);
    SSL_CTX_free(early);
    OSSL_PROVIDER_unload(x);
    OSSL_PROVIDER_unload(ed);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    ED301V2_CHECK(OSSL_PROVIDER_available(NULL, ED301V2_TLS_PROVIDER) == 0
            && OSSL_PROVIDER_available(NULL, "x301_v2_tls_test") == 0,
        "custom provider discovery never changed the default libctx");
    return ed301v2_summary("provider_discovery_order");
}
