/* N2 observation only: no key/CSR/container frontend and no explicit load.
 * The caller supplies a private run-local OPENSSL_CONF for this process. */
#include "harness_common.h"

struct provider_inventory {
    unsigned int seen;
    int unexpected;
};

static int inspect_provider(OSSL_PROVIDER *provider, void *argument)
{
    struct provider_inventory *inventory = argument;
    const char *name = OSSL_PROVIDER_get0_name(provider);

    if (strcmp(name, "default") == 0)
        inventory->seen |= 1U;
    else if (strcmp(name, "ed301_eddsa_v2_tls") == 0)
        inventory->seen |= 2U;
    else if (strcmp(name, "x301_v2_tls") == 0)
        inventory->seen |= 4U;
    else
        inventory->unexpected = 1;
    return 1;
}

int main(void)
{
    struct provider_inventory inventory = { 0, 0 };
    EVP_KEYMGMT *ed = NULL;
    EVP_KEYMGMT *x = NULL;
    int ok = 0;

    ED301V2_REQUIRE_RUNTIME_BINDING();
    if (getenv("OPENSSL_TEST_LIBCTX") != NULL) {
        fputs("DEFAULT_CONTEXT_TEST_LIBCTX_FORBIDDEN\n", stderr);
        return 2;
    }
    if (OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL) != 1
            || OSSL_PROVIDER_do_all(NULL, inspect_provider, &inventory) != 1
            || inventory.seen != 7U || inventory.unexpected) {
        fputs("DEFAULT_CONTEXT_PROVIDERS_MISSING_OR_UNEXPECTED\n", stderr);
        return 1;
    }
    ed = EVP_KEYMGMT_fetch(NULL, "Ed301-EdDSA", NULL);
    x = EVP_KEYMGMT_fetch(NULL, "X301", NULL);
    ok = ed != NULL && x != NULL
        && strcmp(OSSL_PROVIDER_get0_name(EVP_KEYMGMT_get0_provider(ed)),
            "ed301_eddsa_v2_tls") == 0
        && strcmp(OSSL_PROVIDER_get0_name(EVP_KEYMGMT_get0_provider(x)),
            "x301_v2_tls") == 0;
    EVP_KEYMGMT_free(ed);
    EVP_KEYMGMT_free(x);
    if (ok)
        puts("DEFAULT_CONTEXT_V2=PASS providers=default,ed301_eddsa_v2_tls,x301_v2_tls explicit_loads=0");
    return ok ? 0 : 1;
}
