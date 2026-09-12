#ifndef CURVE301_V2_GENERATION_POLICY_H
#define CURVE301_V2_GENERATION_POLICY_H

#include <openssl/provider.h>
#include <string.h>

/* Closed module set for the owned D2 integration contexts. The caller must
 * serialize ALL loads/unloads while configuring a context, and bind these
 * names to its verified module directory before using this helper.
 * This is application policy, not an OpenSSL-wide provider-load interposer.
 * Direct OSSL_PROVIDER_load() calls and renamed/unverified modules are outside
 * this boundary. In particular v2 cannot make an unchanged v1 DSO enforce
 * a ban on a later load initiated by unrelated application code.
 */
static inline int curve301_v2_module_allowed(const char *name)
{
    static const char *const allowed[] = {
        "default", "base", "null",
        "ed301_eddsa_v2", "ed301_eddsa_v2_pki_test",
        "ed301_eddsa_v2_tls", "ed301_eddsa_v2_tls_collider",
        "ed301_eddsa_v2_failpoint",
        "x301_v2", "x301_v2_pki_test", "x301_v2_tls",
        "x301_v2_failpoint",
        /* Builtin deterministic providers exist only in these testbinaries. */
        "ed301_test_rand", "x301_test_rand"
    };

    if (name == NULL)
        return 0;
    for (size_t i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++)
        if (strcmp(name, allowed[i]) == 0)
            return 1;
    return 0;
}

static int curve301_v2_check_loaded(OSSL_PROVIDER *provider, void *arg)
{
    int *allowed = arg;

    if (!curve301_v2_module_allowed(OSSL_PROVIDER_get0_name(provider)))
        *allowed = 0;
    return 1;
}

static inline int curve301_v2_generation_policy_ok(OSSL_LIB_CTX *libctx)
{
    int allowed = 1;

    return libctx != NULL
        && OSSL_PROVIDER_do_all(libctx, curve301_v2_check_loaded, &allowed) == 1
        && allowed;
}

static inline OSSL_PROVIDER *curve301_v2_load_checked(
    OSSL_LIB_CTX *libctx, const char *name)
{
    if (!curve301_v2_module_allowed(name)
            || !curve301_v2_generation_policy_ok(libctx))
        return NULL;
    return OSSL_PROVIDER_load(libctx, name);
}

#endif
