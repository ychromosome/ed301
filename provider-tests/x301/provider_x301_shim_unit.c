/* ABI-table and inherited core-version admission tests, without loading a DSO. */
#include "../harness_common.h"
#include "../../provider/crates/x301-provider/c/provider_shim.c"

static const char *version_text;
static int core_params_result = 1;

static void dummy(void) {}

static int core_params(const OSSL_CORE_HANDLE *handle, OSSL_PARAM params[])
{
    OSSL_PARAM *parameter = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_CORE_VERSION);

    (void)handle;
    return core_params_result && parameter != NULL
        && OSSL_PARAM_set_utf8_ptr(parameter, version_text) == 1;
}

#define CHECK_CALLBACK(field) do { \
    X301_RUST_API broken = api; \
    broken.field = NULL; \
    ED301V2_CHECK(!x301_rust_api_is_valid(&broken), "missing X301 callback: %s", #field); \
} while (0)

int main(void)
{
    X301_RUST_API api = { 0 };
    X301_RUST_API broken;
    const OSSL_CORE_HANDLE *handle = (const OSSL_CORE_HANDLE *)&api;

    ED301V2_REQUIRE_RUNTIME_BINDING();
    api.abi_version = 1;
    api.struct_size = sizeof(api);
    api.secret_bytes = api.public_bytes = api.shared_bytes = 38;
#define ASSIGN(field) api.field = (__typeof__(api.field))dummy
    ASSIGN(key_new); ASSIGN(key_free); ASSIGN(key_import); ASSIGN(key_set_encoded_public);
    ASSIGN(key_generate); ASSIGN(key_duplicate); ASSIGN(key_has); ASSIGN(key_validate);
    ASSIGN(key_match); ASSIGN(key_get_private); ASSIGN(key_get_public);
    ASSIGN(exchange_new); ASSIGN(exchange_free); ASSIGN(exchange_duplicate);
    ASSIGN(exchange_init); ASSIGN(exchange_set_peer); ASSIGN(exchange_derive); ASSIGN(cleanse);
#undef ASSIGN
    ED301V2_CHECK(x301_rust_api_is_valid(&api), "complete X301 ABI accepted");
    ED301V2_CHECK(!x301_rust_api_is_valid(NULL), "NULL X301 ABI rejected");
    broken = api; broken.abi_version++;
    ED301V2_CHECK(!x301_rust_api_is_valid(&broken), "wrong X301 ABI version rejected");
    broken = api; broken.struct_size--;
    ED301V2_CHECK(!x301_rust_api_is_valid(&broken), "wrong X301 ABI table size rejected");
    broken = api; broken.secret_bytes--;
    ED301V2_CHECK(!x301_rust_api_is_valid(&broken), "wrong X301 secret width rejected");
    broken = api; broken.public_bytes--;
    ED301V2_CHECK(!x301_rust_api_is_valid(&broken), "wrong X301 public width rejected");
    broken = api; broken.shared_bytes--;
    ED301V2_CHECK(!x301_rust_api_is_valid(&broken), "wrong X301 shared width rejected");
    CHECK_CALLBACK(key_new); CHECK_CALLBACK(key_free); CHECK_CALLBACK(key_import);
    CHECK_CALLBACK(key_set_encoded_public); CHECK_CALLBACK(key_generate); CHECK_CALLBACK(key_duplicate);
    CHECK_CALLBACK(key_has); CHECK_CALLBACK(key_validate); CHECK_CALLBACK(key_match);
    CHECK_CALLBACK(key_get_private); CHECK_CALLBACK(key_get_public);
    CHECK_CALLBACK(exchange_new); CHECK_CALLBACK(exchange_free); CHECK_CALLBACK(exchange_duplicate);
    CHECK_CALLBACK(exchange_init); CHECK_CALLBACK(exchange_set_peer); CHECK_CALLBACK(exchange_derive); CHECK_CALLBACK(cleanse);

    version_text = OPENSSL_VERSION_MAJOR == 3 ? "3.5.8" : "4.0.2";
    ED301V2_CHECK(x301_core_version_is_supported(handle, core_params), "matching current core version accepted");
    ED301V2_CHECK(!x301_core_version_is_supported(NULL, core_params)
            && !x301_core_version_is_supported(handle, NULL), "missing core upcall inputs rejected");
    core_params_result = 0;
    ED301V2_CHECK(!x301_core_version_is_supported(handle, core_params), "failed core get_params rejected");
    core_params_result = 1;
    for (size_t i = 0; i < 5; i++) {
        const char *const invalid[] = { "", "invalid", "3", "3.x", "42949672960.5.8" };

        version_text = invalid[i];
        ED301V2_CHECK(!x301_core_version_is_supported(handle, core_params), "malformed core major/minor rejected: %s", version_text);
    }
    version_text = OPENSSL_VERSION_MAJOR == 3 ? "4.0.2" : "3.5.8";
    ED301V2_CHECK(!x301_core_version_is_supported(handle, core_params), "different OpenSSL ABI major rejected");
#if OPENSSL_VERSION_MAJOR == 3
    version_text = "3.4.9";
# if defined(X301_ENABLE_HYBRID_MLKEM1024)
    ED301V2_CHECK(!x301_core_version_is_supported(handle, core_params), "hybrid rejects pre-3.5 core");
# else
    ED301V2_CHECK(x301_core_version_is_supported(handle, core_params), "ordinary raw adapter retains its inherited major-3 admission rule");
# endif
#endif
    return ed301v2_summary("provider_x301_shim_unit");
}
