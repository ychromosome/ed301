/*
 * Ed301-EdDSA-v2 OpenSSL provider. Raw signatures and key management are
 * always present; separately built variants add codecs and private-use TLS.
 * The generated profile header defines the v2 identity.
 */

#include <stdarg.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/provider.h>
#include <openssl/rand.h>

/*
 * One artifact per ABI major.  The provider uses message-signature dispatches
 * that are absent from early OpenSSL 3 releases, so ABI-major compatibility
 * starts at the oldest source and runtime lane exercised by this project.
 */
#if OPENSSL_VERSION_MAJOR == 3
# if OPENSSL_VERSION_MINOR < 5 \
     || (OPENSSL_VERSION_MINOR == 5 && OPENSSL_VERSION_PATCH < 7)
#  error "The Ed301 provider requires OpenSSL 3.5.7 or later headers"
# else
#  define ED301_SUPPORTED_HEADERS 1
#  define ED301V2_SUPPORTED_CORE_MAJOR 3U
#  define ED301V2_MINIMUM_CORE_MINOR 5U
#  define ED301V2_MINIMUM_CORE_PATCH 7U
# endif
#elif OPENSSL_VERSION_MAJOR == 4
# if OPENSSL_VERSION_MINOR == 0 && OPENSSL_VERSION_PATCH < 1
#  error "The Ed301 provider requires OpenSSL 4.0.1 or later headers"
# else
#  define ED301_SUPPORTED_HEADERS 1
#  define ED301V2_SUPPORTED_CORE_MAJOR 4U
#  define ED301V2_MINIMUM_CORE_MINOR 0U
#  define ED301V2_MINIMUM_CORE_PATCH 1U
# endif
#else
#error "The Ed301 provider requires OpenSSL ABI major 3 or 4 headers"
#endif

#ifdef ED301_SUPPORTED_HEADERS

#include "param_helpers.h"
#include "provider_internal.h"

#define ED301V2_SEED_BYTES ((size_t)38)
#define ED301V2_PUBLIC_KEY_BYTES ((size_t)38)
#define ED301V2_SIGNATURE_BYTES ((size_t)76)
#define ED301V2_MAX_CONTEXT_BYTES ((size_t)255)
#define ED301V2_PKCS8_SALT_BYTES ((size_t)16)
#define ED301V2_BITS 301
#define ED301V2_SECURITY_BITS 149
#define ED301V2_TLS_VERSION_1_3 0x0304

/*
 * The TLS variant verifies the process OID/SIGID after registration.
 * Its private-use SignatureScheme is distinct from historical generations.
 */
#include "../../../common/generated_ed301_profile.h"

#define CURVE301_PROVIDER_CONTEXT ED301V2_PROVIDER_CONTEXT
#define CURVE301_KEY ED301V2_KEY
#define CURVE301_SECURITY_BITS ED301V2_SECURITY_BITS
#define CURVE301_SEED_BYTES ED301V2_SEED_BYTES
#define CURVE301_PUBLIC_KEY_BYTES ED301V2_PUBLIC_KEY_BYTES
#define CURVE301_PKCS8_SALT_BYTES ((size_t)16)
#define CURVE301_DISPLAY_NAME "Ed301-EdDSA"
#define CURVE301_HAS_TEST_DECODER ED301V2_HAS_TEST_DECODER
#define CURVE301_HAS_PRIVATE_KEY_DECODER ED301V2_HAS_PRIVATE_KEY_DECODER
#define CURVE301_HAS_TEXT_ENCODER ED301V2_HAS_TEXT_ENCODER
#define CURVE301_ALGORITHM_NAME ED301V2_ALGORITHM_NAME
#define CURVE301_ALGORITHM_NAMES ED301V2_ALGORITHM_NAMES
#define CURVE301_OPERATION_ALGORITHM_NAMES ED301V2_OPERATION_ALGORITHM_NAMES
#define CURVE301_DECODER_ALGORITHM_NAMES ED301V2_DECODER_ALGORITHM_NAMES
#define CURVE301_PROVIDER_BASENAME ED301V2_PROVIDER_BASENAME
#define CURVE301_PKCS8_PREFIX ED301V2_PKCS8_PREFIX
#define CURVE301_SPKI_PREFIX ED301V2_SPKI_PREFIX
#define CURVE301_OID_TLV_BYTES ED301V2_OID_TLV_BYTES
#define CURVE301_MAX_ENCODED_KEY_BYTES ED301V2_MAX_ENCODED_KEY_BYTES
#define CURVE301_R_ALLOCATION_FAILURE ED301V2_R_ALLOCATION_FAILURE
#define CURVE301_R_SERIALIZATION_FAILURE ED301V2_R_SERIALIZATION_FAILURE
#define curve301_allocate ed301v2_allocate
#define curve301_clear_free ed301v2_clear_free
#define curve301_raise ed301v2_raise
#define curve301_selection_supported ed301v2_selection_supported
#define curve301_wants_private ed301v2_wants_private
#define curve301_wants_public ed301v2_wants_public
#define curve301_key_new ed301v2_key_new
#define curve301_key_free ed301v2_key_free
#define curve301_key_import ed301v2_key_import
#define curve301_key_export ed301v2_key_export


/*
 * Each diagnostic/private-use surface has a separate module name and
 * "provider=" property.  The ordinary module exposes no TLS capability.
 */
#ifdef ED301V2_TEST_FAILPOINT_ARTIFACT
# define ED301V2_PROVIDER_BASENAME "ed301_eddsa_v2_failpoint"
#elif defined(ED301V2_TLS_EXPERIMENT_ARTIFACT)
# define ED301V2_PROVIDER_BASENAME "ed301_eddsa_v2_tls"
#elif defined(ED301V2_TLS_COLLIDER_ARTIFACT)
# define ED301V2_PROVIDER_BASENAME "ed301_eddsa_v2_tls_collider"
#elif defined(ED301V2_PKI_EXPERIMENT_ARTIFACT)
# define ED301V2_PROVIDER_BASENAME "ed301_eddsa_v2_pki_test"
#else
# define ED301V2_PROVIDER_BASENAME "ed301_eddsa_v2"
#endif

#ifdef ED301V2_PKI_EXPERIMENT_ARTIFACT
# define ED301V2_HAS_TEST_PKI_INTEGRATION 1
#else
# define ED301V2_HAS_TEST_PKI_INTEGRATION 0
#endif

#if defined(ED301V2_TLS_EXPERIMENT_ARTIFACT) \
    || defined(ED301V2_TLS_COLLIDER_ARTIFACT)
# define ED301V2_HAS_TEST_TLS_CAPABILITY 1
# define ED301V2_HAS_TEST_DECODER 1
#else
# define ED301V2_HAS_TEST_TLS_CAPABILITY 0
# define ED301V2_HAS_TEST_DECODER 0
#endif

#ifdef ED301V2_TLS_EXPERIMENT_ARTIFACT
# define ED301V2_HAS_PRIVATE_KEY_DECODER 1
# define ED301V2_HAS_TEXT_ENCODER 1
#else
# define ED301V2_HAS_PRIVATE_KEY_DECODER 0
# define ED301V2_HAS_TEXT_ENCODER 0
#endif

static const char ED301V2_PROVIDER_NAME[] =
    "Ed301-EdDSA v2 Provider";
static const char ED301V2_PROVIDER_VERSION[] = "0.2.0";
static const char ED301V2_PROVIDER_BUILDINFO[] =
    ED301V2_PROVIDER_BASENAME "; headers: " OPENSSL_VERSION_TEXT;
static const char ED301V2_ALGORITHM_NAME[] = "Ed301-EdDSA";
static const char ED301V2_ALGORITHM_NAMES[] = "Ed301-EdDSA:Ed301-EdDSA-v2";
#define ED301V2_DECODER_ALGORITHM_NAMES \
    "Ed301-EdDSA:Ed301-EdDSA-v2:" ED301V2_OID_TEXT
#ifdef ED301V2_TLS_EXPERIMENT_ARTIFACT
# define ED301V2_OPERATION_ALGORITHM_NAMES \
    ED301V2_DECODER_ALGORITHM_NAMES
# define ED301V2_REGISTER_PROCESS_OID 1
#else
# define ED301V2_OPERATION_ALGORITHM_NAMES ED301V2_ALGORITHM_NAMES
# define ED301V2_REGISTER_PROCESS_OID 0
#endif
static const char ED301V2_PROPERTY[] =
    "provider=" ED301V2_PROVIDER_BASENAME;

#if ED301V2_REGISTER_PROCESS_OID
static int ed301v2_process_identity_is_exact(void)
{
    char numeric_oid[96];
    const int oid_nid = OBJ_txt2nid(ED301V2_OID_TEXT);
    const ASN1_OBJECT *object;
    const char *short_name;
    const char *long_name;
    int candidate_nid;
    int digest_nid = NID_undef;
    int found = 0;
    int next_nid;
    int public_key_nid = NID_undef;
    int signature_nid = NID_undef;

    if (oid_nid == NID_undef
            || OBJ_sn2nid(ED301V2_ALGORITHM_NAME) != oid_nid
            || OBJ_ln2nid(ED301V2_ALGORITHM_NAME) != oid_nid)
        return 0;
    object = OBJ_nid2obj(oid_nid);
    short_name = OBJ_nid2sn(oid_nid);
    long_name = OBJ_nid2ln(oid_nid);
    if (object == NULL || short_name == NULL || long_name == NULL
            || strcmp(short_name, ED301V2_ALGORITHM_NAME) != 0
            || strcmp(long_name, ED301V2_ALGORITHM_NAME) != 0
            || OBJ_obj2txt(numeric_oid, sizeof(numeric_oid), object, 1)
                != (int)strlen(ED301V2_OID_TEXT)
            || strcmp(numeric_oid, ED301V2_OID_TEXT) != 0)
        return 0;

    next_nid = OBJ_new_nid(0);
    if (next_nid == NID_undef)
        return 0;
    for (candidate_nid = 1; candidate_nid < next_nid; candidate_nid++) {
        if (OBJ_find_sigid_algs(
                candidate_nid, &digest_nid, &public_key_nid) != 1)
            continue;
        if (candidate_nid != oid_nid && digest_nid != oid_nid
                && public_key_nid != oid_nid)
            continue;
        if (candidate_nid != oid_nid || digest_nid != NID_undef
                || public_key_nid != oid_nid || found)
            return 0;
        found = 1;
    }
    return found
        && OBJ_find_sigid_by_algs(
               &signature_nid, NID_undef, oid_nid) == 1
        && signature_nid == oid_nid;
}
#endif

#if ED301V2_HAS_TEST_TLS_CAPABILITY
static const char ED301V2_OID[] = ED301V2_OID_TEXT;
static const char ED301V2_TLS_SIGALG_CAPABILITY[] = "TLS-SIGALG";
static const char ED301V2_TLS_SIGALG_IANA_NAME[] =
    "ed301_eddsa_v2";
#endif

_Static_assert(
    sizeof(ED301V2_ALGORITHM_ID_DER) == 15,
    "v2 AlgorithmIdentifier must be exactly 15 bytes");
_Static_assert(
    sizeof(ED301V2_SPKI_PREFIX) + ED301V2_PUBLIC_KEY_BYTES == 58,
    "v2 SPKI must be exactly 58 bytes");
_Static_assert(
    sizeof(ED301V2_PKCS8_PREFIX) + ED301V2_SEED_BYTES
        == ED301V2_MAX_ENCODED_KEY_BYTES,
    "v2 PKCS#8 must be exactly 62 bytes");

typedef struct ed301v2_key_st {
    ED301V2_PROVIDER_CONTEXT *provider;
    void *inner;
} ED301V2_KEY;

typedef struct ed301v2_gen_context_st {
    ED301V2_PROVIDER_CONTEXT *provider;
} ED301V2_GEN_CONTEXT;

typedef struct ed301v2_signature_context_st {
    ED301V2_PROVIDER_CONTEXT *provider;
    void *inner;
} ED301V2_SIGNATURE_CONTEXT;

enum {
    ED301V2_R_INVALID_KEY = 1,
    ED301V2_R_INVALID_STATE = 2,
    ED301V2_R_INVALID_PARAMETER = 3,
    ED301V2_R_ALLOCATION_FAILURE = 4,
    /* Reason 5 was the removed object-registration failure. */
    ED301V2_R_SERIALIZATION_FAILURE = 6,
    ED301V2_R_UNSUPPORTED_MODE = 7
};

/* Static reason descriptions copied by a successfully initialized core. */
static const OSSL_ITEM ED301V2_REASON_STRINGS[] = {
    { ED301V2_R_INVALID_KEY, "invalid key" },
    { ED301V2_R_INVALID_STATE, "invalid state" },
    { ED301V2_R_INVALID_PARAMETER, "invalid parameter" },
    { ED301V2_R_ALLOCATION_FAILURE, "allocation failure" },
    { ED301V2_R_SERIALIZATION_FAILURE, "serialization failure" },
    { ED301V2_R_UNSUPPORTED_MODE, "unsupported mode" },
    { 0, NULL }
};

static const OSSL_PARAM ED301V2_PROVIDER_GETTABLE_PARAMS[] = {
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, NULL, 0),
    OSSL_PARAM_int(OSSL_PROV_PARAM_STATUS, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM ED301V2_KEY_GETTABLE_PARAMS[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM ED301V2_PRIVATE_TYPES[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM ED301V2_PUBLIC_TYPES[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM ED301V2_KEYPAIR_TYPES[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM ED301V2_SETTABLE_KEY_PARAMS[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END
};

/*
 * Ed301-EdDSA-v2 accepts one opaque native context and defines no digest,
 * prehash, streaming or randomized signing mode. Recognized requests for those
 * modes are rejected; unknown keys are ignored as recommended by OSSL_PARAM(3).
 * The transport-metadata exception
 * is the TLS version on the OpenSSL 4.0 lane: its libssl announces it to
 * the signature provider as a signed int constructed with
 * OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_TLS_VERSION, &s->version),
 * and only that exact form carrying TLS 1.3 is tolerated.  The 3.5 lane
 * sends no such parameter, advertises nothing and keeps rejecting it.
 */
#if OPENSSL_VERSION_MAJOR == 4
# define ED301V2_ACCEPT_TLS_VERSION_PARAM 1
#else
# define ED301V2_ACCEPT_TLS_VERSION_PARAM 0
#endif

static const OSSL_PARAM ED301V2_SETTABLE_CTX_PARAMS[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
#if ED301V2_ACCEPT_TLS_VERSION_PARAM
    OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_TLS_VERSION, NULL),
#endif
    OSSL_PARAM_END
};

static const OSSL_PARAM ED301V2_GETTABLE_CTX_PARAMS[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
    OSSL_PARAM_END
};

static int ed301v2_selection_supported(int selection)
{
    return (selection & ~OSSL_KEYMGMT_SELECT_ALL) == 0;
}

static int ed301v2_wants_private(int selection)
{
    return (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
}

static int ed301v2_wants_public(int selection)
{
    return (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
}

static void ed301v2_raise_at(
    ED301V2_PROVIDER_CONTEXT *provider,
    uint32_t reason,
    const char *file,
    int line,
    const char *function,
    const char *format,
    ...)
{
    va_list arguments;

    if (provider == NULL || provider->new_error == NULL
            || provider->set_error_debug == NULL
            || provider->vset_error == NULL)
        return;

    provider->new_error(provider->handle);
    provider->set_error_debug(provider->handle, file, line, function);
    va_start(arguments, format);
    provider->vset_error(provider->handle, reason, format, arguments);
    va_end(arguments);
}

#define ed301v2_raise(provider, reason, ...) \
    ed301v2_raise_at((provider), (reason), __FILE__, __LINE__, __func__, \
        __VA_ARGS__)

static void *ed301v2_allocate(
    ED301V2_PROVIDER_CONTEXT *provider,
    size_t size)
{
    if (provider == NULL || provider->zalloc == NULL)
        return NULL;
    return provider->zalloc(size, __FILE__, __LINE__);
}

static void ed301v2_clear_free(
    ED301V2_PROVIDER_CONTEXT *provider,
    void *pointer,
    size_t size)
{
    if (provider != NULL && provider->clear_free != NULL && pointer != NULL)
        provider->clear_free(pointer, size, __FILE__, __LINE__);
}

static void *ed301v2_key_load(const void *reference, size_t reference_size)
{
    void **mutable_reference;
    void *key;

    if (reference == NULL || reference_size != sizeof(key))
        return NULL;

    mutable_reference = (void **)reference;
    key = *mutable_reference;
    *mutable_reference = NULL;
    return key;
}

/* ------------------------------------------------------------------ */
/* Key management                                                     */
/* ------------------------------------------------------------------ */

static ED301V2_KEY *ed301v2_wrap_key(
    ED301V2_PROVIDER_CONTEXT *provider,
    void *inner)
{
    ED301V2_KEY *key;

    if (provider == NULL || inner == NULL)
        return NULL;
    key = ed301v2_allocate(provider, sizeof(*key));
    if (key == NULL) {
        provider->rust->key_free(inner);
        ed301v2_raise(provider, ED301V2_R_ALLOCATION_FAILURE,
            "Ed301-EdDSA-v2 key allocation failed");
        return NULL;
    }

    key->provider = provider;
    key->inner = inner;
    return key;
}

static void *ed301v2_key_new(void *provider_context)
{
    ED301V2_PROVIDER_CONTEXT *provider = provider_context;
    void *inner;

    if (provider == NULL || provider->rust == NULL)
        return NULL;
    inner = provider->rust->key_new();
    if (inner == NULL) {
        ed301v2_raise(provider, ED301V2_R_ALLOCATION_FAILURE,
            "Ed301-EdDSA-v2 key allocation failed");
        return NULL;
    }
    return ed301v2_wrap_key(provider, inner);
}

static void ed301v2_key_free(void *key_data)
{
    ED301V2_KEY *key = key_data;
    ED301V2_PROVIDER_CONTEXT *provider;

    if (key == NULL)
        return;
    provider = key->provider;
    if (provider != NULL && provider->rust != NULL && key->inner != NULL)
        provider->rust->key_free(key->inner);
    ed301v2_clear_free(provider, key, sizeof(*key));
}

static int ed301v2_key_import(
    void *key_data,
    int selection,
    const OSSL_PARAM params[])
{
    ED301V2_KEY *key = key_data;
    const unsigned char *private_key = NULL;
    const unsigned char *public_key = NULL;
    size_t private_length = 0;
    size_t public_length = 0;
    const int wants_private = ed301v2_wants_private(selection);
    const int wants_public = ed301v2_wants_public(selection);

    if (key == NULL || key->provider == NULL || key->inner == NULL)
        return 0;
    if (params == NULL || !ed301v2_selection_supported(selection)
            || (!wants_private && !wants_public))
        goto invalid;

    if (wants_private && !ed301v2_param_get_strict_octet_string(
            params,
            OSSL_PKEY_PARAM_PRIV_KEY,
            &private_key,
            &private_length,
            ED301V2_SEED_BYTES,
            wants_private && !wants_public))
        goto invalid;

    if (wants_public && !ed301v2_param_get_strict_octet_string(
            params,
            OSSL_PKEY_PARAM_PUB_KEY,
            &public_key,
            &public_length,
            ED301V2_PUBLIC_KEY_BYTES,
            wants_public && !wants_private))
        goto invalid;

    /*
     * Selection contract (see the disclosed historical import-selection
     * correction, independently re-reviewed for this experiment): a
     * private-only selection requires a seed and a public-only selection
     * requires a public key.  A keypair selection accepts either component:
     * OpenSSL's EVP_PKEY_new_raw_public_key_ex() deliberately imports a
     * public-only raw key with OSSL_KEYMGMT_SELECT_KEYPAIR, as do the built-in
     * Ed25519/Ed448 key managers.  Whenever a seed is present its derived
     * public key must still match any supplied encoding.
     */
    if ((private_key == NULL && public_key == NULL)
            || (wants_private && !wants_public && private_key == NULL)
            || (wants_public && !wants_private && public_key == NULL))
        goto invalid;

    if (key->provider->rust->key_import(
            key->inner,
            wants_private ? private_key : NULL,
            wants_private ? private_length : 0,
            wants_public ? public_key : NULL,
            wants_public ? public_length : 0) != 1)
        goto invalid;

    return 1;

invalid:
    ed301v2_raise(key->provider, ED301V2_R_INVALID_KEY,
        "invalid Ed301-EdDSA-v2 key material");
    return 0;
}

static const OSSL_PARAM *ed301v2_key_import_types(int selection)
{
    const int wants_private = ed301v2_wants_private(selection);
    const int wants_public = ed301v2_wants_public(selection);

    if (!ed301v2_selection_supported(selection))
        return NULL;
    if (wants_private && wants_public)
        return ED301V2_KEYPAIR_TYPES;
    if (wants_private)
        return ED301V2_PRIVATE_TYPES;
    if (wants_public)
        return ED301V2_PUBLIC_TYPES;
    return NULL;
}

static int ed301v2_key_export(
    void *key_data,
    int selection,
    OSSL_CALLBACK *parameter_callback,
    void *callback_argument)
{
    ED301V2_KEY *key = key_data;
    unsigned char private_key[ED301V2_SEED_BYTES] = { 0 };
    unsigned char public_key[ED301V2_PUBLIC_KEY_BYTES] = { 0 };
    OSSL_PARAM export_params[3];
    size_t parameter_count = 0;
    int result = 0;
    const int wants_private = ed301v2_wants_private(selection);
    const int wants_public = ed301v2_wants_public(selection);
    int has_private;
    int has_public;

    if (key == NULL || key->provider == NULL || key->inner == NULL
            || parameter_callback == NULL
            || !ed301v2_selection_supported(selection)
            || (!wants_private && !wants_public))
        goto cleanup;

    has_private = key->provider->rust->key_has(key->inner, 1, 0) == 1;
    has_public = key->provider->rust->key_has(key->inner, 0, 1) == 1;

    if (wants_private && has_private) {
        if (key->provider->rust->key_get_private(
                key->inner,
                private_key,
                sizeof(private_key)) != 1)
            goto cleanup;
        export_params[parameter_count++] = (OSSL_PARAM)
            OSSL_PARAM_octet_string(
                OSSL_PKEY_PARAM_PRIV_KEY,
                private_key,
                sizeof(private_key));
    }
    if (wants_public && has_public) {
        if (key->provider->rust->key_get_public(
                key->inner,
                public_key,
                sizeof(public_key)) != 1)
            goto cleanup;
        export_params[parameter_count++] = (OSSL_PARAM)
            OSSL_PARAM_octet_string(
                OSSL_PKEY_PARAM_PUB_KEY,
                public_key,
                sizeof(public_key));
    }
    if (parameter_count == 0)
        goto cleanup;
    export_params[parameter_count] = (OSSL_PARAM)OSSL_PARAM_END;
    result = parameter_callback(export_params, callback_argument);

cleanup:
    if (key != NULL && key->provider != NULL && key->provider->rust != NULL)
        key->provider->rust->cleanse(private_key, sizeof(private_key));
    if (result != 1 && key != NULL)
        ed301v2_raise(key->provider, ED301V2_R_INVALID_KEY,
            "Ed301-EdDSA-v2 key export failed");
    return result == 1 ? 1 : 0;
}

static const OSSL_PARAM *ed301v2_key_export_types(int selection)
{
    return ed301v2_key_import_types(selection);
}

static const OSSL_PARAM *ed301v2_key_gettable_params(void *provider_context)
{
    (void)provider_context;
    return ED301V2_KEY_GETTABLE_PARAMS;
}

static int ed301v2_key_get_params(void *key_data, OSSL_PARAM params[])
{
    ED301V2_KEY *key = key_data;
    OSSL_PARAM *public_param;
    OSSL_PARAM *encoded_public_param;
    OSSL_PARAM *private_param;
    unsigned char private_key[ED301V2_SEED_BYTES] = { 0 };
    unsigned char public_key[ED301V2_PUBLIC_KEY_BYTES] = { 0 };
    int result = 0;

    if (key == NULL || key->provider == NULL || key->provider->rust == NULL
            || key->inner == NULL || params == NULL)
        goto cleanup;

    if (!ed301v2_param_set_optional_int(
            OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS),
            ED301V2_BITS)
            || !ed301v2_param_set_optional_int(
                OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS),
                ED301V2_SECURITY_BITS)
            || !ed301v2_param_set_optional_int(
                OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE),
                (int)ED301V2_SIGNATURE_BYTES)
            || !ed301v2_param_set_optional_utf8_string(
                OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST),
                ""))
        goto cleanup;

    public_param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
    encoded_public_param =
        OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (public_param != NULL || encoded_public_param != NULL) {
        if (key->provider->rust->key_has(key->inner, 0, 1) == 1) {
            if (key->provider->rust->key_get_public(
                    key->inner,
                    public_key,
                    sizeof(public_key)) != 1
                    || !ed301v2_param_set_optional_octet_string(
                        public_param,
                        public_key,
                        sizeof(public_key))
                    || !ed301v2_param_set_optional_octet_string(
                        encoded_public_param,
                        public_key,
                        sizeof(public_key)))
                goto cleanup;
        }
    }

    private_param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (private_param != NULL
            && key->provider->rust->key_has(key->inner, 1, 0) == 1) {
        if (key->provider->rust->key_get_private(
                key->inner,
                private_key,
                sizeof(private_key)) != 1
                || !ed301v2_param_set_optional_octet_string(
                    private_param,
                    private_key,
                    sizeof(private_key)))
            goto cleanup;
    }

    result = 1;

cleanup:
    if (key != NULL && key->provider != NULL && key->provider->rust != NULL)
        key->provider->rust->cleanse(private_key, sizeof(private_key));
    if (result != 1 && key != NULL)
        ed301v2_raise(key->provider, ED301V2_R_INVALID_PARAMETER,
            "Ed301-EdDSA-v2 key parameter query failed");
    return result;
}

static const OSSL_PARAM *ed301v2_key_settable_params(void *provider_context)
{
    (void)provider_context;
    return ED301V2_SETTABLE_KEY_PARAMS;
}

static int ed301v2_key_set_params(void *key_data, const OSSL_PARAM params[])
{
    ED301V2_KEY *key = key_data;
    const unsigned char *public_key = NULL;
    size_t public_length = 0;

    if (key == NULL || key->provider == NULL || key->inner == NULL)
        return 0;
    if (params == NULL
            || OSSL_PARAM_locate_const(
                params,
                OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY) == NULL)
        return 1;
    if (!ed301v2_param_get_strict_octet_string(
            params,
            OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
            &public_key,
            &public_length,
            ED301V2_PUBLIC_KEY_BYTES,
            1)
            || key->provider->rust->key_set_encoded_public(
                key->inner,
                public_key,
                public_length) != 1) {
        ed301v2_raise(key->provider, ED301V2_R_INVALID_KEY,
            "invalid Ed301-EdDSA-v2 encoded public key");
        return 0;
    }
    return 1;
}

static int ed301v2_key_has(const void *key_data, int selection)
{
    const ED301V2_KEY *key = key_data;

    if (key == NULL || key->provider == NULL
            || key->provider->rust == NULL || key->inner == NULL
            || !ed301v2_selection_supported(selection))
        return 0;
    return key->provider->rust->key_has(
        key->inner,
        ed301v2_wants_private(selection),
        ed301v2_wants_public(selection));
}

static int ed301v2_key_validate(
    const void *key_data,
    int selection,
    int check_type)
{
    const ED301V2_KEY *key = key_data;
    int result;

    if (key == NULL || key->provider == NULL
            || key->provider->rust == NULL || key->inner == NULL
            || !ed301v2_selection_supported(selection)
            || (check_type != OSSL_KEYMGMT_VALIDATE_FULL_CHECK
                && check_type != OSSL_KEYMGMT_VALIDATE_QUICK_CHECK))
        return 0;

    result = key->provider->rust->key_validate(
        key->inner,
        ed301v2_wants_private(selection),
        ed301v2_wants_public(selection));
    if (result != 1)
        ed301v2_raise(key->provider, ED301V2_R_INVALID_KEY,
            "Ed301-EdDSA-v2 key validation failed");
    return result;
}

static int ed301v2_key_match(
    const void *first_data,
    const void *second_data,
    int selection)
{
    const ED301V2_KEY *first = first_data;
    const ED301V2_KEY *second = second_data;

    if (first == NULL || second == NULL || first->provider == NULL
            || first->provider != second->provider
            || first->provider->rust == NULL
            || first->inner == NULL || second->inner == NULL
            || !ed301v2_selection_supported(selection))
        return 0;

    return first->provider->rust->key_match(
        first->inner,
        second->inner,
        ed301v2_wants_private(selection),
        ed301v2_wants_public(selection));
}

static void *ed301v2_key_duplicate(const void *source_data, int selection)
{
    const ED301V2_KEY *source = source_data;
    void *inner;

    if (source == NULL || source->provider == NULL
            || source->provider->rust == NULL
            || source->inner == NULL
            || !ed301v2_selection_supported(selection))
        return NULL;
    inner = source->provider->rust->key_duplicate(
        source->inner,
        ed301v2_wants_private(selection),
        ed301v2_wants_public(selection));
    if (inner == NULL) {
        ed301v2_raise(source->provider, ED301V2_R_ALLOCATION_FAILURE,
            "Ed301-EdDSA-v2 key duplication failed");
        return NULL;
    }
    return ed301v2_wrap_key(source->provider, inner);
}

static const char *ed301v2_key_query_operation_name(int operation_id)
{
    if (operation_id == OSSL_OP_SIGNATURE)
        return ED301V2_ALGORITHM_NAME;
    return NULL;
}

static void *ed301v2_key_gen_init(
    void *provider_context,
    int selection,
    const OSSL_PARAM params[])
{
    ED301V2_PROVIDER_CONTEXT *provider = provider_context;
    ED301V2_GEN_CONTEXT *generation;
    size_t index;
    const int generates_keypair =
        (selection & OSSL_KEYMGMT_SELECT_KEYPAIR)
            == OSSL_KEYMGMT_SELECT_KEYPAIR;

    if (provider == NULL || provider->rust == NULL
            || !generates_keypair || !ed301v2_selection_supported(selection)) {
        ed301v2_raise(provider, ED301V2_R_INVALID_PARAMETER,
            "invalid Ed301-EdDSA-v2 key generation parameters");
        return NULL;
    }
    for (index = 0; params != NULL && params[index].key != NULL; index++) {
        /* This fixed profile has no selectable group or key size. */
        if (strcmp(params[index].key, OSSL_PKEY_PARAM_GROUP_NAME) == 0
                || strcmp(params[index].key, OSSL_PKEY_PARAM_BITS) == 0) {
            ed301v2_raise(provider, ED301V2_R_INVALID_PARAMETER,
                "Ed301-EdDSA-v2 key generation has a fixed group and size");
            return NULL;
        }
        /* Unknown metadata has no bearing on private RAND or the key. */
    }

    generation = ed301v2_allocate(provider, sizeof(*generation));
    if (generation == NULL) {
        ed301v2_raise(provider, ED301V2_R_ALLOCATION_FAILURE,
            "Ed301-EdDSA-v2 generation context allocation failed");
        return NULL;
    }
    generation->provider = provider;
    return generation;
}

/* OpenSSL-owned DRBG with no child-context thread-local instance. */
#include "../../../common/provider_rand.h"

static void *ed301v2_key_gen(
    void *generation_context,
    OSSL_CALLBACK *progress_callback,
    void *callback_argument)
{
    ED301V2_GEN_CONTEXT *generation = generation_context;
    ED301V2_PROVIDER_CONTEXT *provider;
    const ED301V2_SIGNATURE_RUST_API *rust;
    unsigned char seed[ED301V2_SEED_BYTES] = { 0 };
    void *inner = NULL;
    ED301V2_KEY *key = NULL;

    (void)progress_callback;
    (void)callback_argument;
    if (generation == NULL)
        return NULL;
    provider = generation->provider;
    if (provider == NULL || provider->rust == NULL || provider->libctx == NULL)
        return NULL;
    rust = provider->rust;

    if (!curve301_fill_random(provider, seed, sizeof(seed), 1)) {
        ed301v2_raise(provider, ED301V2_R_INVALID_KEY,
            "OpenSSL private RAND failed during Ed301-EdDSA-v2 key generation");
        goto cleanup;
    }
    inner = rust->key_from_seed(seed, sizeof(seed));
    if (inner == NULL) {
        ed301v2_raise(provider, ED301V2_R_INVALID_KEY,
            "Ed301-EdDSA-v2 key derivation failed");
        goto cleanup;
    }
    key = ed301v2_wrap_key(provider, inner);
    inner = NULL;

cleanup:
    rust->cleanse(seed, sizeof(seed));
    if (inner != NULL)
        rust->key_free(inner);
    return key;
}

static void ed301v2_key_gen_cleanup(void *generation_context)
{
    ED301V2_GEN_CONTEXT *generation = generation_context;
    ED301V2_PROVIDER_CONTEXT *provider;

    if (generation == NULL)
        return;
    provider = generation->provider;
    ed301v2_clear_free(provider, generation, sizeof(*generation));
}

/* ------------------------------------------------------------------ */
/* Signature operation                                                */
/* ------------------------------------------------------------------ */

static ED301V2_SIGNATURE_CONTEXT *ed301v2_signature_wrap_context(
    ED301V2_PROVIDER_CONTEXT *provider,
    void *inner)
{
    ED301V2_SIGNATURE_CONTEXT *signature;

    if (provider == NULL || provider->rust == NULL || inner == NULL)
        return NULL;
    signature = ed301v2_allocate(provider, sizeof(*signature));
    if (signature == NULL) {
        provider->rust->signature_free(inner);
        ed301v2_raise(provider, ED301V2_R_ALLOCATION_FAILURE,
            "Ed301-EdDSA-v2 signature context allocation failed");
        return NULL;
    }

    signature->provider = provider;
    signature->inner = inner;
    return signature;
}

static void *ed301v2_signature_new_context(
    void *provider_context,
    const char *property_query)
{
    ED301V2_PROVIDER_CONTEXT *provider = provider_context;
    void *inner;

    (void)property_query;
    if (provider == NULL || provider->rust == NULL)
        return NULL;
    inner = provider->rust->signature_new();
    if (inner == NULL) {
        ed301v2_raise(provider, ED301V2_R_ALLOCATION_FAILURE,
            "Ed301-EdDSA-v2 signature context allocation failed");
        return NULL;
    }
    return ed301v2_signature_wrap_context(provider, inner);
}

static void ed301v2_signature_free_context(void *signature_context)
{
    ED301V2_SIGNATURE_CONTEXT *signature = signature_context;
    ED301V2_PROVIDER_CONTEXT *provider;

    if (signature == NULL)
        return;
    provider = signature->provider;
    if (provider != NULL && provider->rust != NULL
            && signature->inner != NULL)
        provider->rust->signature_free(signature->inner);
    ed301v2_clear_free(provider, signature, sizeof(*signature));
}

static void *ed301v2_signature_duplicate_context(void *signature_context)
{
    ED301V2_SIGNATURE_CONTEXT *source = signature_context;
    void *inner;

    if (source == NULL || source->provider == NULL
            || source->provider->rust == NULL || source->inner == NULL)
        return NULL;
    inner = source->provider->rust->signature_duplicate(source->inner);
    if (inner == NULL) {
        ed301v2_raise(source->provider, ED301V2_R_ALLOCATION_FAILURE,
            "Ed301-EdDSA-v2 signature context duplication failed");
        return NULL;
    }
    return ed301v2_signature_wrap_context(source->provider, inner);
}

static void ed301v2_signature_reset(
    ED301V2_SIGNATURE_CONTEXT *signature)
{
    if (signature != NULL && signature->provider != NULL
            && signature->provider->rust != NULL
            && signature->inner != NULL)
        signature->provider->rust->signature_reset(signature->inner);
}

static void ed301v2_signature_clear_context(
    ED301V2_SIGNATURE_CONTEXT *signature)
{
    if (signature != NULL && signature->provider != NULL
            && signature->provider->rust != NULL
            && signature->inner != NULL)
        (void)signature->provider->rust->signature_set_context(
            signature->inner, NULL, 0);
}

static void ed301v2_signature_invalidate(
    ED301V2_SIGNATURE_CONTEXT *signature)
{
    ed301v2_signature_reset(signature);
    ed301v2_signature_clear_context(signature);
}

static int ed301v2_signature_get_context_params(
    void *signature_context,
    OSSL_PARAM params[])
{
    ED301V2_SIGNATURE_CONTEXT *signature = signature_context;
    OSSL_PARAM *context_parameter;
    unsigned char context[ED301V2_MAX_CONTEXT_BYTES];
    size_t context_length = 0;

    if (signature == NULL || signature->provider == NULL
            || signature->provider->rust == NULL
            || signature->inner == NULL)
        return 0;
    if (params == NULL)
        return 1;

    if (!ed301v2_param_set_optional_octet_string(
            OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID),
            ED301V2_ALGORITHM_ID_DER,
            sizeof(ED301V2_ALGORITHM_ID_DER)))
        return 0;
    context_parameter = OSSL_PARAM_locate(
        params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING);
    if (context_parameter == NULL)
        return 1;
    if (signature->provider->rust->signature_get_context(
            signature->inner,
            context,
            sizeof(context),
            &context_length) != 1
            || context_length > sizeof(context))
        return 0;
    return ed301v2_param_set_optional_octet_string(
        context_parameter, context, context_length);
}

static const OSSL_PARAM *ed301v2_signature_gettable_context_params(
    void *signature_context,
    void *provider_context)
{
    (void)signature_context;
    (void)provider_context;
    return ED301V2_GETTABLE_CTX_PARAMS;
}

static int ed301v2_is_unsupported_signature_parameter(const char *key)
{
    static const char *const unsupported[] = {
        OSSL_SIGNATURE_PARAM_DIGEST,
        OSSL_SIGNATURE_PARAM_DIGEST_SIZE,
        OSSL_SIGNATURE_PARAM_PROPERTIES,
        OSSL_SIGNATURE_PARAM_INSTANCE,
        OSSL_SIGNATURE_PARAM_NONCE_TYPE,
        OSSL_SIGNATURE_PARAM_DETERMINISTIC,
        OSSL_SIGNATURE_PARAM_ADD_RANDOM,
        OSSL_SIGNATURE_PARAM_TEST_ENTROPY,
        OSSL_SIGNATURE_PARAM_SIGNATURE,
        "prehash", "streaming"
    };
    size_t index;

    for (index = 0; index < sizeof(unsupported) / sizeof(unsupported[0]); index++) {
        if (strcmp(key, unsupported[index]) == 0)
            return 1;
    }
    return 0;
}

/* Validate recognized parameters before atomically replacing the context. */
static int ed301v2_signature_apply_params(
    ED301V2_SIGNATURE_CONTEXT *signature,
    const OSSL_PARAM params[])
{
    unsigned char context[ED301V2_MAX_CONTEXT_BYTES];
    size_t context_length = 0;
    size_t index;
    int context_seen = 0;
    int tls_version_seen = 0;

    if (params == NULL)
        return 1;
    for (index = 0; params[index].key != NULL; index++) {
        const OSSL_PARAM *parameter = &params[index];

        if (strcmp(parameter->key,
                OSSL_SIGNATURE_PARAM_CONTEXT_STRING) == 0) {
            if (context_seen
                    || parameter->data_type != OSSL_PARAM_OCTET_STRING
                    || parameter->data_size > sizeof(context)
                    || (parameter->data_size != 0
                        && parameter->data == NULL)) {
                ed301v2_raise(signature->provider,
                    ED301V2_R_INVALID_PARAMETER,
                    "Ed301-EdDSA-v2 context must be one OCTET STRING of "
                    "at most 255 bytes");
                return 0;
            }
            if (parameter->data_size != 0)
                memcpy(context, parameter->data, parameter->data_size);
            context_length = parameter->data_size;
            context_seen = 1;
            continue;
        }
        if (strcmp(parameter->key, "tls-version") == 0) {
#if ED301V2_ACCEPT_TLS_VERSION_PARAM
            /*
             * OpenSSL 4.0 transport metadata only: at most one
             * OSSL_PARAM_INTEGER of exactly sizeof(int) whose value is
             * exactly TLS 1.3. It is neither stored nor hashed nor added
             * to the transcript. The remaining parameters are still checked.
             */
            if (!tls_version_seen
                    && parameter->data_type == OSSL_PARAM_INTEGER
                    && parameter->data != NULL
                    && parameter->data_size == sizeof(int)) {
                int tls_version = 0;

                memcpy(&tls_version, parameter->data, sizeof(tls_version));
                if (tls_version == ED301V2_TLS_VERSION_1_3) {
                    tls_version_seen = 1;
                    continue;
                }
            }
#endif
            ed301v2_raise(signature->provider, ED301V2_R_UNSUPPORTED_MODE,
                "Ed301-EdDSA-v2 rejects unsupported TLS metadata");
            return 0;
        }
        if (ed301v2_is_unsupported_signature_parameter(parameter->key)) {
            ed301v2_raise(signature->provider, ED301V2_R_UNSUPPORTED_MODE,
                "Ed301-EdDSA-v2 rejects parameter '%s': no digest, prehash, "
                "instance, streaming or randomized mode is defined",
                parameter->key);
            return 0;
        }
        /* Unknown keys are ignored without inspecting their type or value. */
    }
    (void)tls_version_seen;
    if (context_seen
            && signature->provider->rust->signature_set_context(
                signature->inner,
                context_length == 0 ? NULL : context,
                context_length) != 1) {
        ed301v2_raise(signature->provider, ED301V2_R_INVALID_PARAMETER,
            "Ed301-EdDSA-v2 context update failed");
        return 0;
    }
    return 1;
}

static int ed301v2_signature_set_context_params(
    void *signature_context,
    const OSSL_PARAM params[])
{
    ED301V2_SIGNATURE_CONTEXT *signature = signature_context;

    if (signature == NULL || signature->provider == NULL
            || signature->provider->rust == NULL
            || signature->inner == NULL)
        return 0;
    return ed301v2_signature_apply_params(signature, params);
}

static const OSSL_PARAM *ed301v2_signature_settable_context_params(
    void *signature_context,
    void *provider_context)
{
    (void)signature_context;
    (void)provider_context;
    return ED301V2_SETTABLE_CTX_PARAMS;
}

static int ed301v2_signature_sign_init(
    void *signature_context,
    void *key_data,
    const OSSL_PARAM params[])
{
    ED301V2_SIGNATURE_CONTEXT *signature = signature_context;
    ED301V2_KEY *key = key_data;

    if (signature == NULL || signature->provider == NULL
            || signature->provider->rust == NULL
            || signature->inner == NULL)
        return 0;

    if (key == NULL) {
        if (signature->provider->rust->signature_sign_init(
                signature->inner, NULL) != 1) {
            ed301v2_raise(signature->provider, ED301V2_R_INVALID_STATE,
                "v2 signing reinitialization has no bound signing key");
            return 0;
        }
        return ed301v2_signature_apply_params(signature, params);
    }

    /* Match Ed448: clear both the prior key operation and native context. */
    ed301v2_signature_invalidate(signature);
    if (signature->provider != key->provider
            || key->inner == NULL) {
        ed301v2_raise(signature->provider, ED301V2_R_INVALID_KEY,
            "v2 signing key belongs to a different provider context");
        return 0;
    }
    if (!ed301v2_signature_apply_params(signature, params)) {
        return 0;
    }
    if (signature->provider->rust->signature_sign_init(
            signature->inner,
            key->inner) != 1) {
        ed301v2_raise(signature->provider, ED301V2_R_INVALID_KEY,
            "v2 signing requires a consistent private key");
        return 0;
    }
    return 1;
}

static int ed301v2_signature_verify_init(
    void *signature_context,
    void *key_data,
    const OSSL_PARAM params[])
{
    ED301V2_SIGNATURE_CONTEXT *signature = signature_context;
    ED301V2_KEY *key = key_data;

    if (signature == NULL || signature->provider == NULL
            || signature->provider->rust == NULL
            || signature->inner == NULL)
        return 0;

    if (key == NULL) {
        if (signature->provider->rust->signature_verify_init(
                signature->inner, NULL) != 1) {
            ed301v2_raise(signature->provider, ED301V2_R_INVALID_STATE,
                "v2 verification reinitialization has no bound key");
            return 0;
        }
        return ed301v2_signature_apply_params(signature, params);
    }

    /* Match Ed448: clear both the prior key operation and native context. */
    ed301v2_signature_invalidate(signature);
    if (signature->provider != key->provider
            || key->inner == NULL) {
        ed301v2_raise(signature->provider, ED301V2_R_INVALID_KEY,
            "v2 verification key belongs to a different provider context");
        return 0;
    }
    if (!ed301v2_signature_apply_params(signature, params)) {
        return 0;
    }
    if (signature->provider->rust->signature_verify_init(
            signature->inner,
            key->inner) != 1) {
        ed301v2_raise(signature->provider, ED301V2_R_INVALID_KEY,
            "v2 verification requires a valid public key");
        return 0;
    }
    return 1;
}

static int ed301v2_signature_sign(
    void *signature_context,
    unsigned char *signature_value,
    size_t *signature_length,
    size_t signature_size,
    const unsigned char *message,
    size_t message_length)
{
    ED301V2_SIGNATURE_CONTEXT *signature = signature_context;

    if (signature == NULL || signature->provider == NULL
            || signature->provider->rust == NULL
            || signature->inner == NULL || signature_length == NULL)
        return 0;
    if (signature_value == NULL) {
        *signature_length = ED301V2_SIGNATURE_BYTES;
        return 1;
    }
    if (signature_size < ED301V2_SIGNATURE_BYTES) {
        *signature_length = ED301V2_SIGNATURE_BYTES;
        ed301v2_raise(signature->provider, ED301V2_R_INVALID_PARAMETER,
            "Ed301-EdDSA-v2 output buffer is too small");
        return 0;
    }

    *signature_length = 0;
    if (signature->provider->rust->signature_sign(
            signature->inner,
            message,
            message_length,
            signature_value,
            signature_size) != 1) {
        ed301v2_raise(signature->provider, ED301V2_R_INVALID_STATE,
            "Ed301-EdDSA-v2 signing failed");
        return 0;
    }
    *signature_length = ED301V2_SIGNATURE_BYTES;
    return 1;
}

static int ed301v2_signature_verify(
    void *signature_context,
    const unsigned char *signature_value,
    size_t signature_length,
    const unsigned char *message,
    size_t message_length)
{
    ED301V2_SIGNATURE_CONTEXT *signature = signature_context;
    int result;

    if (signature == NULL || signature->provider == NULL
            || signature->provider->rust == NULL
            || signature->inner == NULL)
        return -1;
    if ((message == NULL && message_length != 0)
            || message_length > (size_t)INTPTR_MAX) {
        ed301v2_raise(signature->provider, ED301V2_R_INVALID_PARAMETER,
            "Ed301-EdDSA-v2 verification received an invalid input buffer");
        return -1;
    }
    if (signature_length != ED301V2_SIGNATURE_BYTES)
        return 0;
    if (signature_value == NULL) {
        ed301v2_raise(signature->provider, ED301V2_R_INVALID_PARAMETER,
            "Ed301-EdDSA-v2 verification received an invalid signature buffer");
        return -1;
    }
    result = signature->provider->rust->signature_verify(
        signature->inner,
        message,
        message_length,
        signature_value,
        signature_length);
    if (result < 0)
        ed301v2_raise(signature->provider, ED301V2_R_INVALID_STATE,
            "Ed301-EdDSA-v2 verification failed internally");
    return result;
}

static int ed301v2_digest_name_is_pure(const char *digest_name)
{
    return digest_name == NULL || digest_name[0] == '\0';
}

static int ed301v2_signature_digest_sign_init(
    void *signature_context,
    const char *digest_name,
    void *key_data,
    const OSSL_PARAM params[])
{
    ED301V2_SIGNATURE_CONTEXT *signature = signature_context;

    if (!ed301v2_digest_name_is_pure(digest_name)) {
        if (signature != NULL) {
            ed301v2_raise(signature->provider, ED301V2_R_UNSUPPORTED_MODE,
                "Ed301-EdDSA-v2 does not accept an external digest");
        }
        return 0;
    }
    return ed301v2_signature_sign_init(signature_context, key_data, params);
}

static int ed301v2_signature_digest_verify_init(
    void *signature_context,
    const char *digest_name,
    void *key_data,
    const OSSL_PARAM params[])
{
    ED301V2_SIGNATURE_CONTEXT *signature = signature_context;

    if (!ed301v2_digest_name_is_pure(digest_name)) {
        if (signature != NULL) {
            ed301v2_raise(signature->provider, ED301V2_R_UNSUPPORTED_MODE,
                "Ed301-EdDSA-v2 does not accept an external digest");
        }
        return 0;
    }
    return ed301v2_signature_verify_init(signature_context, key_data, params);
}

static int ed301v2_signature_digest_sign(
    void *signature_context,
    unsigned char *signature_value,
    size_t *signature_length,
    size_t signature_size,
    const unsigned char *message,
    size_t message_length)
{
    return ed301v2_signature_sign(
        signature_context,
        signature_value,
        signature_length,
        signature_size,
        message,
        message_length);
}

static int ed301v2_signature_digest_verify(
    void *signature_context,
    const unsigned char *signature_value,
    size_t signature_length,
    const unsigned char *message,
    size_t message_length)
{
    return ed301v2_signature_verify(
        signature_context,
        signature_value,
        signature_length,
        message,
        message_length);
}

/* ------------------------------------------------------------------ */
/* Dispatch and algorithm tables                                      */
/* ------------------------------------------------------------------ */

#include "../../../common/provider_codec.h"

static const OSSL_DISPATCH ED301V2_KEYMGMT_DISPATCH[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))ed301v2_key_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))ed301v2_key_free },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))ed301v2_key_load },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))ed301v2_key_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))ed301v2_key_gen },
    {
        OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
        (void (*)(void))ed301v2_key_gen_cleanup
    },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))ed301v2_key_get_params },
    {
        OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
        (void (*)(void))ed301v2_key_gettable_params
    },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))ed301v2_key_set_params },
    {
        OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
        (void (*)(void))ed301v2_key_settable_params
    },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))ed301v2_key_has },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))ed301v2_key_validate },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))ed301v2_key_match },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))ed301v2_key_import },
    {
        OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
        (void (*)(void))ed301v2_key_import_types
    },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))ed301v2_key_export },
    {
        OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
        (void (*)(void))ed301v2_key_export_types
    },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))ed301v2_key_duplicate },
    {
        OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
        (void (*)(void))ed301v2_key_query_operation_name
    },
    { 0, NULL }
};

static const OSSL_DISPATCH ED301V2_SIGNATURE_DISPATCH[] = {
    {
        OSSL_FUNC_SIGNATURE_NEWCTX,
        (void (*)(void))ed301v2_signature_new_context
    },
    {
        OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT,
        (void (*)(void))ed301v2_signature_sign_init
    },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))ed301v2_signature_sign },
    {
        OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,
        (void (*)(void))ed301v2_signature_verify_init
    },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))ed301v2_signature_verify },
    {
        OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
        (void (*)(void))ed301v2_signature_digest_sign_init
    },
    {
        OSSL_FUNC_SIGNATURE_DIGEST_SIGN,
        (void (*)(void))ed301v2_signature_digest_sign
    },
    {
        OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
        (void (*)(void))ed301v2_signature_digest_verify_init
    },
    {
        OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,
        (void (*)(void))ed301v2_signature_digest_verify
    },
    {
        OSSL_FUNC_SIGNATURE_FREECTX,
        (void (*)(void))ed301v2_signature_free_context
    },
    {
        OSSL_FUNC_SIGNATURE_DUPCTX,
        (void (*)(void))ed301v2_signature_duplicate_context
    },
    {
        OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
        (void (*)(void))ed301v2_signature_get_context_params
    },
    {
        OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
        (void (*)(void))ed301v2_signature_gettable_context_params
    },
    {
        OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
        (void (*)(void))ed301v2_signature_set_context_params
    },
    {
        OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
        (void (*)(void))ed301v2_signature_settable_context_params
    },
    { 0, NULL }
};

static const OSSL_ALGORITHM ED301V2_KEYMGMT_ALGORITHMS[] = {
    {
        ED301V2_OPERATION_ALGORITHM_NAMES,
        ED301V2_PROPERTY,
        ED301V2_KEYMGMT_DISPATCH,
        "Ed301-EdDSA-v2 raw key management"
    },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM ED301V2_SIGNATURE_ALGORITHMS[] = {
    {
        ED301V2_OPERATION_ALGORITHM_NAMES,
        ED301V2_PROPERTY,
        ED301V2_SIGNATURE_DISPATCH,
        "Ed301-EdDSA-v2 one-shot signatures"
    },
    { NULL, NULL, NULL, NULL }
};

/* ------------------------------------------------------------------ */
/* Capabilities                                                       */
/* ------------------------------------------------------------------ */

#if ED301V2_HAS_TEST_TLS_CAPABILITY
static int ed301v2_provider_get_capabilities(
    void *provider_context,
    const char *capability,
    OSSL_CALLBACK *callback,
    void *callback_argument)
{
    unsigned int code_point = ED301V2_TLS_SIGALG_CODE_POINT;
    unsigned int security_bits = ED301V2_SECURITY_BITS;
    int minimum_tls = ED301V2_TLS_VERSION_1_3;
    int maximum_tls = ED301V2_TLS_VERSION_1_3;
    int minimum_dtls = -1;
    int maximum_dtls = -1;
    OSSL_PARAM sigalg_parameters[] = {
        OSSL_PARAM_utf8_string(
            OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME,
            (char *)ED301V2_TLS_SIGALG_IANA_NAME,
            sizeof(ED301V2_TLS_SIGALG_IANA_NAME)),
        OSSL_PARAM_utf8_string(
            OSSL_CAPABILITY_TLS_SIGALG_NAME,
            (char *)ED301V2_ALGORITHM_NAME,
            sizeof(ED301V2_ALGORITHM_NAME)),
        OSSL_PARAM_utf8_string(
            OSSL_CAPABILITY_TLS_SIGALG_OID,
            (char *)ED301V2_OID,
            sizeof(ED301V2_OID)),
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT, &code_point),
        OSSL_PARAM_uint(
            OSSL_CAPABILITY_TLS_SIGALG_SECURITY_BITS,
            &security_bits),
        OSSL_PARAM_utf8_string(
            OSSL_CAPABILITY_TLS_SIGALG_KEYTYPE,
            (char *)ED301V2_ALGORITHM_NAME,
            sizeof(ED301V2_ALGORITHM_NAME)),
        OSSL_PARAM_utf8_string(
            OSSL_CAPABILITY_TLS_SIGALG_KEYTYPE_OID,
            (char *)ED301V2_OID,
            sizeof(ED301V2_OID)),
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MIN_TLS, &minimum_tls),
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MAX_TLS, &maximum_tls),
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MIN_DTLS, &minimum_dtls),
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MAX_DTLS, &maximum_dtls),
        OSSL_PARAM_END
    };

    (void)provider_context;
    if (capability == NULL || callback == NULL)
        return 0;
    if (strcmp(capability, ED301V2_TLS_SIGALG_CAPABILITY) == 0)
        return callback(sigalg_parameters, callback_argument);
    /*
     * Unknown capabilities succeed with zero entries; returning failure
     * would abort the caller's provider iteration (libssl treats a zero
     * return from the capability query as a hard error).
     */
    return 1;
}
#endif

/* ------------------------------------------------------------------ */
/* Provider plumbing                                                  */
/* ------------------------------------------------------------------ */

static void ed301v2_provider_teardown(void *provider_context)
{
    ED301V2_PROVIDER_CONTEXT *provider = provider_context;

    if (provider != NULL) {
        curve301_drbg_free(provider->private_drbg);
        provider->private_drbg = NULL;
        curve301_drbg_free(provider->public_drbg);
        provider->public_drbg = NULL;
        CRYPTO_THREAD_lock_free(provider->drbg_lock);
        provider->drbg_lock = NULL;
        OSSL_LIB_CTX_free(provider->libctx);
        provider->libctx = NULL;
    }
    if (provider != NULL && provider->clear_free != NULL) {
        provider->clear_free(
            provider,
            sizeof(*provider),
            __FILE__,
            __LINE__);
    }
}

static const OSSL_ITEM *ed301v2_provider_get_reason_strings(
    void *provider_context)
{
    (void)provider_context;
    return ED301V2_REASON_STRINGS;
}

static const OSSL_PARAM *ed301v2_provider_gettable_params(
    void *provider_context)
{
    (void)provider_context;
    return ED301V2_PROVIDER_GETTABLE_PARAMS;
}

static int ed301v2_provider_get_params(
    void *provider_context,
    OSSL_PARAM params[])
{
    ED301V2_PROVIDER_CONTEXT *provider = provider_context;

    if (provider == NULL)
        return 0;

    if (!ed301v2_param_set_optional_utf8_ptr(
            OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME),
            ED301V2_PROVIDER_NAME)
            || !ed301v2_param_set_optional_utf8_ptr(
                OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION),
                ED301V2_PROVIDER_VERSION)
            || !ed301v2_param_set_optional_utf8_ptr(
                OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO),
                ED301V2_PROVIDER_BUILDINFO)
            || !ed301v2_param_set_optional_int(
                OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS),
                1))
        return 0;

    return 1;
}

static const OSSL_ALGORITHM *ed301v2_provider_query_operation(
    void *provider_context,
    int operation_id,
    int *no_cache)
{
    (void)provider_context;

    if (no_cache != NULL)
        *no_cache = 0;
    if (operation_id == OSSL_OP_KEYMGMT)
        return ED301V2_KEYMGMT_ALGORITHMS;
    if (operation_id == OSSL_OP_SIGNATURE)
        return ED301V2_SIGNATURE_ALGORITHMS;
    if (operation_id == OSSL_OP_ENCODER && ED301V2_HAS_TEST_PKI_INTEGRATION)
        return CURVE301_ENCODER_ALGORITHMS;
#if ED301V2_HAS_TEST_DECODER
    if (operation_id == OSSL_OP_DECODER)
        return CURVE301_DECODER_ALGORITHMS;
#endif
    return NULL;
}

static const OSSL_DISPATCH ED301V2_PROVIDER_DISPATCH[] = {
    {
        OSSL_FUNC_PROVIDER_TEARDOWN,
        (void (*)(void))ed301v2_provider_teardown
    },
    {
        OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
        (void (*)(void))ed301v2_provider_gettable_params
    },
    {
        OSSL_FUNC_PROVIDER_GET_PARAMS,
        (void (*)(void))ed301v2_provider_get_params
    },
    {
        OSSL_FUNC_PROVIDER_GET_REASON_STRINGS,
        (void (*)(void))ed301v2_provider_get_reason_strings
    },
    {
        OSSL_FUNC_PROVIDER_QUERY_OPERATION,
        (void (*)(void))ed301v2_provider_query_operation
    },
#if ED301V2_HAS_TEST_TLS_CAPABILITY
    {
        OSSL_FUNC_PROVIDER_GET_CAPABILITIES,
        (void (*)(void))ed301v2_provider_get_capabilities
    },
#endif
    { 0, NULL }
};

static int ed301v2_parse_version_component(
    const char **cursor,
    unsigned int *value)
{
    const char *position;
    unsigned int parsed = 0;

    if (cursor == NULL || *cursor == NULL || value == NULL)
        return 0;
    position = *cursor;
    if (*position < '0' || *position > '9')
        return 0;
    do {
        unsigned int digit = (unsigned int)(*position - '0');

        if (parsed > (UINT_MAX - digit) / 10U)
            return 0;
        parsed = parsed * 10U + digit;
        position++;
    } while (*position >= '0' && *position <= '9');
    *cursor = position;
    *value = parsed;
    return 1;
}

static int ed301v2_core_version_text_is_supported(const char *core_version)
{
    const char *cursor = core_version;
    unsigned int major = 0;
    unsigned int minor = 0;
    unsigned int patch = 0;

    if (!(ed301v2_parse_version_component(&cursor, &major)
            && *cursor++ == '.'
            && ed301v2_parse_version_component(&cursor, &minor)
            && *cursor++ == '.'
            && ed301v2_parse_version_component(&cursor, &patch)
            && *cursor == '\0'))
        return 0;

    if (major != ED301V2_SUPPORTED_CORE_MAJOR)
        return 0;
    return minor > ED301V2_MINIMUM_CORE_MINOR
        || (minor == ED301V2_MINIMUM_CORE_MINOR
            && patch >= ED301V2_MINIMUM_CORE_PATCH);
}

static int ed301v2_core_version_is_supported(
    const OSSL_CORE_HANDLE *handle,
    OSSL_FUNC_core_get_params_fn *get_params)
{
    char *core_version = NULL;
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_utf8_ptr(
            OSSL_PROV_PARAM_CORE_VERSION,
            &core_version,
            0),
        OSSL_PARAM_END
    };

    return handle != NULL && get_params != NULL
        && get_params(handle, parameters) == 1
        && ed301v2_core_version_text_is_supported(core_version);
}

/* ------------------------------------------------------------------ */
/* Entry point called by the Rust cdylib wrapper                      */
/* ------------------------------------------------------------------ */

/* Every function pointer is part of the Rust/C ABI contract. */
static int ed301v2_rust_api_valid(
    const ED301V2_SIGNATURE_RUST_API *rust_api)
{
    return rust_api != NULL
        && rust_api->abi_version == 3
        && rust_api->struct_size == sizeof(*rust_api)
        && rust_api->seed_bytes == ED301V2_SEED_BYTES
        && rust_api->public_key_bytes == ED301V2_PUBLIC_KEY_BYTES
        && rust_api->signature_bytes == ED301V2_SIGNATURE_BYTES
        && rust_api->key_new != NULL
        && rust_api->key_free != NULL
        && rust_api->key_import != NULL
        && rust_api->key_set_encoded_public != NULL
        && rust_api->key_from_seed != NULL
        && rust_api->key_duplicate != NULL
        && rust_api->key_has != NULL
        && rust_api->key_validate != NULL
        && rust_api->key_match != NULL
        && rust_api->key_get_private != NULL
        && rust_api->key_get_public != NULL
        && rust_api->signature_new != NULL
        && rust_api->signature_free != NULL
        && rust_api->signature_duplicate != NULL
        && rust_api->signature_reset != NULL
        && rust_api->signature_set_context != NULL
        && rust_api->signature_get_context != NULL
        && rust_api->signature_sign_init != NULL
        && rust_api->signature_verify_init != NULL
        && rust_api->signature_sign != NULL
        && rust_api->signature_verify != NULL
        && rust_api->cleanse != NULL;
}

int ed301_eddsa_v2_shim_init(
    const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *input_dispatch,
    const OSSL_DISPATCH **output_dispatch,
    void **provider_context,
    const ED301V2_SIGNATURE_RUST_API *rust_api);

int ed301_eddsa_v2_shim_init(
    const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *input_dispatch,
    const OSSL_DISPATCH **output_dispatch,
    void **provider_context,
    const ED301V2_SIGNATURE_RUST_API *rust_api)
{
    const OSSL_DISPATCH *dispatch;
    OSSL_FUNC_CRYPTO_zalloc_fn *zalloc = NULL;
    OSSL_FUNC_CRYPTO_clear_free_fn *clear_free = NULL;
    OSSL_FUNC_core_new_error_fn *new_error = NULL;
    OSSL_FUNC_core_set_error_debug_fn *set_error_debug = NULL;
    OSSL_FUNC_core_vset_error_fn *vset_error = NULL;
    OSSL_FUNC_BIO_read_ex_fn *bio_read_ex = NULL;
    OSSL_FUNC_BIO_write_ex_fn *bio_write_ex = NULL;
    OSSL_FUNC_BIO_ctrl_fn *bio_ctrl = NULL;
    OSSL_FUNC_core_get_params_fn *core_get_params = NULL;
#if ED301V2_REGISTER_PROCESS_OID
    OSSL_FUNC_core_obj_create_fn *core_obj_create = NULL;
    OSSL_FUNC_core_obj_add_sigid_fn *core_obj_add_sigid = NULL;
#endif
    ED301V2_PROVIDER_CONTEXT *provider;

    if (handle == NULL || input_dispatch == NULL || output_dispatch == NULL
            || provider_context == NULL)
        return 0;

    *output_dispatch = NULL;
    *provider_context = NULL;

    if (!ed301v2_rust_api_valid(rust_api))
        return 0;

    for (dispatch = input_dispatch; dispatch->function_id != 0; dispatch++) {
        switch (dispatch->function_id) {
        case OSSL_FUNC_CORE_GET_PARAMS:
            core_get_params = OSSL_FUNC_core_get_params(dispatch);
            break;
        case OSSL_FUNC_CRYPTO_ZALLOC:
            zalloc = OSSL_FUNC_CRYPTO_zalloc(dispatch);
            break;
        case OSSL_FUNC_CRYPTO_CLEAR_FREE:
            clear_free = OSSL_FUNC_CRYPTO_clear_free(dispatch);
            break;
        case OSSL_FUNC_CORE_NEW_ERROR:
            new_error = OSSL_FUNC_core_new_error(dispatch);
            break;
        case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
            set_error_debug = OSSL_FUNC_core_set_error_debug(dispatch);
            break;
        case OSSL_FUNC_CORE_VSET_ERROR:
            vset_error = OSSL_FUNC_core_vset_error(dispatch);
            break;
        case OSSL_FUNC_BIO_READ_EX:
            bio_read_ex = OSSL_FUNC_BIO_read_ex(dispatch);
            break;
        case OSSL_FUNC_BIO_WRITE_EX:
            bio_write_ex = OSSL_FUNC_BIO_write_ex(dispatch);
            break;
        case OSSL_FUNC_BIO_CTRL:
            bio_ctrl = OSSL_FUNC_BIO_ctrl(dispatch);
            break;
#if ED301V2_REGISTER_PROCESS_OID
        case OSSL_FUNC_CORE_OBJ_CREATE:
            core_obj_create = OSSL_FUNC_core_obj_create(dispatch);
            break;
        case OSSL_FUNC_CORE_OBJ_ADD_SIGID:
            core_obj_add_sigid = OSSL_FUNC_core_obj_add_sigid(dispatch);
            break;
#endif
        default:
            break;
        }
    }

    if (zalloc == NULL || clear_free == NULL || bio_write_ex == NULL
            || core_get_params == NULL)
        return 0;
#if ED301V2_HAS_TEST_DECODER
    if (bio_read_ex == NULL || bio_ctrl == NULL)
        return 0;
#endif
#if ED301V2_REGISTER_PROCESS_OID
    if (core_obj_create == NULL || core_obj_add_sigid == NULL)
        return 0;
#endif
    if (!ed301v2_core_version_is_supported(handle, core_get_params))
        return 0;
    provider = zalloc(sizeof(*provider), __FILE__, __LINE__);
    if (provider == NULL)
        return 0;

    provider->handle = handle;
    provider->zalloc = zalloc;
    provider->clear_free = clear_free;
    provider->new_error = new_error;
    provider->set_error_debug = set_error_debug;
    provider->vset_error = vset_error;
    provider->bio_read_ex = bio_read_ex;
    provider->bio_write_ex = bio_write_ex;
    provider->bio_ctrl = bio_ctrl;
    provider->rust = rust_api;
    provider->libctx = OSSL_LIB_CTX_new_child(handle, input_dispatch);
    if (provider->libctx == NULL) {
        clear_free(provider, sizeof(*provider), __FILE__, __LINE__);
        return 0;
    }
    {
        OSSL_PROVIDER *null_provider = OSSL_PROVIDER_load(
            provider->libctx, "null");

        if (null_provider == NULL
                || OSSL_PROVIDER_unload(null_provider) != 1) {
            OSSL_LIB_CTX_free(provider->libctx);
            clear_free(provider, sizeof(*provider), __FILE__, __LINE__);
            return 0;
        }
    }
    provider->drbg_lock = CRYPTO_THREAD_lock_new();
    if (provider->drbg_lock == NULL) {
        OSSL_LIB_CTX_free(provider->libctx);
        clear_free(provider, sizeof(*provider), __FILE__, __LINE__);
        return 0;
    }
#if ED301V2_REGISTER_PROCESS_OID
    if (core_obj_create(handle, ED301V2_OID, ED301V2_ALGORITHM_NAME,
            ED301V2_ALGORITHM_NAME) != 1
            || core_obj_add_sigid(
                handle, ED301V2_OID, "", ED301V2_OID) != 1
            || !ed301v2_process_identity_is_exact()) {
        ed301v2_raise(provider, ED301V2_R_INVALID_STATE,
            "Ed301-EdDSA-v2 OID/SIGID registration is not exact");
        CRYPTO_THREAD_lock_free(provider->drbg_lock);
        provider->drbg_lock = NULL;
        OSSL_LIB_CTX_free(provider->libctx);
        provider->libctx = NULL;
        clear_free(provider, sizeof(*provider), __FILE__, __LINE__);
        return 0;
    }
#endif

    *provider_context = provider;
    *output_dispatch = ED301V2_PROVIDER_DISPATCH;
    return 1;
}

#endif /* ED301_SUPPORTED_HEADERS */
