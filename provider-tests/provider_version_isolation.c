/* Real TLS-engine version controls, with one generation per private libctx.
 * The transport is an in-process BIO pair, not a TCP performance claim.
 * Each generation first passes its own positive control with fresh keys.
 */
#include <openssl/ssl.h>
#include <openssl/sslerr.h>
#include <openssl/x509.h>
#include "harness_common.h"

typedef struct {
    OSSL_LIB_CTX *libctx;
    OSSL_PROVIDER *deflt;
    OSSL_PROVIDER *provider;
    EVP_PKEY *key;
    X509 *certificate;
    SSL_CTX *server;
    SSL_CTX *client;
    unsigned int group;
    unsigned int scheme;
} ENDPOINT;

typedef struct {
    int cv_count;
    unsigned int scheme;
} OBSERVATION;

static void observe(int write_p, int version, int content_type,
    const void *buffer, size_t length, SSL *ssl, void *argument)
{
    OBSERVATION *seen = argument;
    const unsigned char *bytes = buffer;

    (void)version;
    (void)ssl;
    if (!write_p && content_type == SSL3_RT_HANDSHAKE && length >= 8
            && bytes[0] == SSL3_MT_CERTIFICATE_VERIFY) {
        seen->cv_count++;
        seen->scheme = ((unsigned int)bytes[4] << 8) | bytes[5];
    }
}

static void endpoint_free(ENDPOINT *endpoint)
{
    SSL_CTX_free(endpoint->client);
    SSL_CTX_free(endpoint->server);
    X509_free(endpoint->certificate);
    EVP_PKEY_free(endpoint->key);
    OSSL_PROVIDER_unload(endpoint->provider);
    OSSL_PROVIDER_unload(endpoint->deflt);
    OSSL_LIB_CTX_free(endpoint->libctx);
    memset(endpoint, 0, sizeof(*endpoint));
}

static int endpoint_setup(ENDPOINT *endpoint, const char *directory,
    const char *module, const char *keytype, const char *sigalgs,
    const char *groups, unsigned int group, unsigned int scheme)
{
    EVP_PKEY_CTX *keygen = NULL;
    EVP_MD_CTX *sign = NULL;
    X509_NAME *name = NULL;
    int ec = strcmp(keytype, "EC") == 0;
    int ok = 0;
    char property[128];
    int property_length;

    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->group = group;
    endpoint->scheme = scheme;
    endpoint->libctx = OSSL_LIB_CTX_new();
    if (endpoint->libctx == NULL
            || OSSL_PROVIDER_set_default_search_path(endpoint->libctx, directory) != 1
            || (endpoint->deflt = OSSL_PROVIDER_load(endpoint->libctx, "default")) == NULL
            || (endpoint->provider = OSSL_PROVIDER_load(endpoint->libctx, module)) == NULL)
        goto done;
    property_length = snprintf(property, sizeof(property), "provider=%s", ec ? "default" : module);
    if (property_length <= 0 || (size_t)property_length >= sizeof(property))
        goto done;
    keygen = EVP_PKEY_CTX_new_from_name(endpoint->libctx, keytype, property);
    if (keygen == NULL || EVP_PKEY_keygen_init(keygen) != 1
            || (ec && EVP_PKEY_CTX_set_group_name(keygen, "prime256v1") != 1)
            || EVP_PKEY_generate(keygen, &endpoint->key) != 1)
        goto done;
    endpoint->certificate = X509_new_ex(endpoint->libctx, NULL);
    name = X509_NAME_new();
    sign = EVP_MD_CTX_new();
    if (endpoint->certificate == NULL || name == NULL || sign == NULL
            || X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                (const unsigned char *)"D2 local version control", -1, -1, 0) != 1
            || X509_set_version(endpoint->certificate, 2) != 1
            || ASN1_INTEGER_set(X509_get_serialNumber(endpoint->certificate), 1) != 1
            || X509_gmtime_adj(X509_getm_notBefore(endpoint->certificate), -60) == NULL
            || X509_gmtime_adj(X509_getm_notAfter(endpoint->certificate), 3600) == NULL
            || X509_set_subject_name(endpoint->certificate, name) != 1
            || X509_set_issuer_name(endpoint->certificate, name) != 1
            || X509_set_pubkey(endpoint->certificate, endpoint->key) != 1
            || EVP_DigestSignInit_ex(sign, NULL, ec ? "SHA256" : NULL,
                endpoint->libctx, property, endpoint->key, NULL) != 1
            || X509_sign_ctx(endpoint->certificate, sign) <= 0)
        goto done;
    endpoint->server = SSL_CTX_new_ex(endpoint->libctx, NULL, TLS_server_method());
    endpoint->client = SSL_CTX_new_ex(endpoint->libctx, NULL, TLS_client_method());
    if (endpoint->server == NULL || endpoint->client == NULL
            || SSL_CTX_use_certificate(endpoint->server, endpoint->certificate) != 1
            || SSL_CTX_use_PrivateKey(endpoint->server, endpoint->key) != 1
            || SSL_CTX_check_private_key(endpoint->server) != 1
            || SSL_CTX_set_num_tickets(endpoint->server, 0) != 1)
        goto done;
    SSL_CTX_set_verify(endpoint->client, SSL_VERIFY_PEER, NULL);
    for (int side = 0; side < 2; side++) {
        SSL_CTX *context = side ? endpoint->server : endpoint->client;

        if (SSL_CTX_set_min_proto_version(context, TLS1_3_VERSION) != 1
                || SSL_CTX_set_max_proto_version(context, TLS1_3_VERSION) != 1
                || SSL_CTX_set_ciphersuites(context, "TLS_AES_256_GCM_SHA384") != 1
                || SSL_CTX_set1_sigalgs_list(context, sigalgs) != 1
                || SSL_CTX_set1_groups_list(context, groups) != 1)
            goto done;
    }
    ok = 1;
done:
    EVP_MD_CTX_free(sign);
    X509_NAME_free(name);
    EVP_PKEY_CTX_free(keygen);
    return ok;
}

static void handshake_case(ENDPOINT *server_endpoint, ENDPOINT *client_endpoint,
    const char *label, int expected_reason)
{
    SSL *server = NULL;
    SSL *client = NULL;
    BIO *server_bio = NULL;
    BIO *client_bio = NULL;
    OBSERVATION seen = { 0 };
    int ok = 0;
    int ready = 0;
    unsigned long failure = 0;
    unsigned char sent = 73;
    unsigned char received = 0;

    if (server_endpoint->server == NULL || client_endpoint->client == NULL)
        goto done;
    ERR_clear_error();
    if (X509_STORE_add_cert(SSL_CTX_get_cert_store(client_endpoint->client),
            server_endpoint->certificate) != 1)
        goto done;
    server = SSL_new(server_endpoint->server);
    client = SSL_new(client_endpoint->client);
    if (server == NULL || client == NULL
            || BIO_new_bio_pair(&server_bio, 0, &client_bio, 0) != 1)
        goto done;
    SSL_set_bio(server, server_bio, server_bio);
    SSL_set_bio(client, client_bio, client_bio);
    server_bio = client_bio = NULL;
    SSL_set_accept_state(server);
    SSL_set_connect_state(client);
    SSL_set_msg_callback(client, observe);
    SSL_set_msg_callback_arg(client, &seen);
    ready = 1;
    for (int i = 0; i < 200; i++) {
        int client_result;
        int server_result;
        int error;

        ERR_clear_error();
        client_result = SSL_do_handshake(client);
        error = client_result == 1 ? SSL_ERROR_NONE : SSL_get_error(client, client_result);
        if (error != SSL_ERROR_NONE && error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
            failure = ERR_peek_last_error();
            break;
        }
        ERR_clear_error();
        server_result = SSL_do_handshake(server);
        error = server_result == 1 ? SSL_ERROR_NONE : SSL_get_error(server, server_result);
        if (error != SSL_ERROR_NONE && error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
            failure = ERR_peek_last_error();
            break;
        }
        if (client_result == 1 && server_result == 1) {
            ok = 1;
            break;
        }
    }
    if (expected_reason != 0) {
        ED301V2_CHECK(!ok && ERR_GET_LIB(failure) == ERR_LIB_SSL
                && ERR_GET_REASON(failure) == expected_reason && seen.cv_count == 0,
            "%s: explicit version mismatch, no CertificateVerify or fallback", label);
    } else {
        long nid = server_endpoint->group == 29 ? NID_X25519
            : TLSEXT_nid_unknown | server_endpoint->group;

        ED301V2_CHECK(ok && SSL_get_verify_result(client) == X509_V_OK
                && SSL_get0_peer_certificate(client) != NULL
                && SSL_get_negotiated_group(client) == nid
                && SSL_get_negotiated_group(server) == nid
                && seen.cv_count == 1 && seen.scheme == server_endpoint->scheme
                && SSL_write(client, &sent, 1) == 1 && SSL_read(server, &received, 1) == 1
                && received == sent && SSL_write(server, &sent, 1) == 1
                && SSL_read(client, &received, 1) == 1 && received == sent,
            "%s: same-generation positive handshake, exact group/CV and verified traffic", label);
    }
    printf("VERSION_CONTROL %s handshake=%d reason=%d cv=%d scheme=0x%04x\n",
        label, ok, ERR_GET_REASON(failure), seen.cv_count, seen.scheme);
done:
    ED301V2_CHECK(ready, "%s: test pair was fully configured", label);
    SSL_free(client);
    SSL_free(server);
    BIO_free(client_bio);
    BIO_free(server_bio);
}

int main(int argc, char **argv)
{
    ENDPOINT old_ed = { 0 }, new_ed = { 0 }, old_x = { 0 }, new_x = { 0 };
    char old_ed_directory[PATH_MAX];
    char old_x_directory[PATH_MAX];
    int ready;

    ED301V2_REQUIRE_RUNTIME_BINDING();
    ED301V2_REQUIRE_TLS_RUNTIME_BINDING();
    if (argc != 3 || snprintf(old_ed_directory, sizeof(old_ed_directory), "%s/ed-tls", argv[1]) >= (int)sizeof(old_ed_directory)
            || snprintf(old_x_directory, sizeof(old_x_directory), "%s/x-tls", argv[1]) >= (int)sizeof(old_x_directory)) {
        fprintf(stderr, "usage: %s LEGACY_MODULES_ROOT V2_MODULES_DIRECTORY\n", argv[0]);
        return 2;
    }
    ready = endpoint_setup(&old_ed, old_ed_directory, "ed301_eddsa_v1_tls_test",
                "Ed301-EdDSA-v1", "Ed301-EdDSA-v1", "X25519", 29, 0xfe84)
        && endpoint_setup(&new_ed, argv[2], "ed301_eddsa_v2_tls_test",
                "Ed301-EdDSA", "Ed301-EdDSA", "X25519", 29, 0xfe85)
        && endpoint_setup(&old_x, old_x_directory, "x301", "EC",
                "ecdsa_secp256r1_sha256", "X301MLKEM1024", 0xfe2e, 0x0403)
        && endpoint_setup(&new_x, argv[2], "x301_v2_tls_test", "EC",
                "ecdsa_secp256r1_sha256", "X301MLKEM1024", 0xfe2f, 0x0403);
    ED301V2_CHECK(ready, "four private endpoints with separately loaded v1/v2 modules and fresh credentials");
    if (ready) {
        handshake_case(&old_ed, &old_ed, "Ed-v1-positive", 0);
        handshake_case(&new_ed, &new_ed, "Ed-v2-positive", 0);
        handshake_case(&old_x, &old_x, "Hybrid-v1-positive", 0);
        handshake_case(&new_x, &new_x, "Hybrid-v2-positive", 0);
        handshake_case(&old_ed, &new_ed, "Ed-v1-server-v2-client", SSL_R_NO_SHARED_SIGNATURE_ALGORITHMS);
        handshake_case(&new_ed, &old_ed, "Ed-v2-server-v1-client", SSL_R_NO_SHARED_SIGNATURE_ALGORITHMS);
        handshake_case(&old_x, &new_x, "Hybrid-v1-server-v2-client", SSL_R_NO_SUITABLE_KEY_SHARE);
        handshake_case(&new_x, &old_x, "Hybrid-v2-server-v1-client", SSL_R_NO_SUITABLE_KEY_SHARE);
    }
    endpoint_free(&new_x);
    endpoint_free(&old_x);
    endpoint_free(&new_ed);
    endpoint_free(&old_ed);
    ED301V2_CHECK(OSSL_PROVIDER_available(NULL, "ed301_eddsa_v1_tls_test") == 0
            && OSSL_PROVIDER_available(NULL, "ed301_eddsa_v2_tls_test") == 0
            && OSSL_PROVIDER_available(NULL, "x301") == 0
            && OSSL_PROVIDER_available(NULL, "x301_v2_tls_test") == 0,
        "neither generation was loaded into the process default libctx");
    return ed301v2_summary("provider_version_isolation");
}
