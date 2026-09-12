/* Same TLS 1.3 engine benchmark for old/new providers and standard controls.
 * Measures full, non-resumed handshakes including SSL/BIO creation/free in
 * warm SSL_CTX objects. Fresh certificate/key generation is outside timing.
 * This is an in-memory transport benchmark, not a TCP latency measurement.
 */
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/provider.h>
#include <openssl/x509.h>

static unsigned int observed_scheme;
static unsigned int observed_count;

static void observe(int write_p, int version, int content_type,
    const void *buffer, size_t length, SSL *ssl, void *argument)
{
    const unsigned char *bytes = buffer;

    (void)version;
    (void)ssl;
    (void)argument;
    if (!write_p && content_type == SSL3_RT_HANDSHAKE && length >= 8
            && bytes[0] == SSL3_MT_CERTIFICATE_VERIFY) {
        observed_count++;
        observed_scheme = ((unsigned int)bytes[4] << 8) | bytes[5];
    }
}

static int one_handshake(SSL_CTX *server_ctx, SSL_CTX *client_ctx,
    long expected_group, int check_traffic)
{
    SSL *server = SSL_new(server_ctx);
    SSL *client = SSL_new(client_ctx);
    BIO *server_bio = NULL;
    BIO *client_bio = NULL;
    int finished = 0;
    int ok = 0;
    unsigned char sent = 93, received = 0;

    if (server == NULL || client == NULL
            || BIO_new_bio_pair(&server_bio, 0, &client_bio, 0) != 1)
        goto done;
    SSL_set_bio(server, server_bio, server_bio);
    SSL_set_bio(client, client_bio, client_bio);
    server_bio = client_bio = NULL;
    SSL_set_accept_state(server);
    SSL_set_connect_state(client);
    for (int round = 0; round < 200; round++) {
        int client_result, server_result, error;

        ERR_clear_error();
        client_result = SSL_do_handshake(client);
        error = client_result == 1 ? SSL_ERROR_NONE : SSL_get_error(client, client_result);
        if (error != SSL_ERROR_NONE && error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
            goto done;
        ERR_clear_error();
        server_result = SSL_do_handshake(server);
        error = server_result == 1 ? SSL_ERROR_NONE : SSL_get_error(server, server_result);
        if (error != SSL_ERROR_NONE && error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
            goto done;
        if (client_result == 1 && server_result == 1) {
            finished = 1;
            break;
        }
    }
    ok = finished && SSL_get_verify_result(client) == X509_V_OK
        && SSL_get0_peer_certificate(client) != NULL
        && SSL_get_negotiated_group(client) == expected_group
        && SSL_get_negotiated_group(server) == expected_group
        && !SSL_session_reused(client) && !SSL_session_reused(server);
    if (ok && check_traffic)
        ok = SSL_write(client, &sent, 1) == 1 && SSL_read(server, &received, 1) == 1
            && received == sent && SSL_write(server, &sent, 1) == 1
            && SSL_read(client, &received, 1) == 1 && received == sent;
done:
    SSL_free(client);
    SSL_free(server);
    BIO_free(client_bio);
    BIO_free(server_bio);
    return ok;
}

static int clock_ns(uint64_t *result)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &now) != 0 || now.tv_sec < 0)
        return 0;
    *result = (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
    return 1;
}

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *deflt = NULL, *ed = NULL, *x = NULL;
    EVP_PKEY_CTX *keygen = NULL;
    EVP_MD_CTX *sign = NULL;
    EVP_PKEY *key = NULL;
    X509 *certificate = NULL;
    X509_NAME *name = NULL;
    SSL_CTX *server = NULL, *client = NULL;
    char *tail = NULL;
    unsigned long long count;
    unsigned long wire_group;
    long expected_group;
    unsigned int expected_scheme;
    const char *sigalgs;
    uint64_t start, end;
    int ec;
    int status = 1;

    if (argc != 10) {
        fprintf(stderr, "usage: %s SIGN_ALGORITHM PROPERTIES ED_MODULE_DIR ED_MODULE X_MODULE_DIR X_MODULE GROUP WIRE_GROUP COUNT\n", argv[0]);
        return 2;
    }
    errno = 0;
    count = strtoull(argv[9], &tail, 10);
    if (errno || tail == argv[9] || *tail || count == 0 || count > 1000000)
        return 2;
    errno = 0;
    wire_group = strtoul(argv[8], &tail, 0);
    if (errno || tail == argv[8] || *tail || wire_group > 65535)
        return 2;
    expected_group = wire_group == 29 ? NID_X25519 : TLSEXT_nid_unknown | wire_group;
    ec = strcmp(argv[1], "EC") == 0;
    if (ec) {
        sigalgs = "ecdsa_secp256r1_sha256";
        expected_scheme = 0x0403;
    } else if (strcmp(argv[1], "Ed301-EdDSA-v1") == 0) {
        sigalgs = argv[1];
        expected_scheme = 0xfe84;
    } else if (strcmp(argv[1], "Ed301-EdDSA") == 0) {
        sigalgs = argv[1];
        expected_scheme = 0xfe85;
    } else if (strcmp(argv[1], "ED25519") == 0) {
        sigalgs = "ed25519";
        expected_scheme = 0x0807;
    } else if (strcmp(argv[1], "ED448") == 0) {
        sigalgs = "ed448";
        expected_scheme = 0x0808;
    } else {
        return 2;
    }
    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL || (deflt = OSSL_PROVIDER_load(libctx, "default")) == NULL)
        goto done;
    if (strcmp(argv[4], "-") != 0
            && (OSSL_PROVIDER_set_default_search_path(libctx, argv[3]) != 1
                || (ed = OSSL_PROVIDER_load(libctx, argv[4])) == NULL))
        goto done;
    if (strcmp(argv[6], "-") != 0
            && (OSSL_PROVIDER_set_default_search_path(libctx, argv[5]) != 1
                || (x = OSSL_PROVIDER_load(libctx, argv[6])) == NULL))
        goto done;
    keygen = EVP_PKEY_CTX_new_from_name(libctx, argv[1], argv[2]);
    if (keygen == NULL || EVP_PKEY_keygen_init(keygen) != 1
            || (ec && EVP_PKEY_CTX_set_group_name(keygen, "prime256v1") != 1)
            || EVP_PKEY_generate(keygen, &key) != 1)
        goto done;
    certificate = X509_new_ex(libctx, NULL);
    name = X509_NAME_new();
    sign = EVP_MD_CTX_new();
    if (certificate == NULL || name == NULL || sign == NULL
            || X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                (const unsigned char *)"D2 ephemeral benchmark", -1, -1, 0) != 1
            || X509_set_version(certificate, 2) != 1
            || ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1) != 1
            || X509_gmtime_adj(X509_getm_notBefore(certificate), -60) == NULL
            || X509_gmtime_adj(X509_getm_notAfter(certificate), 3600) == NULL
            || X509_set_subject_name(certificate, name) != 1
            || X509_set_issuer_name(certificate, name) != 1
            || X509_set_pubkey(certificate, key) != 1
            || EVP_DigestSignInit_ex(sign, NULL, ec ? "SHA256" : NULL, libctx, argv[2], key, NULL) != 1
            || X509_sign_ctx(certificate, sign) <= 0)
        goto done;
    server = SSL_CTX_new_ex(libctx, NULL, TLS_server_method());
    client = SSL_CTX_new_ex(libctx, NULL, TLS_client_method());
    if (server == NULL || client == NULL || SSL_CTX_use_certificate(server, certificate) != 1
            || SSL_CTX_use_PrivateKey(server, key) != 1 || SSL_CTX_check_private_key(server) != 1
            || X509_STORE_add_cert(SSL_CTX_get_cert_store(client), certificate) != 1
            || SSL_CTX_set_num_tickets(server, 0) != 1)
        goto done;
    SSL_CTX_set_verify(client, SSL_VERIFY_PEER, NULL);
    for (int side = 0; side < 2; side++) {
        SSL_CTX *context = side ? server : client;

        SSL_CTX_set_session_cache_mode(context, SSL_SESS_CACHE_OFF);
        if (SSL_CTX_set_min_proto_version(context, TLS1_3_VERSION) != 1
                || SSL_CTX_set_max_proto_version(context, TLS1_3_VERSION) != 1
                || SSL_CTX_set_ciphersuites(context, "TLS_AES_256_GCM_SHA384") != 1
                || SSL_CTX_set1_groups_list(context, argv[7]) != 1
                || SSL_CTX_set1_sigalgs_list(context, sigalgs) != 1)
            goto done;
    }
    SSL_CTX_set_msg_callback(client, observe);
    if (!one_handshake(server, client, expected_group, 1)
            || observed_count != 1 || observed_scheme != expected_scheme)
        goto done;
    SSL_CTX_set_msg_callback(client, NULL);
    if (!clock_ns(&start))
        goto done;
    for (unsigned long long i = 0; i < count; i++)
        if (!one_handshake(server, client, expected_group, 0))
            goto done;
    if (!clock_ns(&end) || end < start)
        goto done;
    printf("RESULT operation=full-handshake-warm-context algorithm=%s group=%s count=%llu total_ns=%" PRIu64 " mean_ns=%.3f\n",
        argv[1], argv[7], count, end - start, (double)(end - start) / (double)count);
    status = 0;
done:
    if (status)
        ERR_print_errors_fp(stderr);
    SSL_CTX_free(client);
    SSL_CTX_free(server);
    X509_NAME_free(name);
    X509_free(certificate);
    EVP_MD_CTX_free(sign);
    EVP_PKEY_CTX_free(keygen);
    EVP_PKEY_free(key);
    OSSL_PROVIDER_unload(x);
    OSSL_PROVIDER_unload(ed);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    return status;
}
