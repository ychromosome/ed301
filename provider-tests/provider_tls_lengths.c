/* In-process TLS conformance only: alter a declared length in our own
 * ClientHello/ServerHello transport buffer. No sockets or external targets.
 * A unique fixed key_share envelope is located with libc memmem; libssl is
 * the actual parser and must reject before peer authentication completes.
 */
#include <openssl/buffer.h>
#include <openssl/ssl.h>
#include <openssl/sslerr.h>
#include <openssl/x509.h>
#include "harness_common.h"
#include "../provider/common/generated_x301_profile.h"

static int received_cv;

static void observe(int write_p, int version, int type, const void *data,
    size_t length, SSL *ssl, void *argument)
{
    const unsigned char *bytes = data;

    (void)version;
    (void)ssl;
    (void)argument;
    if (!write_p && type == SSL3_RT_HANDSHAKE && length >= 4
            && bytes[0] == SSL3_MT_CERTIFICATE_VERIFY)
        received_cv++;
}

static int forward(BIO *from, BIO *to, unsigned int group, size_t share_bytes,
    int direction, int delta, int *mutated)
{
    unsigned char buffer[32768];
    int length;

    while ((length = BIO_read(from, buffer, sizeof(buffer))) > 0) {
        if (delta != 0 && !*mutated) {
            unsigned char pattern[10];
            size_t pattern_length = direction == 1 ? 10 : 8;
            size_t body_length = share_bytes + (direction == 1 ? 6 : 4);
            unsigned char *match;
            size_t offset = 4;

            pattern[0] = 0;
            pattern[1] = TLSEXT_TYPE_key_share;
            pattern[2] = (unsigned char)(body_length >> 8);
            pattern[3] = (unsigned char)body_length;
            if (direction == 1) {
                pattern[offset++] = (unsigned char)((share_bytes + 4) >> 8);
                pattern[offset++] = (unsigned char)(share_bytes + 4);
            }
            pattern[offset++] = (unsigned char)(group >> 8);
            pattern[offset++] = (unsigned char)group;
            pattern[offset++] = (unsigned char)(share_bytes >> 8);
            pattern[offset++] = (unsigned char)share_bytes;
            match = memmem(buffer, (size_t)length, pattern, pattern_length);
            if (match == NULL || offset != pattern_length
                    || memmem(match + pattern_length,
                        (size_t)length - (size_t)(match + pattern_length - buffer),
                        pattern, pattern_length) != NULL)
                return 0;
            body_length = (size_t)((long)share_bytes + delta);
            match[pattern_length - 2] = (unsigned char)(body_length >> 8);
            match[pattern_length - 1] = (unsigned char)body_length;
            *mutated = 1;
        }
        if (BIO_write(to, buffer, length) != length)
            return 0;
    }
    return BIO_should_retry(from) || BIO_eof(from);
}

static void run_case(OSSL_LIB_CTX *libctx, EVP_PKEY *key, X509 *certificate,
    const char *group_name, unsigned int group, size_t share_bytes,
    int mutation_direction, int delta)
{
    SSL_CTX *server_ctx = SSL_CTX_new_ex(libctx, NULL, TLS_server_method());
    SSL_CTX *client_ctx = SSL_CTX_new_ex(libctx, NULL, TLS_client_method());
    SSL *server = NULL, *client = NULL;
    BIO *server_in = NULL, *server_out = NULL, *client_in = NULL, *client_out = NULL;
    int setup = 0, mutated = 0, finished = 0, failed_endpoint = 0;
    unsigned long failure = 0;

    received_cv = 0;
    if (server_ctx == NULL || client_ctx == NULL
            || SSL_CTX_use_certificate(server_ctx, certificate) != 1
            || SSL_CTX_use_PrivateKey(server_ctx, key) != 1
            || X509_STORE_add_cert(SSL_CTX_get_cert_store(client_ctx), certificate) != 1)
        goto done;
    SSL_CTX_set_verify(client_ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_msg_callback(client_ctx, observe);
    for (int side = 0; side < 2; side++) {
        SSL_CTX *ctx = side ? server_ctx : client_ctx;

        if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1
                || SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1
                || SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384") != 1
                || SSL_CTX_set1_groups_list(ctx, group_name) != 1
                || SSL_CTX_set1_sigalgs_list(ctx, "ecdsa_secp256r1_sha256") != 1)
            goto done;
    }
    server = SSL_new(server_ctx);
    client = SSL_new(client_ctx);
    server_in = BIO_new(BIO_s_mem());
    server_out = BIO_new(BIO_s_mem());
    client_in = BIO_new(BIO_s_mem());
    client_out = BIO_new(BIO_s_mem());
    if (server == NULL || client == NULL || server_in == NULL || server_out == NULL
            || client_in == NULL || client_out == NULL)
        goto done;
    SSL_set_bio(server, server_in, server_out);
    SSL_set_bio(client, client_in, client_out);
    SSL_set_accept_state(server);
    SSL_set_connect_state(client);
    setup = 1;
    for (int round = 0; round < 200; round++) {
        int client_result, server_result, error;

        ERR_clear_error();
        client_result = SSL_do_handshake(client);
        error = client_result == 1 ? SSL_ERROR_NONE : SSL_get_error(client, client_result);
        if (error != SSL_ERROR_NONE && error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
            failed_endpoint = 2;
            failure = ERR_peek_last_error();
            break;
        }
        if (!forward(client_out, server_in, group, share_bytes, 1,
                mutation_direction == 1 ? delta : 0, &mutated))
            break;
        ERR_clear_error();
        server_result = SSL_do_handshake(server);
        error = server_result == 1 ? SSL_ERROR_NONE : SSL_get_error(server, server_result);
        if (error != SSL_ERROR_NONE && error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
            failed_endpoint = 1;
            failure = ERR_peek_last_error();
            break;
        }
        if (!forward(server_out, client_in, group, share_bytes, 2,
                mutation_direction == 2 ? delta : 0, &mutated))
            break;
        if (client_result == 1 && server_result == 1) {
            finished = 1;
            break;
        }
    }
    if (delta == 0) {
        ED301V2_CHECK(finished && received_cv == 1 && SSL_get_verify_result(client) == X509_V_OK
                && SSL_get_negotiated_group(client) == (TLSEXT_nid_unknown | group)
                && SSL_get_negotiated_group(server) == (TLSEXT_nid_unknown | group),
            "%s: unchanged length positive handshake", group_name);
    } else {
        ED301V2_CHECK(mutated && !finished && failed_endpoint == mutation_direction
                && ERR_GET_LIB(failure) == ERR_LIB_SSL && ERR_GET_REASON(failure) == SSL_R_LENGTH_MISMATCH
                && received_cv == 0,
            "%s: direction=%d declared share length %+d rejected before peer authentication", group_name, mutation_direction, delta);
    }
    printf("TLS_LENGTH group=%s direction=%d delta=%d mutated=%d handshake=%d reason=%d\n",
        group_name, mutation_direction, delta, mutated, finished, ERR_GET_REASON(failure));
done:
    ED301V2_CHECK(setup, "%s: length-control endpoints configured", group_name);
    if (!setup) {
        BIO_free(server_in); BIO_free(server_out);
        BIO_free(client_in); BIO_free(client_out);
    }
    SSL_free(client); SSL_free(server);
    SSL_CTX_free(client_ctx); SSL_CTX_free(server_ctx);
}

int main(void)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *deflt = NULL, *x = NULL;
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *sign = NULL;
    X509 *certificate = NULL;
    X509_NAME *name = NULL;
    int ready = 0;

    ED301V2_REQUIRE_RUNTIME_BINDING();
    ED301V2_REQUIRE_TLS_RUNTIME_BINDING();
    libctx = OSSL_LIB_CTX_new();
    deflt = curve301_v2_load_checked(libctx, "default");
    x = curve301_v2_load_checked(libctx, "x301_v2_tls");
    if (deflt == NULL || x == NULL)
        goto done;
    key = EVP_PKEY_Q_keygen(libctx, "provider=default", "EC", "prime256v1");
    certificate = X509_new_ex(libctx, NULL);
    name = X509_NAME_new();
    sign = EVP_MD_CTX_new();
    if (key == NULL || certificate == NULL || name == NULL || sign == NULL
            || X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                (const unsigned char *)"D2 ephemeral length control", -1, -1, 0) != 1
            || X509_set_version(certificate, 2) != 1
            || ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1) != 1
            || X509_gmtime_adj(X509_getm_notBefore(certificate), -60) == NULL
            || X509_gmtime_adj(X509_getm_notAfter(certificate), 3600) == NULL
            || X509_set_subject_name(certificate, name) != 1
            || X509_set_issuer_name(certificate, name) != 1
            || X509_set_pubkey(certificate, key) != 1
            || EVP_DigestSignInit_ex(sign, NULL, "SHA256", libctx, "provider=default", key, NULL) != 1
            || X509_sign_ctx(certificate, sign) <= 0)
        goto done;
    ready = 1;
    for (int hybrid = 0; hybrid < 2; hybrid++) {
        const char *group_name = hybrid ? "X301MLKEM1024" : "X301";
        unsigned int group = hybrid ? X301V2_TLS_HYBRID_GROUP_ID : X301V2_TLS_RAW_GROUP_ID;
        size_t bytes = hybrid ? 1606 : 38;

        run_case(libctx, key, certificate, group_name, group, bytes, 0, 0);
        for (int direction = 1; direction <= 2; direction++)
            for (int delta = -1; delta <= 1; delta += 2)
                run_case(libctx, key, certificate, group_name, group, bytes, direction, delta);
    }
done:
    ED301V2_CHECK(ready, "fresh default-provider certificate and private X301 context");
    EVP_MD_CTX_free(sign); X509_NAME_free(name);
    X509_free(certificate); EVP_PKEY_free(key);
    OSSL_PROVIDER_unload(x); OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    return ed301v2_summary("provider_tls_lengths");
}
