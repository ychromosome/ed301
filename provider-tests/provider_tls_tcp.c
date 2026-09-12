/* D2 local TCP acceptance. No CLI/global-libctx provider activation.
 * Each connection binds 127.0.0.1:0 and retains its listener through accept.
 * Certificates and all three signing keys are generated afresh in memory.
 * The small wire readers below only observe libssl's own handshake output;
 * they are test assertions, not a production TLS/ASN.1 implementation.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/sslerr.h>
#include <openssl/x509v3.h>

#include "harness_common.h"
#include "strict_pki.h"
#include "v2_tls_policy.h"
#include "../provider/common/generated_x301_profile.h"
#include "../provider/common/generated_ed301_profile.h"

#define TEST_HOST "server.v2.test.example"
#define MAX_TRANSFER 8193

typedef struct {
    unsigned int group;
    size_t share_length;
    int client_hellos;
    int client_share_seen;
    int server_share_seen;
    int hrr;
    int cv[2][2];
    int keyupdate[2][2];
    int plaintext_handshake_records[2];
    size_t client_hello_size;
    int bad;
} WIRE_TRACE;

typedef struct {
    WIRE_TRACE *trace;
    int server;
} ENDPOINT_TRACE;

typedef struct {
    SSL *client;
    SSL *server;
    int client_fd;
    int server_fd;
    unsigned short port;
    unsigned long failure;
} TCP_PAIR;

typedef struct {
    OSSL_LIB_CTX *libctx;
    OSSL_PROVIDER *deflt;
    OSSL_PROVIDER *ed;
    OSSL_PROVIDER *x;
    EVP_PKEY *ca_key;
    EVP_PKEY *server_key;
    EVP_PKEY *client_key;
    X509 *ca;
    X509 *server_cert;
    X509 *client_cert;
} FIXTURE;

static unsigned int u16(const unsigned char *p)
{
    return ((unsigned int)p[0] << 8) | p[1];
}

static int observe_client_hello(SSL *ssl, int *alert, void *arg)
{
    WIRE_TRACE *trace = arg;
    const unsigned char *bytes = NULL;
    size_t length = 0;
    size_t offset = 2;

    (void)alert;
    trace->client_hellos++;
    if (!SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_key_share, &bytes, &length)
            || length < 2 || u16(bytes) != length - 2) {
        trace->bad = 1;
        return SSL_CLIENT_HELLO_SUCCESS;
    }
    while (offset < length) {
        unsigned int group;
        size_t share_length;

        if (length - offset < 4) {
            trace->bad = 1;
            break;
        }
        group = u16(bytes + offset);
        share_length = u16(bytes + offset + 2);
        offset += 4;
        if (share_length > length - offset) {
            trace->bad = 1;
            break;
        }
        if (group == trace->group) {
            trace->client_share_seen++;
            if (share_length != trace->share_length)
                trace->bad = 1;
        }
        offset += share_length;
    }
    return SSL_CLIENT_HELLO_SUCCESS;
}

static void observe_server_hello(WIRE_TRACE *trace,
    const unsigned char *bytes, size_t length)
{
    static const unsigned char hrr_random[32] = {
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
        0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
        0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
        0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c
    };
    size_t offset = 38; /* header, version, random */
    int hrr;
    int found = 0;

    if (length < offset + 1)
        goto bad;
    hrr = memcmp(bytes + 6, hrr_random, sizeof(hrr_random)) == 0;
    if (hrr)
        trace->hrr++;
    offset += 1 + bytes[offset];
    if (offset > length || length - offset < 5)
        goto bad;
    offset += 3; /* cipher suite and legacy compression */
    if (u16(bytes + offset) != length - offset - 2)
        goto bad;
    offset += 2;
    while (offset < length) {
        unsigned int type;
        size_t ext_length;

        if (length - offset < 4)
            goto bad;
        type = u16(bytes + offset);
        ext_length = u16(bytes + offset + 2);
        offset += 4;
        if (ext_length > length - offset)
            goto bad;
        if (type == TLSEXT_TYPE_key_share) {
            if (found++ || ext_length < 2
                    || u16(bytes + offset) != trace->group)
                goto bad;
            if (hrr) {
                if (ext_length != 2)
                    goto bad;
            } else {
                if (ext_length != 4 + trace->share_length
                        || u16(bytes + offset + 2) != trace->share_length)
                    goto bad;
                trace->server_share_seen++;
            }
        }
        offset += ext_length;
    }
    if (found == 1)
        return;
bad:
    trace->bad = 1;
}

static void observe_message(int outgoing, int version, int type,
    const void *buffer, size_t length, SSL *ssl, void *arg)
{
    ENDPOINT_TRACE *endpoint = arg;
    WIRE_TRACE *trace = endpoint->trace;
    const unsigned char *bytes = buffer;

    (void)version;
    (void)ssl;
    if (type == SSL3_RT_HEADER && outgoing && length == 5
            && bytes[0] == SSL3_RT_HANDSHAKE) {
        trace->plaintext_handshake_records[endpoint->server]++;
        if (u16(bytes + 3) > 512)
            trace->bad = 1;
    }
    if (type != SSL3_RT_HANDSHAKE)
        return;
    if (length < 4 || (((size_t)bytes[1] << 16)
            | ((size_t)bytes[2] << 8) | bytes[3]) != length - 4) {
        trace->bad = 1;
        return;
    }
    if (outgoing && !endpoint->server && bytes[0] == SSL3_MT_CLIENT_HELLO)
        trace->client_hello_size = length;
    if (outgoing && endpoint->server && bytes[0] == SSL3_MT_SERVER_HELLO)
        observe_server_hello(trace, bytes, length);
    if (bytes[0] == SSL3_MT_CERTIFICATE_VERIFY) {
        trace->cv[endpoint->server][outgoing != 0]++;
        if (length != 84 || u16(bytes + 4) != ED301V2_TLS_SIGALG_CODE_POINT
                || u16(bytes + 6) != 76)
            trace->bad = 1;
    }
    if (bytes[0] == SSL3_MT_KEY_UPDATE) {
        trace->keyupdate[endpoint->server][outgoing != 0]++;
        if (length != 5 || bytes[4] > 1)
            trace->bad = 1;
    }
}

static int strict_chain_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    if (preverify_ok
            && !ed301v2_pki_certificate_is_exact(
                X509_STORE_CTX_get_current_cert(ctx))) {
        X509_STORE_CTX_set_error(ctx, X509_V_ERR_APPLICATION_VERIFICATION);
        return 0;
    }
    return preverify_ok;
}

static int add_extension(X509 *cert, X509 *issuer, int nid, const char *text)
{
    X509V3_CTX ctx;
    X509_EXTENSION *ext;
    int ok;

    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer == NULL ? cert : issuer, cert, NULL, NULL, 0);
    ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, text);
    ok = ext != NULL && X509_add_ext(cert, ext, -1) == 1;
    X509_EXTENSION_free(ext);
    return ok;
}

static X509 *issue_certificate(FIXTURE *f, EVP_PKEY *key,
    const char *name, int role)
{
    X509 *cert = X509_new_ex(f->libctx, NULL);
    X509_NAME *subject = X509_NAME_new();
    int ca = role == 0;

    if (cert == NULL || subject == NULL
            || X509_set_version(cert, 2) != 1
            || ASN1_INTEGER_set(X509_get_serialNumber(cert), role + 1) != 1
            || X509_gmtime_adj(X509_getm_notBefore(cert), -60) == NULL
            || X509_gmtime_adj(X509_getm_notAfter(cert), 3600) == NULL
            || X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                (const unsigned char *)name, -1, -1, 0) != 1
            || X509_set_subject_name(cert, subject) != 1
            || X509_set_issuer_name(cert, ca ? subject
                : X509_get_subject_name(f->ca)) != 1
            || X509_set_pubkey(cert, key) != 1
            || !add_extension(cert, ca ? NULL : f->ca, NID_basic_constraints,
                ca ? "critical,CA:TRUE" : "critical,CA:FALSE")
            || !add_extension(cert, ca ? NULL : f->ca, NID_key_usage,
                ca ? "critical,keyCertSign,cRLSign" : "critical,digitalSignature")
            || (!ca && !add_extension(cert, f->ca, NID_ext_key_usage,
                role == 1 ? "serverAuth" : "clientAuth"))
            || (role == 1 && !add_extension(cert, f->ca,
                NID_subject_alt_name, "DNS:" TEST_HOST))
            || X509_sign(cert, f->ca_key, NULL) <= 0
                || !ed301v2_pki_verify_certificate(cert, f->ca_key)) {
        X509_NAME_free(subject);
        X509_free(cert);
        return NULL;
    }
    X509_NAME_free(subject);
    return cert;
}

static void pair_free(TCP_PAIR *pair)
{
    SSL_free(pair->client);
    SSL_free(pair->server);
    if (pair->client_fd >= 0)
        close(pair->client_fd);
    if (pair->server_fd >= 0)
        close(pair->server_fd);
    memset(pair, 0, sizeof(*pair));
    pair->client_fd = pair->server_fd = -1;
}

static int pair_new(TCP_PAIR *pair, SSL_CTX *server_ctx, SSL_CTX *client_ctx)
{
    struct sockaddr_in address = { 0 };
    struct sockaddr_in peer = { 0 };
    socklen_t length = sizeof(address);
    int listener = -1;
    int one = 1;
    int flags;

    memset(pair, 0, sizeof(*pair));
    pair->client_fd = pair->server_fd = -1;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0
            || bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0
            || listen(listener, 1) != 0
            || getsockname(listener, (struct sockaddr *)&address, &length) != 0
            || address.sin_addr.s_addr != htonl(INADDR_LOOPBACK)
            || address.sin_port == 0)
        goto error;
    pair->port = ntohs(address.sin_port);
    pair->client_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (pair->client_fd < 0
            || connect(pair->client_fd, (struct sockaddr *)&address,
                sizeof(address)) != 0)
        goto error;
    length = sizeof(peer);
    pair->server_fd = accept4(listener, (struct sockaddr *)&peer,
        &length, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (pair->server_fd < 0 || peer.sin_addr.s_addr != htonl(INADDR_LOOPBACK))
        goto error;
    close(listener);
    listener = -1;
    flags = fcntl(pair->client_fd, F_GETFL);
    if (flags < 0 || fcntl(pair->client_fd, F_SETFL, flags | O_NONBLOCK) != 0
            || setsockopt(pair->client_fd, IPPROTO_TCP, TCP_NODELAY,
                &one, sizeof(one)) != 0
            || setsockopt(pair->server_fd, IPPROTO_TCP, TCP_NODELAY,
                &one, sizeof(one)) != 0)
        goto error;
    pair->server = SSL_new(server_ctx);
    pair->client = SSL_new(client_ctx);
    if (pair->server == NULL || pair->client == NULL
            || SSL_set_fd(pair->server, pair->server_fd) != 1
            || SSL_set_fd(pair->client, pair->client_fd) != 1
            || SSL_set_tlsext_host_name(pair->client, TEST_HOST) != 1)
        goto error;
#if OPENSSL_VERSION_MAJOR >= 4
    if (SSL_set1_dnsname(pair->client, TEST_HOST) != 1)
#else
    if (SSL_set1_host(pair->client, TEST_HOST) != 1)
#endif
        goto error;
    SSL_set_accept_state(pair->server);
    SSL_set_connect_state(pair->client);
    return 1;
error:
    if (pair->client == NULL && pair->server == NULL)
        perror("local TCP setup");
    if (listener >= 0)
        close(listener);
    pair_free(pair);
    return 0;
}

static double monotonic_seconds(void)
{
    struct timespec time;

    if (clock_gettime(CLOCK_MONOTONIC, &time) != 0)
        return -1;
    return (double)time.tv_sec + (double)time.tv_nsec / 1e9;
}

static int retryable(SSL *ssl, int result, TCP_PAIR *pair)
{
    int error = SSL_get_error(ssl, result);

    if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
        return 1;
    pair->failure = ERR_peek_last_error();
    return 0;
}

static int handshake(TCP_PAIR *pair)
{
    int client_done = 0;
    int server_done = 0;
    double start = monotonic_seconds();

    while (start >= 0 && monotonic_seconds() - start < 10) {
        int result;
        struct pollfd fds[2] = {
            { pair->client_fd, POLLIN, 0 },
            { pair->server_fd, POLLIN, 0 }
        };

        if (!client_done) {
            ERR_clear_error();
            result = SSL_do_handshake(pair->client);
            client_done = result == 1;
            if (!client_done && !retryable(pair->client, result, pair))
                return 0;
        }
        if (!server_done) {
            ERR_clear_error();
            result = SSL_do_handshake(pair->server);
            server_done = result == 1;
            if (!server_done && !retryable(pair->server, result, pair))
                return 0;
        }
        if (client_done && server_done)
            return 1;
        if (poll(fds, 2, 1) < 0 && errno != EINTR)
            return 0;
    }
    return 0;
}

static int transfer(TCP_PAIR *pair, int client_sends, unsigned char salt)
{
    unsigned char sent[MAX_TRANSFER];
    unsigned char received[MAX_TRANSFER];
    SSL *writer = client_sends ? pair->client : pair->server;
    SSL *reader = client_sends ? pair->server : pair->client;
    size_t written = 0;
    size_t read_count = 0;
    double start = monotonic_seconds();

    for (size_t i = 0; i < sizeof(sent); i++)
        sent[i] = (unsigned char)(salt + i * 29);
    while (start >= 0 && monotonic_seconds() - start < 10) {
        int result;
        size_t count = 0;

        if (written < sizeof(sent)) {
            ERR_clear_error();
            result = SSL_write_ex(writer, sent + written,
                sizeof(sent) - written, &count);
            if (result == 1)
                written += count;
            else if (!retryable(writer, result, pair))
                return 0;
        }
        if (read_count < sizeof(received)) {
            ERR_clear_error();
            result = SSL_read_ex(reader, received + read_count,
                sizeof(received) - read_count, &count);
            if (result == 1)
                read_count += count;
            else if (!retryable(reader, result, pair))
                return 0;
        }
        if (written == sizeof(sent) && read_count == sizeof(received))
            return memcmp(sent, received, sizeof(sent)) == 0;
    }
    return 0;
}

static int exporter_matches(TCP_PAIR *pair)
{
    unsigned char client[64];
    unsigned char server[64];
    static const char label[] = "EXPORTER-ED301-v2-D2-local-test";

    return SSL_export_keying_material(pair->client, client, sizeof(client),
            label, sizeof(label) - 1, NULL, 0, 0) == 1
        && SSL_export_keying_material(pair->server, server, sizeof(server),
            label, sizeof(label) - 1, NULL, 0, 0) == 1
        && CRYPTO_memcmp(client, server, sizeof(client)) == 0;
}

static SSL_CTX *make_context(FIXTURE *f, int server, const char *groups)
{
    static const unsigned char session_id[] = "v2-local-tcp";
    SSL_CTX *ctx = SSL_CTX_new_ex(f->libctx, NULL,
        server ? TLS_server_method() : TLS_client_method());

    if (ctx == NULL)
        return NULL;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER
        | (server ? SSL_VERIFY_FAIL_IF_NO_PEER_CERT : 0), strict_chain_callback);
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1
            || SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1
            || SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384") != 1
            || SSL_CTX_set1_sigalgs_list(ctx, ED301V2_ALG) != 1
            || (groups != NULL && SSL_CTX_set1_groups_list(ctx, groups) != 1)
            || SSL_CTX_set_max_send_fragment(ctx, 512) != 1
            || SSL_CTX_use_certificate(ctx,
                server ? f->server_cert : f->client_cert) != 1
            || SSL_CTX_use_PrivateKey(ctx,
                server ? f->server_key : f->client_key) != 1
            || SSL_CTX_check_private_key(ctx) != 1
            || X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), f->ca) != 1
            || (server && (SSL_CTX_set_num_tickets(ctx, 1) != 1
                || SSL_CTX_set_session_id_context(ctx,
                    session_id, sizeof(session_id) - 1) != 1))) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

static void run_case(FIXTURE *f, const char *name,
    const char *server_groups, const char *client_groups,
    unsigned int group, size_t share_length, int hrr_expected, int success)
{
    SSL_CTX *server_ctx = make_context(f, 1, server_groups);
    SSL_CTX *client_ctx = make_context(f, 0, client_groups);
    TCP_PAIR pair = { .client_fd = -1, .server_fd = -1 };
    WIRE_TRACE trace = { .group = group, .share_length = share_length };
    ENDPOINT_TRACE server_trace = { &trace, 1 };
    ENDPOINT_TRACE client_trace = { &trace, 0 };
    SSL_SESSION *session = NULL;
    long expected_nid = group == 29 ? NID_X25519 : TLSEXT_nid_unknown | group;
    int ok;

    ED301V2_CHECK(server_ctx != NULL && client_ctx != NULL,
        "%s: contexts configured", name);
    if (server_ctx == NULL || client_ctx == NULL)
        goto done;
    SSL_CTX_set_msg_callback(server_ctx, observe_message);
    SSL_CTX_set_msg_callback_arg(server_ctx, &server_trace);
    SSL_CTX_set_msg_callback(client_ctx, observe_message);
    SSL_CTX_set_msg_callback_arg(client_ctx, &client_trace);
    SSL_CTX_set_client_hello_cb(server_ctx, observe_client_hello, &trace);
    ED301V2_CHECK(pair_new(&pair, server_ctx, client_ctx),
        "%s: owned ephemeral loopback TCP pair", name);
    if (pair.client == NULL || pair.server == NULL)
        goto done;
    ok = handshake(&pair);
    if (!success) {
        ED301V2_CHECK(!ok && ERR_GET_LIB(pair.failure) == ERR_LIB_SSL
                && ERR_GET_REASON(pair.failure) == SSL_R_NO_SUITABLE_KEY_SHARE,
            "%s: no shared group, not a timeout or certificate failure", name);
        ED301V2_CHECK(SSL_get_negotiated_group(pair.client)
                != (TLSEXT_nid_unknown | X301V2_TLS_RAW_GROUP_ID)
                && SSL_get_negotiated_group(pair.server)
                != (TLSEXT_nid_unknown | X301V2_TLS_RAW_GROUP_ID),
            "%s: raw X301 was not negotiated", name);
        printf("TCP %s port=%u expected_rejection=1 reason=%d\n",
            name, pair.port, ERR_GET_REASON(pair.failure));
        goto done;
    }
    ED301V2_CHECK(ok, "%s: TLS handshake", name);
    if (!ok)
        goto done;
    ED301V2_CHECK(SSL_version(pair.client) == TLS1_3_VERSION
            && SSL_version(pair.server) == TLS1_3_VERSION
            && SSL_CIPHER_get_protocol_id(SSL_get_current_cipher(pair.client))
                == 0x1302
            && SSL_CIPHER_get_protocol_id(SSL_get_current_cipher(pair.server))
                == 0x1302
            && SSL_get_negotiated_group(pair.client) == expected_nid
            && SSL_get_negotiated_group(pair.server) == expected_nid,
        "%s: exact TLS version, ciphersuite and group at both endpoints", name);
    ED301V2_CHECK(SSL_get_verify_result(pair.client) == X509_V_OK
            && SSL_get_verify_result(pair.server) == X509_V_OK
            && X509_cmp(SSL_get0_peer_certificate(pair.client), f->server_cert) == 0
            && X509_cmp(SSL_get0_peer_certificate(pair.server), f->client_cert) == 0,
        "%s: fresh CA-only trust, hostname and mutual leaf authentication", name);
    ED301V2_CHECK(!trace.bad && trace.client_hellos == 1 + hrr_expected
            && trace.hrr == hrr_expected && trace.client_share_seen == 1
            && trace.server_share_seen == 1
            && trace.cv[0][0] == 1 && trace.cv[0][1] == 1
            && trace.cv[1][0] == 1 && trace.cv[1][1] == 1,
        "%s: observed shares, HRR count and both FE85 CertificateVerify directions", name);
    if (share_length == 1606)
        ED301V2_CHECK(trace.client_hello_size > 512
                && trace.plaintext_handshake_records[0] >= 4
                && trace.plaintext_handshake_records[1] >= 4,
            "%s: 1606-byte shares span multiple <=512-byte TLS records", name);
    if (client_groups == NULL) {
        uint16_t *groups = NULL;
        int count = SSL_get0_iana_groups(pair.server, &groups);
        int absent = count > 0;

        for (int i = 0; i < count; i++)
            if (groups[i] == X301V2_TLS_RAW_GROUP_ID)
                absent = 0;
        ED301V2_CHECK(absent, "%s: stock client DEFAULT never offered raw X301", name);
    }
    ED301V2_CHECK(transfer(&pair, 1, 17) && transfer(&pair, 0, 51),
        "%s: 8193 bytes each way across fragmented records", name);
    ED301V2_CHECK(exporter_matches(&pair), "%s: exporter agreement", name);
    ED301V2_CHECK(SSL_key_update(pair.client, SSL_KEY_UPDATE_REQUESTED) == 1
            && transfer(&pair, 1, 83) && transfer(&pair, 0, 117)
            && transfer(&pair, 1, 151) && !trace.bad
            && trace.keyupdate[0][1] == 1 && trace.keyupdate[1][0] == 1
            && trace.keyupdate[1][1] == 1 && trace.keyupdate[0][0] == 1,
        "%s: requested and reciprocal KeyUpdate with verified traffic", name);
    session = SSL_get1_session(pair.client);
    ED301V2_CHECK(session != NULL && SSL_SESSION_is_resumable(session) == 1,
        "%s: fresh ticket received", name);
    printf("TCP %s port=%u group=0x%04x share=%zu hrr=%d mutual=1 keyupdate=1\n",
        name, pair.port, group, share_length, trace.hrr);
    /* Keep both original endpoints alive: freeing an uncleanly shut down
     * connection can invalidate its cached session before this test uses it. */
    if (session != NULL && SSL_SESSION_is_resumable(session) == 1) {
        TCP_PAIR resumed = { .client_fd = -1, .server_fd = -1 };

        memset(&trace, 0, sizeof(trace));
        trace.group = group;
        trace.share_length = share_length;
        ok = pair_new(&resumed, server_ctx, client_ctx)
            && SSL_set_session(resumed.client, session) == 1
            && handshake(&resumed);
        ED301V2_CHECK(ok && SSL_session_reused(resumed.client) == 1
                && SSL_session_reused(resumed.server) == 1
                && SSL_get_verify_result(resumed.client) == X509_V_OK
                && SSL_get_verify_result(resumed.server) == X509_V_OK
                && SSL_get_negotiated_group(resumed.client) == expected_nid
                && SSL_get_negotiated_group(resumed.server) == expected_nid
                && !trace.bad && trace.client_share_seen == 1
                && trace.server_share_seen == 1
                && trace.cv[0][0] == 0 && trace.cv[1][0] == 0
                && transfer(&resumed, 1, 181) && transfer(&resumed, 0, 213)
                && exporter_matches(&resumed),
            "%s: real TCP PSK-DHE resumption retains exact fresh group shares", name);
        pair_free(&resumed);
    }
done:
    SSL_SESSION_free(session);
    pair_free(&pair);
    SSL_CTX_free(server_ctx);
    SSL_CTX_free(client_ctx);
    ERR_clear_error();
}

int main(void)
{
    FIXTURE f = { 0 };
    int ready;

    ED301V2_REQUIRE_RUNTIME_BINDING();
    ED301V2_REQUIRE_TLS_RUNTIME_BINDING();
    signal(SIGPIPE, SIG_IGN);
    ed301v2_property = ED301V2_TLS_PROP;
    f.libctx = OSSL_LIB_CTX_new();
    f.ed = ed301v2_load_named(f.libctx, &f.deflt, ED301V2_TLS_PROVIDER);
    if (f.ed != NULL)
        f.x = curve301_v2_load_checked(f.libctx, "x301_v2_tls");
    if (f.x != NULL) {
        f.ca_key = ed301v2_keygen(f.libctx);
        f.server_key = ed301v2_keygen(f.libctx);
        f.client_key = ed301v2_keygen(f.libctx);
    }
    if (f.ca_key != NULL && f.server_key != NULL && f.client_key != NULL) {
        f.ca = issue_certificate(&f, f.ca_key, "D2 ephemeral CA", 0);
        if (f.ca != NULL) {
            f.server_cert = issue_certificate(&f, f.server_key, TEST_HOST, 1);
            f.client_cert = issue_certificate(&f, f.client_key, "D2 client", 2);
        }
    }
    ready = f.ca != NULL && f.server_cert != NULL && f.client_cert != NULL;
    ED301V2_CHECK(ready, "private provider context and freshly issued certificate chain");
    if (ready) {
        run_case(&f, "raw-explicit", X301_V2_RAW_TEST_GROUP,
            X301_V2_RAW_TEST_GROUP, X301V2_TLS_RAW_GROUP_ID, 38, 0, 1);
        run_case(&f, "raw-hrr", X301_V2_RAW_TEST_GROUP,
            "*X25519:X301", X301V2_TLS_RAW_GROUP_ID, 38, 1, 1);
        run_case(&f, "hybrid-default-policy", X301_V2_DEFAULT_GROUPS,
            X301_V2_DEFAULT_GROUPS, X301V2_TLS_HYBRID_GROUP_ID, 1606, 0, 1);
        run_case(&f, "hybrid-hrr", X301_V2_DEFAULT_GROUPS,
            "*X25519:X301MLKEM1024", X301V2_TLS_HYBRID_GROUP_ID, 1606, 1, 1);
        run_case(&f, "hybrid-policy-peer-prefers-raw", X301_V2_DEFAULT_GROUPS,
            "*X301:X301MLKEM1024", X301V2_TLS_HYBRID_GROUP_ID, 1606, 1, 1);
        run_case(&f, "stock-server-default-peer-offers-raw", NULL,
            "X301:X25519", 29, 32, 1, 1);
        run_case(&f, "stock-client-default", "X301:X25519",
            NULL, 29, 32, 0, 1);
        run_case(&f, "stock-server-default-raw-only-peer", NULL,
            X301_V2_RAW_TEST_GROUP, X301V2_TLS_RAW_GROUP_ID, 38, 0, 0);
        run_case(&f, "stock-client-default-raw-only-server", X301_V2_RAW_TEST_GROUP,
            NULL, X301V2_TLS_RAW_GROUP_ID, 38, 0, 0);
        run_case(&f, "hybrid-policy-raw-only-peer", X301_V2_DEFAULT_GROUPS,
            X301_V2_RAW_TEST_GROUP, X301V2_TLS_RAW_GROUP_ID, 38, 0, 0);
    }
    X509_free(f.client_cert);
    X509_free(f.server_cert);
    X509_free(f.ca);
    EVP_PKEY_free(f.client_key);
    EVP_PKEY_free(f.server_key);
    EVP_PKEY_free(f.ca_key);
    OSSL_PROVIDER_unload(f.x);
    OSSL_PROVIDER_unload(f.ed);
    OSSL_PROVIDER_unload(f.deflt);
    OSSL_LIB_CTX_free(f.libctx);
    ED301V2_CHECK(OSSL_PROVIDER_available(NULL, ED301V2_TLS_PROVIDER) == 0
            && OSSL_PROVIDER_available(NULL, "x301_v2_tls") == 0,
        "v2 providers absent from the process default libctx");
    return ed301v2_summary("provider_tls_tcp");
}
