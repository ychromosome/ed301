/* Run-local CSR frontend for the private-libctx test profile. Stock req/x509
 * loading helpers in the pinned apps do not preserve that context for a CSR.
 * This utility uses public OpenSSL APIs and never enables a global v2 module.
 * Issued leaves have the fixed project test DNS name, not a production CA policy.
 */
#include <errno.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include "strict_pki.h"

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *deflt = NULL, *provider = NULL;
    X509_REQ *request = NULL;
    X509 *ca = NULL, *leaf = NULL;
    EVP_PKEY *public_key = NULL, *ca_key = NULL;
    EVP_MD_CTX *sign = NULL;
    BIO *input = NULL, *output = NULL;
    int issue;
    int status = 1;
    const char *stage = "arguments";

    ED301V2_REQUIRE_RUNTIME_BINDING();
    issue = argc == 7 && strcmp(argv[1], "issue") == 0;
    if (!issue && !(argc == 3 && strcmp(argv[1], "verify") == 0)) {
        fprintf(stderr, "usage: %s verify CSR | issue CSR CA_CERT CA_KEY SERIAL OUT_CERT\n", argv[0]);
        return 2;
    }
    stage = "private provider context";
    libctx = OSSL_LIB_CTX_new();
    provider = ed301v2_load_named(libctx, &deflt, ED301V2_TLS_PROVIDER);
    if (provider == NULL)
        goto done;
    stage = "CSR loading and strict verification";
    request = X509_REQ_new_ex(libctx, NULL);
    input = BIO_new_file(argv[2], "rb");
    if (request == NULL || input == NULL || PEM_read_bio_X509_REQ(input, &request, NULL, NULL) == NULL)
        goto done;
    /* X509_REQ's nested X509_PUBKEY can retain its original default context
     * even when the request itself was allocated with new_ex. Read its
     * already parsed, profile-checked bytes and import explicitly in libctx.
     * Do not rewrite the CSR before checking its signed request bytes. */
    if (ed301v2_pki_request_is_exact(request)) {
        const unsigned char *encoded = NULL;
        int encoded_length = 0;

        if (X509_PUBKEY_get0_param(NULL, &encoded, &encoded_length, NULL,
                X509_REQ_get_X509_PUBKEY(request)) == 1
                && encoded != NULL && encoded_length == 38)
            public_key = EVP_PKEY_new_raw_public_key_ex(libctx,
                ED301V2_ALG, ED301V2_TLS_PROP, encoded, (size_t)encoded_length);
    }
    if (public_key == NULL || !ed301v2_pki_verify_request(request, public_key))
        goto done;
    BIO_free(input);
    input = NULL;
    if (!issue) {
        puts("private_csr_verify=PASS strict_profile=1");
        status = 0;
        goto done;
    }
    stage = "CA credential loading";
    ca = X509_new_ex(libctx, NULL);
    input = BIO_new_file(argv[3], "rb");
    if (ca == NULL || input == NULL || PEM_read_bio_X509(input, &ca, NULL, NULL) == NULL
            || !ed301v2_pki_certificate_is_exact(ca))
        goto done;
    BIO_free(input);
    input = BIO_new_file(argv[4], "rb");
    if (input == NULL)
        goto done;
    ca_key = PEM_read_bio_PrivateKey_ex(input, NULL, NULL, NULL, libctx, NULL);
    if (ca_key == NULL || X509_check_private_key(ca, ca_key) != 1)
        goto done;
    stage = "test leaf issuance";
    {
        char *end = NULL;
        long serial;
        X509V3_CTX extensions;
        const struct { int nid; const char *value; } profile[] = {
            { NID_basic_constraints, "critical,CA:FALSE" },
            { NID_key_usage, "critical,digitalSignature" },
            { NID_ext_key_usage, "serverAuth" },
            { NID_subject_alt_name, "DNS:server.v2.test.example" },
        };

        errno = 0;
        serial = strtol(argv[5], &end, 10);
        if (errno || end == argv[5] || *end != '\0' || serial <= 0)
            goto done;
        leaf = X509_new_ex(libctx, NULL);
        if (leaf == NULL || X509_set_version(leaf, 2) != 1
                || ASN1_INTEGER_set(X509_get_serialNumber(leaf), serial) != 1
                || X509_gmtime_adj(X509_getm_notBefore(leaf), -60) == NULL
                || X509_gmtime_adj(X509_getm_notAfter(leaf), 3600) == NULL
                || X509_set_subject_name(leaf, X509_REQ_get_subject_name(request)) != 1
                || X509_set_issuer_name(leaf, X509_get_subject_name(ca)) != 1
                || X509_set_pubkey(leaf, public_key) != 1)
            goto done;
        X509V3_set_ctx_nodb(&extensions);
        X509V3_set_ctx(&extensions, ca, leaf, NULL, NULL, 0);
        for (size_t i = 0; i < sizeof(profile) / sizeof(profile[0]); i++) {
            X509_EXTENSION *extension = X509V3_EXT_conf_nid(NULL, &extensions,
                profile[i].nid, profile[i].value);
            int added = extension != NULL && X509_add_ext(leaf, extension, -1) == 1;

            X509_EXTENSION_free(extension);
            if (!added)
                goto done;
        }
    }
    sign = EVP_MD_CTX_new();
    if (sign == NULL || EVP_DigestSignInit_ex(sign, NULL, NULL, libctx, ED301V2_TLS_PROP, ca_key, NULL) != 1
            || X509_sign_ctx(leaf, sign) <= 0 || !ed301v2_pki_verify_certificate(leaf, ca_key))
        goto done;
    output = BIO_new_file(argv[6], "wx");
    if (output == NULL || PEM_write_bio_X509(output, leaf) != 1 || BIO_flush(output) != 1)
        goto done;
    puts("private_csr_issue=PASS strict_profile=1 test_dns=server.v2.test.example");
    status = 0;
done:
    if (status != 0) {
        fprintf(stderr, "private CSR frontend failed at %s\n", stage);
        ERR_print_errors_fp(stderr);
    }
    if (OSSL_PROVIDER_available(NULL, ED301V2_TLS_PROVIDER) != 0)
        status = 1;
    BIO_free(output);
    BIO_free(input);
    EVP_MD_CTX_free(sign);
    EVP_PKEY_free(ca_key);
    EVP_PKEY_free(public_key);
    X509_free(leaf);
    X509_free(ca);
    X509_REQ_free(request);
    OSSL_PROVIDER_unload(provider);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    return status;
}
