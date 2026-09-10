/* Use OpenSSL's native PKCS12_parse with a context-bound PKCS12 object.
 * No replacement bag parser or cryptography; local test files only.
 */
#include <openssl/encoder.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include "strict_pki.h"

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *deflt = NULL, *provider = NULL;
    PKCS12 *container = NULL;
    EVP_PKEY *key = NULL;
    X509 *certificate = NULL;
    STACK_OF(X509) *chain = NULL;
    BIO *input = NULL, *key_output = NULL, *cert_output = NULL;
    OSSL_ENCODER_CTX *encoder = NULL;
    int status = 1;
    const char *stage = "arguments";

    ED301V2_REQUIRE_RUNTIME_BINDING();
    if (argc != 5) {
        fprintf(stderr, "usage: %s PKCS12 TEST_PASSWORD OUT_KEY OUT_CERT\n", argv[0]);
        return 2;
    }
    stage = "private provider context";
    libctx = OSSL_LIB_CTX_new();
    provider = ed301v2_load_named(libctx, &deflt, ED301V2_TLS_PROVIDER);
    if (provider == NULL)
        goto done;
    stage = "context-bound PKCS12 decoding";
    container = PKCS12_init_ex(NID_pkcs7_data, libctx, NULL);
    input = BIO_new_file(argv[1], "rb");
    if (container == NULL || input == NULL || d2i_PKCS12_bio(input, &container) == NULL)
        goto done;
    stage = "PKCS12 MAC and native parsing";
    if (PKCS12_mac_present(container) != 1 || PKCS12_verify_mac(container, argv[2], -1) != 1
            || PKCS12_parse(container, argv[2], &key, &certificate, &chain) != 1
            || key == NULL || certificate == NULL
            || !ed301v2_pki_certificate_is_exact(certificate)
            || X509_check_private_key(certificate, key) != 1)
        goto done;
    stage = "private key and leaf export";
    encoder = OSSL_ENCODER_CTX_new_for_pkey(key, EVP_PKEY_KEYPAIR, "PEM", "PrivateKeyInfo", ED301V2_TLS_PROP);
    key_output = BIO_new_file(argv[3], "wx");
    cert_output = BIO_new_file(argv[4], "wx");
    if (encoder == NULL || key_output == NULL || cert_output == NULL
            || OSSL_ENCODER_to_bio(encoder, key_output) != 1
            || PEM_write_bio_X509(cert_output, certificate) != 1
            || BIO_flush(key_output) != 1 || BIO_flush(cert_output) != 1)
        goto done;
    printf("private_pkcs12_parse=PASS mac=1 key_matches_leaf=1 extra_certificates=%d\n", sk_X509_num(chain));
    status = 0;
done:
    if (status != 0) {
        fprintf(stderr, "private PKCS12 frontend failed at %s\n", stage);
        ERR_print_errors_fp(stderr);
    }
    if (OSSL_PROVIDER_available(NULL, ED301V2_TLS_PROVIDER) != 0)
        status = 1;
    OSSL_ENCODER_CTX_free(encoder);
    BIO_free(cert_output); BIO_free(key_output); BIO_free(input);
    sk_X509_pop_free(chain, X509_free);
    X509_free(certificate); EVP_PKEY_free(key); PKCS12_free(container);
    OSSL_PROVIDER_unload(provider); OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    return status;
}
