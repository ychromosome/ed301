/* Test-only complete-file entry point. Build separately for Ed301 and X301.
 * Formats exceed neither 8 KiB in this fixed-width test profile nor one object.
 */
#include "v2_file_boundary.h"

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *provider = NULL;
    BIO *file = NULL;
    EVP_PKEY *key = NULL;
    unsigned char input[8192];
    unsigned char extra;
    size_t length = 0;
    size_t more = 0;
    int is_public;
    int status = 1;

    ED301V2_REQUIRE_RUNTIME_BINDING();
    if ((argc != 4 && argc != 5)
            || (strcmp(argv[1], "DER") != 0 && strcmp(argv[1], "PEM") != 0)
            || (strcmp(argv[2], "private") != 0 && strcmp(argv[2], "public") != 0)) {
        fprintf(stderr, "usage: %s DER|PEM private|public FILE [TEST_PASSWORD]\n", argv[0]);
        return 2;
    }
    is_public = strcmp(argv[2], "public") == 0;
    ed301v2_property = ED301V2_TLS_PROP;
    libctx = OSSL_LIB_CTX_new();
    provider = ed301v2_load_named(libctx, &deflt, ED301V2_TLS_PROVIDER);
    file = provider == NULL ? NULL : BIO_new_file(argv[3], "rb");
    if (file == NULL || BIO_read_ex(file, input, sizeof(input), &length) != 1
            || BIO_read_ex(file, &extra, 1, &more) == 1 || more != 0 || !BIO_eof(file))
        goto done;
    key = ed301v2_keyfile_decode(libctx, input, length, argv[1], is_public,
        argc == 5 ? (const unsigned char *)argv[4] : NULL,
        argc == 5 ? strlen(argv[4]) : 0);
    if (key != NULL && OSSL_PROVIDER_available(NULL, ED301V2_TLS_PROVIDER) == 0) {
        printf("keyfile_complete=PASS algorithm=%s format=%s selection=%s\n", ED301V2_ALG, argv[1], argv[2]);
        status = 0;
    }
done:
    OPENSSL_cleanse(input, sizeof(input));
    EVP_PKEY_free(key);
    BIO_free(file);
    OSSL_PROVIDER_unload(provider);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    if (status != 0) {
        fprintf(stderr, "keyfile_complete=REJECT\n");
        ERR_print_errors_fp(stderr);
    }
    return status;
}
