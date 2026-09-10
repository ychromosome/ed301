/* Same EVP encoder/decoder object path for every selected algorithm.
 * Each timed operation includes codec-context allocation and teardown.
 * Fresh key generation and the first roundtrip check are outside the timer.
 * Complete-file policy and malformed-input tests are separate, untimed gates.
 */
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>

static const unsigned char password[] = "D2 codec benchmark test password";
static volatile unsigned char sink;

static int clock_ns(uint64_t *result)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &now) != 0 || now.tv_sec < 0)
        return 0;
    *result = (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
    return 1;
}

static int encode(EVP_PKEY *key, const char *properties, const char *format,
    int is_public, int encrypted, unsigned char **data, size_t *length)
{
    OSSL_ENCODER_CTX *ctx = OSSL_ENCODER_CTX_new_for_pkey(key,
        is_public ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR, format,
        is_public ? "SubjectPublicKeyInfo" : encrypted ? "EncryptedPrivateKeyInfo" : "PrivateKeyInfo",
        properties);
    int ok = ctx != NULL
        && (!encrypted || (OSSL_ENCODER_CTX_set_cipher(ctx, "AES-256-CBC", NULL) == 1
            && OSSL_ENCODER_CTX_set_passphrase(ctx, password, sizeof(password) - 1) == 1))
        && OSSL_ENCODER_to_data(ctx, data, length) == 1;

    OSSL_ENCODER_CTX_free(ctx);
    return ok;
}

static EVP_PKEY *decode(OSSL_LIB_CTX *libctx, const char *algorithm,
    const char *format, int is_public, int encrypted,
    const unsigned char *data, size_t length)
{
    EVP_PKEY *key = NULL;
    OSSL_DECODER_CTX *ctx = OSSL_DECODER_CTX_new_for_pkey(&key, format,
        NULL, algorithm, is_public ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR, libctx, NULL);
    const unsigned char *cursor = data;
    size_t remaining = length;

    if (ctx == NULL || (encrypted && OSSL_DECODER_CTX_set_passphrase(ctx,
            password, sizeof(password) - 1) != 1)
            || OSSL_DECODER_from_data(ctx, &cursor, &remaining) != 1
            || remaining != 0 || key == NULL || !EVP_PKEY_is_a(key, algorithm)) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    OSSL_DECODER_CTX_free(ctx);
    return key;
}

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *provider = NULL;
    EVP_PKEY_CTX *keygen = NULL;
    EVP_PKEY *key = NULL;
    EVP_PKEY *decoded = NULL;
    unsigned char *data = NULL;
    size_t length = 0;
    uint64_t start, end;
    unsigned long long count;
    char *tail = NULL;
    int is_public;
    int encrypted;
    int encoding;
    int status = 1;
    const char *stage = "arguments";

    if (argc != 9)
        return 2;
    errno = 0;
    count = strtoull(argv[8], &tail, 10);
    if (errno != 0 || tail == argv[8] || *tail != '\0' || count == 0 || count > 10000000)
        return 2;
    encoding = strcmp(argv[1], "encode") == 0;
    is_public = strcmp(argv[2], "public") == 0;
    encrypted = strcmp(argv[2], "encrypted") == 0;
    if ((!encoding && strcmp(argv[1], "decode") != 0)
            || (!is_public && !encrypted && strcmp(argv[2], "private") != 0)
            || (strcmp(argv[3], "DER") != 0 && strcmp(argv[3], "PEM") != 0))
        return 2;
    stage = "private context and provider";
    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL || OSSL_PROVIDER_set_default_search_path(libctx, argv[6]) != 1
            || (deflt = OSSL_PROVIDER_load(libctx, "default")) == NULL
            || (strcmp(argv[7], "-") != 0 && (provider = OSSL_PROVIDER_load(libctx, argv[7])) == NULL))
        goto done;
    stage = "key generation";
    keygen = EVP_PKEY_CTX_new_from_name(libctx, argv[4], argv[5]);
    if (keygen == NULL || EVP_PKEY_keygen_init(keygen) != 1
            || EVP_PKEY_generate(keygen, &key) != 1)
        goto done;
    EVP_PKEY_CTX_free(keygen);
    keygen = NULL;
    stage = "initial encoding";
    if (!encode(key, argv[5], argv[3], is_public, encrypted, &data, &length))
        goto done;
    stage = "initial decoding";
    decoded = decode(libctx, argv[4], argv[3], is_public, encrypted, data, length);
    if (decoded == NULL)
        goto done;
    stage = "roundtrip equality";
    if (EVP_PKEY_eq(key, decoded) != 1)
        goto done;
    EVP_PKEY_free(decoded);
    decoded = NULL;
    stage = "measurement";
    if (!clock_ns(&start))
        goto done;
    for (unsigned long long i = 0; i < count; i++) {
        if (encoding) {
            unsigned char *output = NULL;
            size_t output_length = 0;
            int ok = encode(key, argv[5], argv[3], is_public, encrypted, &output, &output_length);

            if (!ok || output_length == 0) {
                OPENSSL_clear_free(output, output_length);
                goto done;
            }
            sink ^= output[0];
            OPENSSL_clear_free(output, output_length);
        } else {
            decoded = decode(libctx, argv[4], argv[3], is_public, encrypted, data, length);
            if (decoded == NULL)
                goto done;
            sink ^= (unsigned char)(uintptr_t)decoded;
            EVP_PKEY_free(decoded);
            decoded = NULL;
        }
    }
    if (!clock_ns(&end) || end < start)
        goto done;
    printf("RESULT operation=%s-%s-%s algorithm=%s count=%llu total_ns=%" PRIu64 " mean_ns=%.3f\n",
        argv[1], argv[2], argv[3], argv[4], count, end - start, (double)(end - start) / (double)count);
    status = 0;
done:
    if (status) {
        fprintf(stderr, "codec benchmark failed at %s\n", stage);
        ERR_print_errors_fp(stderr);
    }
    OPENSSL_clear_free(data, length);
    EVP_PKEY_free(decoded);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(keygen);
    OSSL_PROVIDER_unload(provider);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    return status;
}
