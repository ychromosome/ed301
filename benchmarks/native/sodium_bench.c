#define _POSIX_C_SOURCE 200809L

/* libsodium Ed25519/X25519 reference timings for the Rust-core table. */

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sodium.h>

static volatile unsigned char sink;

static int monotonic_ns(uint64_t *value)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &now) != 0
            || now.tv_sec < 0 || now.tv_nsec < 0)
        return 0;
    *value = (uint64_t)now.tv_sec * UINT64_C(1000000000)
        + (uint64_t)now.tv_nsec;
    return 1;
}

int main(int argc, char **argv)
{
    unsigned char seed[crypto_sign_SEEDBYTES];
    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
    unsigned char secret_key[crypto_sign_SECRETKEYBYTES];
    unsigned char signature[crypto_sign_BYTES];
    unsigned char message[64];
    unsigned char x_secret[crypto_scalarmult_SCALARBYTES];
    unsigned char x_peer[crypto_scalarmult_BYTES];
    unsigned char x_output[crypto_scalarmult_BYTES];
    const char *operation;
    char *end = NULL;
    uintmax_t count;
    uint64_t started, finished;
    size_t index;
    int ok = 1;

    if (argc != 3 || sodium_init() < 0)
        return 2;
    operation = argv[1];
    errno = 0;
    count = strtoumax(argv[2], &end, 10);
    if (errno != 0 || end == argv[2] || *end != '\0' || count == 0
            || count > 100000000)
        return 2;

    for (index = 0; index < sizeof(seed); index++)
        seed[index] = (unsigned char)index;
    memset(message, 0x5a, sizeof(message));
    for (index = 0; index < sizeof(x_secret); index++)
        x_secret[index] = (unsigned char)(index + 1);
    if (crypto_sign_seed_keypair(public_key, secret_key, seed) != 0
            || crypto_sign_detached(signature, NULL, message,
                sizeof(message), secret_key) != 0
            || crypto_scalarmult_base(x_peer, seed) != 0)
        return 3;

    if (!monotonic_ns(&started))
        return 3;
    for (uintmax_t round = 0; round < count; round++) {
        if (strcmp(operation, "expand") == 0)
            ok &= crypto_sign_seed_keypair(public_key, secret_key, seed) == 0;
        else if (strcmp(operation, "sign") == 0)
            ok &= crypto_sign_detached(signature, NULL, message,
                sizeof(message), secret_key) == 0;
        else if (strcmp(operation, "verify") == 0)
            ok &= crypto_sign_verify_detached(signature, message,
                sizeof(message), public_key) == 0;
        else if (strcmp(operation, "import") == 0)
            ok &= crypto_core_ed25519_is_valid_point(public_key) == 1;
        else if (strcmp(operation, "x-public") == 0)
            ok &= crypto_scalarmult_base(x_output, x_secret) == 0;
        else if (strcmp(operation, "x-shared") == 0)
            ok &= crypto_scalarmult(x_output, x_secret, x_peer) == 0;
        else
            return 2;
        sink ^= signature[0] ^ x_output[0];
    }
    if (!monotonic_ns(&finished) || !ok)
        return 4;
    printf("count=%" PRIuMAX " total_ns=%" PRIu64 "\n",
        count, finished - started);
    return 0;
}
