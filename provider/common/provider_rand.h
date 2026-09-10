/* Shared provider-owned OpenSSL DRBGs from the bound Ed301-v1 adapter. */
#ifndef CURVE301_PROVIDER_RAND_H
#define CURVE301_PROVIDER_RAND_H

static EVP_RAND_CTX *curve301_drbg_new(OSSL_LIB_CTX *libctx)
{
    EVP_RAND_CTX *parent;
    EVP_RAND *rand;
    EVP_RAND_CTX *drbg;
    OSSL_PARAM parameters[2];

    parent = RAND_get0_primary(libctx);
    if (parent == NULL)
        return NULL;
    rand = EVP_RAND_fetch(libctx, "CTR-DRBG", NULL);
    if (rand == NULL)
        return NULL;
    drbg = EVP_RAND_CTX_new(rand, parent);
    EVP_RAND_free(rand);
    if (drbg == NULL)
        return NULL;
    parameters[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_DRBG_PARAM_CIPHER, (char *)"AES-256-CTR", 0);
    parameters[1] = OSSL_PARAM_construct_end();
    if (EVP_RAND_enable_locking(drbg) != 1
            || EVP_RAND_instantiate(drbg, CURVE301_SECURITY_BITS, 0,
                NULL, 0, parameters) != 1) {
        EVP_RAND_CTX_free(drbg);
        return NULL;
    }
    return drbg;
}

static void curve301_drbg_free(EVP_RAND_CTX *drbg)
{
    if (drbg == NULL)
        return;
    (void)EVP_RAND_uninstantiate(drbg);
    EVP_RAND_CTX_free(drbg);
}

static EVP_RAND_CTX *curve301_drbg_get(
    CURVE301_PROVIDER_CONTEXT *provider,
    int private_output)
{
    EVP_RAND_CTX **slot;
    EVP_RAND_CTX *drbg;

    if (provider == NULL || provider->libctx == NULL
            || provider->drbg_lock == NULL)
        return NULL;
    slot = private_output
        ? &provider->private_drbg : &provider->public_drbg;
    if (CRYPTO_THREAD_read_lock(provider->drbg_lock) != 1)
        return NULL;
    drbg = *slot;
    CRYPTO_THREAD_unlock(provider->drbg_lock);
    if (drbg != NULL)
        return drbg;
    if (CRYPTO_THREAD_write_lock(provider->drbg_lock) != 1)
        return NULL;
    drbg = *slot;
    if (drbg == NULL) {
        drbg = curve301_drbg_new(provider->libctx);
        *slot = drbg;
    }
    CRYPTO_THREAD_unlock(provider->drbg_lock);
    return drbg;
}

static int curve301_fill_random(
    CURVE301_PROVIDER_CONTEXT *provider,
    unsigned char *output,
    size_t output_length,
    int private_output)
{
    EVP_RAND_CTX *drbg = curve301_drbg_get(provider, private_output);

    return drbg != NULL && output != NULL
        && EVP_RAND_generate(drbg, output, output_length,
            CURVE301_SECURITY_BITS, 0, NULL, 0) == 1;
}


#endif
