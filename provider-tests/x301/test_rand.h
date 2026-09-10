/* Test-only deterministic RAND shared by raw-contract and hybrid-KAT lanes.
 * Caller supplies X301_BYTES and the hash-bound WEAK_SECRETS fixture. */
#ifndef X301_V2_TEST_RAND_H
#define X301_V2_TEST_RAND_H

#include <openssl/rand.h>
#define TEST_RAND_PROVIDER "x301_test_rand"
#define TEST_RAND_PROPERTY "provider=x301_test_rand"

typedef struct test_rand_context_st {
    int state;
} TEST_RAND_CONTEXT;

static unsigned int rand_generate_calls;
static int rand_poisoned;
static unsigned int rand_weak_remaining;


static int (*test_rand_output)(unsigned char *, size_t);

static void *test_rand_newctx(
    void *provider_context,
    void *parent,
    const OSSL_DISPATCH *parent_dispatch)
{
    TEST_RAND_CONTEXT *context = calloc(1, sizeof(*context));

    (void)provider_context;
    (void)parent;
    (void)parent_dispatch;
    if (context != NULL)
        context->state = EVP_RAND_STATE_UNINITIALISED;
    return context;
}

static void test_rand_freectx(void *context)
{
    free(context);
}

static int test_rand_instantiate(
    void *context_data,
    unsigned int strength,
    int prediction_resistance,
    const unsigned char *personalization,
    size_t personalization_length,
    const OSSL_PARAM params[])
{
    TEST_RAND_CONTEXT *context = context_data;

    (void)prediction_resistance;
    (void)personalization;
    (void)personalization_length;
    (void)params;
    if (context == NULL || strength > 256U)
        return 0;
    context->state = EVP_RAND_STATE_READY;
    return 1;
}

static int test_rand_uninstantiate(void *context_data)
{
    TEST_RAND_CONTEXT *context = context_data;

    if (context == NULL)
        return 0;
    context->state = EVP_RAND_STATE_UNINITIALISED;
    return 1;
}

static int test_rand_generate(
    void *context_data,
    unsigned char *output,
    size_t output_length,
    unsigned int strength,
    int prediction_resistance,
    const unsigned char *additional_input,
    size_t additional_input_length)
{
    TEST_RAND_CONTEXT *context = context_data;
    size_t index;

    (void)prediction_resistance;
    (void)additional_input;
    (void)additional_input_length;
    rand_generate_calls++;
    if (context == NULL || context->state != EVP_RAND_STATE_READY
            || output == NULL || strength > 256U || rand_poisoned)
        return 0;
    if (test_rand_output != NULL)
        return test_rand_output(output, output_length);
    if (rand_weak_remaining != 0 && output_length == X301_BYTES) {
        memcpy(output, WEAK_SECRETS[64U - rand_weak_remaining], X301_BYTES);
        rand_weak_remaining--;
    } else {
        for (index = 0; index < output_length; index++)
            output[index] = (unsigned char)(0xa0U + index);
    }
    return 1;
}

static int test_rand_enable_locking(void *context)
{
    return context != NULL;
}

static int test_rand_lock(void *context)
{
    return context != NULL;
}

static void test_rand_unlock(void *context)
{
    (void)context;
}

static const OSSL_PARAM *test_rand_gettable(
    void *context,
    void *provider_context)
{
    static const OSSL_PARAM parameters[] = {
        OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, NULL),
        OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
        OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
        OSSL_PARAM_END
    };

    (void)context;
    (void)provider_context;
    return parameters;
}

static int test_rand_get_params(void *context_data, OSSL_PARAM params[])
{
    TEST_RAND_CONTEXT *context = context_data;
    OSSL_PARAM *parameter;

    if (context == NULL)
        return 0;
    parameter = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
    if (parameter != NULL
            && OSSL_PARAM_set_int(parameter, context->state) != 1)
        return 0;
    parameter = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (parameter != NULL && OSSL_PARAM_set_uint(parameter, 256U) != 1)
        return 0;
    parameter = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (parameter != NULL
            && OSSL_PARAM_set_size_t(parameter, INT_MAX) != 1)
        return 0;
    return 1;
}

static const OSSL_DISPATCH TEST_RAND_FUNCTIONS[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void (*)(void))test_rand_newctx },
    { OSSL_FUNC_RAND_FREECTX, (void (*)(void))test_rand_freectx },
    { OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void))test_rand_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE,
        (void (*)(void))test_rand_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void (*)(void))test_rand_generate },
    { OSSL_FUNC_RAND_ENABLE_LOCKING,
        (void (*)(void))test_rand_enable_locking },
    { OSSL_FUNC_RAND_LOCK, (void (*)(void))test_rand_lock },
    { OSSL_FUNC_RAND_UNLOCK, (void (*)(void))test_rand_unlock },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,
        (void (*)(void))test_rand_gettable },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void))test_rand_get_params },
    { 0, NULL }
};

static const OSSL_ALGORITHM TEST_RAND_ALGORITHMS[] = {
    { "CTR-DRBG", TEST_RAND_PROPERTY, TEST_RAND_FUNCTIONS,
        "poisonable X301 contract-test RAND" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *test_rand_query(
    void *provider_context,
    int operation_id,
    int *no_cache)
{
    (void)provider_context;
    if (no_cache != NULL)
        *no_cache = 0;
    return operation_id == OSSL_OP_RAND ? TEST_RAND_ALGORITHMS : NULL;
}

static const OSSL_DISPATCH TEST_RAND_PROVIDER_DISPATCH[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION,
        (void (*)(void))test_rand_query },
    { 0, NULL }
};

static int test_rand_provider_init(
    const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *input_dispatch,
    const OSSL_DISPATCH **output_dispatch,
    void **provider_context)
{
    (void)handle;
    (void)input_dispatch;
    if (output_dispatch == NULL || provider_context == NULL)
        return 0;
    *provider_context = NULL;
    *output_dispatch = TEST_RAND_PROVIDER_DISPATCH;
    return 1;
}

#endif
