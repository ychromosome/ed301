/* Shared OSSL_PARAM helper contracts for both local provider aliases. */
#include <assert.h>
#include <string.h>
#include "../provider/crates/ed301-eddsa-provider/c/param_helpers.h"
#include "../provider/crates/x301-provider/c/param_helpers.h"

int main(void)
{
    unsigned char bytes[38] = {1};
    unsigned char output[38] = {0};
    const unsigned char *value = NULL;
    size_t length = 0;
    int number = 0;
    char text[8] = {0};
    char *pointer = NULL;
    OSSL_PARAM params[] = {OSSL_PARAM_END, OSSL_PARAM_END};
    OSSL_PARAM parameter = OSSL_PARAM_construct_int("int", &number);
    assert(ed301v2_param_set_optional_int(NULL, 2));
    assert(x301_param_set_optional_int(&parameter, 7) && number == 7);
    parameter = OSSL_PARAM_construct_utf8_string("text", text, sizeof(text));
    assert(ed301v2_param_set_optional_utf8_string(&parameter, "v2"));
    assert(strcmp(text, "v2") == 0);
    parameter = OSSL_PARAM_construct_utf8_ptr("pointer", &pointer, 0);
    assert(x301_param_set_optional_utf8_ptr(&parameter, "X301"));
    assert(strcmp(pointer, "X301") == 0);
    assert(ed301v2_param_set_optional_utf8_ptr(NULL, "Ed301"));
    parameter = OSSL_PARAM_construct_octet_string("bytes", output, sizeof(output));
    assert(x301_param_set_optional_octet_string(&parameter, bytes, sizeof(bytes)));
    assert(memcmp(bytes, output, sizeof(bytes)) == 0);
    parameter = OSSL_PARAM_construct_octet_string("bytes", output, 1);
    assert(!ed301v2_param_set_optional_octet_string(&parameter, bytes, sizeof(bytes)));
    assert(x301_param_get_strict_octet_string(NULL, "key", &value, &length, 38, 0));
    assert(value == NULL && length == 0);
    assert(!x301_param_get_strict_octet_string(NULL, "key", &value, &length, 38, 1));
    params[0] = OSSL_PARAM_construct_octet_string("key", bytes, sizeof(bytes));
    assert(ed301v2_param_get_strict_octet_string(params, "key", &value, &length, 38, 1));
    assert(value == bytes && length == 38);
    assert(x301_param_get_strict_octet_string(params, "key", &value, &length, 38, 1));
    params[0].data_size = 37;
    assert(!x301_param_get_strict_octet_string(params, "key", &value, &length, 38, 1));
    assert(value == NULL && length == 0);
    params[0].data_size = 38;
    params[0].data = NULL;
    assert(!ed301v2_param_get_strict_octet_string(params, "key", &value, &length, 38, 1));
    params[0].data = bytes;
    params[0].data_type = OSSL_PARAM_OCTET_PTR;
    assert(!x301_param_get_strict_octet_string(params, "key", &value, &length, 38, 1));
    assert(!x301_param_get_strict_octet_string(params, NULL, &value, &length, 38, 1));
    assert(!x301_param_get_strict_octet_string(params, "key", NULL, &length, 38, 1));
    return 0;
}
