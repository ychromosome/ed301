/* Shared v2 fixed-width key codecs, extracted from the bound Ed301-v1
 * adapter. Profile bindings supply names, OIDs, byte sizes and KEYMGMT.
 * OpenSSL owns PEM, PKCS#8 encryption and generic decrypt chains. */
#ifndef CURVE301_PROVIDER_CODEC_H
#define CURVE301_PROVIDER_CODEC_H

typedef enum curve301_codec_structure_st {
    CURVE301_CODEC_PRIVATE_KEY_INFO = 1,
    CURVE301_CODEC_SUBJECT_PUBLIC_KEY_INFO = 2,
    CURVE301_CODEC_KEY_TEXT = 3,
    CURVE301_CODEC_ENCRYPTED_PRIVATE_KEY_INFO = 4
} CURVE301_CODEC_STRUCTURE;

typedef enum curve301_codec_format_st {
    CURVE301_CODEC_FORMAT_DER = 1,
    CURVE301_CODEC_FORMAT_PEM = 2,
    CURVE301_CODEC_FORMAT_TEXT = 3
} CURVE301_CODEC_FORMAT;

typedef struct curve301_codec_context_st {
    CURVE301_PROVIDER_CONTEXT *provider;
    CURVE301_CODEC_STRUCTURE structure;
    CURVE301_CODEC_FORMAT format;
    EVP_CIPHER *cipher;
    char *cipher_properties;
    size_t cipher_properties_length;
    int cipher_intent;
    int selection;
    int invalid;
} CURVE301_CODEC_CONTEXT;

static CURVE301_CODEC_CONTEXT *curve301_codec_new_context(
    void *provider_context,
    CURVE301_CODEC_STRUCTURE structure,
    CURVE301_CODEC_FORMAT format)
{
    CURVE301_PROVIDER_CONTEXT *provider = provider_context;
    CURVE301_CODEC_CONTEXT *codec;

    if (provider == NULL || provider->bio_write_ex == NULL)
        return NULL;
    codec = curve301_allocate(provider, sizeof(*codec));
    if (codec == NULL) {
        curve301_raise(provider, CURVE301_R_ALLOCATION_FAILURE,
            CURVE301_DISPLAY_NAME " codec context allocation failed");
        return NULL;
    }
    codec->provider = provider;
    codec->structure = structure;
    codec->format = format;
    codec->cipher = NULL;
    codec->cipher_properties = NULL;
    codec->cipher_properties_length = 0;
    codec->cipher_intent = 0;
    codec->selection = 0;
    codec->invalid = 0;
    return codec;
}

static void *curve301_pkcs8_der_codec_new_context(void *provider_context)
{
    return curve301_codec_new_context(
        provider_context,
        CURVE301_CODEC_PRIVATE_KEY_INFO,
        CURVE301_CODEC_FORMAT_DER);
}

static void *curve301_pkcs8_pem_codec_new_context(void *provider_context)
{
    return curve301_codec_new_context(
        provider_context,
        CURVE301_CODEC_PRIVATE_KEY_INFO,
        CURVE301_CODEC_FORMAT_PEM);
}

static void *curve301_encrypted_pkcs8_der_codec_new_context(
    void *provider_context)
{
    return curve301_codec_new_context(
        provider_context,
        CURVE301_CODEC_ENCRYPTED_PRIVATE_KEY_INFO,
        CURVE301_CODEC_FORMAT_DER);
}

static void *curve301_encrypted_pkcs8_pem_codec_new_context(
    void *provider_context)
{
    return curve301_codec_new_context(
        provider_context,
        CURVE301_CODEC_ENCRYPTED_PRIVATE_KEY_INFO,
        CURVE301_CODEC_FORMAT_PEM);
}

static void *curve301_spki_der_codec_new_context(void *provider_context)
{
    return curve301_codec_new_context(
        provider_context,
        CURVE301_CODEC_SUBJECT_PUBLIC_KEY_INFO,
        CURVE301_CODEC_FORMAT_DER);
}

static void *curve301_spki_pem_codec_new_context(void *provider_context)
{
    return curve301_codec_new_context(
        provider_context,
        CURVE301_CODEC_SUBJECT_PUBLIC_KEY_INFO,
        CURVE301_CODEC_FORMAT_PEM);
}

#if CURVE301_HAS_TEXT_ENCODER
static void *curve301_text_codec_new_context(void *provider_context)
{
    return curve301_codec_new_context(
        provider_context,
        CURVE301_CODEC_KEY_TEXT,
        CURVE301_CODEC_FORMAT_TEXT);
}
#endif

static void curve301_codec_free_context(void *codec_context)
{
    CURVE301_CODEC_CONTEXT *codec = codec_context;
    CURVE301_PROVIDER_CONTEXT *provider;

    if (codec == NULL)
        return;
    provider = codec->provider;
    EVP_CIPHER_free(codec->cipher);
    codec->cipher = NULL;
    curve301_clear_free(provider, codec->cipher_properties,
        codec->cipher_properties_length);
    codec->cipher_properties = NULL;
    codec->cipher_properties_length = 0;
    curve301_clear_free(provider, codec, sizeof(*codec));
}

static int curve301_codec_is_private(const CURVE301_CODEC_CONTEXT *codec)
{
    return codec != NULL
        && (codec->structure == CURVE301_CODEC_PRIVATE_KEY_INFO
            || codec->structure
                == CURVE301_CODEC_ENCRYPTED_PRIVATE_KEY_INFO);
}

static int curve301_codec_required_selection(
    const CURVE301_CODEC_CONTEXT *codec)
{
    if (codec == NULL)
        return 0;
    if (curve301_codec_is_private(codec))
        return OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
    if (codec->structure == CURVE301_CODEC_SUBJECT_PUBLIC_KEY_INFO)
        return OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
    if (codec->structure == CURVE301_CODEC_KEY_TEXT)
        return OSSL_KEYMGMT_SELECT_KEYPAIR;
    return 0;
}

static int curve301_codec_does_selection(void *codec_context, int selection)
{
    const CURVE301_CODEC_CONTEXT *codec = codec_context;

    if (codec == NULL)
        return 0;
    if (curve301_codec_is_private(codec))
        return selection == 0
            || (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
    if (codec->structure == CURVE301_CODEC_SUBJECT_PUBLIC_KEY_INFO)
        return selection == 0
            || ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0
                && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0);
    if (codec->structure == CURVE301_CODEC_KEY_TEXT)
        return selection == 0
            || (curve301_selection_supported(selection)
                && (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0);
    return 0;
}

static int curve301_private_codec_does_selection(
    void *provider_context,
    int selection)
{
    (void)provider_context;
    return selection == 0
        || (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
}

static int curve301_public_codec_does_selection(
    void *provider_context,
    int selection)
{
    (void)provider_context;
    return selection == 0
        || ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0
                && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0);
}

#if CURVE301_HAS_TEXT_ENCODER
static int curve301_text_codec_does_selection(
    void *provider_context,
    int selection)
{
    (void)provider_context;
    return selection == 0
        || (curve301_selection_supported(selection)
            && (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0);
}
#endif

static const OSSL_PARAM *curve301_private_codec_settable_ctx_params(
    void *provider_context)
{
    static const OSSL_PARAM parameters[] = {
        OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_END
    };

    (void)provider_context;
    return parameters;
}

static int curve301_private_codec_set_ctx_params(
    void *codec_context,
    const OSSL_PARAM parameters[])
{
    CURVE301_CODEC_CONTEXT *codec = codec_context;
    const OSSL_PARAM *cipher_parameter;
    const OSSL_PARAM *properties_parameter;
    const char *cipher_name = NULL;
    const char *properties = NULL;
    EVP_CIPHER *cipher;
    char *properties_copy = NULL;
    size_t properties_length = 0;

    if (!curve301_codec_is_private(codec) || codec->provider == NULL
            || codec->provider->libctx == NULL)
        return 0;
    if (parameters == NULL)
        return 1;
    cipher_parameter = OSSL_PARAM_locate_const(
        parameters, OSSL_ENCODER_PARAM_CIPHER);
    if (cipher_parameter == NULL)
        return 1;
    properties_parameter = OSSL_PARAM_locate_const(
        parameters, OSSL_ENCODER_PARAM_PROPERTIES);
    if (!OSSL_PARAM_get_utf8_string_ptr(cipher_parameter, &cipher_name)
            || (properties_parameter != NULL
                && !OSSL_PARAM_get_utf8_string_ptr(
                    properties_parameter, &properties))) {
        codec->invalid = 1;
        curve301_raise(codec->provider, CURVE301_R_SERIALIZATION_FAILURE,
            "invalid encrypted PKCS#8 cipher parameters");
        return 0;
    }
    if (cipher_name == NULL) {
        EVP_CIPHER_free(codec->cipher);
        codec->cipher = NULL;
        curve301_clear_free(codec->provider, codec->cipher_properties,
            codec->cipher_properties_length);
        codec->cipher_properties = NULL;
        codec->cipher_properties_length = 0;
        codec->cipher_intent = 0;
        codec->invalid = 0;
        return 1;
    }
    codec->cipher_intent = 1;
    cipher = EVP_CIPHER_fetch(
        codec->provider->libctx, cipher_name, properties);
    if (cipher == NULL) {
        codec->invalid = 1;
        curve301_raise(codec->provider, CURVE301_R_SERIALIZATION_FAILURE,
            "encrypted PKCS#8 cipher fetch failed");
        return 0;
    }
    if (properties != NULL) {
        properties_length = strlen(properties) + 1;
        properties_copy = curve301_allocate(
            codec->provider, properties_length);
        if (properties_copy == NULL) {
            EVP_CIPHER_free(cipher);
            codec->invalid = 1;
            curve301_raise(codec->provider, CURVE301_R_ALLOCATION_FAILURE,
                "encrypted PKCS#8 property allocation failed");
            return 0;
        }
        memcpy(properties_copy, properties, properties_length);
    }
    EVP_CIPHER_free(codec->cipher);
    curve301_clear_free(codec->provider, codec->cipher_properties,
        codec->cipher_properties_length);
    codec->cipher = cipher;
    codec->cipher_properties = properties_copy;
    codec->cipher_properties_length = properties_length;
    codec->invalid = 0;
    return 1;
}

static const unsigned char *curve301_codec_prefix(
    const CURVE301_CODEC_CONTEXT *codec,
    size_t *prefix_length,
    size_t *encoded_length)
{
    if (prefix_length == NULL || encoded_length == NULL || codec == NULL)
        return NULL;

    if (curve301_codec_is_private(codec)) {
        *prefix_length = sizeof(CURVE301_PKCS8_PREFIX);
        *encoded_length = sizeof(CURVE301_PKCS8_PREFIX)
            + CURVE301_SEED_BYTES;
        return CURVE301_PKCS8_PREFIX;
    }
    if (codec->structure == CURVE301_CODEC_SUBJECT_PUBLIC_KEY_INFO) {
        *prefix_length = sizeof(CURVE301_SPKI_PREFIX);
        *encoded_length = sizeof(CURVE301_SPKI_PREFIX)
            + CURVE301_PUBLIC_KEY_BYTES;
        return CURVE301_SPKI_PREFIX;
    }
    return NULL;
}

static void curve301_codec_cleanse(
    const CURVE301_CODEC_CONTEXT *codec,
    unsigned char *buffer,
    size_t buffer_length)
{
    if (codec == NULL || codec->provider == NULL || buffer == NULL
            || codec->provider->rust == NULL)
        return;
    codec->provider->rust->cleanse(buffer, buffer_length);
}

static int curve301_codec_write_all(
    const CURVE301_CODEC_CONTEXT *codec,
    OSSL_CORE_BIO *output,
    const unsigned char *data,
    size_t data_length)
{
    size_t offset = 0;

    if (codec == NULL || codec->provider == NULL
            || codec->provider->bio_write_ex == NULL || output == NULL
            || (data == NULL && data_length != 0))
        return 0;
    while (offset < data_length) {
        size_t written = 0;

        if (codec->provider->bio_write_ex(
                output,
                data + offset,
                data_length - offset,
                &written) != 1
                || written == 0 || written > data_length - offset)
            return 0;
        offset += written;
    }
    return 1;
}

#if CURVE301_HAS_TEST_DECODER
static int curve301_codec_read_exact(
    const CURVE301_CODEC_CONTEXT *codec,
    OSSL_CORE_BIO *input,
    unsigned char *data,
    size_t data_length)
{
    size_t offset = 0;

    if (codec == NULL || codec->provider == NULL
            || codec->provider->bio_read_ex == NULL || input == NULL
            || (data == NULL && data_length != 0))
        return 0;
    while (offset < data_length) {
        size_t read_length = 0;

        if (codec->provider->bio_read_ex(
                input,
                data + offset,
                data_length - offset,
                &read_length) != 1
                || read_length == 0 || read_length > data_length - offset)
            return 0;
        offset += read_length;
    }
    return 1;
}

/*
 * Decoder composition is transactional.  OpenSSL's decoder framework
 * supplies a seekable core BIO (wrapping an unseekable source in its bounded
 * read-buffer BIO).  Prove that contract before consuming anything, and
 * restore the checkpoint whenever this candidate has not positively matched
 * the Ed301 OID.  A retry or short read therefore leaves the next attempt at
 * the original byte instead of retaining a partial parser state.
 */
static int curve301_codec_checkpoint(
    const CURVE301_CODEC_CONTEXT *codec,
    OSSL_CORE_BIO *input,
    long *position)
{
    long current;

    if (codec == NULL || codec->provider == NULL
            || codec->provider->bio_ctrl == NULL || input == NULL
            || position == NULL)
        return 0;
    current = codec->provider->bio_ctrl(
        input, BIO_C_FILE_TELL, 0, NULL);
    if (current < 0)
        return 0;
    (void)codec->provider->bio_ctrl(
        input, BIO_C_FILE_SEEK, current, NULL);
    if (codec->provider->bio_ctrl(
            input, BIO_C_FILE_TELL, 0, NULL) != current)
        return 0;
    *position = current;
    return 1;
}

static int curve301_codec_restore(
    const CURVE301_CODEC_CONTEXT *codec,
    OSSL_CORE_BIO *input,
    long position)
{
    if (codec == NULL || codec->provider == NULL
            || codec->provider->bio_ctrl == NULL || input == NULL
            || position < 0)
        return 0;
    (void)codec->provider->bio_ctrl(
        input, BIO_C_FILE_SEEK, position, NULL);
    return codec->provider->bio_ctrl(
        input, BIO_C_FILE_TELL, 0, NULL) == position;
}

static int curve301_codec_has_target_oid(
    const CURVE301_CODEC_CONTEXT *codec,
    const unsigned char *encoded,
    size_t encoded_length)
{
    const unsigned char *prefix;
    size_t prefix_length = 0;
    size_t expected_length = 0;
    size_t oid_offset;

    prefix = curve301_codec_prefix(codec, &prefix_length, &expected_length);
    if (prefix == NULL)
        return 0;
    oid_offset =
        codec->structure == CURVE301_CODEC_PRIVATE_KEY_INFO ? 7 : 4;
    return prefix_length >= oid_offset + CURVE301_OID_TLV_BYTES
        && encoded_length >= oid_offset + CURVE301_OID_TLV_BYTES
        && memcmp(
            encoded + oid_offset,
            prefix + oid_offset,
            CURVE301_OID_TLV_BYTES) == 0;
}
#endif

static int curve301_codec_write_pem(
    const CURVE301_CODEC_CONTEXT *codec,
    OSSL_CORE_BIO *output,
    const unsigned char *der,
    size_t der_length)
{
    BIO *bio = NULL;
    const char *name;
    int result = 0;

    if (codec == NULL || codec->provider == NULL
            || codec->provider->libctx == NULL || output == NULL || der == NULL
            || der_length > LONG_MAX)
        return 0;
    if (codec->structure == CURVE301_CODEC_PRIVATE_KEY_INFO)
        name = PEM_STRING_PKCS8INF;
    else if (codec->structure == CURVE301_CODEC_SUBJECT_PUBLIC_KEY_INFO)
        name = PEM_STRING_PUBLIC;
    else
        return 0;

    bio = BIO_new_from_core_bio(codec->provider->libctx, output);
    if (bio != NULL)
        result = PEM_write_bio(bio, name, "", der, (long)der_length);
    BIO_free(bio);
    return result;
}

/* OpenSSL's Ed448 encoder pattern, using only public PKCS#8 APIs. */
static int curve301_codec_write_encrypted_pkcs8(
    const CURVE301_CODEC_CONTEXT *codec,
    OSSL_CORE_BIO *output,
    const unsigned char *der,
    size_t der_length,
    OSSL_PASSPHRASE_CALLBACK *passphrase_callback,
    void *passphrase_argument)
{
    char passphrase[PEM_BUFSIZE] = { 0 };
    unsigned char salt[CURVE301_PKCS8_SALT_BYTES] = { 0 };
    unsigned char iv[EVP_MAX_IV_LENGTH] = { 0 };
    size_t passphrase_length = 0;
    const unsigned char *cursor = der;
    PKCS8_PRIV_KEY_INFO *private_key_info = NULL;
    X509_ALGOR *pbe = NULL;
    X509_SIG *encrypted = NULL;
    BIO *bio = NULL;
    int iv_length;
    int result = 0;

    if (codec == NULL || codec->provider == NULL
            || codec->provider->libctx == NULL || codec->cipher == NULL
            || output == NULL || der == NULL || der_length > LONG_MAX
            || passphrase_callback == NULL)
        goto cleanup;
    private_key_info = d2i_PKCS8_PRIV_KEY_INFO(
        NULL, &cursor, (long)der_length);
    if (private_key_info == NULL || cursor != der + der_length
            || passphrase_callback(passphrase, sizeof(passphrase),
                &passphrase_length, NULL, passphrase_argument) != 1
            || passphrase_length > sizeof(passphrase)
            || passphrase_length > INT_MAX)
        goto cleanup;
    iv_length = EVP_CIPHER_get_iv_length(codec->cipher);
    if (iv_length <= 0 || (size_t)iv_length > sizeof(iv)
            || !curve301_fill_random(
                codec->provider, salt, sizeof(salt), 0)
            || !curve301_fill_random(
                codec->provider, iv, (size_t)iv_length, 0))
        goto cleanup;
    pbe = PKCS5_pbe2_set_iv_ex(codec->cipher, PKCS5_DEFAULT_ITER,
        salt, (int)sizeof(salt), iv, -1, codec->provider->libctx);
    if (pbe == NULL)
        goto cleanup;
    encrypted = PKCS8_set0_pbe_ex(passphrase, (int)passphrase_length,
        private_key_info, pbe, codec->provider->libctx,
        codec->cipher_properties);
    if (encrypted == NULL)
        goto cleanup;
    pbe = NULL;
    bio = BIO_new_from_core_bio(codec->provider->libctx, output);
    if (bio == NULL)
        goto cleanup;
    if (codec->format == CURVE301_CODEC_FORMAT_DER)
        result = i2d_PKCS8_bio(bio, encrypted);
    else if (codec->format == CURVE301_CODEC_FORMAT_PEM)
        result = PEM_write_bio_PKCS8(bio, encrypted);

cleanup:
    BIO_free(bio);
    X509_SIG_free(encrypted);
    X509_ALGOR_free(pbe);
    PKCS8_PRIV_KEY_INFO_free(private_key_info);
    curve301_codec_cleanse(codec, salt, sizeof(salt));
    curve301_codec_cleanse(codec, iv, sizeof(iv));
    curve301_codec_cleanse(
        codec, (unsigned char *)passphrase, sizeof(passphrase));
    return result;
}

static int curve301_codec_get_key_bytes(
    const CURVE301_CODEC_CONTEXT *codec,
    const void *key_data,
    CURVE301_CODEC_STRUCTURE component,
    unsigned char output[CURVE301_SEED_BYTES])
{
    const CURVE301_KEY *key = key_data;

    if (codec == NULL || codec->provider == NULL || key == NULL
            || output == NULL || key->provider != codec->provider
            || key->inner == NULL || codec->provider->rust == NULL)
        return 0;
    if (component == CURVE301_CODEC_PRIVATE_KEY_INFO
            || component == CURVE301_CODEC_ENCRYPTED_PRIVATE_KEY_INFO)
        return codec->provider->rust->key_get_private(
            key->inner, output, CURVE301_SEED_BYTES);
    if (component == CURVE301_CODEC_SUBJECT_PUBLIC_KEY_INFO)
        return codec->provider->rust->key_get_public(
            key->inner, output, CURVE301_PUBLIC_KEY_BYTES);
    return 0;
}

#if CURVE301_HAS_TEXT_ENCODER
static int curve301_codec_print_labeled_bytes(
    BIO *output,
    const char *label,
    const unsigned char *bytes,
    size_t length)
{
    size_t index;

    if (output == NULL || label == NULL || bytes == NULL
            || BIO_printf(output, "%s\n", label) <= 0)
        return 0;
    for (index = 0; index < length; index++) {
        if (index % 16 == 0) {
            if (index != 0 && BIO_printf(output, "\n") <= 0)
                return 0;
            if (BIO_printf(output, "    ") <= 0)
                return 0;
        }
        if (BIO_printf(output, "%02x%s", (unsigned int)bytes[index],
                index + 1 == length ? "" : ":") <= 0)
            return 0;
    }
    return BIO_printf(output, "\n") > 0;
}

static int curve301_codec_write_text(
    const CURVE301_CODEC_CONTEXT *codec,
    OSSL_CORE_BIO *output,
    const void *key_data,
    int selection)
{
    unsigned char private_key[CURVE301_SEED_BYTES] = { 0 };
    unsigned char public_key[CURVE301_PUBLIC_KEY_BYTES] = { 0 };
    BIO *bio = NULL;
    int wants_private;
    int result = 0;

    if (codec == NULL || codec->provider == NULL
            || codec->provider->libctx == NULL || output == NULL
            || key_data == NULL)
        goto cleanup;
    if (selection == 0)
        selection = OSSL_KEYMGMT_SELECT_KEYPAIR;
    wants_private = curve301_wants_private(selection);
    if (!wants_private && !curve301_wants_public(selection))
        goto cleanup;
    if (wants_private
            && !curve301_codec_get_key_bytes(codec, key_data,
                CURVE301_CODEC_PRIVATE_KEY_INFO, private_key))
        goto cleanup;
    if (!curve301_codec_get_key_bytes(codec, key_data,
            CURVE301_CODEC_SUBJECT_PUBLIC_KEY_INFO, public_key))
        goto cleanup;

    bio = BIO_new_from_core_bio(codec->provider->libctx, output);
    if (bio == NULL)
        goto cleanup;
    if (BIO_printf(bio, CURVE301_DISPLAY_NAME " %s-Key:\n",
            wants_private ? "Private" : "Public") <= 0)
        goto cleanup;
    if (wants_private
            && !curve301_codec_print_labeled_bytes(
                bio, "priv:", private_key, sizeof(private_key)))
        goto cleanup;
    if (!curve301_codec_print_labeled_bytes(
            bio, "pub:", public_key, sizeof(public_key)))
        goto cleanup;
    result = 1;

cleanup:
    BIO_free(bio);
    curve301_codec_cleanse(codec, private_key, sizeof(private_key));
    curve301_codec_cleanse(codec, public_key, sizeof(public_key));
    return result;
}
#endif

static void *curve301_codec_import_object(
    void *codec_context,
    int selection,
    const OSSL_PARAM parameters[])
{
    CURVE301_CODEC_CONTEXT *codec = codec_context;
    void *key = NULL;
    int effective_selection;

    if (codec == NULL || parameters == NULL
            || !curve301_codec_does_selection(codec, selection))
        return NULL;
    effective_selection = selection == 0
        ? curve301_codec_required_selection(codec)
        : selection;
    key = curve301_key_new(codec->provider);
    if (key == NULL
            || !curve301_key_import(key, effective_selection, parameters)) {
        curve301_key_free(key);
        return NULL;
    }
    return key;
}

static void curve301_codec_free_object(void *key_data)
{
    curve301_key_free(key_data);
}

static int curve301_codec_encode(
    void *codec_context,
    OSSL_CORE_BIO *output,
    const void *key_data,
    const OSSL_PARAM key_parameters[],
    int selection,
    OSSL_PASSPHRASE_CALLBACK *passphrase_callback,
    void *passphrase_argument)
{
    CURVE301_CODEC_CONTEXT *codec = codec_context;
    unsigned char encoded[CURVE301_MAX_ENCODED_KEY_BYTES] = { 0 };
    unsigned char key_bytes[CURVE301_SEED_BYTES] = { 0 };
    const unsigned char *prefix;
    size_t prefix_length = 0;
    size_t encoded_length = 0;
    CURVE301_CODEC_STRUCTURE key_component;
    int result = 0;

    if (codec == NULL || codec->invalid || output == NULL || key_data == NULL
            || key_parameters != NULL
            || !curve301_codec_does_selection(codec, selection))
        goto cleanup;
#if CURVE301_HAS_TEXT_ENCODER
    if (codec->format == CURVE301_CODEC_FORMAT_TEXT) {
        result = curve301_codec_write_text(
            codec, output, key_data, selection);
        goto cleanup;
    }
#endif
    key_component = curve301_codec_is_private(codec)
        ? CURVE301_CODEC_PRIVATE_KEY_INFO : codec->structure;
    prefix = curve301_codec_prefix(codec, &prefix_length, &encoded_length);
    if (prefix == NULL || encoded_length > sizeof(encoded)
            || !curve301_codec_get_key_bytes(
                codec, key_data, key_component, key_bytes))
        goto cleanup;

    memcpy(encoded, prefix, prefix_length);
    memcpy(encoded + prefix_length, key_bytes, CURVE301_SEED_BYTES);
    if (curve301_codec_is_private(codec)
            && (codec->cipher_intent
                || codec->structure
                    == CURVE301_CODEC_ENCRYPTED_PRIVATE_KEY_INFO)) {
        result = curve301_codec_write_encrypted_pkcs8(
            codec, output, encoded, encoded_length,
            passphrase_callback, passphrase_argument);
    } else if (codec->format == CURVE301_CODEC_FORMAT_DER) {
        result = curve301_codec_write_all(
            codec, output, encoded, encoded_length);
    } else if (codec->format == CURVE301_CODEC_FORMAT_PEM) {
        result = curve301_codec_write_pem(
            codec, output, encoded, encoded_length);
    }

cleanup:
    curve301_codec_cleanse(codec, key_bytes, sizeof(key_bytes));
    curve301_codec_cleanse(codec, encoded, sizeof(encoded));
    if (result != 1 && codec != NULL)
        curve301_raise(codec->provider, CURVE301_R_SERIALIZATION_FAILURE,
            CURVE301_DISPLAY_NAME " key encoding failed");
    return result;
}

#if CURVE301_HAS_TEST_DECODER
static void *curve301_codec_import_key(
    CURVE301_CODEC_CONTEXT *codec,
    const unsigned char key_bytes[CURVE301_SEED_BYTES])
{
    OSSL_PARAM parameters[2];
    void *key = NULL;
    const int selection = curve301_codec_required_selection(codec);
    const char *parameter_name;

    if (codec == NULL || key_bytes == NULL || selection == 0)
        return NULL;
    parameter_name = codec->structure == CURVE301_CODEC_PRIVATE_KEY_INFO
        ? OSSL_PKEY_PARAM_PRIV_KEY
        : OSSL_PKEY_PARAM_PUB_KEY;
    parameters[0] = OSSL_PARAM_construct_octet_string(
        parameter_name,
        (void *)key_bytes,
        CURVE301_SEED_BYTES);
    parameters[1] = OSSL_PARAM_construct_end();

    key = curve301_key_new(codec->provider);
    if (key == NULL || !curve301_key_import(key, selection, parameters)) {
        curve301_key_free(key);
        return NULL;
    }
    return key;
}

static int curve301_codec_decode(
    void *codec_context,
    OSSL_CORE_BIO *input,
    int selection,
    OSSL_CALLBACK *data_callback,
    void *callback_argument,
    OSSL_PASSPHRASE_CALLBACK *passphrase_callback,
    void *passphrase_argument)
{
    CURVE301_CODEC_CONTEXT *codec = codec_context;
    unsigned char encoded[CURVE301_MAX_ENCODED_KEY_BYTES] = { 0 };
    const unsigned char *prefix;
    void *key = NULL;
    void *reference;
    size_t prefix_length = 0;
    size_t encoded_length = 0;
    long checkpoint = -1;
    long pending;
    int object_type = OSSL_OBJECT_PKEY;
    char *data_type;
    OSSL_PARAM object_parameters[4];
    int owns_input = 0;
    int result = 1;

    (void)passphrase_callback;
    (void)passphrase_argument;
    if (codec == NULL || codec->format != CURVE301_CODEC_FORMAT_DER
            || input == NULL || data_callback == NULL
            || !curve301_codec_does_selection(codec, selection))
        return 0;
    codec->selection = selection == 0
        ? curve301_codec_required_selection(codec)
        : selection;
    prefix = curve301_codec_prefix(codec, &prefix_length, &encoded_length);
    if (prefix == NULL || encoded_length > sizeof(encoded))
        return 0;

    /* Reject an unrewindable stream before consuming its first byte. */
    if (!curve301_codec_checkpoint(codec, input, &checkpoint))
        goto cleanup;

    /*
     * A positive short pending count identifies a retryable source whose
     * bytes must remain outside the decoder's read buffer.  A regular file
     * may report zero pending bytes despite being readable, so zero is not a
     * short-input signal and proceeds to the bounded read below.
     */
    pending = codec->provider->bio_ctrl(
        input, BIO_CTRL_PENDING, 0, NULL);
    if (pending < 0
            || (pending > 0 && (size_t)pending < encoded_length))
        goto cleanup;

    /*
     * Read one bounded candidate.  A short or retryable source leaves no
     * parser state: cleanup rewinds to the checkpoint.  Outer-shape
     * mismatches and foreign OIDs are likewise "not mine" and are rewound so
     * another decoder starts at exactly the same byte.
     */
    if (!curve301_codec_read_exact(
            codec, input, encoded, encoded_length))
        goto cleanup;
    if (curve301_codec_has_target_oid(codec, encoded, encoded_length))
        owns_input = 1;
    if (encoded[0] != 0x30
            || encoded[1] != (unsigned char)(encoded_length - 2)) {
        if (owns_input) {
            curve301_raise(codec->provider,
                CURVE301_R_SERIALIZATION_FAILURE,
                "non-canonical " CURVE301_DISPLAY_NAME " key encoding");
            result = 0;
        }
        goto cleanup;
    }
    if (!owns_input)
        goto cleanup;

    if (memcmp(encoded, prefix, prefix_length) != 0) {
        curve301_raise(codec->provider, CURVE301_R_SERIALIZATION_FAILURE,
            "non-canonical " CURVE301_DISPLAY_NAME " key encoding");
        result = 0;
        goto cleanup;
    }

    key = curve301_codec_import_key(codec, encoded + prefix_length);
    if (key == NULL) {
        curve301_raise(codec->provider, CURVE301_R_SERIALIZATION_FAILURE,
            CURVE301_DISPLAY_NAME " key decoding rejected key material");
        result = 0;
        goto cleanup;
    }

    data_type = (char *)CURVE301_ALGORITHM_NAME;
    reference = key;
    object_parameters[0] = OSSL_PARAM_construct_int(
        OSSL_OBJECT_PARAM_TYPE,
        &object_type);
    object_parameters[1] = OSSL_PARAM_construct_utf8_string(
        OSSL_OBJECT_PARAM_DATA_TYPE,
        data_type,
        0);
    object_parameters[2] = OSSL_PARAM_construct_octet_string(
        OSSL_OBJECT_PARAM_REFERENCE,
        &reference,
        sizeof(reference));
    object_parameters[3] = OSSL_PARAM_construct_end();
    result = data_callback(object_parameters, callback_argument);
    key = reference;

cleanup:
    if (!owns_input && checkpoint >= 0
            && !curve301_codec_restore(codec, input, checkpoint)) {
        curve301_raise(codec->provider, CURVE301_R_SERIALIZATION_FAILURE,
            CURVE301_DISPLAY_NAME " decoder could not restore an unowned input");
        result = 0;
    }
    curve301_key_free(key);
    curve301_codec_cleanse(codec, encoded, sizeof(encoded));
    return result;
}

static int curve301_codec_export_object(
    void *codec_context,
    const void *reference,
    size_t reference_size,
    OSSL_CALLBACK *export_callback,
    void *callback_argument)
{
    CURVE301_CODEC_CONTEXT *codec = codec_context;
    void *key;
    int selection;

    if (codec == NULL || reference == NULL
            || reference_size != sizeof(key) || export_callback == NULL)
        return 0;
    key = *(void *const *)reference;
    if (key == NULL)
        return 0;
    selection = codec->selection == 0
        ? curve301_codec_required_selection(codec)
        : codec->selection;
    return curve301_key_export(
        key, selection, export_callback, callback_argument);
}
#endif

#define CURVE301_DEFINE_ENCODER_DISPATCH(name, new_context, does_selection) \
    static const OSSL_DISPATCH name[] = {                                   \
        { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))new_context },          \
        { OSSL_FUNC_ENCODER_FREECTX,                                        \
            (void (*)(void))curve301_codec_free_context },                  \
        { OSSL_FUNC_ENCODER_DOES_SELECTION,                                 \
            (void (*)(void))does_selection },                               \
        { OSSL_FUNC_ENCODER_ENCODE,                                         \
            (void (*)(void))curve301_codec_encode },                        \
        { OSSL_FUNC_ENCODER_IMPORT_OBJECT,                                  \
            (void (*)(void))curve301_codec_import_object },                 \
        { OSSL_FUNC_ENCODER_FREE_OBJECT,                                    \
            (void (*)(void))curve301_codec_free_object },                   \
        { 0, NULL }                                                         \
    }

#define CURVE301_DEFINE_PRIVATE_ENCODER_DISPATCH(                           \
    name, new_context, does_selection)                                      \
    static const OSSL_DISPATCH name[] = {                                   \
        { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))new_context },          \
        { OSSL_FUNC_ENCODER_FREECTX,                                        \
            (void (*)(void))curve301_codec_free_context },                  \
        { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,                            \
            (void (*)(void))curve301_private_codec_settable_ctx_params },   \
        { OSSL_FUNC_ENCODER_SET_CTX_PARAMS,                                 \
            (void (*)(void))curve301_private_codec_set_ctx_params },        \
        { OSSL_FUNC_ENCODER_DOES_SELECTION,                                 \
            (void (*)(void))does_selection },                               \
        { OSSL_FUNC_ENCODER_ENCODE,                                         \
            (void (*)(void))curve301_codec_encode },                        \
        { OSSL_FUNC_ENCODER_IMPORT_OBJECT,                                  \
            (void (*)(void))curve301_codec_import_object },                 \
        { OSSL_FUNC_ENCODER_FREE_OBJECT,                                    \
            (void (*)(void))curve301_codec_free_object },                   \
        { 0, NULL }                                                         \
    }

#if CURVE301_HAS_TEST_DECODER
# define CURVE301_DEFINE_DECODER_DISPATCH(name, new_context, does_selection) \
    static const OSSL_DISPATCH name[] = {                                   \
        { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))new_context },          \
        { OSSL_FUNC_DECODER_FREECTX,                                        \
            (void (*)(void))curve301_codec_free_context },                  \
        { OSSL_FUNC_DECODER_DOES_SELECTION,                                 \
            (void (*)(void))does_selection },                               \
        { OSSL_FUNC_DECODER_DECODE,                                         \
            (void (*)(void))curve301_codec_decode },                        \
        { OSSL_FUNC_DECODER_EXPORT_OBJECT,                                  \
            (void (*)(void))curve301_codec_export_object },                 \
        { 0, NULL }                                                         \
    }
#endif

CURVE301_DEFINE_PRIVATE_ENCODER_DISPATCH(
    CURVE301_PKCS8_DER_ENCODER_DISPATCH,
    curve301_pkcs8_der_codec_new_context,
    curve301_private_codec_does_selection);
CURVE301_DEFINE_PRIVATE_ENCODER_DISPATCH(
    CURVE301_PKCS8_PEM_ENCODER_DISPATCH,
    curve301_pkcs8_pem_codec_new_context,
    curve301_private_codec_does_selection);
CURVE301_DEFINE_PRIVATE_ENCODER_DISPATCH(
    CURVE301_ENCRYPTED_PKCS8_DER_ENCODER_DISPATCH,
    curve301_encrypted_pkcs8_der_codec_new_context,
    curve301_private_codec_does_selection);
CURVE301_DEFINE_PRIVATE_ENCODER_DISPATCH(
    CURVE301_ENCRYPTED_PKCS8_PEM_ENCODER_DISPATCH,
    curve301_encrypted_pkcs8_pem_codec_new_context,
    curve301_private_codec_does_selection);
CURVE301_DEFINE_ENCODER_DISPATCH(
    CURVE301_SPKI_DER_ENCODER_DISPATCH,
    curve301_spki_der_codec_new_context,
    curve301_public_codec_does_selection);
CURVE301_DEFINE_ENCODER_DISPATCH(
    CURVE301_SPKI_PEM_ENCODER_DISPATCH,
    curve301_spki_pem_codec_new_context,
    curve301_public_codec_does_selection);
#if CURVE301_HAS_TEXT_ENCODER
CURVE301_DEFINE_ENCODER_DISPATCH(
    CURVE301_TEXT_ENCODER_DISPATCH,
    curve301_text_codec_new_context,
    curve301_text_codec_does_selection);
#endif

#if CURVE301_HAS_TEST_DECODER
CURVE301_DEFINE_DECODER_DISPATCH(
    CURVE301_SPKI_DER_DECODER_DISPATCH,
    curve301_spki_der_codec_new_context,
    curve301_public_codec_does_selection);
#endif
#if CURVE301_HAS_PRIVATE_KEY_DECODER
CURVE301_DEFINE_DECODER_DISPATCH(
    CURVE301_PKCS8_DER_DECODER_DISPATCH,
    curve301_pkcs8_der_codec_new_context,
    curve301_private_codec_does_selection);
#endif

static const OSSL_ALGORITHM CURVE301_ENCODER_ALGORITHMS[] = {
#if CURVE301_HAS_TEXT_ENCODER
    {
        CURVE301_OPERATION_ALGORITHM_NAMES,
        "provider=" CURVE301_PROVIDER_BASENAME ",output=text",
        CURVE301_TEXT_ENCODER_DISPATCH,
        CURVE301_DISPLAY_NAME " key text encoder"
    },
#endif
    {
        CURVE301_ALGORITHM_NAMES,
        "provider=" CURVE301_PROVIDER_BASENAME ",output=der,structure=EncryptedPrivateKeyInfo",
        CURVE301_ENCRYPTED_PKCS8_DER_ENCODER_DISPATCH,
        CURVE301_DISPLAY_NAME " encrypted PKCS#8 DER encoder"
    },
    {
        CURVE301_ALGORITHM_NAMES,
        "provider=" CURVE301_PROVIDER_BASENAME ",output=pem,structure=EncryptedPrivateKeyInfo",
        CURVE301_ENCRYPTED_PKCS8_PEM_ENCODER_DISPATCH,
        CURVE301_DISPLAY_NAME " encrypted PKCS#8 PEM encoder"
    },
    {
        CURVE301_ALGORITHM_NAMES,
        "provider=" CURVE301_PROVIDER_BASENAME ",output=der,structure=PrivateKeyInfo",
        CURVE301_PKCS8_DER_ENCODER_DISPATCH,
        CURVE301_DISPLAY_NAME " PKCS#8 DER encoder"
    },
    {
        CURVE301_ALGORITHM_NAMES,
        "provider=" CURVE301_PROVIDER_BASENAME ",output=pem,structure=PrivateKeyInfo",
        CURVE301_PKCS8_PEM_ENCODER_DISPATCH,
        CURVE301_DISPLAY_NAME " PKCS#8 PEM encoder"
    },
    {
        CURVE301_ALGORITHM_NAMES,
        "provider=" CURVE301_PROVIDER_BASENAME ",output=der,structure=SubjectPublicKeyInfo",
        CURVE301_SPKI_DER_ENCODER_DISPATCH,
        CURVE301_DISPLAY_NAME " SPKI DER encoder"
    },
    {
        CURVE301_ALGORITHM_NAMES,
        "provider=" CURVE301_PROVIDER_BASENAME ",output=pem,structure=SubjectPublicKeyInfo",
        CURVE301_SPKI_PEM_ENCODER_DISPATCH,
        CURVE301_DISPLAY_NAME " SPKI PEM encoder"
    },
    { NULL, NULL, NULL, NULL }
};

#if CURVE301_HAS_TEST_DECODER
static const OSSL_ALGORITHM CURVE301_DECODER_ALGORITHMS[] = {
# if CURVE301_HAS_PRIVATE_KEY_DECODER
    {
        CURVE301_DECODER_ALGORITHM_NAMES,
        "provider=" CURVE301_PROVIDER_BASENAME ",input=der,structure=PrivateKeyInfo",
        CURVE301_PKCS8_DER_DECODER_DISPATCH,
        CURVE301_DISPLAY_NAME " transactional PKCS#8 DER decoder"
    },
# endif
    {
        CURVE301_DECODER_ALGORITHM_NAMES,
        "provider=" CURVE301_PROVIDER_BASENAME ",input=der,structure=SubjectPublicKeyInfo",
        CURVE301_SPKI_DER_DECODER_DISPATCH,
        CURVE301_DISPLAY_NAME " transactional SPKI DER decoder"
    },
    { NULL, NULL, NULL, NULL }
};
#endif


#endif
