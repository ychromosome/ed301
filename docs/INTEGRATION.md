# OpenSSL integration

The providers in [`provider/`](../provider) expose Ed301-EdDSA-v2 and X301-v2
to OpenSSL 3.5 and 4.0. Each module is a Rust `cdylib` with a C adapter; the
cryptography is done by the safe-Rust cores in [`rust/crates`](../rust/crates).

## Modules

Each variant is a separate build of one workspace package with one feature.

| Module | Package / feature | Operations beyond key management |
| --- | --- | --- |
| `ed301_eddsa_v2` | `ed301-eddsa-provider` | One-shot Ed301 signatures |
| `ed301_eddsa_v2_tls` | `ed301-eddsa-provider` / `tls-experiment` | Signatures, DER/PEM codecs, text output, TLS SignatureScheme |
| `x301_v2` | `x301-provider` | Raw X301 key exchange |
| `x301_v2_tls` | `x301-provider` / `tls-x301-mlkem1024` | Raw exchange, codecs, hybrid key management and KEM, TLS groups |

The test suite also builds diagnostic variants (`*_pki_test`, `*_failpoint`,
`ed301_eddsa_v2_tls_collider`); they are not meant for deployment. Each module
exports only `OSSL_provider_init`.

The provider build requires `CC=/usr/bin/gcc`, `AR=/usr/bin/ar`,
`ED301_HERMETIC_PROVIDER_BUILD=1` (Ed301) or `X301_HERMETIC_PROVIDER_BUILD=1`
(X301), and `OPENSSL_INCLUDE_DIR` / `OPENSSL_LIB_DIR`; it rejects `CFLAGS`,
`LDFLAGS` and similar overrides. [`provider-tests/run.py`](../provider-tests/run.py)
shows a complete build.

## Identifiers

| Registry | Value | Assignment |
| --- | --- | --- |
| OID | `1.3.6.1.4.1.66282.301.5` | Ed301-EdDSA-v2 key and signature algorithm |
| OID | `1.3.6.1.4.1.66282.301.6` | X301-v2 key algorithm |
| SignatureScheme | `0xFE85` | Ed301-EdDSA-v2 |
| NamedGroup | `0xFE2F` | `X301MLKEM1024` hybrid |
| NamedGroup | `0xFE30` | Raw X301, explicit opt-in only |

Both AlgorithmIdentifiers have absent parameters, not ASN.1 NULL. Canonical
SPKI is 58 DER bytes; PKCS#8 PrivateKeyInfo version 0 is 62 DER bytes and
holds the original 38-byte seed or secret (for X301 not the clamped copy).

Earlier generations used OIDs `…301.1` to `…301.4`, SignatureSchemes
`0xFE2D` and `0xFE84` and NamedGroup `0xFE2E`; these stay retired and are not
reused. All values are project assignments in private-use ranges, not IANA
registrations. Do not load v1 and v2 providers into the same `OSSL_LIB_CTX`;
OID registration is process-global even with private library contexts.

## Contexts and TLS

Set the module search path and load the providers, then create `SSL_CTX`
objects in the same `OSSL_LIB_CTX`. An `SSL_CTX` created before the providers
were loaded must be recreated. Configure TLS 1.3, the signature algorithm and
the full group list explicitly.

Loading the providers does not change OpenSSL's `DEFAULT` group list. Enable
only `X301MLKEM1024` to require the hybrid: raw `X301` has no ML-KEM
protection, and a client offering raw X301 first can obtain it.

| Hybrid value | Layout |
| --- | --- |
| Client key share | ML-KEM-1024 public key (1568 bytes), then X301 public key (38 bytes) |
| Server key share | ML-KEM-1024 ciphertext (1568 bytes), then X301 public key (38 bytes) |
| Shared secret | ML-KEM output (32 bytes), then X301 output (38 bytes) |

ML-KEM runs in OpenSSL's default provider; TLS owns the key schedule. There
is no standalone or persistent hybrid KEM format. Invalid X301 input or an
all-zero X301 output fails without partial output. The nested ML-KEM fetch
uses the child context's mirrored default properties, not the outer
`provider=x301_v2_tls` selector.

## Randomness

Ed301 and X301 private-key generation use provider-owned OpenSSL CTR-DRBG
instances (AES-256-CTR) whose parent is the child context's primary DRBG;
PKCS#8 salts and IVs use a separate public-output DRBG. The child context
mirrors the loaded providers and default properties but not the
application's RAND or seed-source configuration. Applications that require a
specific entropy source must enforce it at the generation boundary;
configuring only the parent context is not enough. ML-KEM has its own RAND
consumers.

## Responsibilities

| Property | Provider | Application |
| --- | --- | --- |
| Key encoding and subgroup rules | Checks raw keys and their DER objects | Select the right algorithm and generation |
| Complete key files | The decoder consumes one matching object | Reject trailing or extra objects; validate decrypted contents |
| PKI profile | Signs and verifies the bytes it is given | Inspect AlgorithmIdentifiers; enforce the certificate profile |
| Hybrid-only TLS | Offers raw and hybrid groups separately | Enable only the hybrid |
| Generation isolation | Registers its own identifiers | Control provider loading; do not mix v1 and v2 |

[`provider-tests/v2_file_boundary.h`](../provider-tests/v2_file_boundary.h) and
[`provider-tests/strict_pki.h`](../provider-tests/strict_pki.h) show these
application-side checks.

## Encrypted private keys

PEM, PKCS#8, PBES2 and PKCS#12 cryptography is OpenSSL's. For encrypted
PKCS#8 the provider encoder uses AES-256-CBC with PBKDF2-HMAC-SHA256 and
1,000,000 iterations by default. The unsigned integer encoder parameter
`curve301-pbkdf2-iterations` accepts 1 to 10,000,000. Invalid values block
output, including after a later cipher-only update; a valid value restores
it. Clearing the cipher resets the cost to the default. Existing files stay
readable and are not upgraded in place. The setting does not affect separate
OpenSSL operations such as `openssl pkcs8 -iter`.

## Versions

Supported minimums are OpenSSL 3.5.7 and 4.0.1, with one build per ABI major.
The Ed301 module enforces these patch levels at build and load time; the X301
module checks the ABI major and, for the hybrid on OpenSSL 3, minor version 5
or later. The test suite in this tree passes against OpenSSL 4.0.3; the
providers were previously validated against 3.5.8 and 4.0.2.
