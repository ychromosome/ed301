# Current OpenSSL integration contract

This contract accompanies the [v2 profile](../specifications/CURRENT_PROFILE.md).
The [original decisions](../phase-d/d2/inputs/D1_BEWERTUNG_UND_D2_ENTSCHEIDUNGEN_2026-09-10.md)
and [D2 integration record](../phase-d/d2/INTEGRATION_CONTRACT.md) are historical
inputs; their pending-phase statements do not describe the current modules.

## Module variants

Each feature selection is built separately in the [provider workspace](../provider/Cargo.toml).

| Module | Operations beyond raw key management |
| --- | --- |
| `ed301_eddsa_v2` | One-shot Ed301 signatures |
| `ed301_eddsa_v2_tls` | Signatures, codecs/text and TLS SignatureScheme |
| `x301_v2` | Raw X301 key exchange |
| `x301_v2_tls` | Raw exchange, codecs/text, hybrid KEYMGMT/KEM and TLS groups |

Separate `*_pki_test`, `*_failpoint` and `ed301_eddsa_v2_tls_collider` modules
are diagnostic fixtures, not shipping variants. Former `*_tls_test` names
are not aliases. Internal Cargo feature names retain their existing spelling.
The public algorithms are `Ed301-EdDSA`, `X301` and `X301MLKEM1024`;
`MLKEM1024X301` is not an alias. The TLS signature selection name is
`ed301_eddsa_v2` and its wire value is `0xFE85`.

Ed301 key generation uses `EVP_PKEY_CTX_new_from_name`, `EVP_PKEY_keygen_init`
and `EVP_PKEY_generate`; the provider does not advertise the generation
parameters needed by `EVP_PKEY_Q_keygen`.

## Contexts and TLS

Set the module search path, load the required providers, then create
`SSL_CTX` objects in that same `OSSL_LIB_CTX`. Configure TLS 1.3, the signature
and the complete group list explicitly. Context configuration is serialized
by the application; an existing `SSL_CTX` must be recreated after missing
capabilities are loaded. Do not co-load v1 and v2 generations in one context.

The [checked loader](../provider-tests/v2_generation_policy.h) enforces a
closed module-name policy for the test integration, assuming hash-verified
module files. It is not an interposer on arbitrary `OSSL_PROVIDER_load` calls.
OID/SIGID registration is process-global even with private library contexts.

The project [TLS policy helper](../provider-tests/v2_tls_policy.h) enables
only `X301MLKEM1024` (`0xFE2F`). Raw `X301` (`0xFE30`) is explicit opt-in and
has no ML-KEM protection. If both are enabled, a raw-first client can obtain
Raw X301 in the tested OpenSSL lanes. Require the hybrid by omitting Raw from
the allowed list. Loading the providers does not change OpenSSL `DEFAULT`.

| Hybrid value | Layout |
| --- | --- |
| Client key share | ML-KEM public key 1568 bytes, then X301 public key 38 bytes |
| Server key share | ML-KEM ciphertext 1568 bytes, then X301 public key 38 bytes |
| Shared key material | ML-KEM output 32 bytes, then X301 output 38 bytes |

ML-KEM runs in OpenSSL; TLS owns the subsequent key schedule. There is no
extra project KDF or supported standalone/persistent hybrid-KEM profile.
Invalid X301 input or all-zero output fails without partial caller output;
ML-KEM implicit rejection remains OpenSSL-owned.

The outer property query selects the hybrid provider. Its nested ML-KEM
fetch uses the child context's mirrored default properties, not the outer
`provider=x301_v2_tls` selector. See the
[nested-property tests](../provider-tests/x301/provider_x301_nested_properties.c).

## Enforcement boundaries

| Property | Provider/DSO | Application responsibility |
| --- | --- | --- |
| Key encoding and subgroup rules | Checks raw key material and its supported DER object | Select the correct generation and algorithm |
| Complete key file | Decoder consumes one matching BIO object | Reject trailing/extra objects and validate decrypted wrapper contents |
| Extra all-Ed301 PKI rules | Signature operation receives the key and signed bytes | Inspect AlgorithmIdentifiers and enforce the certificate profile |
| Hybrid-only negotiation | Advertises separate Raw and Hybrid groups | Enable only Hybrid |
| Generation isolation | Registers/checks its own identity where applicable | Control provider loading; do not mix v1/v2 |

The [file-boundary helper](../provider-tests/v2_file_boundary.h) performs the
extra plain/decrypted whole-object checks before generic decoding. The
[key-file test utility](../provider-tests/provider_keyfile_check.c) also
limits files to 8 KiB; it is not a general-purpose parser. The
[strict PKI helper](../provider-tests/strict_pki.h) belongs in the application's
certificate verification callback for the all-Ed301 test profile. Stock CLI
success alone does not establish those additional whole-file/PKI properties.

PEM, encrypted PKCS#8, PBES2 and PKCS#12 cryptography are delegated to OpenSSL.
The provider encoder currently uses `PKCS5_DEFAULT_ITER` for PBES2. A calibrated,
configurable password-cost policy remains a separate task before relying on
human-password protection for persistent keys; this contract does not change
the KDF or its parameters.

## Versions and deployment

Supported combined-stack minimums are OpenSSL 3.5.7 and 4.0.1, with a separate
build per ABI major. Ed301 enforces these patch minimums at build/load time;
X301 checks the ABI major and, for its hybrid on OpenSSL 3, minor version
at least 5; it does not enforce the same patch floor. A version
accepted by one module is not therefore a supported combined-stack version.
Recorded E8 lanes are 3.5.8 and 4.0.2. Compiler/profile acceptance is separate
from this compatibility statement.

[N2 stock-CLI tests](../phase-d/d2/N2_N4_PREPARATION.md) load providers through
process-local default-context configuration. Older private-context CLI
receipts used [CSR](../provider-tests/provider_csr_cli.c) and
[PKCS#12](../provider-tests/provider_pkcs12_cli.c) frontends; these are distinct
test modes. [Fedora packaging](../packaging/fedora/README.md) separates software
from activation policy. Removing the policy does not reconfigure already
running processes, and removing the meta-package alone need not remove policy.
