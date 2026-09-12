# Ed301-EdDSA / X301 v2 profile contract

This is the normative entry point for the current v2 implementation. It
incorporates the mathematical and byte rules in the frozen
[Ed301 specification](Ed301-EdDSA-v2.md) and [X301 specification](X301-v2.md).
The identifiers, API scope and error ordering below supersede their historical
phase-status and future-allocation statements. Project maturity and binary
acceptance are recorded in the [project README](../README.md#review-status).

## Parameters and encodings

The [frozen parameter set](../provenance/phase-a/2026-09-09/parameter/ed301-v2.json)
defines `p = 2^301 - 2^89 + 907`, `a = 247399²`, `d = -301`, orders `4q` and
`4q_t`, and the base point of order `q`. Its SHA-256 is
`13f0eaf541919a1447b9d3c58e6d57eb77ffab94ebe37539c70301d6fddcfaa0`.

| Profile | Public name | OID | TLS private-use assignment |
| --- | --- | --- | --- |
| Ed301-EdDSA-v2 | `Ed301-EdDSA` | `1.3.6.1.4.1.66282.301.5` | SignatureScheme `0xFE85` |
| X301-v2 | `X301` | `1.3.6.1.4.1.66282.301.6` | NamedGroup `0xFE30` |
| Hybrid | `X301MLKEM1024` | None | NamedGroup `0xFE2F` |

These assignments do not identify either v1 generation and are not IANA
registrations. The [registry](../docs/OID_REGISTRY.md) retains historical IDs;
the generated [Ed301](../provider/common/generated_ed301_profile.h) and
[X301](../provider/common/generated_x301_profile.h) headers carry the values
used by the providers.

Seeds/secrets and public keys are 38 bytes. Ed301 signatures are 76 bytes.
Compressed Ed301 points encode canonical `y`, two zero reserved bits and the
parity of canonical `x`; sign 1 for `x = 0` is rejected. X301 peer inputs
require bits 301–303 zero and `u < p`; they are never masked or reduced.

Both AlgorithmIdentifiers have absent parameters, not ASN.1 NULL. Canonical
SPKI is 58 DER bytes. PKCS#8 PrivateKeyInfo version 0 is 62 DER bytes and
contains a nested OCTET STRING with the original 38 seed/secret bytes.
X301 exports the original secret, not its clamped working copy.

## Ed301 signatures

Signing is deterministic and one-shot. Binary contexts have length 0–255.
The domain is `ASCII("SigEd301-v2") || 0x00 || octet(len(C)) || C`, including
for an empty context. SHAKE256 produces 76 bytes for seed expansion, nonce
and challenge derivation, as specified in the frozen byte contract.
Prehash, streaming, batch verification and randomized signing are unsupported.

Public keys must be canonical, nonidentity members of the prime-order
subgroup. Import may take public-input-dependent time and must not receive
confidential data. Secret derivation and signing bypass that parser.
Verification accepts precisely the canonical encodings satisfying
`[4S]G = [4]R + [4k]A`, with `0 <= S < q`. It neither requires `R` to be in
the prime-order subgroup nor rejects `S = 0` solely because it is zero.

## X301 and error ordering

Clamp a private working copy with `k[0] &= 0xfc` and
`k[37] = (k[37] & 0x0f) | 0x10`. Reject the full twist order `N_t`, including
all 64 raw aliases. Key generation retries only this weak-secret condition;
random-source failures and other errors propagate.

For the raw two-input operation, errors have this cross-language precedence:

1. Invalid secret type/length, then the excluded clamped secret.
2. Invalid peer type/length, then noncanonical peer encoding.
3. A ladder result at infinity or an all-zero output.

No ladder executes after an input error and no partial result is returned.
Language-specific exception classes need not be identical; the failing input
and stage must agree. The shared
[precedence corpus](../vectors/x301-error-precedence.json) tests this rule.
The historical Phase-B references checked the peer first; their archived
results remain unchanged. Successful outputs and historical vectors are unchanged.

Peer DH uses all 301 rounds and the specified minus-A24 formula. Canonical
low-order peer values can pass decoding but must fail the result check.
The returned 38 bytes are raw DH material; the application supplies a reviewed
KDF and authentication.

## Provider integration

The [current integration contract](../docs/INTEGRATION.md) defines module
variants, OpenSSL context ownership, group selection, nested properties,
file/PKI boundaries and supported versions. It takes precedence over historical
integration status narratives. Changes to either current contract require
matching tests; old manifests are checked only against their original snapshots.
