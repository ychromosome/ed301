# Ed301-EdDSA-v2

Deterministic EdDSA-style signatures over the Ed301 curve. Experimental: not
standardized and not intended for production use.

This profile instantiates the generic EdDSA construction of
[RFC 8032, section 3](https://www.rfc-editor.org/rfc/rfc8032.html#section-3)
with the domain shape of its Ed448 instance. It is neither Ed25519 nor Ed448.
The hash is SHAKE256 ([FIPS 202](https://csrc.nist.gov/pubs/fips/202/final)).

## Parameters

All curve values come from [`math/ed301-v2.json`](../math/ed301-v2.json),
SHA-256 `13f0eaf541919a1447b9d3c58e6d57eb77ffab94ebe37539c70301d6fddcfaa0`:
the twisted Edwards curve `a·x² + y² = 1 + d·x²·y²` over `p = 2^301 − 2^89 + 907`
with `a = 247399²`, `d = −301`, group order `4q` and base point `G` of prime
order `q`. See [the mathematics](../docs/MATHEMATICS.md) for derivations.

## Encodings

All integers are little-endian, 38 bytes.

- **Field element:** an integer `0 ≤ x < p`; bits 301–303 are zero.
- **Point:** `y` in bits 0–300, bits 301 and 302 zero, and the parity of the
  canonical `x` in bit 303. Decoding recovers `x² = (1 − y²)/(a − d·y²)` and
  rejects `y ≥ p`, nonzero reserved bits, non-points, and sign 1 with `x = 0`.
  Inputs are never reduced.
- **Scalar:** an integer `0 ≤ S < q`, including zero.

Seeds and public keys are 38 bytes; signatures are 76 bytes (`R || S`).

## Public keys

A public key must decode canonically, differ from the identity and lie in
the prime-order subgroup (`[q]A = O`). Public-key import processes only public
data and may take time that depends on the key; it must not receive
confidential data. Key derivation and signing do not use the import checks.

## Key expansion

For a 38-byte seed, compute `h = SHAKE256(seed, 76)`. Let `lower` be its first
38 bytes and `prefix` its last 38 bytes. Prune `lower`:

```text
lower[0]  &= 0xfc
lower[37]  = (lower[37] & 0x0f) | 0x10
```

and let `s` be its integer value; the public key is `A = ENC([s]G)`.
Key expansion has no domain prefix.

Pruning gives `s = 2^300 + 4n` with `0 ≤ n < 2^298`, so `s < 2^301 ≤ 4q`. Since
`q` is odd, `[s]G = O` would require `4q | s`; hence `A` is never the identity.

## Signing

For a binary context `C` of 0–255 bytes:

```text
dom(C) = ASCII("SigEd301-v2") || 0x00 || octet(len(C)) || C
```

An empty context still uses the domain prefix. For a message `M`:

```text
r = LE(SHAKE256(dom(C) || prefix || M, 76)) mod q
R = ENC([r]G)
k = LE(SHAKE256(dom(C) || R || A || M, 76)) mod q
S = (r + k·s) mod q
signature = R || ENC_SCALAR(S)
```

Signing is one-shot and deterministic. Prehash, streaming, batch
verification and randomized signing are not part of this profile.

## Verification

Check all lengths and the public-key rules, decode `R` canonically and
require `0 ≤ S < q`. Recompute `k` and accept exactly when

```text
[4S]G = [4]R + [4k]A
```

`R` need not lie in the prime-order subgroup, and `S = 0` is not rejected
for being zero. No further `R` check, nonzero-`S` rule or fallback applies.
An invalid equation with a torsion-bearing `R` is rejected; a valid
cofactored equation with such an `R` is accepted.

## Identifiers and containers

| Item | Value |
| --- | --- |
| OpenSSL algorithm name | `Ed301-EdDSA` |
| OID | `1.3.6.1.4.1.66282.301.5` (parameters absent, not NULL) |
| TLS 1.3 SignatureScheme | `0xFE85` (private use) |
| SubjectPublicKeyInfo | 58 DER bytes |
| PKCS#8 PrivateKeyInfo v0 | 62 DER bytes; nested OCTET STRING with the 38-byte seed |

These identifiers are project assignments, not IANA registrations, and are
distinct from the earlier v1 generation.

## Test vectors and reference

[`vectors/ed301-eddsa-v2.json`](../vectors/ed301-eddsa-v2.json) holds signing
traces with every intermediate value, verification decisions, point and
scalar decoding cases and signing errors. The Python reference
[`reference/ed301_sig.py`](../reference/ed301_sig.py) implements this
specification with variable-time arithmetic, for public test data only.
