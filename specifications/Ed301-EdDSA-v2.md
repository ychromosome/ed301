# Ed301-EdDSA: internal v2 byte contract

Experimental Phase-B reference profile. Not standardized, not constant-time,
not a product release. Gate A approved the mathematical package only; Gate B
is still required for this reference and its vectors.

## Sources and parameters

The curve is exclusively the immutable file
`provenance/phase-a/2026-09-09/parameter/ed301-v2.json`, SHA-256
`13f0eaf541919a1447b9d3c58e6d57eb77ffab94ebe37539c70301d6fddcfaa0`.
Its archived pre-review status text remains unchanged. Gate A was subsequently
approved by Claude on 2026-09-09, bound to commit
`23c8feef7fd89bf0a2db0910df778f393aaf4614`.

This profile instantiates the generic EdDSA construction described in
[RFC 8032 section 3](https://www.rfc-editor.org/rfc/rfc8032.html#section-3),
with the domain shape of its Ed448 instance. It is not Ed448 or Ed25519.
SHAKE256 is supplied by the language runtime, following
[FIPS 202](https://csrc.nist.gov/pubs/fips/202/final); no new hash is implemented.
The inherited current v1 contract and the approved v2 changes are bound in
`phase-b/SOURCES.md`.

## Encoding and public-key policy

Seeds and public keys are 38 bytes; signatures are 76 bytes. Field elements
are 38-byte little-endian integers less than p, with bits 301..303 zero.
Compressed points encode y in bits 0..300, zero reserved bits 301 and 302,
and the parity of canonical x in bit 303. Decode with
`x² = (1-y²)/(a-d*y²)`, rejecting non-points, y >= p and sign 1 for x = 0.
There is no input reduction. Signature scalars encode `0 <= S < q` in 38
little-endian bytes, including the canonical value zero.

A public key must decode canonically, differ from the identity, and satisfy
`[q]A = O`. R must decode canonically, but need not have prime order.

## Transcript

For an opaque binary context C of length 0..255:

```text
dom(C) = ASCII("SigEd301-v2") || 0x00 || octet(len(C)) || C
```

An absent context is empty, not an absent domain. The phflag is always zero;
prehash, streaming, batch verification, randomized signing and hash-to-curve
are outside this profile.

For an exact 38-byte seed, expand `h = SHAKE256(seed, 76)`. Let lower be its
first 38 bytes and prefix its last 38 bytes. Prune with
`lower[0] &= 0xfc; lower[37] = (lower[37] & 0x0f) | 0x10` and set s to its
little-endian integer. The public key is `ENC([s]G)`. Key expansion has no
domain prefix. The Gate-A pruning proof rules out the identity public key.

For message M, an opaque byte string:

```text
r = LE(SHAKE256(dom(C) || prefix || M, 76)) mod q
Renc = ENC([r]G)
k = LE(SHAKE256(dom(C) || Renc || public_key || M, 76)) mod q
S = (r + k*s) mod q
signature = Renc || ENC_SCALAR(S)
```

Verification first enforces all lengths and canonical/public-key rules,
then recomputes k and accepts exactly when `[4S]G = [4]R + [4k]A`.
An invalid equation with a torsion-bearing R is rejected; a correctly formed
cofactored equation with such an R is accepted. No extra R-subgroup check,
nonzero-S rule, nonzero-nonce retry or verification fallback is allowed.

## Reference API and profile separation

`public_from_seed(seed)`, `sign(seed, message, context=b"")` and
`verify(public_key, message, signature, context=b"")` operate on bytes.
Invalid signing arguments raise ValueError. Invalid verification arguments
return False; internal arithmetic invariant failures are not hidden.
`sign_trace` exposes intermediates solely for public deterministic test seeds.

The internal identifiers are ED301-v2 and Ed301-EdDSA-v2. The public project
name remains Ed301-EdDSA. New OID numbers and private TLS codepoints have not
yet been assigned and are not guessed here. Unchanged historical v1 fixtures
are negative cross-profile controls, not fallback inputs. Same-size raw bytes
do not carry an identity tag; final container separation will use distinct
identifiers in the later provider/integration phases.
