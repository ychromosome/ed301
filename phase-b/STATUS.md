# Phase B: Ed301-EdDSA subset

Started 2026-09-09 after Martin's go-ahead following Claude's Gate-A approval.
This is development work on Testing, not a Gate-B submission or release.

## Implemented and checked

- B1, curve and signature: Python affine reference with exact hash-bound
  Gate-A parameters; current Ed301-EdDSA-v1 transcript structure with the
  approved internal v2 identity and domain.
- B2, signature: 9 deterministic signing cases and all 108 transcript
  intermediates; 61 verification cases; 15 point-decoding cases; 6 scalar
  boundary cases; 4 signing-error cases; 5 domain-conformance controls.
- Contexts include empty, ASCII, embedded zero/non-ASCII binary, 255 bytes
  and the rejected 256-byte case. Seeds include all-zero and all-one inputs;
  messages include empty, binary and 4096-byte fixtures.
- Canonical y, negative zero, reserved point bits, lengths, nonsquare recovery,
  S >= q, identity/torsion/mixed-order public keys, and changed message/context
  are checked. Scalar zero is canonical but does not rescue a false equation.
- R is governed by the cofactored equation: 8 explicitly constructed valid
  cases cover identity, order-2, both order-4 signs, and prime-subgroup plus
  torsion. Incorrect R replacements and additions with unchanged S fail.
- Both directions of v1/v2 incompatibility are checked with all 7 frozen v1
  signing fixtures. The unchanged v1 oracle must still reproduce and accept
  its own fixtures. Swapped signatures under each profile's own public key
  are rejected too; this is not merely an old-key decoding check.
- B3, signature: a separately written Node/BigInt implementation with generic
  extended Edwards coordinates reproduces all listed signature/encoding
  vectors and intermediate bytes. It also rejects all 7 v1 fixtures.
- 16 Python test methods additionally check parameter relations, deterministic
  basepoint derivation, group laws and torsion, model maps, the low-level
  Montgomery ladder against Edwards multiplication, malformed API types,
  pruning extremes and the nonidentity proof, and frozen source hashes.
- Exact regeneration reproduces the checked-in vector file byte for byte.

Counts above describe the current Ed301 corpus, not full feature parity or a
security audit. Test seeds, secrets and transcripts are public synthetic data.

## Important acceptance distinctions

R has no prime-subgroup requirement. The inherited cofactored contract accepts
correct equations with torsion in R and rejects incorrect ones. Silently
rejecting every torsion-bearing R would change the profile.

A verifier cannot enforce deterministic nonce derivation. The control with
the nonce domain removed therefore differs from the normative signer KAT but
still verifies. Omitting or changing the challenge domain is rejected. The
positive KAT intermediates catch omission from either hashing step.

## Counterimplementation independence and limits

Python reuses the project's audited affine-formula structure and built-in
modular inversion. Node implements the published generic extended-coordinate
formula and left-to-right multiplication; its inversion uses exponentiation.
It does not import Python code, reuse Python arithmetic outputs as constants,
or invoke Python to obtain expected answers. Both read the same approved
parameter artifact, as required, and compare with the generated public corpus.

This is method/language independence, not independent authorship or an
external review. Claude's separate Gate-B review remains required. Both hash
backends here use OpenSSL 3.5.8 (Python through hashlib, Node through crypto),
so no independent SHAKE implementation is claimed. Python is 3.14.7; Node is
v22.22.2, Linux x64. No runtime packages were installed.

Python integers and Node BigInt are deliberate reference-only choices from
the Phase-B assignment. The test oracle's small modular exponentiation fills
a missing Node BigInt primitive; it is not a handwritten limb backend.
SHAKE256, JSON parsing, hashes and test assertions use the runtimes' libraries.
Neither reference is constant-time or guarantees erasure of secret copies.
This work establishes no Rust/provider/integration or performance result.

## Still open before a complete Gate B

1. Martin must bind the external X301-u policy: strict canonical decoding from
   the github baseline versus masking/reduction from the integration baseline.
   No default or compromise is chosen in this subset. Raw-TLS group coverage
   is a separate unresolved integration decision; choosing the input policy
   must not silently remove that surface.
2. B1 X301 profile API, B2 DH/twist/all-zero/iteration and input-policy vectors,
   and B3 independent X301 replay remain to be implemented on that contract.
   The canonical-u mathematical ladder is not a completed X301 profile.
3. Complete the combined Phase-B artifacts, then explicitly select a Review
   snapshot and submit to Claude. Do not start Phase C before Gate B passes.

OID numbers and TLS codepoints are still unassigned and were not needed or
invented for this byte-level reference subset. No main/Review/tag promotion is
part of this intermediate implementation.

## Replay and evidence

Run `python3 -B tools/check_phase_b_eddsa.py` from the repository root. It
checks this subset's source manifest, the immutable Phase-A manifest and the
signed search-package manifest, then runs Python tests, Node and deterministic
regeneration. It makes no source writes and requires no network.

`phase-b/EDDSA_SOURCE_MANIFEST.sha256` binds code, vectors, the frozen controls
and documentation. `phase-b/SOURCES.md` binds the input artifacts. A passing
runner is not Claude's approval and deliberately reports the X301 limitation.
