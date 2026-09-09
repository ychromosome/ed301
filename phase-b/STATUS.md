# Phase B: Ed301-EdDSA and X301 reference package

Started 2026-09-09 after Martin's go-ahead following Claude's Gate-A approval.
The Ed301 subset was committed as `42c33bc9b892110720fcd7481e9d33ee6d1bed08`.
Martin subsequently supplied the X301 revision-2 contract, explicitly including
the inherited twist-order-secret exclusion. The complete reference package is
prepared for Claude's Gate B. This is not Gate-B approval or a product release.

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

## X301 completion under revision 2

- B1: strict peer decoding through the existing field decoder, unchanged
  clamping on a secret copy, explicit import validation, rejection of k=N_t,
  fixed 301-step ladder with Gate-A A24_minus, mandatory infinity/all-zero
  errors and canonical output. KeyGen retries only the excluded secret.
- B2: 7 key derivation/clamping cases, 4 DH pairs in both directions,
  24 main-curve/twist evaluations, 33 malformed/all-zero inputs and all
  64 raw aliases that clamp to N_t. The iteration recurrence has newly
  computed checkpoints 1, 10, 100 and 1000; no v1 outputs are inherited.
- B3: the separate Node X301 implementation uses a direct add/double pair
  schedule, rather than the Python swap schedule. It agrees on every X301
  vector and rejects the same malformed inputs before ladder entry. All
  64 weak aliases are checked across clamp, import, Public, Shared and
  KeyGen resampling. Both infinity and a forced affine zero are errors.
- 13 new Python test methods verify the same behavior and independently
  recompute all 24 positive u evaluations by affine chord/tangent arithmetic
  on the Gate-A Weierstrass curve or specified z=2 twist. Public keys are
  also checked against Edwards multiplication. Tests reconstruct the clamp
  bounds, weak-alias count and twist annihilator with the v2 parameters.
- Runtime tracing counts exactly 301 Python ladder rounds, including raw
  mathematical scalars 0 and 1 with leading zeros. Test spies prove that
  malformed peer inputs and excluded secrets cause no first ladder step.
- Result APIs return complete bytes or raise: sentinels remain unchanged on
  failure. There is no caller-supplied output buffer in the reference API;
  provider-buffer atomicity is still a Phase-D test, not claimed here.
- The old integration normalization expectations are explicitly classified
  as historical in `HISTORICAL_X301_TESTS.md`. Their source is unchanged;
  hybrid/provider/TLS test intentions are retained for Phase D.

The complete Python suite has 29 test methods. These counts describe Phase-B
references, not full feature parity or a security audit. All seeds, secrets
and transcripts in the corpus are public synthetic data.

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
X301 uses hmac.compare_digest and Node crypto.timingSafeEqual for fixed-length
secret/result comparisons. These existing primitives avoid homemade byte
comparison routines but do not establish constant-time behavior for the
surrounding Python/BigInt arithmetic or later Rust/provider binaries.
Neither reference is constant-time or guarantees erasure of secret copies.
This work establishes no Rust/provider/integration or performance result.

## Remaining gates and deferred decisions

1. Claude must perform Gate B on the selected immutable commit/archive:
   independently recalculate vector samples and check negative coverage
   against the profile and revision-2 contract. Local replay is not that
   external approval. Do not start Phase C before Gate B passes.
2. Phase C still covers Rust, field-reduction bounds, generated constants,
   actual constant-time/codegen/taint/timing evidence and performance.
3. OIDs, TLS codepoints, Raw-TLS versus Hybrid-only, provider/codec and
   handshake work remain Phase D. The input policy no longer blocks Phase B.

OID numbers and TLS codepoints are still unassigned and were not needed or
invented for the byte-level references. Raw XDH values carry no profile tag;
this package does not claim that v1 u bytes are universally rejected by v2.
The later protocol/container identity must select the correct profile.
No main promotion, tag change or product release is authorized by this package.

## Replay and evidence

Run `python3 -B tools/check_phase_b.py` from the repository root. Its eight
steps check the full source manifest, the immutable Phase-A manifest and the
signed search-package manifest, then run all Python tests, both Node checks
and exact regeneration of both vector files. No network or source writes are
required. This replaces the earlier Ed301-only runner in the development tree;
that earlier replay remains available at its original immutable commit.

`phase-b/PHASE_B_SOURCE_MANIFEST.sha256` binds code, vectors, the unchanged
legacy controls, contract copy and documentation. `phase-b/SOURCES.md` binds
the input artifacts. `phase-b/GATE_B_HANDOFF.md` gives the review checklist.
A passing runner explicitly reports that Claude's Gate B remains required.
