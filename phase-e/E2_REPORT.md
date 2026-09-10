# E2: complete X301 ladder in the lazy field domain

Result: **implemented and differentially correct in the fresh host checks**.
All five private ladder state coordinates now use Fe301Lazy in [0,2p).
The complete 301-round schedule, scalar-bit reads and conditional swaps remain;
leading zero bits do not shorten the ladder. A24 remains a full five-limb field
multiplication. Only the two returned projective coordinates are canonicalised.
The final inversion, affine conversion, zero-result status, strict public import,
weak-secret precedence and the E1 fixed-base public path are unchanged.

The per-round induction and all intermediate product maxima are documented in
`phase-c/FIELD_BOUNDS.md` and recomputed by its exact-integer checker. Every
product is below 2^606 and every round restores the [0,2p) state bound. No
additional tightening is necessary. No field reducer or wide product changes.

The lazy conditional selection uses the same five-word constant-time assignment
as the canonical type. Its Default is all-zero words and its Zeroize
implementation uses the same volatile overwrite mechanism. The existing real
ladder-scope unwind test now checks the lazy state. An added field test covers
selection of zero and 2p-1, then verifies that all five words are overwritten.
This is a named-owner guarantee, not erasure of every compiler-generated copy.

## Fresh correctness

- The previous canonical ladder remains under cfg(test). Its 1285-byte function
  body is identical to the pre-E2 body after substituting private oracle names.
- All Gate-B curve/twist evaluations and all 33 error cases are compared with it.
- 10000 deterministic raw-secret/canonical-peer cases, including u=0,1,2, compare
  exact output bytes or exact error status. Both implementations visit 301 rounds.
- All five lazy state bounds are asserted after every test-mode round.
- All original 54 Ed301 and 25 X301 named tests remain. New totals: **57/50**,
  equal for the sign-self-verify and X301 taint feature variants.
- Generated parameters, vendor verification, field bounds, Clippy with warnings
  denied, both format checks, no_std consumer and build-profile markers pass.
- Fresh Phase-B replay: **8/8**. No failed preparation run was needed for E2.

Correctness evidence:
`/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e2_after_01_2026-09-10/ED301-v2_PHASE_E_core-check_uzw33t9p`

Summary SHA-256: `4df9d8122881b905534c8409af1f113bb9d3aab40ccca3c7ec9070a9a5d0a341`.
Receipt manifest SHA-256: `7611a5fbca4e6158720989a1fb43c97eee94b7042df78f539648eba3c58a4878`.
Rust source manifest SHA-256: `79543114d54c811397a9437bdf8d06f90bdf5e58b2b7a3f805f4a1e7f4814ac8`.
Full frozen-source manifest SHA-256: `af42bd85fee184639e88c2d5e78f68e481a550b9eea0d49152e647c0cbe35c6f`.

## Before/after/v1 measurement

32 cases, nine interleaved repetitions, CPU 2, 200 ms calibrated target,
same runner/harness/profile as E4 and E1. Selected medians in microseconds:

| Operation | v1 | v2 before E2 | v2 after E2 |
| --- | ---: | ---: | ---: |
| Ed301 expand | 27.598 | 27.730 | 27.860 |
| Ed301 prepared sign | 28.562 | 28.702 | 28.687 |
| Ed301 prepared verify | 85.950 | 84.955 | 84.386 |
| Ed301 import | 96.888 | 95.570 | 95.723 |
| X301 public | 27.848 | 27.137 | 27.309 |
| X301 shared | 56.554 | 80.552 | 62.704 |
| X301 prepared shared | n/a | 80.544 | 62.213 |

Raw shared-secret derivation improves by about 22.2% against E1, but remains
about 10.9% above v1 in this run. Sign also remains narrowly above v1. The
Phase-E speed target is **not yet met**; no ladder shortening or weakened
validation is used to close that gap. Small differences on unchanged paths
are not attributed to E2. Final same-run measurements, full taint, dudect,
updated strict codegen closure checks, resources, provider/TLS matrices and
independent Gate E remain mandatory.

The X301 benchmark's GNU size text/read-only-data category decreases from
470458 to 468314 bytes (-2144); writable data and BSS remain 14008 and 264 bytes.
This is a preliminary linked-binary observation, not the final resource gate.

Benchmark evidence:
`/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_core-bench_aq2zplo3`

Summary SHA-256: `893d58b3f1ad1a0e226b2463d127cff944a821add46a20e46cfb9d4331d7ecba`.
Receipt manifest SHA-256: `5b92d58ed348c52eb46e70e319a724b0640adf56a1298ee75c2d63d63ef56331`.
After X301 binary SHA-256: `b545997caeedf1192977c6d83089bfb37b26a0164fc0e904cd85b1e2ec374b88`.
Runner SHA-256: `3a341b0801165bf5de182dc9c53bad8227b1b3f71ed949ca7e113a5f7201d2f0`.
