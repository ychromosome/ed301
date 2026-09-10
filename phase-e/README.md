# Phase E: optimization under a fresh Gate E

Phase E is authorized by Martin's 2026-09-10 instruction and the hash-bound
Gate-D approval. This is still Stage 1: x86-64, private-libctx test providers,
OpenSSL 3.5.8 and 4.0.2, owned test inputs and localhost. Gate E remains Claude's
independent review. Stage 2 requires Martin's separate explicit approval.
No installation, RPM activation, production use or additional publication is
authorized here.

## Authoritative inputs

| Input | SHA-256 |
| --- | --- |
| `/home/martin/Dokumente/ED301/GATE_D_FREIGABE_UND_PHASE_E_START_2026-09-10.md` | `0eff72f3c509a70e7d87ebc13fc1f794be4d63c6819bf52e5a6ea72d7d7b8ddd` |
| `/home/martin/Dokumente/ED301/AUFTRAG_EMMY_PHASE_E_OPTIMIERUNG_2026-09-10.md` | `5faf1c1fa7c5c4fd8f6473ef298b6fdea3a9df7b9dedf320ae00ff566c6c2b93` |
| `/home/martin/Dokumente/ED301/PHASE_E_subgroup_halving_proof.py` | `cabec1f325944610049bc1282691890af9dab4188615f22bc5e74adbd9b7f32d` |
| `/home/martin/Dokumente/ED301/PHASE_E_subgroup_halving_vectors.json` | `e78ae62a636242ba9c01f4a4a0edce7d38dbe89ebb1508b144baaa3334b91737` |

Approved D2 code is commit `5dcb89fa97e85e6bba14a32a29586326f5696052`.
The additive approval/contract commit is
`a7eeab14c5e2bd850a57ac76b154d40c7f71823d`; this is the published Testing
starting point, not a release.

## Method

Order: E4 verification, E1 fixed-base public derivation, E2 lazy shared-secret
ladder, E3 subgroup halving, optional E5 sign folding, E6 DER encoding analysis.
Each completed item has its own commit, source manifest and before/after
receipt. Historical C/D manifests are checked against the historical snapshot;
they are not rewritten to falsely describe an optimized source as unchanged.

The Phase-E correctness runner builds the approved baseline again to extract
the exact 54 Ed301 and 25 X301 test names. Every name must remain in the new
test inventory, with no failed, ignored or filtered tests. New tests are
additional. It checks both feature variants, generated constants, field
bounds, vendor integrity, Clippy, formatting, a no_std host consumer and
Phase-B replay. This is not a side-channel gate.

The per-optimization core benchmark runner rebuilds v1, before and after,
uses the same harness for all three and interleaves exactly nine rotations
on CPU 2 with a 200 ms calibrated target. All four Ed301 core operations and
all D1 X301 core operations are retained, including the separate v2 prepared
APIs. Only historical X301-v1 crypto-bigint retains overflow checks off;
all v2 crates have checks on. No governor or boost policy is changed.
The complete provider/TLS, timing, taint, codegen and resource gates must run
again on the final Phase-E source and actual binaries. Core microbenchmarks
do not replace those final gates or Claude's independent Gate E.

Safety and contracts take priority over the target of beating v1. No manual
assembler/SIMD field arithmetic, ladder truncation, input masking or relaxed
encoding/subgroup/error-order rule is part of Phase E. Missed performance
targets will be reported explicitly.
