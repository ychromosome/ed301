# Phase E: optimization under a fresh Gate E

## Completed scoped security review

The four-pass offline Deep Scan of the two Rust cores and both providers at
commit ddc6e5d is complete, with zero reportable findings. Its retained
cleanup questions, static-only limitations, original artifacts and the
comparison with existing codegen/taint evidence are recorded in
[/home/martin/Dokumente/ED301/ed301/phase-e/SECURITY_DEEP_REVIEW_CLOSURE.md](SECURITY_DEEP_REVIEW_CLOSURE.md).
This documentation closeout is not a new Gate E or Stage-2/release approval.
Historical reports and source manifests remain bound to their original
commits; no past coverage or PASS result is retroactively widened.

## Current correctness entry point and historical receipts

Use the Phase-E runner for the optimized Ed301 and X301 sources:

```sh
python3 -I -B /home/martin/Dokumente/ED301/ed301/phase-e/tools/check_core_correctness.py \
  --baseline /home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e4_before_2026-09-10/source \
  --previous /home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e8_final_01_2026-09-10/source
```

These example arguments name existing immutable local snapshots: the approved
pre-optimization Gate-D source and the E8 source respectively. When using an
extracted evidence package, select its corresponding authenticated snapshots
instead. The runner checks historical seals on the baseline, rebuilds the
baseline/previous test inventories, and retains every named test in the
current source. It does not treat historical C/D1 checkers as current gates:
the C checker expects 54 tests and the D1 checker requires unchanged C inputs.

Provider stages reuse the bound D2 controllers. Their full OpenSSL lane
receipts include sources, input archive, build logs, installed files and
external digests; an independently built prefix is not a substitute. See
/home/martin/Dokumente/ED301/ed301/phase-d/d2/README.md.
For replay of the completed E8 package use
/home/martin/Dokumente/ED301/ed301/phase-e/e8_handoff/verify_handoff.py
with the bundle and externally supplied manifest hash. Replay is not a new
build or a full repetition of timing, memory and benchmark stages.

The codegen gate requires the toolchain and GNU-awk dependency documented in
/home/martin/Dokumente/ED301/ed301/phase-e/CODEGEN_POLICY.md.
Old archives, reports and manifests remain tied to their original commits;
later documentation/test follow-ups do not retroactively change their inputs.

## Original Phase-E authorization and method

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
