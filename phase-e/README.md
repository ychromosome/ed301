# Phase E: optimization and verification

E8 completed the x86-64 optimization series. Start with the
[final report](E8_FINAL_REPORT.md), [benchmarks](E8_FINAL_BENCHMARKS.md),
[resource measurements](E8_FINAL_RESOURCES.md) and
[review decision](reference/e8_followup/CLAUDE_GATE_E8.md).
Later [review follow-ups](E8_REVIEW_FOLLOWUP.md) and the
[four-pass static review](SECURITY_DEEP_REVIEW_CLOSURE.md) are separate records.

## Current core checks

The combined runner requires an immutable approved Gate-D baseline. The
optional previous snapshot adds a test-retention check against a later
Phase-E state. For the local evidence trees:

```sh
python3 -I -B /home/martin/Dokumente/ED301/ed301/phase-e/tools/check_core_correctness.py \
  --baseline /home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e4_before_2026-09-10/source \
  --previous /home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e8_final_01_2026-09-10/source
```

For an extracted package, substitute its corresponding authenticated source
trees. The runner rebuilds the baseline and previous inventories, retains
every named test, and checks both current core feature variants, generated
parameters, field bounds, vendor integrity, profile markers, Clippy,
formatting, a downstream `no_std` consumer and historical Phase-B replay.
It does not run the side-channel gates.

Historical C and D1 runners apply only to their recorded commits: C expects
54 Ed301 tests and D1 requires unchanged C inputs. Historical reports,
archives and source manifests are not current-checkout manifests. The
maintained READMEs may change without rewriting those historical seals.

## Provider checks and replay

Provider stages use the [D2 controllers](../phase-d/d2/README.md) and complete
authenticated OpenSSL lane receipts. Independent builds need their own
source and binary evidence; a build prefix alone is insufficient.

[`e8_handoff/verify_handoff.py`](e8_handoff/verify_handoff.py) verifies the
completed E8 bundle against an externally supplied manifest hash. Packaged
replay is distinct from fresh timing, taint, memory and benchmark runs.

The [codegen policy](CODEGEN_POLICY.md) binds the inspected compiler/profile;
X301 checks require GNU awk. A new compiler requires separate binary
acceptance, not a relaxed historical allowlist. This remains open for the
[Fedora 45 candidates](../packaging/fedora/README.md).
