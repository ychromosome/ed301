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
Phase-E state. Set `GATE_D_SOURCE` and `PREVIOUS_E_SOURCE` to the authenticated
source trees from the corresponding evidence packages. From the repository root:

```sh
python3 -I -B phase-e/tools/check_core_correctness.py \
  --baseline "$GATE_D_SOURCE" --previous "$PREVIOUS_E_SOURCE"
```

For an extracted package, substitute its corresponding authenticated source
trees. The runner rebuilds the baseline and previous inventories, retains
every named test, and checks both current core feature variants, generated
parameters, field bounds, vendor integrity, profile markers, Clippy,
formatting, a downstream `no_std` consumer, historical Phase-B replay and
current Python/Node checks including the shared X301 error-priority corpus.
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
