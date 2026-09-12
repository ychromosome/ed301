# E4: verify the already-specialized square

Result: **existing optimization confirmed; no new arithmetic or speedup**.
The approved v2 field already has five diagonal and ten doubled cross products.
The bound v1 source has the same schedule. This corrects the premise of E4,
without substituting another optimization or carrying forward an estimated gain.

The entire non-test prefix of the shared field source is byte-identical before
and after, SHA-256 `fa23ba53afba5310a31e65353ae960eba3897dc9d2bd5f85fd5492f9bd0ec6f4`.
Ed301 and X301 compile the same shared field source. Only its cfg(test) section
changed: one additional test checks the full ten-word square against both
schoolbook multiplication and crypto-bigint `widening_mul`, with 100000 full-word
samples, 320 one-hot inputs, ten all-max cross pairs and five directed cases.

The bound derivation now states all nine exact column/carry maxima, the retained
129th bit of a doubled cross product, the two u128 word additions, the <=4 high
word and the final one-word carry. All inequalities pass. The wide reducer and
its input domain are unchanged.

## Fresh correctness

Evidence directory:
`/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e4_after_04_2026-09-10/ED301-v2_PHASE_E_core-check_ktbz6xid`

- Approved baseline rebuilt: 54 Ed301 and 25 X301 named tests.
- New source: 55 Ed301 and 26 X301 tests; every old name retained.
- Same 55/26 tests with sign-self-verify / taint-instrumentation features.
- Generated parameters, field bounds, vendor checks, Clippy with warnings denied,
  formatting, no_std host consumer and crate profile attestations: PASS.
- Phase-B replay: 8/8 PASS.
- Historical C/D1 source seals: PASS against the approved baseline snapshot.

Summary SHA-256: `cca7ed8dbd8bdab5097814238047f0a145d00d5ee64affc1e6f9567d291b1111`.
Receipt manifest SHA-256: `c07b8a60c45f78efd8fac2ed5753e144880e09196acfba6667b279929b97ba93`.
The snapshot source manifest is `3a0850982bb9cb42796aea272343010ef14fdc2a50b6a1b9c58760ff2ddb7ae1`.

## Same-run v1/before/after comparison

All 32 core cases passed, nine interleaved rotations, CPU 2, 200 ms target,
AMD Ryzen 9 5950X, Fedora rustc 1.98.0 / LLVM 21.1.8. Both versions' ordinary
profiles retain overflow checks on; the documented historical X301-v1 dependency
exception remains off. Frequency/boost settings were not changed.

Selected medians in microseconds (full raw data, dispersion and binaries retained):

| Operation | v1 | v2 before | v2 after |
| --- | ---: | ---: | ---: |
| Ed301 expand | 27.643 | 27.506 | 27.623 |
| Ed301 prepared sign | 28.786 | 28.529 | 28.452 |
| Ed301 prepared verify | 85.726 | 86.296 | 85.951 |
| Ed301 import | 96.597 | 95.928 | 96.079 |
| X301 public | 27.405 | 81.032 | 80.668 |
| X301 shared | 56.759 | 80.901 | 80.611 |

These are unchanged-code measurements, not optimization gains. The full Phase-E
target is not met here: verify remains slightly above v1 and both X301 operations
remain materially above v1. E1/E2/E3 follow; final gates and independent Gate E
are not inferred from this preparatory result.

Evidence directory:
`/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_core-bench_totko0gp`

Summary SHA-256: `ab00f34942db2a42ef13605ca904352d8eb97e72fe6c2a1c9f18f25dd94d4b8a`.
Receipt manifest SHA-256: `aaa8b11bb506aa1d1bdeff5839fba9caedbfd8dc9467dbc233156f15497e19f4`.
Runner SHA-256: `3a341b0801165bf5de182dc9c53bad8227b1b3f71ed949ca7e113a5f7201d2f0`.

## Preparation failures retained

The unmodified D1 checker correctly rejects changed C sources at its historical
unchanged-source seal. It was not weakened: Phase E has a separate checker which
checks that seal on the baseline and freshly validates optimized sources.
Two new-harness/test issues were corrected before the successful receipt:
the test-name parser initially omitted the `should panic` decoration, and the
new wide-square test initially used the deprecated alias `split_mul`. Neither
was a field arithmetic failure. The final test uses `widening_mul`; Clippy passes.
The failed source snapshots and logs remain separate, not overwritten or counted
as successful runs. Earlier arithmetic-only nine-repeat measurements also remain
available but the table above uses the final tested source.
