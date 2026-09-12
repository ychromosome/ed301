# E1: shared Edwards fixed-base table for X301 public derivation

Result: **implemented and differentially correct in the fresh host checks**.
X301 public derivation now uses the actual shared Edwards fixed-base module
and converts `(X:Y:Z:T)` to `u=(Z+Y)/(Z-Y)`. It passes the already-validated X301
clamp directly to the fixed-base multiplier: no EdDSA expansion/pruning, no
reduction modulo q, no new public API and no new Cargo dependency. Shared-secret
derivation retains the unchanged complete 301-round canonical Montgomery ladder.

The shared scalar module is compiled only to satisfy the Edwards module's other
crate-private interfaces; it is not used to transform the X301 scalar. All secret
table digits still scan all eight entries in each row. The common finalization
performs one inversion and preserves the existing declassified zero-result status
and error ordering. An internal zero-scalar test reaches that error boundary.

Named fixed-base accumulator, result point, Montgomery numerator/denominator,
projective output, inverse, affine coordinate and output bytes have zeroizing
owners. The fixed-base accumulator's new owner also applies to Ed301; its real
scope has an unwind failpoint test that observes overwritten coordinates and
successful recovery. The existing Fe301 DefaultIsZeroes implementation moved
from the X301 crate into the shared field source, without changing its overwrite
semantics. This is a named-owner guarantee, not a claim that every register or
compiler-created copy is erased.

## Correctness and bounded early taint check

- All seven Gate-B public keys match both the table and the 301-round ladder.
- 10000 further deterministic full-byte secrets produce bit-identical results.
- All original 54 Ed301 and 25 X301 named tests remain; new totals are 56/48.
  The X301 total now also includes the shared Edwards/scalar/owner module tests.
- Both feature variants, generated parameters, field bounds, vendor verification,
  Clippy with warnings denied, formatting, no_std consumer and profile markers pass.
- Phase-B replay is 8/8; weak-secret precedence and full shared-secret round counts
  are unchanged.
- Early fixed-base taint subset: 14 successful public/import cases, defined and
  tainted, **28/28 PASS**. This is not the final full 526-run X301 gate. Its
  `shared_output_keeps_taint=false` field means this subset does not exercise
  shared-secret output; the explicit selection field identifies that scope.

Correctness evidence:
`/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e1_after_02_2026-09-10/ED301-v2_PHASE_E_core-check_8rmbdmm2`

Summary SHA-256: `b25b024981dcc64d84dd10402f3fd963461c15586aac34848d2b438d10b07eed`.
Receipt manifest SHA-256: `ca38f02e23b79a92e37b65dba775279e01e45d476a2bfe295a80cc2451d00bcf`.

Early taint evidence:
`/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e1_after_03_2026-09-10/X301-v2_PHASE_E-taint_2ur6t573`

Summary SHA-256: `eb6746d0049aee0c75b12bba6356b7bc7cfaa2e5c7f7ea924cb8a4ad54e817d9`.
Receipt manifest SHA-256: `e0190805cd7ac875ed379653d00d2812e4aa88c682b23c310ecf4aa873de48e1`.
Instrumented binary SHA-256: `d9b897e5b9d8bbb791fe39c91231165bf9784e17b95e13a9d358594d776f3ca8`.

The correctness and taint snapshots have byte-identical Rust trees, source
manifest SHA-256 `e50cf128070024cdde1705f6a964c5d8b6846cf61326643c9f3cea95eaacc4ce`.
The benchmark consumes the same Rust tree. The first preparation run correctly
flagged an obsolete keygen test expectation of 301 public-derivation ladder
rounds and an unused generated word constant; both were addressed explicitly.
The final public tests retain a separate 301-round ladder comparison, and a
compile-time assertion binds the generated base words to the public bytes.

## Before/after/v1 measurement

32 cases, nine interleaved repetitions, CPU 2, 200 ms calibrated target,
same runner/harness/profile as E4. Selected medians in microseconds:

| Operation | v1 | v2 before E1 | v2 after E1 |
| --- | ---: | ---: | ---: |
| Ed301 expand | 27.753 | 27.752 | 27.653 |
| Ed301 prepared sign | 28.546 | 29.166 | 29.032 |
| Ed301 prepared verify | 85.383 | 84.572 | 84.138 |
| Ed301 import | 96.701 | 95.625 | 95.512 |
| X301 public | 27.284 | 80.625 | 27.103 |
| X301 shared | 56.372 | 80.735 | 80.500 |
| X301 prepared public | n/a | 80.232 | 27.107 |

Public derivation is about 66.4% faster than before; its median is narrowly
below v1 in this run. The small differences on unoptimized operations are not
claimed as E1 gains. Sign and shared-secret medians still miss the Phase-E
target. Final same-run measurements, full taint, dudect, updated strict codegen
closure checks, resources, provider/TLS matrices and independent Gate E remain.

The X301 benchmark's GNU size text/read-only-data category grows from 393063 to
470458 bytes (+77395), reflecting the shared table and fixed-base code. This is
a preliminary linked-binary size observation, not the final resource gate.

Benchmark evidence:
`/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_core-bench_1wbr9rpf`

Summary SHA-256: `b4167e5957492d7a4626d5779733d56e6f11febe99eca73ffe198ad85a9d32ce`.
Receipt manifest SHA-256: `0e23dcfe89e53c6d962355c27b0ab1be36eb0b062342b85cc176a4143cfeb7a0`.
After X301 binary SHA-256: `9bdd9a439d85a8edd3c52320bca298b61a792b47872e670dcffd851c9d65d2d7`.
