# E3: Ed301 import by selection-free halving

Result: **implemented using fixed-exponent Euler symbol tests; fresh host
correctness passes**. Import order remains length/canonical point decoding,
identity rejection, full subgroup check, then table construction. Both symbol
tests always run; Y=-1 and an invalid discriminant root are rejected. No input
encoding, error status, signature equation, point decoder, field reducer or
X301 arithmetic changes. The mathematical boundary and the Jacobi fallback
decision are detailed in E3_MATH_AND_CODEGEN.md.

The previous table-based [q] predicate remains under cfg(test); its 783-byte
function text is byte-identical to the pre-E3 function. The sparse [q] oracle
and optional sign-self-verify path are retained independently.

## Fresh checks

- Supplied independent proof: 156 directed/random points, three explicit
  torsion points; all 25 supplied vectors reproduce byte-for-byte.
- Rust compares every supplied intermediate and both test-only halving roots.
- 100000 random [k]G+torsion comparisons with the old [q] predicate: exactly
  6250 in each joint k-mod-4/torsion class, plus directed exceptional points.
- All 15 Gate-B point cases compare old and new import decisions.
- 100000 field values plus 0,1,-1 compare production Euler/sqrt with the
  independent Montgomery/Euler backend and the library Jacobi oracle.
- All original 54 Ed301 and 25 X301 named tests remain; final totals **60/53**,
  also with sign-self-verify and X301 secret-taint-instrumentation enabled.
- Parameter reproduction, vendor checks, field bounds, warnings-denied Clippy,
  formatting, no_std consumer and enforced build profiles pass. Phase-B: **8/8**.

Final correctness evidence:
`/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e3_after_03_2026-09-10/ED301-v2_PHASE_E_core-check_e08tjzdn`

Summary SHA-256: `04ac8cf4d8d58cb80b0acbcd17f455598e81af88f0a0db8c64fe9002bf9fab0f`.
Receipt manifest SHA-256: `76c0e109f9bf742cad5b6b7afe8ab841909798f6b9feab7cb0353b9f1f995b83`.
Rust source manifest SHA-256: `3f8e4444594319f7f1f00aef011b9989a25aea721c305d9158d0382ca609487b`.
Full frozen-source manifest SHA-256: `6bf42dc6dda18e1a2acd0e7d544bb92e8a8371a3713a2cac06b2aa7d101b9dc0`.

Independent reference evidence:
`/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_halving-proof_6j8zqqw0`

Summary SHA-256: `8f5083daec9786f06557b524ace8559733dab22205c9a523c307f3318574abfb`.
Receipt manifest SHA-256: `90ae593503b283665a4fbb8275f89599477f75261cf3b23670acd4d272a49f52`.

## Same-run before/after/v1 medians

Same runner, harnesses, CPU 2, nine interleaved repetitions and 200 ms target
as E4/E1/E2. Before is the frozen E2 source; after is the final Euler source.
Values below are microseconds.

| Operation | v1 | v2 before E3 | v2 after E3 |
| --- | ---: | ---: | ---: |
| Ed301 expand | 27.823 | 28.086 | 28.183 |
| Ed301 prepared sign | 28.897 | 29.272 | 29.288 |
| Ed301 prepared verify | 86.838 | 85.058 | 85.993 |
| Ed301 import | 97.337 | 97.033 | 66.029 |
| X301 public | 27.643 | 27.401 | 27.384 |
| X301 shared | 56.962 | 62.790 | 62.945 |

Import improves by about 32.0% against E2 and is below v1. This is slower than
the initial estimate in the assignment and is reported as measured. Sign and
X301 shared still exceed v1, so the overall Phase-E speed target is not met.
Small movements on unchanged operations are not attributed to E3. The linked
Ed301 GNU size text/read-only category grows from 529593 to 538225 bytes;
data/BSS remain 13904/264 bytes. X301 sizes are unchanged. Final full codegen,
taint, timing, resources and provider/TLS gates remain to be run on the final
Phase-E source, followed by independent Gate E.

Benchmark evidence:
`/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_core-bench__a_s9r42`

Summary SHA-256: `5e44cf8bd56ec95dc1f0df4589cbd51e0ea5577afa2f1651dae28cde58d0d3fc`.
Receipt manifest SHA-256: `2383e43abc05f15259872bbb231b37b324b15cfbff4b2909f32fff4ca2fa8105`.
After Ed301 binary SHA-256: `af118a0432dbe3b4c740b1306bdfbd19f6a13d396c2699eee3356b604d67e1b8`.
Runner SHA-256: `3a341b0801165bf5de182dc9c53bad8227b1b3f71ed949ca7e113a5f7201d2f0`.

## Retained preparation results, not final evidence

The first snapshot stopped at the X301 generator's deliberate hash check
because E3 had added generated Ed301 constants. The generator was explicitly
rebound to the reproduced declarations; the X301 output bytes remain unchanged.
Historical Gate-C/D1 source manifests were not rewritten.

The second snapshot used the available Jacobi API and passed 60/53 tests and
8/8 replay. Its import median was 52.211 us, but disassembly showed a
symbol-dependent branch in the library enum conversion. This candidate was
not retained in production and its faster number is not the E3 result.
Evidence: `/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_core-bench_jvagnida`
(summary `9e62d6fc90752452b70983719a532de7ae4c5f0080ee103755cc7dbcc018229f`),
with the decision record in
`/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_jacobi_codegen_2026-09-10`.
No assertion, call-closure or taint rule was relaxed to accept that candidate.

The byte-identical external helper retains its original trailing space on line
80 (outside the executed first 57 lines). Git's whitespace check therefore
reports that one preserved source byte; all project-authored changes pass the
check. The helper is checked by its original SHA-256 instead of reformatting it.
