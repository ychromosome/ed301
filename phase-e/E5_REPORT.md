# E5: fold the sign of d into Edwards addition

Result: implemented as a small algebraic change. Runtime extended addition,
mixed addition and point validity use the positive magnitude 301 with the
corresponding sum/subtraction exchanged. Cached points explicitly store
`dt_abs=301*x*y`, including the compile-time fixed-base table. Negating a
point still negates this cached product. Dedicated doubling contains no d
term and is unchanged. There are no encoding or error-order changes.

The canonical `add_const` and `double_const` functions remain unchanged as
independent test oracles. The now-unused lazy negation remains test-only,
including its existing zero/extreme-value tests. The field-bounds document
derives why swapping the two loose linear expressions preserves all bounds.

## Fresh correctness

All **61 Ed301 and 54 X301 tests** pass, also in sign-self-verify and
secret-taint-instrumentation variants. All original 54/25 named tests remain.
The additional test checks every compile-time fixed-base table entry, runtime
and const cache construction, cache negation, identity and directed torsion
against the original addition formula. The retained 5000-point differential
formula test and all Gate-B vectors pass unchanged.

Both generators, exact field bounds, vendor integrity, warnings-denied Clippy,
formatting, no_std consumer and build-profile markers pass. Phase-B: **8/8**.

Evidence:
`/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e5_after_01_2026-09-10/ED301-v2_PHASE_E_core-check_mf3w_bl_`

Summary SHA-256: `206cbf90d97f95adf6883859cd243b3b463dabe2937090d1140ebfc9962d1512`.
Receipt SHA-256: `d9d1c3bb56e45c7bcdb224ff31cfe23e6e5a5e4172ecb5f285e7554050341908`.
Rust manifest SHA-256: `1819d32b142e27155f5c62fc8943b326eea71adf95c5dfb547010964be1d78b9`.
Frozen full-source manifest: `097296a1eedbf37818a11ca76726895b98556348927f9fbc9fdc967169cabc0b`.

## Same-run before/after/v1 medians

Identical runner and harnesses, CPU 2, nine interleaved repetitions, 200 ms
calibration target as E4/E1/E2/E3. Before is the final E3 Euler snapshot.
All 32 core cases are present in the receipt; values below are microseconds.

| Operation | v1 | v2 before E5 | v2 after E5 |
| --- | ---: | ---: | ---: |
| Ed301 expand | 27.659 | 27.959 | 27.643 |
| Ed301 prepared sign | 29.120 | 29.456 | 29.011 |
| Ed301 prepared verify | 85.536 | 84.586 | 84.694 |
| Ed301 import | 97.569 | 64.390 | 63.844 |
| X301 public | 27.241 | 27.399 | 27.561 |
| X301 shared | 56.480 | 61.945 | 62.054 |

Sign and import improve by about 1.5% and 0.85% versus the paired E3 build.
The estimated verify improvement is not observed (+0.13%); no speedup is
claimed for that lane. Sign is only 0.38% below v1 in this run and the
variation is larger than that margin. X301 public/shared remain above v1,
so the overall Phase-E speed target is **not met**. Shared arithmetic is
unchanged by E5; its small movement is not attributed to this change.

GNU size text/read-only bytes: Ed301 538225 -> 537745 (-480), X301
468314 -> 468330 (+16). Data/BSS stay 13904/264 and 14008/264 bytes.
Full final codegen, taint, timing, resources and provider/TLS gates are
separate; these core results do not constitute independent Gate-E approval.

Evidence:
`/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_core-bench_xbc_fsnd`

Summary SHA-256: `ff1867baccaff3856163fe1df92f25c4885045a325c1a7b4fcfcba5a4bee3802`.
Receipt SHA-256: `6a7b7372dd69188b3a6087ed2e2c9ca148cc900a8169e865612c3bf94227ee72`.
Ed301 binary SHA-256: `43f2af86910321b927cf363d8f0bc53194ed0451e3ca8dc9f3dbc5b86ac6c39b`.
X301 binary SHA-256: `1cba1577687318bfd0ee0c9b8ee8e1615c22a0997cad96ac1b5e5c76522baebb`.
Runner SHA-256: `3a341b0801165bf5de182dc9c53bad8227b1b3f71ed949ca7e113a5f7201d2f0`.
