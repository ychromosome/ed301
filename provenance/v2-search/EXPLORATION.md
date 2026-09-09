# Disclosed exploratory work

The v2 candidate was found before this publication package existed. Martin chose
the family `d=-301` after exploration of `d=145`, `d=89`, and `d=-301` over the
fixed field `p=2^301-2^89+907`. This family choice is an author decision, separate
from the first-valid-counter rule within that family.

Three filter stages occurred: the inherited v1 filter, an intermediate `t<0`
filter, and the final requirement that the main subgroup have exactly 300 bits.
The intermediate trace condition is weaker than the final one for this field.
The fixed final condition is `4q >= 2^301`, equivalently `t <= 908-2^89`.

## Archive and scope

`exploration.tar.gz` contains the supplied exploratory directory snapshot:
7,446 regular files, including 7,381 original raw block files; uncompressed
regular-file contents total 1,682,354 bytes. It includes the old workers and
drivers, status/coverage reports, candidate values, old and corrected audits,
the deliberately failing error-recovery controls, and the v3 worker check.

Archive SHA-256:

```text
06275ec4934992f34fcfc151119de238098de52ccbf4e31c50a0741641f45a99
```

Archive member order, ownership and timestamps were normalized for reproducible
packaging; gzip filename/time metadata was omitted. These archive timestamps
are **not historical time evidence**. Regular-file contents were preserved.
The archive contains no absolute member paths, parent traversal, or symlinks.

Historical scripts are evidence, not instructions to run them: some retain old
absolute output paths and obsolete failure handling. Use only the manifest-bound
v3 tools outside this archive for the new confirmation run.

## Coverage reconstructed from raw records

The supplied coverage report and a separate read-only reconstruction agree on:

| Family and phase | Counter range | Unique complete blocks | Recorded hits |
|---|---|---|---|
| -301, inherited v1 rule | 0..85439 | 1335 | 84722; main subgroup only 299 bits |
| -301, intermediate t<0 | 85440..93951 | 133 | none |
| -301, final 300-bit rule | 93952..246527 | 2384 | 246492; main subgroup 300 bits |
| 89, inherited v1 rule | 0..68607 | 1072 | 68592; also satisfies the final rule |

The -301 final phase has 2,763 files: 379 additional block copies agree on the
test count and hit list. No gaps or conflicting records were found in those
ranges. Thus the recorded searches support 246492 and 68592 as their respective
first valid counters under the final rule. This is a check of existing records,
not a new point count of every rejected candidate or proof of the historical
execution environment. The fresh confirmation run remains mandatory.

The 145 family was paused without a final-rule hit. Its earlier counter 13201
has a 299-bit main subgroup and fails the final filter. The archive preserves
the actual block records and the supplied coverage/status descriptions.

Some intermediate JSONL files were truncated or reused during the exploratory
parallel runs; `STATUS.md` in the archive discloses this. Raw block files are the
basis of the coverage reconstruction. They must not be mixed with fresh run
outputs or be counted as evidence that the formal run has already occurred.

## Historical audit corrections

The earliest audit code confused properties observed for the v1 winner with
selection requirements. Maximum embedding degree and Frobenius conductor 2
were removed as extra requirements; exact values and all possible conductor
divisors remain reported. The selected -301 candidate has embedding degrees
`(q-1)/4` and `(q_t-1)/2`, fundamental CM discriminant size 290 bits, and
Frobenius conductor 94.

Old mixed result files and pass markers are retained as historical artifacts,
not treated as valid clean audit evidence. Corrected v3 tools use fatal error
handling. The supplied v3 report for -301 has one final pass marker and reports
main/twist subgroup sizes 300/299, with approximately 149.326 bits in the
negation-optimized Pollard-rho expected-work model. That audit is exploratory
evidence and does not replace A3 after the confirmation run.

The prediction in `EXPECTED_CANDIDATE.json` is derived from the archived supplied
candidate file; its values are unchanged. Neither the prediction nor the old
audit may override a discrepant fresh computation.
