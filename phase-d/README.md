# Phase D work: D1 core baseline

Current local results:
[/home/martin/Dokumente/ED301/ed301/phase-d/D1_REPORT_2026-09-10.md](/home/martin/Dokumente/ED301/ed301/phase-d/D1_REPORT_2026-09-10.md).

This is the first X301-v2 Rust-core milestone, not the complete provider/TLS
phase and not a Gate-D approval. The measured implementation is intentionally
the complete canonical 301-round ladder. Its performance regression against
the optimized v1 integration is recorded, not hidden or turned into a claim
about the intrinsic speed of the curve.

The D1 source manifest covers the new crate, shared Rust sources/dependencies,
new tests/tools and the bound prior phase/input manifests. The separate
evidence index binds the measured binaries and original receipt folders.
The approved Phase-A/B/C snapshots and their archives remain unchanged.

Reproduce the local core checks:

```sh
python3 -I -B /home/martin/Dokumente/ED301/ed301/phase-d/tools/check_x301_correctness.py
python3 -I -B /home/martin/Dokumente/ED301/ed301/phase-d/tools/run_x301_taint.py
python3 -I -B /home/martin/Dokumente/ED301/ed301/phase-d/tools/run_x301_benchmarks.py
python3 -I -B /home/martin/Dokumente/ED301/ed301/phase-d/tools/run_x301_timing.py
```

Codegen consumes the exact benchmark ELF and compiler marker named in the
report. Resource measurements consume those same measured ELFs. These scripts
require the bound local donor/baseline material and installed system tools;
they are not yet an independently relocatable full Gate-D release bundle.

Outstanding D2 decisions are OIDs/private codepoints, the Raw TLS surface
beside Hybrid, and the X301 persistent-key format contract. Provider
activation/deployment and future pushes require their explicit approval.
