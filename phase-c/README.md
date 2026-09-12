# Phase C: signature-core evidence

This directory records the original Ed301-EdDSA-v2 Rust core at commit
`0be31f50cccf3d5af4675d081661ea463c575027` and its
[Gate-C approval](GATE_C_APPROVAL.md).

The historical correctness runner requires exactly 54 tests. It is not a
checker for the optimized core with 65 tests and will reject that later
snapshot. Use the [Phase-E verification guide](../phase-e/README.md) for
current sources. Phase E reuses selected measurement and taint harnesses
with fresh source and binary receipts.

Historical results and contracts:

- [Final report](GATE_C_REPORT_2026-09-10.md) and [handoff](GATE_C_HANDOFF.md)
- [Initial C1/C2 measurements](BERICHT_C1_C2_2026-09-10.md)
- [Field bounds](FIELD_BOUNDS.md) and [test inventory](TEST_INVENTORY.md)
- [Source import](SOURCE_IMPORT.md) and [benchmark contract](BENCHMARK_CONTRACT.md)

Source manifests apply only to their recorded snapshots. The reports retain
their original results and then-open items; current status is in the
[project README](../README.md).
