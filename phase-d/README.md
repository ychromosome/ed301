# Phase D: X301 core and OpenSSL integration

D1 introduced the strict X301-v2 Rust core at commit
`67f2910e7697cdab782cc992e44dc28843f93970`.
Its [report](D1_REPORT_2026-09-10.md) records correctness, performance and
binary checks for the original 301-round implementation.

The D1 correctness runner requires unchanged historical Phase-C inputs.
It will reject optimized E8 sources; use the
[Phase-E verification guide](../phase-e/README.md) for current code.
Historical manifests remain tied to the snapshots they identify.

[D2](d2/README.md) added providers, persistent formats and TLS integration.
The [current integration contract](../docs/INTEGRATION.md) defines the interfaces;
[Gate-D approval](d2/GATE_D_APPROVAL.md) records the review decision.
The initial [feature inventory](FEATURE_INVENTORY.md) and
[implementation plan](IMPLEMENTATION_PLAN.md) are historical planning records.
