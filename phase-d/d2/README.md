# D2: providers, formats and TLS

The completed D2 snapshot is commit
`5dcb89fa97e85e6bba14a32a29586326f5696052`.
It adds Ed301/X301 providers, DER/PEM codecs, the OpenSSL-owned ML-KEM hybrid
and TLS 1.3 integration to the original Rust cores.

- [Current integration contract](../../docs/INTEGRATION.md) and [identifier registry](../../docs/OID_REGISTRY.md)
- [D2 report](D2_REPORT_2026-09-10.md), [feature inventory](FEATURE_INVENTORY.md) and [benchmarks](D2_BENCHMARKS_2026-09-10.md)
- [Gate-D approval](GATE_D_APPROVAL.md) and [handoff/replay guide](HANDOFF.md)
- [Later stock-CLI and module-name checks](N2_N4_PREPARATION.md)

Phase E reuses the functional, memory, CLI and TCP controllers in this
directory. Their `--openssl-lane` argument requires the authenticated lane
from the corresponding evidence package: sources, archive, build logs,
installed files and the externally pinned seal. A system installation or
independent build prefix alone does not satisfy
[`verify_openssl_lane.sh`](tools/verify_openssl_lane.sh).

Use the [Phase-E guide](../../phase-e/README.md) for current verification and
the [Fedora guide](../../packaging/fedora/README.md) for package tests.
D2 reports and manifests retain their original scope and results.
