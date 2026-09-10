# D2: provider, formats and TLS integration

## Historical D2 scope; reuse by Phase E

The completed D2 integration snapshot is commit
`5dcb89fa97e85e6bba14a32a29586326f5696052`. The status text below records its
original development phase; it does not describe the later optimized E8 core.
Historical C/D1 seals and D2 receipts continue to bind their original inputs.

Phase E reuses the source-bound D2 functional/memory/CLI/TCP controllers.
They require a complete immutable source snapshot and authenticated OpenSSL
lane receipts, not merely a locally installed OpenSSL prefix. In particular,
/home/martin/Dokumente/ED301/ed301/phase-d/d2/tools/verify_openssl_lane.sh
checks the source/archive/log layout and the externally pinned lane seal.
For --openssl-lane use the authenticated lane from the corresponding evidence
package. Independent builds need their own evidence workflow; do not bypass
or replace the historical digest checks to make them appear identical.

Current core checks and the distinction between fresh stage execution and
packaged replay are described in
/home/martin/Dokumente/ED301/ed301/phase-e/README.md.

## Original D2 development scope

Active development on `Testing`, following D1 commit
`67f2910e7697cdab782cc992e44dc28843f93970`.
The approved decision input is preserved under
/home/martin/Dokumente/ED301/ed301/phase-d/d2/inputs.

The Phase-A/B/C and D1 source files and evidence remain unchanged. D2 adds
provider adapters to the existing Rust cores; performance optimization of
the D1 ladder is a later, separately gated change.

Order: bind donor sources and identifiers; Ed301 KEYMGMT/SIGNATURE and codecs;
strict X301 KEYMGMT/KEYEXCH and codecs; OpenSSL-owned ML-KEM hybrid; TLS and
version-isolation tests; final-DSO correctness/taint/codegen/timing/sanitizer
and reproducible-build evidence; same-layer benchmarks and handoff.

Test authority is limited to private OSSL_LIB_CTX instances in local test
processes, build-local modules, fresh uncommitted test keys/certificates,
and project-owned localhost endpoints on ephemeral ports. There is no
authority for system configuration, installation, external endpoints,
push or publication. Packaging and activation remain a post-Gate-D stage
requiring a separate explicit go-ahead.

Until evidence is recorded per inventory row, this directory describes work
in progress, not completed functional parity or a Gate-D approval.
