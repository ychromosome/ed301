# D2: provider, formats and TLS integration

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
