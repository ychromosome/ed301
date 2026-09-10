# D1 source provenance

Normative inputs remain the approved Gate-A parameters, Gate-B vectors and
revision-2 X301 contract in the repository. The active starting commit is
2b605d77d1f940f74e090796d7b345ef812a1da1, which records Gate-C approval without
changing the approved core snapshot 0be31f50cccf3d5af4675d081661ea463c575027.

The strict ladder/API donor at
/home/martin/Dokumente/ED301/x301-github has no Git commit. Its Git-visible
source set (tracked plus nonignored untracked files, excluding build/cache
outputs under its existing ignore rules) was captured in
/home/martin/Dokumente/ED301/X301-v1_D1_DONOR_2026-09-10.tar.gz:
af4f808bb04a03946021569d051cead20dc8689923ac6e56a9630fb0a9acee30.
All 911 files were verified from a fresh extraction against
/home/martin/Dokumente/ED301/ed301/phase-d/provenance/X301_V1_DONOR_SHA256SUMS,
whose SHA-256 is a0d4fd9cf102bd53ce78c222a9716afc924fd8c46f0b5ebee6ac879006fe9857.
No fictitious commit is assigned to that tree, and the original tree is not modified.

The v1 integration source and performance comparison is commit
569dc4ff10e0e5e19d106cbe490d2a5aaeac935e in
/home/martin/Dokumente/ED301/x301-integration. It supplies the later provider/
hybrid inventory and existing zeroizing-state patterns. Its normalization,
fixed-bit shortcut and fast Edwards Public path are historical implementation
choices, not v2 normative input rules.

Shared, unchanged Phase-C source modules:

| File | SHA-256 |
|---|---|
| /home/martin/Dokumente/ED301/ed301/rust/crates/ed301-eddsa/src/field_5x64.rs | 6bb0214c767094d2f2122cdb1a62c294d63a555c8c861696328224a5d4a0940a |
| /home/martin/Dokumente/ED301/ed301/rust/crates/ed301-eddsa/src/field.rs | a75009d45f20a6d1d8644872b1f69e7d769a659b7771e9f71cc7617373a2fd4d |
| /home/martin/Dokumente/ED301/ed301/rust/crates/ed301-eddsa/src/generated_parameters.rs | 089321a9f25162712f02275ebafbf7f572f1e992e88c65a62544fc0d79e1b947 |
| /home/martin/Dokumente/ED301/ed301/rust/crates/ed301-eddsa/src/test_support.rs | 68233a45eed0610e1459e3a0d620f34bd42469e3daa75d2b45f271b86bc9e2ea |

The shared declassification helper and all vendored dependencies also remain
unchanged. The D1 source manifest binds them along with the new crate and tools.
Field/scalar comparisons, randomness and zeroization use the existing libraries;
no new production byte parser or inverse implementation is introduced.

The X301-specific constants are generated from checked source hashes and
compiled into the library. The library does not load JSON at runtime.
The new key-owner API preserves raw serialization and rejects Nt before peer
decoding. Thus the old donor's substitute-and-reject-later policy is explicitly
not copied into v2. The Phase-B Python module remains its approved snapshot;
new Rust error-precedence tests cover the requested follow-up behavior.

The D1 timing driver/adapter are adapted from the existing Phase-C timing
harness; the dudect header is shared byte-for-byte. The codegen tool reuses
the approved C scanner/GOT/negative-control machinery, with D1-specific
complete-ladder and call-closure rules. The controls do not establish a
universal proof or automatically cover a future provider DSO.

This local D1 report is not a complete Gate-D package or an authorization to
publish source archives. A later external review bundle must include the
complete donor sources and their parent/provenance/licence closure, not only
the excerpts and absolute authoring paths in this working directory.
