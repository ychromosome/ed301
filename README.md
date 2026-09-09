# Ed301-EdDSA

Experimental cryptographic engineering. Not standardized or production-ready.

The internal ED301-v2 mathematical package passed Claude's Gate A on
2026-09-09. Its frozen provenance is under `provenance/phase-a/2026-09-09/`.
The signed pre-search publication under `provenance/v2-search/` is unchanged.

Phase B now includes the Ed301-EdDSA and X301 Python references, public test
vectors and separate Node counterimplementations. X301 follows Martin's
revision-2 strict-input contract, including the excluded twist-order scalar.
The package is prepared for **Claude's Gate-B review, not yet approved**.
See `phase-b/STATUS.md` for coverage, source hashes and remaining gates.

Run all reference checks from the repository root with Python 3.10+,
Node.js supporting SHAKE256 and GNU coreutils installed:

```sh
python3 -B tools/check_phase_b.py
```

No package installation, network access, private keys or production data are
needed. All fixture seeds are public test data. Both implementations are
variable-time references, not applications for handling real secret keys.

The profiles are documented in `specifications/Ed301-EdDSA-v2.md` and
`specifications/X301-v2.md`. Historical
v1 oracles and fixtures remain byte-identical, test-only incompatibility
controls; they are never runtime fallbacks for the new reference.

Development belongs on `Testing`, selected review snapshots on `Review`.
`main` remains reserved for the completed product after the required gates
and Martin's explicit release approval. Rust, providers, formats, TLS,
performance, side-channel gates and production readiness are not delivered
by Phase B. OIDs and TLS codepoints remain unassigned. No Phase C starts
before Claude's Gate B passes.
