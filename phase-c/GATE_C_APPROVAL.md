# Gate C approved; Phase D authorized

Martin supplied Claude's Gate-C approval. The full report was read and its
SHA-256 checked. Phase C is approved for the Rust Ed301-EdDSA-v2 core,
constant chain, test transfer, scoped taint/codegen/timing gates and benchmark
methodology. Phase D may begin; that permission does not approve its results.

| Approved object | Binding |
|---|---|
| Testing snapshot | `0be31f50cccf3d5af4675d081661ea463c575027` |
| Internal review archive SHA-256 | `5713efb5b5ac869e450376a172e536d73515537b9be09ffe0f13d6e3ced183b1` |
| Package manifest SHA-256 | `4aa8ebb51fc5c5d6bf9af466a11c1f4212df1501aa8c53957939876e22778312` |
| Approved Phase-C source manifest SHA-256 | `d5ce5790b59cff8204e346a0db57666802d98fbd2f680abf2e2c4b00d34c46c2` |
| Approval report SHA-256 | `81b4f23bdbf3f7072aebf61c8b92337610661d987b8d7d2fe271436885046c6d` |

Report:
/home/martin/Projekte/Claude/OpenSSL-Fork/review/ed301-v2-curve-search-2026-09-09/GATE_C_FREIGABE_2026-09-10.md.

The approval rests on Claude's independent checks: 40 constants, 1301
differential cases, independent reducer-bound checks, source and disassembly
review, a positive taint-method control and an independent 54-test run.
The complete 16-step replay is corroborating evidence, not a substitute for
those independent checks. No high or medium findings remain.

The optional d-negation optimization is not being applied. Documentation
clarification N2: the five Gate-B `domain_controls` are not consumed by name
in the Rust crate; their statement is covered by the Rust context tests and
the Python/Node Phase-B replay. The approved test inventory remains available
unchanged in the reviewed snapshot.

## Post-approval publication metadata

Martin explicitly authorized this Testing push on 10 September 2026. This
follow-up commit records the approval and adds the supplied upgraded OTS
receipt, without changing the Rust core, approved commit or internal archive.
The current source manifest is regenerated for these post-approval additions;
the approved manifest above remains unchanged in commit `0be31f5` and its archive.

Added receipt:
/home/martin/Dokumente/ED301/ed301/provenance/v2-search/RUN_MANIFEST.sha256.ots,
SHA-256 `a83e91590afbb5ea68a252b805d5c2764549b469a3f2e8f36f358a1900913d46`.
Its decoded file commitment matches the unchanged search-manifest SHA-256
`a9c210823af851675678117d401415b54c2ad0cad8bb4ab47ce94f669acae313`.
No new timestamp was created or upgraded during this publication step.
The local backup is excluded from the commit.

Only the Git Testing branch is authorized for this push. The internal review
archive, Whitepaper PDF and legacy briefing documents are not published.
Review, main and signed provenance tags are not changed. No signing key is
used. Future pushes, production release and provider activation still require
Martin's explicit approval. OID numbers and TLS codepoints remain unassigned;
X301-v2 follows the already approved revision-2 input contract in Phase D.
