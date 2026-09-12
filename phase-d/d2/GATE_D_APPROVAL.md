# Gate D approved; Phase E authorized

Martin supplied Claude's Gate-D approval and authorized publishing the reviewed
D1/D2 commits plus this approval record to `Testing`. The full approval and
Phase-E assignment were read; the following complete SHA-256 bindings were
verified against the local artifacts. Approval is limited to Stage 1, native
x86-64, OpenSSL 3.5.8 and 4.0.2. It is not production or system-activation approval.

| Object | Binding |
| --- | --- |
| Reviewed D2 commit | `5dcb89fa97e85e6bba14a32a29586326f5696052` |
| D1 predecessor | `67f2910e7697cdab782cc992e44dc28843f93970` |
| Approval report | `0eff72f3c509a70e7d87ebc13fc1f794be4d63c6819bf52e5a6ea72d7d7b8ddd` |
| Internal review archive | `35ca21ea2497ff670ef70b8251db409c40211184feb7812d2bdbface4ee904cf` |
| Outer package manifest | `b204405d8e435a551c8dc9af7fe6f8cc5d0c0e9b62c10f293097e022d9bc191d` |
| D2 evidence index | `d90eceac51c317cc7584042a3be2a706eaed585ff58e8a0b6f1e08d73d379f92` |
| Phase-E assignment | `5faf1c1fa7c5c4fd8f6473ef298b6fdea3a9df7b9dedf320ae00ff566c6c2b93` |
| Supplied halving proof | `cabec1f325944610049bc1282691890af9dab4188615f22bc5e74adbd9b7f32d` |
| Supplied halving vectors | `e78ae62a636242ba9c01f4a4a0edce7d38dbe89ebb1508b144baaa3334b91737` |

Approval source:
/home/martin/Dokumente/ED301/GATE_D_FREIGABE_UND_PHASE_E_START_2026-09-10.md.
Phase-E assignment:
/home/martin/Dokumente/ED301/AUFTRAG_EMMY_PHASE_E_OPTIMIERUNG_2026-09-10.md.

Claude's independent CLI/oracle checks, independently driven and parsed TLS
handshakes, wire values and DSO disassembly carry the approval. The CLI checks
were 33/34 per lane: the remaining case is accepted OpenSSL trailing-DER parity,
not an unreported all-pass result. His own TLS checks passed 13/13 per lane;
the package verification and 88-call replay corroborated his independent work.
No high or medium findings remain; seven low findings have the following scope.

## Recorded follow-up obligations

- N1: Stock CLI decodes a DER object and can accept trailing bytes, as with
  Ed25519. No decoder change is requested. Stage-2 user documentation must explain
  the distinction from the existing complete-file test integration.
- N2: After separately authorized global activation, stock `req -verify`,
  `x509 -req` and PKCS#12 key extraction must pass without the private-context
  test frontends. These are mandatory Stage-2 acceptance tests, not a present
  claim about activated behavior.
- N3/E6: Investigate the measured DER-encoding overhead; repeated seed expansion
  during validation is a hypothesis, not an established cause. Fix only after
  identifying the actual path and preserving validation guarantees.
- N4: Decide before Stage 2 whether to retain or rename test-suffixed module and
  CLI display names. The wire contains numeric codepoints, not these strings.
  A rename requires fresh functional/TCP validation; none is performed here.
- N5: The integration contract now explicitly records client key-share order.
  A server enforces hybrid-only operation by not enabling Raw X301 at all.
- N6: No AArch64 approval. New ARM artifacts need their own validation.
- N7: The unoptimized X301/hybrid cost is a Phase-E measurement and review item.

## Phase E and publication boundaries

Phase E is authorized in the order E4, E1, E2, E3, optional E5, plus E6 from
Gate D. Each optimization has its own commit, renewed source manifest and
paired before/after measurements. Security properties, encodings, clamp and
error order stay unchanged. Final correctness, bounds, taint, codegen, timing,
provider/TLS and performance gates must run anew on the new artifacts.
Claude decides Gate E; Stage 2 still requires Martin's separate explicit go.

This publication adds no keys, certificates, archives or production binaries.
Only the `Testing` branch is pushed; `Review`, `main`, tags and signing keys are
untouched. The reviewed D2 commit and internal archive remain immutable. The new
post-approval source manifest is separate from all historical A/B/C/D1 and
Gate-D input seals. The existing untracked timestamp backup is excluded.
