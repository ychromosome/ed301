# Phase-B input provenance

Snapshot read on 2026-09-09. The authoring workspace paths below identify the
inputs; replay does not depend on those external paths. Required legacy
oracles/fixtures are copied byte-identically into this repository and tested
against the hashes below. All v2 curve parameters are read directly from the
approved repository artifact, not transcribed from a draft or a prior curve.

## Approval and unchanged mathematical artifacts

Gate A approved the mathematical package at commit
`23c8feef7fd89bf0a2db0910df778f393aaf4614` on Review. The source of this
implementation work was Testing commit
`acfc680de51d9feabf9593c044380d76c48ae163`, which adds only the supplemental
OTS receipt/note beyond that Gate-A snapshot. No signing key was used here.

| Artifact | SHA-256 |
|---|---|
| `/home/martin/Projekte/Claude/OpenSSL-Fork/review/ed301-v2-curve-search-2026-09-09/GATE_A_FREIGABE_2026-09-09.md` | `7c8857b938edf27e41d831e7da90dc21637b3142246a9d3dfcc05cca30672786` |
| `/home/martin/Dokumente/ED301/ed301/provenance/phase-a/2026-09-09/parameter/ed301-v2.json` | `13f0eaf541919a1447b9d3c58e6d57eb77ffab94ebe37539c70301d6fddcfaa0` |
| `/home/martin/Dokumente/ED301/ed301/provenance/phase-a/2026-09-09/PHASE_A_MANIFEST.sha256` | `7c1f1b54795713d77d8fe91b195c7be17c8af54df5dbf4c96dd2a7cdd744dfcf` |
| `/home/martin/Dokumente/ED301/ed301/provenance/phase-a/2026-09-09/phase-a-evidence.tar.gz` | `746c24ff5d6e2a88cb65397f6f55a024492b918a16dd73de7ef631797b1e2930` |

The pre-review status strings inside the approved artifact are archival and
remain unchanged. Approval is recorded separately rather than rewriting the
hash-bound Gate-A package. No new parameter selection or search was performed.

## Assignment and profile contract

| Artifact | SHA-256 |
|---|---|
| `/home/martin/Dokumente/ED301/AUFTRAG_EMMY_ED301-v2_IMPLEMENTIERUNG_2026-09-09.md` | `9c42115fbbbf93b55963ff9bc84fc3c9cd5b0dfc5c3576c990a39061a6b785ee` |
| `/home/martin/Dokumente/ED301/VORSCHLAG_PUNKTE_5_6_7_ED301-v2_2026-09-09.md` (current Fassung 4) | `0683870d634911c2bb2435a9a21138540a9c786b7920219d028a739535e019d8` |
| `/home/martin/Dokumente/ED301/NEUE_KURVE_VORABFRAGEN_2026-09-09.md` (read snapshot) | `d64171299447a97cc3419ac9233fd09541bd876d725cdcd58bdd741bcd90d8b7` |
| `/home/martin/Dokumente/ED301/ed301/AGENTS.md` | `ec5a6226d9a42f96c96aaff871daef2f9edda948bfd7a71717e197b38af941dd` |

The approved choices preserve the current PureEdDSA transcript and byte rules
while changing the curve, internal identity and label to SigEd301-v2. OIDs
and TLS codepoints are not assigned. The X301-u rule was initially left open;
Martin's later explicit revision-2 decision is bound below.

## Reused v1 components and frozen controls

The clean source checkout `/home/martin/Dokumente/ED301/ed301-eddsa-github`
was at commit `5c688206a15f6ab88a50d53fe503665a302cec4d`.

| Artifact | SHA-256 |
|---|---|
| `/home/martin/Dokumente/ED301/ed301_technischer_abschluss/referenz/ed301_curve.py` | `ccbf257630430e8c995cde2614b1cefd7502de7cff02228633802736f425da8c` |
| `/home/martin/Dokumente/ED301/ed301-eddsa-github/provider-tests/oracle/ed301_eddsa/reference.py` | `36773f7eee765e4a79fba60b542dc17fe8f6efccd4df62de781908d5c4e0b7dc` |
| `/home/martin/Dokumente/ED301/ed301-eddsa-github/provider-tests/oracle/ed301_eddsa/__init__.py` | `20b9ed448b1efc3385b9d1ff450d3ddd9040c3d83992f2239912289af7339578` |
| `/home/martin/Dokumente/ED301/ed301-eddsa-github/provider-tests/oracle/ed301_eddsa_v1/reference.py` | `9580a3c948dd1972a2f482449a2b284d3da2e88d12ca867be7dada95bf557da8` |
| `/home/martin/Dokumente/ED301/ed301-eddsa-github/provider-tests/oracle/ed301_eddsa_v1/__init__.py` | `d75cc9324076a5443080ecba46fd783dd0b1eb4b4f56aacddcf4e1ddfde12f73` |
| `/home/martin/Dokumente/ED301/ed301-eddsa-github/inputs/v1/ed301-eddsa-v1.json` | `6dd09bd623af136be707bb1d57bf2502907cd0d2e30be71e1ef1ddbeab5b67f9` |
| `/home/martin/Dokumente/ED301/ed301-eddsa-github/inputs/v1/ED301-EdDSA-v1.md` | `f0062953da9c6a09cecf46b4cf0927e26a1a1ff723c8ad8872f133b2c2ff8982` |

The curve reference retains the affine formulas and low-level model maps,
replaces the entire parameter declaration with the Gate-A JSON loader, and
uses Python's built-in modular inverse. The signature reference adapts the
current v1 transcript to that module and the approved v2 label. No numeric
search/replace was used to manufacture the new parameter set.

The older `/home/martin/Dokumente/ED301/ed301_technischer_abschluss/referenz/ed301_sig.py`
(SHA-256 `930adceb25c2a486d3cdec63a0818b93b731b687d7694acc98ab41368011f546`)
was inspected and explicitly excluded as a signature template because it
implements the retired Ed301-Sig-v1 protocol. The current v1 independent-check
script `/home/martin/Dokumente/ED301/ed301-eddsa-github/review-tests/independent-v1-oracle.py`
(SHA-256 `0c8b31301b19a061c12b873ab2b4edf31951bf9b65e1f62da33bb2099185ad8c`)
was read for existing test conventions; its implementation is not imported
by the new Node oracle.

## Primary algorithm references

- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html), generic EdDSA and
  the Ed448 domain shape. The new curve is a project-defined instance, not a
  named RFC algorithm.
- [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html), the mathematical
  Montgomery ladder pattern. The external X301-u profile deliberately departs
  from its tolerant X25519/X448 decoder under Martin's decision below.
- [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final), SHAKE256 provided by
  Python hashlib and Node crypto, not a project hash implementation.
- [Explicit-Formulas Database: generic extended twisted Edwards](https://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#addition-add-2008-hwcd),
  add-2008-hwcd, used by the Node counterimplementation. This formula uses
  the general a parameter, not the specialization a = -1.

Standards and mathematical formulae were consulted online on 2026-09-09; no
third-party executable package or cryptographic implementation was downloaded.

## X301 contract and implementation inputs

Martin explicitly approved strict u decoding and then retained the v1
twist-order-secret exclusion in revision 2. The original decision file is
copied byte-identically under `phase-b/inputs/`; its displayed date is
2026-09-10. The local input file and historical source checkouts were not
modified by the implementation work.

| Artifact | SHA-256 |
|---|---|
| `/home/martin/Dokumente/ED301/X301-v2_EINGABEVERTRAG_2026-09-10.md`, revision 2 | `b33d3fe0bf6b5b026192695902902f4b7592d4271ca98161f47920b47c6a1c2c` |
| `/home/martin/Dokumente/ED301/ed301_technischer_abschluss/referenz/x301.py` | `acf12998fa26f6d19d97ae356ddf9a973994b5b5166034a259c4aaf533aa7dfe` |
| `/home/martin/Dokumente/ED301/ed301_technischer_abschluss/spezifikation/X301-v1.md` | `e70748b5fa7176ffde914d32183c1f6c0150e1aaf799be70633499fd387f549e` |
| `/home/martin/Dokumente/ED301/ed301_technischer_abschluss/gegenpruefung/x301/x301.js` (read for existing oracle/API structure) | `babc850a8717bf95d8e9ea3118b580079551fabb367cbbadf90d17b6b487499c` |
| `/home/martin/Dokumente/ED301/x301-integration/provider-tests/x301/provider_x301_contract.c` | `808a232945293521a76acc70662273d28a50e5f81b55c8cf71d83a3f6028906d` |

The clean X301 integration checkout was at
`569dc4ff10e0e5e19d106cbe490d2a5aaeac935e`. The normalization expectations
are identified as historical in `phase-b/HISTORICAL_X301_TESTS.md`; provider
and hybrid/TLS integration remain Phase D, with the decoder governed by the
new contract. The existing strict X301 reference was the Python API template,
not a source of v2 constants or expected outputs. The newly generated
1000-call iteration chain uses the RFC-7748 recurrence with the v2 basepoint;
no old iteration result is carried over.

[RFC 8446 section 7.4.2](https://www.rfc-editor.org/rfc/rfc8446.html#section-7.4.2)
was consulted for the unconditional TLS all-zero requirement. It is a model
for the X301 contract, not a claim that X301 is a standardized TLS group.
