# Ed301 / X301 identifier registry

Allocation decision: Martin, 10 September 2026, recorded in the
[D2 decisions](../phase-d/d2/inputs/D1_BEWERTUNG_UND_D2_ENTSCHEIDUNGEN_2026-09-10.md)
(SHA-256 `c5c18ad17baa32718cb6d5d3805d206334800facfa26896ae08b49766f04e0c7`).
The historical entries follow the bound Ed301-v1 registry at commit
`5c688206a15f6ab88a50d53fe503665a302cec4d`; they are not reassigned.

| OID | Assignment | Status |
| --- | --- | --- |
| `1.3.6.1.4.1.66282.301.1` | Ed301-Sig-v1 | Retired; never reassign |
| `1.3.6.1.4.1.66282.301.2` | X301-v1 | Historical assignment; unchanged |
| `1.3.6.1.4.1.66282.301.3` | Ed301-EdDSA-draft-00 | Frozen; never reinterpret |
| `1.3.6.1.4.1.66282.301.4` | Ed301-EdDSA-v1 key and signature algorithm | Historical assignment; unchanged |
| `1.3.6.1.4.1.66282.301.5` | Ed301-EdDSA-v2 key and signature algorithm | Current v2 assignment |
| `1.3.6.1.4.1.66282.301.6` | X301-v2 key algorithm | Current v2 assignment |

Both v2 AlgorithmIdentifiers have absent parameters (not ASN.1 NULL).
SPKI contains 38 public-key bytes. PKCS#8 PrivateKeyInfo version 0 contains
an inner OCTET STRING of the 38 original seed/secret bytes. For X301 this
is the original, not the clamped, secret. The canonical DER lengths remain
58 bytes (SPKI) and 62 bytes (PKCS#8); these are checked against generated
OID encodings, not inferred by editing historical octets.

Public algorithm names remain `Ed301-EdDSA` and `X301`. Internal profile
identifiers, OIDs and TLS codepoints distinguish v2. Applications must not
load v1 and v2 provider generations into the same OSSL_LIB_CTX.

## Separate TLS private-use assignments

| Registry | Value | Assignment |
| --- | --- | --- |
| SignatureScheme | `0xFE2D` | Retired historical signature scheme; never reinterpret |
| SignatureScheme | `0xFE84` | Ed301-EdDSA-v1; unchanged |
| SignatureScheme | `0xFE85` | Ed301-EdDSA-v2 |
| NamedGroup | `0xFE2E` | X301MLKEM1024-v1; unchanged |
| NamedGroup | `0xFE2F` | X301MLKEM1024-v2; default in the project integration policy |
| NamedGroup | `0xFE30` | Raw-X301-v2; explicit test/measurement choice only |

The project integration sets `X301MLKEM1024` as its complete group list.
Stock OpenSSL's `DEFAULT` remains the built-in list: loading a provider does
not add either custom group to it. Raw-X301 is excluded from the project
default and must be selected explicitly. It has no ML-KEM protection. The hybrid has no separate
persistent-key OID or standalone application KEM format.

These are project/private-use assignments, not IANA TLS registrations or
standards. OIDs, SignatureSchemes, NamedGroups and CipherSuites are separate
namespaces; the G301 CipherSuite `0xFF30` is unchanged. See the
[current profile](../specifications/CURRENT_PROFILE.md) for the active contract.
