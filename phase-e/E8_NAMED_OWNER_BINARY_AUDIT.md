# E8d: benannte Löschbesitzer im finalen x86-64-Maschinencode

Stand: 11. September 2026. Ergänzende, begrenzte Binärinspektion; kein
universeller Nachweis über alle physischen Kopien eines Geheimnisses.

Die sechs unten identifizierten finalen ELF-Eingaben stammen aus den beiden
erfolgreichen Codegen-Receipts. Die vollständigen Disassemblierungen sind
bereits dort versiegelt. Geprüft wurden encode_components, SigningKey::expand
und ExpandedSigningKey::sign_with_context, jeweils Ordinary-/TLS-Provider
und primärer gemessener Core je ABI. Die beiden Core-Dateien sind bytegleich.

## Beobachtete Besitzer

Referenzadressen im Ordinary-DSO des 3.5.8-Laufs:

- Encoder: invert kehrt bei 0x1497d zurück. Der benannte 40-Byte-Besitzer
  liegt bei rsp+0x60; die Rückgabetemporäre beginnt bei rsp+0x98.
  Erfolgsweg 0x15554 bis 0x1557b und Inverse-fehlt-Weg 0x15592 bis
  0x155b9 schreiben die 40 Besitzerbytes aus verifizierten Nullkonstanten
  zurück. Der frühere Gültigkeitsfehler springt vor Erzeugung des Besitzers
  zurück. Nach Besitzererzeugung enthält diese Ordinary-Encoderfunktion
  keinen weiteren Funktionsaufruf; der kontrollierte Test-Unwind wird
  ausschließlich im Diagnose-/Testbuild ausgelöst.
- Public-Punkt bei Expansion: Nach Rückkehr der Festbasismultiplikation
  wird der 160-Byte-Punkt in den bewachten Bereich rsp+0x250 kopiert.
  Seine vier 40-Byte-Felder beginnen bei 0x250, 0x278, 0x2a0 und 0x2c8.
  Die Löschfolgen nach 0xff87 (Fehler), 0x102a5 (Erfolg) und 0x10394
  (Cleanup-Landing-Pad) überschreiben alle vier Felder. r13 und r15
  bezeichnen dabei rsp+0x278 und rsp+0x2a0. Der öffentliche ausgegebene
  Punkt entsteht separat aus den kanonischen affinen Koordinaten.
- Commitment-Punkt: Der zurückgegebene Punkt wird in rsp+0x170 übernommen
  und dem Encoder geborgt. Fehler ab 0x213b2, Erfolg ab 0x219d9 und
  Cleanup ab 0x21c17 löschen die vier Felder bei 0x170, 0x198, 0x1c0
  und 0x1e8. Die Cleanup-Folge geht vor _Unwind_Resume durch den
  benannten Besitzer.

Die adressnormalisierten Instruktionsfolgen aller drei Funktionen stimmen
in allen sechs Eingaben überein. Dabei wurden nur Instruktionsadressen,
RIP-Displacements, numerische Ziele direkt vor erhaltenen Symbolnamen und
Disassembler-Kommentare normalisiert. Mnemonik, Register, Stackoffsets,
Immediate-Werte und benannte direkte Sprung-/Aufrufziele blieben erhalten.
Das vergleicht die beobachtete Form, nicht die Semantik jedes indirekten
Aufrufs oder jeder entfernten Datenkonstante. Die für die Löschungen
verwendeten drei RO-Blöcke wurden zusätzlich in jeder tatsächlichen
ELF-Datei mit objdump -s gelesen: 16 + 16 + 8 ausschließlich Nullbytes.

| Funktion | Instruktionen | SHA-256 der normalisierten Folge |
| --- | --- | --- |
| encode_components | 831 | 4dd841ce775c18092ccd075e76688f3026fff480c9f49a3946d95ebb7fd83650 |
| SigningKey::expand | 480 | 76bdca4f4386d77e3841a7d14e6af63248128b49837191cfe59776644fb676b3 |
| ExpandedSigningKey::sign_with_context | 479 | f060cc496e69b25cc919996da4c06971c5ed5cf2728585687e3b5b6591632860 |

## Grenzen und dynamische Ergänzung

Die Festbasis-Rückgabepuffer, invert-Rückgabetemporäre, Register und
arithmetische Spillkopien sind damit nicht pauschal als gelöscht bewiesen.
Diese Einschränkung ist materiell: der benannte Besitzer ist nicht jede
vom Compiler erzeugte Kopie. Die Reparatur beansprucht genau die
angeforderten Besitzergrenzen.

Die neuen Tests returned_fixed_base_points_zeroize_on_return_and_unwind
und encoding_inverse_owner_zeroizes_on_return_and_unwind prüfen den
tatsächlichen Payload dieser Besitzer auf normalem Rückweg und bei
kontrolliertem Unwind; die vollständigen 65 Ed301-Tests bestehen auch
mit sign-self-verify. Das ergänzt diese Binärinspektion; es ersetzt sie
nicht durch eine allgemeine Leak-Freiheitsbehauptung.

Quellen:
- /home/martin/Dokumente/ED301/ed301/rust/crates/ed301-eddsa/src/signature.rs
- /home/martin/Dokumente/ED301/ed301/rust/crates/ed301-eddsa/src/edwards.rs
- /home/martin/Dokumente/ED301/ed301/phase-e/E8_FIX_REPORT.md

## Genaue Eingaben

Die body_sha256-Werte beziehen sich auf den unveränderten jeweiligen
Funktionsblock einschließlich Kopfzeile aus der angegebenen versiegelten
Disassemblierung. Die RO-Lesegrenze lautet zero_RO_start bis
zero_RO_start + 40, exklusives Ende.

```json
[
  {
    "abi": "3.5.8",
    "label": "ed301_eddsa_v2",
    "binary": "/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e8_final_01_2026-09-10/functional-3.5.8/modules/ed301_eddsa_v2.so",
    "binary_sha256": "4f536fb43fefc6f0ab90578d2ebefa7e58b2329be972ee5e6cb15b57aaef7488",
    "objdump": "/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e8_final_01_2026-09-10/codegen-3.5.8/ed301_eddsa_v2/core.objdump",
    "objdump_sha256": "31594d134e00a4f94db01952aaba0842561e1d6edb28d9a1ff829e0ced965a3c",
    "zero_RO_start": "0x63f28",
    "verified_zero_RO_bytes": 40,
    "functions": {
      "EdwardsPoint>::encode_components": {
        "address": "0000000000014930",
        "body_sha256": "172421ccd39ce4d60496caaafc497316f0e36d41c03553b59bf0d6cfc5514b22"
      },
      "SigningKey>::expand": {
        "address": "000000000000f840",
        "body_sha256": "47d8cab1e6c693c57dd6907b188fd951ac1c030cd88b0c092b4ad4c420c65ba3"
      },
      "ExpandedSigningKey>::sign_with_context": {
        "address": "0000000000021250",
        "body_sha256": "6d7e380d6e3572192a23262664ca6fe621b477674cfbf234e503500803d3eba9"
      }
    }
  },
  {
    "abi": "3.5.8",
    "label": "ed301_eddsa_v2_tls_test",
    "binary": "/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e8_final_01_2026-09-10/functional-3.5.8/modules/ed301_eddsa_v2_tls_test.so",
    "binary_sha256": "1b8730398a7a8d83e69923fc7a880092fce20b08c7e88d66ac8cccc9ebb2339d",
    "objdump": "/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e8_final_01_2026-09-10/codegen-3.5.8/ed301_eddsa_v2_tls_test/core.objdump",
    "objdump_sha256": "bdfa281390cd9b07bab5822fd343ccff194c25d56012e95bcda92c80514da6e8",
    "zero_RO_start": "0x68198",
    "verified_zero_RO_bytes": 40,
    "functions": {
      "EdwardsPoint>::encode_components": {
        "address": "0000000000014af0",
        "body_sha256": "ba5b37598335142dd886aa80a323041edac6763e670a39e1197a4d4e4cbd163a"
      },
      "SigningKey>::expand": {
        "address": "000000000000fa00",
        "body_sha256": "b4493b483e7fb0f7edc73daa18ba1b65704114b89b1c1f55a233fa5fb25dd704"
      },
      "ExpandedSigningKey>::sign_with_context": {
        "address": "0000000000021410",
        "body_sha256": "1d5a70e672653b6903aa9349d11f50bc31007a35f1ef1ebab63fbf77a89d12f4"
      }
    }
  },
  {
    "abi": "3.5.8",
    "label": "ed-core",
    "binary": "/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e8_final_01_2026-09-10/benchmarks-3.5.8/bin/ed-v2",
    "binary_sha256": "ffd6875a3c6dc7544a0de5e3adcf47dd310abbfa385f7374c173098e4d4a3d9e",
    "objdump": "/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e8_final_01_2026-09-10/codegen-3.5.8/ed-core/core.objdump",
    "objdump_sha256": "249f73286dcbd99807148a3b081faf00eac69d23aa6bacdca378d30883cfcaed",
    "zero_RO_start": "0x6b6d8",
    "verified_zero_RO_bytes": 40,
    "functions": {
      "EdwardsPoint>::encode_components": {
        "address": "000000000001b670",
        "body_sha256": "737113864ab61bb28afe0bcd1f924e5cccb94c62b282bd1b37e5bab19af4ae2b"
      },
      "SigningKey>::expand": {
        "address": "00000000000164f0",
        "body_sha256": "bfc6fbc7094a616ba3f561019071f2fa1923ff5d4787b83f272a1e4b21ed581b"
      },
      "ExpandedSigningKey>::sign_with_context": {
        "address": "0000000000027f90",
        "body_sha256": "62a8f88eedcd1e1949092d37d6c3064dd6928d0e8c1e7649d5009301e649b101"
      }
    }
  },
  {
    "abi": "4.0.2",
    "label": "ed301_eddsa_v2",
    "binary": "/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e8_final_01_2026-09-10/functional-4.0.2/modules/ed301_eddsa_v2.so",
    "binary_sha256": "7e2443208146a94d994330009c1f3452e9b0ddffcde1ba488088896e54668ced",
    "objdump": "/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e8_final_01_2026-09-10/codegen-4.0.2/ed301_eddsa_v2/core.objdump",
    "objdump_sha256": "14fdcc3fdcb72a95fe767d66ba5814ecc6f548d7e69e78f80b651dac19e85f32",
    "zero_RO_start": "0x63f28",
    "verified_zero_RO_bytes": 40,
    "functions": {
      "EdwardsPoint>::encode_components": {
        "address": "0000000000014930",
        "body_sha256": "172421ccd39ce4d60496caaafc497316f0e36d41c03553b59bf0d6cfc5514b22"
      },
      "SigningKey>::expand": {
        "address": "000000000000f840",
        "body_sha256": "127a73819ab345c7410b38a750db48ff06b26926e50b56a8e4236dcaad040f48"
      },
      "ExpandedSigningKey>::sign_with_context": {
        "address": "0000000000021250",
        "body_sha256": "e66cd68f7343f290f8df9c8c41557365a4d091f10f37ee3a8a32ad6941ab07dd"
      }
    }
  },
  {
    "abi": "4.0.2",
    "label": "ed301_eddsa_v2_tls_test",
    "binary": "/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e8_final_01_2026-09-10/functional-4.0.2/modules/ed301_eddsa_v2_tls_test.so",
    "binary_sha256": "af12f4237fb808d3da181d96eefdf50d3c73467650d8ba4118760aee48d6d4be",
    "objdump": "/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e8_final_01_2026-09-10/codegen-4.0.2/ed301_eddsa_v2_tls_test/core.objdump",
    "objdump_sha256": "768490056ad8441341f143debd75b51ead54a5f2c4260b7b95c200a4c716821b",
    "zero_RO_start": "0x68198",
    "verified_zero_RO_bytes": 40,
    "functions": {
      "EdwardsPoint>::encode_components": {
        "address": "0000000000014af0",
        "body_sha256": "ba5b37598335142dd886aa80a323041edac6763e670a39e1197a4d4e4cbd163a"
      },
      "SigningKey>::expand": {
        "address": "000000000000fa00",
        "body_sha256": "d3a70415986b9076f07a2f324e1cf433775a42769ba117a57e73f97d1232c7f7"
      },
      "ExpandedSigningKey>::sign_with_context": {
        "address": "0000000000021410",
        "body_sha256": "360933d4629b0864780280b95fe8febac38e9aeb75345023f16e65b07d77d878"
      }
    }
  },
  {
    "abi": "4.0.2",
    "label": "ed-core",
    "binary": "/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e8_final_01_2026-09-10/benchmarks-4.0.2/bin/ed-v2",
    "binary_sha256": "ffd6875a3c6dc7544a0de5e3adcf47dd310abbfa385f7374c173098e4d4a3d9e",
    "objdump": "/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e8_final_01_2026-09-10/codegen-4.0.2/ed-core/core.objdump",
    "objdump_sha256": "c1e3a3e7970465ca73fefd9e7944cbc485ed0100976845c32b6b707611667a22",
    "zero_RO_start": "0x6b6d8",
    "verified_zero_RO_bytes": 40,
    "functions": {
      "EdwardsPoint>::encode_components": {
        "address": "000000000001b670",
        "body_sha256": "737113864ab61bb28afe0bcd1f924e5cccb94c62b282bd1b37e5bab19af4ae2b"
      },
      "SigningKey>::expand": {
        "address": "00000000000164f0",
        "body_sha256": "bfc6fbc7094a616ba3f561019071f2fa1923ff5d4787b83f272a1e4b21ed581b"
      },
      "ExpandedSigningKey>::sign_with_context": {
        "address": "0000000000027f90",
        "body_sha256": "62a8f88eedcd1e1949092d37d6c3064dd6928d0e8c1e7649d5009301e649b101"
      }
    }
  }
]
```
