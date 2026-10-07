# Bearbeitung des Reviews vom 7. Oktober 2026

Ausgangsstand: Review `b2d4861b0a4704ef7ecbf5f7287ef6af87a9081b`
(inhaltsgleich mit Testing `7211d8451a2bcd93884d4e90000d9289d07b1203`).
Das [Originalreview](../phase-e/reference/claude_20261007/ED301-REVIEW-20261007.md)
ist unverändert erhalten. Kurvenparameter, Byteformate, Decoder, Signatur- und
X301-Pfade wurden nicht geändert.

| Befund | Bearbeitung |
| --- | --- |
| B1 Untergruppenprüfung über Bibliotheks-Jacobi | Behoben: `Fe301::is_nonzero_square` nutzt wieder das Euler-Kriterium. |
| B2 Fehlerschutz beim deterministischen Signieren | Unverändert; `sign-self-verify` bleibt optional. |
| B3/B4 Nullisierung, Robustheitshinweise | Unverändert; keine Funktionsauswirkung. |

## B1: falsche Jacobi-Symbole beim Schlüsselimport

Das gebundene crypto-bigint 0.7.5 berechnet `jacobi_symbol` für Eingaben mit
mindestens vier Limbs über einen optimierten Binär-GCD. Für manche strukturierten
Eingaben liefert er ein falsches Vorzeichen
([RustCrypto/crypto-bigint#1295](https://github.com/RustCrypto/crypto-bigint/issues/1295),
upstream behoben durch [#1313](https://github.com/RustCrypto/crypto-bigint/pull/1313)).
Seit E8a (Option c) nutzte die Halbierungsprüfung des Imports genau diese Funktion.
Die Option wurde nur auf Seitenkanäle bewertet, nicht auf Korrektheit.

Folge am Ausgangsstand, mit OpenSSL 4.0.3 und dem Modul `ed301_eddsa_v2`
(Feature `tls-experiment`) über `openssl pkey -pubin -text` nachgewiesen:

| Öffentlicher Schlüssel | Ordnung | Ausgangsstand | Behoben |
| --- | --- | --- | --- |
| `ed8b187e…cff546b16` | 2q | angenommen | abgelehnt |
| `30f76623…2c124a1c` | q | abgelehnt | angenommen |

Ein Schlüssel A und A+T₂ galten damit beide als gültig. Signaturen ließen sich
nicht fälschen, weil die Verifikation den Kofaktor 4 einrechnet. Die
dokumentierte Zusage „Element der Primordnungs-Untergruppe“ galt aber nicht.

Behebung: `Fe301::is_nonzero_square` berechnet `x^((p-1)/2)` über den
vorhandenen Exponentiator mit fester öffentlicher Potenz. Name und
`#[inline(never)]` bleiben erhalten, damit die bestehende Aufrufgrenzen-Prüfung
unverändert greift. Das Bibliotheks-Jacobi bleibt nur als `cfg(test)`-Querprüfung.
Das Prädikat bleibt öffentlich-eingabe-only; seine Laufzeit ist jetzt fest.

Neue Regressionstests:

- sechs Symboleingaben (beide Halbierungssymbole der drei Schlüssel), bei
  denen die Bibliothek dreimal falsch lag;
- Import der zwei 2q-Schlüssel mit beiden x-Vorzeichen muss scheitern, der
  q-Schlüssel muss gelingen.

Beide Tests scheitern am Ausgangsstand und bestehen nach der Behebung.

## Codegen-Gate

`check_codegen_dataflow.py` erwartet zusätzlich genau einen Exponent-Aufruf
mit `(p-1)/2` in `Fe301::is_nonzero_square`; `codegen_ed.sh` schreibt dessen
Aufrufgraph auf genau `pow_fixed_window4` fest. Der [Codegen-Policy-Text](../phase-e/CODEGEN_POLICY.md)
ist angepasst. Historische Manifeste bleiben unverändert.

## Prüfungen

Ausgeführt mit rustc 1.99.0 und OpenSSL 4.0.3 (Fedora 45, x86-64):

- `cargo fmt --check`, `cargo clippy --all-targets`: ohne Befund.
- Kern-Smoke-Tests aus der README: 67 Ed301-Tests je Feature-Konfiguration,
  59 X301-Tests (X301 bindet `field_5x64.rs` ein und führt den Feldtest mit aus).
- Provider-Workspace-Tests: 20 Ed301- und 7 X301-Tests.
- Ende-zu-Ende-Import wie oben, Ausgangsstand und Behebung.
- Gate-Teilprüfung `exponent_sites` und `public_import_boundary` direkt auf
  einem 1.99-Kernbinary: altes Gate besteht am Ausgangsstand und scheitert an
  der Behebung nur bei der Exponentmenge; das angepasste Gate besteht.

Nicht ausgeführt: der kanonische Codegen-Gate-Lauf (verlangt rustc 1.98.0 /
LLVM 21.1.8; mit 1.99 scheitert bereits der unveränderte Ausgangsstand an
compilerbedingten Stellen), die Speicher-/Taint-Lanes, die OpenSSL-3.5-Lane
und die Python-/Node-Referenzläufe (Referenzen unverändert, nutzen exakte
Arithmetik). Deshalb gibt es keinen Evidenzindex. Vor einer Promotion nach
`main` sind diese Lanes nachzuholen.
