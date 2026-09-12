# E8: Weitere Optimierungen nach Gate E (Claude, 10. September 2026)

Auftrag von Martin: nach Gate E noch einmal selbst nach Optimierungen suchen. Bezug: E7-Stand `74d30ba`. Belege: `gate_c/e/e8/`, Patch `PHASE_E_E8b_LEITERRUNDE_R1_CLAUDE.diff`. Alle Messungen auf derselben CPU, verschränkt, bei belastetem Host (VM, zweiter Codex); Mediane.

## E8a: Legendre-Symbol über crypto-bigint statt Euler-Exponent (Import)

Der Import rechnet zwei Legendre-Symbole (Satz 1 und Satz 2 der Halbierungsprüfung) über die feste Exponentiation mit (p−1)/2: je 8,7 µs. crypto-bigint, bereits gebundene Abhängigkeit, liefert `U320::jacobi_symbol` in konstanter Zeit für 2,5 µs und `jacobi_symbol_vartime` für 1,5 µs. Emmys Test vergleicht beide bereits gegen den Euler-Orakel über 100 003 Werte.

Empfehlung: die konstantzeitige Variante nehmen, obwohl der Public Key öffentlich ist; sie ist mit 2,5 µs schnell genug und erspart jede Diskussion über variable Zeit. Gewinn: 2 × 6,2 ≈ 12 µs, Ed301 import ≈ 63 → 51 µs (−20 %, gegenüber v1 dann −47 %). Kein neuer Code: `legendre()` existiert schon unter `cfg(test)` und wird produktiv. Die Quadratwurzel für Δ und die Punktdekodierung bleiben Exponentiationen (dafür gibt es bei p ≡ 3 mod 4 nichts Schnelleres).

Warum Emmy das verworfen hat, steht nur als Halbsatz im E3-Bericht ("sicherheitsseitig geprüfte Euler-Fassung"). Falls der Grund ein eigener Jacobi-Versuch war: entfällt, weil die Bibliotheksfunktion verwendet wird. Falls der Grund die Vendor-Fork-Prüfung ist: `mod_symbol.rs` gehört zu den unveränderten Upstream-Dateien, das ist zu bestätigen.

## E8b: Umordnung der Leiterrunde (X301 shared)

Gleiche Operationen, andere Reihenfolge: die beiden Kreuzprodukte da, cb vor den Quadrierungen, dann die Summen/Differenzen, die kleinen Multiplikationen gebündelt, Ergebnisse zuletzt. Der Compiler bekommt zwei unabhängige Abhängigkeitsketten nebeneinander. Patch liegt bei; 56/56 Tests inklusive des 10 000-Fälle-Orakels bestehen.

| Stand | X301 shared µs |
|---|---:|
| v1 | 58,2 (min 56,7) |
| E7 | 59,0 |
| E7 + R1 | 57,9 |

Gewinn ≈ 2 %; damit liegt shared gleichauf mit v1 im Rauschen. Eine zweite Ordnung (R2) brachte nichts. Bounds, Rundenzahl, Swap und Fehlerpfade sind unverändert; der Codegen-Prüfer muss das neue Symbol trotzdem erneut sehen.

## E8c: Geprüft und nicht empfohlen

- **Radix-2^51-Feld mit sechs Limbs und verzögerten Carries** (Stil curve25519-dalek): plausibel 10–20 % auf allen Lanes, aber ein Neubau der Feldarithmetik mit neuen Schrankenbeweisen, neuem Codegen-Profil und vollständigem Re-Gating aller Phasen. Nicht für ein paar Prozent.
- **Verifikation** (84 µs): 300 Verdopplungen dominieren, das ist bei einer Doppel-Skalarmultiplikation mit Kofaktor-Gleichung so; OpenSSLs Ed25519 liegt bei 80 µs für 255 Bit. Größere Fenster verschieben nur Kosten in die Tabellenauswahl.
- **Signieren** (28 µs): Festbasis mit Radix 16, 76 Additionen; Radix 32 spart 15 Additionen und verdoppelt die Auswahlkosten. Kein Nettogewinn erwartet.
- **Leiter-Abkürzung über feste Clamp-Bits:** bereits gemessen, kein Gewinn, Vertrag bleibt.
- **Assembler:** ausgeschlossen (Sicherheit vor Performance).

## Erwartung nach E8a und E8b

Ed301 import ≈ 51 µs (−47 % zu v1), X301 shared ≈ v1, alle übrigen Lanes unverändert. Damit wäre das Ziel "auf keiner Lane langsamer als v1" innerhalb des Rauschens erreicht. Beide Änderungen sind klein; die Gates (Korrektheit, Taint, Codegen, dudect, Benchmarks) müssen für den neuen Stand trotzdem neu laufen, danach Gate E-Nachtrag durch mich mit denselben eigenen Tests.

## Entscheidung (Martin, 10. September 2026)

Martin folgt den Empfehlungen: E8a (konstantzeitiges Jacobi-Symbol aus crypto-bigint im Import) und E8b (Rundenumordnung R1 nach beiliegendem Patch) werden umgesetzt; E8c bleibt ausgeschlossen. Danach voller Gate-Durchlauf an den neuen Binaries und DSOs, dann Gate-E-Nachtrag durch Claude. Stufe 2 erst danach mit Martins gesondertem Go.

## Ergänzung aus dem dritten Review (Claude, 10. September 2026)

- **E8c:** Verifikationstabelle nicht mehr beim Keygen/Import jedes Signierschlüssels bauen (`sig_ffi.rs` `key_from_seed`), sondern erst bei Verifikationsbedarf einmalig; fehlbare Allokation, nebenläufige Nutzung und Schlüssel-Snapshots erhalten; strikte Prüfung fremder Public Keys bleibt. Erwartung: EVP keygen ≈ 57 → 31 µs, 10 KB weniger pro Signierschlüssel.
- **E8d:** `commitment_point`, `public_point` und die Inverse in `encode_components` in Zeroizing-Besitzern halten bis zur kanonischen Ausgabe; Unwind-Test nach Rückkehr aus der Festbasismultiplikation.
- **E8e:** Unbekannte `OSSL_PARAM`-Schlüssel gemäß OSSL_PARAM(3) ignorieren (EdDSA-Setter, X301-Exchange-Init, Hybrid-KEM-Init); erkannte, nicht unterstützte Modi weiter abweisen; Konformitätstest mit gültigem Context und unbekanntem Schlüssel.

Bewertung des Reviews: `/home/martin/Dokumente/ED301/BEWERTUNG_DRITTES_REVIEW_74d30ba_2026-09-10.md`.
