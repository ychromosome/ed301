# Gate E: Rückgabe mit E7 (X301-Leiter und Quadrierung)

Prüfer: Claude. Datum: 10. September 2026. Bezug: Phase-E-Abschlusscommit `b32cf0c8b8b81af832ed6d180aa74485d0667816`, Archiv `a0a3e52b…`.

**Entscheidung: Gate E noch nicht erteilt.** Martins Ziel "etwas schneller als v1" ist bei X301 shared mit +9,6 bis +11,1 % verfehlt, und das ist nach Martins Vorgabe nicht akzeptabel. Die Ursache ist gefunden, quantifiziert und mit einem getesteten Patch belegt. Die vollständige unabhängige Gate-E-Prüfung (E1–E6 mit eigenen Tests, Replay, Disassembly) führe ich nach E7 in einem Durchgang aus, damit nicht zweimal gegatet wird.

## 1. Ursache, gemessen (Belege: `gate_c/e/E7_measurements.txt`, Patch `PHASE_E_E7_VARIANTE_AFL_CLAUDE.diff`)

Gleiche Maschine, gleicher Harness (`x301_core_bench.rs`), CPU 3, neun Läufe, Mediane:

| Stand | X301 shared µs | gegenüber v1 |
|---|---:|---:|
| v1 (x301-integration `569dc4ff`) | 56,6–57,0 | – |
| v2 Phase-E-Endstand | 62,4–62,7 | +10 % |
| v2 + Variante AFL (E7) | 58,7–58,9 | +3,5 % |

Pro Leiterrunde kostet der v2-Endstand ≈ 21 ns mehr als v1, über 301 Runden ≈ 6 µs. Zwei Ursachen, beide im Vergleich mit dem tatsächlichen v1-Bezugsstand (x301-integration, nicht ed301-eddsa-github, von dem der v2-Kern abgeleitet wurde):

1. **A24 als volle Feldmultiplikation.** v1 nutzt a24 = (A−2)/4 = d/(a−d) und skaliert beide projektiven Verdopplungsausgaben mit (a−d): X2 = (a−d)·AA·BB, Z2 = E·((a−d)·AA + d·E). Zwei kleine Multiplikationen (je ≈ 3–6 ns) ersetzen eine volle (≈ 18–22 ns). Für v2: (a−d) = a + 301 = 61 206 265 502 < 2^36 (innerhalb der bewiesenen Small-Multiplier-Schranke), d = −301, also Z2 = E·((a−d)·AA − 301·E). Anteil ≈ 12 ns pro Runde.
2. **Quadrierung.** Multiplikation, Reduktion, Faltung und Auswahl sind in beiden Feldern byteidentisch; nur `square_wide` unterscheidet sich. x301-integration verwendet die zeilenweise Form nach OpenSSL `bn_sqr_normal` (Kreuzprodukte, Verdopplung per Shift, Diagonale), v2 die spaltenweise 192-Bit-Akkumulatorform aus ed301-eddsa-github. Gemessen 16,6 gegen 18,8 ns pro Quadrierung; vier pro Runde ≈ 9 ns.

Nicht ursächlich (gemessen, verworfen): Swap-Implementierung (in-place gegen zwei Selects: kein Unterschied), Schleifenstruktur (v1-Struktur auf v2-Feld: −2 %), die Abkürzung über die festen Clamp-Bits 300/1/0 (kein messbarer Gewinn; entfällt, damit bleibt der Vertrag mit 301 Runden unverändert), `mul_small`-Reduzierer (identisch bis auf Shift-Konstante).

## 2. E7: Auftrag an Emmy

1. **Quadrierung:** `square_wide` aus `x301-integration/crates/ed301-eddsa/src/field_5x64.rs` (Commit `569dc4ff`) in den v2-Kern übernehmen. Gleiche Signatur, gleiche Ausgabe; die vorhandenen Oracle-Tests gegen crypto-bigint decken sie ab. Schranken: die Zwischensummen der zeilenweisen Form sind in `FIELD_BOUNDS.md` neu zu belegen (x² < 2^640, Verdopplung ohne Überlauf), `check_field_bounds.py` ergänzen. Wirkt auch auf Ed301 sign/verify/import (≈ 1–3 %).
2. **Skalierte a24-Leiter:** wie im Patch `PHASE_E_E7_VARIANTE_AFL_CLAUDE.diff`: Konstanten `A24_SCALE_DENOMINATOR = EDWARDS_A + EDWARDS_D_MAGNITUDE` (Compile-Zeit-Assertion ≤ MAX_SMALL_MULTIPLIER) und `A24_SCALE_NUMERATOR_MAGNITUDE = 301`; `X2 = scaled_aa·BB`, `Z2 = E·(scaled_aa − 301·E)`. Dazu `Fe301LazyLinear::mul_small_narrow(u64)` mit Schranke < 2^32 (Produkt < 2^335 < 2^338, damit das Ergebnis in [0,2p) liegt), damit E nicht vorher getightened werden muss. Beweis der Gleichheit mit dem A24-Weg: (A−2)/4 = d/(a−d) folgt aus A = 2(a+d)/(a−d); im Generator prüfen `A24_MINUS · (a−d) ≡ −301 (mod p)` und als Test festhalten. Kein Test darf verschwinden; der kanonische Oracle-Vergleich (10 000 Fälle) und alle Gate-B-Vektoren bleiben.
3. **Keine** Abkürzung der Leiter, keine Vertragsänderung, kein Assembler.
4. Danach Vorher/Nachher-Messung auf allen fünf Kern-Lanes und, wie in Phase E vorgesehen, alle Gates neu an den neuen Binaries und DSOs.

Erwartung nach E7: X301 shared ≈ 58,7 µs (+3,5 % zu v1), X301 public und Ed301 import deutlich unter v1, Ed301 sign/verify leicht unter v1.

## 3. Der Rest von 3,5 %

Er liegt bei ≈ 7 ns pro Runde und ist mit den vorhandenen Mikrobenchmarks nicht mehr auf eine einzelne Operation zurückzuführen (Feldoperationen einzeln gleich schnell, Schleife strukturell gleich). Kandidaten: Registerdruck und Scheduling im generierten Code der Runde, die 36-Bit- gegen 31-Bit-Konstante im Small-Multiplikator. Klären ließe sich das nur mit einem Vergleich der erzeugten Rundencodes (objdump beider Leitern) und gezielten Umstellungen. Das ist Aufwand ohne Gewissheit. Vorschlag: E7 umsetzen und messen; dann entscheidet Martin, ob die verbleibenden Prozent weiteren Aufwand rechtfertigen oder ob "auf vier von fünf Lanes schneller, auf der fünften 3,5 % langsamer" das Ziel hinreichend erfüllt.
