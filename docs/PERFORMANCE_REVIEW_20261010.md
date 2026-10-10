# Performance-Durchsicht der Rust-Kerne

Stand: 10. Oktober 2026. Ausgangspunkt: Testing `ed258b5`. Auftrag: die
Performance der Rust-Kerne erneut prüfen und nur Optimierungen ohne
Sicherheitsverlust umsetzen. Kurve, Byteformate, Annahmemengen für
Schlüssel und Signaturen, öffentliche API und alle Ergebnisse bleiben
unverändert. Geändert sind ausschließlich Pfade, die nur öffentliche Daten
verarbeiten: Signaturprüfung, Punktdekodierung und Public-Key-Import.

## Ergebnis

Gemessen mit dem unveränderten Kern-Benchmark (`rust/performance/ed301-bench`,
`phase-d/benchmarks/x301_core_bench.rs`), Release-Profil O3, ThinLTO, CGU1,
`panic=unwind`, Overflow-Checks; rustc 1.97.0 / LLVM 22.1.6 auf einer
Cloud-VM (Intel Xeon 2,8 GHz, 4 vCPUs), CPU 2 per `taskset`. Vorher/Nachher
abwechselnd, 15 Wiederholungen, Mittelwert je Lauf; angegeben sind Median
und Minimum der Laufmittel. Die VM ist deutlich lauter und langsamer als der
E8-Referenzrechner; die Werte sind nicht mit den E8-Tabellen vergleichbar.

| Operation | vorher Median µs | nachher Median µs | Median | vorher Min µs | nachher Min µs | Min |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Ed301 verify | 132,9 | 115,5 | −13,1 % | 129,0 | 109,8 | −14,9 % |
| Ed301 import | 97,9 | 79,3 | −19,0 % | 94,1 | 77,4 | −17,8 % |
| Ed301 sign | 53,5 | 49,4 | −7,7 % | 47,5 | 47,6 | +0,2 % |
| Ed301 expand | 48,0 | 48,5 | +0,9 % | 46,3 | 46,1 | −0,4 % |
| X301 public | 47,1 | 46,8 | −0,7 % | 44,6 | 44,4 | −0,5 % |
| X301 shared | 93,2 | 94,3 | +1,2 % | 90,7 | 90,5 | −0,2 % |

Signieren, Schlüsselableitung und X301 führen bitgleichen Maschinencode aus
(siehe Prüfungen); ihre Abweichungen sind Messrauschen. Einzelkosten im
selben Umfeld: eine feste Exponentiation sinkt von 12,3–13,9 µs auf
8,4–8,7 µs; `decode` entsprechend um etwa 4–5 µs.

## Änderung 1: Verdopplung ohne T in der Signaturprüfung

Die vollständige Verdopplungsformel liest nur `X`, `Y` und `Z`; `T` braucht
erst die nächste Addition. Bei wNAF-Breite 8 für beide Skalare tragen rund
vier Fünftel der etwa 300 Positionen keine Ziffer. Die variable-time
Straus-Schleife hält dazwischen einen projektiven Punkt `(X:Y:Z)` mit
Koordinaten im faulen Bereich `[0, 2p)` und bildet `T` sowie kanonische
Koordinaten nur vor einer Addition und für das Ergebnis. Jede solche
Verdopplung spart eine Feldmultiplikation und vier kanonische Korrekturen.
Das Verdoppeln des Startpunkts (Identität) entfällt.

`EdwardsPoint::double` nutzt dieselben Formelterme (`DoublingTerms`, inline);
sein Maschinencode und der aller geheimen Pfade ist unverändert. Nur die
öffentliche Verifikation verwendet `ProjectivePoint`. Signatur, Challenge
und Schlüssel sind dort öffentlich; die Schleife war bereits variable-time.

## Änderung 2: Additionskette für die festen Exponenten

Alle drei Laufzeit-Exponenten leiten sich aus `e = (p - 3) / 4 =
(2^212 - 1) * 2^87 + 226` ab: `(p + 1) / 4 = e + 1` und
`(p - 1) / 2 = 2e + 1`. Statt des 4-Bit-Fensters (300 Quadrierungen,
etwa 70 Multiplikationen, jede kanonisch korrigiert) berechnet
`Fe301::pow_p_minus_3_over_4` eine feste Kette mit 298 Quadrierungen und
13 Multiplikationen im faulen Bereich und korrigiert einmal am Ende.
Die 13 Schritte rufen `Fe301Lazy::square_times_mul` mit literalen Zählern
auf; es gibt keine Tabelle, keinen Index und keine Verzweigung außer
diesen festen Zählern.

- `sqrt_ratio` (Dekodierung): unverändert `numerator * (numerator *
  denominator)^e`, weiterhin mit Wurzelprobe und Nenner-ungleich-null.
- `sqrt_fixed` (Halbierung): `x^e * x`, weiterhin mit Wurzelprobe.
- `is_nonzero_square`: weiterhin Euler-Kriterium, `(x^e)^2 * x == 1`;
  Name und `#[inline(never)]`-Grenze bleiben, kein Bibliotheks-Jacobi.

Ein Konstantenblock bindet die Kettenform beim Übersetzen an den generierten
Exponenten und an den Modulus (`4e + 3 = p`) sowie `e + 1` und `2e + 1` an
die generierten Wurzel- und Euler-Exponenten. Der Fenster-Exponentiator
bleibt als `cfg(test)`-Orakel erhalten.

## Unverändert

Fixed-Base-Kamm, konstante Tabellenauswahl (`cmov`), `add_affine`,
`double`, X301-Leiter, safegcd-Inversion, Skalararithmetik, SHAKE256,
Zeroizing-Besitzer und Deklassifizierungsgrenzen. Keine neue Abhängigkeit,
kein `unsafe`, keine API-Änderung. Der Untergruppentest berechnet weiterhin
beide Symbole und die Wurzelmaske; die kofaktorierte Gleichung bleibt.

## Prüfungen

Ausgeführt mit rustc 1.97.0 / LLVM 22.1.6 (x86-64):

- `cargo fmt --check` und `cargo clippy --all-targets` für Ed301 (ohne und
  mit `sign-self-verify`) und X301: ohne Befund.
- Kern-Tests: 70 Ed301-Tests je Feature-Konfiguration, 62 X301-Tests
  (je drei neue: Additionskette gegen das Fenster für alle drei Exponenten
  auf 64 kleinen, 64 randnahen, 301 Einzelbit-, 3 dichten und 20 000
  Zufallswerten; projektive Verdopplungsketten gegen erweiterte Verdopplung
  auf 506 Punkten inklusive Torsion und `Z != 1`; Straus gegen die bisherige
  Schleife auf 63 × 63 Skalarpaaren, darunter dünn besetzte Skalare). Die
  bestehenden Prüfungen gegen das unabhängige Montgomery-Orakel (100 003
  Werte) und die sechs B1-Regressionseingaben bestehen unverändert.
- Maschinencodevergleich der Benchmark-Binaries vor/nach, je Funktion
  normalisiert: In Ed301 ändern sich nur `EdwardsPoint::decode`,
  `Fe301::is_nonzero_square`, `ValidatedPublicKey::from_bytes` und
  `VerifyingKey::verify_bytes_with_context`; `pow_fixed_window4` entfällt,
  neu sind `pow_p_minus_3_over_4`, `Fe301Lazy::square_times_mul` und
  `ProjectivePoint::doubling_terms`. Alle übrigen Funktionen, darunter
  sämtliche Pfade mit geheimen Daten, sind identisch. In X301 ist keine
  Funktion geändert.
- Valgrind-Secret-Taint, gebaut wie `phase-c/tools/run_core_taint.py`:
  Ed301 `public`/`sign` definiert und markiert über 9 Vektoren (36 Läufe);
  Importgrenze definiert/markiert/definiert wie
  `run_import_boundary_taint.py` (markierte Eingabe abgelehnt, Exit 101);
  X301 vollständiger Gate-B-Korpus, 263 Fälle (526 Läufe). Alle bestanden.
- Provider-Workspace (Nachtrag): 20 Ed301- und 7 X301-Tests gegen ein lokal
  aus dem Release-Archiv gebautes OpenSSL 3.5.8, mit rustc 1.97.0 und 1.91.0:
  bestanden.
- Mindestversion (Nachtrag): Mit rustc 1.91.0 / LLVM 21.1.2 bestehen
  zusätzlich alle Kern-Tests (70/70/62) und alle oben genannten Taint-Läufe
  (36 + 3 + 526). Rust 1.90.0 scheitert einzig an `u64::borrowing_sub`
  (stabil seit 1.91); die Abhängigkeiten verlangen höchstens 1.85. Die
  deklarierte Mindestversion 1.91 ist damit die tatsächlich nötige und bleibt.
- Codegröße: Die Kette (3,6 KB) ist kleiner als der Fenster-Exponentiator
  (7,3 KB). Die Verifikationsschleife wächst um etwa 17 KB; das Ed301-
  Benchmark-Binary insgesamt von 538 240 auf 555 040 Byte Text (+3,1 %).
  Vollständig eingebettete Verdopplungsterme wären bei der Prüfung etwa
  3 % schneller, aber 5,5 KB größer; die kompaktere Variante ist gewählt.

## Nicht ausgeführt und offen

- Kanonisches Codegen-Gate (verlangt rustc 1.98.0 / LLVM 21.1.8). Mit
  1.97/LLVM 22 scheitert bereits der unveränderte Ausgangsstand an
  compilerbedingten Aufrufsequenzen.
- Die E3-Regeln zum Exponentiator beziehen sich auf das entfernte Symbol
  und scheitern am neuen Stand absichtlich geschlossen: `field_pow` und die
  Aufrufgraphen `public_import`/`public_jacobi` in `codegen_ed.sh` sowie
  `pow_structure`, `exponent_sites` und deren Negativkontrollen in
  `check_codegen_dataflow.py`. Sie wurden ohne kanonisches Binary weder
  abgeschwächt noch neu gefasst. Beobachtet mit 1.97/LLVM 22: Aufrufgraphen
  wie bisher mit `pow_p_minus_3_over_4` statt `pow_fixed_window4`; die Kette
  hat keine bedingte Verzweigung und ruft nur 13-mal `square_times_mul` mit
  den Literal-Zählern 1, 1, 3, 6, 12, 24, 48, 96, 12, 6, 2, 82, 4 in `%edx`;
  `square_times_mul` hat genau eine Schleifenkante (`dec %edx`/`jne`) und
  keinen Aufruf; beide haben keine indizierten Zugriffe. Die Exponent-Herkunft liegt
  nicht mehr als Read-only-Bytes vor, sondern in dieser Zählerfolge und den
  Multiplikanden; die Quellbindung leisten Konstantenblock und Tests.
- Benchmarks auf dem E8-Referenzrechner, Speicher-/Timing-Lanes,
  OpenSSL-Lanes, Python-/Node-Referenzen (Referenzen unverändert).

## Weitere Möglichkeiten, nicht umgesetzt

Diese Punkte brauchen eine Entscheidung, weil sie Verträge, bewusst
redundante Prüfungen oder Gate-Minima berühren.

1. Größe der Verifikationstabelle. Der Aufbau der 64 Einträge kostet hier
   etwa 44 µs, nach dieser Änderung mehr als die Hälfte von `import`. Bei
   TLS wird je Peer-Schlüssel meist nur eine Signatur geprüft. Eine
   kleinere Tabelle (Breite 5 oder 6) oder ein One-Shot-Pfad ohne
   Tabellennormalisierung spart dort geschätzt rund 30 µs pro Handshake,
   kostet wiederholte Prüfungen aber etwa 3–6 µs je Signatur. Das betrifft
   die E8c-Cache-Entscheidung und gegebenenfalls die Provider-API.
2. Erstes Halbierungssymbol. Nach erfolgreicher Dekodierung mit `y != ±1`
   ist `χ(w) = χ(b)·χ(1-y²)` und `χ(δ) = χ(a-d)·χ(a-d·y²)`. Da
   `(1-y²)(a-d·y²)` dann ein Quadrat ungleich null ist und
   `χ(b) = χ(a-d) = -1` gilt, ist `first_symbol` äquivalent zur
   Wurzelmaske `root_valid`; numerisch auf 20 000 dekodierbaren `y`
   bestätigt. Das Weglassen spart eine Exponentiation (etwa 8 µs beim
   Import), entfernt aber eine bewusst redundante Prüfung und braucht eine
   mathematische Freigabe samt Halbierungsreferenz.
3. Geheime Fixed-Base-Pfade, je höchstens wenige Prozent: In
   `select_basepoint` wird `y` bei der Negation unnötig ausgewählt und
   `y - x` über Negation plus Addition gebildet; ein faul reduzierter
   Akkumulator spart vier Korrekturen je Addition. Beides senkt die
   `cmov`/`sbb`-Zahlen, die die Codegen-Minima binden.
4. Größere Signierfenster und Radixwechsel bleiben wie seit E8
   ausgeschlossen. Die safegcd-Inversion (etwa 5 µs) ist schneller als eine
   Fermat-Kette (etwa 8–9 µs) und bleibt.
