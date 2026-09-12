# E7: skalierte X301-Verdopplung und zeilenweise Quadrierung

Stand: 10. September 2026. Dies ist der Umsetzungs- und Zwischenmessbericht,
keine Gate-E-Freigabe. Die vollständigen neuen Provider-, Timing-, Speicher-
und Abschlussmessungen folgen in einem separaten E7-Abschlussbericht.

## Umsetzung und Herkunft

Claudes drei Eingaben sind unverändert unter
/home/martin/Dokumente/ED301/ed301/phase-e/reference/e7/ abgelegt. SHA-256:

- /home/martin/Dokumente/ED301/ed301/phase-e/reference/e7/REQUEST.md:
  `98de6fcddfbf679edda7cfd05eba07a08d779fd84bafd7ed0b9bc14ce02d0315`
- /home/martin/Dokumente/ED301/ed301/phase-e/reference/e7/CLAUDE_AFL.diff:
  `ffc4f1650c79a8d764928ce8c252510d08c47b5714c233a721012501225df929`
- /home/martin/Dokumente/ED301/ed301/phase-e/reference/e7/CLAUDE_MEASUREMENTS.txt:
  `c510b3a2625678e1ef6a18bc1bb8abe4e1db02ef747fe052d7ab406a3d82d1f6`

Der Produktionsrumpf von `square_wide` stammt bytegleich aus X301-v1
`569dc4ff10e0e5e19d106cbe490d2a5aaeac935e`. Der bisherige Spaltenrumpf und
seine vier Hilfsfunktionen bleiben unverändert als reine Testorakel erhalten.
Die frühere E4-Aussage über den gleichen v1-Quadrierungskern war zu weit:
sie galt für den Ed301-v1-Donor, nicht für den tatsächlichen X301-v1-Donor.

Die neue Verdopplung verwendet `K=a-d=61206265502` und `d=-301`:
`X2=(K*AA)*BB`, `Z2=E*(K*AA-301*E)`. Beide Koordinaten sind gegenüber dem
kanonischen A24-Weg mit demselben nichtnull K skaliert. Generator und
Schrankenprüfer prüfen die Identität gegen die hashgebundenen Gate-A-Daten.
`mul_small_narrow` akzeptiert ausschließlich öffentliche Faktoren unter
2^32; für lose Operanden unter 4p bleibt das Produkt unter 2^335 und damit
im bestehenden Small-Reducer-Bereich unter 2^338. Kein vorheriges Tightening
von E ist nötig. Die vollständigen Zwischenwertbeweise stehen in
/home/martin/Dokumente/ED301/ed301/phase-c/FIELD_BOUNDS.md.

301 Runden, Clamp-Regeln, Swaps, Fehlerreihenfolge, Zeroizing-Besitzer,
Ausgabeverträge, Parameter und Kodierungen bleiben unverändert. Kein
Assembler, keine Clamp-Bit-Abkürzung und keine Schleifenumstrukturierung.

## Frische Kernprüfungen

Der erste E7-Kandidat scheiterte beim Neubau, weil `mul_tight` irrtümlich auf
Tests beschränkt worden war; gemischte Edwards-Addition benötigt die Methode
weiterhin. Diese Einschränkung wurde entfernt. Die fehlerhaften Artefakte
bleiben unter /home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e7_after_01_2026-09-10/
erhalten und werden nicht als bestandene Evidenz verwendet.

Der korrigierte, schreibgeschützte Kandidat ist
/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e7_after_02_2026-09-10/source,
vollständiges Quellmanifest
`80a91b31c968ce147a1859c9feb4f789a1929292e90c74ebacf3c50c99541327`.
Frisch aufgebaut wurden Gate-C/D1 mit 54/25 Tests, E1–E6 mit 61/54 Tests und
E7 mit 62/56 Tests. Alle alten Testnamen sind erhalten; die beiden
Feature-Varianten haben dieselben 62/56 Tests, ohne ignorierte oder gefilterte
Fälle. Clippy mit `-D warnings`, Formatierung, Generatoren, Schranken,
Vendor-Prüfung, `no_std`-Verbraucher, Profilmarker und Gate-B-Replay 8/8: PASS.
Zusätzlich prüfen die bestehenden vollen Domänen 100000 neue enge
Small-Produkte; der neue Skalierungstest prüft 10000 zufällige und vier
exceptionelle AA/BB-Paare. Die alten 10000 vollständigen Leiter-Oracles bleiben.

Prüflauf:
/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e7_after_02_2026-09-10/ED301-v2_PHASE_E_core-check_y6waj_7w/;
Receipt-SHA-256 `066222842b7a08d0605256918a2da18b4c8b5c4fa6fd9d9e05ee6058e664bd91`.

## Gleicher Harness: v1, E1–E6 und E7

32 Fälle, jeweils neun verschachtelte Läufe, CPU 2, Zielzeit mindestens
200 ms, unverändertes O3/ThinLTO/CGU1-Profil mit Overflow-Checks; ausschließlich
die dokumentierte historische X301-v1-crypto-bigint-Ausnahme bleibt aus.
Alle sechs Programme wurden frisch gebaut. Kein Lauf oder Ausreißer entfernt.
Während der Messung liefen keine weiteren von Emmy gestarteten Rechenprüfungen;
sonstige Systemlast ist nicht ausgeschlossen. Claudes CPU-3-Reihe wird nicht
mit dieser CPU-2-Reihe vermischt.

| Lane | v1 µs | E1–E6 µs | E7 µs | E7 ggü. E1–E6 | E7 ggü. v1 |
|---|---:|---:|---:|---:|---:|
| Ed301 sign | 29.277438 | 29.799042 | 29.514521 | −0.95 % | +0.81 % |
| Ed301 verify | 89.010746 | 87.092226 | 83.335425 | −4.31 % | −6.38 % |
| Ed301 import | 98.168513 | 66.774133 | 62.416451 | −6.53 % | −36.42 % |
| X301 public | 28.528298 | 28.072040 | 28.032819 | −0.14 % | −1.74 % |
| X301 shared | 58.120661 | 66.091234 | 60.212009 | −8.90 % | +3.60 % |

Der wesentliche X301-shared-Gewinn ist sichtbar; der Abstand zu v1 bleibt.
Diese Reihe belegt nicht vier schnellere Lanes: Sign liegt noch geringfügig
über v1. Seine E7-Standardabweichung beträgt 2.813 µs; auch der
X301-shared-Vorher-Stand streut mit 6.793 µs deutlich. Kleine Differenzen
werden nicht als belastbarer Gewinn ausgegeben. Die abschließenden beiden
ABI-Matrizen bleiben erforderlich.

Messartefakte einschließlich Rohdaten und Streuungen:
/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e7_after_02_2026-09-10/ED301-v2_PHASE_E_core-bench_jghg3aii/;
Receipt-SHA-256 `3ca6f86c5f75b30a7f469a762c22730524bdf7ddf49b52e327c12814081c2f7e`.

## Codegen-Zwischenprüfung und verbleibende Gates

Die tatsächlich gemessenen E7-Kern-ELFs bestehen die angepasste strikte
Codegen-Prüfung. Ihre SHA-256 sind Ed301
`c3a84f3f4ad73d4a85e844033912fb9d5ad37f51a675979b411ee02ffa488da6`
und X301 `2a2f9a4a8e359d9a7dd51e319d21c777feca34e5eea000cd7c5c739c917ad22f`.
Prüfverzeichnisse:
/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e7_after_02_2026-09-10/codegen-ed-review03/
und /home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e7_after_02_2026-09-10/codegen-x-review03/.

Die Regelanpassung bindet E7s neue Register-/Stackbelegung: öffentlicher
`memcpy`-GOT-Zeiger in rbp mit Clobber-Gegenproben, die Herkunft aller
Exponentenindizes und genau ein skalarindizierter Bytezugriff pro Leiterrunde.
Die Leiter enthält genau den öffentlichen Rücksprung 300 bis 0, keine Calls
im Rundenteil und 30 cmov. Die fünf Produkte mit K und die fünf mit 301
(vier volle, ein nachgewiesen begrenztes oberstes Wort) sind explizit gebunden.
Alle bisherigen Branch-/Call-Regeln, Minima und Gegenproben bleiben erhalten;
neue Herkunfts-/Skalierungs-Gegenproben kommen hinzu. Test-only-Spaltenhelfer
werden im endgültigen ELF ausdrücklich verworfen. Dies ist eine begrenzte
Codegen-Prüfung, kein universeller Constant-Time-Beweis.

Offen zum Zeitpunkt dieses Zwischenberichts: alle neuen Taint- und
Timing-Läufe, beide vollständigen Provider-/OpenSSL-ABI-Gates, erweiterte
Kern-Matrix, Mikrobenchmarks, Stack/RSS, finaler DSO-Codegen, Abschlussmessungen
und verifizierte Übergabe. Frühere E1–E6-PASS-Belege werden dafür nicht
übertragen. Gate E bleibt bei Claude/Martin; weiterer Optimierungsaufwand für
den Restabstand benötigt Martins Entscheidung. Kein Push, keine Installation,
keine Aktivierung, keine RPMs und kein Stage 2.

### Nachtrag: Provider-Lowering vor dem vollständigen Abschlusslauf

Die ersten frischen Provider-Bauten bestehen beide nichtvernetzten
Funktionsläufe (je 137 Schritte). Ed301-Taint 36/36, X301-Taint 526/526 und
der unabhängige Halbierungs-Replay sind ebenfalls bestanden. Die
schreibgeschützte Kandidaten-Evidenz liegt unter
/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e7_final_01_2026-09-10/.

In den Ed301-DSOs verwendet der unveränderte öffentliche Decoder-/Halbierungs-
Status nach E7 den Stackplatz `0x3a0` statt `0x3b0`. Die Adresse des Decoder-
Rückgabewerts, seine Prüfung und die spätere kombinierte Akzeptanzprüfung
wurden im Disassembly nachvollzogen. Ausschließlich diese drei exakten
Operanden wurden in der Provider-Regel angepasst. Alle acht normalen/TLS-
DSOs beider ABIs bestehen damit die vollständige Codegen-Zwischenprüfung.
Die Kompilierquellen bleiben identisch, Manifest
`ce0a57d9763452a99e3b2632f83f102c85399e18bacb82913167724a6b81291d`.
Für den konsistenten Abschlusslauf wird ein neuer vollständiger Quellenstand
einschließlich dieser Prüfregel eingefroren; frühere Kandidaten bleiben
unverändert erhalten. Die endgültigen Codegen-Belege werden anschließend
wieder direkt an die tatsächlich abschließend gemessenen Programme gebunden.
