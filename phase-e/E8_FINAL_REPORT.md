# E8a–E8e: Abschluss zur unabhängigen Gate-E-Prüfung

Stand: 11. September 2026. Lokale Umsetzung und technische Gates abgeschlossen.
**Gate E ist nicht erteilt.** Claudes unabhängiger Nachtrag und Martins
gesonderte Entscheidung zu Stufe 2 bleiben erforderlich.

## Ergebnis auf allen fünf Kern-Lanes

Unmittelbar gepaarter Vergleich: v1, vorheriger E7-Stand und E8a–E8e,
identischer Harness, CPU 2, neun Rotationen, sechs frisch gebaute Programme.
Mediane von neun Laufmitteln in µs; negative Änderungen bedeuten weniger Zeit.
Keine entfernten Ausreißer, keine Auswahl günstiger Wiederholungen.

| Lane | v1 µs | E7 µs | E8 µs | E8 ggü. E7 % | E8 ggü. v1 % |
| --- | --- | --- | --- | --- | --- |
| Ed301 sign | 28.606667 | 28.827272 | 28.795025 | -0.112 | +0.658 |
| Ed301 verify | 86.270272 | 82.927333 | 84.052430 | +1.357 | -2.571 |
| Ed301 import | 96.522255 | 61.509447 | 50.371274 | -18.108 | -47.814 |
| X301 public | 27.170005 | 27.236319 | 27.414418 | +0.654 | +0.900 |
| X301 shared | 56.677302 | 58.693491 | 57.804881 | -1.514 | +1.989 |

Streuung der besonders nahen Vergleiche, Stichproben-SD in µs:

| Lane | Stand | SD µs |
| --- | --- | --- |
| Ed301 sign | v1 | 0.456942 |
| Ed301 sign | before | 1.979585 |
| Ed301 sign | after | 2.162048 |
| X301 shared | v1 | 0.602859 |
| X301 shared | before | 0.468409 |
| X301 shared | after | 0.720789 |

Zwei weitere vollständige ABI-Matrizen mit unabhängig neu gebauten
Vergleichsbinaries folgen. Der Rust-Kern ruft selbst kein OpenSSL auf.
Jede Zeile verwendet ihren eigenen v1-Bezug; verschiedene Läufe und
Claudes externe Messungen werden nicht zusammengerechnet.

| ABI-Lauf | Kernoperation | v1 µs | E8 µs | Änderung % | Median unter v1 |
| --- | --- | --- | --- | --- | --- |
| 3.5.8 | Ed301 sign | 29.046959 | 29.191607 | +0.498 | nein |
| 3.5.8 | Ed301 verify | 86.925736 | 85.145214 | -2.048 | ja |
| 3.5.8 | Ed301 import | 99.561405 | 50.779526 | -48.997 | ja |
| 3.5.8 | X301 public | 27.942615 | 28.766837 | +2.950 | nein |
| 3.5.8 | X301 shared | 58.000873 | 58.604700 | +1.041 | nein |
| 4.0.2 | Ed301 sign | 29.281941 | 29.175429 | -0.364 | ja |
| 4.0.2 | Ed301 verify | 86.607092 | 83.461143 | -3.632 | ja |
| 4.0.2 | Ed301 import | 98.228798 | 51.024464 | -48.055 | ja |
| 4.0.2 | X301 public | 27.889040 | 27.678694 | -0.754 | ja |
| 4.0.2 | X301 shared | 57.406325 | 58.523505 | +1.946 | nein |

In 6 von 10 endgültigen Kernzeilen liegt der Median unter v1.
Das ist weder ein Signifikanztest noch eine allgemeine Laufzeitgarantie.
Ein positiver Restabstand bleibt sichtbar und wird nicht durch das Wort
„Rauschen“ zu einem bestandenen strikten Fünf-Lanes-Ziel umgedeutet.

Die für E8c und E8b wichtigen Provider-Grenzen:

| ABI | EVP-Operation | v1 µs | E8 µs | Änderung % |
| --- | --- | --- | --- | --- |
| 3.5.8 | Ed301 keygen | 56.966400 | 29.967500 | -47.394 |
| 3.5.8 | X301 derive-steady | 57.389600 | 58.145700 | +1.317 |
| 4.0.2 | Ed301 keygen | 57.306000 | 30.514000 | -46.753 |
| 4.0.2 | X301 derive-steady | 57.758900 | 58.464300 | +1.221 |

Die erstmalige Verifikation erzeugt nun die Tabelle; vorbereitete
Verifikationen verwenden denselben unveränderlichen Snapshot. Eine
10.240-Byte-Tabelle entfällt bei reinen Signierschlüsseln, aber kleine
validierte Public-Daten und Mutex bleiben. Das ist keine gemessene
isolierte RSS-Ersparnis von exakt 10 KB pro Schlüssel. Die Tabellen
weisen Prozess-RSS, Objektgrößen und Messgrenzen getrennt aus.

## Umsetzung und bewusste Grenzen

Ausgangscommit: 74d30ba7f463ea7898249dc5560032f39358569b auf Testing.

- E8a: unverändertes gebundenes U320::jacobi_symbol für die zwei
  Halbierungssymbole. Martin genehmigte Option c nach einer Pause:
  Public-Key-Import verarbeitet ausschließlich öffentliche Daten und
  darf davon abhängige Laufzeit haben. Kein Vendor-Patch, keine Behauptung
  einer sprungfreien Jacobi-Enum-Konvertierung. Euler bleibt Testorakel
  über 100.003 Werte. Signieren/Schlüsselableitung umgehen diesen Parser.
- E8b: exakt die gelieferte R1-Rundenumordnung; Operationen, Feldschranken,
  301 Runden, Clamp, Swap und Fehlerfolge bleiben erhalten.
- E8c: strikte Public-Key-Prüfung bleibt beim Import. Validierter kleiner
  Public-Key-Wert und große Verifikationstabelle sind getrennt. Ein
  Mutex schützt die fehlbare, einmalige Cache-Veröffentlichung. Fehler,
  Wiederholung, Nebenläufigkeit, Public-only-Duplikate und alte
  Signatur-/Verifikations-Snapshots sind gezielt geprüft.
- E8d: commitment_point, public_point und die Encoder-Inverse besitzen
  Zeroizing-Guards bis zur kanonischen öffentlichen Ausgabe. Encoder
  borgen die Punkte; normale Rückwege und kontrolliertes Unwind prüfen
  die tatsächlichen benannten Besitzer. Kein Beweis über jede physische
  Compilerkopie, jedes Register oder sämtliche Stackreste.
- E8e: unbekannte OSSL_PARAM-Metadaten werden ohne Interpretation ihres
  Wertes ignoriert. Erkannte unerlaubte Modi bleiben Fehler; gültiger
  Context/TLS-Wert, Duplikatregeln und atomare Übernahme bleiben erhalten.
  OSSL_PARAM beschreibt Ignorieren unbekannter Schlüssel als Empfehlung,
  nicht als uneingeschränktes kryptografisches MUST.

Ausführliche Implementierungsgrenzen:
/home/martin/Dokumente/ED301/ed301/phase-e/E8_OPTIMIZATION.md

Befundbezogene Prüfungen:
/home/martin/Dokumente/ED301/ed301/phase-e/E8_FIX_REPORT.md

Ergänzende Inspektion der benannten Löschbesitzer in sechs finalen ELFs:
/home/martin/Dokumente/ED301/ed301/phase-e/E8_NAMED_OWNER_BINARY_AUDIT.md

Der Signaturvertrag bleibt die kofaktorierte Gleichung: kein zusätzlicher
R-Untergruppentest, kein Verbot von S=0. Gleich große Rohschlüssel erhalten
keinen erfundenen Herkunftstag. Keine Radix-Neuentwicklung, kein Assembler,
keine Clamp-Abkürzung und keine zusätzliche Optimierungsvariante.

## Technische Gates

Kern: 65 Ed301- und 57 X301-Tests,
auch mit sign-self-verify beziehungsweise Taint-Feature. Alle ursprünglichen
54/25 und alle E7-Testnamen 62/56 sind erhalten, nichts ignoriert/gefiltert.
Clippy mit warnings denied, Formatierung, no_std-Consumer, Generatoren,
Feldschranken, Vendor-Integrität und Release-Profilmarker bestehen.
Die Phase-B-Replay 8/8 läuft auf ihrer unveränderten historischen Quelle;
32 aktuelle Eingaben sind damit gebunden, mit ausschließlich der exakt
genehmigten sechszeiligen Public-Import-Ergänzung. Aktuelle Gate-A- und
signierte Suchpakete werden zusätzlich vollständig geprüft.

36 Ed301- und 526 X301-Core-Taint-Läufe sind neu für E8 ausgeführt.
Der Public-Import-Zusatz prüft definierte Eingabe, synthetisch geheime
Shadow-Bits mit gezielter Ablehnung und anschließend wieder legitime
Eingabe. Die Signier-/Ableitungsläufe beobachten null Parseraufrufe,
ohne geheime Eingaben an der Prüfgrenze öffentlich zu markieren.

Je OpenSSL 3.5.8 und 4.0.2: neun neue v2-DSO-Varianten, vier bitidentische
unabhängige Rebuilds, neue gebundene v1-Provider, 20/7 Provider-Rust-Tests
und vollständige Functional-, CLI-, TCP-, strukturierte Vertrags-,
Speicher-, Kontroll-, Codegen-, Timing- und Benchmark-Stages.
TCP: eigene 127.0.0.1-Endpunkte, je 95 Prüfungen einschließlich HRR/KeyUpdate.

ASan/UBSan prüfen native C-Teile; Memcheck prüft ganze Prozesse einschließlich
Rust/OpenSSL. Instrumentierte DSOs werden nicht als Ordinary-DSOs ausgegeben.
Codegen bindet je ABI vier tatsächliche Ordinary-/TLS-DSOs und die beiden
gemessenen primären Core-ELFs. Geheime Arithmetikregeln bleiben strikt;
nur die genehmigte Public-Import-Grenze ist öffentlich klassifiziert.
Zwölf Ed301- und sechs X301-Datenfluss-Gegenproben prüfen die Regeln.
Ein zusätzlicher synthetischer Fehlerstatus 47 muss durch den Shell-Treiber
bis zum Aufrufer durchgereicht werden, ohne abschließendes Codegen-PASS.
Statisch aufgelöste Call-Edges plus Tests/Taint sind kein universeller
Whole-Program-Beweis gegen jeden möglichen indirekten Aufruf.

dudect: 200000 angeforderte Messungen je Test insgesamt, zufällige Klassen,
sticky detection, Schwelle |t| > 10. Positivkontrollen erkannt, reguläre
Tests bestanden, keine Vorbereitungs-/Operationsfehler. T5 (Hybrid-Reject)
bleibt informativ; delegiertem ML-KEM wird kein eigenständiger umfassender
Constant-Time-Beweis zugeschrieben. Taint/dudect/Codegen zusammen sind
ebenfalls kein universeller Seitenkanalbeweis.

128 Benchmarkfälle je ABI, zusätzlich 98 Nachrichten-/Context-/Lifecycle-
und 38 Mikrobenchmarkfälle: je neun Rotationen, vollständige Rohwerte.
52 Ed301- und 15 X301-Ressourcenfälle: drei Massif- und neun RSS-Prozesse.
14 tatsächliche Core-ELFs: Sektionen und Festbasistabellen. Zusätzlichen
Messharnesses wird kein nicht ausgeführter Codegen-Gate zugeschrieben.
DER-Callgrind ist auf beiden finalen Codec-DSO-Sätzen wiederholt; bestehende
Context-/Aliasgrenzen bleiben unverändert. Instruktionen sind keine Zeiten.

## Quellenbindung und Hand-off

Ausgeführte Quelle:
/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e8_final_01_2026-09-10/source

Quellmanifest SHA-256: 1b9e7aecf9d69b1a5b38cf5b81f12b399b951770d99b03ac2fe77d0c1f8fde35; 1929 Dateien.
Die ABI-Gates binden diesen vollständigen Snapshot. Frühere erfolgreiche
E8-Core-Receipts werden nur mit dateiweisem Gleichheitsbeleg des vollständigen
Rust-Baums und ihrer Harness-/Runner-Eingaben verwendet. Es werden keine
E7- oder älteren PASS-Receipts als E8-Nachweis übernommen.

Frühe abgewiesene Codegen-Formen, die historische Phase-B-Dokumentbindung
und die zwischenzeitlich erkannte fehlende Bindung des aktuellen Suchpakets
sind nicht als PASS umetikettiert. Die aktuelle Paketprüfung wurde vor dem
finalen Snapshot korrigiert und ihre Ablehnung eines geänderten Members
mit einem isolierten vollständigen Fixture erneut belegt. Historische
Manifeste wurden nicht umgeschrieben. Alle Endgates nutzen den korrigierten
Checker. Die alte Freitext-Profilbezeichnung E1–E5 im unveränderten
Benchmarkrunner ersetzt nicht die maßgeblichen E8-Quell-/Binärhashes.

Index:
/home/martin/Dokumente/ED301/ed301/phase-e/E8_EVIDENCE_INDEX.json

Er bindet 20 ABI-Stages,
17 Zusatzreceipts und
3 Vergleichssnapshots.
Neue Berichte/Übergabecontroller sind getrennte Nach-Ausführungsdateien;
die ausgeführte Quelle wird nicht nachträglich verändert. Frühere
E7-Berichte und Archive bleiben unverändert.

Das Paket enthält Rohwerte, Befehle, Logs, Toolchain-/Libcrypto-Identitäten,
DSOs, benötigte Core-Binaries und Quellvergleiche. Nur Build-Caches und
explizit inventarisierte große Kontroll-Fixtures werden ausgelassen.
Erzeugte Schlüssel sind ausschließlich lokale Testschlüssel.
Archivtest, frische Extraktion und natives Replay erhalten äußere Receipts.

Die bisherigen Integrationsgrenzen bleiben: vollständige Keyfile-Prüfung
für DER-Nachlauf, Stock-CLI als Stufe-2-Thema, Testnamen/Key-Share-Reihenfolge
und kein AArch64-Nachweis. Kein Push, Upload, RPM-Bau, Installation,
Aktivierung, Produktivfreigabe oder Stufe 2. Ein vollständiges lokales Paket
macht das bislang fehlende öffentliche Review-Asset nicht automatisch
erreichbar; dessen Veröffentlichung entscheidet Martin separat.
