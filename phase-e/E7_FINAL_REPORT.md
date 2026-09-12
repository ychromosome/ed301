# E7: Abschluss zur unabhängigen Gate-E-Prüfung

Stand: 10. September 2026. E7 und die erneut ausgeführten lokalen Gates sind
abgeschlossen. **Gate E ist nicht erteilt.** Die Tabellen liefern Martin die
Entscheidungsgrundlage für den verbleibenden Abstand zu v1; die unabhängige
Gesamtprüfung durch Claude steht aus. Keine weitere Optimierungsvariante wurde
nach dieser Messreihe gesucht.

## Ergebnis auf allen fünf Kern-Lanes

Zuerst der unmittelbar gepaarte Vergleich von v1, E1–E6 und E7: identischer
Harness, CPU 2, neun Rotationen, alle sechs Programme frisch gebaut.
Alle Zahlen sind Mediane von neun Laufmitteln in µs; negative Änderungen
bedeuten geringere Laufzeit. Kein Ausreißer und kein Lauf wurde entfernt.

| Lane | v1 µs | E1–E6 µs | E7 µs | E7 ggü. E1–E6 % | E7 ggü. v1 % |
| --- | --- | --- | --- | --- | --- |
| Ed301 sign | 29.277438 | 29.799042 | 29.514521 | -0.955 | +0.810 |
| Ed301 verify | 89.010746 | 87.092226 | 83.335425 | -4.314 | -6.376 |
| Ed301 import | 98.168513 | 66.774133 | 62.416451 | -6.526 | -36.419 |
| X301 public | 28.528298 | 28.072040 | 28.032819 | -0.140 | -1.737 |
| X301 shared | 58.120661 | 66.091234 | 60.212009 | -8.896 | +3.598 |

Diese Reihe bestätigt den wesentlichen Gewinn bei X301 shared, aber nicht
„vier von fünf Lanes schneller“: Ed301 sign liegt hier ebenfalls knapp über v1.
Die E7-SD bei sign beträgt 2,813 µs, die Vorher-SD bei X301 shared 6,793 µs.
Kleine Abstände sind angesichts der Streuung keine Geschwindigkeitsgarantie.

Danach folgen zwei neue vollständige ABI-Matrizen mit unabhängig neu
gebauten Vergleichsbinaries. Ihr Rust-Kern selbst ruft kein OpenSSL auf.
Jede Tabellenzeile verwendet ausschließlich ihren eigenen v1-Bezugswert;
weder ABI-Läufe noch Claudes CPU-3-Reihe werden zusammengelegt.

| ABI-Lauf | Kernoperation | v1 µs | E7 µs | Änderung % | Median unter v1 |
| --- | --- | --- | --- | --- | --- |
| 3.5.8 | Ed301 sign | 29.132135 | 29.697896 | +1.942 | nein |
| 3.5.8 | Ed301 verify | 87.375733 | 83.506851 | -4.428 | ja |
| 3.5.8 | Ed301 import | 98.739871 | 63.081360 | -36.114 | ja |
| 3.5.8 | X301 public | 28.100456 | 27.587280 | -1.826 | ja |
| 3.5.8 | X301 shared | 57.866651 | 59.700955 | +3.170 | nein |
| 4.0.2 | Ed301 sign | 29.411091 | 29.117105 | -1.000 | ja |
| 4.0.2 | Ed301 verify | 87.352064 | 83.433324 | -4.486 | ja |
| 4.0.2 | Ed301 import | 98.094883 | 62.539953 | -36.245 | ja |
| 4.0.2 | X301 public | 27.553107 | 27.773344 | +0.799 | nein |
| 4.0.2 | X301 shared | 57.473484 | 60.447131 | +5.174 | nein |

Die vollständigen Streuungen und Rohwerte stehen im Benchmarkbericht und
in den versiegelten Receipts. Das Kriterium „alle fünf Lanes unter v1“ wird
nicht aus einer Auswahl des jeweils günstigsten Laufs abgeleitet.
X301 shared bleibt in den beiden endgültigen Matrizen +3,170 % beziehungsweise
+5,174 % über v1. Bei Ed301 sign und X301 public wechselt das Vorzeichen
zwischen den Läufen. Damit ist auch „vier von fünf schneller“ nicht stabil
belegt; die Entscheidung über diese Restabstände bleibt offen.

## Umsetzung und Belege

Commit c5f8989d8195efc456439f6b8f9b38ab21191281 enthält E7: zeilenweise
square_wide aus dem tatsächlichen X301-v1-Donor 569dc4ff, skalierte A24-
Verdopplung, mul_small_narrow, Schranken, Generatorprüfung und zusätzliche
Tests. Commit a83511cf26ade60c9355998ab1ccbc11f73d83c8 ergänzt die exakte
öffentliche Status-Stackbelegung der finalen Ed301-DSOs im Codegen-Prüfer.

Die frühere E4-Aussage gleicher Quadrierungskerne war für den tatsächlichen
X301-v1-Donor falsch; sie traf nur auf den Ed301-v1-Donor zu. E7 korrigiert
diese Zuordnung ausdrücklich. Der alte Spaltenrumpf bleibt bytegleich als
Testorakel; der neue Produktionsrumpf entspricht dem X301-v1-Donor.

Mit K=a−d=61206265502 und d=−301 lautet die Verdopplung
X2=(K·AA)·BB und Z2=E·(K·AA−301·E). Beide projektiven Ausgaben sind gegenüber
dem alten Weg mit demselben nichtnull K skaliert. Generator und Tests prüfen
A24_MINUS·K ≡ −301 mod p. Der lose enge Small-Multiplikator hat Eingabe <4p
und öffentlichen Faktor <2^32; das Produkt bleibt <2^335, innerhalb der
bestehenden <2^338-Reduziererschranke. Die zeilenweise Quadrierung besitzt
neue exakte Zwischenwert- und Überlaufbelege.

Vollständige Herleitung und Zwischenprüfung:
/home/martin/Dokumente/ED301/ed301/phase-e/E7_OPTIMIZATION.md.

Schranken:
/home/martin/Dokumente/ED301/ed301/phase-c/FIELD_BOUNDS.md.

Unverändert bleiben 301 Runden, Clamp, Swaps, Fehlerreihenfolge, Parameter,
Kodierungen, Zeroizing-Besitzer und Ausgabeverträge. Kein Assembler, keine
Clamp-Bit-Abkürzung, keine weitere Schleifenumstellung. Claudes drei Eingaben
werden bytegleich aufbewahrt, einschließlich der Leerzeichen im Originaldiff.

## Alle technischen Gates neu

Kern: 62 Ed301- und 56 X301-Tests,
jeweils auch mit sign-self-verify beziehungsweise Taint-Feature. Sowohl
die ursprünglichen 54/25 als auch sämtliche E1–E6-Testnamen (61/54) bleiben
enthalten; keine ignorierten, gemessenen oder herausgefilterten Tests.
Gate-B-Vektoren, Phase-B-Replay 8/8, Generatoren, Feldschranken, Vendor-
Integrität, Clippy mit warnings denied, Formatierung, no_std-Consumer und
Release-Profilmarker bestehen. Die historischen Vergleichsquellen wurden
dafür ebenfalls neu gebaut und werden als Quellen, nicht als alte PASS-
Receipts, mitgeliefert.

Neue Core-Taint-Läufe: 36 Ed301 und 526 X301, einschließlich Fehlerpfaden
und weiterhin geheim markierter Shared-Ausgabe. Je OpenSSL-ABI 3.5.8/4.0.2:
neun neue v2-DSO-Varianten, vier unabhängige bitidentische Rebuilds, frisch
gebaute v1-Provider und bestandene Funktions-, CLI-, TCP-, strukturierte
Vertrags-, Speicher-, Kontroll-, Codegen-, Timing- und Benchmark-Stages.
TCP verwendet ausschließlich eigene 127.0.0.1-Endpunkte und besteht je
95 Prüfungen einschließlich HRR, KeyUpdate und Negativfällen.

ASan/UBSan gelten für die nativen C-Teile, Memcheck zusätzlich für ganze
Prozesse einschließlich Rust und OpenSSL. Taint instrumentierter DSOs
ersetzt nicht die Prüfung der tatsächlich gemessenen Ordinary-DSOs.
Der strikte x86-64-Codegen-Gate bindet je ABI vier tatsächliche Ordinary-/
TLS-DSOs und beide gemessenen primären Core-ELFs. Alle alten Call-/Branch-
Regeln und Gegenproben bleiben; neue Herkunfts-/Skalierungs-Gegenproben
prüfen die geänderte Registerbelegung. Die feste Leiter bleibt 300 bis 0.

dudect: 200000 angeforderte Messungen je Test, zufällige Klassenbelegung
in den Rohdaten, Schwelle |t| > 10 und sticky detection. Positivkontrollen
erkannt, reguläre Tests bestanden, keine Vorbereitungs-/Operationsfehler.
Weder dudect noch Taint oder Codegen sind ein universeller Seitenkanalbeweis.
Der Hybrid-Reject-Fall T5 bleibt ein informativer Test; delegiertem ML-KEM
wird hier kein eigenständiger umfassender Constant-Time-Nachweis zugeschrieben.

Frische Messmatrizen: 128 Fälle je ABI, zusätzlich 98 Nachrichten-/Context-
und Lifecycle-Fälle sowie 38 Mikrobenchmarks, jeweils neun Rotationen.
Dazu 52 Ed301- und 15 X301-Ressourcenfälle mit drei Massif- und neun
nativen RSS-Wiederholungen und neue Positivkontrollen. 14 tatsächlich
gemessene Core-ELFs wurden auf Sektionen und Festbasistabellen geprüft.
Diesen zusätzlichen Messharnesses wird kein nicht ausgeführter Codegen-
Gate zugeschrieben.

## E6 und Integrationsgrenzen

Die DER-Callgrind-Prüfung ist an beiden neuen finalen Codec-Binaries und
DSO-Sätzen wiederholt: ein Key-Import im Setup, keine Seed-Re-Expansion,
kein Key-Validate und kein Encoder-Reimport im Messloop. Drei statt zwei
Aliasse verursachen zusätzliche Encoder-Suche. Diese Grenzen wurden
nicht durch Aliasentfernung oder Context-Wiederverwendung verändert.
Instruktionszahlen sind keine Laufzeitmessungen.

Die bisherigen N1/N2/N4/N5/N6-Grenzen bleiben: explizite vollständige
Keyfile-Prüfung bei DER-Nachlauf, Stock-CLI-Integration als Stufe-2-Gate,
Entscheidung zu sichtbaren Testnamen, dokumentierte Key-Share-Reihenfolge
und kein AArch64-Nachweis. TLS-Engine-Ergebnisse werden frisch ausgewiesen.
Es gibt keine Freigabe für Stufe 2, RPM-Bau, Installation, Aktivierung,
Produktivnutzung, Push oder Veröffentlichung.

## Quellenbindung, Fehlläufe und Übergabe

Ausgeführter Endstand:
/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e7_final_02_2026-09-10/source

Quellmanifest SHA-256: 00defea7ec46cfb503f3f14c65e9b4f2f8d3f086adefa1d68e219440a1725e79; 1906 Dateien.
Alle E7-Core-Prüfungen werden dateiweise über den vollständigen Rust-Baum
und die jeweiligen Harness-/Runner-Manifeste mit diesem Endstand verglichen.
Die abschließenden ABI-Gates verwenden durchgängig dieses vollständige
Quellmanifest. Die historische Profilbeschreibung im unveränderten
Benchmarkcontroller nennt E1–E5; maßgeblich sind die neuen E7-Quell- und
Binärhashes, nicht diese alte Freitextbezeichnung.

Frühe E7-Vorbereitungsläufe wurden nicht überschrieben oder als PASS
gezählt: die anfängliche Test-only-Einschränkung von mul_tight wurde
korrigiert, bevor die erfolgreiche Kernprüfung entstand. Die zunächst
verweigerten Codegen-Formen wurden anhand der tatsächlichen Disassemblies
nachvollzogen und mit Negativkontrollen gebunden. Der vollständige finale
Quellstand wurde erst nach diesen Prüferanpassungen eingefroren.

Nach Ausführung hinzugefügte E7-Berichte und Übergabecontroller stehen
getrennt im Index; keine Hash-Identität mit dem ausgeführten Snapshot wird
vorgetäuscht. Frühere E1–E6-Berichte und ihre Übergabe bleiben unverändert
historisch; kein dortiger PASS-Beleg ersetzt einen neuen E7-Gate.

Index:
/home/martin/Dokumente/ED301/ed301/phase-e/E7_EVIDENCE_INDEX.json

Der Index bindet 20 ABI-Stages,
14 ergänzende Receipts und
3 Vergleichs-Quellsnapshots. Build-Caches und
ausdrücklich inventarisierte große Kontroll-Fixtures werden ausgelassen;
alle versiegelten Ergebnislogs, Messartefakte und benötigten Binaries
bleiben enthalten. Enthaltene Schlüssel sind ausschließlich erzeugte
Testschlüssel. Archivprüfung, frische Extraktion und natives Replay
erhalten eigene äußere Receipts. Gate E und die Entscheidung über weiteren
Optimierungsaufwand bleiben bei Claude beziehungsweise Martin.
