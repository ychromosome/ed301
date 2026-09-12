# Phase E: Abschluss zur unabhängigen Gate-E-Prüfung

Stand: 10. September 2026. Die beauftragten Optimierungen und lokalen Prüfungen
sind abgeschlossen. **Das Ziel, auf allen fünf Kern-Lanes schneller als v1 zu
sein, ist nicht vollständig erreicht.** Das ist kein bestandenes Gate E:
Claudes unabhängige Prüfung und Entscheidung stehen aus.

## Ergebnis des Geschwindigkeitskriteriums

Median der neun Laufmittel in µs; Änderung v2 relativ zu gleichzeitig gemessenem
v1. Die ABI-Bezeichnung identifiziert den vollständigen Messlauf; der reine
Rust-Kern selbst ruft kein OpenSSL auf.

| ABI-Lauf | Kernoperation | v1 µs | v2 µs | Änderung % | Median unter v1 |
| --- | --- | --- | --- | --- | --- |
| 3.5.8 | Ed301 sign | 29.252734 | 29.979550 | +2.485 | nein |
| 3.5.8 | Ed301 verify | 87.950564 | 86.800313 | -1.308 | ja |
| 3.5.8 | Ed301 import | 98.993170 | 65.760546 | -33.571 | ja |
| 3.5.8 | X301 public | 28.003621 | 27.993124 | -0.037 | ja |
| 3.5.8 | X301 shared | 58.119736 | 64.573765 | +11.105 | nein |
| 4.0.2 | Ed301 sign | 29.131439 | 28.999268 | -0.454 | ja |
| 4.0.2 | Ed301 verify | 86.961010 | 85.502459 | -1.677 | ja |
| 4.0.2 | Ed301 import | 98.866831 | 65.213853 | -34.039 | ja |
| 4.0.2 | X301 public | 28.044990 | 27.743499 | -1.075 | ja |
| 4.0.2 | X301 shared | 57.436946 | 62.954397 | +9.606 | nein |

X301 shared bleibt in beiden Läufen langsamer als v1. Signieren liegt im
3.5.8-Lauf darüber und im 4.0.2-Lauf knapp darunter. Die kleinen Vorteile bei
Signieren, Verifizieren und X301 public sind angesichts der Streuung keine
allgemeine Geschwindigkeitsgarantie. Ed301-Import verbessert sich deutlich.
Keine Auswahl des jeweils günstigsten Laufs und keine weitere, nicht beauftragte
Optimierung zur Erfüllung des Kriteriums.

## Maßnahmen und getrennte Commits

| Schritt | Ergebnis | Commit |
| --- | --- | --- |
| E4 | Echte 15-Produkt-Quadrierung war bereits in v1 und v2 vorhanden; neue Schranken und Oracle-Tests, kein erfundener Laufzeitgewinn | f00a7ca |
| E1 | X301 public über gemeinsame Edwards-Festbasis, unveränderter X301-Clamp und Konvertierung nach Montgomery | 164d87e |
| E2 | Volle 301-Runden-Leiter in der Lazy-Domäne; keine verkürzte Leiter oder abgeschwächte Prüfung | ff62c6b |
| E3 | Auswahlfreie Halbierungsprüfung, eine Quadratwurzel und zwei feste Euler-Symboltests; bisherige Prüfung bleibt Testorakel | 4524831 |
| E5 | Vorzeichen von d algebraisch in Addition und Cache gefaltet; dedicated doubling enthält keinen d-Term und bleibt unverändert | c6d5670 |
| E6 | DER-Mehrbedarf als Encoder-Discovery/zusätzlicher Alias erklärt; keine Seed-Re-Expansion, deshalb keine bedingt beauftragte Laufzeitkorrektur | 10fd80b |
| Endprüfwerkzeuge | Neue Symbole und vollständige Aufruf-/Zähler-/Exponentenregeln an den optimierten Binaries | 27092c1 |

Alle fünf Vorher/Nachher-Läufe enthalten v1, v2 vorher und v2 nachher im selben
32-Fälle-Runner mit neun Rotationen auf CPU 2. Die vollständigen Rohdaten und
Binärdateien sowie sechs unveränderte zugehörige Quellsnapshots sind im Paket.
E4 ist ein Gleichcode-Vergleich. E6 hat keine Laufzeitänderung und daher keinen
Vorher/Nachher-Gewinn. Die früheren Schrittberichte bleiben unverändert als
historische Arbeitsstände; ihre damaligen offenen Endprüfungen werden durch
diesen Abschluss und die neuen Receipts beantwortet.

Der schnellere Jacobi-Versuch aus E3 wurde wegen seines Codegen-Befunds nicht
übernommen. Die Produktionsfassung verwendet die dokumentierten Euler-Exponenten.
Die geschätzten Importkosten von 30–45 µs wurden nicht erreicht.

## Frische technische Prüfungen

61 Ed301- und 54 X301-Tests, jeweils auch mit sign-self-verify beziehungsweise
secret-taint-instrumentation, bestehen. Alle ursprünglichen 54/25 Testnamen
bleiben enthalten. Gate-B-Vektoren, Phase-B-Replay 8/8, Generatoren, Vendor-
Integrität, exakte Feldschranken, Clippy mit warnings denied, Formatierung,
no_std-Consumer und Build-Profilmarker bestehen.

E1 enthält 10000 Leiter/Festbasis-Vergleiche; E2 10000 Vergleiche mit der alten
vollständigen Leiter; E3 100000 alte/neue Untergruppenentscheidungen, die 25
vorgegebenen Vektoren mit Zwischenwerten und die zusätzliche Feld-/Symbol-
Differentialprüfung. Die unabhängige mathematische Referenz wurde erneut
ausgeführt. E5 prüft unter anderem sämtliche Festbasistabelleneinträge.

Core-Taint: 36 Ed301- und 526 X301-Läufe bestehen, einschließlich geprüftem
Input-Taint und weiterhin tainted Shared-Secret-Ausgabe. Das ist ein begrenzter
Werkzeugnachweis, kein universeller Seitenkanalbeweis.

Je ABI wurden neun v2-DSO-Varianten neu gebaut, vier davon bitidentisch
reproduziert, die v1-Vergleichsprovider frisch aus gebundenen Donor-Archiven
gebaut und alle Functional-, CLI-, TCP-, strukturierten Vertrags-, Memory-,
Kontroll-, Codegen-, Timing- und Benchmark-Stages bestanden. ASan/UBSan gelten
für die nativen C-Teile; zusätzlich prüft Memcheck ganze Prozesse einschließlich
Rust und Failpoints. Instrumentierte DSOs ersetzen keine Ordinary-DSO-Prüfung.

Der strikte x86-64-Codegen-Gate gilt je ABI für die vier tatsächlichen Ordinary-/
TLS-DSOs und die beiden tatsächlich gemessenen primären Core-ELFs. Die neuen
Symbole, festen Schleifenzähler, vollständigen Call-Closures, öffentlichen
Exponentenherkünfte und Negativkontrollen sind enthalten. Die gesonderten
Matrix-, Mikrobenchmark- und Ressourcen-Harnesses sind gehashte Messartefakte;
ihnen wird kein zusätzlicher, nicht ausgeführter Codegen-Gate zugeschrieben.

dudect: jeweils 200000 angeforderte Messungen pro Klasse, Schwelle |t| > 10,
sticky detection; sämtliche Positivkontrollen erkannt, keine Vorbereitungs-
oder Operationsfehler. Core-Maxima regulär 2.51, Provider-Maxima regulär 3.52.
Diese statistischen Beobachtungen sind weder Konstantzeitbeweis noch Benchmark.

Die vollständigen Messungen umfassen 128 Fälle je ABI, weitere 98 Nachrichten-/
Context-/Lifecycle-Fälle und 38 Arithmetik-Mikrobenchmarks, jeweils neun
Wiederholungen; außerdem 52 Ed301- und 15 X301-Ressourcenfälle mit drei Massif-
und neun nativen RSS-Wiederholungen. Keine alten v1- oder Phase-C/D-Messwerte
wurden als Endergebnis übertragen.

## E6 und verbleibende Integrationsgrenzen

Die Callgrind-Prüfung wurde auch auf den neuen finalen Codec-Binaries und DSOs
beider ABIs wiederholt. Einmaliger Key-Import im Setup, kein Key-Validate und
kein Encoder-Reimport im Messloop; der Seed-Getter liefert gespeicherte Bytes.
v2 hat drei statt zwei Algorithmus-Aliasse, die zusätzliche Encoder-Suchen
verursachen. DER-Ausgabe hat innerhalb derselben ABI identische Instruktions-
zahlen. Aliasentfernung oder Context-Wiederverwendung würde den Vertrag oder
die Messgrenze verändern und wurde nicht vorgenommen. N3 ist damit erklärt,
der gemessene Mehrbedarf besteht weiter.

N1 bleibt dokumentierte OpenSSL-Parität bei angehängten DER-Bytes. N2 bleibt
Pflichttest für Stufe 2: Stock req -verify, x509 -req und PKCS#12-Keydump müssen
nach Aktivierung ohne privates Frontend funktionieren. N4, die sichtbaren
_test-Namen, braucht vor Stufe 2 eine ausdrückliche Entscheidung. Zu N5 gilt:
Die Client-Key-Share-Reihenfolge entscheidet; Hybrid wird serverseitig nur
erzwungen, wenn Raw nicht angeboten wird. N6 bleibt: kein AArch64-Nachweis.
N7 wird anhand der frisch gemessenen TLS-Engine-Lanes neu beziffert, nicht aus
Gate D übernommen.

## Bindung und Übergabegrenze

Ausgeführter Quellstand: `/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_final_02_2026-09-10/source`.

Quellmanifest SHA-256: `16e13fc68b35812c553b6659f3101b4e956b57d6f980ce9819216205536deb8a`; 1888 Dateien.

Die nach E5 ausgeführten Core-Prüfungen und Core-Timings werden über sämtliche
Rust-Dateien und ihre jeweiligen Harness-/Runner-Manifeste byteweise mit diesem
Endstand verglichen. Später hinzugekommen sind nur Endprüfwerkzeuge beziehungsweise
Berichte und Übergabecontroller, keine neue Arithmetik. Der finale Commitmanifest
trennt diese nach der Ausführung hinzugefügten Dateien ausdrücklich vom
unveränderten ausgeführten Quellstand; es wird keine Hash-Identität vorgetäuscht.

Vollständiger Index: `/home/martin/Dokumente/ED301/ed301/phase-e/PHASE_E_EVIDENCE_INDEX.json`.

Der Index bindet 20 ABI-Stages, 18 ergänzende Receipts, die sechs Schritt-
Quellsnapshots und die nachträglichen Berichte/Controller. Das äußere Manifest
prüft zusätzlich Datei-/Verzeichnis-/Linkinventar, Modi und Inhalte. Build-Caches
und ausdrücklich inventarisierte große Negativkontroll-Fixtures werden nicht
mitkopiert; sämtliche ursprünglichen versiegelten Logs und Ergebnisse bleiben
enthalten. Zusätzliche gemessene Core-ELFs werden mit ihren ursprünglichen
Identitätshashes aufgenommen. Enthaltene Schlüssel sind ausschließlich frisch
erzeugte Testschlüssel und nicht für produktive Nutzung vorgesehen.

Die zunächst sandboxbedingt abgewiesenen TCP-Versuche bleiben separat erhalten;
die freigegebenen Wiederholungen verwenden ausschließlich eigene Loopback-
Endpunkte und bestehen. Frühere fehlgeschlagene Vorbereitungsläufe werden nicht
als PASS gezählt und nicht überschrieben.

Paketprüfung, frische Archivextraktion und natives Replay werden im äußeren
Übergabezettel mit ihren eigenen Receipts dokumentiert. Diese nachträglichen
Verpackungsprüfungen sind nicht Teil eines zirkulär selbstbestätigten Berichts.
Gate E liegt bei Claude. Stufe 2, RPM-Bau, Installation, Aktivierung, AArch64,
Produktionsfreigabe und Veröffentlichung sind nicht autorisiert. Phase E wird
nicht ohne separates Go gepusht.
