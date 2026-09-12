# Ed301 / X301: zweiter Review mit frischen Seitenkanalprüfungen

Datum: 12. September 2026. Branch `Review`, Commit **5f446b495ca09d11694479b30ce6fe0a5c6dade7**.

## Ergebnis

Die Nacharbeiten sind im aktuellen Snapshot nachvollziehbar umgesetzt. Die funktionalen Prüfungen, frischen Core- und Provider-Taint-Läufe, C-Sanitizer-/Memcheck-Prüfungen und die vorhandenen Codegen-Gates bestehen. Die Timing-Prüfungen ergeben in den untersuchten Klassen kein Leakage-Signal. Eine bestätigte neue Schwachstelle der Kryptokerne oder Provider wurde nicht gefunden.

Die Untersuchung der Prüfwerkzeuge zeigt drei konkrete Grenzen, die als nächste Verbesserungen sinnvoll sind: allgemeine Tail-Call-Abdeckung, Prüfung der tatsächlichen Löschschreibzugriffe und eine präzisere X301-Taint-Baseline. Ergänzende Inspektion der aktuellen Binärdateien fand bei den betrachteten Löschfunktionen und Sprungzielen keine entsprechende Fehlfunktion. Diese Werkzeuglücken sind keine nachgewiesenen kryptografischen Angriffe.

Die erneute Prüfung umfasst eigene aktive Kryptologik, Provider und relevante Testwerkzeuge; der gesamte Vendor- und historische Archivbestand wurde weiterhin nicht vollständig zeilenweise auditiert. Die Repository-Abdeckung des begleitenden Security-Scans ist deshalb ausdrücklich partiell. Die hier aufgeführten Laufzeitergebnisse wurden frisch ermittelt.

## 1. Quellen und Nacharbeiten

Gelesene Nutzerdateien:

- [/home/martin/Dokumente/ED301/ed301/docs/REVIEW_FOLLOWUP_20260912.json](/home/martin/Dokumente/ED301/ed301/docs/REVIEW_FOLLOWUP_20260912.json)
- [/home/martin/Dokumente/ED301/ed301/docs/REVIEW_FOLLOWUP_20260912.md](/home/martin/Dokumente/ED301/ed301/docs/REVIEW_FOLLOWUP_20260912.md)

Beide sind bytegleich mit ihren Kopien im neu geklonten Review-Snapshot. Der Checkout liegt unter [/home/martin/Projekte/hostile-Reviews/ed301-Review-followup-20260912](/home/martin/Projekte/hostile-Reviews/ed301-Review-followup-20260912).

Für die Laufzeittests wurde ein eigenes, schreibgeschütztes Archiv dieses Commits unter [/tmp/ed301-followup-audit-VXVHCg/source](/tmp/ed301-followup-audit-VXVHCg/source) erstellt. Das vollständige Quellmanifest [/tmp/ed301-followup-audit-VXVHCg/SOURCE_SHA256SUMS](/tmp/ed301-followup-audit-VXVHCg/SOURCE_SHA256SUMS) hat SHA-256 `c8e22f994c36a49d7bfa0933fa7bd38ced03f2c8095048549ff8ea42bf13061e` und enthält 1.992 Dateien.

Das frühere 1.990-Dateien-Manifest aus den Nacharbeiten wurde gegen diesen Snapshot geprüft. Seine Einträge stimmen überein; die beiden anschließend ergänzten Follow-up-Dokumente erklären die Differenz. Die aktive Kurvenarithmetik, Parameter, Signatur-/XDH-Kryptologik, DRBGs und `Shared<T>` sind gegenüber dem ersten Review unverändert. Dafür wurden Quellen verglichen; es wurde keine neue Kurvensuche gestartet.

| Früherer Befund | Ergebnis dieses Reviews |
|---|---|
| R1: veraltete normative Einstiegspunkte | Behoben durch den aktuellen Profilvertrag mit ausdrücklich geregeltem Vorrang gegenüber eingefrorenen Phasentexten. |
| R2: X301-Fehlerpriorität | Behoben: aktueller Vertrag, Python, Node und Rust verwenden Secret-first. Neuer gemeinsamer Korpus mit 39 Fällen. |
| R3: Ed301-Diagnose bei X301 | Behoben durch den vorhandenen algorithmusspezifischen Anzeigenamen; beide ABI-Lanes bestehen die Decodertests. |
| R4: Abhängigkeitsangaben | Behoben: aktive direkte Cargo-Abhängigkeiten, Build-Rolle von `cc` und nur retained Vendorquellen sind unterschieden. |
| R5: unportable Integrationsverweise | Behoben am aktuellen Einstieg; historische Dokumente behalten ihre ursprünglichen Pfade. DSO-/Anwendungsgrenzen sind deutlich beschrieben. |
| R6: doppelte Hilfsfunktionen | Behoben durch gemeinsame Build-/Parameterhilfen, mit Regressionstests. |
| R7: überflüssige Rechtfertigungen | Weitgehend bereinigt. Zwei kleine alte Quellkommentare bleiben unten als redaktionelle Restpunkte genannt. |

Aktuelle Verträge:

- [/home/martin/Projekte/hostile-Reviews/ed301-Review-followup-20260912/specifications/CURRENT_PROFILE.md](/home/martin/Projekte/hostile-Reviews/ed301-Review-followup-20260912/specifications/CURRENT_PROFILE.md)
- [/home/martin/Projekte/hostile-Reviews/ed301-Review-followup-20260912/docs/INTEGRATION.md](/home/martin/Projekte/hostile-Reviews/ed301-Review-followup-20260912/docs/INTEGRATION.md)

Die aktuellen Angaben zu Nested Properties, unterschiedlichen OpenSSL-Versionsguards, Hybrid-only-Gruppenwahl und den Anwendungsprüfungen für vollständige Dateien/PKI entsprechen den gelesenen Verbrauchern. Die RPM-Eingaben werden korrekt als älterer Kandidat beschrieben; sie sind nicht durch diesen Review neu akzeptiert.

## 2. Frisch geprüfte Plattform und Binärbindung

- Native Architektur: x86-64.
- Rust: `1.98.0 (88d9e12ae 2026-08-18)`, LLVM `21.1.8`.
- Valgrind: `3.27.1`.
- Kontrollierte OpenSSL-Lanes: `3.5.8` und `4.0.2`, aus den vorhandenen geprüften Eingaben neu in eigene Verzeichnisse kopiert und erneut hashgeprüft.
- Rust-Releaseprofil: O3, ThinLTO, eine Codegen-Unit, `panic=unwind`, Overflow-Prüfungen aktiv. Profilmarker wurden geprüft.
- Die Timing-Läufe erfolgten nacheinander auf logischer CPU 2, ohne Governor-/Boost- oder Systemkonfigurationsänderung. Die Umgebung ist keine vollständig hardwareisolierte Messstation; die Runner protokollieren Hintergrundlast.

Je OpenSSL-Lane wurden neun Provider-Varianten frisch gebaut. Vier Ordinary-/TLS-Module wurden aus getrennten Buildverzeichnissen jeweils bytegleich erneut erzeugt. Neue Functional-Receipts binden Source, Module, Testprogramme, OpenSSL-Bibliotheken und Kontrollausgaben. Die folgenden Stufen prüfen diese Bindungen vor und nach dem Lauf.

| Stufe | Frisches Ergebnis |
|---|---|
| Native funktionale Controller | 139 Schritte je ABI bestanden |
| Rust-Provider-Tests | 20 Ed301 + 7 X301 je ABI bestanden |
| Core-Funktionstests | 65 Ed301 und 58 X301 bestanden |
| Core Ed301 Self-Verify | 65 Tests bestanden |
| Python-Referenzen | 30 Tests bestanden |
| Node-Fehlerpriorität | 39 gemeinsame Fälle bestanden |
| Dokumentations-/Inventarprüfungen | 5 Kennungen, 54 Links und aktuelles Cargo-Inventar bestanden |
| Gemeinsamer Build-Helfer | 3 Tests mit 39 Unterprozessen bestanden |
| Stock-CLI | 48 Schritte je ABI bestanden; nur prozesslokale Aktivierung |
| TLS/TCP | 95 Prüfungen je ABI bestanden; eigene Loopback-Endpunkte und Testschlüssel |

## 3. Taint, Sanitizer und Speicherzugriffe

| Prüfung | Ergebnis und Aussage |
|---|---|
| Ed301-Core | 36 Valgrind-Läufe für 9 Vektoren, Public/Sign und Defined/Tainted bestanden. |
| X301-Core | 526 Valgrind-Läufe über 263 Fälle bestanden: Public/Import, Curve-/Twist-DH, ungültige Eingaben und 192 Weak-Secret-Operationsfälle. |
| Öffentliche Importgrenze | Defined davor/danach erfolgreich; secret-markierter Eingang wird mit dem erwarteten spezifischen Fehler abgewiesen. |
| Native C-ASan/UBSan | 22 Testaufrufe je ABI bestanden; instrumentiert sind C-Harnesses und C-Shims. |
| Ganze Prozesse unter Memcheck | 22 Testaufrufe je ABI bestanden; diese umfassen auch Rust und OpenSSL. |
| Provider-Taint und private Exporte | In beiden ABI-Lanes bestanden, einschließlich Raw-/Parameter-/PKCS#8-Ausgabe und Encoder-Brücke. |
| Positivkontrollen | Die absichtlich ausgelösten undefinierten Verwendungen und privaten Exportkontrollen liefern jeweils den erwarteten Valgrind-Exitcode 99. |

Jeder Memory-Controller umfasst 107 protokollierte Schritte, einschließlich der frischen Sanitizer-/Taint-Builds. Der instrumentierte X301-Core prüft auch die Markierung seiner geheimen Ausgabe. Das Instrumentieren echter RNG-Ergebnisse ist sinnvoll, weil Valgrind korrekt erzeugten Zufall sonst als definiert betrachtet.

ASan/UBSan und Memcheck sind keine Suche nach sämtlichen nach Funktionsende verbliebenen geheimen Register-/Stackkopien. Diese Frage wird durch ein bestandenes Memory-Receipt nicht automatisch beantwortet. Sie bleibt eine gesonderte Binär- und Lebensdauerprüfung.

## 4. Timing-Ergebnisse

Die vorhandenen dudect-Harnesses wurden unverändert mit **200.000 angeforderten Messungen je Test** ausgeführt. Der konfigurierte Detektionsschwellwert ist `|t| = 10`; Rohzahlen, Batches und gültige Stichproben stehen in den Protokollen. Ein einmal erkanntes Signal bleibt über weitere Batches hinweg gesetzt. Vorbereitung und eigentliche Operationen meldeten keine Fehler.

| Messung | Core | Provider 3.5.8 | Provider 4.0.2 |
|---|---:|---:|---:|
| Ed301 vorbereitetes Signieren | 2,565 | 2,69 | 3,17 |
| Ed301 Seed-Expansion / privater Import | 2,765 | 3,55 | 2,12 |
| X301 Public-Ableitung | 3,350 | — | — |
| X301 DH, Secret-Klassen | 2,805 | 2,68 | 2,45 |
| X301 DH, öffentliche Peer-Klassen | — | 2,74 | 2,77 |
| X301 privater Import | — | 2,65 | 3,41 |
| Hybrid-Decapsulation, gültige Ciphertext-Klassen | — | 3,06 | 2,17 |
| Hybrid-Rejection, nur informativ | — | 2,56 | 2,14 |

Zahlen sind jeweils der größte beobachtete absolute t-Wert, keine Laufzeiten. Core-Expansion und Provider-Import sind verschiedene API-Grenzen und werden deshalb nicht als identische Performanceoperation verglichen. Alle sechs absichtlich undichten Positivkontrollen wurden erkannt; deren Spitzenwerte liegen zwischen rund 4.310 und 6.397.

**Interpretation:** Kein Leakage-Signal in den ausgeführten Klassen. Öffentliche Peer-Variation ist für sich kein Nachweis eines Secret-Leaks. Die Positivkontrolle prüft die Erkennung einer deutlichen künstlichen Abhängigkeit, aber keine kalibrierte kleinste erkennbare Leckage. Das Ergebnis deckt weder jede denkbare Eingabeverteilung noch andere Prozessoren oder Compiler ab.

## 5. Maschinencode und zusätzliche direkte Inspektion

Die vorhandene Phase-E-Policy besteht frisch für acht Ordinary-/TLS-Provider-DSOs (vier je ABI) und zwei aktuelle Core-Programme. Auch die vorhandenen negativen Kontrollen, die Weitergabe eines gezielt abgelehnten Dataflow-Prüfschritts und die Tool-Prerequisite-Tests bestehen.

Für die Core-Inspektion wurden die vorhandenen Benchmark-Harnessquellen gegen den aktuellen Core gebaut. Das ist eine Codegen-Prüfung dieser neuen Programme; es wurde keine neue vollständige historische v1/E8-Performancevergleichsmatrix behauptet. Das X301-Harness erhielt nur ein externes Cargo-Manifest, seine Quelle wurde nicht geändert.

Zusätzlich wurden tatsächliche Disassemblierungen gelesen und mit einem ergänzenden, ausschließlich lesenden Skript untersucht:

- **20 Instanzen** der 38-Byte-Löschfunktion enthalten Null-Schreibzugriffe für sämtliche Offsets 0 bis 37.
- Die betrachteten allgemeinen Rechenhelfer enthalten keine unbekannten externen Tail-Transfers. Die gefundenen externen Sprünge führen von X301-Key-Drops zu den geprüften Löschfunktionen.
- Der X301-Key-Drop verschiebt den Zeiger um 38 Bytes, um den zweiten 38-Byte-Besitzer zu löschen; der gelesene Unwind-Pfad berücksichtigt ihn ebenfalls.

Das ergänzt die bestehenden Gates für genau diese Binaries. Es zertifiziert nicht alle Aufrufstellen, Besitzer-Offsets, Compilerkopien oder physische Löschung im gesamten Prozess.

Ergänzende Artefakte:

- [/home/martin/Projekte/hostile-Reviews/ed301-followup-review-results-20260912/inspect_codegen_outputs.py](/home/martin/Projekte/hostile-Reviews/ed301-followup-review-results-20260912/inspect_codegen_outputs.py)
- [/home/martin/Projekte/hostile-Reviews/ed301-followup-review-results-20260912/actual-wipe-and-tail-inventory.json](/home/martin/Projekte/hostile-Reviews/ed301-followup-review-results-20260912/actual-wipe-and-tail-inventory.json)
- [/home/martin/Projekte/hostile-Reviews/ed301-followup-review-results-20260912/core-wipe-and-tail-inventory.json](/home/martin/Projekte/hostile-Reviews/ed301-followup-review-results-20260912/core-wipe-and-tail-inventory.json)

## 6. Neue Befunde an den Prüfwerkzeugen

### T1 — Allgemeine Call-Closure lässt Tail-Transfers offen

**Einordnung: konkrete Lücke der automatischen Regressionserkennung, kein bestätigter aktueller Seitenkanal.**

Der allgemeine Call-Graph-Prüfer erfasst `call`, während der Branch-Form-Prüfer `jmp`/`jmpq` ausnimmt. Für einzelne Symbole existieren spezielle Tail-Prüfungen, aber keine allgemeine Klassifikation aller Transfers bei den entsprechend zugelassenen Rechenhelfern.

Belege: [/home/martin/Projekte/hostile-Reviews/ed301-Review-followup-20260912/phase-e/tools/check_codegen.sh:447](/home/martin/Projekte/hostile-Reviews/ed301-Review-followup-20260912/phase-e/tools/check_codegen.sh:447), insbesondere auch die Branch-Auswertung derselben Datei ab Zeile 579.

**Empfehlung:** Jeden unbedingten Sprung als internes Ziel oder aufgelösten externen Tail-Call einordnen. Externe Tails müssen in die Call-Closure eingehen; entsprechende Ablehnungskontrollen ergänzen. Die direkte Inspektion der aktuellen ausgewählten Symbole ergab nur die oben beschriebenen erwarteten Ziele.

### T2 — „Branch-free zeroizer“ prüft nicht die vollständige Löschung

**Einordnung: konkrete Aussagegrenze des Gates; aktuelle geprüfte 38-Byte-Funktionen löschen vollständig.**

`check_all_branch_free` prüft Instanzzahl und fehlenden Kontrollfluss, jedoch weder Nullwerte noch Zieladressen oder Byteabdeckung der Schreibzugriffe. Die Prüfung der 76-Byte-Digit-Loops zeigt bereits im selben Werkzeug einen stärkeren Ansatz.

Belege: [/home/martin/Projekte/hostile-Reviews/ed301-Review-followup-20260912/phase-e/tools/check_codegen.sh:549](/home/martin/Projekte/hostile-Reviews/ed301-Review-followup-20260912/phase-e/tools/check_codegen.sh:549), [/home/martin/Projekte/hostile-Reviews/ed301-Review-followup-20260912/phase-e/tools/check_codegen_dataflow.py:121](/home/martin/Projekte/hostile-Reviews/ed301-Review-followup-20260912/phase-e/tools/check_codegen_dataflow.py:121).

**Empfehlung:** Nullwerte, Zielbereiche, vollständige Byteabdeckung und die relevanten Besitzer-Offsets prüfen; Kontrollen für unvollständige oder falsch adressierte Löschung ergänzen. Die ergänzende aktuelle Inspektion dieses Reviews ersetzt solche dauerhaften Regressionstests nicht.

### T3 — X301-„defined“-Modus ist keine durchgehend unmarkierte Baseline

**Einordnung: Präzisierung des Testdesigns, keine Produktionsfehlfunktion.**

Der Provider-Harness prüft seinen Eingangsmodus korrekt. Die instrumentierte Rust-FFI markiert die importierte private Kopie anschließend aber in beiden Modi erneut als geheim. Deshalb erwarten beide Modi am Ende eine markierte Shared-Secret-Ausgabe. Das deckt Ingress und geheime Arithmetik ab, beweist hinter der Kopiergrenze jedoch nicht unabhängig den Erhalt der ursprünglichen Eingangsmarkierung.

Belege: [/home/martin/Projekte/hostile-Reviews/ed301-Review-followup-20260912/provider-tests/x301/provider_x301_secret_taint.c:99](/home/martin/Projekte/hostile-Reviews/ed301-Review-followup-20260912/provider-tests/x301/provider_x301_secret_taint.c:99), [/home/martin/Projekte/hostile-Reviews/ed301-Review-followup-20260912/provider/crates/x301-provider/src/x301_ffi.rs:572](/home/martin/Projekte/hostile-Reviews/ed301-Review-followup-20260912/provider/crates/x301-provider/src/x301_ffi.rs:572).

**Empfehlung:** Die Prüfung importierter Markierungsweitergabe von der absichtlichen Markierung neuer RNG-Ausgaben trennen. Alternativ die vorhandenen Modi genauer benennen und ihren Umfang beschreiben. Produktionscode muss dafür nicht allein aufgrund dieses Befunds geändert werden.

### Weitere kleine Punkte

- Das Codegen-Werkzeug bindet den Toolchain-Marker per Hash, erzwingt dessen Versionsinhalt aber nicht selbst. Hier wurde die reale Version unabhängig gelesen und entspricht LLVM 21.1.8. Für automatisierte Abnahmen anderer Compiler ist eine explizite Prüfung beziehungsweise eigene Freigabe nötig.
- [/home/martin/Projekte/hostile-Reviews/ed301-Review-followup-20260912/rust/crates/ed301-eddsa/src/field.rs:3](/home/martin/Projekte/hostile-Reviews/ed301-Review-followup-20260912/rust/crates/ed301-eddsa/src/field.rs:3) beschreibt den spezialisierten Backend-Ausbau noch als Zukunft. Heute dient dieses Modul als Gegenmodell und Inversionsbackend.
- [/home/martin/Projekte/hostile-Reviews/ed301-Review-followup-20260912/provider/crates/ed301-eddsa-provider/c/provider_shim.c:1441](/home/martin/Projekte/hostile-Reviews/ed301-Review-followup-20260912/provider/crates/ed301-eddsa-provider/c/provider_shim.c:1441) enthält noch die alte Abschnittsbezeichnung „Test-only encoders“, obwohl TLS-Module diese Codecs enthalten.

## 7. Was weiterhin offen bleibt

Priorität haben jetzt die drei Werkzeugpräzisierungen und anschließend eine konkrete Untersuchung verbleibender geheimer Kopien an den gewünschten Auslieferungsdateien. Die aktuelle Pipeline hat einen erheblichen Teil der Seitenkanalprüfung frisch geleistet; vollständige physische Löschung ist damit weiterhin nicht bewiesen.

Ebenso bleiben offen:

- Neue Fedora-/LLVM-22-RPMs und deren eigene Binärabnahme; in diesem Review wurde kein Paket installiert oder aktiviert.
- Andere Architekturen und Prozessoren, die MSRV-1.91-Lane sowie weitere Compilerprofile.
- Isolierte Miri-/Nebenläufigkeitsmodell-Prüfung von `Shared<T>`.
- Kalibrierte konfigurierbare PBES2-Passwortkosten vor dauerhafter Ablage unter menschlichen Passwörtern. Die bekannten 2048 Default-Iterationen wurden nicht als neue Regression ausgegeben; der aktuelle Vertrag benennt diese Grenze ausdrücklich.
- Vollständige neue mathematische Suche/Zertifikatserzeugung: nicht nötig für diese unveränderten Parameter und hier nicht durchgeführt.

## 8. Nachweise und Erhalt des Snapshots

Neue Laufprotokolle: [/home/martin/Projekte/hostile-Reviews/ed301-followup-review-results-20260912/logs](/home/martin/Projekte/hostile-Reviews/ed301-followup-review-results-20260912/logs).

Vollständige lokale Laufverzeichnisse mit Source, Receipts, neuen Modulen und Disassemblierungen: [/tmp/ed301-followup-audit-VXVHCg](/tmp/ed301-followup-audit-VXVHCg).

Der ergänzende automatische Security-Report liegt unter [/home/martin/Projekte/hostile-Reviews/ed301-followup-review-results-20260912/security/report.md](/home/martin/Projekte/hostile-Reviews/ed301-followup-review-results-20260912/security/report.md). Der Scan wurde mit null bestätigten Kryptografie-/Provider-Sicherheitsbefunden abgeschlossen; die drei Werkzeuggrenzen und übrigen offenen Fragen stehen ausdrücklich in der partiellen Coverage.

Das kompakte Nachweisarchiv liegt unter [/home/martin/Projekte/hostile-Reviews/ed301-followup-review-results-20260912/ED301_FOLLOWUP_EVIDENCE_20260912.tar.gz](/home/martin/Projekte/hostile-Reviews/ed301-followup-review-results-20260912/ED301_FOLLOWUP_EVIDENCE_20260912.tar.gz). Entbehrliche Cargo-Buildcaches werden ausgelassen; die geprüften Core- und Taint-Programme aus [/tmp/ed301-followup-audit-VXVHCg/tested-binaries](/tmp/ed301-followup-audit-VXVHCg/tested-binaries) bleiben zusätzlich erhalten. Es ist ein Nachweisarchiv, keine Zusage eines ohne neue Konfiguration umziehbaren Replay-Systems.

Das Abschlusswerkzeug meldet für vier zugeordnete Thread-Rollouts 31.701.040 Tokens: 31.612.567 Eingabe- und 88.473 Ausgabetokens, mit 30.981.504 gecachten Eingabetokens. Dies ist eine Werkzeugmetrik der Thread-Rollouts, keine separat bestätigte Kostenabrechnung ausschließlich dieses Reviews.

Der Review-Checkout und seine Historie wurden nicht geändert. Das ergänzende Disassemblierungs-Skript und das externe Cargo-Manifest gehören ausschließlich zu den Review-Artefakten. Alle verwendeten Schlüssel waren öffentliche Vektoren oder neu erzeugte Testschlüssel. Es erfolgten kein Push, keine Signatur, keine Installation und keine Änderung der System-Providerkonfiguration.
