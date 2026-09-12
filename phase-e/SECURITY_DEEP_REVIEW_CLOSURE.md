# Deep-Security-Review: Ergebnis und Grenzen

Geprüft am 11. September 2026, redaktionell gekürzt am 12. September 2026.
Vier unabhängige Standard-Durchläufe: **keine bestätigte berichtspflichtige
Schwachstelle**. Die Prüfung war statisch; Builds, Laufzeittests, Timing
und Maschinencodeprüfungen waren nicht Bestandteil dieses Scans.

## Umfang und Quellenbindung

Geprüft wurden 45 Dateien aus `provider`, `rust/crates/ed301-eddsa` und
`rust/crates/x301`. Der übrige Repository-Baum und das Arbeitsbasisverzeichnis
waren keine Scan-Ziele. 1660 weitere Dateien dienten nur als Kontext.

| Bindung | Wert |
| --- | --- |
| Quellcommit | `ddc6e5d33e6b4b4e3fe7665355eab1ce2145e70b` |
| Quellbaum | `fe2b976a2472fd3298356a19ba5f941b3e391339` |
| Separater Scan-Snapshot | `bedcd26eaec73883c8b2d17a67bdb7288dccbdc9` |
| Scan-ID | `119d3788-07ba-4553-a232-fd785bb38dd5` |
| Werkzeug | Codex Security Plugin 0.1.24, Deep Scan |
| Zielmanifest SHA-256 | `22399e7a8937838893a7bec655c9196bd49c0ec9bac8e1e27fa0b9de0cc382a3` |
| Originalbericht SHA-256 | `437a816abcc5bd0e45e512351be4c92048acd105b6e6d424cc3864e3c0c9824f` |

Der [Originalbericht](reference/security_deep_ddc6e5d/report.md),
[Scanmanifest](reference/security_deep_ddc6e5d/scan-manifest.json), Findings,
Coverage und SARIF unter [reference/security_deep_ddc6e5d](reference/security_deep_ddc6e5d)
bleiben bytegleich. Dort stehen auch die Ziel-/Kontextmanifeste, die
Snapshot-Identität und der gekennzeichnete Abschlussmetadatenauszug.
Alle 45 Zielhashes wurden beim Abschluss gegen den Checkout geprüft.
Die beiden Rust-Kerne waren gegenüber E8-Commit `a81eeb5` unverändert;
die spätere Provider-Umbenennung erzeugt dennoch andere Binärartefakte.

## Offene Löschungsfrage

Die Quellenprüfung fand innere geheime `Copy`-Zwischenwerte ohne eigenen
Löschbesitzer. Ein angreiferlesbarer überlebender Speicherinhalt mit
nachgewiesenem Vertraulichkeitsverlust wurde nicht etabliert.

| Bereich | Vorhandene Absicherung | Nicht belegt |
| --- | --- | --- |
| Inversion/Konvertierung | Benannte äußere Besitzer; begrenzte Codegen-Prüfung | Vollständige Löschung innerer `oracle`-/`inverse`-/`converted`-Werte und Konvertierungspuffer |
| Optionaler Sign-Self-Verify-Untergruppencheck | Löschbesitzer des zurückgegebenen Punkts; feste öffentliche Schleifensteuerung | Löschung des lokalen Akkumulators |
| X301-Leiter und gemeinsame Rechenhelfer | Bewachte `LadderState`-, `ProjectiveOutput`- und Rückgabebesitzer | Vollständige Löschung aller weiteren lokalen Werte und Kopien |
| Privater Export/DER | Taint-Markierung und Trennung vom öffentlichen Importpfad | Vollständiger Speicherresttest nach Funktionsende |

Das ist eine offene Quellenbeobachtung, weder eine bestätigte Schwachstelle
noch ein als behoben oder widerlegt geltender Befund. Eine Binär- und
Lebensdauerprüfung müsste die konkreten Auslieferungsartefakte untersuchen.
Fester Kontrollfluss und äußere Löschbesitzer beweisen für sich keine
vollständige Löschung innerer Kopien.

Die betroffenen Helfer liegen in `field_5x64.rs`, `field.rs`, `edwards.rs`
und `signature.rs` des Ed301-Kerns sowie `x301.rs` des X301-Kerns.
Der [E8-Named-Owner-Audit](E8_NAMED_OWNER_BINARY_AUDIT.md) beschreibt seine
begrenzte Binärabdeckung; die [Codegen-Policy](CODEGEN_POLICY.md) und der
[private Export-/Taint-Nachtrag](E8_REVIEW_FOLLOWUP.md) definieren die
jeweiligen Prüfgrenzen.

## Weitere Abdeckungsgrenzen

- OpenSSL selbst, spätere Paketierung, Modulbindung und Host-Konfiguration
  waren nicht geprüft. Die aktuellen N2-Runner-/Konfigurationsgeneratorquellen
  lagen nicht im Scan-Kontext.
- Ein Durchlauf erhielt Architekturhinweise, aber keine abschließende
  strukturierte Unterreview-Übergabe; der Elternreviewer schloss diesen Teil ab.
- Das originale Coverage-JSON meldet `completeness=complete`, enthält jedoch
  leere `surfaces`-/`deferred`-Listen. Bericht und `sourceCoverage` behalten
  offene Fragen und partielle Abdeckung bei; der Status schließt sie nicht.
- Das Ergebnis ist kein universeller Constant-Time-/Löschungsbeweis und keine
  erneute mathematische oder plattformübergreifende Freigabe.

## Abschlussabgleich

Erneut hashgeprüft wurden die 45 Zielquellen, sechs E8-ELFs samt sechs
Disassemblierungen, beide E8-Followup-Receipts sowie beide N2/N4-Codegen-
Receipts einschließlich ihrer Memberhashes. Die übernommenen Scanartefakte
wurden mit dem abgeschlossenen lokalen Paket verglichen; alle waren identisch.
Es gab dabei keine neuen Laufzeit-, Timing- oder Codegen-Ergebnisse.

Die Receipt-Pfade und Bindungen stehen im
[E8-Followup-Index](E8_REVIEW_FOLLOWUP_INDEX.json) und
[N2/N4-Index](../phase-d/d2/N2_N4_EVIDENCE_INDEX.json).
[SECURITY_DEEP_REVIEW_CLOSURE_SHA256SUMS](SECURITY_DEEP_REVIEW_CLOSURE_SHA256SUMS)
bindet diese redaktionelle Fassung und die unveränderten Originalartefakte;
die ursprüngliche Zusammenfassung und ihr Manifest bleiben in Commit `1ebf575`.

Aktueller Paketstatus: [Fedora-45-Kandidaten](../packaging/fedora/README.md).
Die bestehende Gate-E-Entscheidung bleibt an ihre ursprünglichen Quellen und
Binärdateien gebunden.
