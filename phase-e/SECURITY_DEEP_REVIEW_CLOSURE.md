# Deep-Security-Review: Abschluss und Einordnung

Stand: 11. September 2026. Geprüfter Quellcommit auf Testing:
`ddc6e5d33e6b4b4e3fe7665355eab1ce2145e70b`.

Ergebnis: Vier unabhängige vollständige Standard-Scan-Workflows wurden zu
einem Deep-Scan-Ergebnis zusammengeführt. Keine berichtspflichtige
Schwachstelle wurde bestätigt. Die Prüfung war statisch; offene
Löschungsfragen bleiben offen. Dieser Dokumentationsabschluss ist weder ein
neues Gate E noch eine Produktions-, RPM- oder Aktivierungsfreigabe.

Martin hat anschließend den Review-Abschluss, den gezielten Abgleich mit
vorhandenen Nachweisen und den Push des abgeschlossenen Stands auf Testing
autorisiert. Keine Implementierungsänderung, neue Optimierung, Installation,
Aktivierung, Release-Veröffentlichung, Signatur oder Änderung von Review/main
ist Bestandteil dieses Schritts.

## 1. Exakter Scanumfang und Quellenbindung

Die drei alleinigen Quellziele waren:

- /home/martin/Dokumente/ED301/ed301/provider
- /home/martin/Dokumente/ED301/ed301/rust/crates/ed301-eddsa
- /home/martin/Dokumente/ED301/ed301/rust/crates/x301

Der Scanner erhielt einen getrennten, schreibgeschützten 45-Dateien-Snapshot
mit den ursprünglichen relativen Pfaden, ohne Original-Git-Historie oder
Remotes:
/home/martin/Dokumente/ED301/ED301_SECURITY_DEEP_ddc6e5d_2026-09-11/target

Das Basisverzeichnis /home/martin/Dokumente/ED301 und der übrige Repository-
Baum waren keine Scan-Ziele. Die separat bereitgestellten 1660 Kontextdateien
lieferten nur passende Abhängigkeiten, Spezifikationen und Tests, keinen
zusätzlichen Auditauftrag. Der Scan war offline; keine URL-Abfragen,
Produktivdaten oder fremden Endpunkte gehörten dazu.

| Bindung | Wert |
| --- | --- |
| Originalcommit | `ddc6e5d33e6b4b4e3fe7665355eab1ce2145e70b` |
| Originalbaum | `fe2b976a2472fd3298356a19ba5f941b3e391339` |
| Synthetischer Snapshotcommit | `bedcd26eaec73883c8b2d17a67bdb7288dccbdc9` |
| Scan-ID | `119d3788-07ba-4553-a232-fd785bb38dd5` |
| Werkzeug | Codex Security Plugin 0.1.24, Deep Scan |
| Abschluss (UTC) | `2026-09-11T10:32:39.593356Z` |
| Zielmanifest SHA-256 | `22399e7a8937838893a7bec655c9196bd49c0ec9bac8e1e27fa0b9de0cc382a3` |
| Kontextmanifest SHA-256 | `7bbcf0b69bb7ba9599f9349b03535731a26485b5e21af3a357284e1b818edf2e` |
| Originalbericht SHA-256 | `437a816abcc5bd0e45e512351be4c92048acd105b6e6d424cc3864e3c0c9824f` |

Alle 45 Zielhashes stimmen beim Abschlussabgleich auch mit dem ursprünglichen
Checkout überein. Die beiden Rust-Kerne sind gegenüber dem E8-Commit
`a81eeb526579c6e8066183919a7e488bb56eeba7` unverändert. Die Namensänderung
verändert dennoch die Provider-Artefakte; historische Binäradressen oder
Binärhashes werden deshalb nicht auf die neuen DSOs übertragen.

## 2. Originalergebnis und seine Grenzen

Bericht, Scanmanifest, Findings, Coverage und SARIF sind bytegleiche Kopien
der vom Plugin abgeschlossenen Artefakte, keine neu erzeugte oder korrigierte
Scan-Auswertung. Sie liegen mit den Quellenbindungsmanifesten unter:
/home/martin/Dokumente/ED301/ed301/phase-e/reference/security_deep_ddc6e5d

Originalbericht:
[/home/martin/Dokumente/ED301/ed301/phase-e/reference/security_deep_ddc6e5d/report.md](reference/security_deep_ddc6e5d/report.md)

Die vier Standard-Durchläufe sind in der sourceCoverage-Liste des
Scanmanifests identifiziert. Die dokumentierte Quellprüfung umfasst alle
45 Dateien einschließlich beider Implementierungen und Provider. Builds,
Unit-/Vektortests, Timingmessungen und aktuelle Maschinencodeprüfungen wurden
im Scan nicht ausgeführt; die Worker meldeten ein nur lesbares Dateisystem.
Ein vollständiger Workflow ist daher kein vollständiger Sicherheitsbeweis.

Materielle Einschränkungen bleiben erhalten:

- Die Löschung interner geheimnisabhängiger Zwischenwerte ist nicht umfassend
  geklärt. Es wurde kein angreiferlesbarer überlebender Speicherinhalt mit
  nachgewiesenem Vertraulichkeitsverlust etabliert.
- Die delegierte OpenSSL-Implementierung und die tatsächliche spätere
  Paketierung, Modulbindung und Host-Konfiguration waren nicht geprüft.
- Die aktuellen N2-Runner-/Konfigurationsgeneratorquellen lagen nicht im
  Scan-Kontext. Ihre separat vorhandenen Integrationsergebnisse sind keine
  unabhängigen Scan-Ergebnisse.
- Ein Standard-Durchlauf erhielt Architekturhinweise, aber nicht die
  abschließende strukturierte Übergabe seines Architektur-Unterreviewers;
  der jeweilige Elternreviewer schloss diesen Teil selbst ab.
- Der Scan begründet weder universelle Constant-Time-/Löschungszusagen noch
  eine erneute mathematische Kurvenfreigabe oder eine andere Plattformfreigabe.

Werkzeugbeobachtung: Das originale Coverage-JSON meldet completeness=complete,
enthält aber leere surfaces/deferred-Listen. Der Originalbericht und die
sourceCoverage-Angaben behalten zugleich offene Kandidaten und partielle
Absicherung bei. Das maschinelle complete wird hier ausdrücklich NICHT als
Schließung dieser Fragen interpretiert. Die Originalartefakte werden nicht
nachträglich verändert; dieser getrennte Nachtrag hält die Diskrepanz fest.

## 3. Gezielter Abgleich der Löschungsfrage

Dieser Abgleich verwendet den unveränderten aktuellen Quelltext, bestehende
Prüferregeln und erneut hashgeprüfte historische Belege. Er ist keine neue
Vulnerabilitätsreproduktion, kein weiterer Scan und kein neuer Laufzeit-PASS.
Die folgenden Beobachtungen werden thematisch eingeordnet, nicht ohne Beleg
zu einem einzigen identischen Fehler zusammengelegt.

| Beobachtung | Was die vorhandenen Nachweise abdecken | Was offen bleibt |
| --- | --- | --- |
| Inversions-/Konvertierungsbrücke | Der zurückgegebene Encoder-Inversenbesitzer und die bewachten X301-Ergebnisse sind explizit geschützt; der Codegen-Gate prüft begrenzte Kontrollfluss-/Aufrufeigenschaften. | Innere Copy-Werte wie oracle/inverse/converted sowie Konvertierungspuffer werden dadurch nicht sämtlich als gelöscht bewiesen. |
| Optionaler sign-self-verify-Untergruppencheck | Der äußere zurückgegebene Public-Punkt hat einen Löschbesitzer; der Sparse-Check benutzt öffentliche feste Schleifensteuerung. | Sein eigener lokaler accumulator hat keinen eigenen Löschbesitzer. Fester Kontrollfluss ist kein Nachweis über dessen spätere Speicherreste. |
| X301-Leiter und gemeinsame Edwards-/Feldhelfer | LadderState, ProjectiveOutput und benannte Rückgabebesitzer sind bewacht; vorhandene Tests und Regeln prüfen jeweils ihre angegebenen Grenzen. | Weitere lokale Rechenwerte und Kopien dieser Helfer haben nicht allein durch den äußeren Besitzer eine eigene Löschgarantie. |
| Private Export-/DER-Taint-Läufe | Sie beobachten Geheimnis-Markierungen, relevante datenabhängige Nutzung und die Trennung vom öffentlichen Importpfad in den ausdrücklich getesteten Wegen. | Sie sind kein vollständiger Speicherresttest nach Funktionsende und widerlegen die vorstehenden Löschungsfragen nicht. |

Die Unterscheidung ist nicht nur eine allgemeine Warnung vor unsichtbaren
Compilerkopien: Im Quelltext existieren auch benannte innere Copy-Lokale ohne
individuelle Löschbesitzer. Ob und wo diese in einem bestimmten optimierten
Artefakt physisch überleben und unter welchen zusätzlichen Voraussetzungen
ein Geheimnis offengelegt werden könnte, ist damit noch nicht beantwortet.

Disposition: Quellenbeobachtung erhalten; tatsächlicher Vertraulichkeitsverlust
nicht nachgewiesen; weder als bestätigte Schwachstelle noch als widerlegt oder
behoben kennzeichnen. Eine spätere eng begrenzte Binär-/Lebensdauerprüfung
müsste an genau benannten Auslieferungsartefakten ansetzen. Sie gehört nicht
zu diesem Dokumentationsabschluss. Eine pauschale Zusage, sämtliche geheimen
Zwischenwerte seien gelöscht, darf aus den bisherigen PASS-Werten nicht
abgeleitet werden.

Gezielt abgeglichene Quellstellen (Zeilen des geprüften Commits):

- /home/martin/Dokumente/ED301/ed301/rust/crates/ed301-eddsa/src/field_5x64.rs:191
- /home/martin/Dokumente/ED301/ed301/rust/crates/ed301-eddsa/src/field.rs:62
- /home/martin/Dokumente/ED301/ed301/rust/crates/ed301-eddsa/src/field.rs:87
- /home/martin/Dokumente/ED301/ed301/rust/crates/ed301-eddsa/src/edwards.rs:190
- /home/martin/Dokumente/ED301/ed301/rust/crates/ed301-eddsa/src/edwards.rs:508
- /home/martin/Dokumente/ED301/ed301/rust/crates/ed301-eddsa/src/edwards.rs:617
- /home/martin/Dokumente/ED301/ed301/rust/crates/ed301-eddsa/src/signature.rs:516
- /home/martin/Dokumente/ED301/ed301/rust/crates/x301/src/x301.rs:257
- /home/martin/Dokumente/ED301/ed301/rust/crates/x301/src/x301.rs:280
- /home/martin/Dokumente/ED301/ed301/rust/crates/x301/src/x301.rs:461

Die vorhandene begrenzte E8-Binärinspektion nennt die ausgeschlossenen
Rückgabepuffer, Register und Spillkopien bereits ausdrücklich:
[/home/martin/Dokumente/ED301/ed301/phase-e/E8_NAMED_OWNER_BINARY_AUDIT.md](E8_NAMED_OWNER_BINARY_AUDIT.md)

Weitere abgeglichene Nachweise und Regeln:

- /home/martin/Dokumente/ED301/ed301/phase-e/CODEGEN_POLICY.md
- /home/martin/Dokumente/ED301/ed301/phase-e/tools/codegen_ed.sh
- /home/martin/Dokumente/ED301/ed301/phase-e/tools/codegen_x.sh
- /home/martin/Dokumente/ED301/ed301/phase-e/tools/check_codegen_dataflow.py
- /home/martin/Dokumente/ED301/ed301/phase-e/E8_REVIEW_FOLLOWUP.md
- /home/martin/Dokumente/ED301/ed301/phase-e/E8_REVIEW_FOLLOWUP_INDEX.json
- /home/martin/Dokumente/ED301/ed301/phase-d/d2/N2_N4_EVIDENCE_INDEX.json

## 4. Tatsächlich ausgeführte Abschlussprüfungen

- Alle 45 Zielquellen gegen das Scan-Zielmanifest geprüft; identisch.
- Beide Rust-Kerne gegen a81eeb5 verglichen; keine Änderung.
- Alle sechs im E8-Named-Owner-Audit genannten ELF-Eingaben und alle sechs
  zugehörigen Disassemblierungen erneut gegen ihre dortigen SHA-256-Werte
  geprüft; identisch. Die Inspektion selbst wurde nicht als neuer Binär-Gate
  wiederholt oder auf andere Artefakte ausgeweitet.
- Beide E8-Followup-Receipts sowie beide N2/N4-Codegen-Receipts einschließlich
  ihrer Memberhashes erneut geprüft; identisch. Die gespeicherten PASS-Werte
  bleiben historische Ergebnisse ihrer gebundenen Läufe.
- Die fünf übernommenen kanonischen Ergebnisartefakte und drei
  Quellenbindungsdateien bytegleich mit dem abgeschlossenen lokalen
  Scanpaket verglichen. Das Originalpaket bleibt unverändert.
- Keine Builds, Timing-/Taint-Neuläufe, Quellreparaturen oder Änderung der
  Codegen-Allowlists in diesem Abschluss.

| Erneut geprüfter Receipt | SHA-256 des Receipt-Manifests |
| --- | --- |
| E8-Followup 3.5.8 | `1872b154b4643bf258e9d2effd958ea0a7e423b6862d84296e5a103575a266ce` |
| E8-Followup 4.0.2 | `fdf6c8d3e95d1efac3ef643ac444055c6269432e19dde9209953ccafcd79874a` |
| N2/N4-Codegen 3.5.8 | `304a510f3c95ca10e9715a1d6e7f5fff68990a52a54894526a14074a7ac81449` |
| N2/N4-Codegen 4.0.2 | `28a436eb9f13e735d9cfa400c471e2fa91196cb6c65b0b135142e039b7c1266c` |

Die Receipt-Verzeichnisse stehen in den oben genannten, unveränderten
Evidenzindizes. Dies ist eine veröffentlichbare Ergebnis-/Quellenbindung,
kein vollständiges neu zusammengestelltes Runtime- oder Worker-Archiv.

Ein zusätzliches Manifest bindet diesen Nachtrag, den README-Verweis und die
neun übernommenen beziehungsweise ausdrücklich als Auszug gekennzeichneten
Referenzdateien (Pfade relativ zur Repository-Wurzel; ohne Selbsthash):
/home/martin/Dokumente/ED301/ed301/phase-e/SECURITY_DEEP_REVIEW_CLOSURE_SHA256SUMS
Es ersetzt keine historischen Quell- oder Scanmanifeste.

## 5. Abschlussmetadaten und weiterhin getrennte Freigaben

Der separat gekennzeichnete Auszug aus der erfolgreichen Abschlussantwort
enthält vier abgeschlossene unabhängige Reviews, null Findings und die
gemessene Nutzung:
/home/martin/Dokumente/ED301/ed301/phase-e/reference/security_deep_ddc6e5d/SCAN_COMPLETION_EXCERPT.json

Das Plugin meldet 134574808 Tokens insgesamt, davon 134119883 Eingabe und
454925 Ausgabe. In der Eingabe sind 128381568 gecachte Tokens enthalten.
Das sind vollständig erfasste Werkzeug-Nutzungsdaten, keine Kostenrechnung
und kein Maß für die Sicherheitsabdeckung. Die Scan-Metadaten nennen
gpt-6-astra/xhigh; daraus wird kein bestimmtes Modell für jeden Worker
abgeleitet.

Die vier E8-Nacharbeiten, die N4-Umbenennung und die prozesslokalen N2-Prüfungen
sind getrennt dokumentiert und werden nicht erneut als unerledigt geführt.
N5 ist im Integrationsvertrag beschrieben. Aussagen wie „kein Deep Scan
gestartet“ in den früheren Vorbereitungsberichten beschreiben deren damaligen
Stand; sie werden nicht rückwirkend umgeschrieben.

Gate E bleibt die bestehende gebundene Prüferentscheidung. Dieser Abschluss
erteilt keine weitergehende Freigabe. Für Stufe 2 fehlen weiterhin Martins
gesondertes Go und die Prüfung der tatsächlichen RPM-Installation,
Aktivierung, v1/v2-Ablösung und Rückkehr zum vorherigen Stand. N2 ist nach
Paketinstallation erneut zu prüfen. Diagnose-/Failpoint-Varianten dürfen
nicht durch eine unkontrollierte Feature-Kombination als normale
Auslieferungsartefakte behandelt werden; der Scan hat die spätere
Paketierung nicht abgenommen. Review, main, Tags und Signierschlüssel bleiben
unberührt.
