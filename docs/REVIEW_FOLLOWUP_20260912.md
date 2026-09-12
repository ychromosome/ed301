# Nacharbeiten zum Review vom 12. September 2026

R1–R7 aus dem [Originalreview](../phase-e/reference/review_20260912/ED301-Review-20260912.md)
zu Commit `e959518` sind umgesetzt und funktional geprüft. Ausgangspunkt auf
Testing ist `5a6c84b`. Kurvenparameter, Rust-Kryptologik, DRBGs und
`Shared<T>` bleiben unverändert.

## Änderungen

| Befund | Umsetzung |
| --- | --- |
| R1 | [Aktueller Profilvertrag](../specifications/CURRENT_PROFILE.md) mit Vorrangregel; historische Spezifikationen bleiben bytegleich. Aktive Crate-Texte enthalten keine überholten Gate-Aussagen. |
| R2 | Python und Node prüfen wie Rust zuerst das Secret. Ein gemeinsamer Korpus prüft 39 Fehlerkombinationen in allen drei Sprachen. Alte Vektoren bleiben unverändert. |
| R3 | Beide Decoderdiagnosen verwenden den algorithmusspezifischen Anzeigenamen; Tests prüfen die ausgegebene Fehlerkennung. |
| R4 | Korrigierte Notices und [maschinell abgeleitetes Cargo-Inventar](DEPENDENCIES.md); `cc` ist Build-Abhängigkeit, `getrandom`/`r-efi` sind nur noch enthaltene Vendorquellen. |
| R5 | [Portabler Integrationsvertrag](INTEGRATION.md) mit relativen Verweisen und klaren DSO-/Anwendungsgrenzen. |
| R6 | Gemeinsame Build- und OSSL_PARAM-Helfer; die bisherigen Prüffunktionen bleiben inhaltlich gleich. |
| R7 | Funktionsbezogene Crate-, Provider- und Codec-Texte; technische Invarianten und Diagnosevarianten bleiben gekennzeichnet. |

Der aktuelle Integrationsvertrag erklärt außerdem Nested Properties,
unterschiedliche Versionsguards, Hybrid-only-Auswahl und die noch offene
Passwortkostenpolitik. Die vorhandenen RPM-Eingaben bleiben auf ihren älteren
Kandidaten festgelegt; sie enthalten diese Nacharbeiten noch nicht.

## Frische Prüfung

Ein unveränderlicher Snapshot mit 1990 Dateien wurde für die abschließenden
Läufe verwendet. Hashes und Receipt-Verzeichnisse stehen im
[Evidenzindex](REVIEW_FOLLOWUP_20260912.json). Bericht und Index wurden erst
nach den Läufen ergänzt und gehören nicht zu deren Quellmanifest.

| Prüfung | Ergebnis |
| --- | --- |
| Ed301-Kern | 65 Tests, zusätzlich 65 mit Self-Verify |
| X301-Kern | 58 Tests, zusätzlich 58 mit Taint-Feature |
| Historische Testnamen, Parameter, Feldschranken, Vendor, Clippy, Formatierung, no_std-Verbraucher | PASS |
| Historisches Phase-B-Replay | 8/8; gegen die historische Quelle |
| Aktuelle Referenzen | 30 Python-Tests; beide Node-Vektorprüfer und neuer Prioritätsprüfer bestanden |
| Provider je OpenSSL 3.5.8 / 4.0.2 | 20 Ed301- und 7 X301-Rusttests; neun Varianten; vier bytegleiche Wiederholungsbuilds; 139 Controller-Schritte |
| Stock-CLI je OpenSSL-Version | 48 Schritte bestanden, nur prozesslokale Aktivierung |
| TLS/TCP je OpenSSL-Version | 95 bestanden, 0 fehlgeschlagen |
| Build-Helfer | Drei Regressionstests mit 39 Unterprozessen; beide bisherigen Funktionskörper unverändert übernommen |
| Parameterhilfen | Alle neun bisherigen Funktionskörper nach Namensnormalisierung gleich; C-Vertragstest auf beiden ABIs bestanden |
| Dokumentation | Fünf Kennungen gegen generierte Header und 54 lokale Links geprüft; Cargo-Inventar aktuell |

Die beiden generierten X301-C-Header und alle 802 Provider-Vektorfälle sind
zum bisherigen E8-Satz identisch; nur die Quellenbindung im JSON wurde
aktualisiert. Elf zusätzliche Quellenbindungs-Kontrollen akzeptieren genau
die Referenz-Umordnung und verwerfen fremde Änderungen.
Der neue X301-Decodertest erkennt mit den alten N2/N4-Modulen zwölf falsch
benannte Diagnosen; mit den neuen Modulen besteht er auf beiden ABIs.

Die ersten Provider-Vorprüfungen verwarfen den alten Referenzhash im Generator.
Die TCP-Sandboxversuche scheiterten am Socket-Verbot; dieselben gebundenen
Programme bestanden anschließend mit eigenen Loopback-Verbindungen außerhalb
der Sandbox. Diese Fehlversuche bleiben getrennte Protokolle.

## Weiter offen

- Neue Fedora-RPMs: korrigierten Quellstand wählen und den Buildflags-Patch
  auf den gemeinsamen Helfer anpassen; anschließend neue Binärabnahme.
- Vollständige Codegen-/Timing-/Taint-Prüfung und Untersuchung verbleibender
  geheimer Speicherkopien an den tatsächlichen Auslieferungsdateien.
- Isolierte Miri-/Nebenläufigkeitsprüfung von `Shared<T>`.
- Kalibrierte, konfigurierbare Passwortkosten für dauerhafte Schlüsselablage.

Es wurden keine RPMs installiert oder aktiviert und keine Signierschlüssel
verwendet. Historische Reviews, Kurvenpakete und deren Manifeste bleiben erhalten.
