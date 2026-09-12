# Nacharbeiten am Prüfwerkzeug

Stand: 12. September 2026. Ausgangspunkt: Testing `27ee0e9` und der
[externe Follow-up-Review](../phase-e/reference/followup_20260912/ED301-FOLLOWUP-REVIEW-20260912.md)
zu Review `5f446b4`. Die Befunde betreffen Prüfabdeckung, keine bestätigte
Fehlfunktion der Kryptokerne. Kurve, Kryptologik, Schlüsselakzeptanz und
öffentliche API-Verträge bleiben unverändert.

## Änderungen

- T1: Gemeinsame Auflösung von Aufrufen und externen Tail-Transfers für alle
  drei Aufrufprüfer. Interne Sprünge müssen auf einen Befehlsanfang derselben
  Symbolinstanz zeigen. Unaufgelöste Ziele scheitern an der Callee-Policy.
- T2: Jede der zwei 38-Byte-Löschfunktionsinstanzen muss alle Besitzerbytes
  mit Null überschreiben. X301 bindet zusätzlich die Zeiger für den ersten
  Besitzer sowie den zweiten Besitzer im Normal- und Landing-Pad-Pfad.
- T3: Importierte X301-Kopien behalten ihre eingehende Geheimmarkierung;
  die Instrumentierung markiert weiterhin frische RNG-Ausgaben. Der Harness
  vergleicht beim privaten Export sämtliche Shadow-Bytes mit dem Eingang und
  prüft die DH-Ausgabe modusabhängig. RNG-basierte Hybridoperationen bleiben
  in beiden Modi getrennt markiert.
- Die Compilerprüfung verlangt den aufgezeichneten Rust-1.98.0-/LLVM-21.1.8-
  x86-64-Marker ohne fehlende oder doppelte Pflichtfelder. Zwei veraltete
  Quellkommentare sind bereinigt.

Die engste gemeinsame Grenze ist jeweils das Prüfwerkzeug beziehungsweise
die Import-Instrumentierung. Insbesondere wurden keine kryptografischen
Prüfungen entfernt und keine LLVM-22-Lowering-Formen freigegeben.

## Patch-Review und Prüfung

Ein getrenntes Patch-Review fand noch zwei Fehler in der ersten Fassung der
Registerherkunftsprüfung: übersprungene Ladebefehle und Teilbreiten-Ladevorgänge.
Die Korrektur verlangt vollständige Zeigerladungen auf allen betrachteten
direkten Kontrollflusspfaden. Zusätzliche Textfixtures prüfen diese Fälle,
zulässige Schleifen und beidseitige Verzweigungsursprünge. Die Korrekturen
wurden anschließend lokal geprüft; ein zweites unabhängiges Patch-Review
wurde nicht durchgeführt.

| Prüfung | Ergebnis |
| --- | --- |
| Parser-/Lösch-/Zeigertests | 18 Tests bestanden |
| Werkzeug-/Compiler-Vorprüfung | 7 Tests bestanden |
| Frische funktionale Provider-Abnahme | 139 Schritte je OpenSSL-Version bestanden, einschließlich 20 + 7 Rust-Tests |
| Reproduzierbare Provider-Builds | Vier Ordinary-/TLS-Module je ABI bytegleich erneut gebaut |
| Speicher-/Taint-Controller | 107 Schritte je ABI bestanden; darunter je 22 C-ASan/UBSan- und 22 Whole-Process-Memcheck-Aufrufe |
| Abschließende Codegen-Prüfung | Acht frische Provider-DSOs und zehn erhaltene Review-ELFs bestanden |
| Abschließende X301-Taint-Prüfung | Defined/Tainted je ABI erneut bestanden, zwei Positivkontrollen erkannt |
| Fehlerweitergabe des Codegen-Treibers | Erwartete Ablehnung des Dataflow-Prüfschritts weitergegeben |

Geprüft auf x86-64 mit Rust 1.98.0, LLVM 21.1.8, Valgrind 3.27.1 und den
hashgeprüften OpenSSL-Lanes 3.5.8 und 4.0.2. Die OpenSSL-Abhängigkeiten wurden
aus ihren authentifizierten Eingaben kopiert, nicht neu kompiliert.

`run-01` enthält die frischen Provider-/Speicherläufe. `run-02` enthält die
abschließende Werkzeugfassung nach dem Patch-Review. Dazwischen blieben alle
1.727 verglichenen Build-, Harness- und Controllerdateien bytegleich;
der gemeinsame Build-Quellhash bindet die weiterverwendeten frischen Binaries.
Maßgeblich für die neuen Codegen-Regeln ist `run-02/final-validation`.
Der [Evidenzindex](TOOLING_FOLLOWUP_20260912.json) enthält die Hashes.

## Archivkorrektur und Grenzen

Das ursprüngliche externe Archiv bleibt unverändert. Eine gesonderte Fassung
ergänzt vier im Quellmanifest aufgeführte `cc`-Vendorquellen aus dem gebundenen
Review-Commit. Alle 1.992 Quelldateien stimmen nun mit dem Manifest überein;
die bisherigen 6.522 regulären Dateien und sechs Verknüpfungen sind unverändert.
Das bleibt ein Belegarchiv, kein ohne Konfiguration umziehbares Replay-System.

Nicht neu durchgeführt: Timing-Messreihen, mathematische Zertifikatserzeugung
oder Fedora-RPM-Abnahme. Die Löschprüfung erfasst die benannten Funktionen
und X301-Besitzerpfade, nicht sämtliche Aufrufstellen, Exception-Tabellen,
Register-/Stackkopien oder physische Löschung im Gesamtprozess. Die bestehende
PBES2-Passwortkosten-Grenze und die separate Anforderung vertraulicher
öffentlicher Schlüssel bleiben unverändert.
