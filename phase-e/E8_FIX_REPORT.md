# E8d/E8e: Befundbezogener Reparaturnachweis

Ergebnis: **fixed** für die benannten Besitzer- und Parametergrenzen,
keine Behauptung eines zuvor beobachteten Schlüsselleaks. Der Status gilt
für den nachstehend gebundenen lokalen x86-64-Stand und die geprüften ABIs,
nicht als externe Gate-E- oder Produktfreigabe.

## Grenze, Strategie, legitimes Verhalten

E8d: Der Rückweg der Festbasismultiplikation ließ benannte
geheimnisabhängige Projektivpunkte außerhalb eines Löschbesitzers;
die Encoder-Inverse hatte dieselbe Eigentumslücke. Das ist eine
fehlende Zeroisierungszusage, kein nachgewiesener Speicherleseangriff.
Die engste vollständige Reparatur verwendet vorhandene Zeroizing-Muster
an den tatsächlichen Besitzern und borgende Encoderzugriffe. Normale
Kodierung, Signaturbytes, Fehler und Unwind müssen erhalten bleiben.

Geänderte Laufzeitdateien:
/home/martin/Dokumente/ED301/ed301/rust/crates/ed301-eddsa/src/signature.rs
/home/martin/Dokumente/ED301/ed301/rust/crates/ed301-eddsa/src/edwards.rs
/home/martin/Dokumente/ED301/ed301/rust/crates/ed301-eddsa/src/field_5x64.rs

E8e: EdDSA-Parameterparser sowie X301-Exchange-/Hybrid-KEM-Init verwarfen
unbekannte Metadaten zusammen mit echten unerlaubten Modi. Die Reparatur
liegt an den vorhandenen gemeinsamen Parsergrenzen: unbekannte Schlüssel
ignorieren, erkannte nicht unterstützte Betriebsarten explizit ablehnen,
Context/TLS-Prüfung, Duplikatregeln und atomare Übernahme beibehalten.
Das ist dokumentierte Provider-Konformität, keine Authentifizierungsumgehung.

Geänderte Laufzeitdateien:
/home/martin/Dokumente/ED301/ed301/provider/crates/ed301-eddsa-provider/c/provider_shim.c
/home/martin/Dokumente/ED301/ed301/provider/crates/x301-provider/c/provider_shim.c
/home/martin/Dokumente/ED301/ed301/provider/crates/x301-provider/c/hybrid_kem.c

## Geordnete Validierung

1. Quellgrenzen, direkte Aufrufer, Rück-/Fehlerwege und bestehende Tests
   wurden vor der Reparatur untersucht. Der fix-finding-Ablauf ergänzte
   eine unabhängige Nur-Lese-Untersuchung und genau eine unabhängige
   Kandidatenprüfung nach den fokussierten Tests. Der bestätigte
   Nachweisfehler bei aktuellen Provenienzpaketen wurde behoben und
   mit einer isolierten Gegenprobe abgesichert. Keine zweite Reviewrunde.
2. Syntax/Build/Lints: cargo fmt --check, cargo clippy --all-targets
   --all-features -- -D warnings, gebundene Release-Builds und no_std-
   Consumer bestanden. Die genauen Manifeste, Umgebungen und Befehle
   stehen unverändert in den commands.json der Receipts.
3. Stärkster fokussierter Eigentumsnachweis statt eines nicht belegten
   Datenleaks: returned_fixed_base_points_zeroize_on_return_and_unwind
   und encoding_inverse_owner_zeroizes_on_return_and_unwind bestehen.
   Sie beobachten den gelöschten tatsächlichen Payload des benannten
   Besitzers auf normalem Rückweg und bei kontrolliertem Unwind nach
   Rückkehr aus der Festbasismultiplikation. Nachfolgendes legitimes
   Signieren funktioniert weiter; bytegleiche Vektoren bleiben erhalten.
4. Parametergegenbeispiel: gültiger Context plus unbekannter Schlüssel
   funktioniert nun durch den tatsächlichen Provider; unbekannte Werte
   werden nicht interpretiert. Weitere Typ-/Reihenfolge-/Duplikat-
   und unerlaubte Modusfälle erhalten strikte Ablehnung. X301-Raw und
   Hybrid-KEM werden jeweils über ihre tatsächliche Init-Grenze geprüft.
5. Legitimität und Paketgates: beide ABIs bestehen vollständige
   Funktions-/CLI-/TLS-/Vertrags-/Speicher-/Taintprüfungen. Die zusätzlichen
   E8c-Tests prüfen fehlbare Allokation und Wiederholung, Mutex-Poisoning,
   konkurrierende Wiederverwendung, Public-only-Duplikate und erhaltene
   Schlüssel-Snapshots. Alle alten benannten Kernprüfungen bleiben.

Fokussierte Testdateien:
/home/martin/Dokumente/ED301/ed301/provider-tests/provider_signature.c
/home/martin/Dokumente/ED301/ed301/provider-tests/provider_shim_unit.c
/home/martin/Dokumente/ED301/ed301/provider-tests/provider_hardening.c
/home/martin/Dokumente/ED301/ed301/provider-tests/x301/provider_x301_contract.c
/home/martin/Dokumente/ED301/ed301/provider-tests/x301/provider_x301_hybrid_contract.c
/home/martin/Dokumente/ED301/ed301/provider/crates/ed301-eddsa-provider/src/sig_ffi.rs

## Befehle und Artefakte

Die volle Kernprüfung wurde mit check_core_correctness.py --baseline
und --previous auf unveränderten Vergleichsquellen ausgeführt; PASS
65/57 aktuelle Tests, jeweils auch im Feature-Lauf. Vollständiger Befehl:
/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e8_optionc_candidate_07_2026-09-10/ED301-v2_PHASE_E_core-check_5qb51d3e/commands.json

Je ABI wurden run_functional.py, run_memory.py, run_cli.py, run_tcp.py,
run_controls.py und die strukturierte Vertragswiederholung mit
--source-sha 1b9e7aecf9d69b1a5b38cf5b81f12b399b951770d99b03ac2fe77d0c1f8fde35 und den jeweiligen gebundenen Functional-Receipts
ausgeführt. Die Ergebnisverzeichnisse enthalten unveränderte Befehle,
native Testlogs und Hashmanifeste; nicht nur zusammengefasste PASS-Wörter.

/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e8_final_01_2026-09-10
/home/martin/Dokumente/ED301/ed301/phase-e/E8_EVIDENCE_INDEX.json

Neue E8a-Grenzprüfung: run_import_boundary_taint.py, drei kontrollierte
Valgrind-Läufe, PASS; definierte legitime Eingaben vor/nach gezielter
Ablehnung synthetischer geheimer Shadow-Bits. Das ist eine Diagnose-
Build-Prüfung, keine Eingabevalidierungsgarantie im Ordinary-Build.

## Unsicherheit

Die Eigentumslücke wurde durch bewachte benannte Werte geschlossen und
dynamisch auf Rück-/Unwindwegen geprüft. Keine Rekonstruktion eines
privaten Schlüssels, kein Auslesen fremden Speichers und kein Exploit
war Bestandteil der Untersuchung. Keine Zusage, dass der Compiler
überhaupt keine zusätzlichen temporären Kopien erzeugt.

ASan/UBSan erfassen die nativen C-Teile; Memcheck den Gesamtprozess.
Timing/Codegen/Taint sind begrenzte komplementäre Beobachtungen, keine
universellen Seitenkanalbeweise. Nicht-x86-64-Plattformen, öffentliche
Archivverfügbarkeit und externe Reviewakzeptanz bleiben außerhalb dieses
lokalen Reparaturnachweises.
