#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Render receipt-derived Markdown to stdout; never modify evidence or reports."""

import argparse
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from handoff_common import check_members, read_json
from handoff_inputs import SOURCE_SHA, VERSIONS

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--index", type=Path, required=True)
args = parser.parse_args()
index = read_json(args.index)
if index["source_manifest_sha256"] != SOURCE_SHA:
    raise SystemExit("unexpected report source")
for record in [*index["stages"].values(), *index["supplementary"].values()]:
    check_members(Path(record["path"]), "SHA256SUMS", record["manifest_sha256"])
root = Path(index["evidence_root"])
checkout = Path(__file__).resolve().parents[2]


def table(headers, rows):
    result = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    result += ["| " + " | ".join(map(str, row)) + " |" for row in rows]
    return "\n".join(result) + "\n"


def stats(row, divisor=1000):
    return [f"{row[key] / divisor:.6f}" for key in ("median_ns", "stdev_ns", "min_ns", "max_ns")]


def select(version, layer, algorithm, operation):
    return next(row for row in index["benchmarks"][version]
                if (row["layer"], row["algorithm"], row["operation"]) == (layer, algorithm, operation))


target_rows = []
for version in VERSIONS:
    for layer, algorithm, operation in (("Rust-Ed", "Ed301", "sign"), ("Rust-Ed", "Ed301", "verify"),
                                       ("Rust-Ed", "Ed301", "import"), ("Rust-X", "X301", "public"),
                                       ("Rust-X", "X301", "shared")):
        before, after = [select(version, layer, algorithm + "-" + v, operation) for v in ("v1", "v2")]
        delta = 100 * (after["median_ns"] / before["median_ns"] - 1)
        target_rows.append([version, algorithm + " " + operation, f"{before['median_ns']/1000:.6f}",
                            f"{after['median_ns']/1000:.6f}", f"{delta:+.3f}", "ja" if delta < 0 else "nein"])

paired = index["supplementary"]["benchmark-E8"]
paired_rows = []
for api, operation in (("ed", "sign"), ("ed", "verify"), ("ed", "import"), ("x", "public"), ("x", "shared")):
    values = [next(r for r in paired["SUMMARY.json"]
                   if (r["api"], r["operation"], r["version"]) == (api, operation, v))
              for v in ("v1", "before", "after")]
    v1, before, after = [r["median_ns"] for r in values]
    paired_rows.append([("Ed301" if api == "ed" else "X301") + " " + operation,
                        *[f"{r['median_ns']/1000:.6f}" for r in values],
                        f"{100*(after/before-1):+.3f}", f"{100*(after/v1-1):+.3f}"])
counts = index["supplementary"]["core-correctness"]["SUMMARY.json"]["test_counts"]

keygen_rows = []
for version in VERSIONS:
    for layer, algorithm, operation in (("EVP-signature", "Ed301", "keygen"),
                                        ("EVP-XDH", "X301", "derive-steady")):
        values = [select(version, layer, algorithm + "-" + v, operation) for v in ("v1", "v2")]
        keygen_rows.append([version, algorithm + " " + operation,
            *[f"{r['median_ns']/1000:.6f}" for r in values],
            f"{100*(values[1]['median_ns']/values[0]['median_ns']-1):+.3f}"])
faster = sum(row[-1] == "ja" for row in target_rows)
paired_spread = [[("Ed301" if r["api"] == "ed" else "X301") + " " + r["operation"],
                 r["version"], f"{r['stdev_ns']/1000:.6f}"]
                for r in paired["SUMMARY.json"] if r["operation"] in ("sign", "shared")]
report = f"""# E8a–E8e: Abschluss zur unabhängigen Gate-E-Prüfung

Stand: 11. September 2026. Lokale Umsetzung und technische Gates abgeschlossen.
**Gate E ist nicht erteilt.** Claudes unabhängiger Nachtrag und Martins
gesonderte Entscheidung zu Stufe 2 bleiben erforderlich.

## Ergebnis auf allen fünf Kern-Lanes

Unmittelbar gepaarter Vergleich: v1, vorheriger E7-Stand und E8a–E8e,
identischer Harness, CPU 2, neun Rotationen, sechs frisch gebaute Programme.
Mediane von neun Laufmitteln in µs; negative Änderungen bedeuten weniger Zeit.
Keine entfernten Ausreißer, keine Auswahl günstiger Wiederholungen.

""" + table(["Lane", "v1 µs", "E7 µs", "E8 µs", "E8 ggü. E7 %", "E8 ggü. v1 %"], paired_rows) + """
Streuung der besonders nahen Vergleiche, Stichproben-SD in µs:

""" + table(["Lane", "Stand", "SD µs"], paired_spread) + """
Zwei weitere vollständige ABI-Matrizen mit unabhängig neu gebauten
Vergleichsbinaries folgen. Der Rust-Kern ruft selbst kein OpenSSL auf.
Jede Zeile verwendet ihren eigenen v1-Bezug; verschiedene Läufe und
Claudes externe Messungen werden nicht zusammengerechnet.

""" + table(["ABI-Lauf", "Kernoperation", "v1 µs", "E8 µs", "Änderung %", "Median unter v1"], target_rows) + f"""
In {faster} von 10 endgültigen Kernzeilen liegt der Median unter v1.
Das ist weder ein Signifikanztest noch eine allgemeine Laufzeitgarantie.
Ein positiver Restabstand bleibt sichtbar und wird nicht durch das Wort
„Rauschen“ zu einem bestandenen strikten Fünf-Lanes-Ziel umgedeutet.

Die für E8c und E8b wichtigen Provider-Grenzen:

""" + table(["ABI", "EVP-Operation", "v1 µs", "E8 µs", "Änderung %"], keygen_rows) + f"""
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
{checkout / 'phase-e/E8_OPTIMIZATION.md'}

Befundbezogene Prüfungen:
{checkout / 'phase-e/E8_FIX_REPORT.md'}

Ergänzende Inspektion der benannten Löschbesitzer in sechs finalen ELFs:
{checkout / 'phase-e/E8_NAMED_OWNER_BINARY_AUDIT.md'}

Der Signaturvertrag bleibt die kofaktorierte Gleichung: kein zusätzlicher
R-Untergruppentest, kein Verbot von S=0. Gleich große Rohschlüssel erhalten
keinen erfundenen Herkunftstag. Keine Radix-Neuentwicklung, kein Assembler,
keine Clamp-Abkürzung und keine zusätzliche Optimierungsvariante.

## Technische Gates

Kern: {counts['current-ed']} Ed301- und {counts['current-x']} X301-Tests,
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
{root / 'source'}

Quellmanifest SHA-256: {SOURCE_SHA}; {index['source_files']} Dateien.
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
{checkout / 'phase-e/E8_EVIDENCE_INDEX.json'}

Er bindet {len(index['stages'])} ABI-Stages,
{len(index['supplementary'])} Zusatzreceipts und
{len(index['source_snapshots'])} Vergleichssnapshots.
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
"""

fixes = f"""# E8d/E8e: Befundbezogener Reparaturnachweis

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
{checkout / 'rust/crates/ed301-eddsa/src/signature.rs'}
{checkout / 'rust/crates/ed301-eddsa/src/edwards.rs'}
{checkout / 'rust/crates/ed301-eddsa/src/field_5x64.rs'}

E8e: EdDSA-Parameterparser sowie X301-Exchange-/Hybrid-KEM-Init verwarfen
unbekannte Metadaten zusammen mit echten unerlaubten Modi. Die Reparatur
liegt an den vorhandenen gemeinsamen Parsergrenzen: unbekannte Schlüssel
ignorieren, erkannte nicht unterstützte Betriebsarten explizit ablehnen,
Context/TLS-Prüfung, Duplikatregeln und atomare Übernahme beibehalten.
Das ist dokumentierte Provider-Konformität, keine Authentifizierungsumgehung.

Geänderte Laufzeitdateien:
{checkout / 'provider/crates/ed301-eddsa-provider/c/provider_shim.c'}
{checkout / 'provider/crates/x301-provider/c/provider_shim.c'}
{checkout / 'provider/crates/x301-provider/c/hybrid_kem.c'}

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
{checkout / 'provider-tests/provider_signature.c'}
{checkout / 'provider-tests/provider_shim_unit.c'}
{checkout / 'provider-tests/provider_hardening.c'}
{checkout / 'provider-tests/x301/provider_x301_contract.c'}
{checkout / 'provider-tests/x301/provider_x301_hybrid_contract.c'}
{checkout / 'provider/crates/ed301-eddsa-provider/src/sig_ffi.rs'}

## Befehle und Artefakte

Die volle Kernprüfung wurde mit check_core_correctness.py --baseline
und --previous auf unveränderten Vergleichsquellen ausgeführt; PASS
65/57 aktuelle Tests, jeweils auch im Feature-Lauf. Vollständiger Befehl:
{index['supplementary']['core-correctness']['path']}/commands.json

Je ABI wurden run_functional.py, run_memory.py, run_cli.py, run_tcp.py,
run_controls.py und die strukturierte Vertragswiederholung mit
--source-sha {SOURCE_SHA} und den jeweiligen gebundenen Functional-Receipts
ausgeführt. Die Ergebnisverzeichnisse enthalten unveränderte Befehle,
native Testlogs und Hashmanifeste; nicht nur zusammengefasste PASS-Wörter.

{root}
{checkout / 'phase-e/E8_EVIDENCE_INDEX.json'}

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
"""

bench = """# E8: vollständige abschließende Benchmarktabellen

Alle Werte sind frisch auf AMD Ryzen 9 5950X, x86-64, CPU 2 erhoben.
Rust 1.98.0 / LLVM 21.1.8, O3, ThinLTO, CGU1, panic=unwind; v2 durchgehend mit
Overflow-Checks. Der historische X301-v1-Vergleich behält seine ausgewiesene
crypto-bigint-Ausnahme und sein originales C-O0-Profil. Keine Assembler-/SIMD-
Erweiterung; Governor/Boost unverändert. Andere Hostlast ist nicht ausgeschlossen.
Messjobs wurden untereinander seriell ausgeführt.

Median, Stichproben-SD und Min/Max beziehen sich auf neun Laufmittel, nicht auf
Einzelaufruf-Perzentile oder Konfidenzintervalle. Der 128-Fälle-Runner verwendet
100 Aufwärmoperationen, 200-ms-Kalibrierziel und rotierende/wechselnde Reihenfolge.
Die zusätzliche Matrix und die Mikrobenchmarks verwenden unverändert die
100-ms-Methodik von Gate C. Jede Vergleichszeile hat ihren eigenen frisch
gemessenen v1-Bezugswert; ABI-Läufe werden nicht zusammengelegt.

EVP ist die API-Schicht, nicht die Rechenimplementierung. TLS-engine misst
echte TLS-1.3-Zustandsmaschinen über Memory-BIO, vorbereitete SSL_CTX, aber
einschließlich SSL-/BIO-Allokation und Freigabe, ohne Resumption. Das ist keine
TCP-Latenzmessung. Codec-Fälle schließen Context-Konstruktion und Abbau ein;
Objekte sind gültig und neu generiert. X301-v1 hat keine vergleichbaren
persistent-codec- oder Raw-TLS-Lanes; fehlende Verfahren werden nicht erfunden.

Die Tabellen enthalten sämtliche 392 endgültigen Geschwindigkeitsfälle.
Der neue gepaarte 32-Fälle-E8-Vergleich bleibt zusätzlich vollständig im Paket.

"""
for version in VERSIONS:
    record = index["stages"]["benchmarks-" + version]
    bench += f"## Vollständiger ABI-Lauf {version}\n\nReceipt: `{record['path']}`.\n\nSHA-256 des Receipt-Manifests: `{record['manifest_sha256']}`.\n\n"
    bench += table(["Schicht", "Verfahren", "Operation", "Median µs", "SD µs", "Min µs", "Max µs"],
                   [[r["layer"], r["algorithm"], r["operation"], *stats(r)] for r in index["benchmarks"][version]]) + "\n"
for name, title, unit, divisor in (("core-matrix", "Erweiterte Nachrichten-/Context-Matrix", "µs", 1000),
                                   ("core-microbenchmarks", "Arithmetik-Mikrobenchmarks", "ns", 1)):
    record = index["supplementary"][name]
    bench += f"## {title}\n\nReceipt: `{record['path']}`.\n\nSHA-256: `{record['manifest_sha256']}`.\n\n"
    if name == "core-matrix":
        bench += "cold-sign enthält Seedimport und Expansion; prepared-sign/prepared-verify verwenden vorbereitete Schlüssel. import-verify enthält die erneute Public-Key-Prüfung. Nachricht i=(29i+7) mod 256, Context i=(17i+3) mod 256. Kalt bezeichnet den Schlüssel-Lifecycle, keinen geleerten CPU-Cache.\n\n"
        columns = ["Version", "Operation", "Nachricht Byte", "Context Byte"]
        rows = [[r["version"], r["operation"], r["message_bytes"], r["context_bytes"], *stats(r)] for r in record["SUMMARY.json"]]
    else:
        bench += "Identischer privater Harness auf unveränderten Modulquellen, 16 rotierende Operanden und Kopierkontrolle. Loop, Operandenwahl, black_box und Ergebnis-Drop sind enthalten. Kein Produkt-API- oder Seitenkanal-Gate. field-mul-d misst weiterhin den ursprünglichen einzelnen Feldoperator, nicht den algebraischen E5-Gesamtgewinn.\n\n"
        columns = ["Version", "Operation"]
        rows = [[r["version"], r["operation"], *stats(r, divisor)] for r in record["SUMMARY.json"]]
    bench += table(columns + ["Median " + unit, "SD " + unit, "Min " + unit, "Max " + unit], rows) + "\n"

bench += "## Gepaarter E8-Schrittvergleich\n\n"
bench += table(["API", "Version", "Operation", "Median µs", "SD µs", "Min µs", "Max µs"],
               [[r["api"], r["version"], r["operation"], *stats(r)] for r in paired["SUMMARY.json"]]) + "\n"

resources = """# E8: vollständige Ressourcenbeobachtungen

Die Core-Tabellen zeigen Gesamtprozess-High-Water inklusive Runtime, Harness,
Vorbereitung und Selbsttests: keine isolierte Stackgrenze pro Kryptofunktion,
keine Baseline-Subtraktion, kein Worst-Case-Beweis. Massif: heap=no, stacks=yes,
time-unit=B, peak-inaccuracy=0.0, max-snapshots=1000, drei Prozesse mit je zehn
Operationen. Native RSS: GNU time %M ohne Valgrind, neun Prozesse mit je 100
Operationen. Alle auf CPU 2. Kleine RSS-Differenzen sind kein isolierter Beweis
besserer Speicherökonomie. Die 256-KiB-Stack- und berührten 8-MiB-RSS-Kontrollen
wurden frisch gebaut und gemessen. Die X301-Tabelle verwendet exakt die bereits
gemessenen und klassifizierten primären finalen X301-Binaries des 3.5.8-Laufs.

"""
for name in ("ed-core-resources", "x-core-resources"):
    record = index["supplementary"][name]
    resources += f"## {name}\n\nReceipt: `{record['path']}`.\n\nSHA-256: `{record['manifest_sha256']}`.\n\n"
    columns = ["Version", "Operation"] + (["Nachricht Byte", "Context Byte"] if name.startswith("ed-") else [])
    rows = []
    for r in record["SUMMARY.json"]:
        lead = [r["version"], r["operation"]] + ([r["message_bytes"], r["context_bytes"]] if name.startswith("ed-") else [])
        rows.append(lead + [f"{r[lane][key]:.3f}" for lane in ("stack_B", "rss_KiB") for key in ("median", "stdev", "min", "max")])
    resources += table(columns + ["Stack Median B", "Stack SD B", "Stack Min B", "Stack Max B", "RSS Median KiB", "RSS SD KiB", "RSS Min KiB", "RSS Max KiB"], rows) + "\n"
    resources += "Gebundene Positivkontrollen:\n\n```json\n" + json.dumps(record["IDENTITY.json"]["controls"], indent=2) + "\n```\n\n"
matrix_identity = index["supplementary"]["core-matrix"]["IDENTITY.json"]
resources += "## Objektgrößen und Core-Binärgrößen\n\n"
resources += table(["Version", "Ed301 size_of"], [[v, matrix_identity[v]["sizes"]] for v in ("v1", "v2")]) + "\n"
resources += "X301 size_of: SecretKey=76, PublicKey=80, SharedSecret=38 Byte. Objektgrößen sind weder Stackspitzen noch Prozess-RSS.\n\n"
layout = index["supplementary"]["core-layout"]
resources += f"Frische ELF-Inspektion: `{layout['path']}`.\n\nReceipt-SHA-256: `{layout['manifest_sha256']}`.\n\n"
size_rows = [[row["label"], *[row["gnu_size"][key] for key in ("text_including_ro", "data", "bss")]]
             for row in layout["SUMMARY.json"]]
resources += table(["Messbinary", "GNU text inkl. RO Byte", "data Byte", "bss Byte"], size_rows) + "\n"
table_rows = [[row["label"], entry["symbol"], entry["bytes"]] for row in layout["SUMMARY.json"] for entry in row["fixed_base_tables"]]
resources += "Statische Festbasistabellen laut nm -S; bereits in den ELF-Größen enthalten, kein zusätzlicher Laufzeit-Heap. Nur tatsächlich gelinkte benannte Tabellen werden aufgeführt.\n\n"
resources += table(["Messbinary", "Symbol", "Byte"], table_rows) + "\n"
for version in VERSIONS:
    directory = root / ("benchmarks-" + version)
    cases = read_json(directory / "CASES.json")
    rss_rows, module_rows = [], []
    for command in read_json(directory / "commands.json"):
        step = command["step"]
        if step.startswith("resources-"):
            case = cases[int(step.split("-")[1])]
            output = (directory / "logs" / (step + ".log")).read_text()
            rss = re.search(r"Maximum resident set size \(kbytes\): (\d+)", output)
            if rss is None:
                raise SystemExit("missing provider RSS")
            rss_rows.append([case["layer"], case["algorithm"], case["operation"], rss[1]])
        elif step.startswith("module-size-"):
            output = (directory / "logs" / (step + ".log")).read_text()
            sections = dict(re.findall(r"^(\.[^\s]+)\s+(\d+)\s+\d+$", output, re.M))
            binary = Path(command["command"][-1])
            module_rows.append([binary.parent.name + "/" + binary.name, *[sections.get(key, "0") for key in (".text", ".rodata", ".data", ".bss")]])
    if len(rss_rows) != 26 or len(module_rows) != 14:
        raise SystemExit("incomplete ABI resource inventory")
    resources += f"## Provider-/TLS-Ressourcen {version}\n\nEin einzelner zusätzlicher nativer 100-Operations-Lauf pro Fall, keine neunfache Core-RSS-Statistik.\n\n"
    resources += table(["Schicht", "Verfahren", "Operation", "Max RSS KiB"], rss_rows) + "\n"
    resources += "DSO-Sektionsgrößen in Byte; keine Addition zu einer isolierten Kryptokern- oder residenten Speichergröße. Vollständige size -A und readelf -SW-Ausgaben bleiben im Receipt.\n\n"
    resources += table(["Modul", ".text", ".rodata", ".data", ".bss"], module_rows) + "\n"

print(json.dumps({"E8_FINAL_REPORT.md": report, "E8_FINAL_BENCHMARKS.md": bench,
                  "E8_FINAL_RESOURCES.md": resources, "E8_FIX_REPORT.md": fixes}, ensure_ascii=False))
