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

report = f"""# Phase E: Abschluss zur unabhängigen Gate-E-Prüfung

Stand: 10. September 2026. Die beauftragten Optimierungen und lokalen Prüfungen
sind abgeschlossen. **Das Ziel, auf allen fünf Kern-Lanes schneller als v1 zu
sein, ist nicht vollständig erreicht.** Das ist kein bestandenes Gate E:
Claudes unabhängige Prüfung und Entscheidung stehen aus.

## Ergebnis des Geschwindigkeitskriteriums

Median der neun Laufmittel in µs; Änderung v2 relativ zu gleichzeitig gemessenem
v1. Die ABI-Bezeichnung identifiziert den vollständigen Messlauf; der reine
Rust-Kern selbst ruft kein OpenSSL auf.

""" + table(["ABI-Lauf", "Kernoperation", "v1 µs", "v2 µs", "Änderung %", "Median unter v1"], target_rows) + """
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

"""
report += f"Ausgeführter Quellstand: `{root / 'source'}`.\n\nQuellmanifest SHA-256: `{SOURCE_SHA}`; 1888 Dateien.\n\n"
report += "Die nach E5 ausgeführten Core-Prüfungen und Core-Timings werden über sämtliche\nRust-Dateien und ihre jeweiligen Harness-/Runner-Manifeste byteweise mit diesem\nEndstand verglichen. Später hinzugekommen sind nur Endprüfwerkzeuge beziehungsweise\nBerichte und Übergabecontroller, keine neue Arithmetik. Der finale Commitmanifest\ntrennt diese nach der Ausführung hinzugefügten Dateien ausdrücklich vom\nunveränderten ausgeführten Quellstand; es wird keine Hash-Identität vorgetäuscht.\n\n"
report += f"Vollständiger Index: `{checkout / 'phase-e/PHASE_E_EVIDENCE_INDEX.json'}`.\n\n"
report += "Der Index bindet 20 ABI-Stages, 18 ergänzende Receipts, die sechs Schritt-\nQuellsnapshots und die nachträglichen Berichte/Controller. Das äußere Manifest\nprüft zusätzlich Datei-/Verzeichnis-/Linkinventar, Modi und Inhalte. Build-Caches\nund ausdrücklich inventarisierte große Negativkontroll-Fixtures werden nicht\nmitkopiert; sämtliche ursprünglichen versiegelten Logs und Ergebnisse bleiben\nenthalten. Zusätzliche gemessene Core-ELFs werden mit ihren ursprünglichen\nIdentitätshashes aufgenommen. Enthaltene Schlüssel sind ausschließlich frisch\nerzeugte Testschlüssel und nicht für produktive Nutzung vorgesehen.\n\n"
report += "Die zunächst sandboxbedingt abgewiesenen TCP-Versuche bleiben separat erhalten;\ndie freigegebenen Wiederholungen verwenden ausschließlich eigene Loopback-\nEndpunkte und bestehen. Frühere fehlgeschlagene Vorbereitungsläufe werden nicht\nals PASS gezählt und nicht überschrieben.\n\n"
report += "Paketprüfung, frische Archivextraktion und natives Replay werden im äußeren\nÜbergabezettel mit ihren eigenen Receipts dokumentiert. Diese nachträglichen\nVerpackungsprüfungen sind nicht Teil eines zirkulär selbstbestätigten Berichts.\nGate E liegt bei Claude. Stufe 2, RPM-Bau, Installation, Aktivierung, AArch64,\nProduktionsfreigabe und Veröffentlichung sind nicht autorisiert. Phase E wird\nnicht ohne separates Go gepusht.\n"

bench = """# Phase E: vollständige abschließende Benchmarktabellen

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
Die fünf getrennten 32-Fälle-Schrittvergleiche bleiben zusätzlich im Paket.

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

resources = """# Phase E: vollständige Ressourcenbeobachtungen

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

print(json.dumps({"FINAL_REPORT.md": report, "FINAL_BENCHMARKS.md": bench,
                  "FINAL_RESOURCES.md": resources}, ensure_ascii=False))
