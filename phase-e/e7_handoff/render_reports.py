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

paired = index["supplementary"]["benchmark-E7"]
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

report = f"""# E7: Abschluss zur unabhängigen Gate-E-Prüfung

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

""" + table(["Lane", "v1 µs", "E1–E6 µs", "E7 µs", "E7 ggü. E1–E6 %", "E7 ggü. v1 %"], paired_rows) + f"""
Diese Reihe bestätigt den wesentlichen Gewinn bei X301 shared, aber nicht
„vier von fünf Lanes schneller“: Ed301 sign liegt hier ebenfalls knapp über v1.
Die E7-SD bei sign beträgt 2,813 µs, die Vorher-SD bei X301 shared 6,793 µs.
Kleine Abstände sind angesichts der Streuung keine Geschwindigkeitsgarantie.

Danach folgen zwei neue vollständige ABI-Matrizen mit unabhängig neu
gebauten Vergleichsbinaries. Ihr Rust-Kern selbst ruft kein OpenSSL auf.
Jede Tabellenzeile verwendet ausschließlich ihren eigenen v1-Bezugswert;
weder ABI-Läufe noch Claudes CPU-3-Reihe werden zusammengelegt.

""" + table(["ABI-Lauf", "Kernoperation", "v1 µs", "E7 µs", "Änderung %", "Median unter v1"], target_rows) + f"""
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
{checkout / 'phase-e/E7_OPTIMIZATION.md'}.

Schranken:
{checkout / 'phase-c/FIELD_BOUNDS.md'}.

Unverändert bleiben 301 Runden, Clamp, Swaps, Fehlerreihenfolge, Parameter,
Kodierungen, Zeroizing-Besitzer und Ausgabeverträge. Kein Assembler, keine
Clamp-Bit-Abkürzung, keine weitere Schleifenumstellung. Claudes drei Eingaben
werden bytegleich aufbewahrt, einschließlich der Leerzeichen im Originaldiff.

## Alle technischen Gates neu

Kern: {counts['current-ed']} Ed301- und {counts['current-x']} X301-Tests,
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
{root / 'source'}

Quellmanifest SHA-256: {SOURCE_SHA}; {index['source_files']} Dateien.
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
{checkout / 'phase-e/E7_EVIDENCE_INDEX.json'}

Der Index bindet {len(index['stages'])} ABI-Stages,
{len(index['supplementary'])} ergänzende Receipts und
{len(index['source_snapshots'])} Vergleichs-Quellsnapshots. Build-Caches und
ausdrücklich inventarisierte große Kontroll-Fixtures werden ausgelassen;
alle versiegelten Ergebnislogs, Messartefakte und benötigten Binaries
bleiben enthalten. Enthaltene Schlüssel sind ausschließlich erzeugte
Testschlüssel. Archivprüfung, frische Extraktion und natives Replay
erhalten eigene äußere Receipts. Gate E und die Entscheidung über weiteren
Optimierungsaufwand bleiben bei Claude beziehungsweise Martin.
"""

bench = """# E7: vollständige abschließende Benchmarktabellen

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
Der neue gepaarte 32-Fälle-E7-Vergleich bleibt zusätzlich vollständig im Paket.

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

bench += "## Gepaarter E7-Schrittvergleich\n\n"
bench += table(["API", "Version", "Operation", "Median µs", "SD µs", "Min µs", "Max µs"],
               [[r["api"], r["version"], r["operation"], *stats(r)] for r in paired["SUMMARY.json"]]) + "\n"

resources = """# E7: vollständige Ressourcenbeobachtungen

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

print(json.dumps({"E7_FINAL_REPORT.md": report, "E7_FINAL_BENCHMARKS.md": bench,
                  "E7_FINAL_RESOURCES.md": resources}, ensure_ascii=False))
