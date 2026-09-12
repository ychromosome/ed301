**Adversariales Review: Ed301-EdDSA-v2 / X301-v2**

Prüfstand: `ychromosome/ed301`, Branch `Testing`, Commit `74d30ba7f463ea7898249dc5560032f39358569b`. Alle Zeilenangaben beziehen sich ausschließlich auf diesen Commit. Prüfung am 10. September 2026. Die untenstehenden Kommandos sind im Repository-Verzeichnis auszuführen.

Belegt sind fünf Befunde: drei mittlere und zwei niedrige. Ein hoher Befund ist nicht nachgewiesen. Die Sicherheitsprüfung ist statisch und durch die unten ausgewiesenen eigenen Referenzläufe ergänzt. Rust/Cargo fehlen in der Prüfungsumgebung; das vorhandene OpenSSL 3.0.13 erfüllt die Mindestversion des Providers nicht. Native Provider-, Taint-, Dudect- und Disassembly-Prüfungen wurden deshalb hier nicht ausgeführt. Sämtliche Laufzeiten sind neu ausgewertete **Repository-Messwerte**, keine eigenen Messungen. Diese Begrenzung ist insbesondere für Befund 3 relevant.

**1. [mittel] Die Zeroisierung verliert die zurückgegebenen geheimnisabhängigen Projektivpunkte im EdDSA-Pfad.**

Datei/Zeile: `rust/crates/ed301-eddsa/src/signature.rs:308`, `:409`, `:440`; `rust/crates/ed301-eddsa/src/edwards.rs:46`, `:54`, `:370`, `:386`, `:594`; Testabdeckung `edwards.rs:885`.

Die Festbasismultiplikation hält ihren Akkumulator in `Secret<EdwardsPoint>`, gibt in Zeile 386 jedoch `*result` als gewöhnlichen `EdwardsPoint` zurück. Die Aufrufer speichern diese Kopie in `commitment_point` beziehungsweise `public_point`, jeweils ohne `Secret`/`Zeroizing`. Der Typ implementiert `Copy` und eine explizite `Zeroize`-Methode, aber keine automatische Löschung beim Verlassen des Gültigkeitsbereichs. `Copy`-Typen können in Rust keinen `Drop`-Destruktor implementieren. Die vorhandene Methode wird nicht dadurch ausgeführt, dass der Wert nicht mehr benötigt wird. Das unterscheidet diese ausdrücklich benannten Werte von unvermeidbaren zusätzlichen Compilerkopien. [Rust: Copy](https://doc.rust-lang.org/std/marker/trait.Copy.html#when-cant-my-type-be-copy).

Auch `encode_components` hält `Z⁻¹` ab Zeile 594 ohne Lösch-Guard. Dass die fertige Punktkodierung öffentlich ist, macht die vorherigen Projektivkoordinaten nicht öffentlich: `canonical_public_artifact` bezeichnet gerade `Z` in Zeilen 560–563 als geheimnisabhängig und gibt nur die kanonischen affinen Koordinaten frei. Der X301-Pfad setzt den zurückgegebenen Festbasispunkt dagegen unmittelbar unter `Zeroizing` (`rust/crates/x301/src/x301.rs:454`).

**Reproduzierbarer Nachweis:** Die folgenden Quellprüfungen wurden ausgeführt; alle Assertions bestehen. Zusammen mit der `Copy`-/`Drop`-Semantik belegen sie die fehlende automatische Löschung der benannten Werte.

```bash
python3 -B - <<'PY'
from pathlib import Path
s = Path('rust/crates/ed301-eddsa/src/signature.rs').read_text()
e = Path('rust/crates/ed301-eddsa/src/edwards.rs').read_text()
assert 'let commitment_point = EdwardsPoint::scalar_mul_base(&nonce);' in s
assert 'let public_point = EdwardsPoint::scalar_mul_base_pruned(&pruned_scalar);' in s
assert '#[derive(Clone, Copy)]\npub(crate) struct EdwardsPoint' in e
assert 'let mut result = crate::secret::secret(Self::IDENTITY);' in e
assert '        *result\n    }' in e
assert 'let inverse = self.z.invert();' in e
print('PASS: benannte Kopien liegen außerhalb des Lösch-Guards')
PY
git show 74d30ba:rust/crates/ed301-eddsa/src/edwards.rs | sed -n '368,387p;550,607p;884,894p'
```

Der bestehende Unwind-Test zählt die Löschung **innerhalb** der Festbasismultiplikation. Er prüft nicht die Löschung des anschließend zurückgegebenen Punktes. Der Befund beweist eine fehlende Zeroisierungsgarantie, weder einen tatsächlich beobachteten Speicherrest noch eine Schlüsselrekonstruktion.

**Korrektur:** Geheimnisabhängige Projektivpunkte und Normalisierungsinversen bis zur öffentlichen kanonischen Ausgabe in bewachten Besitzern halten. Die Übergabe an die Encoder muss diese Besitzergrenze erhalten. Einen gezielten Test für normalen Rückweg und Unwind nach Rückkehr aus der Festbasismultiplikation ergänzen; das Löschen nur des inneren Akkumulators genügt nicht.

**2. [mittel] Unbekannte OSSL_PARAM-Schlüssel werden als verbotene Betriebsarten behandelt.**

Datei/Zeile: `provider/crates/ed301-eddsa-provider/c/provider_shim.c:1091`, `:1136`, außerdem `:860`; `provider/crates/x301-provider/c/provider_shim.c:240`, `:883`; `provider/crates/x301-provider/c/hybrid_kem.c:428`.

Der EdDSA-Setter kennt `context-string` und abhängig von der ABI `tls-version`. Jeder andere Schlüssel erreicht den unbedingten Fehlerausgang in Zeile 1141. X301-Exchange-Init und Hybrid-KEM-Init lehnen jedes nichtleere Parameterarray ab. Damit werden auch vollständig unbekannte, für die Operation bedeutungslose Erweiterungsparameter abgewiesen.

OSSL_PARAM empfiehlt ausdrücklich, unbekannte Schlüssel zu ignorieren und einen konsistenten Satz erkannter Parameter erfolgreich zu verarbeiten. Das ist eine Abweichung von der dokumentierten Provider-Konvention, keine Verletzung eines kryptografischen MUST aus den Ed301-Spezifikationen. [OpenSSL: OSSL_PARAM, NOTES](https://docs.openssl.org/3.5/man3/OSSL_PARAM/).

**Reproduzierbarer Vertragsgegenbeleg:** Ein gültiger initialisierter EdDSA-Kontext erhält folgende Parameter. Der erste Parameter ist gültig; der zweite verändert keine definierte kryptografische Betriebsart.

```c
unsigned char context[] = {'r'};
unsigned int extension = 1;
OSSL_PARAM p[] = {
    OSSL_PARAM_octet_string("context-string", context, sizeof(context)),
    OSSL_PARAM_uint("review.extension", &extension),
    OSSL_PARAM_END
};
```

Der konkrete Kontrollfluss ist: erster Schleifendurchlauf → Zeile 1111; zweiter Durchlauf → Zeile 1141 → Rückgabe 0. Das Kontext-Update in Zeile 1145 wird nicht erreicht. Für X301 reicht das Array mit ausschließlich `review.extension`: `x301_params_are_empty(p)` ist falsch und Exchange-Init liefert 0. Diese Ergebnisse sind aus dem vollständigen Kontrollfluss abgeleitet; ein Live-EVP-Aufruf auf den Ziel-ABIs wurde hier nicht ausgeführt.

```bash
git show 74d30ba:provider/crates/ed301-eddsa-provider/c/provider_shim.c | sed -n '1079,1154p'
git show 74d30ba:provider/crates/x301-provider/c/provider_shim.c | sed -n '240,243p;872,890p'
git show 74d30ba:provider/crates/x301-provider/c/hybrid_kem.c | sed -n '420,442p'
```

**Korrektur:** Erkannte, nicht unterstützte Modusanfragen wie Digest/Prehash weiterhin explizit abweisen; wirklich unbekannte Erweiterungsschlüssel ignorieren. Gemeinsame Parameterarrays mit einem gültigen Kontext und einer unbekannten Erweiterung als Konformitätsfall testen. Die atomare Übernahme des erkannten Kontextwertes beibehalten.

**3. [mittel; Nachweisrisiko] Die nativen Sicherheits- und Messbelege sind aus dem angegebenen Commit nicht vollständig nachprüfbar.**

Datei/Zeile: `phase-e/E7_EVIDENCE_INDEX.json:3`, `:29`, `:31`, `:2724`, `:7673`; `phase-e/E7_FINAL_BENCHMARKS.md:29`.

Der Index enthält Prüfergebnisse, Binärhashes und statistische Kennzahlen. Die dazugehörigen Receipt-Manifeste, Rohmessungen, Taint-/Disassembly-Artefakte und Zwischenstände werden jedoch über einen externen lokalen Evidence-Root referenziert. Im Git-Baum des Prüfcommits liegen **0 von 20** referenzierten Stufenverzeichnissen, **0 von 14** Zusatzverzeichnissen und **0 von 3** Snapshot-Verzeichnissen. Die Benchmarkeinträge enthalten Kennzahlen, nicht die neun einzelnen Laufmittel. Hashes ohne die gehashten Bytes erlauben keine unabhängige Kontrolle der behaupteten Ausführung.

**Reproduzierbarer Nachweis:** Dieser Check liest ausschließlich den Commit und den enthaltenen Index, keine externen Pfade.

```bash
python3 -B - <<'PY'
import json, subprocess
j = json.loads(subprocess.check_output(
    ['git', 'show', '74d30ba:phase-e/E7_EVIDENCE_INDEX.json'], text=True))
files = subprocess.check_output(
    ['git', 'ls-tree', '-r', '--name-only', '74d30ba'], text=True).splitlines()
for section in ['stages', 'supplementary', 'source_snapshots']:
    entries = j[section]
    present = 0
    for entry in entries.values():
        prefix = entry['relative_path'].rstrip('/') + '/'
        present += any(f.startswith(prefix) or f.startswith('phase-e/' + prefix)
                       for f in files)
    print(section, len(entries), present)
print(sorted(j['benchmarks']['3.5.8'][0]))
PY
```

Ausgeführt mit Ergebnis `stages 20 0`, `supplementary 14 0`, `source_snapshots 3 0`; Kennzahlenfelder: `algorithm, layer, max_ns, mean_ns, median_ns, min_ns, operation, repetitions, stdev_ns`.

Das ist kein Beleg falscher Messergebnisse. Es ist eine konkrete Grenze dieses Review-Eingangs: insbesondere nativen Konstantzeit- und Zeroisierungsbehauptungen kann hier keine unabhängige Freigabe folgen. Der enthaltene Quellmanifest ist dagegen überprüfbar: `E7_FINAL_HANDOFF_SOURCE_MANIFEST.sha256` wurde über **1919 Dateien ohne fehlende Datei oder Hashabweichung** geprüft. Dass im Index der vorherige Build-Commit steht, ist dadurch nicht für sich ein Befund.

**Korrektur:** Das zu den angegebenen Hashes gehörende vollständige Review-Paket als erreichbaren, unveränderlichen Review-Eingang beilegen, einschließlich einzelner Messläufe, Kommandos, Toolchain-/Libcrypto-Identität und Binär-/Codegen-Artefakten. Die eigene Gate-E-Zurückhaltung des Projekts ist angemessen; ein bloßes PASS-Label ersetzt diese Daten nicht.

**4. [niedrig] Der Provider berechnet eine große Verifikationstabelle auch für ausschließlich zum Signieren verwendete Schlüssel.**

Datei/Zeile: `provider/crates/ed301-eddsa-provider/src/sig_ffi.rs:405`, zusätzlich privater Import `:338`; `rust/crates/ed301-eddsa/src/signature.rs:372`; `phase-c/benchmarks/core_matrix.rs:94`; `phase-e/E7_EVIDENCE_INDEX.json:1631`, `:2712`.

Die Seed-Expansion enthält bereits den validierten öffentlichen Punkt und seine Kodierung. `key_from_seed` erzeugt trotzdem immer `private.expanded.verifying_key()` und speichert dessen vorbereitete Tabelle. Die Signieroperation verwendet den ExpandedSigningKey; sie benötigt diese Tabelle im normalen Build nicht. Dadurch fallen bei jedem neu erzeugten Signierschlüssel zusätzliche Arbeit und dauerhafter öffentlicher Cache-Speicher an. Das betrifft den Schlüssel-Lifecycle, nicht eine erneute Tabellenberechnung bei jeder vorbereiteten Signatur.

**Reproduzierbarer Nachweis:** Der unbedingte Aufruf steht in Zeile 405. Die vorhandene Mikrobenchmark misst genau diesen Aufruf (`core_matrix.rs:94–98`); der E7-Index weist für v2 `prepare-verifier` **26,154107 µs** aus. Die Größe des VerifyingKey beträgt laut enthaltenem Größenbeleg **10.280 Byte**, davon 10.240 Byte Tabelle. Der EVP-Keygen-Median beträgt 56,9286 µs unter 3.5.8. `26,154107 / 56,9286 = 45,94 %` beschreibt die Größenordnung; wegen verschiedener Messgrenzen ist das keine garantierte Einsparung von 45,94 %.

```bash
git show 74d30ba:provider/crates/ed301-eddsa-provider/src/sig_ffi.rs | sed -n '394,418p'
git show 74d30ba:rust/crates/ed301-eddsa/src/signature.rs | sed -n '364,380p'
git show 74d30ba:phase-c/benchmarks/core_matrix.rs | sed -n '94,105p'
git show 74d30ba:phase-e/E7_EVIDENCE_INDEX.json | sed -n '1628,1641p;2710,2719p'
```

**Korrektur:** Validierten öffentlichen Punkt/Kodierung von der vorbereiteten Verifikationstabelle trennen und die Tabelle bei tatsächlichem Verifikationsbedarf einmalig materialisieren. Dabei fehlbare Allokation, konkurrierende Verwendung und die bestehenden Schlüssel-Snapshots erhalten. Die strikte Prüfung fremder öffentlicher Schlüssel darf dadurch nicht entfallen. Das erfordert weder Assembler noch schwächere Prüfungen.

**5. [niedrig] X301-DH erfüllt das dokumentierte Performanceziel gegenüber v1 noch nicht.**

Datei/Zeile: `rust/crates/x301/src/x301.rs:261`, `:291`; `phase-e/E7_FINAL_BENCHMARKS.md:45`, `:46`, `:83`, `:86`, `:182`, `:183`, `:220`, `:223`; die noch offene Zielerreichung ist auch in `phase-e/E7_FINAL_REPORT.md:4` und der dortigen Vergleichstabelle erkennbar.

Die abgelegten Endmessungen zeigen den verbleibenden Rückstand sowohl im Rust-Kern als auch beim wiederholten EVP-DH. Das ist ein bekannter Restbefund des Prüfstandes, kein neu entdeckter Sicherheitsfehler und keine Behauptung eines statistisch abgesicherten universellen Regressionsfaktors.

| Messreihe | v1 µs | v2 µs | Mehrzeit v2 |
| --- | ---: | ---: | ---: |
| Rust shared, Lauf 3.5.8 | 57,866651 | 59,700955 | 3,170 % |
| Rust shared, Lauf 4.0.2 | 57,473484 | 60,447131 | 5,174 % |
| EVP derive-steady, 3.5.8 | 57,4928 | 59,1041 | 2,803 % |
| EVP derive-steady, 4.0.2 | 57,7319 | 59,5917 | 3,221 % |

**Reproduzierbarer Nachweis:** Ausgeführte Rechnung `100 × (Median_v2 / Median_v1 − 1)`, getrennt nach ABI-Lauf:

```bash
python3 -B - <<'PY'
import json
from pathlib import Path
j = json.loads(Path('phase-e/E7_EVIDENCE_INDEX.json').read_text())
for abi, rows in j['benchmarks'].items():
    d = {(r['layer'], r['operation'], r['algorithm']): r['median_ns'] for r in rows}
    for layer, op in [('Rust-X', 'shared'), ('EVP-XDH', 'derive-steady')]:
        a, b = (d[layer, op, 'X301-' + v] for v in ['v1', 'v2'])
        print(abi, layer, op, a / 1000, b / 1000, 100 * (b / a - 1))
PY
```

**Korrektur bzw. Entscheidung:** Das Ziel weiter als offen behandeln oder den gemessenen Restaufwand ausdrücklich akzeptieren. Weitere Optimierung muss die 301 Runden, strikte Eingabeverarbeitung, schwache-Skalar-Prüfung und atomare Nullergebnisablehnung erhalten. Aus den vorliegenden Zahlen folgt kein Nachweis, welcher einzelne verbleibende Teil die Mehrzeit verursacht. Insbesondere sind Vergleiche zum historischen v1 kein Gleichstand der Sicherheits- und Compilerprofile: dessen dokumentierte crypto-bigint-Ausnahme und C-O0-Einstellung bleiben erhalten (`E7_FINAL_BENCHMARKS.md:4–7`).

**Vergleich der heißen EVP-Pfade mit den vier OpenSSL-Verfahren**

Die Zahlen sind Mediane von neun Laufmitteln in µs auf dem dokumentierten Ryzen 9 5950X, CPU 2. Sie sind weder Einzelaufruf-Perzentile noch Konfidenzintervalle. Quelle: `phase-e/E7_FINAL_BENCHMARKS.md:55–86` und `:192–223`, maschinenlesbar `E7_EVIDENCE_INDEX.json → benchmarks`. Die Kurven haben unterschiedliche Sicherheitsniveaus; ein Rückstand zu Ed25519/X25519 ist für sich kein Sicherheits- oder Implementierungsfehler. Die Werte gelten für die enthaltene Buildkonfiguration und keinen hier nachgemessenen einheitlichen No-Asm-Build aller Vergleichsverfahren.

| ABI | Operation | Ed25519 / X25519 | Ed448 / X448 | Ed301 / X301 v1 | Ed301 / X301 v2 |
| --- | --- | ---: | ---: | ---: | ---: |
| 3.5.8 | Ed Keygen | 24,740 | 148,182 | 57,052 | 56,929 |
| 3.5.8 | Ed Sign | 24,060 | 147,857 | 29,863 | 29,926 |
| 3.5.8 | Ed Verify | 80,222 | 157,990 | 87,409 | 84,836 |
| 3.5.8 | X Keygen | 24,013 | 146,138 | 29,299 | 29,610 |
| 3.5.8 | X erster Derive | 23,966 | 121,414 | 57,854 | 59,404 |
| 3.5.8 | X wiederholter Derive | 23,725 | 120,513 | 57,493 | 59,104 |
| 4.0.2 | Ed Keygen | 24,506 | 147,414 | 57,409 | 56,709 |
| 4.0.2 | Ed Sign | 24,085 | 148,176 | 30,414 | 29,742 |
| 4.0.2 | Ed Verify | 79,861 | 157,976 | 87,076 | 84,144 |
| 4.0.2 | X Keygen | 23,982 | 145,968 | 30,102 | 29,725 |
| 4.0.2 | X erster Derive | 23,973 | 121,261 | 58,237 | 58,803 |
| 4.0.2 | X wiederholter Derive | 23,740 | 120,328 | 57,732 | 59,592 |

X301-v2 benötigt beim wiederholten DH damit das 2,49-/2,51-Fache von X25519 und rund 49,0/49,5 % der X448-Zeit. Ed301-Verifikation liegt in beiden Reihen näher an Ed25519 als an Ed448 und unter dem jeweiligen v1-Median. Die kleinen Signaturdifferenzen gegenüber v1 wechseln je nach Reihe die Richtung; daraus lässt sich keine durchgehende Überlegenheit ableiten.

Beim Codec liegt ein zusätzlicher, bereits untersuchter Integrationsaufwand vor: privates Ed301-DER-Encoding einschließlich Kontextaufbau kostet 56,146435 statt 40,231381 µs unter 3.5.8 und 32,738872 statt 23,353329 µs unter 4.0.2, also rund 39,6/40,2 % mehr als v1. Die enthaltene E6-Analyse (`phase-e/E6_REPORT.md:23–60`) weist die zusätzliche Encoder-Suche bei drei statt zwei Aliasnamen aus und widerlegt erneute Seed-Expansion im gemessenen Loop. Daher ist dies **kein zusätzlicher Befund unnötiger Schlüsselerzeugung**. Aliasentfernung oder Weglassen des Kontextaufbaus würde den API-Vertrag beziehungsweise die Messgrenze verändern. Context-Wiederverwendung ist nur bei einem tatsächlich passenden Anwendungs-Lifecycle eine sinnvolle eigene Messreihe.

**Eigene Prüfungen und abgegrenzte Verdachtsmomente**

`python3 -B tools/check_phase_b.py` wurde vollständig ausgeführt: 8/8 Schritte, 29 Python-Tests, erfolgreiche Node-Gegenimplementierungen und bytegenaue deterministische Regeneration beider Vektorsätze. Die Prüfungen umfassen unter anderem Kurve/Twist, 64 schwache Skalar-Aliase, Nullergebnisse, Kanonizität und beide v1/v2-Kreuzrichtungen. `python3 -B phase-c/tools/check_field_bounds.py` meldet PASS für die exakten öffentlichen Ganzzahlschranken; das ist kein nativer Konstantzeitnachweis.

Die unabhängige Halving-Referenz wurde direkt mit Ausgabe ausschließlich unter `.audit/` ausgeführt. Sie stimmt auf 156 gerichteten/zufälligen Punkten und den drei nichttrivialen Torsionspunkten mit dem Untergruppenorakel überein; die 25 ausgegebenen Vektoren sind bytegleich zu `vectors/ed301-v2-subgroup-halving.json`, SHA-256 `e78ae62a636242ba9c01f4a4a0edce7d38dbe89ebb1508b144baaa3334b91737`. Dies ist eine Wiederholung der vorhandenen unabhängigen Referenz, kein neuer formaler Beweis.

```bash
mkdir -p .audit
python3 -I -B phase-e/reference/claude/phase_e/subgroup_halving_proof.py "$PWD" "$PWD/.audit/halving-vectors.json"
cmp .audit/halving-vectors.json vectors/ed301-v2-subgroup-halving.json
```

Die vermeintlich falsche E7-A24-Formel ist kein Befund: Mit `K = a − d = 61206265502` und `A24_minus · K ≡ d ≡ −301 (mod p)` berechnet der neue Schritt `X' = K·AA·BB`, `Z' = E·(K·AA − 301·E)`. Beide ursprünglichen Projektivkoordinaten werden mit demselben von null verschiedenen Faktor K skaliert. Die errechnete affine Koordinate bleibt gleich. Auch die Festbasisableitung des X301-Public-Keys per Edwards-Abbildung ist nicht allein deshalb eine RFC-Abweichung, weil der DH-Pfad eine Montgomery-Leiter verwendet.

Die strikte X301-Kodierung ist gegenüber [RFC 7748 §5](https://www.rfc-editor.org/rfc/rfc7748.html#section-5) abweichend, aber im normativen Eingabevertrag ausdrücklich entschieden. Das wäre ein Befund bei behaupteter X25519-Kompatibilität; eine solche Gleichsetzung ist hier nicht gerechtfertigt. Ebenso begründet die Übernahme des EdDSA-Schemas aus [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html) keine Kompatibilität mit dessen festgelegten Ed25519-/Ed448-Parametern. Die geprüfte Signaturverifikation verwendet das vorgesehene kofaktorbehaftete Prüfkriterium; ein zusätzlicher R-Untergruppentest oder das Verbot von S=0 wäre keine zulässige eigenmächtige Härtung dieses Profils.

Bei Containeridentitäten ist [RFC 8410 §3](https://www.rfc-editor.org/rfc/rfc8410.html#section-3) die Vergleichsbasis für parameterlose AlgorithmIdentifier, nicht die Zuweisung seiner Ed25519-/X25519-OIDs an Ed301. Unterschiedliche v1/v2-Domänen und Containeridentitäten trennen die Profile; gleich lange nackte Rohschlüssel enthalten dagegen keinen Herkunftstag. Eine aus diesen Rohbytes ableitbare v1/v2-Erkennung wurde im Review nicht unterstellt.

Für Libctx, Provider-RAND, Encoder/Decoder-Ketten und TLS-Capabilities ergab die statische Prüfung keinen weiteren belegten Defekt. Geprüft wurden insbesondere Child-Libctx statt Umdeutung des Core-Kontexts, gebundene EVP-Fetches, delegiertes ML-KEM, Ausgabekopie erst nach erfolgreichem Signieren/Derive/Hybrid-KEM, Decoder-Weitergabe bei fremder Eingabe und die getrennten TLS-Testoberflächen. Die selbst verwalteten DRBG-Kontexte verwenden OpenSSL EVP_RAND; der dokumentierte Lebensdauergrund verbietet die pauschale Empfehlung, sie durch einen unbedachten RAND_priv_bytes_ex-Aufruf zu ersetzen. Für eine neue Kurve ersetzt OpenSSL seine fest auf die RFC-Verfahren ausgelegten ECX-Implementierungen auch nicht einfach durch Parameterübergabe. Aus der bloßen Existenz eigener Feldarithmetik, kleiner DER-Schablonen oder eines fehlbar allokierenden Shared-Besitzers folgt daher kein Befund.

Die versionierten Quelldateien wurden nicht verändert; es erfolgten weder Commit/Push noch Pull Request, Installation oder Zugriff auf die im Evidence-Index genannten externen Systempfade.
