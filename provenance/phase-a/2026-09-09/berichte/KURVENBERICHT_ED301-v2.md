# ED301-v2 – Kurvenbericht und Gate-A-Vorlage

Stand: 9. September 2026. Erstellung und lokale Nachweise: Codex/Emmy.
Externe Gate-A-Prüfung: Claude, noch ausstehend.

## 1. Ergebnis und verbleibende Grenze

Die ausgewählte Familie d=−301 hat im formal neu ausgeführten Bestätigungslauf
den ersten gültigen Zähler **c=246492** ergeben. Damit sind
s=247399 und a=61206265201 bestätigt. Der frische Vollaudit, unabhängige
Primzahlzertifikatsprüfungen, reine Python-Ordnungszeugen und die
Basispunkt-Gegenprüfung sind bestanden.

Dies ist ein mathematisches Nachweispaket für Gate A. Es ist keine neue
EdDSA-/XDH-/Provider-Implementierung, kein Benchmark, keine Standardisierung
und keine Produktionsfreigabe. Phase B beginnt erst nach Claudes Gate-A-Prüfung.

## 2. Vorabbindung und dokumentierte Verfahrensänderung

| Gegenstand | Bindung |
|---|---|
| Signierter Tag | v2-search-rule-2026-09-09 |
| Tagobjekt | 6d48ac5f584263c7fde3afd347c9b93debe3b224 |
| Freigegebener Quellcommit | 0bf9b5936737fc920d701815cf55cfd35c54d288 |
| Manifest SHA-256 | a9c210823af851675678117d401415b54c2ad0cad8bb4ab47ce94f669acae313 |
| Regeldatei SHA-256 | b5e9c6d49641f2181c3d5635b7827814c799d924ffcfbc7cdbeb9bbb61cdab7a |
| GPG-Fingerprint | A1A573F04786BE9FF8A6BF7C109858B57B6B73BA |
| GitHub-Release-ID | 385742722 |
| Server-published_at | 2026-09-09T18:11:30Z |
| Tatsächlicher A2-Start | 2026-09-09T18:14:16Z |
| A2-Ende / Exit | 2026-09-09T18:58:03Z / 0 |

Das [öffentliche Prerelease](https://github.com/ychromosome/ed301/releases/tag/v2-search-rule-2026-09-09)
wurde vor dem Lauf zurückgelesen und als JSON archiviert. Maßgeblich ist
published_at, nicht ein clientseitiges Commit-/Tag-Datum oder created_at.

Martin hat die ursprünglich zusätzlich verlangte OTS-/Bitcoin-Bedingung
ausdrücklich vor A2 aufgehoben und den Ablauf Prerelease, dann A2 freigegeben.
Diese Änderung ist im Release-Text und in Commit
7e00e5c270086a588a6a42c58fe1c575f2985e68 getrennt dokumentiert.
Tag, Manifest, mathematische Kriterien und ausführende Such-/Auditwerkzeuge
wurden nicht verändert. Es wird kein zweiter unabhängiger Zeitnachweis vor A2
behauptet. Ein später vom Autor angelegter OTS-Beleg ist ein zusätzlicher
nachträglicher Beleg und keine rückwirkende Erfüllung des ursprünglichen Gates.

## 3. Offenlegung der Exploration

Vor Veröffentlichung der Regel waren drei Familien (145, 89, −301) untersucht
worden. Die Filterstufen waren die v1-Regel, eine Zwischenregel t<0 und die
strengere 300-Bit-Bedingung. Die Familienwahl d=−301 ist eine gesonderte
Autorenentscheidung; die neue Rechnung ist ausdrücklich ein
**Bestätigungslauf nach offengelegter explorativer Vorarbeit**.

Die historischen Rohdateien, widerspruchsfreien Doppelblöcke, Zwischenstände
und korrigierten Auditversuche bleiben im signierten Explorationsarchiv.
Sie wurden nicht in das neue Ausgabeverzeichnis übernommen und nicht als
abgeschlossene Blöcke des Bestätigungslaufs gewertet. Die frühere
Ersttrefferaussage wurde somit nicht bloß aus alten Protokollen übernommen.

## 4. A2 – frischer Bestätigungslauf

Die Ausführung benutzte die vier manifestgebundenen Dateien in einer neuen
Laufumgebung, nach erneuter Prüfung aller 17 Manifest-Einträge und der
Werkzeugversionen. Die Quelldateien waren schreibgeschützt.

```text
python3 search_v3.py --d -301 --start 0 --chunk 64 --workers 10 --maximum 1000000 --out raw_v3
```

Der systemd-Benutzerprozess war vom Werkzeugaufruf entkoppelt und endete
regulär. Seine Invocation-ID ist c2c85daf9a264881865b65f7898ef2d1.
Die Laufzeit betrug **43 Minuten 47 Sekunden**; das ist eine
Reproduktionslaufzeit, kein vergleichender Performance-Benchmark.

Die unabhängige Rohprotokoll-Abnahme prüfte jeden JSONL-Eintrag gegen die
zugehörige Rohdatei: Exitstatus, Fehlerliste, Metadaten, Dateiname,
Blockgrenzen, Testanzahl, Trefferarray, Duplikate und vollständige Vereinigung.

| Prüfung | Ergebnis |
|---|---|
| Abgeschlossene Blöcke | 3858 |
| Getestete Zähler | 246912 |
| Lückenlose Abdeckung | 0..246911 |
| Fehlgeschlagene Blöcke | 0 |
| Treffer insgesamt | 1 |
| Kleinster gültiger Zähler | 246492 |
| Trefferblock | 246464..246527 |
| Vorhersagevergleich | alle 14 Werte identisch |
| Driver-stderr | leer |
| Finale Zusammenfassung | genau einmal, status=OK |

Die zusätzlichen Blöcke oberhalb des Trefferblocks waren bereits zugeteilt
und wurden ordnungsgemäß zu Ende gerechnet. Der numerisch kleinste Treffer
wurde unabhängig bestimmt, nicht aus der lexikographischen Sortierung des
Treibers abgeleitet.

A2-Ergebnis SHA-256:
16cac939e17e0b81158ccd01cbd744687de5bd3d288eccd7fcf1d540fc850fdc.

Aggregat der Rohdateien:
2513371433243ac9c0d4fb345f0000933652b89bd8c3eeedda73922751cae246.
Die genaue Aggregatbildung und Einzelprotokoll-Hashes stehen in
evidence/A2_RESULT.json; der ausführbare read-only Prüfer liegt in
evidence/verify_a2_records.py.

## 5. A3 – frischer Vollaudit

A3 erhielt d, c, q und q_twist aus dem akzeptierten frischen A2-Ergebnis.
Der Lauf dauerte von 19:02:30Z bis 19:02:43Z und endete mit Exitcode 0.
Ergebnisdatei und stdout sind byteidentisch; stderr enthält ausschließlich
zwei Stackgrößen-Warnungen. Es gibt genau einen abschließenden Passmarker.

| Eigenschaft | Ergebnis |
|---|---|
| p, q, q_twist | beweisender PARI-isprime-Test bestanden |
| N und N_twist | jeweils separat durch SEA erneut gezählt |
| Kofaktoren | exakt 4 und 4 |
| Haupt-/Twistuntergruppe | 300 / 299 Bit |
| Pruninggrenze | 4q≥2^301 |
| q−1 und q_twist−1 | vollständig faktorisiert, Faktoren in PARI bewiesen |
| Einbettungsgrade | (q−1)/4 und (q_twist−1)/2, jeweils 298 Bit |
| Hasse, Twistrelation | bestanden |
| Anomal / supersingulär / j=0 / j=1728 | jeweils nein |
| Fundamentale CM-Diskriminante | -1649252704580914034745319541732100801594268949563749078783894799941862868943069362120347, 290 Bit |
| Frobeniusleiter | 94 |
| Mögliche Endring-Leiter | 1, 2, 47, 94 |
| Negations-Rho-Modell | ungefähr 149,326 Bit Gruppenoperationen |

Faktorisierungsprodukte und modulare Zeugen der exakten Einbettungsgrade
wurden zusätzlich mit Python-Ganzzahlen abgeglichen. Die Primheit sämtlicher
Faktoren der beiden N−1-Zahlen wird in dieser Zeile nicht als unabhängig
zweitbewiesen behauptet; sie ist ein Befund des frischen PARI-Audits.
Die gesonderten unabhängigen Zertifikatsprüfungen für p, q und q_twist folgen
in A4.

SHA-256 von `audit/audit_v3_d-301_c246492_pari.txt` und dem byteidentischen
`evidence/audit.stdout.log`:
`c1cbb23fea448cc12b023fc30ca0bc0925a89c7bc34421c0e817e23fe249259f`.

Der getrennte Abnahmebericht `evidence/A3_RESULT.json` hat SHA-256
`e21a4bfabdbb4efd78dc5e0d2c533b8e0538875d5cd5771604de2f65a7225d53`.

## 6. A4 – unabhängige Primheits- und Ordnungsnachweise

Für p, q und q_twist wurden neue ECPP-Zertifikate erzeugt, mit PARI validiert
und in reiner Python-Ganzzahlarithmetik unabhängig geprüft. Die Python-Prüfung
importiert weder PARI noch eine Kurvenbibliothek. Ihre Terminalprimzahlen
wurden durch vollständige Probedivision bewiesen, nicht nur als wahrscheinlich
prim übernommen.

| Wurzel | ECPP-Stufen | Terminalprimzahl | Probedivision bis floor(sqrt) |
|---|---|---|---|
| p | 12 | 167433425655079 | 12939606 |
| q | 9 | 321556323770389 | 17931991 |
| q_twist | 8 | 668665795981 | 817719 |

Die adaptierten v1-Prüfer verlangen die erwartete Zertifikatswurzel ausdrücklich.
Der ECPP-Prüfer kontrolliert zusätzlich positive Theoremparameter und
invertierbare Zwischenwerte beziehungsweise eindeutig definierte
Ausnahmezweige der projektiven Addition über dem Zertifikatsmodulus.
Dadurch wird keine Primheit des Modulus für die Gruppenrechnung vorausgesetzt.

Zusätzlich wurden native PARI-N−1/BLS-Zertifikate für q und q_twist erzeugt
und mit dem unabhängigen v1-Python-Prüfverfahren gegengeprüft. Dessen
64-Bit-Blätter verwenden den vorhandenen deterministischen Miller-Rabin-
Basissatz; die großen Wurzeln werden durch die Pocklington-/BLS-Bedingungen
abgesichert.

Prüfkontrollen verwarfen:
- ein ECPP-Zertifikat mit geändertem Trace;
- ein N−1-Zertifikat mit doppeltem Faktor;
- ein gültiges ECPP-Zertifikat unter einer falschen erwarteten Wurzel.

Alle drei Kontrollen endeten erwartungsgemäß mit Exitcode 1. Das ist eine
gezielte Regressionskontrolle, kein Anspruch auf erschöpfendes Fuzzing.

Unabhängige Ordnungszeugen wurden auf dem Weierstraßmodell und dem Twist
konstruiert. Die deterministischen Start-x-Werte sind 1 beziehungsweise 7.
Nach Multiplikation mit 4 sind beide Zeugen nichtneutral und werden von der
jeweiligen zertifizierten Primzahl annihiliert. Im Hasse-Intervall existiert
jeweils genau ein Vielfaches dieser Primzahl, nämlich 4q beziehungsweise
4*q_twist. Das bestätigt die Ordnungen methodisch unabhängig von SEA.

## 7. A5 – Basispunkt

Das im signierten Paket festgelegte SHAKE256-Verfahren mit dem neuen DST
ergibt bereits bei Zähler **0** den ersten gültigen Basispunkt:

```text
DST = ED301-BASEPOINT-DERIVATION-v2
G_x = 245172735077481686141532231884424203654311209138530333716187517083174888339324898223239818
G_y = 1808980237167142700180815997420225869231424645512138687717783516228016417571735456686768070
ENC(G) = c67f33b932f3097533c5ebca430d01b9c000ba91025af84747afd17d6a9b242bf2b1fe6e350e
```

Die Python-Ableitung protokolliert Hash-Framing, vollständige 38-Byte-Ausgabe,
Maskierung, Rekonstruktion, gerade x-Parität, Kofaktormultiplikation,
Punktprüfung und Kodierungs-Roundtrip. PARI bestätigt über sein
Weierstraßmodell G=[4]P und die exakte Ordnung q. Ein separater OpenSSL-
CLI-Aufruf bestätigt Framing und SHAKE-Ausgabe; er ist kein behaupteter
zweiter SHAKE-Implementierungsnachweis.

Die Maskierungs-/Verwerfungsanalyse betrifft ein Modell gleichverteilter
XOF-Ausgaben. Die feste DST-/Zählerableitung selbst ist deterministisch;
es wird keine informationstheoretische Gleichverteilung eines endlichen
Zählerraums über das gesamte Feld behauptet.

## 8. A6 – Parametersatz und Spezifikation

[ed301-v2.json](../parameter/ed301-v2.json) wird aus akzeptiertem A2-Ergebnis,
frischem A3-Bericht und geprüftem A5-Basispunkt erzeugt. Große Ganzzahlen sind
dezimal als Strings gespeichert, damit JSON-Verbraucher keine Präzision durch
Gleitkommazahlen verlieren. Hex- und Little-Endian-Darstellungen sowie A24,
Weierstraß-/Twistkoeffizienten und Exponenten werden daraus neu berechnet.

Die [Spezifikation](../spezifikation/ED301-v2.md) trennt mathematische
Kurvenkodierungen, Signaturregeln und die noch festzulegende externe
X301-u-Eingabepolitik. OIDs und TLS-Codepoints sind nicht zugewiesen.

## 9. Werkzeugkorrekturen und Grenzen

Fehler in neu adaptierten, nachgelagerten Hilfsskripten wurden vor
Übernahme ihrer Ergebnisse behoben:

1. Der erste Zertifikatsexport nutzte eine für GP unvollständige mehrzeilige
   if-Anweisung. Drei Versuche endeten mit Exitcode 1 ohne Passmarker. Die
   korrigierte, geklammerte Exportfunktion wurde separat erneut ausgeführt.
2. Der erste PARI-Basispunktwrapper verwendete min/max statt vecmin/vecmax.
   Er brach vor der Punktprüfung ab. Der korrigierte Wrapper bestand den
   anschließenden Lauf.
3. Der neue Spezifikations-Konsistenzprüfer erfasste zunächst Zeilengrenzen
   beziehungsweise zusätzliche symbolische Gleichungen falsch. Nach Eingrenzung
   auf die numerischen und hexadezimalen Zuweisungszeilen bestand der Abgleich;
   Parameter und Spezifikation wurden dafür nicht verändert.

Fehlerhafte Quellen und Logs bleiben getrennt in proofs/scripts/history
beziehungsweise proofs/logs erhalten. Sie sind keine bestandenen Nachweise.
Die signierten Suchwerkzeuge, A2-Daten und der gebundene A3-Audit wurden durch
diese Änderungen nicht angefasst.

Die v1-Herkunft und Anpassungen der nachgelagerten Prüfer sind im Quellnachweis
des Gate-A-Pakets dokumentiert. Noch nicht erbracht sind Phase B (Referenz und
Vektoren), Phase C (gehärteter Kern und Performance) und Phase D (X301/Provider/
PKI/TLS-Integration). Keine dieser Grenzen wird durch ein bestandenes
mathematisches Gate ersetzt.

## 10. Übergabe an Claude

Zur Prüfung stehen:
- Vorabbindung, Veröffentlichung und dokumentierter OTS-Verzicht;
- vollständige A2-Rohprotokolle und unabhängige Abnahme;
- frischer A3-Audit;
- Zertifikate, unabhängige Prüfer, Kontrollen und Ordnungszeugen;
- Basispunkt und PARI-Gegenprüfung;
- Parametersatz, Spezifikation und Quellen-/Dateihashes.

**Gate A wird nicht von der erstellenden Instanz selbst erteilt.** Claude
prüft diesen Stand. Erst danach wird Phase B auf den bestätigten Werten begonnen.
