# ED301-v2 – Suchregel für den öffentlichen Bestätigungslauf

Stand: 9. September 2026. Zur Prüfung, persönlichen Signatur durch Martin und
anschließenden Veröffentlichung vorbereitet. Diese Datei behauptet weder eine bereits
erfolgte Veröffentlichung noch einen abgeschlossenen Bestätigungslauf. Die neun
Annahmekriterien in Abschnitt 3 sind gegenüber dem geprüften Entwurf unverändert.

Vor dem Bestätigungslauf werden diese Datei und das zugehörige `RUN_MANIFEST.sha256`
öffentlich gebunden: Martins signierter Git-Tag auf dem freigegebenen `Review`-Commit,
GitHub-Release mit dokumentiertem `published_at` und vollständiger, verifizierter
OpenTimestamps-Bestätigung des Manifestes. Ein Git-Commit-/Tag-Datum oder eine noch
ausstehende OTS-Einreichung ersetzt diesen Nachweis nicht. Erst danach gibt Martin A2 frei.

## 0. Offenlegung

Vor diesem Bestätigungslauf hat eine explorative Suche stattgefunden (9. September 2026).
Ihre Rohdaten, Worker, Treiber, Statusberichte und Kontroll-/Auditdateien sind im getrennten
Archiv `exploration.tar.gz` erhalten; `EXPLORATION.md` erläutert dessen Grenzen. Sie prüfte
die Familien d = 145, d = 89 und d = −301 mit der v1-Regel, einer Zwischenregel t<0 und
schließlich der strengeren 300-Bit-Bedingung. Ergebnis für d = −301 unter der
endgültigen Regel: kleinstes gültiges c = 246492. Der Bestätigungslauf ist daher ein
**öffentlich festgelegter, reproduzierbarer Bestätigungslauf nach offengelegter explorativer
Vorarbeit**, keine ungesehene Erstauswahl. Er muss c = 246492 als ersten Treffer ab c = 0
in einem einzigen Lauf unter dieser einen Regel reproduzieren.

## 1. Feste Eingaben (nicht Gegenstand der Suche)

```text
p   = 2^301 - 2^89 + 907          (bewiesen prim; p ≡ 3 mod 8)
    = 0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffe000000000000000000038b
d   = -301 ≡ p - 301               (quadratischer Nichtrest mod p; Entscheidung des Autors)
Kurve: a·x² + y² = 1 + d·x²·y² über F_p (getwistete Edwards-Form)
```

907 = 301 + 89 + 372 + 145. Die Wahl von d ist eine dokumentierte Autorenentscheidung;
die beiden anderen explorierten Familien (145, 89) sind mit ihren Ergebnissen im
Offenlegungsarchiv enthalten.

## 2. Starre Kandidatenfolge

```text
c = 0, 1, 2, ...          (lückenlos aufsteigend)
s = 907 + c
a = s² mod p
```

Angenommen wird der **kleinste** c, dessen Kandidat sämtliche Kriterien in Abschnitt 3
erfüllt. Es gibt keine weitere Auswahl, keine Gewichtung nach Geschwindigkeit, Einfachheit
oder Symbolik innerhalb der Familie.

## 3. Annahmekriterien (alle zwingend; Reihenfolge = Prüfreihenfolge in `search_worker_v3.gp`)

1. Vollständigkeitsbedingungen: `a ≠ 0`, `a ≠ d`, `a` quadratischer Rest mod p (bei `a = s²`
   automatisch), `d` quadratischer Nichtrest.
2. Montgomery-Modell `A = 2(a+d)/(a−d)`, `B = 4/(a−d)`: `A ≠ ±2`, `B ≠ 0`,
   `A² − 4` quadratischer Nichtrest mod p (twist-sichere Leiter).
3. Weierstraß-Modell `y² = x³ + A·B·x² + B²·x`: `j ≠ 0` und `j ≠ 1728`.
4. Exakte Ordnung `N = #E(F_p)` per SEA; `N_t = 2p + 2 − N`; `N ≡ 4 (mod 8)` und
   `N_t ≡ 4 (mod 8)`; `q = N/4`, `q_t = N_t/4`.
5. **Untergruppenbitlängen: `bitlen(q) = 300`**, d. h. `4q ≥ 2^301`, äquivalent
   `t ≤ 908 − 2^89`; **`bitlen(q_t) ≥ 299`**.
   (Zweck: jeder v1-geprunte Skalar `s < 2^301 ≤ 4q` ist kein Vielfaches von q; der
   v1-Nachweis des nichtneutralen öffentlichen Schlüssels bleibt wörtlich gültig.)
6. `q` und `q_t` sind prim. Im Lauf: `ispseudoprime` gefolgt vom beweisenden PARI-`isprime`-Test
   (`factor_proven` bleibt Standard; das Verfahren wird nicht auf APR-CL festgelegt). Getrennt
   davon liefert das Nachweispaket ECPP-Zertifikate für `p`, `q`, `q_t`, die ohne PARI prüfbar sind.
7. Kein kleiner Einbettungsgrad: `p^k ≢ 1 (mod q)` und `p^k ≢ 1 (mod q_t)` für alle
   `1 ≤ k ≤ 100`.
8. `t = p + 1 − N` erfüllt `t² ≤ 4p`; `N ≠ p`, `N_t ≠ p` (nicht anomal).
9. Fundamentale CM-Diskriminante `D_K = coredisc(t² − 4p)` mit `|D_K| > 2^100`.

Nur berichtet, nicht entscheidend: exakte Einbettungsgrade und ihre Kofaktoren in
`q − 1`, `q_t − 1`; SafeCurves-Schranke `k ≥ (Ordnung − 1)/100`; Frobenius-Konduktor
und die vollständige Liste möglicher Endring-Diskriminanten; Pollard-rho-Aufwand im
Negationsmodell `log2(sqrt(π·q/4))`; Bitlänge von `a`.

## 4. Werkzeuge und Protokollierung

- PARI/GP ≥ 2.17 mit `pari-seadata`; Worker `search_worker_v3.gp` (Kriterien 1–9 in
  exakt dieser Reihenfolge, `default(recover, 0)`), Treiber `search_v3.py`, Blockgröße 64,
  Blöcke `[start, start+63]` lückenlos ab 0, Rohdateien unter `raw_v3/`.
- Je Block eine Rohdatei `raw_v3/search_v3_d-301_<start>_<end>_worker_<id>.txt` mit
  `tested`, `elapsed_ms`, `hits` (vollständiger Kandidatenvektor
  `[c, s, a, A, B, N, q, N_t, q_t, t, D_K]`).
- Ein Block gilt nur als abgeschlossen, wenn der Worker mit Exitcode 0 endete, keine
  PARI-Fehlerzeile ausgab und seine Rohdatei existiert. Jeder andere Fall stoppt die
  Zuteilung, wird in der Zusammenfassung als `status=FATAL` mit den betroffenen Blöcken
  ausgewiesen und beendet den Treiber mit Exitcode 1; der Lauf ist dann ungültig und wird
  als Ganzes wiederholt.
- Hashbindung vor dem Lauf: `RUN_MANIFEST.sha256` bindet diese Regeldatei,
  `search_worker_v3.gp`, `search_v3.py`, `audit_v3_template.gp`, die Startparameter in
  `RUN_PARAMETERS.json`, den Werkzeugstand in `TOOL_VERSIONS.txt` und die ergänzenden
  Offenlegungs-/Referenzdateien. Das Manifest wird mit der Regeldatei veröffentlicht.
- Festgelegter A2-Aufruf: `python3 search_v3.py --d -301 --start 0 --chunk 64 --workers 10
  --maximum 1000000 --out raw_v3`. Die operative Obergrenze begrenzt die Laufzeit, nicht
  die mathematische Annahmeregel. Ein Lauf ohne bestätigten Treffer ist kein Erfolg.
- Frische Laufumgebung: eigenes leeres Verzeichnis, in das nur die vier Dateien aus dem
  Manifest kopiert werden; der Treiber legt Rohdateien unter `--out` und das Blockprotokoll
  `search_v3_d-301_from0.jsonl` ebenfalls unter `--out` ab. Explorative Rohdaten bleiben im
  Offenlegungsverzeichnis und werden nicht in die Laufumgebung übernommen.
- Der Lauf endet, sobald ein Treffer vorliegt und alle Blöcke unterhalb abgeschlossen
  sind. Nachweis der Lückenlosigkeit durch Rekonstruktion aus den Rohdateien
  und Abgleich mit dem JSONL-Protokoll: d, Bereichsgrenzen, vollständige Testanzahl,
  widerspruchsfreie Treffer, keine fehlgeschlagenen Blöcke und numerisch kleinster
  gültiger Zähler. `status=OK` allein ersetzt diese Abnahme nicht. Historische
  Abdeckungsberichte aus dem Offenlegungsarchiv werden nicht als neue Laufresultate verwendet.
- Anschließend Vollaudit mit `audit_v3_template.gp` (Kandidat aus der Umgebung, Kriterium 5
  als Pflichtprüfung, `default(recover, 0)`, genau ein Passmarker), ECPP-Zertifikate für
  `p`, `q`, `q_t`, unabhängiger Ordnungszeuge in reiner Python-Ganzzahlarithmetik,
  deterministische Basispunktableitung (Abschnitt 5).

## 5. Vom Suchergebnis abgeleitet, nicht Teil der Suche

- Basispunkt `G`: SHAKE256-Ableitung nach dem unveränderten Verfahren in
  `reference/ED301-v1.md`, Abschnitte 9.3 und 10, mit den bestätigten v2-Werten p, a, d, q
  und `DST = "ED301-BASEPOINT-DERIVATION-v2"`. Der separate Basispunktzähler läuft von 0
  bis 2^32−1, wird als vier Big-Endian-Bytes an den ASCII-DST angehängt und mit SHAKE256
  auf 38 Ausgabebytes abgebildet. `candidate[37] &= 0x1f`; y muss kleiner als p sein;
  die rekonstruierte x-Wurzel hat fest gerade Parität. Nullnenner und Nichtpunkte werden
  verworfen. Setze G=[4]P, verwerfe G=O und nimm den ersten verbleibenden Zähler; beweise
  anschließend die Ordnung q. Erschöpfung des Zählerraums ist ein Fehler. Historische
  Zahlen und der v1-DST aus der Referenz werden nicht als v2-Konstanten übernommen.
- Profilkennungen (Vorabfragen Punkt 6): `ED301-v2`, `Ed301-EdDSA-v2`, `SigEd301-v2`,
  neue OIDs, neue TLS-Testcodepoints.

## 6. Erwartetes Ergebnis (aus der offengelegten Exploration)

```text
c = 246492, s = 247399, a = 61206265201
q   = 1018517988167243043134222844204689080525734197161172607405736521898659399129740227070627621
q_t = 1018517988167243043134222844204689080525734196504763643230403927146236890812251410387989153
t   = -1312817928350665189504845016634977633365276936
```

Weicht der Bestätigungslauf davon ab, gilt der Bestätigungslauf; die Abweichung wird
dokumentiert und nicht wegerklärt.
