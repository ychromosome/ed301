# ED301-v2 – Vorlage für Gate A

**A2–A6 lokal bestanden; externe Gate-A-Prüfung durch Claude ausstehend.**
Keine Produktionsfreigabe und noch keine neue Signatur-/XDH-/Providerimplementierung.

Der neu ausgeführte Bestätigungslauf hat c=246492 für d=−301 als einzigen und
kleinsten gültigen Treffer bestätigt: 3858 Blöcke, lückenlos 0..246911, Exitcode 0.
Der frische A3-Audit, unabhängige ECPP- und N−1/BLS-Prüfungen, unabhängige
Ordnungszeugen sowie die Python-/PARI-Basispunktprüfung sind bestanden.

## Einstieg

- [Kurvenbericht](berichte/KURVENBERICHT_ED301-v2.md): Verfahren, Ergebnisse,
  Offenlegung, Hashzuordnung und Grenzen.
- [Parametersatz](parameter/ed301-v2.json): alle großen Ganzzahlen als Strings.
- [Kurvenspezifikation](spezifikation/ED301-v2.md): mathematischer Vertrag und Kodierungen.
- [Nachweisarchiv](phase-a-evidence.tar.gz): frischer Quell-Snapshot, Rohblöcke,
  Prozess-/Release-Belege, Audit, Zertifikate, Prüfer, Kontrollen und Quellhinweise.
- [Manifest](PHASE_A_MANIFEST.sha256): Hashbindung dieses Prüfstands.

Das Archiv enthält auch erfolglose Entwicklungsversuche nachgelagerter
Hilfsskripte, deutlich von den bestandenen Nachweisen getrennt. Sie werden
weder versteckt noch als erfolgreiche Belege gewertet. Der signierte
Vorabstand und die eigentlichen Such-/Auditwerkzeuge wurden nicht verändert.

## Prüfung aus frischem Verzeichnis

```sh
sha256sum --check PHASE_A_MANIFEST.sha256
work=$(mktemp -d)
tar -xzf phase-a-evidence.tar.gz -C "$work"
python3 "$work/verify_gate_a.py"
```

Erforderlich sind Python 3, PARI/GP, OpenSSL mit SHAKE256 und sha256sum.
Der Prüfer wiederholt **nicht** die gesamte Suche und erzeugt keine neuen
Zertifikate. Er prüft das signierte Quellmanifest, alle A2-Blockdaten, den
frischen A3-Bericht, die Zertifikate samt Negativkontrollen, Ordnungszeugen,
Basispunkt und die Übereinstimmung von Parametersatz und Spezifikation.
Die Prüfung ist ohne Netzwerkzugriff möglich; sie liest die archivierten
GitHub-Metadaten, ersetzt aber keine unabhängige Live-Prüfung der Veröffentlichung.

Für die Veröffentlichungsbindung sind der öffentlich verfügbare signierte Tag
`v2-search-rule-2026-09-09`, das Tagobjekt
`6d48ac5f584263c7fde3afd347c9b93debe3b224`, der Quellcommit
`0bf9b5936737fc920d701815cf55cfd35c54d288` und
[das Prerelease](https://github.com/ychromosome/ed301/releases/tag/v2-search-rule-2026-09-09)
maßgeblich. Der Tag und der Quellcommit sind im Archiv zusätzlich als öffentliche
Gitobjekte enthalten; eine GPG-Verifikation benötigt den entsprechenden öffentlichen Schlüssel.

## Publikationsentscheidung

GitHub meldet published_at=2026-09-09T18:11:30Z; A2 begann danach um 18:14:16Z.
Martin hatte die zusätzliche OTS-/Bitcoin-Voraussetzung zuvor ausdrücklich
aufgehoben. Diese Entscheidung ist getrennt im Release und in Commit
`7e00e5c270086a588a6a42c58fe1c575f2985e68` dokumentiert. Es wird kein zweiter,
vor A2 abgeschlossener Zeitnachweis behauptet. Ein späterer OTS-Beleg bleibt
ein zusätzlicher nachträglicher Beleg und gehört nicht zu dieser Freigabebedingung.

## Branch- und Gate-Grenze

Entwicklung bleibt auf `Testing`, dieser Prüfstand wird als Snapshot auf
`Review` bereitgestellt. `main` und der signierte Vorab-Tag bleiben unverändert.
Claude prüft Gate A; erst danach folgt Phase B. OIDs, TLS-Codepoints und die
abschließende X301-Profil-/Integrationsbindung werden hier nicht zugewiesen.
