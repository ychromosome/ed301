# Nachträglicher OTS-Zusatzbeleg

- Datum dieses Nachtrags: **9. September 2026**.
- Client: **OpenTimestamps-Python-Client 0.7.2** (`ots --version`); Erstellung
  und Upgrade durch Martin.
- Beleg: `RUN_MANIFEST.sha256.ots`, unveränderte Kopie des aktualisierten Belegs.
- Blockhöhe laut `ots info`: **966260**, vollständiger Nachweispfad über
  `alice.btc.calendar.opentimestamps.org`.
- Gebundener SHA-256 von `../v2-search/RUN_MANIFEST.sha256`:
  `a9c210823af851675678117d401415b54c2ad0cad8bb4ab47ce94f669acae313`.
- SHA-256 des hier abgelegten OTS-Belegs:
  `a83e91590afbb5ea68a252b805d5c2764549b469a3f2e8f36f358a1900913d46`.

**Verifikationsannahme:** Der Nachweispfad ist vollständig und seine Bindung an
das richtige Manifest wurde mit `ots info` kontrolliert. Eine Verifikation über
einen eigenen Bitcoin-Core-Knoten ist hier nicht nachgewiesen; der lokale
CLI-Versuch scheiterte an fehlender RPC-Konfiguration. Ohne eigenen validierenden
Knoten wird die Richtigkeit der gelieferten Kalender-/externen Blockdaten
vorausgesetzt. Eine Browserprüfung mit Blockexplorern ist entsprechend keine
vollständige eigene Bitcoin-Konsensprüfung. „Timestamp complete“ allein wird
nicht mit einer solchen Verifikation gleichgesetzt.

Der Beleg entstand nach dem A2-Start und ist nur eine zusätzliche nachträgliche
Absicherung. Der Vorab-Zeitnachweis bleibt das GitHub-Prerelease mit
`published_at=2026-09-09T18:11:30Z`; die OTS-Pflicht war zuvor vom Autor aufgehoben
worden. Der signierte Tag und das Paket unter `v2-search/` werden nicht verändert.

Bei vorhandener Bitcoin-Core-Verbindung kann aus diesem Verzeichnis ausdrücklich
gegen die unveränderte Originaldatei geprüft werden:

```sh
ots verify -f ../v2-search/RUN_MANIFEST.sha256 RUN_MANIFEST.sha256.ots
```
