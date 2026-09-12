# Gate-D-Handoff: Umfang und Wiederholung

Zuerst den Bericht lesen:
/home/martin/Dokumente/ED301/ed301/phase-d/d2/D2_REPORT_2026-09-10.md.
Dann die Inventur
/home/martin/Dokumente/ED301/ed301/phase-d/d2/FEATURE_INVENTORY.md
gegen den maschinenlesbaren Index
/home/martin/Dokumente/ED301/ed301/phase-d/d2/D2_EVIDENCE_INDEX.json
prüfen. Claudes Freigabe ist ein nachgelagerter eigener Schritt.

## Was das lokale Archiv enthält

Das Paket enthält den unveränderten ausgeführten Quell-Snapshot, alle normalen
DSOs/Harnesses/OpenSSL-Lanes, instrumentierte Test-DSOs, v1-Vergleichsmodule,
gebundene Donorarchive, Befehls-/Umgebungsprotokolle, Timing-/Benchmark-Rohdaten,
Codegen-Artefakte und die nach Ausführung erstellten Berichte.

Cargo-Zwischenverzeichnisse sind nicht enthalten. Die zehn absichtlich
manipulierten OpenSSL-Kopien je Controls-Lane sind ebenfalls ausgelassen; ihre
Originalhashes und Symlinkziele sind als explizite Auslassungen verzeichnet.
Ihre Prüflogs, Befehle und Controllerquellen bleiben enthalten. Insbesondere
wird der absichtlich absolute Negativtest-Symlink nicht als aktiver Link ins
Archiv übernommen. Diese Testkopien sind regenerierbar, aber nicht als portable
Runtime freigegeben. Die sechs normalen relativen OpenSSL-Symlinks sind erhalten
und werden zusammen mit Dateien, Verzeichnissen und Modi vollständig inventarisiert.

Historische Receipt- und OpenSSL-Seals bleiben unverändert. Das Paket besitzt
zusätzlich ein äußeres Manifest. Dessen SHA-256 und der Archivhash stehen im
separaten abschließenden Übergabebeleg; sie können nicht selbstreferenziell im
versiegelten Paket stehen. Vor Ausführung den Archivhash gegen diesen Beleg
prüfen, in ein neues privates Verzeichnis auspacken und anschließend den
Manifesthash von außen an den Prüfer übergeben.

Die frischen CLI-Testschlüssel sind nur lokale Testdaten im privaten Paket;
sie sind nicht im Git-Commit und dürfen nicht als Betriebsschlüssel dienen.
Der Git-Stand enthält nur Quellcode, feste öffentliche Testvektoren und Berichte.

## Prüfer und Replay

Die Übergabewerkzeuge liegen im Checkout unter
/home/martin/Dokumente/ED301/ed301/phase-d/d2/handoff.
Im entpackten Paket liegen sie im Berichtsunterverzeichnis, getrennt von den
früher ausgeführten Buildinputs. Der Prüfer
/home/martin/Dokumente/ED301/ed301/phase-d/d2/handoff/verify_handoff.py
benötigt die Optionen `--bundle` und `--manifest-sha`.
Ohne weitere Option prüft er ausschließlich Dateien, Typen, Modi, Links,
Stage-Seals, Identitäten und ausdrücklich deklarierte Auslassungen.

Mit `--replay-output` auf ein neues Verzeichnis startet er die gebundenen
nativen Funktionstests beider ABIs einschließlich Oracle-/Decoder-/TLS-Engine-
Prüfungen, OID-/Retry- und nativer OpenSSL-EVP-Tests. Nur die absolute
Nachweiswurzel in Argumenten und Umgebungswerten wird auf den entpackten Ort
umgebunden. `LD_LIBRARY_PATH` und die erwartete OpenSSL-Prefixbindung werden
gemeinsam geändert; die Harnesses prüfen weiterhin die tatsächlich geladenen
Libraries. Das Paket wird danach erneut unverändert verifiziert.

`--tcp` ist eine zusätzliche ausdrückliche Auswahl für die projektinternen
`127.0.0.1:0`-Tests. Es gibt keine fremden Ziele und keine festen Listenerports.
Ein Replay ist kein Neubau, keine vollständige Wiederholung der CLI-/Memory-
Stages und keine erneute Leistungsmessung. Seine eigenen Befehle und Logs
werden separat versiegelt; die ursprünglichen Ergebnisse werden nie überschrieben.

## Vollständige Stage-Wiederholung

Die ausgeführten Controller stehen unter
/home/martin/Dokumente/ED301/ED301-v2_D2-matrix_2026-09-10_06/source/phase-d/d2/tools.
Jeder akzeptiert nur einen von außen gebundenen Quellmanifesthash und neue
Ausgabeverzeichnisse. Für einen frischen Functional-Build kann die bereits
authentifizierte OpenSSL-Lane aus dem Paket als `--openssl-lane` dienen.
`run_functional.py` übernimmt keine alten Provider-Buildresultate; es baut
die Varianten und unabhängigen Rebuilds offline neu.

Nachgeordnete Controller benötigen zusätzlich `--functional` und dessen von
außen übernommenen `--functional-sha`. Die v1-Vergleichsstage braucht beide
Donorarchive; die Benchmarkstage zusätzlich deren neuen `--legacy-sha`.
Alle Argumente und bereinigten Umgebungen der ursprünglichen Ausführung sind
im jeweiligen Befehlsprotokoll enthalten. Strukturierte Zusatzläufe sind dort
als die beiden direkten, explizit ausgewählten EVP-Harnessaufrufe dokumentiert.

Timing und Benchmarks seriell, ohne parallele Builds/Instrumentierung laufen
lassen. Sie setzen nur prozesslokale CPU-Affinität; keine Frequenz-/Governor-
Änderung vornehmen. Die ursprüngliche Maschine ist ein AMD Ryzen 9 5950X,
native x86-64, mit protokolliertem Compiler und OpenSSL 3.5.8/4.0.2.
Für einen anderen Rechner sind neue Messwerte und ein eigener Nachweis nötig.

Systeminstallation, RPMs, Aktivierung, externe Endpunkte, Push, Veröffentlichung
und D1-Optimierung sind kein Bestandteil dieses Pakets oder Replayauftrags.
