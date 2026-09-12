# Phase C zur externen Prüfung

Maßgeblicher Bericht:
[/home/martin/Dokumente/ED301/ed301/phase-c/GATE_C_REPORT_2026-09-10.md](/home/martin/Dokumente/ED301/ed301/phase-c/GATE_C_REPORT_2026-09-10.md).

Der neue Rust-Kern, die übertragene Testinventur, Taint/Codegen/Timing,
168 Geschwindigkeitsfälle und 52 Ressourcenfälle werden als Reviewkandidat
vorgelegt. Dies ist keine eigene Gate-C-Freigabe. Numerische Ressourcen- oder
Performance-Grenzen und zusätzliche Zielplattformen wurden nicht erfunden.

Die zuvor offene Messliste ist bearbeitet: Feld-/Skalarmessungen, Stack-/RSS-
Beobachtungen mit Kontrollen, Objekt-/Tabellen-/Binärgrößen und Vorberechnungszeit.
Die älteren Dateien im Phase-C-Verzeichnis bleiben historische Zwischenstände;
ihre damaligen offenen Punkte werden durch diesen Handoff eingeordnet, nicht
rückwirkend umgeschrieben.

Quellen und Belege:

- /home/martin/Dokumente/ED301/ed301/phase-c/PHASE_C_SOURCE_MANIFEST.sha256
- /home/martin/Dokumente/ED301/ed301/phase-c/EVIDENCE_INDEX.json
- /home/martin/Dokumente/ED301/ed301/phase-c/FIELD_BOUNDS.md
- /home/martin/Dokumente/ED301/ed301/phase-c/TEST_INVENTORY.md

Der äußere Übergabezettel bindet den tatsächlichen Testing-Commit, das
Paketmanifest und den Archivhash. Das Paket enthält drei vollständige Git-
Snapshots einschließlich Git-Bundles, die ursprünglichen Binaries und Belege,
hashadressierte historische Quellbytes, alle drei alten Parent-Inputs sowie
gefrorene Primärquellen/Errata. Fehlende Parent-Verweise in den alten Baselines
werden durch einzeln deklarierte Provenienz-Symlinks ergänzt; kein getrackter
Quellblob wird dafür verändert.

Der Paketprüfer kontrolliert Dateimenge, Hashes, Git-Blobs/Dateimodi, alle
historischen Quellmanifest-Einträge und die Parent-Pfade. Der Replay baut aus
einer frischen Arbeitskopie mit lokal aus Git-Bundles ausgecheckten Baselines;
alle bisherigen Runner laufen mit ihren vollständigen Default-Wiederholungen.
Auch diese erneuten Benchmarkwerte werden tabellarisch ausgegeben. Das Paket
selbst bleibt während des Replay unverändert.

Für Claude bleiben die inhaltlichen Freigabefragen: Faltungsschranken selbst
nachrechnen, Konstantenkette gegen Gate A/B, übertragene Akzeptanzregeln gegen
den Vertrag, die drei Gates gegen ihre jeweils tatsächlichen Binärhashes und
die Gesamtmethodik der Messungen prüfen. Kein Hashcheck ersetzt diese Prüfung.

Provider-/OID-/PKI-/TLS-/Hybrid- und X301-v2-Integration bleiben entsprechend
Martins ausdrücklicher Phasengrenze späteren Arbeiten vorbehalten. Keine
Phase-D-Implementierung, kein Vorschieben nicht verfügbarer Benchmarks,
keine Umdeutung alter Kennungen und keine Promotion nach main.
