# Quellenbindung dieses lokalen C1/C2-Zwischenstands

Der Kern ist eine Anpassung des bestehenden Rust-Kerns, keine vollständig neu
geschriebene Kryptobibliothek. Der Bezugsstand in
/home/martin/Dokumente/ED301/ed301-eddsa-github ist Commit
5c688206a15f6ab88a50d53fe503665a302cec4d. Der Checkout wurde nicht verändert.

Mit git archive wurden dessen Workspace-/Lock-/Cargo-Konfiguration,
Kern-Crate, vendorte Abhängigkeiten, Secret-Taint-Harness, Rust-Benchmark,
Profil-/Vendor-Prüfwerkzeuge und Third-Party-Notices nach
/home/martin/Dokumente/ED301/ed301/rust übernommen. Änderungen betreffen
die neuen Parameter, ihre Ableitung, zugehörige Tests und Profilbeschreibungen.
Die übertragenen Abhängigkeiten und ihre bestehenden Forks wurden nicht geändert.
Die Forkprüfung kontrolliert die dokumentierten Upstream-Abweichungen erneut.

Die alte Notice-Datei unter
/home/martin/Dokumente/ED301/ed301/rust/THIRD_PARTY_NOTICES.md
ist bewusst eine unveränderte Herkunftsdatei. Ihre Provider-/dudect-Pfadnamen
beziehen sich auf den originalen v1-Baum und bedeuten nicht, dass ein v2-Provider
bereits implementiert wäre. Der hier tatsächlich verwendete dudect-Testcode
liegt unter /home/martin/Dokumente/ED301/ed301/phase-c/timing/third_party/dudect;
Header, Lizenz und historische Provenienz sind bytegleich übernommen. Die
historische AArch64-Timeranpassung bleibt erhalten, wird hier aber nicht ausgeführt.

Die Signatur-EVP-Messquelle wurde bytegleich aus demselben v1-Commit übernommen.
Die XDH-EVP-Messquelle und der ausschließlich als Vergleich gebaute X301-v1-Provider
stammen aus Commit 569dc4ff10e0e5e19d106cbe490d2a5aaeac935e in
/home/martin/Dokumente/ED301/x301-integration. Auch dieser Checkout bleibt sauber.
Die neue Rust-Matrix wird bytegleich gegen beide Ed301-Kerne gebaut.

Die Codegen-Regeln stammen aus dem vorhandenen v1-Prüfer. Für den Kern wurden
Artefakt-/Einstiegspunktnamen und die Annahme eines x86-64-Benchmark-ELF angepasst;
die übernommenen geradlinigen Instruktionsregeln, festen Schleifen und zulässigen
Aufrufketten wurden nicht wegen eines Testfehlers gelockert. Der Timing-Test
verwendet den vorhandenen dudect-Statistikkern mit einem getrennten minimalen
Rust-FFI-Testadapter. Neue Programme orchestrieren Messungen und Prüfläufe;
sie ersetzen keine SHAKE-, Big-Integer- oder Statistikbibliothek.

Die Parameter sind durch das freigegebene Paket in
/home/martin/Dokumente/ED301/ed301/provenance/phase-a/2026-09-09 und die Vektoren in
/home/martin/Dokumente/ED301/ed301/vectors/ed301-eddsa-v2.json gebunden.
Der Generator prüft deren feste SHA-256-Werte sowie die gebundene Python-
Kurvenreferenz, bevor er eingebettete Konstanten erzeugt. Die Phase-A/B-Manifeste
werden bei der erneuten Korrektheitsprüfung unverändert kontrolliert.

Jeder ausgeführte Benchmark-/Taint-/Timing-Runner erzeugt einen separaten
Belegordner mit Quellhashes, Befehlen, Toolchain, Profilmarkern, Binärhashes und
Rohdaten. Die genauen Pfade und maßgeblichen Hashes stehen im Bericht
/home/martin/Dokumente/ED301/ed301/phase-c/BERICHT_C1_C2_2026-09-10.md.

Dies ist noch kein extern auslieferbares Gate-C-Reviewpaket. Vor einer solchen
Übergabe werden die vollständigen commitgenauen Herkunfts-Snapshots und Belege
mit aufgenommen und Quell-/Provenienz-/Ausführungspfade aus einer frischen
Entpackung geprüft. Ein erfolgreicher lokaler Lauf allein erfüllt diese
Paketvollständigkeitsanforderung nicht. Kein Phase-C-Commit oder Push wurde
für diesen Zwischenstand vorgenommen; die freigegebenen älteren Snapshots und
Martins Signatur-/Timestamp-Artefakte bleiben unverändert.
