# N4 und N2: TLS-Namen und Stock-CLI geprüft

Stand: 11. September 2026. Ausgangscommit:
494a28cc1baaaff258d5467d11749f8b1acc7314 auf Testing.

Ergebnis: Die angeforderten Namensänderungen sind umgesetzt; die Stock-CLI
besteht N2 in getrennten Prozessen mit lauf-lokaler Standard-Libctx-Konfiguration
unter OpenSSL 3.5.8 und 4.0.2. Kein Provider-/Kryptografiefehler wurde dabei
beobachtet. Keine RPMs, Hostinstallation, Host-Konfigurationsänderung, dauerhafte
Aktivierung oder Veröffentlichung. Kein Deep Scan wurde gestartet.

## N4: genaue Namensänderungen

| Bisherige Kennung | Neue Kennung |
| --- | --- |
| ed301_eddsa_v2_tls_test | ed301_eddsa_v2_tls |
| x301_v2_tls_test | x301_v2_tls |
| ed301_eddsa_v2_test (TLS-SIGALG-Auswahl/Anzeige) | ed301_eddsa_v2 |

Produktnamen Ed301-EdDSA, X301 und X301MLKEM1024, OIDs, SignatureScheme 0xFE85
sowie Gruppen 0xFE2F/0xFE30 bleiben unverändert. Der TLS-SIGALG-Text ist keine
zusätzliche Drahtkennung und keine IANA-Registrierung. Die alten TLS-Modulnamen
sind keine weiter akzeptierten Aliase; neue Tests prüfen ihre Ablehnung vor
einem Ladeversuch. PKI-Versuchs-, Collider- und Failpoint-Varianten bleiben
getrennt und behalten ihre Diagnosebezeichnungen.

Die beiden Provider-C-Shims unterscheiden sich vom Ausgangscommit exakt
durch diese drei Stringersetzungen. Der übrige Provider-Code, der vollständige
Rust-Kern und alle Vektoren sind unverändert. Aktive Testharnesses und generische
Build-/CLI-/Codegen-/Messrunner verwenden die neuen Namen. Historische
Receipts, Manifeste, Übergabecontroller und Referenzberichte bleiben an ihre
alten Snapshots gebunden und wurden nicht pauschal umbenannt.

## N2: tatsächlicher Standard-Libctx, keine Frontends

Neuer Runner:
/home/martin/Dokumente/ED301/ed301/phase-d/d2/tools/run_default_context_cli.py

Beobachter für Provider-/Kontextidentität:
/home/martin/Dokumente/ED301/ed301/provider-tests/provider_default_context.c

Jeder Stock-OpenSSL-Prozess erhält ein eigenes OPENSSL_CONF aus seinem
privaten Ergebnisverzeichnis. Darin sind nur default und die zwei neuen
TLS-Modulnamen aktiviert. Die tatsächlichen Module und Libraries stammen
aus dem authentifizierten neuen Functional-Receipt. OPENSSL_TEST_LIBCTX ist
nicht gesetzt; kein Stock-Kommando verwendet -provider oder -provider-path.
Der C-Beobachter lädt selbst keine Provider und bearbeitet keine Schlüssel,
CSRs oder Container; er bestätigt ausschließlich die Konfiguration im
Prozess-Standardkontext und die unqualifizierte KEYMGMT-Auflösung.

Auf beiden ABIs bestanden insbesondere:
- Stock req -verify für den neu erzeugten Ed301-CSR;
- Stock x509 -req einschließlich CSR-Signaturprüfung und Ausstellung
  eines Leafs durch die kurzlebige Ed301-CA;
- Stock verify einschließlich CA-Selbstsignatur, Zertifikatskette und Hostname;
- Stock PKCS12-Export und private Keydumps für Ed301 und X301;
- Prüfung, dass die extrahierten privaten Schlüssel dieselben Public Keys
  ergeben wie die ursprünglichen Schlüssel;
- Ed301-/X301-Schlüsselgenerierung, private/public Checks und verschlüsselter
  PKCS8-Roundtrip;
- X301-Derive in beiden Richtungen mit identischen nichtnulligen 38 Byte.

Negativkontrollen: falsche PKCS8-/PKCS12-Passwörter, falscher Hostname,
beschädigte CSR-Signatur beim Prüfen und beim Ausstellen sowie eine separate
Konfiguration ohne v2-Aktivierung. Der ungültige CSR erzeugt kein Zertifikat.
Die Inaktivitätskontrolle vor und nach den CLI-Prozessen belegt die
prozesslokale Konfigurationsgrenze; es gibt keinen dauerhaften Host-Schalter.

Alle Schlüssel, Zertifikate und Container sind neue lokale Testdaten außerhalb
des Git-Checkouts. Keine Tests benutzen Produktivschlüssel oder fremde Endpunkte.
Die Befehle ohne Frontends gelten für N2; der separate historische
Private-Libctx-CLI-Gate benutzt seine dort weiterhin benötigten Frontends.

### OpenSSL-4-Konfigurationsbesonderheit

Der erste 4.0.2-N2-Versuch scheiterte vor Ausstellung: x509 liest seit OpenSSL 4
auch Erweiterungen aus der Standardkonfiguration. Ohne benannte
Erweiterungssektion wurden die globalen Initialisierungsdirektiven als
Erweiterungsnamen behandelt (unknown extension name: config_diagnostics).

Die Testkonfiguration benennt jetzt ausdrücklich eine leere n2_extensions-
Sektion. Die angeforderten CSR-Erweiterungen werden weiterhin mit
-copy_extensions copy übernommen; Kette, Verwendungszweck und Hostname des
Zertifikats werden geprüft. Dies folgt dem
Verhalten der gebundenen OpenSSL-4-App und ihrer x509-Manpage, ohne Änderung
an OpenSSL, Provider, Signaturprüfung oder Zertifikat-Verifizierungsregeln.

Der ursprüngliche fehlgeschlagene Lauf bleibt unverändert erhalten:
 /home/martin/Dokumente/ED301/ED301-v2_N2_N4_01_2026-09-11/default-cli-4.0.2

Zwischen erstem und endgültigem Snapshot änderte sich ausschließlich dieser
N2-Testcontroller. Der abschließende gesamte hier ausgewiesene Durchlauf wurde
dennoch auf einem gemeinsamen neuen Snapshot wiederholt; kein FAIL wurde
nachträglich in PASS umetikettiert.

## Abschließende Prüfung und Quellenbindung

Ausgeführte Quelle, 1956 Dateien:
/home/martin/Dokumente/ED301/ED301-v2_N2_N4_02_2026-09-11/source

Quellmanifest SHA-256:
6bdb28e4db8703bcc86c6202ab5b4c5fe04032473b486109619ea25375d71a09

Kompilierter Eingabesatz SHA-256:
5eaa54794c23c0e35af8b04803f048b7fadfec32460e61f9c9291c1096c8e1aa

Je ABI: neun neue Provider-Varianten; vier unabhängige bytegleiche Rebuilds;
20 Ed301- und 7 X301-Provider-Rust-Tests; Lints, Dokumentationsbuild,
Exports-/Laufzeitbindung, komplette vorhandene Functional-Prüfungen und
Private-Libctx-CLI-Stage. Neue Default-Kontext-Stage: je 48 protokollierte
Befehle. Alle N2-Kernkommandos enden erfolgreich, Gegenproben wie erwartet
mit Fehlerstatus.

TCP: je 95/95 Prüfungen mit eigenen 127.0.0.1-Endpunkten, HRR,
gegenseitiger Authentifizierung, KeyUpdate und Gruppen-Negativkontrollen.
Codegen: vier neue Ordinary-/TLS-DSOs je ABI unter den unveränderten
LLVM-21-Arithmetikregeln und Gegenproben, insgesamt acht tatsächliche DSOs.
Keine Lockerung zur Aufnahme anderer Compiler, keine Übernahme des externen
LLVM-22-Ausnahmeprüfers.

| Stage | Protokollierte Befehle | Receipt-Manifest SHA-256 |
| --- | --- | --- |
| functional-3.5.8 | 137 | 96e29298f88f60769df501d6197e6c95022f9793d630e3b2c78e7ed2d42f82d1 |
| default-cli-3.5.8 | 48 | 6e79168f610a8203b45b86c0ad8e4869eb38dd04a895136d9596aaa53bac0831 |
| private-cli-3.5.8 | 93 | dd3cc998386fb548c8b81fc59a395e3e6054997cd53bd40d8fc5dbe0a6dc4b4b |
| codegen-3.5.8 | 4 | 304a510f3c95ca10e9715a1d6e7f5fff68990a52a54894526a14074a7ac81449 |
| tcp-3.5.8 | 1 | 044183e8977ab5c0844251d0e79929bbf9b9e232f477cb33e2f2a6377898afd4 |
| functional-4.0.2 | 137 | a220f233608f2c8afaad60a497331ca5851b21d38a72d2d5635718988b87c93d |
| default-cli-4.0.2 | 48 | b83a518ea02b7fd2ba16efa3451a0cdfb96dc27dcb0516776e64e5dec1056aba |
| private-cli-4.0.2 | 93 | 18a6d67df1ed1198eded7ed6c72aeba1ef02e15453417e0d0329752855e39e58 |
| codegen-4.0.2 | 4 | 28a436eb9f13e735d9cfa400c471e2fa91196cb6c65b0b135142e039b7c1266c |
| tcp-4.0.2 | 1 | ab6bad41c66c917dbba51db3882d393b6a2c2edddf2459bb67bebdb2f8fd719f |

Maschinenlesbarer Index:
/home/martin/Dokumente/ED301/ed301/phase-d/d2/N2_N4_EVIDENCE_INDEX.json

Die zehn Receipts liegen als entsprechend benannte Unterverzeichnisse unter:
/home/martin/Dokumente/ED301/ED301-v2_N2_N4_02_2026-09-11

Befehle, bereinigte Umgebungen, Logs, Module, Profile, Rebuild-Vergleiche
und lauf-lokale Konfigurationen sind dort erhalten. Vollständige Inventare,
Memberhashes, Logbindungen, gemeinsame Quellidentität und Functional-Verknüpfung
wurden nach Abschluss noch einmal geprüft.

Neues abschließendes Inhaltsmanifest:
/home/martin/Dokumente/ED301/ed301/phase-d/d2/N2_N4_SOURCE_MANIFEST.sha256

## Grenzen und nächster vorgeschlagener Schritt

Dies ist keine erneute vollständige Gate-E-Leistungsmessung oder ein
universeller Seitenkanalnachweis. Kern-Timing, Kernbenchmarks und die komplette
Memory-/Taint-Matrix wurden nicht erneut ausgeführt; private CLI-Prüfungen
enthalten ihre bestehenden ASan-/Memcheck-Frontendkontrollen. N2 beweist
Interoperabilität der getesteten Stock-Apps, nicht die Durchsetzung sämtlicher
zusätzlicher strikter Datei-/X509-Profilregeln durch Stock-OpenSSL allein.

N5 ist bereits im Integrationsvertrag dokumentiert: Bei expliziter Freigabe
beider Gruppen kann ein Raw-first-Client Raw erhalten; Hybrid wird durch
serverseitiges Weglassen von Raw erzwungen. OpenSSLs eingebaute DEFAULT-
Gruppenliste bleibt unverändert.

Ein anschließender lesender Codex-Security-Deep-Scan ist als gesonderter
Schritt vorgeschlagen, mit exakt diesem Ziel:
/home/martin/Dokumente/ED301/ed301/provider

Nicht das Basisverzeichnis /home/martin/Dokumente/ED301 und nicht der gesamte
Repository-Baum. Keine automatische Scope-Erweiterung oder Reparatur.
Scanumfang und Start bleiben eine gesonderte Entscheidung. Ein solcher Scan
ersetzt weder die vorstehenden Integrationstests noch die spätere Prüfung
von RPM-Installation, Aktivierung, v1/v2-Migration und Rückfallverhalten.
