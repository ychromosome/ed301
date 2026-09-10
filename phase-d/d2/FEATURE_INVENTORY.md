# D2-Abnahmematrix

Stand: 10. September 2026. Diese additive Fortschreibung ersetzt die D2-Planzeilen
im historischen D1-Bericht, ohne dessen Dateien zu ändern. Gate D entscheidet
Claude; ein lokaler PASS ist keine Freigabe und keine Produktveröffentlichung.

Gemeinsame Nachweiswurzel:
/home/martin/Dokumente/ED301/ED301-v2_D2-matrix_2026-09-10_06.
Die folgenden Laufnamen bezeichnen jeweils beide ABI-Lanes 3.5.8 und 4.0.2.
Exakte Dateipfade, Hashes, Befehle und Ergebnisse stehen im Nachweisindex
/home/martin/Dokumente/ED301/ed301/phase-d/d2/D2_EVIDENCE_INDEX.json.

| ID | Implementierung und positiver Nachweis | Fehler-/Lifecycle-Nachweis | Stand und Profilgrenze |
| --- | --- | --- | --- |
| E01 | Gate-C-Ed301-Kern unverändert; D1-Quellmanifest erneut geprüft | Vorherige Gate-C-Negativvektoren zusätzlich über den neuen Provider | Gate C bleibt eigenständiger historischer Nachweis |
| E02 | `functional`: KEYMGMT 73, SIGNATURE 362/372 Prüfungen; native OpenSSL-EVP-Tests; KeyGen, Import/Export, Sign/Verify | Context 255/256, Typen/Längen, Größenabfrage, Zustandswechsel, Fehler ohne Ausgabe, Observer-Negativkontrolle | implementiert und nativ bestanden; expliziter EVP-KeyGen-Weg, nicht `EVP_PKEY_Q_keygen` |
| E03 | `functional`, `cli`: PKCS#8 v0 und SPKI DER/PEM, verschlüsseltes PKCS#8, OID `.301.5` ohne Parameter | Version 1, Attribute, NULL-Parameter, alte Kennungen, falsche Passphrase und Restbytes | implementiert und bestanden; gewöhnliches Modul und PKI-Testvariante getrennt |
| E04 | `functional`: 78 Ed301-Decoderprüfungen; reale DER/PEM/Decrypt/BIO-Ketten | Trunkierung, nichtkanonisches Profil-DER, Retry-/Fehler-BIO, vollständiger Klartext und entschlüsselter Inhalt | bestanden mit verpflichtender Complete-file-Grenze; Streaming-Decoder allein ist kein EOF-Prüfer |
| E05 | `cli`: Text, CSR, CA/Leaf, Hostnameprüfung, CRL und PKCS#12; `functional`: PKI 42 Prüfungen | manipulierte CSR, falscher Schlüssel, Widerruf, falsche P12-Passphrase; zusätzliche ASan-/Valgrind-Frontendläufe | bestanden mit privaten CSR-/P12-CLI-Frontends; Stock-`req -verify` und Stock-P12-Keydump sind ausdrücklich nicht bestanden |
| E06 | `functional`, `tcp`: Ed301-CertificateVerify `0xFE85`, echte TLS-1.3-Handshakes und Peerprüfung | OID-/SIGID-/TLS-Collider, falscher Codepoint, fehlender/zu spät geladener Provider, Signaturfehler | implementiert und bestanden; private-use, nicht registriert |
| X10 | `functional`, `structured`: X301 KEYMGMT KeyGen/Raw Import/Export/Dup/Match; 802 Oracle-/Grenzfälle einschließlich 512 DH-Fälle | alle 64 WeakSecret-Aliase; Originalsecret-Export; keine u-Maskierung/-Reduktion; RNG-/Allokations-/Panikfehler | implementiert und bestanden; nur WeakSecret löst Neuziehung aus |
| X11 | `functional`, `structured`: Setup, erster/erneuter Derive, Peerwechsel, Reinit, vier Threads mit je 1000 Derives | fehlender Peer, kleiner Puffer, All-zero, veralteter Peerzustand, keine Teilausgabe; 19.762 strukturierte Raw-Fälle | implementiert und bestanden; kanonische Low-order-Publics dürfen importiert werden, DH lehnt Nullergebnis ab |
| X12 | `functional`, `structured`: OpenSSL-eigenes ML-KEM-1024, vier vollständige Hybrid-KATs mit 34 Zusicherungen; 1606/1606/70 Byte | implizite ML-KEM-Rejection, harte X301-Rejection, Propquery-Vererbung, 35.338 strukturierte Fälle, Allokationssweep | implementiert und bestanden; kein eigener ML-KEM, KDF oder persistentes Hybridformat |
| X13-Hybrid | `tcp`: `0xFE2F`, Ed301-Zertifikat, HRR, Fragmentierung, Resumption, KeyUpdate, Exporter, bidirektionale Nutzdaten | fehlende Anbieter, falsche Version/Gruppe/Keysharelänge; `functional` zusätzlich 21 TLS-Längenprüfungen | bestanden; einzige Gruppe der expliziten Integrations-Standardpolicy |
| X13-Raw | `tcp`: explizites `X301`, `0xFE30`, 38-Byte-Keyshares, HRR/Resumption/Nutzdaten | Raw-only-Peer ohne ausdrückliche Raw-Auswahl wird in beiden Rollen nicht als Raw ausgehandelt | bestanden; experimenteller Messpfad ohne ML-KEM-Schutz; Stock-OpenSSL-DEFAULT bleibt unverändert |
| X14 | `functional`, `cli`: X301 PKCS#8 v0/SPKI DER/PEM/verschlüsselt unter `.301.6`; 52 Serialisierungs- und 207 Decoderprüfungen | Originalsecret statt Clamp; strikte Version/Attribute/OID/Parameter/DER-/Dateigrenzen einschließlich verschlüsseltem Innenobjekt | neu implementiert und bestanden; keine v1-Codec-Parität behauptet, da dort nicht vorhanden |
| G01 | `functional`, `memory`: Laden/Entladen, getrennte private Libctx, gemeinsam genutzte unveränderliche Schlüssel, Threads, fallible Besitzer | RNG-/Panik-/Allokationsausfälle; Memcheck und C-ASan/UBSan; Wiederherstellung nach Fehlern | nativ bestanden; Sanitizerinstrumentierung und vollständige Prozessprüfung getrennt ausgewiesen |
| G02 | `legacy_builds`: tatsächlich gebundene v1-Module, 20 Loader-Policy- und 18 Wire-Version-Prüfungen in getrennten Kontexten | alte OIDs/Signaturen/Codepoints, kein Cross-Version-Handshake, kein stilles Umdeuten | bestanden für kontrollierte Anwendung; Loaderpolicy ist kein globaler OpenSSL-Interposer, Rohseeds sind nicht selbstbeschreibend |
| G03 | `functional`, `controls`: neun frische Varianten je ABI; vier ordinary/TLS-DSOs unabhängig byteidentisch nachgebaut; Offline-/Profil-/Runtimebindung | manipulierte Quellen/Seals/Prefixe, falsche Header/ABI/Libraries/Compilerprofile, C-Analysen | native x86-64-Matrix bestanden; neue AArch64-DSOs nicht gebaut oder geprüft, alte ARM-Ergebnisse nicht übertragen |
| G04 | `memory`, `codegen`, `timing`: tatsächliche DSO-/EVP-Wege, instrumentierte Eingangsecrets, kritische Mathematik-/Zeroize-Symbole, dudect | positive Taint-/Timing-/Codegen-Kontrollen; Fehler bleiben sichtbar; Statistik über alle Batches | Ergebnisse ausschließlich laut versiegelten Receipts; keine universelle CT-Aussage und keine unabhängige ML-KEM-CT-Zertifizierung |
| G05 | `tcp`: je ABI 95 Zusicherungen mit Ed301-PKI und X301-Hybrid/Raw im selben privaten Libctx, frische Schlüssel, localhost:0 | Hostname/CA/Zertifikat/Signatur/fehlende Provider, kein stiller Fallback | implementiert und bestanden; kein externer Endpunkt, keine Systemaktivierung |

Die Leistungsmessungen führen Rust-Kern, EVP-Signatur, EVP-XDH, EVP-KEM,
Encoder/Decoder und TLS-Engine getrennt. TLS-Engine-Zeit ist kein TCP-Latenzwert.
D1-Optimierung, RPM-Bau, Installation, Policy-Aktivierung, Push und Veröffentlichung
bleiben außerhalb dieses Standes. CMS/OCSP, OneAsymmetricKey v1 und generische
ASN.1-/PBE-Policy-Erweiterungen sind ebenfalls nicht Bestandteil des Profils.
