# Phase-D-Funktions- und Testinventur

Stand: 10. September 2026. Die anfängliche Planung bleibt im Start-Snapshot erhalten;
die folgenden D1-Zeilen spiegeln die inzwischen gemessenen lokalen Ergebnisse.
Dies ist die Arbeits-/Abnahmematrix, kein bereits bestandener Gate-D-Bericht.

## Gebundene Quellen und Entscheidungen

- Ed301-v1: Commit 5c688206a15f6ab88a50d53fe503665a302cec4d in
  /home/martin/Dokumente/ED301/ed301-eddsa-github.
- X301-Provider-/Hybrid-Bezugsstand: Commit
  569dc4ff10e0e5e19d106cbe490d2a5aaeac935e in
  /home/martin/Dokumente/ED301/x301-integration.
- Strikter X301-Rust-API-/Leiterdonor:
  /home/martin/Dokumente/ED301/x301-github/crates/x301.
  Dieser lokale Baum hat keinen Git-Commit; sein vollständiger Quellstand wird
  vor der Übernahme separat per Dateimanifest/Archiv gebunden. Er besitzt nur
  die dokumentierten alten Smoke-Ergebnisse, keine auf v2 übertragene Freigabe.
- Normativ ist Martins Fassung 2 in
  /home/martin/Dokumente/ED301/ed301/phase-b/inputs/X301-v2_EINGABEVERTRAG_2026-09-10.md,
  SHA-256 b33d3fe0bf6b5b026192695902902f4b7592d4271ca98161f47920b47c6a1c2c.
- Parameter/Vektoren stammen ausschließlich aus den freigegebenen Gate-A/B-
  Dateien im aktuellen Repository. Die Ed301-Produktquellen sind durch Gate C
  an Commit 0be31f50cccf3d5af4675d081661ea463c575027 gebunden.

## D1: X301-Rust-Kern

| ID | Öffentlicher Weg / Eigenschaft | Positiver Nachweis | Negativer Nachweis | Aktueller v2-Stand |
|---|---|---|---|---|
| X01 | Raw Public / Shared / x301 | 7 Schlüssel, 4 DH-Paare, 24 Hauptkurven-/Twistauswertungen aus Gate B | 33 Fehlerfälle ohne Teilausgabe | implementiert; D1-Korpustests bestanden |
| X02 | Secretimport und wiederverwendbarer Besitzer | Originalbytes bleiben exportierbar; gültige Clamp-Aliase gleich | falsche Länge und alle 64 Nt-Aliase vor Arithmetik | implementiert; D1-Korpustests bestanden |
| X03 | Publicimport und wiederverwendbares Peerobjekt | strikt kanonische Hauptkurven-/Twist-u | Länge, u>=p, Bits 301..303; keine Maskierung/Reduktion | implementiert; D1-Korpustests bestanden |
| X04 | KeyGen mit fallibler Zufallsquelle | unabhängige 38-Byte-Ziehungen; deterministischer Testlieferant | nur WeakSecret wird erneut gezogen; RNG-/interner Fehler endet | implementiert; D1-Korpustests bestanden |
| X05 | Feste Montgomery-Leiter | 301 Runden, A24-minus, Gate-B-Kette bis 1000 | führende Nullbits im internen Test; Fehler vor Runde 1 bzw. erst nach voller Leiter klar getrennt | implementiert; D1-Korpustests bestanden |
| X06 | Fehlerreihenfolge | Secret wird vor Peer-u validiert | ungültiges Secret zusammen mit ungültigem u verdeckt Secretfehler nicht | implementiert; D1-Korpustests bestanden |
| X07 | Zeroisierende Secret-/Shared-Besitzer | Borrow-API, Normalreturn und Unwind | keine implizite Copy-/Debug-Ausgabe; Taint bleibt am Shared-Output | implementiert; D1-Korpustests bestanden |
| X08 | Kryptographische Implementierungsgates | no_std/Safe Rust, Oracle-/Grenztests, Taint, finales ELF, dudect | positive Instrumentkontrollen; unerlaubter Codegen wird erkannt | lokale Gates bestanden; keine Gate-D-Freigabe |
| X09 | Performance/Ressourcen | vergleichbare Rust- und EVP-Lanes, kalte/vorbereitete Schlüssel, Größen/Stack/RSS | keine erfundene Regressionsschwelle, keine Ebenenmischung | 44 Zeitfälle und Ressourcenmessungen im D1-Bericht |

Der alte strikte Rust-Donor substituiert Nt und verwirft erst nach der Leiter.
Das wird nicht übernommen: Gate B und Martins Präzisierung verlangen die frühe
Secretablehnung. Der Integrationsdonor maskiert/reduziert u und verkürzt die
feststehenden Randbits der Leiter; auch diese Erwartungen gelten nicht für D1.
Die mathematischen Leiterformeln bleiben die bekannte A24-minus-Konstruktion.

## D2: Provider, Formate und Integration

| ID | Bereich / Buildvariante | Öffentlicher positiver Weg | Negativ-/Lifecycle-Abdeckung | v2-Stand / Entscheidung |
|---|---|---|---|---|
| E01 | Ed301-Rust-Kern und Contexts | Public API, Schlüsselobjekte, 54 Tests und unabhängiger Gate-C-Vergleich | Längen, Domain, Torsion, S+q, v1-Trennung | Gate C bestanden; unverändert |
| E02 | Ed301 ordinary KEYMGMT/SIGNATURE | EVP KeyGen, Import/Export, Sign/Verify, Größenabfrage | Context 256, falsche Typen/Längen, Fehler ohne Ausgabe | nicht implementiert |
| E03 | Ed301 PKI-Testmodul | PKCS#8/SPKI DER/PEM und verschlüsseltes PKCS#8 aus frischem CLI-Prozess | ASN.1-Version 1/Attribute nicht still ergänzen, falsche Kennung | nicht implementiert; neue OID offen |
| E04 | Ed301 TLS-Integrationsmodul, echte Decoder | DER-Decoder und generische PEM-/Decrypt-Ketten, BIO-Eingänge | Trunkierung, Restbytes, nichtkanonisches DER, Retry-/Fehler-BIO | nicht implementiert; neue OID offen |
| E05 | Ed301 Text/PKCS#10/PKCS#12/Chain/CRL | öffentliche OpenSSL-/CLI-Wege, Zertifikatsprüfung | falscher Schlüssel, Signaturfehler, Widerruf, Containerfehler | nicht implementiert |
| E06 | Ed301 TLS-Signaturprofil und Collider | echter TLS-1.3-Handshake mit geprüftem Peer | Kollision, falscher Codepoint, fehlender/zu spät geladener Provider | nicht implementiert; Codepoint offen |
| X10 | X301 KEYMGMT | EVP KeyGen/Raw Import/Export/Dup/Match | strikter Vertrag, getrennte Versionen, fehlerhafte Params | nicht implementiert |
| X11 | X301 KEYEXCH | Setup, erster/wiederholter Derive, Reinit und Peerwechsel | Größenabfrage, kleiner Puffer, All-zero, fehlender/falscher Peer, keine Teilausgabe | nicht implementiert |
| X12 | X301MLKEM1024 KEYMGMT/KEM | Encaps/Decaps, neue parameterabhängige KATs | Komponenten-/Längenfehler, implizite ML-KEM-Rejection, Propquery-Vererbung | nicht implementiert |
| X13 | X301-/Hybrid-TLS-Gruppen | echte Handshakes, HRR, Fragmentierung, Resumption, Datenverkehr | keine gemeinsame Gruppe, falsche Keyshare-/Ciphertextlängen, Versionskollision | nicht implementiert; Raw-TLS-Auswahl/Codepoints offen |
| X14 | X301 persistente Formate | nach ausdrücklich bestimmtem Container-/OID-Vertrag | echte Decoderketten und strikte Ablehnung | im Integrationsbestand nicht vorhanden; zusätzliche Funktion noch zu konkretisieren |
| G01 | Laden/Entladen, Libctx-/Thread-Lebensdauer | private Testkontexte, wiederholte Nutzung, parallele getrennte Contexts | Failure injection, Use-after-free-/Leck-Kontrollen, Rand-Ausfälle | nicht implementiert/getestet |
| G02 | Schlüsseltrennung und Wiederverwendung | getrennte v1/v2-Objekte und Anbieterkennungen | kein stilles Umdeuten von v1-Containern/Codepoints | Kennungen/OIDs/Codepoints teilweise offen |
| G03 | Provider-Build-/Toolchainmatrix | vorhandene OpenSSL-/Architektur-Lanes einzeln inventarisieren und neu bauen | Version/ABI/Compilerabweichung fail-closed | nicht getestet; C-Gates sind keine DSO-Gates |
| G04 | Provider-CT/Taint/Timing/Sanitizer | tatsächliche finale DSO und EVP-Pfade | positive Kontrollen, ASan/UBSan/Valgrind und Failpoints | nicht getestet |
| G05 | Gemeinsame Ed301/X301-Integration | Anbieter vor SSL_CTX-Erzeugung in demselben privaten Libctx; echter Datenaustausch | fehlende Provider, Kollisionen, kein stiller Fallback | nicht implementiert/getestet |

„Nicht implementiert“, „nicht getestet“ und „außerhalb des Profils“ werden nicht
gleichgesetzt. Insbesondere sind fehlende X301-Dateicodecs eine sichtbare Lücke,
keine bereits erfüllte Parität. CMS/OCSP und OneAsymmetricKey-Version 1 werden
nicht allein aufgrund der Paritätsforderung zu neuen Ed301-Anforderungen.

## Bestehende Test-Einstiegspunkte

Ed301:

- /home/martin/Dokumente/ED301/ed301-eddsa-github/PROVIDER_STATUS.md
- /home/martin/Dokumente/ED301/ed301-eddsa-github/provider-tests/provider_keymgmt.c
- /home/martin/Dokumente/ED301/ed301-eddsa-github/provider-tests/provider_signature.c
- /home/martin/Dokumente/ED301/ed301-eddsa-github/provider-tests/provider_serialization.c
- /home/martin/Dokumente/ED301/ed301-eddsa-github/provider-tests/val01_decoder_bio.c
- /home/martin/Dokumente/ED301/ed301-eddsa-github/provider-tests/provider_pki.c
- /home/martin/Dokumente/ED301/ed301-eddsa-github/provider-tests/provider_tls.c
- /home/martin/Dokumente/ED301/ed301-eddsa-github/provider-tests/provider_lifecycle.c
- /home/martin/Dokumente/ED301/ed301-eddsa-github/scripts/test-provider.sh

X301:

- /home/martin/Dokumente/ED301/x301-github/crates/x301/tests/normative_vectors.rs
- /home/martin/Dokumente/ED301/x301-github/crates/x301/tests/python_differential.rs
- /home/martin/Dokumente/ED301/x301-integration/provider-tests/x301/provider_x301_contract.c
- /home/martin/Dokumente/ED301/x301-integration/provider-tests/x301/provider_x301_hybrid_contract.c
- /home/martin/Dokumente/ED301/x301-integration/provider-tests/x301/provider_x301_nested_properties.c
- /home/martin/Dokumente/ED301/x301-integration/provider-tests/x301/provider_x301_secret_taint.c
- /home/martin/Dokumente/ED301/x301-integration/scripts/test-x301-tls.sh

Vor dem Port eines D2-Pfads werden dessen vollständige Implementierung und Tests
gelesen und die Zeile um konkrete v2-Artefakte und Ergebnisse erweitert.
Bis dahin gibt es keine Funktionsparitäts- oder Handshake-Freigabe.
