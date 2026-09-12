# E8: vier Review-Nacharbeiten abgeschlossen

Stand: 11. September 2026. Ausgangscommit:
a81eeb526579c6e8066183919a7e488bb56eeba7 auf Testing.

Ergebnis: Werkzeugvorprüfung, Dokumentationshinweise, Compilerbindung und
gezielte private Export-/Encoder-Taint-Erweiterung umgesetzt und geprüft.
Kein neuer kryptografischer Defekt beobachtet. Keine Änderung der
Kryptografie oder Provider-Laufzeitimplementierung, keine neue Optimierung.

Claudes Gate-E-Entscheidung bleibt als gelieferte Prüferentscheidung erhalten;
dieser Nachtrag ist kein neues vollständiges Gate E und keine Freigabe von
Stufe 2. N2/N4/N5, RPMs, Installation, Aktivierung und Veröffentlichung sind
nicht Teil dieser Nacharbeiten. Keine neue Performanceaussage wird abgeleitet.

## 1. GNU awk

Die X-Profile verlangen /usr/bin/gawk bereits vor Eingangsdatenprüfung,
Erstellung eines Belegordners und Disassemblierung. Die Ed-Profile erhalten
keine zusätzliche GNU-awk-Abhängigkeit. Die Abhängigkeit und strtonum-Nutzung
stehen ausdrücklich in der Codegen-Policy.

Dateien:
- /home/martin/Dokumente/ED301/ed301/phase-e/tools/check_codegen.sh
- /home/martin/Dokumente/ED301/ed301/phase-e/tools/test_codegen_prerequisites.py
- /home/martin/Dokumente/ED301/ed301/phase-e/CODEGEN_POLICY.md

Drei isolierte Prüffälle mit insgesamt sechs Profilkombinationen bestehen:
fehlendes GNU awk unter x-core/x-provider ergibt Exit 127; fehlendes GNU awk
blockiert die Ed-Profile nicht; vorhandenes Werkzeug lässt die X-Profile zur
regulären Eingabeprüfung weiterlaufen. Jeder Fall prüft, dass kein Belegordner
und kein PASS entstehen. Nur eine disposable Treiberkopie verwendet dafür
einen synthetischen Werkzeugpfad; kein Systemwerkzeug wird entfernt/versteckt.

## 2. Historische Prüfer und aktuelle Einstiege

Die READMEs nennen die konkreten historischen C-/D1-/D2-Commits, erklären
den 54-Test- beziehungsweise unveränderte-C-Quellen-Gate und verweisen auf
den gemeinsamen aktuellen Phase-E-Korrektheitsrunner. Die Voraussetzungen
für --baseline und --previous sowie für vollständige authentifizierte
OpenSSL-Lane-Receipts sind beschrieben. Ein beliebiger eigener
OpenSSL-Installationsprefix erfüllt diese historische Quellenbindung nicht.

Geänderte READMEs:
- /home/martin/Dokumente/ED301/ed301/phase-c/README.md
- /home/martin/Dokumente/ED301/ed301/phase-d/README.md
- /home/martin/Dokumente/ED301/ed301/phase-d/d2/README.md
- /home/martin/Dokumente/ED301/ed301/phase-e/README.md

Historische Prüfer, Manifeste und Archive wurden nicht umgeschrieben.

## 3. Compilerbindung

Die Codegen-Policy benennt Fedora Rust 1.98.0 / LLVM 21.1.8 und das
geprüfte x86-64-Release-Profil. Der externe LLVM-22-Unterschied
(vier statt acht memcpy, kein _Unwind_Resume im betreffenden Ed-Symbol)
wird erklärt, aber nicht pauschal akzeptiert. Ein anderer Compiler benötigt
eine eigene Binärabnahme samt passenden geprüften Regeln und Gegenproben.
Keine arithmetische Allowlist oder Negativkontrolle wurde gelockert.

## 4. Privater Export und PKCS#8-DER

Erweiterter Harness:
/home/martin/Dokumente/ED301/ed301/provider-tests/provider_secret_taint.c

Abgedeckte Grenzen:
- EVP_PKEY_get_raw_private_key, einschließlich Längenabfrage;
- privater EVP_PKEY_get_octet_string_param;
- tatsächlicher KEYMGMT-Export über EVP_PKEY_todata, sowohl private-only
  als auch keypair; der getrennte Public-Key-Parameter bleibt definiert;
- PKCS#8-DER über OSSL_ENCODER_to_data und OSSL_ENCODER_to_bio mit Memory-BIO,
  jeweils private-only und keypair;
- direkter Encoder im instrumentierten PKI-Provider sowie die reale
  KEYMGMT-Export-/Encoder-Import-Brücke vom instrumentierten Normalprovider
  zum instrumentierten PKI-Provider.

Die Brücke darf den separat ausgegebenen öffentlichen Schlüssel regulär
parsen. Sie wird nicht fälschlich insgesamt als öffentlicher Pfad klassifiziert.
Der private Seed bleibt getrennt und taint-markiert; ein geheimer Eingang
in den öffentlichen Parser würde an dessen vorhandener Diagnosegrenze
nicht akzeptiert.

Der Harness prüft V-Bits vor EVP-Import, auf privaten Roh-/Parameterausgaben,
auf allen 38 privaten DER-Nutzbytes und auf dem ursprünglichen Seed nach
dem Export. Die 24 Präfixbytes müssen definiert bleiben. Vor dem Vergleich
mit dem bekannten Testvektor wird ausschließlich eine getrennte
Harness-Vergleichskopie definiert, niemals die Providerdaten oder die
eigentliche private Ausgabe. Anschließende öffentliche Ausgabe und zwei
deterministische Signaturen stimmen weiter mit dem bestehenden Vektor überein.

Zusätzliche Positivkontrollen verwenden ein Bit der tatsächlichen noch
taint-markierten DER-Ausgabe für einen absichtlich datenabhängigen
Harness-Zugriff. Pro Kontrollprozess werden alle vier DER-Ausgabevarianten
erreicht; Memcheck muss Exit 99 melden. Es werden ausschließlich feste
öffentliche Testvektoren verwendet, keine Produktivschlüssel.

Der reguläre vollständige Memory-Runner baut künftig auch die
instrumentierte PKI-Variante und führt diese neuen Pfade/Kontrollen aus:
/home/martin/Dokumente/ED301/ed301/phase-d/d2/tools/run_memory.py

## Ausgeführte gezielte Prüfung

Neu eingefrorene Quelle, 1950 Dateien:
/home/martin/Dokumente/ED301/ED301-v2_E8_followup_01_2026-09-11/source

Quellmanifest SHA-256:
ccfda9c000dc0ec32b0b62ec54faac893fd08169fa8a7e1c96b242dd26c2b369

Fokussierter Controller:
/home/martin/Dokumente/ED301/ed301/phase-e/tools/run_review_followup.py

Je OpenSSL 3.5.8 und 4.0.2:
- zwei neue instrumentierte Ed-DSOs: Normal und PKI, inklusive Profilprüfung;
- C-Harnesses mit GCC -O2 -Wall -Wextra -Werror frisch gebaut;
- sechs reguläre definierte/tainted Prozessläufe: Normal, PKI-direkt,
  Normal-zu-PKI-Brücke; alle Exit 0;
- drei Positivkontrollläufe: allgemeine Instrumentierung, DER-direkt und
  DER-Brücke; alle erwarteter Exit 99;
- sechs unveränderte gebundene E8-ELFs mit neuem Abhängigkeits-Preflight
  und den vollständigen bisherigen Codegen-Regeln erneut geprüft: PASS.

Insgesamt zwölf reguläre Taint-Prozesse, sechs erkannte Kontrollprozesse,
zwölf Codegen-Replays und vier neue Diagnose-DSOs. Die regulären Encoderläufe
prüfen zusammen 32 DER-Ausgaben, davon 16 mit taint-markiertem privaten Seed.
Drei Werkzeugvorprüfungstests, Shell-Syntax, Python-Syntax und git diff --check
bestehen. Beide Receipts enthalten jeweils 27 protokollierte Befehle.

| ABI | Receipt-Manifest SHA-256 |
| --- | --- |
| 3.5.8 | 1872b154b4643bf258e9d2effd958ea0a7e423b6862d84296e5a103575a266ce |
| 4.0.2 | fdf6c8d3e95d1efac3ef643ac444055c6269432e19dde9209953ccafcd79874a |

Vollständige Befehle, Umgebungen, Logs, Profile und neue Diagnose-Binaries:
- /home/martin/Dokumente/ED301/ED301-v2_E8_followup_01_2026-09-11/followup-3.5.8
- /home/martin/Dokumente/ED301/ED301-v2_E8_followup_01_2026-09-11/followup-4.0.2

Maschinenlesbarer Index:
/home/martin/Dokumente/ED301/ed301/phase-e/E8_REVIEW_FOLLOWUP_INDEX.json

1656 Dateien aus Rust, Provider und Vektoren wurden byteweise gegen die
freigegebene E8-Quelle verglichen. Der gesamte kompilierte Eingabesatz besitzt
unverändert SHA-256
1a2e43552e6aa794c97f2c82ebfa1e70ca6be1e2a31bc8ed7d69c68e12b0f1e2.
Die neuen Taint-DSOs sind Diagnose-Builds, keine neuen Ordinary-Laufzeitmodule.

## Abgrenzung und bestehende Nachweise

Der volle ASan-/UBSan-/CLI-/TCP-/Benchmark-/dudect-Gate wurde nicht erneut
ausgeführt. Die neue Memory-Runner-Verdrahtung wurde statisch geprüft; ihre
neuen Build-/Taint-Pfade wurden durch den fokussierten Controller ausgeführt.
Der Codegen-Replay betrifft die originalen E8-Ordinary-/TLS- und Core-ELFs,
nicht eine behauptete vollständige Abnahme aller neuen Diagnose-DSOs.

PEM/Base64, passwortbasierte PKCS#8-Verschlüsselung, sämtliche möglichen
Allokationsfehler sowie ein universeller Seitenkanal- oder Löschbeweis sind
nicht Teil der neuen Taint-Aussage. Die zusätzlichen Kontrollen erweitern
gezielt den bisher nur statisch belegten privaten Export-/DER-Pfad.

Das ursprüngliche E8-Archiv bleibt bytegleich:
/home/martin/Dokumente/ED301/ED301-v2_GATE_E_E8_2026-09-11.tar.zst

SHA-256:
e6d637af6b869d02e866e6190876dbd3ef801cb21d50a63d5f8aa6bc2e08085c

Es bindet weiterhin a81eeb5 und seine damaligen Quellen, nicht die späteren
README-/Harnessänderungen. Der neue vollständige Commit-Inhalt wird separat
gebunden; alte Manifeste müssen dafür nicht auf aktuelle Dateien umgedeutet
werden. Diese Nachweise sind eine lokale Ergänzung, kein neues eigenständig
relokierbares Vollarchiv. Die zuvor authentifizierten E8-OpenSSL-Lanes und
ELFs bleiben benannte Eingaben der beiden neuen Receipts.

Neue Manifestdatei:
/home/martin/Dokumente/ED301/ed301/phase-e/E8_REVIEW_FOLLOWUP_SOURCE_MANIFEST.sha256

Claudes unveränderte Bewertung und Gate-E-Entscheidung sind als Referenzen
erhalten:
- /home/martin/Dokumente/ED301/ed301/phase-e/reference/e8_followup/CLAUDE_REVIEW_ACTIONS.md
- /home/martin/Dokumente/ED301/ed301/phase-e/reference/e8_followup/CLAUDE_GATE_E8.md
