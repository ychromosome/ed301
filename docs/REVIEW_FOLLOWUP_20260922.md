# Bearbeitung des externen Reviews vom 22. September 2026

Ausgangsstand: Testing `698848712662564c91015002522e242ff8c2f690`.
Das [Originalreview](../phase-e/reference/grok_20260922/ed301-security-review.md)
ist unverändert erhalten. Kurvenparameter, Kryptokerne und Decoder wurden
nicht geändert.

| Befund | Bearbeitung |
| --- | --- |
| AArch64-SHA3-Backend | Quellbeobachtung bestätigt; der öffentliche CPU-Schalter belegt keinen geheimnisabhängigen Seitenkanal. Die aktuelle [Backend-Dokumentation](../rust/README.md#hash-backends-and-platform-coverage) nennt beide AArch64-Pfade und die begrenzte x86-64-Abdeckung. Kein erzwungener Backendwechsel. |
| PKCS#8 mit 2048 Runden | Gehärtet: Standard jetzt 1.000.000 PBKDF2-Runden, einstellbar über `curve301-pbkdf2-iterations`. Beide Algorithmen verwenden denselben validierenden Encoder. |
| RAND im Kindkontext | Konfigurationsgrenze bestätigt, [dokumentiert](INTEGRATION.md#randomness-configuration) und mit eigenen Läufen belegt. Automatische Übernahme der Eltern-RAND-Konfiguration wurde nicht hinzugefügt; die für sichere Lebensdauern eingeführten Provider-DRBGs bleiben erhalten. |

## Passwortkosten und Kompatibilität

Der neue Parameter akzeptiert explizit 1 bis 10.000.000 Iterationen. Ungültige
Werte sperren die Ausgabe, auch nach einem nachfolgenden Cipher-only-Update.
Eine gültige Kostenangabe stellt diesen Teil des Zustands wieder her, heilt
aber keinen zuvor ungültigen Cipher. Niedrigere Kosten sind eine ausdrückliche
Entscheidung der Anwendung. Bereits gespeicherte Dateien werden nicht verändert.

Die Richtgröße von einer Million ist ein gemessener Projektstandard, keine
allgemeine Passwortgarantie. Zum Vergleich empfiehlt OWASP für
PBKDF2-HMAC-SHA256 mindestens 600.000 Runden im Passwortspeicherungskontext;
OpenSSL dokumentiert `pkcs8 -iter` für ausdrücklich gewählte Kosten.
[OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html),
[OpenSSL](https://docs.openssl.org/4.0/man1/openssl-pkcs8/).

In 16 nativen Exportbeobachtungen je ABI lag der Median auf dem Ryzen 9 5950X
bei ungefähr 119 ms beziehungsweise 124 ms. Dies sind vollständige Exporte,
keine isolierten KDF-Benchmarks oder Kostenprognosen für andere Rechner.

## Prüfungen

- Je OpenSSL-Version 147 funktionale Schritte bestanden, einschließlich
  20 Ed301- und 7 X301-Provider-Rusttests, Clippy und Dokumentationsbau.
- Je ABI neun Provider-Varianten gebaut; vier Ordinary-/TLS-Module aus
  getrennten Buildverzeichnissen bytegleich erneut erzeugt.
- Je ABI 119 Speicher-/Taint-Schritte bestanden, darunter je 26 C-ASan/UBSan-
  und 26 Whole-Process-Memcheck-Aufrufe. Private-Export- und X301-Taint-Läufe
  sowie die erwarteten Positivkontrollen bestanden ebenfalls.
- Abschließend je Algorithmus und ABI 78 Passwortpolicy- und 13 RAND-Prüfungen
  bestanden. Die Passwortprüfungen lesen die tatsächlichen ASN.1-Parameter
  für DER/PEM und beide privaten Strukturen in PKI- und TLS-Modulen.
- Vier mit den alten Providern frisch erzeugte 2048-Runden-Dateien durch beide
  neuen ABI-Lanes entschlüsselt: acht Importe erhalten die ursprünglichen
  kanonischen 62 privaten DER-Bytes exakt.

Der RAND-Kontrollfall setzt im Elternkontext einen nicht verfügbaren DRBG:
Eltern-RAND schlägt fehl, direkte Ed301-/X301-Erzeugung und PKCS#8-Salt/IV im
Kindkontext funktionieren weiter. Eine nicht verfügbare Seed-Quelle allein
führt in der verwendeten 3.5.8-Lane noch zu erfolgreichem Eltern-RAND, in 4.0.2
zum Fehler. Dieses OpenSSL-Verhalten wurde getrennt protokolliert. Über die
delegierten ML-KEM-RAND-Verbraucher wird daraus keine pauschale Aussage abgeleitet.

## Review und Evidenzgrenze

Die unabhängige Vorprüfung bestätigte die gemeinsamen Eingangsgrenzen. Das
anschließende Patch-Review fand einen Dokumentationsfehler zum Cipher-Reset:
nur `PrivateKeyInfo` kann dadurch unverschlüsselt ausgegeben werden;
ausdrückliches `EncryptedPrivateKeyInfo` muss ohne Cipher scheitern. Der Text
ist korrigiert und beide Ausgabeformate erhielten zusätzliche Negativtests.
Weitere konkrete Laufzeitfehler wurden in diesem Review nicht benannt.

Maßgeblich sind `run-02`, `focused-final` und `legacy-containers-02`; der
[Evidenzindex](REVIEW_FOLLOWUP_20260922.json) bindet ihre Nachweise. Nach dem
vollständigen Snapshot änderten sich nur die Reset-Dokumentation und vier
zusätzliche Kontrollen pro Algorithmus/ABI im Passwort-Testharness. Die
Produktquellen blieben bytegleich. Die anfänglichen Harness-Annahmen und
fehlgeschlagenen Vorläufe sind separat erhalten und zählen nicht als bestanden.

Plattform: x86-64, Rust 1.98.1 / LLVM 22.1.8, kontrollierte OpenSSL-Lanes 3.5.8
und 4.0.2. Diese Läufe ersetzen weder AArch64-Abnahme noch die historische
LLVM-21-Codegen-Policy, neue Timing-Messungen oder RPM-Binärabnahme. Die
historischen, hashgebundenen E8-Berichte bleiben unverändert.
