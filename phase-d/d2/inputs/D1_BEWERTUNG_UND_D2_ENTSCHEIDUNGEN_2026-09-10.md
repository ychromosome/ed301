# D1-Bewertung und D2-Entscheidungen (Claude für Emmy, 10. September 2026)

Bezug: Testing-Commit `67f2910e7697cdab782cc992e44dc28843f93970`, Bericht `phase-d/D1_REPORT_2026-09-10.md`, gemessenes X301-v2-ELF `143a381846d57e371f546548de250abc2d92a887cacaf286ccda29c74938d6c7`.
Dies ist eine Zwischenbewertung von D1, keine Gate-D-Freigabe. Gate D steht am Ende von Phase D für den gesamten Provider-/Format-/TLS-Stand.

## 1. D1: bestanden aus meiner Sicht

Eigene Prüfungen (Werkzeuge und Ausgaben unter `/home/martin/Projekte/Claude/OpenSSL-Fork/review/ed301-v2-curve-search-2026-09-09/gate_c/d1/`, Manifest `gate_c/SHA256SUMS`):

- **Differentialtest gegen meine eigene affine Montgomery-/Twist-Implementierung aus Gate B** (kein Leiteralgorithmus, keine Referenz von Emmy): 296 Zeilen über die öffentliche API `x301`, `public_from_secret`, `SecretKey`/`PublicKey`/`shared_secret`. 42 Public-Ableitungen, 60 DH-Paare in beiden Richtungen, 40 zufällige u (Kurve und Twist), u ∈ {0, 1, p−1} → `AllZeroSharedSecret`, u ≥ p und reservierte Bits 301/302/303 → `NonCanonicalPublic`, Längen 0/37/39 → `InvalidPublicLength`, Secret 37/39 → `InvalidSecretLength`, alle 64 N_t-Aliase (× gültiges und ungültiges u) → `WeakSecret` vor jeder u-Verarbeitung, Iterationskette bis 1000 gegen die Gate-B-Kontrollpunkte. **296/296 identisch**, Objekt-API und Einmal-API stimmen in jeder Zeile überein.
- **Eigener Crate-Testlauf** in frischer Kopie: 25/25. `phase-d/D1_SOURCE_MANIFEST.sha256` im Checkout mit `sha256sum --check` bestätigt.
- **Eigener Disassembly-Scan des gemessenen ELF**: `ladder301` hat genau einen Rückwärtssprung (die 301er-Schleife), 130 cmov, keine Division, einen `memcpy`-Aufruf vor der Schleife (Initialzustand), keinen Aufruf in der Schleife. `multiply` hat zwei feste safegcd-Schleifen und einen Vorwärtssprung auf dem deklassifizierten Nullergebnis-Flag. `SecretKey::from_bytes` hat zwei Vorwärtssprünge: Längenprüfung und deklassifiziertes WeakSecret-Flag. Das entspricht dem Vertrag; die variable Logik liegt ausschließlich in den veröffentlichten Statusgrenzen.
- **Codelesung** `x301.rs`: Clamp `[0] &= 0xfc`, `[37] = ([37] & 0x0f) | 0x10`; N_t-Ablehnung per Bibliotheksvergleich vor u-Dekodierung; strikte u-Dekodierung (Länge, u ≥ p, Bits 301–303) über den geprüften Phase-C-Decoder ohne Maskierung; A24-minus-Leiter mit 301 Runden und Swap-Nachführung; Nullprüfung auf z und auf dem affinen Ergebnis nach der vollen Leiter; Secretfehler vor Peerfehler; exportiertes Secret sind die Originalbytes; zeroisierende Besitzer für Raw/Clamp/Leiterzustand/Ausgabe; KeyGen zieht nur bei WeakSecret neu. Keine Eigenentwicklung neben Feld, Big-Int und zeroize.

Kein Befund über "niedrig". Niedrig: Der Bericht nennt 110 cmov in der Leiter, mein Zähler findet 130 über das ganze Symbol; das ist eine Zählregel, keine Abweichung im Code.

## 2. Leistung: 80 µs sind erklärbar und nicht der Endstand

301 Runden × (6 Multiplikationen + 4 Quadrierungen + Additionen) in kanonischer Arithmetik ≈ 265 ns pro Runde. Die Multiplikation mit A24 ist eine volle Feldmultiplikation, weil A für diese Kurve nicht klein ist; das bleibt so. v1 war schneller, weil Public über die Edwards-Festbasistabelle lief (27 µs) und die Leiter in der Lazy-Domäne rechnete (56 µs).

Optimierungspfad für einen späteren, gesondert zu prüfenden Stand (neue Korrektheits-, Taint-, Codegen- und Timing-Gates nötig):

1. Public über `scalar_mul_base` des Ed301-Kerns und u = (1+y)/(1−y) mit einer Inversion: erwartbar ≈ 27–30 µs wie v1.
2. Leiter in der Lazy-Domäne (`Fe301Lazy::mul`/`square`, `add_loose`/`sub_loose`, Tighten nur wo nötig): erwartbar −15 bis −20 % für Shared.
3. Keine weiteren Tricks: kein Verkürzen der Leiter, keine Maskierung von u, keine Änderung der Fehlerreihenfolge.

Empfehlung: D1 als funktionale Basis so belassen, erst D2 (Provider/Formate/TLS) bauen, Optimierung als eigene Stufe danach.

## 3. D2-Entscheidungen (Martin hat entschieden; hier die Spezifikation)

### 3.1 OIDs und TLS-Codepoints

- OIDs: `1.3.6.1.4.1.66282.301.5` = Ed301-EdDSA-v2 (Schlüssel- und Signaturalgorithmus), `1.3.6.1.4.1.66282.301.6` = X301-v2. Wie bei `.301.4`: ohne `AlgorithmIdentifier`-Parameter, in `docs/OID_REGISTRY.md` eintragen; `.301.1` bis `.301.4` bleiben, wie sie sind, und werden nie umgedeutet.
- Was TLS-Codepoints sind: die 16-Bit-Kennungen, die TLS 1.3 auf dem Draht in den Erweiterungen `signature_algorithms` (SignatureScheme) und `supported_groups` (NamedGroup) verwendet. Sie sind von OIDs unabhängig. Ohne IANA-Registrierung gibt es nur die Private-Use-Bereiche: SignatureScheme `0xFE00–0xFFFF` (RFC 8446 §4.2.3), NamedGroup `0xFE00–0xFEFF` (RFC 8446 §4.2.7). v1 belegt SignatureScheme `0xFE84` (Ed301-EdDSA-v1; `0xFE2D` ist ausgemustert) und NamedGroup `0xFE2E` (X301MLKEM1024).
- Vorschlag v2, fortlaufend und kollisionsfrei zu v1: SignatureScheme **`0xFE85`** = Ed301-EdDSA-v2; NamedGroup **`0xFE2F`** = X301MLKEM1024-v2. NamedGroup **`0xFE30`** = Raw-X301-v2 (nur explizit wählbare Testgruppe, siehe 3.2). Keine Kollision mit der G301-Ciphersuite `0xFF30` (anderes Register). Ebenfalls in `OID_REGISTRY.md` als nicht registrierbare Private-Use-Kennungen führen.

### 3.2 Raw-X301 im TLS: Hybrid als Regel, Raw-Gruppe nur per expliziter Auswahl

Martins Entscheidung (10. September 2026, nach Rückfrage): wie v1 mit einer Ergänzung.

- Raw-X301-v2 als EVP-KEYMGMT/KEYEXCH mit v2-Identität und OID `.301.6` (wie v1).
- TLS-GROUP für den Hybrid X301MLKEM1024-v2 mit `0xFE2F` (wie v1). Der Hybrid ist die einzige Gruppe in der Standard-Gruppenliste des Providers und die Betriebsempfehlung.
- **Zusätzlich** eine Raw-TLS-Gruppe X301-v2 mit `0xFE30`, ausschließlich als Test- und Messpfad: nur aushandelbar, wenn sie ausdrücklich per `-groups`/`SSL_CTX_set1_groups_list` gewählt wird; nie in der Standard-Gruppenliste, nie bevorzugt, in der Dokumentation als experimenteller Einzelpfad ohne ML-KEM-Schutz gekennzeichnet.
- Begründung: Nur so lässt sich der X301-v2-Pfad im echten Handshake isoliert prüfen und messen (die TLS-Lane für v2 blieb im D1-Bericht leer); die Form entspricht X25519 neben X25519MLKEM768. Das Risiko einer Fehlbevorzugung wird durch den Ausschluss aus der Standardliste und den folgenden Negativtest begrenzt.
- Inventur: X13 erhält zwei Zeilen (Hybrid, Raw). Neuer Negativtest: Ohne ausdrückliche Gruppenwahl wird Raw-X301-v2 nie ausgehandelt, auch nicht, wenn der Peer sie anbietet. Positive Raw-Tests: Handshake, HRR, Resumption, Datenverkehr mit 38-Byte-Key-Share. `0xFE30` ist damit vergeben, nicht mehr Reserve.

### 3.3 X301-Schlüsseldateien: Featureparität mit dem Ed301-Provider

Neu gegenüber dem v1-Integrationsstand, gewollt: PKCS#8 `PrivateKeyInfo` Version 0 und SPKI in DER und PEM, dazu verschlüsseltes PKCS#8 über OpenSSLs generische PKCS#8-Verschlüsselung um den Encoder herum (keine X301-spezifische Kryptografie). Form nach dem Vorbild von RFC 8410 für X25519/X448: SPKI mit OID `.301.6` ohne Parameter und BIT STRING der 38 kanonischen u-Bytes; PKCS#8 mit OID `.301.6` ohne Parameter und `PrivateKey` = OCTET STRING, das ein OCTET STRING mit den 38 originalen Secret-Bytes enthält (nicht die geklampfte Kopie). Strikt wie beim Ed301-Provider: Version 1 und Attribute nicht stillschweigend ergänzen oder akzeptieren, Restbytes und nichtkanonisches DER ablehnen, Decoder-Ketten (DER, PEM, Decrypt, BIO) real testen. Damit wird X14 der Inventur konkret.

### 3.4 Namen

Nach außen `Ed301-EdDSA` und `X301`, intern v2; die v1-Repos gehen offline. Die Unterscheidung zu v1-Containern leisten die OIDs `.301.5`/`.301.6` und die Codepoints, nicht die Namen. Beide Providergenerationen dürfen nie im selben Libctx geladen werden; das ist zu dokumentieren und in G02 als Negativtest zu führen.

## 4. Freigaben und Grenzen für D2 (Martin, 10. September 2026)

Emmys Einwand war berechtigt: "Provider-Aktivierung" in AGENTS.md meint das System, nicht den Testprozess. Martin hat entschieden, dass v2 dem v1-Modell folgt.

### Stufe 1: Testfreigabe, jetzt erteilt

- Bauen der v2-Provider (Ed301-EdDSA-v2, X301-v2, X301MLKEM1024-v2) aus dem Testing-Stand.
- Laden ausschließlich in privaten `OSSL_LIB_CTX` aus Testbinaries und Skripten, mit `OPENSSL_MODULES` auf den Build-Ordner; kein Eintrag im Standard-Libctx des Hosts.
- Handshakes nur zwischen projekteigenen Endpunkten auf localhost mit ephemeren Ports (wie `test-provider.sh` und `test-x301-tls.sh` bei v1); Testschlüssel und -zertifikate werden pro Lauf frisch erzeugt und nicht committed.
- Valgrind, ASan/UBSan, Taint, dudect und Codegen auf diesen Testprozessen und DSOs.
- Weiterhin untersagt in Stufe 1: Installation in Systempfade, Änderung von `openssl.cnf` oder anderer Systemkonfiguration, Verbindungen zu fremden Hosts, Push, Veröffentlichung.

### Stufe 2: Paketierung und Aktivierung, nach Gate D mit gesondertem Go

Wie bei v1 zwei RPMs je Provider: das ordentliche Provider-Paket installiert das Modul nach `ossl-modules` und aktiviert nichts; das Policy-Paket legt die Konfigurationsdatei mit `activate = 1` ab und aktiviert den Provider systemweit. Martins Begründung: Wer die Pakete installiert, will sie nutzen; standardisiert werden sie nie. Die Trennung in zwei Pakete bleibt, damit das Aktivieren eine bewusste Installationsentscheidung ist. Stufe 2 beginnt erst nach Gate D und nach Martins ausdrücklichem Go für RPM-Bau, Installation und Policy-Paket. Dann ersetzt v2 die v1-Pakete auf dem System; beide Generationen dürfen nie gleichzeitig aktiv sein.

### Unverändert

Phase-A/B/C-Snapshots bleiben unangetastet. Kein Push und keine Veröffentlichung ohne Martins Go. Gate D prüfe ich am Ende von Phase D mit eigenen Tests, wie bei Gate C.
