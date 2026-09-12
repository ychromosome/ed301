# Drei gezielte Prüfungen: Ergebnis

Stand: 12. September 2026, Produktquellen von Testing `af9613b`.
Leistungskosten, OpenSSL-Containeraustausch und `Shared<T>` wurden geprüft.
Kurve, Kryptologik, Decoderregeln und Ownership-Implementierung sind unverändert.
Neu sind die [Prüfprogramme](../assessment/README.md); der X301-Benchmarkrunner
nennt seinen heutigen Quellumfang statt des überholten D1-Arithmetikstands.

## 1. Leistungs- und Komplexitätskosten

Frisch gebaut und seriell gemessen: Ryzen 9 5950X, CPU 2, Rust 1.98.0 /
LLVM 21.1.8, O3, ThinLTO, CGU1, Unwind, v2 mit Overflow-Prüfungen.
Je Fall neun Laufmittel; Mediane unten. Die vollständigen 98 Ed301-, 38 Mikro-
und 12 X301-Fälle einschließlich Streuung stehen in den gebundenen Ergebnissen.
Ed301/Mikro-Kalibrierziel: 100 ms; X301: 200 ms. Governor/Boost unverändert.
Die dokumentierte historische X301-v1-Overflow-Ausnahme bleibt im Vergleich erhalten.

Ed301, Nachricht 64 Byte, leerer Context, Zeiten in µs:

| Operation | EdDSA-v1 | v2 |
| --- | ---: | ---: |
| Signieren einschließlich Seed-Expansion | 56,446 | 56,005 |
| Signieren mit vorbereitetem Schlüssel | 28,673 | 28,586 |
| Verifizieren mit vorbereitetem Schlüssel | 84,353 | 82,690 |
| Public-Key-Import und einmalige Verifikation | 180,682 | 133,063 |

Die Wiederverwendung des Signierschlüssels halbiert hier ungefähr den Aufwand.
Auch die erneute Public-Key-Vorbereitung kostet merklich Zeit. Ein vorbereiteter
`VerifyingKey` belegt 10.280 Byte, ein `ExpandedSigningKey` 280 Byte; das sind
Objektgrößen, keine isolierten RSS-Einsparungen.

Die Multiplikation mit `a` kostet im kanonischen Feldpfad 9,787 ns, gegenüber
25,000 ns für eine allgemeine Feldmultiplikation. Im tatsächlich verwendeten
Lazy-Pfad sind es 6,551 beziehungsweise 21,075 ns. Das ist realer Zusatzaufwand,
aber kein allgemeines 5×5-Limb-Produkt. Daraus lässt sich nicht direkt der
Geschwindigkeitsgewinn einer anderen Koordinatendarstellung ableiten: Bei der
Normierung auf `a = 1` ändert sich auch `d` zu `d/a`.

X301-v2: Public-Ableitung 27,183 µs, Shared-Ableitung 57,262 µs.
Die vorbereitete Shared-Variante liegt bei 57,296 µs; bloße Schlüsselvorbereitung
bringt hier keinen erkennbaren Gewinn. Der gesamte Secret-Import benötigt
31,205 ns. Seine Gültigkeitsprüfung ist damit kein wesentlicher Laufzeitposten.
Der v1-Shared-Median liegt bei 56,570 µs: v2 bleibt in dieser Messung rund
1,2 % darüber. Das ist kein Signifikanztest und kein allgemeines Geschwindigkeitsversprechen.

**Empfehlung:** Vorbereitete Ed301-Schlüssel in Anwendungen wiederverwenden.
Kein weiterer Arithmetikumbau auf Grundlage dieser Messungen. Einen Wechsel
der internen Darstellung gegebenenfalls als getrenntes, bytekompatibles
Experiment bewerten. Historische EVP-/TLS-Messungen wurden nicht als neue
Provider-Benchmarks ausgegeben.

## 2. Verbindlicher Containerumfang

Festgelegt: OpenSSL 3.5.8 und 4.0.2. Beide Versionen erzeugten neue Ed301- und
X301-Prüfschlüssel; jede Version las die eigenen Dateien und die der anderen.
128 Beobachtungen, 446 protokollierte Befehle. Bei angenommenen privaten
Dateien blieben sowohl der öffentliche Schlüssel als auch die ursprünglichen
privaten 38 Byte erhalten. Falsche Passwörter wurden abgewiesen.

| Format oder Variante | Normale OpenSSL-CLI | Strikte Ganzdateiprüfung |
| --- | --- | --- |
| SPKI / PKCS#8 v0, DER und PEM | angenommen | angenommen |
| PEM mit CRLF | angenommen | angenommen |
| Verschlüsseltes PKCS#8, DER und PEM | angenommen | angenommen |
| PKCS#8 mit Attributen | abgewiesen | abgewiesen |
| OneAsymmetricKey mit öffentlichem Schlüssel | abgewiesen | abgewiesen |
| AlgorithmIdentifier mit NULL | abgewiesen | abgewiesen |
| DER mit Zusatzbyte oder zweitem Objekt | erstes Objekt gelesen | abgewiesen |
| PEM mit führender Leerzeile, nachfolgendem Leerraum oder zweitem Objekt | erstes Objekt gelesen | abgewiesen |
| PKCS#12 mit passendem Zertifikat | angenommen | kein direkter PKCS#12-Dateiprüfer |

PKCS#12-Keydumps enthalten Metadaten vor dem PEM-Block. Die normale CLI liest
sie; unsere strikte PEM-Dateiprüfung weist sie ab. Nach Normalisierung mit
`openssl pkey` besteht auch diese Prüfung, mit unveränderten privaten Bytes.
Die Tests verwenden PBES2/AES-256-CBC mit 10.000 Iterationen als Prüffall,
nicht als neue Passwortkostenpolitik.

**Empfehlung:** Diesen Umfang beibehalten und zwischen normaler CLI-Nutzung
und striktem Dateiimport unterscheiden. Java, Go, Bouncy Castle, OpenSSH und
GnuTLS erhalten ohne konkrete Algorithmus-/Anwendungsintegration keine
Kompatibilitätszusage. Attribute und zusätzliche Containerformen bleiben
gezielte mögliche Erweiterungen, nicht stillschweigend akzeptierte Eingaben.

## 3. Isolierte Ownership-Prüfung

Die eigenständige Test-Crate bindet die tatsächliche Datei
`provider/common/allocation.rs` direkt ein; ihr SHA-256 blieb
`1dbf6e48d67950302672f9702608a094a0838957d0c667e34b27cbaa29408e7d`.
Es wurde keine nachgebaute Ownership-Implementierung verwendet.

- Elf native Tests: Alignment/ZST, Clone/Drop, letzte Freigabe, Allokationsfehler,
  Unwind, panikender Destruktor und parallele Leser/Freigaben.
- 32 Miri-Läufe mit je elf Tests: 16 Seeds im Default-Modell und 16 mit
  Tree Borrows. Provenance-, Alignment-, Race- und Weak-Memory-Prüfungen aktiv.
- Tatsächliche Null-Rückgaben des Test-Allokators: native Ausführung sowie
  beide Miri-Modelle; Payload-Drop und anschließender erfolgreicher Versuch geprüft.
- Zwei Compile-fail-Kontrollen: `Shared<Rc<_>>` nicht Send und
  `Shared<Cell<_>>` nicht Sync.
- Memcheck: keine Speicherzugriffsfehler, keine definitiv oder indirekt
  verlorenen Blöcke. 48 Byte „possibly lost“ im Rust-Testrunner treten identisch
  im leeren Kontrolltest ohne `Shared<T>` auf; 544 Byte bleiben dort wie im
  Ownership-Test erreichbar. Keine Suppressions verwendet.

Miri lief in einer getrennten, datierten offiziellen Toolchain
`nightly-2026-09-11` mit Rust 1.100.0-nightly; die System-Toolchain blieb Rust
1.98.0. Die Test-Crate hat keine externen Crate-Abhängigkeiten.

**Ergebnis:** Kein Ownership-Fehler in diesen Ausführungen gefunden; kein
begründeter Anlass für einen Austausch der Implementierung. Miri prüft nur
eine begrenzte Auswahl von Ausführungen. Das ist weder ein vollständiger
Soundness-Beweis noch die Prüfung aller Provider-FFI-Lebensdauern oder der
Löschung sämtlicher Kopien in optimierten Auslieferungsbinaries.

## Nachweise und nächste Grenze

[Der Evidenzindex](ASSESSMENT_20260912.json) bindet Rohmessungen, Prüfprotokolle,
Testbinaries und Toolchain-Metadaten. Neue Schlüssel und Buildprodukte liegen
außerhalb des Repositorys. Die vorangegangenen unvollständigen Interop-Versuche
bleiben getrennt; maßgeblich sind `interop-03` und `shared-02`.

Weiter erforderlich: neue RPMs auf dem korrigierten Quellstand und deren
Binär-/Seitenkanal-/Löschungsabnahme. Optional: Bedarf und Bedrohungsmodell für
vertrauliche öffentliche Schlüssel; dafür wurde kein neuer Verarbeitungspfad eingebaut.
