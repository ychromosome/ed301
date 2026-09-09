# Phase C: Rust-Kern, Performance und Gate-C-Prüfstand

Stand: 10. September 2026. Zur externen Gate-C-Prüfung; keine Gate-C- oder Produktionsfreigabe.

168 Geschwindigkeitsfälle und 52 Ressourcenfälle sind tabellarisch dokumentiert.
Der genaue Testing-Commit, das Paketmanifest und der Archivhash werden im äußeren
Übergabezettel gebunden, ohne einen zirkulären Commit-Hash in diesen Bericht einzubauen.
Phase D bleibt ausdrücklich unberührt.

## Implementierung und Prüfstand

Die Feldarithmetik verwendet den bestätigten Modulus p = 2^301 − 2^89 + 907,
5×64-Bit-Limbs und einen öffentlichen Small-Multiplikator im Bereich 0 ≤ m < 2^36.
Die Schranken, der negative Koeffizient d = −301 und die erzeugten Feld-/Skalar-/
Basispunktkonstanten sind auf das freigegebene Gate-A/B-Paket zurückgeführt.
Der Rust-Kern verwendet Ed301-EdDSA-v2 und SigEd301-v2; er lädt keine Parameterdatei
zur Laufzeit. Die freigegebenen Phase-A/B-Dateien bleiben unverändert.

Bisher geprüft: 54/54 Release-Tests, 54/54 Tests mit sign-self-verify,
Clippy ohne Warnungen, deterministische Konstantenregeneration und die exakten
Faltungsschranken. Alle Gate-B-Signiervektoren samt Zwischenwerten und Negativfällen
werden im Rust-Kern geprüft. Die v1-Tests sind nach ihren übertragbaren
Verhaltensanforderungen angepasst, nicht nach zufälligen alten Feldwerten.

Die abschließende frische Offline-Prüfung bestätigt erneut 54/54 normale Tests
und 54/54 mit sign-self-verify, Clippy ohne Warnungen, Formatierung,
Konstantenregeneration, Feldschranken und unveränderte Vendor-Forks. Ein separater
no_std-Consumer wurde erfolgreich gebaut; Kern und Consumer verbieten Unsafe.
Der gespeicherte Feature-Baum zeigt die tatsächlichen normalen Abhängigkeiten.
Clippy verwendet einen eigenen Targetbaum ohne den ausschließlich rustc
akzeptierenden Codegen-Wrapper; es wird nicht als Binär-Codegen-Nachweis gezählt.
Der vollständige unveränderte Phase-B-Replay besteht 8/8. Dessen historische
Schlussformulierung zur damals noch ausstehenden Gate-B-Freigabe bleibt als Teil
des eingefrorenen Archivs erhalten; Martins inzwischen erteilte Freigabe wird
dadurch nicht zurückgenommen.

Beleg: /home/martin/Dokumente/ED301/ED301-v2_core-check_c8tnk9tg.
SHA-256 von /home/martin/Dokumente/ED301/ED301-v2_core-check_c8tnk9tg/SUMMARY.json:
18677d0df58f9f2ee01b8626ba0aa1469d0d79b70a4a305ec002ff0a34db33f8.
Der Rust-Quellmanifesthash ist identisch zum letzten Taint-Lauf:
1df6c99b740d6267048824a0c2bae785deb450af33b0cacf9b9e9e32a32a7167.
Die Testübertragung ist in
[/home/martin/Dokumente/ED301/ed301/phase-c/TEST_INVENTORY.md](/home/martin/Dokumente/ED301/ed301/phase-c/TEST_INVENTORY.md)
aufgeschlüsselt, die Importquellen in
[/home/martin/Dokumente/ED301/ed301/phase-c/SOURCE_IMPORT.md](/home/martin/Dokumente/ED301/ed301/phase-c/SOURCE_IMPORT.md).

Der erweiterte Taint-Lauf besteht Schlüsselableitung und Signieren für alle neun
Gate-B-Signierfälle, jeweils mit definierten und geheim markierten Testdaten:
36/36 Valgrind-Läufe, einschließlich binärem und 255-Byte-Context.
Beleg: /home/martin/Dokumente/ED301/ED301-v2_core-taint_aif6mcv7.
Binary-SHA-256: c8e4ab25d8ad1af7fa19265e2203a2edd859940a46cc271d732d89d7830ccb4f.
Der Harness prüft die tatsächlich gesetzten Validity-Bits jedes geheimen Inputs;
fehlende Taint-Markierung kann somit nicht stillschweigend als Pass gelten.
Das ist ein begrenzter
Werkzeugnachweis, kein allgemeiner Beweis gegen alle Seitenkanäle. Der abschließende
Codegen-Test des gemessenen x86-64-Kernbinaries und der unten abgegrenzte
statistische Timing-Test sind inzwischen ebenfalls bestanden. Sie gelten nicht
automatisch für spätere Provider, andere Linkartefakte oder andere Plattformen.

## Codegen- und Timing-Belege

Das gemessene v2-Kernbinary besteht die aus v1 übernommenen Instruktions-, festen
Schleifen- und Aufrufkettenregeln; die negativen Kontrollen des Prüfers schlagen
wie verlangt an. Zusätzliche Borrow-/Select-Instruktionen durch d = −301 sind
sichtbar, ohne geheimnisabhängige Sprünge in den geprüften geradlinigen Symbolen.
Beleg: /home/martin/Dokumente/ED301/ED301-v2_core-codegen_2026-09-10_01.
SHA-256 der dortigen summary.txt:
c0799f976b4b3acb25584cd2d8d1414f932ec8359a9cfb9a537db178206c1639.

Für dudect wurde ein getrennter, minimaler Test-FFI-Adapter um denselben Rust-Kern
gebaut; er ist kein Provider und kein Teil der Produkt-API. Sein unvermeidbarer
Pointer-FFI liegt außerhalb des no_std-Kerns mit forbid(unsafe_code).
Je Test: 200000 angeforderte Messungen plus Aufwärmbatch, nach dudects festen
Verwerfungen 198900 verwendete rohe Messungen, zufällig auf feste/zufällige
synthetische Seeds verteilt. 64-Byte-Nachricht, leerer Context, CPU 2.
Signierschlüssel werden vor der Messung expandiert; die zweite Kernklasse misst
Seedobjekt plus Expansion. Der Schwellenwert |t| > 10 folgt dem vorhandenen
v1-dudect-Profil. Ein einmal erkannter Leakage-Zustand bleibt über alle Batches
gespeichert; ein später kleineres t kann ihn nicht zurücknehmen.

| Timing-Test | Größter beobachteter Betrag t | Abschließender Betrag t | Rohmessungen Klasse 0 / 1 | Ergebnis |
|---|---:|---:|---:|---|
| Absichtlich variable Positivkontrolle | 5425,896 | 5419,534 | 99682 / 99218 | erkannt |
| Vorbereitetes Signieren | 2,639 | 1,149 | 99585 / 99315 | keine Leakage-Evidenz in diesem Test |
| Seedexpansion | 2,074 | 1,523 | 99558 / 99342 | keine Leakage-Evidenz in diesem Test |

Keine Vorbereitungs-/Operationsfehler; der FFI-Selbsttest läuft unter Valgrind
ohne gemeldeten Speicherfehler. Dies ist eine begrenzte statistische Beobachtung,
kein Beweis von Konstantzeit und kein Geschwindigkeitsbenchmark.
Beleg: /home/martin/Dokumente/ED301/ED301-v2_core-timing_0y75y2en.
SHA-256 der dortigen SUMMARY.txt:
37f36736cca6ed36818de284bea2ed167f6e88d58f7e9df2734b637098047660.

Nach der Formatierung des Testadapters wurde frisch gebaut und vollständig erneut
gemessen; auch dieser Lauf besteht. Beide Beobachtungen bleiben erhalten, statt
den jeweils günstigeren t-Wert auszuwählen. Der zweite Lauf überlappte mit dem
separaten Taint-Prüflauf; er ist keine Messung auf einem exklusiv reservierten Host.

| Zweiter Timing-Lauf | Größter beobachteter Betrag t | Abschließender Betrag t | Rohmessungen Klasse 0 / 1 | Ergebnis |
|---|---:|---:|---:|---|
| Absichtlich variable Positivkontrolle | 4762,759 | 4762,759 | 99282 / 99618 | erkannt |
| Vorbereitetes Signieren | 2,625 | 1,517 | 99620 / 99280 | keine Leakage-Evidenz in diesem Test |
| Seedexpansion | 2,501 | 2,501 | 99535 / 99365 | keine Leakage-Evidenz in diesem Test |

Beleg des aktuellen formatierten Adapterstands:
/home/martin/Dokumente/ED301/ED301-v2_core-timing_t_imai6j.
SHA-256 von /home/martin/Dokumente/ED301/ED301-v2_core-timing_t_imai6j/SUMMARY.txt:
9ffc1f5cc068eb4ee70822a79a0be6c523f5ad0e401307cef5813292dfc1acf7.

## Messmethode und Bedeutung von EVP

EVP bezeichnet die API-Schicht, nicht die Rechenimplementierung. Unter EVP können
OpenSSL-eigene C-/Assemblerpfade oder die 301-Provider mit kompiliertem Rust liegen.
Der EVP-Vergleich misst die real verfügbaren Implementierungen über dieselbe API;
er isoliert nicht die Kurvenmathematik und normiert weder Optimierungsgrad noch
Sicherheitsniveau. Die Rust-Kernmessung ist deshalb eine eigene Tabelle.

Alle Zahlen wurden neu auf AMD Ryzen 9 5950X, x86-64, mit CPU-Affinität 2 gemessen.
Rust: 1.98.0, LLVM 21.1.8, Release O3, Thin LTO, eine Codegen-Unit, panic=unwind.
Die Profile werden pro Crate erzwungen und geprüft. Overflow-Checks sind an;
ausschließlich der historische X301-v1-Bezugsstand behält seine vorhandene
crypto-bigint-Ausnahme mit ausgeschalteten Overflow-Checks. Diese Ausnahme ist
keine Empfehlung für v2 und wird nicht stillschweigend als identisches Profil ausgegeben.
C-Messharnesses: GCC -O2. EVP-Bibliothek: OpenSSL 3.5.8, tatsächliche Bibliothek
und alle Messbinärdateien sind gehasht. Governor und Boost wurden nicht verändert.

Je Fall: ein Aufwärm-/Kalibrierlauf mit 100 Operationen; daraus feste Wiederholungszahl
für ungefähr 200 ms gemessene Arbeit, begrenzt auf 100000 Operationen. Danach neun
Messrunden mit alternierender Richtung und rotierendem Startfall. Die Tabellen zeigen
den Median der neun Laufmittel, deren Stichprobenstandardabweichung σ sowie den
kleinsten und größten Laufmittelwert. Das sind keine Einzelaufruf-Perzentile und keine
Konfidenzintervalle. Hintergrundlast und Frequenzänderungen können die Streuung beeinflussen.

## Rust-Kern: Ed301-EdDSA-v1 gegen v2

Identischer Rust-Harness, 64-Byte-Nachricht aus 0x5a, leerer Context, identischer
38-Byte-Testseed. expand umfasst Seedobjekt und Expansion; sign verwendet einen
vorbereiteten ExpandedSigningKey, verify einen vorbereiteten VerifyingKey.
import umfasst Public-Key-Dekodierung einschließlich Untergruppenprüfung.
Schlüssel-/Signaturvorbereitung liegt bei sign und verify außerhalb der Messung.

| Verfahren | Operation | Median µs | σ µs | Minimum–Maximum µs |
|---|---|---:|---:|---:|
| Ed301-EdDSA-v1 | expand | 27,807 | 1,098 | 27,330–30,911 |
| Ed301-EdDSA-v2 | expand | 27,462 | 2,080 | 27,202–33,540 |
| Ed301-EdDSA-v1 | sign | 28,560 | 0,219 | 28,319–29,073 |
| Ed301-EdDSA-v2 | sign | 28,425 | 0,831 | 28,150–30,662 |
| Ed301-EdDSA-v1 | verify | 85,955 | 1,817 | 84,921–90,634 |
| Ed301-EdDSA-v2 | verify | 84,910 | 1,236 | 84,134–87,656 |
| Ed301-EdDSA-v1 | import | 96,995 | 1,559 | 96,020–100,290 |
| Ed301-EdDSA-v2 | import | 95,734 | 0,369 | 95,394–96,458 |

Medianänderung v2 gegenüber v1: expand: -1,24 %; sign: -0,47 %; verify: -1,22 %; import: -1,30 %.
Die Werte liegen nah beieinander; wegen Streuung und nur einer Plattform wird daraus
noch kein belastbarer Geschwindigkeitsvorteil oder allgemeiner Regressionsausschluss
abgeleitet. Es wurde keine numerische Freigabeschwelle beschlossen.

### Erste Binärgrößen- und Tabellenkontrolle

Am selben gemessenen Rust-Binary mit GNU size und nm -S erfasst. Größen in Byte;
die size-Spalte text umfasst auch zugehörige Nur-Lese-Segmente und ist keine
isolierte Größe des Kryptokerns. Die statischen Tabellen werden zur Compilezeit
erzeugt, nicht bei jedem Schlüsselimport.

| Größe | v1 | v2 |
|---|---:|---:|
| size: text | 530349 | 529005 |
| size: data | 13904 | 13904 |
| size: bss | 264 | 264 |
| BASEPOINT_TABLE | 48640 | 48640 |
| BASEPOINT_ODD_TABLE | 10240 | 10240 |

Stack-/RSS-Beobachtungen und die gesonderte Vorbereitung der Verifikationstabelle
folgen unten; Binärgrößen werden nicht als Laufzeitspeicher ausgegeben.

## Erweiterte Rust-Matrix: Schlüsselzustand, Nachricht und Context

Neu gebauter identischer Public-API-Harness für v1 und v2, gleiche Plattform und
Release-Profile wie oben. Je Fall 100 Aufwärmoperationen, Kalibrierung auf ungefähr
100 ms und neun rotierende Messrunden. Die 98 Fälle werden vollständig aufgeführt;
Median, Stichproben-σ und Spannweite beziehen sich wieder auf Laufmittel, nicht
auf Einzelaufrufe. Nachricht Byte i = (29i + 7) mod 256; Context Byte i =
(17i + 3) mod 256; fester öffentlicher 38-Byte-Testseed.

cold-sign enthält Seedimport, Expansion und Signatur; prepared-sign verwendet
den vorbereiteten ExpandedSigningKey. prepared-verify verwendet einen zuvor
validierten VerifyingKey, import-verify importiert und prüft den Public Key für
jeden Aufruf erneut. Die Verifikationen verarbeiten Signaturbytes und prüfen den
Rückgabewert auch innerhalb der Schleife. Allocation der Testnachricht, Signatur-
vorbereitung und anfänglicher Selbsttest liegen außerhalb der Messzeit.
„Kalt“ beschreibt den Schlüssel-Lifecycle, nicht einen geleerten CPU-Cache.

| Nachricht Byte | Context Byte | Operation | v1 Median µs | v1 σ µs | v1 Min–Max µs | v2 Median µs | v2 σ µs | v2 Min–Max µs |
|---:|---:|---|---:|---:|---:|---:|---:|---:|
| 0 | 0 | cold-sign | 55,758 | 2,577 | 55,650–63,569 | 55,558 | 0,850 | 55,377–58,053 |
| 0 | 0 | prepared-sign | 28,181 | 0,291 | 28,075–29,010 | 28,182 | 1,939 | 27,975–33,957 |
| 0 | 0 | prepared-verify | 85,258 | 1,736 | 84,918–89,165 | 84,381 | 3,084 | 83,975–93,217 |
| 0 | 0 | import-verify | 181,779 | 1,769 | 181,111–186,528 | 181,501 | 3,496 | 179,737–189,520 |
| 0 | 16 | cold-sign | 56,221 | 0,366 | 55,573–56,687 | 55,609 | 1,324 | 55,420–58,966 |
| 0 | 16 | prepared-sign | 28,333 | 0,745 | 28,067–30,501 | 28,234 | 0,486 | 27,979–29,643 |
| 0 | 16 | prepared-verify | 84,050 | 0,617 | 83,683–85,770 | 84,198 | 1,677 | 84,007–88,934 |
| 0 | 16 | import-verify | 180,724 | 1,241 | 180,182–184,289 | 185,187 | 5,014 | 179,910–194,134 |
| 0 | 255 | cold-sign | 57,392 | 3,011 | 56,743–64,720 | 56,541 | 1,007 | 56,452–59,535 |
| 0 | 255 | prepared-sign | 29,377 | 0,349 | 29,101–30,275 | 29,119 | 0,247 | 29,027–29,840 |
| 0 | 255 | prepared-verify | 85,715 | 1,838 | 85,329–91,193 | 84,033 | 0,841 | 83,693–86,371 |
| 0 | 255 | import-verify | 182,339 | 0,868 | 181,530–184,476 | 180,173 | 4,595 | 179,676–191,263 |
| 64 | 0 | cold-sign | 55,999 | 2,838 | 55,865–63,574 | 55,635 | 2,248 | 55,543–62,380 |
| 64 | 0 | prepared-sign | 28,687 | 2,026 | 28,309–34,697 | 28,402 | 0,176 | 28,142–28,667 |
| 64 | 0 | prepared-verify | 84,094 | 1,714 | 83,931–89,276 | 84,747 | 2,025 | 84,584–90,595 |
| 64 | 0 | import-verify | 180,609 | 3,455 | 180,001–190,926 | 180,525 | 1,289 | 180,101–184,305 |
| 64 | 16 | cold-sign | 55,981 | 1,547 | 55,861–60,461 | 56,002 | 0,991 | 55,608–58,348 |
| 64 | 16 | prepared-sign | 28,587 | 0,906 | 28,327–31,061 | 28,427 | 0,521 | 28,233–29,684 |
| 64 | 16 | prepared-verify | 84,523 | 1,268 | 84,209–88,186 | 83,081 | 0,765 | 82,705–85,288 |
| 64 | 16 | import-verify | 180,816 | 0,418 | 180,557–181,906 | 179,522 | 2,371 | 178,520–184,232 |
| 64 | 255 | cold-sign | 57,015 | 1,211 | 56,852–60,062 | 56,829 | 0,280 | 56,628–57,535 |
| 64 | 255 | prepared-sign | 29,597 | 0,569 | 29,375–30,935 | 29,595 | 0,549 | 29,251–30,921 |
| 64 | 255 | prepared-verify | 85,438 | 2,561 | 85,286–93,118 | 84,054 | 2,701 | 83,444–91,255 |
| 64 | 255 | import-verify | 182,342 | 1,356 | 181,371–185,140 | 179,633 | 1,297 | 179,140–183,261 |
| 1024 | 0 | cold-sign | 59,921 | 0,514 | 59,562–61,215 | 59,411 | 1,624 | 59,237–64,223 |
| 1024 | 0 | prepared-sign | 32,233 | 0,345 | 31,960–33,028 | 32,062 | 0,463 | 31,836–33,108 |
| 1024 | 0 | prepared-verify | 87,672 | 1,040 | 86,721–89,849 | 86,093 | 1,809 | 85,633–90,328 |
| 1024 | 0 | import-verify | 185,637 | 3,230 | 183,338–193,113 | 183,568 | 2,871 | 182,534–191,727 |
| 1024 | 16 | cold-sign | 60,776 | 2,081 | 59,778–66,354 | 59,793 | 0,374 | 59,595–60,524 |
| 1024 | 16 | prepared-sign | 32,688 | 0,386 | 32,248–33,371 | 32,206 | 0,192 | 32,041–32,637 |
| 1024 | 16 | prepared-verify | 86,531 | 0,488 | 86,225–87,543 | 85,753 | 3,095 | 85,571–95,077 |
| 1024 | 16 | import-verify | 183,368 | 3,949 | 182,642–192,009 | 181,603 | 3,390 | 181,301–191,604 |
| 1024 | 255 | cold-sign | 60,662 | 5,741 | 60,576–78,201 | 60,575 | 3,249 | 60,245–70,352 |
| 1024 | 255 | prepared-sign | 33,351 | 2,004 | 32,960–39,341 | 33,166 | 0,975 | 32,860–35,937 |
| 1024 | 255 | prepared-verify | 85,923 | 0,567 | 85,604–87,521 | 85,744 | 1,894 | 85,311–91,331 |
| 1024 | 255 | import-verify | 182,166 | 1,998 | 181,903–188,205 | 181,552 | 3,562 | 181,025–192,180 |
| 16384 | 0 | cold-sign | 117,871 | 3,378 | 117,580–128,104 | 117,492 | 2,371 | 117,358–123,559 |
| 16384 | 0 | prepared-sign | 90,466 | 2,243 | 89,949–95,828 | 90,131 | 1,587 | 89,866–94,356 |
| 16384 | 0 | prepared-verify | 115,616 | 5,203 | 115,156–128,537 | 113,744 | 1,285 | 113,426–116,613 |
| 16384 | 0 | import-verify | 212,324 | 2,607 | 211,645–219,178 | 210,611 | 1,615 | 209,334–213,517 |
| 16384 | 16 | cold-sign | 118,463 | 3,096 | 117,472–127,194 | 119,876 | 11,510 | 117,318–153,796 |
| 16384 | 16 | prepared-sign | 90,609 | 0,728 | 90,005–92,117 | 90,519 | 1,339 | 89,767–93,809 |
| 16384 | 16 | prepared-verify | 116,384 | 1,625 | 114,672–119,519 | 115,229 | 0,701 | 114,880–117,043 |
| 16384 | 16 | import-verify | 211,516 | 8,833 | 211,327–236,399 | 211,629 | 11,677 | 210,942–246,844 |
| 16384 | 255 | cold-sign | 119,536 | 2,770 | 118,568–125,654 | 119,459 | 3,516 | 118,383–127,022 |
| 16384 | 255 | prepared-sign | 91,321 | 3,801 | 91,171–101,946 | 91,262 | 1,336 | 90,908–95,123 |
| 16384 | 255 | prepared-verify | 115,904 | 7,116 | 114,927–137,011 | 116,480 | 6,090 | 115,360–132,361 |
| 16384 | 255 | import-verify | 213,833 | 5,402 | 211,634–227,621 | 213,458 | 2,006 | 211,424–216,885 |

Die meisten Mediane bleiben eng beieinander. Einzelne v2-Fälle sind auch langsamer;
insbesondere werden Ausreißer und Streuung nicht aus den Tabellen entfernt.
Dieser Lauf begründet weder eine universelle Beschleunigung noch einen
statistisch abgesicherten Regressionsausschluss.

### Verifikationstabelle und Objektgrößen

prepare-verifier ruft ExpandedSigningKey::verifying_key() auf einem bereits
expandierten, intern validierten Schlüssel auf. Erfasst werden insbesondere
Tabellenbildung und Normalisierung, aber keine erneute feindliche Eingabedekodierung
oder Untergruppenprüfung. Die komplette externe Importzeit steht in der ersten
Kerntabelle und in import-verify.

| Verfahren | Operation | Median µs | σ µs | Minimum–Maximum µs |
|---|---|---:|---:|---:|
| Ed301-EdDSA-v1 | prepare-verifier | 26,156 | 0,372 | 26,098–27,270 |
| Ed301-EdDSA-v2 | prepare-verifier | 26,434 | 0,272 | 26,326–27,192 |

Mit std::mem::size_of am selben Harness bestimmt; Werte in Byte einschließlich
Padding, keine Messung des maximalen Stackverbrauchs oder der Prozess-RSS:

| Rust-Objekt | v1 | v2 |
|---|---:|---:|
| SigningKey | 38 | 38 |
| ExpandedSigningKey | 280 | 280 |
| VerifyingKey | 10280 | 10280 |
| Signature | 76 | 76 |

Der erweiterte Gesamt-Harness hat laut GNU size text/data/bss
v1 = 536297/13960/264 und v2 = 534889/13960/264 Byte. Er ist ein anderes
Linkartefakt als der erste Kernbenchmark; Größen dürfen nicht zwischen beiden
Harnesses als Kernänderung ausgelegt werden.

Belegordner: [/home/martin/Dokumente/ED301/ED301-v2_core-matrix_fo_7z8pb](/home/martin/Dokumente/ED301/ED301-v2_core-matrix_fo_7z8pb).

| Matrix-Artefakt | SHA-256 |
|---|---|
| /home/martin/Dokumente/ED301/ED301-v2_core-matrix_fo_7z8pb/SUMMARY.json | 59de4b0f8b762f2d7f2a6b8a0f6ee3548f9c2cd5ca4c3346c94ae2acdc93bac0 |
| /home/martin/Dokumente/ED301/ED301-v2_core-matrix_fo_7z8pb/raw.tsv | c1f59f2144f2cfe51d957fc5af16304283d31aff267ba8c2fb8cab378c748e92 |
| /home/martin/Dokumente/ED301/ED301-v2_core-matrix_fo_7z8pb/SHA256SUMS | 95c405be00664f91f2fc25584aeaca14f3e92b06930fd1c1fd80ec604c7fdeda |

Quellset und Inhalte wurden vor/nach dem Lauf verglichen; beide Harnesskopien
sind bytegleich. Die Quellmanifest-, Werkzeug-, Binär- und Profilbindung ist in
/home/martin/Dokumente/ED301/ED301-v2_core-matrix_fo_7z8pb/IDENTITY.json
dokumentiert. Die Public-API-Matrix wird durch die folgenden gesonderten
Feld-/Skalarmessungen ergänzt.

## Feld- und Skalar-Mikrobenchmarks

Die privaten Originalmodule werden ohne Quelländerung in ein getrenntes
Testprogramm eingebunden. Die Produkt-API bleibt unverändert. Derselbe Harness
läuft gegen v1 und v2; nur die Modulpfade und das deklarierte v2-Vorzeichen von d
unterscheiden sich. Der Build verwendet dieselben erzwungenen Release-Profile.

16 feste, nichttriviale Operanden werden zyklisch ausgewählt. Ihre Kodierungen
liegen unter beiden p und q; die breite Hashreduktion erhält volle 76 Byte,
die Pruning-Reduktion korrekt geprunte 38 Byte. Das ist eine Performance-Stichprobe,
kein Ersatz für die Grenz-/Oracle-Tests der vollständigen Eingabedomänen.
Loop, Auswahl, black_box und gegebenenfalls Zeroize-Drop sind enthalten.
Die Copy-Kontrolle wird ausgewiesen, nicht von den Messwerten abgezogen.
Public-wNAF ist ausdrücklich der variable öffentliche Pfad.

1000 Aufwärmoperationen, Kalibrierung auf ungefähr 100 ms, höchstens 100 Millionen
Operationen je Lauf, neun Messrunden mit wechselnder Richtung und Startposition.
Alle Werte dieser Tabelle in Nanosekunden; Median und Stichproben-σ der Laufmittel.

| Operation | v1 Median ns | v1 σ ns | v1 Min–Max ns | v2 Median ns | v2 σ ns | v2 Min–Max ns |
|---|---:|---:|---:|---:|---:|---:|
| control-field-copy | 1,271 | 0,081 | 1,246–1,450 | 1,265 | 0,035 | 1,255–1,347 |
| field-add | 6,963 | 0,086 | 6,948–7,217 | 6,567 | 0,114 | 6,551–6,826 |
| field-sub | 5,928 | 0,061 | 5,914–6,112 | 5,855 | 0,015 | 5,838–5,881 |
| field-mul | 25,851 | 0,218 | 25,519–26,154 | 25,543 | 1,143 | 24,955–28,473 |
| field-square | 24,586 | 0,119 | 24,455–24,830 | 24,701 | 0,089 | 24,590–24,804 |
| field-mul-301 | 10,694 | 0,088 | 10,578–10,849 | 11,252 | 0,094 | 11,117–11,365 |
| field-mul-a | 11,007 | 0,215 | 10,964–11,538 | 9,905 | 0,126 | 9,863–10,209 |
| field-mul-d | 10,655 | 0,256 | 10,549–11,394 | 14,873 | 0,052 | 14,826–14,958 |
| field-invert | 2681,400 | 19,094 | 2671,113–2733,240 | 2710,193 | 43,111 | 2689,219–2822,972 |
| field-sqrt-ratio | 9234,481 | 120,829 | 9188,725–9547,654 | 8992,404 | 46,023 | 8971,371–9085,630 |
| lazy-mul | 21,353 | 0,765 | 21,306–23,662 | 21,474 | 0,156 | 21,357–21,792 |
| lazy-square | 20,416 | 0,518 | 20,244–21,864 | 20,393 | 0,531 | 20,045–21,874 |
| lazy-mul-a | 6,620 | 0,041 | 6,590–6,718 | 6,573 | 0,022 | 6,530–6,608 |
| lazy-loose-mul | 25,500 | 0,152 | 25,430–25,877 | 26,755 | 0,418 | 26,488–27,741 |
| scalar-add | 4,777 | 0,121 | 4,751–5,053 | 4,797 | 0,051 | 4,757–4,919 |
| scalar-mul | 114,357 | 1,313 | 113,902–117,617 | 115,852 | 0,648 | 114,756–116,614 |
| scalar-reduce-pruned | 61,143 | 1,219 | 59,469–63,235 | 60,943 | 1,270 | 59,580–63,713 |
| scalar-reduce-hash | 154,093 | 3,015 | 152,822–161,197 | 153,726 | 2,446 | 151,382–159,787 |
| scalar-wnaf-public | 589,059 | 4,772 | 585,609–601,026 | 588,139 | 5,509 | 584,587–601,741 |

mul-a misst jeweils den Koeffizienten des eigenen Profils; mul-d enthält bei v2
zusätzlich die Negation nach mul_small(301). Deren beobachteter Gesamtunterschied
beträgt hier 4,218 ns, etwa 39,6 % dieser kleinen Einzeloperation. Daraus folgt
keine 39,6-prozentige Verlangsamung von Signieren oder Verifizieren. Andere
Einzeloperationen unterscheiden sich in beide Richtungen. Es wurde keine
Schutzmaßnahme für diese Zahlen entfernt und keine neue Regressionsschwelle erfunden.

Beleg: /home/martin/Dokumente/ED301/ED301-v2_microbench_il4cilr_.
SHA-256 der Zusammenfassung:
30366eafb83da398d80f2f3eebbeec9c522256b1cfdc86061136c3fb3a510cd2.

## Stack- und RSS-Spitzen

Der identische Safe-Rust-Ressourcenharness bildet vollständige Prozess-Lifecycles
ab, einschließlich Startup, Nachrichten-/Context-Puffer und der je Szenario
benötigten Schlüsselvorbereitung. Er reserviert große Verifikationstabellen nicht
schon im leeren Hauptpfad. Die Operationen stehen in getrennten, nicht inline
gesetzten Harnessfunktionen; die Kryptobibliothek behält ihr normales Releaseprofil.
Messung von Ressourcen ist kein zusätzlicher Geschwindigkeits- oder Leakage-Test.

Massif: heap=no, stacks=yes, time-unit=B, peak-inaccuracy=0.0, maximal 1000
Snapshots, drei neue Prozesse je Fall mit zehn Operationen. Verwendet wird die
größte beobachtete mem_stacks_B-Angabe. Massif setzt den anfänglichen Hauptstack
auf null; die Werte beschreiben nicht die gesamte Stack-Abbildung des Betriebssystems.
Die dokumentierten Grenzen der Peak-Erfassung bleiben bestehen.
[Massif-Handbuch](https://valgrind.org/docs/manual/ms-manual.html).

RSS: neun native Prozesse, ohne Valgrind, je 100 Operationen; GNU time %M liefert
die Prozess-High-Water-Mark. Die Werte werden auf diesem Linux-System in KiB
geführt und schließen Loader, Standardbibliothek und Harness ein. Kleine
v1/v2-Unterschiede sind damit nicht isoliert dem Kryptokern zuzurechnen.
[GNU-Time-Handbuch](https://www.gnu.org/software/time/manual/html_node/Memory-Resources.html).

### Stack

Für jede Operation wurden Nachricht/Context = 0/0, 64/0 und 16384/255 Byte
getestet. Alle drei Wiederholungen und alle drei Größen ergaben je Operation
dieselbe Stackspitze; daher eine zusammengefasste Zeile. Median = Minimum =
Maximum, σ = 0 für diese Beobachtungen. Die beiden Positivkontrollen verwenden
64/0 Byte.

| Lifecycle / Kontrolle | v1 beobachtete Stackspitze Byte | v2 beobachtete Stackspitze Byte |
|---|---:|---:|
| empty | 7728 | 7728 |
| seed-expand | 7728 | 7728 |
| cold-sign | 7728 | 7728 |
| prepared-sign | 7728 | 7728 |
| public-import | 57064 | 57048 |
| prepare-verifier | 35976 | 35960 |
| prepared-verify | 57448 | 57432 |
| import-verify | 57480 | 57464 |
| stack-control | 263128 | 263128 |
| rss-control | 7728 | 7728 |

Bei Seedexpansion und Signieren dominiert die Leerlaufspitze von 7728 Byte.
Daraus wird weder „kein zusätzlicher Stack“ noch eine isolierte Stackzahl der
Signaturfunktion behauptet. Die größte beobachtete Kryptoszenario-Spitze liegt
bei 57480 Byte in v1 und 57464 Byte in v2. Das sind keine formal bewiesenen
Worst-Case-Grenzen für beliebige Compiler, Threads, Fehlerpfade oder Integrationen.

### Native RSS

Je Zelle Median der neun Prozessspitzen, Stichproben-σ und Minimum–Maximum in KiB.
Alle 52 Fälle einschließlich Leerlauf und Positivkontrollen sind enthalten.

| Nachricht Byte | Context Byte | Lifecycle / Kontrolle | v1 Median KiB | v1 σ KiB | v1 Min–Max KiB | v2 Median KiB | v2 σ KiB | v2 Min–Max KiB |
|---:|---:|---|---:|---:|---:|---:|---:|---:|
| 0 | 0 | empty | 2124 | 102,120 | 2012–2308 | 2096 | 127,668 | 1976–2288 |
| 0 | 0 | seed-expand | 2244 | 110,582 | 2008–2336 | 2240 | 150,614 | 1956–2336 |
| 0 | 0 | cold-sign | 2240 | 124,453 | 2000–2304 | 2272 | 37,100 | 2224–2336 |
| 0 | 0 | prepared-sign | 2272 | 64,419 | 2160–2336 | 2240 | 100,757 | 2012–2272 |
| 0 | 0 | public-import | 2244 | 59,867 | 2168–2304 | 2272 | 88,606 | 2028–2320 |
| 0 | 0 | prepare-verifier | 2244 | 55,317 | 2164–2336 | 2244 | 89,535 | 2008–2300 |
| 0 | 0 | prepared-verify | 2240 | 117,146 | 1952–2304 | 2224 | 89,487 | 2028–2336 |
| 0 | 0 | import-verify | 2248 | 89,453 | 2008–2304 | 2240 | 109,077 | 2020–2292 |
| 64 | 0 | empty | 2016 | 104,290 | 1976–2308 | 2184 | 112,809 | 2016–2288 |
| 64 | 0 | seed-expand | 2240 | 85,036 | 2016–2300 | 2236 | 34,454 | 2160–2244 |
| 64 | 0 | cold-sign | 2240 | 84,698 | 2020–2300 | 2244 | 127,232 | 2008–2300 |
| 64 | 0 | prepared-sign | 2240 | 66,747 | 2104–2328 | 2244 | 31,048 | 2240–2336 |
| 64 | 0 | public-import | 2244 | 85,255 | 2016–2304 | 2264 | 113,914 | 1952–2336 |
| 64 | 0 | prepare-verifier | 2240 | 124,161 | 1964–2336 | 2244 | 100,142 | 2008–2336 |
| 64 | 0 | prepared-verify | 2236 | 111,954 | 2020–2336 | 2240 | 110,977 | 2008–2336 |
| 64 | 0 | import-verify | 2272 | 27,431 | 2240–2304 | 2256 | 59,632 | 2152–2336 |
| 16384 | 255 | empty | 2012 | 121,980 | 1968–2268 | 2040 | 153,988 | 1952–2308 |
| 16384 | 255 | seed-expand | 2236 | 109,814 | 1976–2272 | 2256 | 109,947 | 2028–2292 |
| 16384 | 255 | cold-sign | 2176 | 102,842 | 2016–2336 | 2272 | 107,606 | 1964–2336 |
| 16384 | 255 | prepared-sign | 2236 | 77,806 | 2012–2272 | 2228 | 84,190 | 2028–2320 |
| 16384 | 255 | public-import | 2240 | 108,753 | 2016–2304 | 2240 | 56,855 | 2084–2272 |
| 16384 | 255 | prepare-verifier | 2244 | 105,281 | 2012–2304 | 2244 | 34,007 | 2176–2304 |
| 16384 | 255 | prepared-verify | 2272 | 81,029 | 2040–2272 | 2272 | 142,030 | 1952–2336 |
| 16384 | 255 | import-verify | 2272 | 29,197 | 2240–2320 | 2244 | 82,852 | 2016–2300 |
| 64 | 0 | stack-control | 2472 | 129,945 | 2256–2560 | 2464 | 79,727 | 2272–2532 |
| 64 | 0 | rss-control | 10156 | 143,066 | 9896–10344 | 10184 | 121,674 | 9912–10236 |

Positivkontrollen: Ein tatsächlich genutztes 256-KiB-Stackobjekt hebt die erfasste
Spitze gegenüber Leerlauf um 255400 Byte an. Ein 8-MiB-Heapobjekt mit beschriebenen
Speicherseiten hebt die native RSS-Median-Spitze um 8140/8000 KiB an. Beide
Kontrollen bestehen die vorgegebenen Erkennungsschranken; sie werden nicht als
Kryptoverbrauch gezählt. Die Differenzen dienen ausschließlich der Instrumentkontrolle,
nicht einer Baseline-Subtraktion der Kryptowerte.

Beleg: /home/martin/Dokumente/ED301/ED301-v2_resources_8s_1_ann.
SHA-256 der Zusammenfassung:
10c8a877a37a52c613f9019b60c68f738d8ba53c8008c3a3aa07277b36e2bfbc.

## EVP-Signaturen: verfügbare Implementierungen

64-Byte-Nachricht mit Byte i = (29i + 7) mod 256, leerer Context. keygen umfasst einen
frischen EVP_PKEY_CTX, KeyGen-Initialisierung, Erzeugung und Freigabe. sign und verify
verwenden vorbereitete Schlüssel, aber pro Operation einen frischen EVP_MD_CTX mit
Init, einmaliger Signatur-/Verifikationsoperation und Freigabe. Verifikationsschlüssel
bleiben über die Schleife erhalten; dies ist kein erneuter Public-Key-Import pro Aufruf.
Der gleiche Harness wird für alle drei verfügbaren Verfahren verwendet.

| Verfahren | Operation | Median µs | σ µs | Minimum–Maximum µs |
|---|---|---:|---:|---:|
| Ed25519 | keygen | 29,707 | 0,235 | 29,560–30,298 |
| Ed448 | keygen | 161,326 | 1,690 | 160,722–166,010 |
| Ed301-EdDSA-v1 | keygen | 56,753 | 0,675 | 55,869–57,620 |
| Ed25519 | sign | 29,386 | 0,211 | 29,288–29,817 |
| Ed448 | sign | 162,473 | 2,213 | 162,117–168,498 |
| Ed301-EdDSA-v1 | sign | 29,406 | 2,096 | 29,241–35,549 |
| Ed25519 | verify | 80,090 | 0,399 | 79,768–80,836 |
| Ed448 | verify | 173,374 | 2,295 | 170,277–176,590 |
| Ed301-EdDSA-v1 | verify | 85,573 | 1,064 | 84,610–87,540 |

Ed301-EdDSA-v2 über EVP ist in diesem Zwischenstand noch nicht verfügbar und daher
nicht gemessen. Seine Rust-Zeit wird nicht als Ersatz in diese Tabelle eingesetzt.

## EVP-Schlüsselaustausch: verfügbare Implementierungen

keygen enthält EVP_PKEY_Q_keygen und Freigabe. derive-setup misst den frischen
Peer-Public-Key-Import, Context-Erzeugung, Init und Set-Peer. Für jeden derive-Fall
wird ein neuer Context mit demselben privaten Schlüssel und einem frisch importierten
Peer vorbereitet; Setup und Freigabe sind nicht in der derive-Zeit enthalten.
first, second und steady messen jeweils den ersten, zweiten beziehungsweise dritten
Derive-Aufruf dieses Contexts, mit null/einem/zwei ungemessenen vorherigen Aufrufen.
steady ist damit der dritte Aufruf, keine unbegrenzte Langzeit-Cachemessung.
Der gleiche Lifecycle wird bei allen drei Verfahren verwendet.

| Verfahren | Operation | Median µs | σ µs | Minimum–Maximum µs |
|---|---|---:|---:|---:|
| X25519 | keygen | 29,116 | 0,215 | 29,036–29,681 |
| X448 | keygen | 159,991 | 1,052 | 159,394–162,856 |
| X301-v1 | keygen | 28,970 | 0,275 | 28,670–29,519 |
| X25519 | derive-setup | 1,223 | 0,016 | 1,216–1,263 |
| X448 | derive-setup | 1,212 | 0,005 | 1,206–1,221 |
| X301-v1 | derive-setup | 1,686 | 0,010 | 1,679–1,707 |
| X25519 | derive-first | 25,093 | 0,165 | 24,970–25,522 |
| X448 | derive-first | 165,840 | 1,445 | 164,845–169,859 |
| X301-v1 | derive-first | 56,605 | 0,538 | 56,477–58,178 |
| X25519 | derive-second | 25,047 | 0,135 | 24,951–25,320 |
| X448 | derive-second | 166,306 | 0,985 | 164,992–168,474 |
| X301-v1 | derive-second | 56,711 | 0,236 | 56,505–57,216 |
| X25519 | derive-steady | 24,997 | 0,155 | 24,959–25,403 |
| X448 | derive-steady | 166,806 | 1,921 | 164,918–170,760 |
| X301-v1 | derive-steady | 56,697 | 0,226 | 56,420–57,198 |

X301-v1 ist der gebundene historische Integrationsstand, einschließlich seiner damaligen
Eingaberegeln. Der positive Benchmark ist kein Nachweis der v2-Eingaberegeln.
X301-v2 wird erst in Phase D implementiert und dann hier ergänzt. Diese DH-Messungen
sind keine TLS-Handshakes und liefern keinen Authentisierungsnachweis.

## Erfüllter C-Umfang und Integrationsgrenzen

| Pfad | Prüfstand |
|---|---|
| Neue Feld-/Skalar-/Edwards-Konstanten, Lazy-Schranken, 36-Bit-Small-Multiplikator | implementiert; exakte Herleitung, Regeneration und Oracle-Tests |
| Signatur-Domain, innere v2-Kennungen, Gate-B-Vertrag | im Rust-Kern umgesetzt; alte Kennungen nicht umgedeutet |
| Taint, Codegen, Timing, no_std, Safe Rust | bestanden im jeweils dokumentierten Quell-/Binär-/Plattformumfang |
| Kern-/EVP-Baselines, Nachrichten-/Contextmatrix, kalte/vorbereitete Schlüssel | 130 Fälle in den übernommenen Tabellen |
| Isolierte Feld-/Skalar-Mikrobenchmarks | weitere 38 Fälle, Tabelle oben |
| Objekt-/Tabellen-/Binärgrößen, Vorberechnungszeit, Stack-/RSS-Spitzen | erfasst; Beobachtungen, keine universellen Ressourcenobergrenzen |
| v2-Provider, neue OIDs, X301-v2, Encoder/Decoder, PKI-/TLS-/Hybrid-Integration | verbleiben gemäß Martins Phasengrenze in der späteren Integration; nicht durch Benchmarks vorgezogen |
| Quellen-/Belegpaket und Commitbindung | über den äußeren Paketindex und Übergabezettel; keine automatische Freigabe |
| Claudes Gate C | zur Prüfung vorgelegt, nicht selbst erteilt |

### Exakte Bindung der drei Gates

Die Verfahren verwenden verschiedene, explizit gebundene Linkartefakte: den
normalen Kernbenchmark, die taintinstrumentierte Variante und den Timing-Adapter.
Es wird nicht behauptet, dass alle drei Prüfungen dasselbe ELF verwenden.
Gemeinsam sind die unveränderten Produktquellen; der Codegen-Pass gilt genau
für das gemessene Kernbenchmark-ELF, nicht automatisch für andere Linkprodukte.

| Gate / Artefakt | SHA-256 des tatsächlichen Binaries |
|---|---|
| taint: /home/martin/Dokumente/ED301/ED301-v2_core-taint_aif6mcv7/target/release/ed301-eddsa-secret-taint | c8e4ab25d8ad1af7fa19265e2203a2edd859940a46cc271d732d89d7830ccb4f |
| codegen: /home/martin/Dokumente/ED301/ED301-v2_C1C2-benchmark_sklybrw7/ed301-v2-core/target/release/ed301-benchmark | cdddffc53b6330dd1d1a86aca86a7b86690f5f70b2fded7aa01f652e2c9f11df |
| timing-current: /home/martin/Dokumente/ED301/ED301-v2_core-timing_t_imai6j/core_timing | e0f4d0665daf6061d6c021fddc9d5944f499439752b99d1fc884c817bee74798 |
| timing-current: /home/martin/Dokumente/ED301/ED301-v2_core-timing_t_imai6j/libed301_core_timing_adapter.so | 0ddd554d4914722d0e124a4b71ffa728a319e42c4a6d8b94cd3f1e91c6fe0f3f |

Der maschinenlesbare Quell-/Binär-/Belegindex steht unter
/home/martin/Dokumente/ED301/ed301/phase-c/EVIDENCE_INDEX.json.
Das Paket enthält die unveränderten Quellstände, beide vollständigen
commitgenauen v1-Bezugsstände, die drei historischen Parent-Inputs, Freigaben,
gefrorene Primärquellen/Errata und die beobachteten Binaries. Ein portabler
Pfadindex löst die ursprünglichen absoluten Belegpfade innerhalb des Pakets auf.

Ältere Belegmanifeste nennen auch damals vorhandene, später erweiterte
Testharnesses und Berichte. Deren ursprüngliche Bytes liegen zusätzlich als
hashadressierte Archivblobs vor. Dadurch bleibt auch die vollständige historische
Quellliste prüfbar; die alten Vier-Fall-Taint-Harnesses werden nicht mit dem
aktuellen 36-Lauf-Nachweis verwechselt. Die Produktarithmetik wurde während
der abschließenden Mikro-/Ressourcenmessungen nicht geändert.

## Quellenbindung und Rohdaten

Ed301-v1: Commit 5c688206a15f6ab88a50d53fe503665a302cec4d im unveränderten Checkout
/home/martin/Dokumente/ED301/ed301-eddsa-github.
X301-v1: Commit 569dc4ff10e0e5e19d106cbe490d2a5aaeac935e im unveränderten Checkout
/home/martin/Dokumente/ED301/x301-integration. Beide Worktrees waren vor und nach
den Messungen sauber. Alle vier Rust-Artefakte wurden frisch offline gebaut.

v2-Quellmanifest SHA-256: 05ec4ffec3a2c0ac753834e9813c5204e45b504a56f204c03f9a8aba1f120b73.
Es bindet den gemessenen C1/C2-Quellstand einschließlich der zu diesem Zeitpunkt
vorhandenen Phase-C-Werkzeuge; spätere Berichtsdateien sind nicht rückwirkend Teil
jenes Manifests. Der Benchmark prüft die Quellhashes vor und nach der Messung.

Vollständiger Belegordner: [/home/martin/Dokumente/ED301/ED301-v2_C1C2-benchmark_sklybrw7](/home/martin/Dokumente/ED301/ED301-v2_C1C2-benchmark_sklybrw7).

| Artefakt | SHA-256 |
|---|---|
| [/home/martin/Dokumente/ED301/ED301-v2_C1C2-benchmark_sklybrw7/SUMMARY.json](/home/martin/Dokumente/ED301/ED301-v2_C1C2-benchmark_sklybrw7/SUMMARY.json) | 703727808c2ddf633e3dc57641927f50234b61c428530566ac4a863675004007 |
| [/home/martin/Dokumente/ED301/ED301-v2_C1C2-benchmark_sklybrw7/raw.tsv](/home/martin/Dokumente/ED301/ED301-v2_C1C2-benchmark_sklybrw7/raw.tsv) | d269d28fccabf896adfbaec7704826abaca93a391a84afc8444e3de8a0a3e8b5 |
| [/home/martin/Dokumente/ED301/ED301-v2_C1C2-benchmark_sklybrw7/SHA256SUMS](/home/martin/Dokumente/ED301/ED301-v2_C1C2-benchmark_sklybrw7/SHA256SUMS) | 2112b9d64abc30788b7ebe93a95a93fdb9df444aaa29a43c925391db080516ff |

Befehle, Einzelprotokolle, Profilmarker, Quellen- und Binärhashes stehen im Belegordner.
Die SHA256SUMS dort bindet die Belegdateien und kopierten Provider; die großen
Cargo-Targetbäume sind aus dieser Belegliste ausgenommen, ihre maßgeblichen Binärhashes
stehen ausdrücklich in /home/martin/Dokumente/ED301/ED301-v2_C1C2-benchmark_sklybrw7/IDENTITY.json.

Die Tabellen wurden unmittelbar aus den jeweils gebundenen JSON-Zusammenfassungen erzeugt.
Der ursprüngliche C1/C2-Zwischenbericht bleibt unverändert als historischer Beleg erhalten.
