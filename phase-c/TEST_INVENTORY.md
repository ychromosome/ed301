# C1/C2-Testinventur und Übertragung aus v1

Stand: 10. September 2026. Kein Ersatz für Claudes Gate C.

Gebundener v1-Bezugsstand: Commit
5c688206a15f6ab88a50d53fe503665a302cec4d in
/home/martin/Dokumente/ED301/ed301-eddsa-github.
Der aktuelle v2-Kern liegt in
/home/martin/Dokumente/ED301/ed301/rust/crates/ed301-eddsa.
Die Tabelle nennt Rust-Modulnamen, keine verkürzten Dateipfade.

## Vollständigkeit der Kern-Testgruppen

| Testmodul | v1 Testfunktionen | v2 Testfunktionen | Übertragung / neue Parameter |
|---|---:|---:|---|
| field::tests | 7 | 7 | strikte Grenzen, Modulus, reservierte Bits, Arithmetik, Inversion, Auswahl und Swap, Wurzeln |
| field_5x64::tests | 5 | 8 | ursprüngliche fünf Oracle-/Grenztests erhalten; drei neue Tests für Small-u64-Schranke, Const/Runtime-Gleichheit und Lazy-Negation |
| scalar::tests | 6 | 6 | q, Radix 2^304, vollständige 608-Bit-Eingabe, höchste Eingabebytes und wNAF-Breitenfehler |
| edwards::tests | 13 | 13 | neue Konstanten und Vektoren, dieselben Gruppen-, Dekoder-, Tabellen-, Leiter- und Untergruppeneigenschaften |
| secret::tests | 1 | 1 | benannter Zeroize-Besitzer bei Unwind |
| signature::test_support | 3 | 3 | reale Unwind-Fehlerpunkte und Wiederaufnahme, intern/extern validierte Schlüssel, Signaturobjekt genau 76 Byte |
| signature_hash::tests | 3 | 3 | SHAKE-Leerwert, Rate-Grenzen, Contextlänge als einzelnes Byte |
| vector_tests | 13 | 13 | neuer Gate-B-Korpus, explizite Übertragung unten |
| Summe | 51 | 54 | Zählung der Testfunktionen, nicht der internen Einzelassertionen |

Die spezialisierten Feldtests vergleichen gegen die vorhandene generische
crypto-bigint-Montgomery-Arithmetik beziehungsweise gegen einen eigenen breiten
Test-Reduktor. Sie umfassen die Lazy-Domäne und bis zu 606 Bit breite Produkte.
Der öffentliche Small-Multiplikator ist ausdrücklich auf 36 Bit begrenzt;
u64 als Argumenttyp ist keine Freigabe des vollen u64-Wertebereichs.

## Vektor-Testabsichten

Alle genannten Funktionsnamen gehören zum Modul vector_tests in
/home/martin/Dokumente/ED301/ed301/rust/crates/ed301-eddsa/src/vector_tests.rs.

| v1-Testabsicht | v2-Prüfung | Entscheidung |
|---|---|---|
| positive Signaturen und Zwischenwerte | all_positive_vectors_and_intermediates_match | 9 Gate-B-Signierfälle, je 12 gebundene Werte, Signieren und Verifizieren |
| Draft-00/v1-Trennung | frozen_v1_fixture_keys_and_signatures_are_separated_from_v2 | 7 unveränderte v1-Fixtures als Gegenstellen; alter/neuer Public Key getrennt |
| native Contexts und Grenzen | native_context_vectors_and_boundaries_match | leer, binär, 255 erlaubt, 256 abgelehnt |
| nichtkanonisches Commitment | all_sixty_one_verification_cases_match; point_sign_and_reserved_bit_boundaries_are_explicit | in vollständiger neuer Matrix enthalten, kein gestrichener Ablehnungsfall |
| Punkt-/Skalarakzeptanz | complete_point_and_scalar_acceptance_matrices_match | 15 Punkt- und 6 Skalarfälle |
| 22 historische Verifikationsränder | all_sixty_one_verification_cases_match | 61 neue Fälle einschließlich erlaubter/verbotener Torsions-R-Gleichungen |
| S + q ablehnen | adding_the_group_order_to_s_is_rejected_as_noncanonical | neues q, weiterhin keine automatische Reduktion |
| angrenzende Byte-Längen | parsers_fail_closed_for_adjacent_lengths | Schlüssel- und Signaturgrenzen bleiben strikt |
| stabile Fixture-IDs | fixture_ids_are_the_expected_stable_set | explizite neue 9er-Menge |
| reine Torsion, Faktor 4 | pure_torsion_commitments_are_accepted_only_by_the_factor_four_language | Faktoren 1/2/4 getrennt geprüft |
| gemischte Torsion | mixed_torsion_matrix_distinguishes_factors_one_two_and_four | gleiche Unterscheidung mit neuen Punkten |
| Vorzeichen-/Reserved-Bits | point_sign_and_reserved_bit_boundaries_are_explicit | neue Feldgrenzen, alte Byteregeln |
| Einzelbyte-Mutationen | deterministic_single_byte_mutations_fail_closed | Schlüssel, Signatur, Nachricht |
| zusätzlich explizit: Signierfehler | signing_error_corpus_is_rejected | 4 gebundene Fehlerfälle |

Die Zeilenzahl dieser Absichtstabelle ist nicht die Testfunktionszahl: Der frühere
separate Commitmenttest ist in zwei umfassendere Prüfungen eingegangen; dafür
steht der Signierfehlerkorpus jetzt in einer eigenen Testfunktion.

v1 nach v2 wird unmittelbar im Rust-Test geprüft. Die Gegenrichtung besitzt
bereits echte positive v1-Kontrollen und negative Cross-Profile-Prüfungen in
/home/martin/Dokumente/ED301/ed301/tests/test_reference.py
(test_v1_fixtures_positive_controls_and_both_cross_directions). Der Rust-v2-Kern
reproduziert den gebundenen v2-Korpus exakt. Dies sind zwei verknüpfte Nachweise;
es wird kein bislang nicht ausgeführter direkter Rust-v1/Rust-v2-Interop-Test behauptet.

## Parameterabhängige Erwartungen nicht blind übernehmen

Der frühere konkrete Nichtpunkt mit y = 3 ist unter dem neuen Modulus nicht
zwingend ein Nichtpunkt. Die neue Negativkodierung stammt deshalb aus dem
gebundenen Gate-B-Fall mit nichtquadratischem x. Ebenso liefert der feste
Wurzelexponent für 25 jetzt die andere der beiden gültigen Wurzeln. Die exakte
Erwartung wird aus dem neuen Modulus regeneriert; Quadrat, Parität und
Dekoderentscheidung bleiben geprüft. Diese Änderungen schwächen keine Regel ab.

## Weitere Nachweise und offene Grenzen

Taint: 9 Signierfälle × Public/Sign × definiert/geheim = 36 Valgrind-Läufe,
mit Prüfung der tatsächlichen Input-Validity-Bits und exakten öffentlichen Ausgaben.
Codegen: gebundenes endgültiges x86-64-Kernbenchmarkbinary, feste Schleifen,
Aufrufketten, gerade Secret-Pfade und Negativkontrollen. Dudect: positive
Leakage-Kontrolle und zwei Kernoperationen, zwei dokumentierte Läufe.
Diese Werkzeuge beweisen weder alle möglichen Seitenkanäle noch andere Plattformen.

Der Kern deklariert no_std und forbid(unsafe_code); die normalen Abhängigkeiten
werden ohne Default-Features eingebunden. Ein separater no_std-Consumer wird
frisch auf dem Host gebaut. Das ist kein Bare-Metal-, AArch64- oder Allocatorbeweis.
Der minimale Timing-FFI-Adapter und die Valgrind-Instrumentierung liegen außerhalb
des Produktkerns; ihre nötigen Unsafe-Grenzen werden nicht als Safe Rust ausgegeben.

Provider-, PKI-/TLS-, Hybrid- und X301-v2-Tests werden nicht als erledigte
Kern-Tests gezählt. Die globale Funktionsinventur bleibt für diese Integrationsstufe
verbindlich. Auch isolierte Feld-/Skalar-Mikrobenchmarks, vollständige Ressourcen-
messung und ein eigenständig entpackbares Gate-C-Reviewpaket sind noch offen.
