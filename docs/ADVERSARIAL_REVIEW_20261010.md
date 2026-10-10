# Adversarial Review des Rust-Codes

Stand: 10. Oktober 2026, Testing `17ebb2a` (nach der Performance-Durchsicht).
Gegenstand: die Kerne `ed301-eddsa` und `x301-core`, die Provider-FFI-Module
`sig_ffi.rs`, `x301_ffi.rs` und `allocation.rs` sowie die in dieser Sitzung
eingeführten Änderungen (projektive Verdopplung in der Verifikation,
Additionskette für `(p-3)/4`). Perspektive: Angreifer mit Kontrolle über alle
öffentlichen Eingaben (Public Keys, Signaturen, Peer-Koordinaten, Kontexte,
FFI-Argumente) und über die Aufrufreihenfolge der Provider-Callbacks.

## Ergebnis

Kein ausnutzbarer Fehler gefunden: keine falsche Annahme oder Ablehnung,
keine Panic auf untrusted Eingaben, keine Zustandsverletzung in der FFI,
kein neuer geheimnisabhängiger Kontrollfluss. Eine Härtung wurde umgesetzt
(fail-closed statt stilles Fehlurteil, siehe unten). Vier Beobachtungen
bleiben als dokumentierte Restrisiken oder Entscheidungen.

## Methode

Statisch, Zeile für Zeile:

- Schranken der faulen Feldarithmetik: Eingaben `[0, 2p)` und `[0, 4p)`,
  Produkte unter `2^606`, zwei Faltungen, kleine Multiplikatoren unter
  `2^36` bzw. `2^32`, Unterlauf-Korrektur mit `p`; alle Pfade der
  Gruppenformeln (`add`, `add_affine`, `double`, `DoublingTerms`, Leiter)
  gegen diese Schranken nachgerechnet.
- Montgomery-Skalarreduktion: `ConstMontyForm::new` ist eine reine
  Multiplikation mit `R²` ohne Eingabeschranke unterhalb des Modulus; für
  Eingaben `< R` liefert REDC ein Ergebnis `< 2L` mit einer bedingten
  Subtraktion. `invert` (Kodierung des geheimen `Z`, X301-Finalisierung)
  ist der constant-time safegcd-Pfad, getrennt von `invert_vartime`.
- Dekodierung und Kanonizität: `y ≥ p`, reservierte Bits, `x = 0` mit
  gesetztem Vorzeichenbit, `S ≥ L`, Identität und Torsion als `R`
  (zulässig, kofaktorierte Gleichung) und als Public Key (abgelehnt).
- Halbierungstest: Beide Wurzelvorzeichen liefern dasselbe zweite Symbol,
  sobald das erste Symbol besteht (Produkt der beiden Kandidaten ist dann
  ein Quadrat); die Wahl des festen Wurzelkandidaten ist daher unkritisch.
- wNAF: Breite 8, Ziffern in `[-127, 127]` ungerade, Tabellenindex `≤ 63`,
  302 Ziffernplätze für Skalare unter `2^300`; neue Straus-Schleife mit
  führender Nullüberspringung und projektiven Verdopplungsläufen gegen die
  bisherige Schleife verifiziert.
- Radix-16-Rekodierung: Ziffer 75 höchstens 2 (gestutzt) bzw. 1 (kanonisch),
  kein Überlauf der Tabelle `[1..8]`.
- X301: Clamp, Ablehnung der Twist-Ordnung, 301 Leiterrunden, skalierte
  `a24`-Formel, All-Zero-Prüfung gegen Punkte kleiner Ordnung auf Kurve und
  Twist (Kofaktor 4 wird durch den Clamp vernichtet).
- FFI: Null/Längen-Konventionen zwischen C-Shim und Rust (`NULL` + 0 für
  fehlende Puffer), Atomarität abgelehnter Importe, Operationswechsel,
  Rückgabewerte `-1/0/1` der Verifikation, `Shared`-Referenzzählung,
  Mutex-Vergiftung, Send/Sync.
- Panic-Stellen im Nicht-Test-Code: ausschließlich Compile-Zeit-Asserts und
  Prüfungen öffentlicher Konstanten; `debug_assert` nur als Diagnose.

Aktiv, mit rustc 1.97.0 (x86-64):

- Gesamte Testsuite im Debug-Profil (aktive `debug_assert`-Schranken in
  `add_loose`/`sub_loose`/wNAF): 70/70/63 bestanden.
- Panic-Fuzzing: 100 000 zufällige und 120 strukturierte Public Keys durch
  `validate_public_key`/`VerifyingKey::from_bytes` (3 080 angenommen,
  erwartet etwa 1/32); 100 000 zufällige und 14 400 strukturierte
  Signaturen (alle Kombinationen aus `R`, `S` ∈ {0, p, L, 2^304−1} ± 2 mit
  sechs Masken des obersten Bytes) gegen einen gültigen Schlüssel (0
  angenommen); falsche Längen 0…1000; Kontexte 0…1000 Byte (Grenze 255
  exakt); 1-MiB-Nachricht. X301: 300 Secrets × 60 Peers plus 175
  strukturierte Werte um 0, p, 2^304−1, Basis-u und Twist-Ordnung; alle
  Fehlerklassen erreicht, keine Panic.
- Round-Trip auf 600 zufälligen Schlüssel/Nachricht/Kontext-Tripeln mit je
  einem Bit-Flip in Signatur, Nachricht, Public Key und mit verändertem
  Kontext oder fremdem Schlüssel: alle abgelehnt.
- Fixed-Base-Extrema (`2^300`, `2^301−4`, Muster, 200 Zufallswerte) gegen
  die 301-Runden-Leiter; kanonische Skalare 0, 1, L−1 auch durch die
  Straus-Schleife.
- Provider-FFI-Fehlbedienung: Signieren ohne Init, Verifizieren auf
  Sign-Kontext (−1), Null-Schlüssel-Reinit, Ausgabepuffer 75, Null-Ausgabe,
  Signaturlängen 75/77 (0) und Null-Signatur (−1), Kontext 256 (abgelehnt,
  alter Kontext bleibt), Größenabfrage, Null-Objekte; Importe mit falschem
  Seed/Public-Paar, falschen Längen, Null-Zeiger mit Länge, ungültiger
  Kodierung und fremdem Public Key lassen den Schlüssel bytegleich zurück;
  Public-only-Schlüssel kann nicht signieren und exportiert kein Secret.
- Valgrind-Secret-Taint nach der Härtung: Ed301 public/sign (36 Läufe),
  Importgrenze (definiert/markiert/definiert, Exit 0/101/0): bestanden.
- Maschinencode-Diff je Funktion: die Härtung ändert ausschließlich
  `ValidatedPublicKey::from_bytes`; X301 bleibt bitgleich.

## Härtung: `is_prime_subgroup_decoded` scheitert geschlossen

Die Halbierungsterme lesen `y` als affine Koordinate; die Zusicherung
`Z = 1` war nur ein `debug_assert`. Ein künftiger Aufrufer mit projektivem
Punkt hätte im Release-Profil ein stilles Fehlurteil bekommen (Annahme eines
Punktes falscher Ordnung möglich). Das Prädikat verknüpft jetzt zusätzlich
`Z == 1` und liefert für jede andere Darstellung `false`. Der einzige
Aufrufer (`ValidatedPublicKey::from_bytes`, nach `decode`) ist unverändert
affin. Neuer Test: eine projektive Darstellung eines gültigen Punktes wird
abgelehnt, ihre kanonische Neudekodierung angenommen. Kosten: ein
Limb-Vergleich im Import.

## Beobachtungen ohne Änderung

1. `key_match` mit Schlüsselpaar-Selektion verlangt beidseitig vorhandene
   Komponenten; OpenSSLs eigene Schlüsselmanager vergleichen dann nur die
   vorhandenen. `EVP_PKEY_eq` nutzt nur die Public-Selektion, daher ist die
   Abweichung über die EVP-API nicht erreichbar und fail-closed. Keine
   Änderung ohne Abgleich mit der Provider-Akzeptanzmatrix.
2. `select_basepoint` gibt den gewählten Tabelleneintrag per Wert zurück;
   dieser ziffernabhängige Stack-Wert wird nicht genullt. Das fällt in die
   dokumentierte Klasse der Compiler-Temporaries (E8d); eine Änderung
   berührt den festgeschriebenen `scalar_mul_base`-Aufrufgraphen des Gates.
3. Der X301-Provider leitet beim Import mit Secret den Public Key auch dann
   ab, wenn er mitgeliefert wird (Abgleich, etwa 45 µs). Korrekt, nur Kosten.
4. `vartime_wnaf` und `mul_small` prüfen öffentliche Konstanten mit
   `assert!`; unerreichbar aus Eingaben.

## Nicht geprüft

Codegen-Gate und Messungen auf dem Referenz-Compiler (wie in der
Performance-Durchsicht), Python-/Node-Referenzen, der C-Shim selbst über die
Aufrufkonventionen hinaus, Keccak-Backend. Der Fuzz-Harness lag außerhalb
des Repositoriums und ist hier nach Umfang und Seeds beschrieben.
