# Nachtrag vom 17. Oktober 2026

Anlass: zweiteiliges KI-Review (Google Gemini) des Standes Testing `9ef3fc2`
bzw. `crypto-review` `ec3259b`. Die Aussagen wurden von Claude nachgerechnet
(eigenes Python-Skript, Kurve ohne Projektcode nachgebaut, 4000 Punkte in
allen vier Nebenklassen von `E[q]`). Beides sind KI-Bewertungen, keine
unabhängige Validierung. Kurvenparameter, Byteformate, Decoder und
Signaturpfade sind unverändert.

## Geändert

- **Halving-Prädikat:** `chi(w)` entfällt. Auf der Kurve gilt
  `1 − y² = x²(a − dy²)`, also `w = B(1 − y²) = (2x/(a − d))²·Δ` mit
  `Δ = (a − d)(a − dy²)`. `Δ` ist nie null, weil `a/d` ein Nichtquadrat ist.
  Für `x ≠ 0` ist `chi(w)` damit gleich der Wurzelmaske von `Δ`; `x = 0`
  heißt `y = ±1` und wird ohnehin ausgeschlossen. Import: drei statt vier
  Exponentiationen. Tests: 100 000 Zufallspunkte und 25 Vektoren vergleichen
  `chi(w)` mit der Wurzelmaske und beide Prädikate mit `[q]P`.
- **`Fe301::invert`:** Konvertierungspuffer und Montgomery-Kopien werden
  genullt. Temporäre innerhalb der safegcd-Inversion von crypto-bigint
  bleiben außerhalb der Kontrolle dieser Crate.
- **`scalar_mul_base_encoded`:** `debug_assert!` auf oberes Byte `< 0x80`.
  `signed_radix16` trägt keinen Carry aus der obersten Ziffer; kanonische
  und geprunte Skalare erfüllen die Bedingung.
- **Codegen-Gate:** eine statt zwei Euler-Aufrufstellen im Import
  (`check_codegen_dataflow.py`, `CODEGEN_POLICY.md`). Gate nicht gelaufen;
  benötigt rustc 1.98.

## Eingeordnet, nicht geändert

- „Keine echte getwistete Kurve“: `a = s²` ist ein Quadrat, die Kurve ist
  isomorph zu `x̃² + y² = 1 + (d/a)·x̃²y²` mit `x̃ = s·x`. Bei `p ≡ 3 (mod 4)`
  muss `a` für vollständige Addition ein Quadrat sein; `a = −1` ist hier
  nicht möglich. Keine Auswirkung auf Gruppe, Ordnung oder Sicherheit.
  Kosten: ein `mul_small(a)` je `double` und `add_affine`.
- Niels-Layout `(y+x, y−x, dt)`: setzt `a = −1` voraus; nicht anwendbar.
- X301-Leiter: zwei `mul_small` je Runde statt einer. Anteil wenige Prozent.
- `hybrid_kem.c`, roher `HYBRID_KEY`-Zeiger im KEM-Kontext: kein
  Use-after-free. `EVP_PKEY_CTX` hält eine Referenz auf den `EVP_PKEY`, das
  keydata lebt mindestens so lange wie der Kontext. OpenSSLs eigenes
  ML-KEM-KEM speichert den Schlüssel ebenso als rohen Zeiger.
- `key_import` X301 vs. Ed301 bei vorbelegtem Schlüsselobjekt: inkonsistent.
  Über EVP nicht erreichbar, Import erfolgt nur auf frischem keydata.
- DER-Codec, Langform-Länge: wird als „nicht meins“ zurückgespult statt
  hart abgewiesen. Ergebnis gleich, kein anderer Decoder kennt die OID.
- `WeakSecret` in X301: doppelte Absicherung neben dem `Z = 0`-Test; bleibt.

## Offen

- **ML-KEM auf dem Child-Libctx** (`hybrid_kem.c`: `EVP_PKEY_Q_keygen`,
  `EVP_PKEY_encapsulate`): OpenSSL legt dabei Thread-DRBGs mit
  Thread-Exit-Handlern auf dem Child-Kontext an, genau das, was
  `provider_rand.h` für X301 vermeidet. Lösung: Keygen-Seed
  (`OSSL_PKEY_PARAM_ML_KEM_SEED`) und Encapsulate-Zufall
  (`OSSL_KEM_PARAM_IKME`) aus dem Provider-DRBG übergeben.
- **Fermat-Inversion** `z^(p−2) = (z^((p−3)/4))⁴·z` statt safegcd: entfernt
  safegcd und `field.rs` aus dem Produktionspfad und löst die
  Nullungsfrage vollständig. Messung siehe unten; Entscheidung offen.

## Messung

Ryzen 9 5950X, rustc 1.99, `rust/performance/ed301-bench`, 5 × 20 000
Aufrufe, Median in µs:

| Operation | Vorher (`9ef3fc2`) | Nachher | Fermat-Variante |
| --- | ---: | ---: | ---: |
| import | 50.99 | 44.65 | 53.87 |
| sign | 29.80 | 29.69 | 32.70 |
| verify | 69.81 | 69.96 | 69.90 |
| expand | 28.66 | 28.86 | 31.86 |

Die Fermat-Variante ist der Ausgangsstand mit
`self.pow_p_minus_3_over_4().square().square().mul(self)` als Inversion;
sie kostet rund 3 µs je Inversion mehr als safegcd (`sign`, `expand`, und
die Tabellen-Normalisierung in `import`).

## Prüfungen

rustc 1.99.0, x86-64:

- `cargo fmt --check`, `cargo clippy --all-targets` für Ed301 (ohne und mit
  `sign-self-verify`) und X301: ohne Befund.
- Tests: 71 Ed301 je Konfiguration, 63 X301, alle bestanden.
- Core-Taint (`phase-c/tools/run_core_taint.py`): PASS, 9 Vektoren,
  36 Valgrind-Läufe.
- Nicht gelaufen: Codegen-Gate (rustc 1.98), Provider-Testsuite,
  Import-Boundary-Taint (benötigt Receipt-Kette), OpenSSL-3.5-Lane.
