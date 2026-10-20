# Testmuster aus libsodium und Wycheproof (20. Oktober 2026)

Abgleich der eigenen Tests mit libsodium (`test/default/sign.c`) und
Wycheproof (`ed25519`, `ed448`, `x25519`, `x448`). Übernommen wurden
Testmuster, keine Vektoren: Diese gelten für andere Kurven.
Kurvenparameter, Byteformate und Ausgaben sind unverändert.

## Neu

- **`vectors/ed301-eddsa-v2-sign-kat.json`:** 1024 Fälle im Aufbau von
  libsodium, Fall `i` mit `i` Byte Nachricht. Seed und Nachricht aus
  SHAKE256. Rust prüft jeden Fall wie libsodium: Signatur bytegleich,
  Verifikation, `S + q` abgelehnt, letztes Byte von `Signatur ‖ Nachricht`
  geändert abgelehnt, Signatur auf `i mod 76` Byte gekürzt abgelehnt.
  Danach wie libsodium: obere Bits von `S`, nichtkanonischer, Null- und
  ungültiger öffentlicher Schlüssel. Den Fall mit überlappenden Puffern gibt
  es in sicherem Rust nicht.
- **`vectors/ed301-eddsa-v2-wycheproof.json`:** Wycheproof-Format
  `eddsa_verify_schema_v1`. Jedes der 304 Bits von `R` einzeln gekippt,
  `S` dazu passend neu berechnet; alle Bits von `R` gekippt; Sonderwerte
  `r ∈ {0, 1, q, p}`, `s ∈ {0, 1, q−1, q, p}`.
- **`vectors/x301-v2-wycheproof.json`:** Wycheproof-Format
  `xdh_comp_schema_v1`, 508 Fälle.
  - `EdgeCaseMultiplication`: `u` so gewählt, dass eine Variable der
    RFC-7748-Leiter (Wycheproof-Namen `A` … `z_2`) bei Präfix `k = 2 … 9`
    einen Sonderwert annimmt. Sonderwerte wie bei X25519/X448:
    `0, 1, −1, 2^(n−1)−1, 2^224, 2^n mod p`. Nullstellen mit PARI/GP
    `polrootsmod`, Treffer in Python nachgerechnet.
  - `EdgeCaseShared`: Ergebnisse nahe `1`, `2^300`, `2^296`, `p`, `2^295`,
    `2^293`, nach dem X25519-Muster.
  - `SpecialPublicKey`: `2^e`, `2^e−1`, `p−2^e` und Wortmuster.
  - `EdgeCasePrivateKey`: Schlüssel `≡ 1 mod q` bzw. `mod q_twist` und die
    Muster `0x55…`, `0xaa…`. `≡ −1` ist mit der X301-Klemmung nicht
    darstellbar.
- **Bit-Mutationen:** `deterministic_single_bit_mutations_fail_closed`
  kippt jedes Bit von Schlüssel, Signatur und Nachricht, vorher nur Bit 0
  je Byte.

## Prüfung

- Rust: Ed301 bytegleich zu Python; X301 Produktionsleiter und kanonisches
  Orakel gegen die Python-Ergebnisse.
- Python: `tests/test_external_pattern_vectors.py`; `x_2`/`z_2` zusätzlich
  gegen `[k]P` der Referenzleiter.
- Node: `reference/node/check_x301_wycheproof.mjs`.
- Neu erzeugen: `tools/generate_external_pattern_vectors.py <corpus> --check <datei>`.

Die Sonderwerte zielen auf die RFC-7748-Formeln. Die Produktionsleiter
skaliert `(x_2, z_2)` mit dem Nenner von `a24`; ihre Zwischenwerte sind
dadurch nicht identisch, wie bei anderen Implementierungen auch.
