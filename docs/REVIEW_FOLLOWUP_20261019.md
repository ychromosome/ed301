# Nachtrag vom 19. Oktober 2026

Anlass: zweiter Durchlauf desselben KI-Reviews (Google Gemini) auf den
Bundles des Standes `crypto-review` `ec3259b`. Nachgeprüft von Claude und
Codex (`gpt-6-astra`), beides KI-Bewertungen, keine unabhängige Validierung.
Kurvenparameter, Byteformate und Ausgaben sind unverändert.

## Geändert

- **Basispunkt-Tabelle:** `AffineNielsPoint` ohne `xy = x + y`.
  Zuvor wurde der ausgewählte Punkt konstantzeitig stets negiert und dessen
  Summe dabei neu berechnet. Tabelle 48 640 → 36 480 Byte,
  `VerifyingKey` 10 280 → 7 720 Byte.
- **X301 `get_params`:** Eine Abfrage mit `pub` und `priv` auf einem
  Public-Only-Schlüssel lässt `priv` unberührt und gelingt, wie bei Ed301
  und OpenSSLs `ecx_get_params`. Vorher schlug die ganze Abfrage fehl.
  Test T6 in `provider_x301_contract.c`.
- **`reduce_wide_unreduced`:** `debug_assert!` auf die dokumentierte
  Produktgrenze `< 2^606`.
- **Ed301-Capability-Kommentar:** nur TLS-GROUP bricht in libssl ab; das
  Ergebnis von TLS-SIGALG wird ignoriert.

## Eingeordnet, nicht geändert

- X301 liefert für fremde Capabilities 0, wie OpenSSLs Default-Provider.
  libssl wertet das bei TLS-SIGALG nicht aus. Kein Fehler.
- Hybrid-KEYMGMT ohne MATCH, DUP und VALIDATE: für TLS nicht benötigt.
  Fehlender Validator heißt in OpenSSL Erfolg ohne Prüfung.
- `[q]A` per Double-and-add statt Halving: 299 Verdopplungen, teurer als
  drei Exponentiationen.
- Cofaktorisierte Verifikation mit Torsion in `R`: `R` geht in den Hash ein,
  keine einfache Torsionsumformung einer bestehenden Signatur.
- Stack-Kopien geheimer `Copy`-Werte, Seed-Quelle des Child-DRBG, fester
  DER-Codec, hermetischer Build: bekannt und dokumentiert.

## Messung

Ryzen 9 5950X, rustc 1.99, `rust/performance/ed301-bench`, CPU 2,
7 × 20 000 Aufrufe abwechselnd, Median in µs:

| Operation | Vorher (`e6b8c50`) | Nachher |
| --- | ---: | ---: |
| import | 44.89 | 44.89 |
| sign | 29.60 | 24.63 |
| verify | 69.64 | 69.34 |
| expand | 28.67 | 23.54 |

Die README-Werte stammen aus einem eigenen Lauf mit dem Messverfahren aus
`crypto-review` (`benchmarks/run.py`, OpenSSL 4.0.3).

## Prüfungen

rustc 1.99.0, x86-64:

- `cargo fmt --check`, `cargo clippy --all-targets` für Ed301 (ohne und mit
  `sign-self-verify`) und X301: ohne Befund.
- Tests: 71 Ed301 je Konfiguration, 63 X301, alle bestanden.
- Core-Taint (`phase-c/tools/run_core_taint.py`): PASS, 36 Valgrind-Läufe.
- X301-Taint (`phase-e/tools/run_x301_taint.py`): PASS, 263 Fälle,
  526 Valgrind-Läufe. X301 nutzt dieselbe Basispunkt-Tabelle.
- `provider_x301_contract` gegen das neu gebaute `x301_v2`: alle Fälle
  bestanden; gegen `e6b8c50` schlägt der neue T6-Fall fehl.
- Nicht gelaufen: Codegen-Gate (rustc 1.98), vollständige Provider-Suite,
  OpenSSL-3.5-Lane.
