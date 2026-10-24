# Optimierung vom 24. Oktober 2026

Kurvenparameter, Byteformate und Ausgaben sind unverändert. Geprüft von
Claude und Codex, beides KI-Bewertungen, keine unabhängige Validierung.

## Geändert

- **Kleiner Multiplikator (`mul_small`, `mul_small_narrow`):** Reduktion
  mit demselben subtraktionsfreien Fold `low + high·K`, `K = 2^89 − 907`,
  wie `reduce_wide_unreduced`. Vorher: `high·2^89` addiert, `907·high`
  abgezogen, nach Unterlauf `p` addiert. Entfallen sind eine Borrow-Kette
  und eine Auswahl über fünf Wörter. Schranke: `high < 2^37`, Ergebnis
  `< 2^301 + 2^126 < 2p`.
- **Härtung:** Eine const-Assertion bindet `FOLD_LOW`/`FOLD_HIGH` an den
  Modul (`p + K = 2^301`) und an `FOLD_SUBTRAHEND`/`FOLD_SHIFT`.
  `accumulate_fold` prüft per `debug_assert!`, dass kein Übertrag verloren
  geht, für alle drei Reduktionen, auch beim Tabellenbau zur Compilezeit.
- **`phase-c/FIELD_BOUNDS.md`, `check_field_bounds.py`:** auf den
  additiven Fold umgestellt, beide Übertragsketten belegt.
- **Codegen-Gate (`codegen_ed.sh`, `codegen_x.sh`):** Jeder eingebettete
  `mul_small` bringt etwa fünf sbb und genau fünf cmov weniger. Minima
  `double` 35→30 cmov, `add` 35→25 cmov und 25→20 sbb, `add_affine`
  30→25 cmov. Vorläufig, aus rustc 1.99.1 abgeleitet; bestätigt erst nach
  dem kanonischen Gate mit rustc 1.98.

## Messung

Ryzen 9 5950X, rustc 1.99.1, CPU 2, je 7 Läufe abwechselnd, Median in µs:

| Operation | Vorher (`01f341e`) | Nachher |
| --- | ---: | ---: |
| sign | 24.01 | 24.03 |
| verify | 67.91 | 67.51 |
| X301 shared | 57.94 | 56.63 |
| X301 public | 21.87 | 21.92 |

X301 −2,3 %, sonst im Rauschen. Lokale Disassembly (rustc 1.99.1),
sbb/cmov: `add` 35/35 → 26/25, `add_affine` 30/30 → 26/25,
`double` 34/40 → 29/35, `ladder301` 39/60 → 30/50. Keine bedingten
Sprünge hinzugekommen.

## Prüfungen

- `cargo fmt --check`, `cargo clippy --all-targets` (Ed301 mit und ohne
  `sign-self-verify`, X301): ohne Befund.
- Tests release: 73/73 Ed301, 64 X301. Dev-Profil mit `debug_assert!`:
  73 Ed301, 64 X301. Alle bestanden.
- `check_field_bounds.py`: PASS.
- Core-Taint (`phase-c/tools/run_core_taint.py`): PASS, 36 Valgrind-Läufe.
- X301-Taint (`phase-e/tools/run_x301_taint.py`): PASS, 263 Fälle,
  526 Valgrind-Läufe. Beide Läufe auf demselben Quellstand
  (Manifest `471d782b…`).
- Nicht gelaufen: kanonisches Codegen-Gate (rustc 1.98). Die Ladder-Prüfung
  in `codegen_x.sh` bindet feste Stack-Offsets, `check_codegen_dataflow.py`
  die ersten Ladder-Instruktionen und den Multiplikationspfad. Beide können
  sich verschieben; bei Abweichung zuerst die Datenherkunft prüfen, dann
  die Vorgaben anpassen.
