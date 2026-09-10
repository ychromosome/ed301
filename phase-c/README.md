# Lokaler C1/C2-Zwischenstand

## Historischer Stand; aktueller Einstieg

Dieser Abschnitt und die folgenden Befehle gehören zum Phase-C-Kernstand
`0be31f50cccf3d5af4675d081661ea463c575027`; die Gate-C-Freigabe wurde in
`2b605d77d1f940f74e090796d7b345ef812a1da1` dokumentiert. Der damalige
Korrektheitsrunner verlangt genau 54 Tests. Er ist kein Prüfer für den
optimierten E8-Stand mit 65 Ed301-Tests; sein Abbruch auf E8 ist erwartbar.
Historische Quellmanifeste bleiben unverändert und werden ausschließlich
gegen ihren gebundenen historischen Snapshot geprüft.

Aktueller gemeinsamer Ed301-/X301-Korrektheitsrunner:
/home/martin/Dokumente/ED301/ed301/phase-e/tools/check_core_correctness.py.
Baseline-/Previous-Argumente und Hinweise zur vollständigen Quellenbindung:
/home/martin/Dokumente/ED301/ed301/phase-e/README.md.
Die historischen Mess- und Taint-Harnesses werden weiterhin gezielt von
Phase E verwendet; dadurch wird der alte 54-Test-Gate nicht zum aktuellen Gate.

## Ursprünglicher Zwischenbericht

Statusbericht mit allen 130 Benchmarkfällen:
[/home/martin/Dokumente/ED301/ed301/phase-c/BERICHT_C1_C2_2026-09-10.md](/home/martin/Dokumente/ED301/ed301/phase-c/BERICHT_C1_C2_2026-09-10.md).

Dies ist kein vollständiges Gate-C-Paket. Noch offen sind insbesondere isolierte
Feld-/Skalarmessungen, Stack-/RSS-Spitzen und die vollständige externe Paketierung;
Provider-/Format-/TLS- und X301-v2-Pfade bleiben in ihrer Integrationsphase.
Keine Gate-C-Freigabe, kein Produktrelease, kein Commit oder Push dieses Stands.

Das lokale Quellmanifest bindet den gesamten neuen Rust-/Phase-C-Baum und das
bereits freigegebene Phase-B-Quellmanifest. Es enthält sich selbst nicht.
Prüfung aus dem Repository:

```sh
cd /home/martin/Dokumente/ED301/ed301
sha256sum --strict --check phase-c/C1C2_SOURCE_SHA256SUMS
```

Frische Offline-Prüfung des Kerns einschließlich Phase-B-Replay:

```sh
python3 -I -B /home/martin/Dokumente/ED301/ed301/phase-c/tools/check_core_correctness.py
```

Separate Mess-/Seitenkanalläufe, jeweils mit eigenem Belegordner:

```sh
python3 -I -B /home/martin/Dokumente/ED301/ed301/phase-c/tools/run_available_benchmarks.py
python3 -I -B /home/martin/Dokumente/ED301/ed301/phase-c/tools/run_core_matrix.py
python3 -I -B /home/martin/Dokumente/ED301/ed301/phase-c/tools/run_core_taint.py
python3 -I -B /home/martin/Dokumente/ED301/ed301/phase-c/tools/run_core_timing.py
```

Die Benchmarkrunner verlangen die sauberen gebundenen v1-Checkouts, CPU 2 und
installierte Systemwerkzeuge. Sie laden keine Quellen aus dem Netz und verändern
weder die Bezugsstände noch Governor/Boost. Konkrete Plattform, Profile,
Histogramm-/Messgrenzen und Artefakthashes sind im Bericht abgegrenzt. Der
Codegen-Prüfer wird auf ein ausdrücklich ausgewähltes endgültiges Kern-ELF
angewendet; ein neues Linkartefakt übernimmt keinen alten Gate-Pass.

Verwandte Nachweise:

- /home/martin/Dokumente/ED301/ed301/phase-c/FIELD_BOUNDS.md
- /home/martin/Dokumente/ED301/ed301/phase-c/TEST_INVENTORY.md
- /home/martin/Dokumente/ED301/ed301/phase-c/SOURCE_IMPORT.md
- /home/martin/Dokumente/ED301/ed301/phase-c/BENCHMARK_CONTRACT.md
- /home/martin/Dokumente/ED301/ed301/phase-c/GATE_B_APPROVAL.md
