# E8: vollständige Ressourcenbeobachtungen

Die Core-Tabellen zeigen Gesamtprozess-High-Water inklusive Runtime, Harness,
Vorbereitung und Selbsttests: keine isolierte Stackgrenze pro Kryptofunktion,
keine Baseline-Subtraktion, kein Worst-Case-Beweis. Massif: heap=no, stacks=yes,
time-unit=B, peak-inaccuracy=0.0, max-snapshots=1000, drei Prozesse mit je zehn
Operationen. Native RSS: GNU time %M ohne Valgrind, neun Prozesse mit je 100
Operationen. Alle auf CPU 2. Kleine RSS-Differenzen sind kein isolierter Beweis
besserer Speicherökonomie. Die 256-KiB-Stack- und berührten 8-MiB-RSS-Kontrollen
wurden frisch gebaut und gemessen. Die X301-Tabelle verwendet exakt die bereits
gemessenen und klassifizierten primären finalen X301-Binaries des 3.5.8-Laufs.

## ed-core-resources

Receipt: `/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e8_final_01_2026-09-10/ED301-v2_resources_3mbf8yyk`.

SHA-256: `263cdc2da943af269e489c87f84d199c2231111a240c0a4c3f1d1f433b04caec`.

| Version | Operation | Nachricht Byte | Context Byte | Stack Median B | Stack SD B | Stack Min B | Stack Max B | RSS Median KiB | RSS SD KiB | RSS Min KiB | RSS Max KiB |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| v1 | empty | 0 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2236.000 | 138.910 | 1956.000 | 2312.000 |
| v2 | empty | 0 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2160.000 | 109.717 | 1968.000 | 2260.000 |
| v1 | seed-expand | 0 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2252.000 | 93.360 | 2040.000 | 2336.000 |
| v2 | seed-expand | 0 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2232.000 | 93.483 | 2040.000 | 2348.000 |
| v1 | cold-sign | 0 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2264.000 | 124.329 | 1976.000 | 2292.000 |
| v2 | cold-sign | 0 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2192.000 | 120.898 | 2012.000 | 2348.000 |
| v1 | prepared-sign | 0 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2244.000 | 98.281 | 2016.000 | 2292.000 |
| v2 | prepared-sign | 0 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2252.000 | 87.150 | 2040.000 | 2316.000 |
| v1 | public-import | 0 | 0 | 57064.000 | 0.000 | 57064.000 | 57064.000 | 2240.000 | 90.510 | 2020.000 | 2320.000 |
| v2 | public-import | 0 | 0 | 46456.000 | 0.000 | 46456.000 | 46456.000 | 2248.000 | 96.356 | 2052.000 | 2332.000 |
| v1 | prepare-verifier | 0 | 0 | 35976.000 | 0.000 | 35976.000 | 35976.000 | 2244.000 | 67.630 | 2084.000 | 2320.000 |
| v2 | prepare-verifier | 0 | 0 | 46264.000 | 0.000 | 46264.000 | 46264.000 | 2304.000 | 49.880 | 2192.000 | 2332.000 |
| v1 | prepared-verify | 0 | 0 | 57448.000 | 0.000 | 57448.000 | 57448.000 | 2236.000 | 101.399 | 2000.000 | 2272.000 |
| v2 | prepared-verify | 0 | 0 | 46616.000 | 0.000 | 46616.000 | 46616.000 | 2252.000 | 76.196 | 2052.000 | 2304.000 |
| v1 | import-verify | 0 | 0 | 57480.000 | 0.000 | 57480.000 | 57480.000 | 2272.000 | 138.171 | 1964.000 | 2336.000 |
| v2 | import-verify | 0 | 0 | 46872.000 | 0.000 | 46872.000 | 46872.000 | 2192.000 | 94.144 | 2000.000 | 2268.000 |
| v1 | empty | 64 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2024.000 | 120.433 | 1976.000 | 2268.000 |
| v2 | empty | 64 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2160.000 | 118.492 | 1984.000 | 2296.000 |
| v1 | seed-expand | 64 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2248.000 | 125.418 | 2000.000 | 2336.000 |
| v2 | seed-expand | 64 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2252.000 | 93.782 | 2016.000 | 2348.000 |
| v1 | cold-sign | 64 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2244.000 | 130.145 | 2012.000 | 2336.000 |
| v2 | cold-sign | 64 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2204.000 | 104.169 | 2028.000 | 2316.000 |
| v1 | prepared-sign | 64 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2240.000 | 108.673 | 2020.000 | 2272.000 |
| v2 | prepared-sign | 64 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2188.000 | 101.550 | 1968.000 | 2252.000 |
| v1 | public-import | 64 | 0 | 57064.000 | 0.000 | 57064.000 | 57064.000 | 2240.000 | 108.425 | 2000.000 | 2300.000 |
| v2 | public-import | 64 | 0 | 46456.000 | 0.000 | 46456.000 | 46456.000 | 2248.000 | 81.095 | 2096.000 | 2348.000 |
| v1 | prepare-verifier | 64 | 0 | 35976.000 | 0.000 | 35976.000 | 35976.000 | 2228.000 | 81.005 | 2016.000 | 2304.000 |
| v2 | prepare-verifier | 64 | 0 | 46264.000 | 0.000 | 46264.000 | 46264.000 | 2252.000 | 44.532 | 2188.000 | 2348.000 |
| v1 | prepared-verify | 64 | 0 | 57448.000 | 0.000 | 57448.000 | 57448.000 | 2180.000 | 112.832 | 2004.000 | 2336.000 |
| v2 | prepared-verify | 64 | 0 | 46616.000 | 0.000 | 46616.000 | 46616.000 | 2236.000 | 98.285 | 1968.000 | 2316.000 |
| v1 | import-verify | 64 | 0 | 57480.000 | 0.000 | 57480.000 | 57480.000 | 2272.000 | 100.062 | 2028.000 | 2336.000 |
| v2 | import-verify | 64 | 0 | 46872.000 | 0.000 | 46872.000 | 46872.000 | 2256.000 | 34.699 | 2192.000 | 2312.000 |
| v1 | empty | 16384 | 255 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2196.000 | 137.615 | 1976.000 | 2292.000 |
| v2 | empty | 16384 | 255 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2020.000 | 116.735 | 1968.000 | 2288.000 |
| v1 | seed-expand | 16384 | 255 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2272.000 | 57.446 | 2160.000 | 2336.000 |
| v2 | seed-expand | 16384 | 255 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2188.000 | 114.105 | 2000.000 | 2312.000 |
| v1 | cold-sign | 16384 | 255 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2272.000 | 26.541 | 2236.000 | 2316.000 |
| v2 | cold-sign | 16384 | 255 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2252.000 | 105.868 | 1976.000 | 2332.000 |
| v1 | prepared-sign | 16384 | 255 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2272.000 | 140.591 | 1956.000 | 2336.000 |
| v2 | prepared-sign | 16384 | 255 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2256.000 | 40.469 | 2192.000 | 2324.000 |
| v1 | public-import | 16384 | 255 | 57064.000 | 0.000 | 57064.000 | 57064.000 | 2240.000 | 112.204 | 2016.000 | 2336.000 |
| v2 | public-import | 16384 | 255 | 46456.000 | 0.000 | 46456.000 | 46456.000 | 2304.000 | 96.605 | 2040.000 | 2348.000 |
| v1 | prepare-verifier | 16384 | 255 | 35976.000 | 0.000 | 35976.000 | 35976.000 | 2244.000 | 83.229 | 2020.000 | 2320.000 |
| v2 | prepare-verifier | 16384 | 255 | 46264.000 | 0.000 | 46264.000 | 46264.000 | 2192.000 | 96.749 | 2008.000 | 2332.000 |
| v1 | prepared-verify | 16384 | 255 | 57448.000 | 0.000 | 57448.000 | 57448.000 | 2256.000 | 116.827 | 2000.000 | 2328.000 |
| v2 | prepared-verify | 16384 | 255 | 46616.000 | 0.000 | 46616.000 | 46616.000 | 2248.000 | 46.609 | 2188.000 | 2332.000 |
| v1 | import-verify | 16384 | 255 | 57480.000 | 0.000 | 57480.000 | 57480.000 | 2104.000 | 108.292 | 2020.000 | 2320.000 |
| v2 | import-verify | 16384 | 255 | 46872.000 | 0.000 | 46872.000 | 46872.000 | 2192.000 | 108.113 | 2016.000 | 2312.000 |
| v1 | stack-control | 64 | 0 | 263128.000 | 0.000 | 263128.000 | 263128.000 | 2288.000 | 147.356 | 2224.000 | 2564.000 |
| v2 | stack-control | 64 | 0 | 263128.000 | 0.000 | 263128.000 | 263128.000 | 2472.000 | 80.103 | 2276.000 | 2532.000 |
| v1 | rss-control | 64 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 10176.000 | 106.379 | 9924.000 | 10192.000 |
| v2 | rss-control | 64 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 10184.000 | 61.518 | 10044.000 | 10280.000 |

Gebundene Positivkontrollen:

```json
[
  {
    "version": "v1",
    "stack_control_delta_B": 255400,
    "rss_control_delta_KiB": 8152,
    "status": "PASS"
  },
  {
    "version": "v2",
    "stack_control_delta_B": 255400,
    "rss_control_delta_KiB": 8024,
    "status": "PASS"
  }
]
```

## x-core-resources

Receipt: `/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e8_final_01_2026-09-10/x-core-resources`.

SHA-256: `2bcbde62642d449b044d8b2a06c45f5501e572fd9fe9da09418d7deb20a7b77f`.

| Version | Operation | Stack Median B | Stack SD B | Stack Min B | Stack Max B | RSS Median KiB | RSS SD KiB | RSS Min KiB | RSS Max KiB |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| v1 | public | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2088.000 | 120.615 | 2008.000 | 2288.000 |
| v2 | public | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2216.000 | 97.477 | 1984.000 | 2272.000 |
| v1 | shared | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2224.000 | 105.542 | 2016.000 | 2288.000 |
| v2 | shared | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2204.000 | 93.547 | 2024.000 | 2284.000 |
| v1 | validate-public | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2220.000 | 108.058 | 2000.000 | 2284.000 |
| v2 | validate-public | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2208.000 | 63.460 | 2060.000 | 2268.000 |
| v1 | canonical-public | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2276.000 | 132.088 | 2008.000 | 2292.000 |
| v2 | canonical-public | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2256.000 | 107.240 | 2044.000 | 2300.000 |
| v2 | import-secret | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2236.000 | 97.491 | 2024.000 | 2300.000 |
| v2 | import-public | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2224.000 | 86.204 | 2028.000 | 2300.000 |
| v2 | prepared-shared | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2208.000 | 89.899 | 2024.000 | 2272.000 |
| v2 | prepared-public | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2252.000 | 122.580 | 1972.000 | 2300.000 |
| control | empty | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2212.000 | 143.750 | 1952.000 | 2312.000 |
| control | stack-control | 263128.000 | 0.000 | 263128.000 | 263128.000 | 2472.000 | 128.361 | 2224.000 | 2552.000 |
| control | rss-control | 7728.000 | 0.000 | 7728.000 | 7728.000 | 10176.000 | 66.316 | 10056.000 | 10288.000 |

Gebundene Positivkontrollen:

```json
{
  "stack_delta_B": 255400,
  "rss_delta_KiB": 7964,
  "status": "PASS"
}
```

## Objektgrößen und Core-Binärgrößen

| Version | Ed301 size_of |
| --- | --- |
| v1 | SIZES SigningKey=38 ExpandedSigningKey=280 VerifyingKey=10280 Signature=76 |
| v2 | SIZES SigningKey=38 ExpandedSigningKey=280 VerifyingKey=10280 Signature=76 |

X301 size_of: SecretKey=76, PublicKey=80, SharedSecret=38 Byte. Objektgrößen sind weder Stackspitzen noch Prozess-RSS.

Frische ELF-Inspektion: `/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e8_final_01_2026-09-10/core-layout`.

Receipt-SHA-256: `da8ba749034b00df055a76da9c7a31a218c1fb592a5fc8f3757d6e2dbac3c791`.

| Messbinary | GNU text inkl. RO Byte | data Byte | bss Byte |
| --- | --- | --- | --- |
| 3.5.8/ed-v1 | 530349 | 13904 | 264 |
| 3.5.8/ed-v2 | 543225 | 14072 | 264 |
| 3.5.8/x-v1 | 492405 | 13896 | 264 |
| 3.5.8/x-v2 | 467973 | 14008 | 264 |
| 4.0.2/ed-v1 | 530349 | 13904 | 264 |
| 4.0.2/ed-v2 | 543225 | 14072 | 264 |
| 4.0.2/x-v1 | 492405 | 13896 | 264 |
| 4.0.2/x-v2 | 467973 | 14008 | 264 |
| core-matrix/ed301-core-matrix-v1 | 536297 | 13960 | 264 |
| core-matrix/ed301-core-matrix-v2 | 549141 | 14128 | 264 |
| core-microbenchmarks/ed301-microbench-v1 | 408741 | 13872 | 264 |
| core-microbenchmarks/ed301-microbench-v2 | 408533 | 13872 | 264 |
| ed-core-resources/v1 | 510402 | 12456 | 264 |
| ed-core-resources/v2 | 523134 | 12616 | 264 |

Statische Festbasistabellen laut nm -S; bereits in den ELF-Größen enthalten, kein zusätzlicher Laufzeit-Heap. Nur tatsächlich gelinkte benannte Tabellen werden aufgeführt.

| Messbinary | Symbol | Byte |
| --- | --- | --- |
| 3.5.8/ed-v1 | ed301_eddsa::edwards::BASEPOINT_TABLE | 48640 |
| 3.5.8/ed-v1 | ed301_eddsa::edwards::BASEPOINT_ODD_TABLE | 10240 |
| 3.5.8/ed-v2 | ed301_eddsa::edwards::BASEPOINT_TABLE | 48640 |
| 3.5.8/ed-v2 | ed301_eddsa::edwards::BASEPOINT_ODD_TABLE | 10240 |
| 3.5.8/x-v1 | ed301_eddsa::edwards::BASEPOINT_TABLE | 48640 |
| 3.5.8/x-v2 | x301_core::edwards::BASEPOINT_TABLE | 48640 |
| 4.0.2/ed-v1 | ed301_eddsa::edwards::BASEPOINT_TABLE | 48640 |
| 4.0.2/ed-v1 | ed301_eddsa::edwards::BASEPOINT_ODD_TABLE | 10240 |
| 4.0.2/ed-v2 | ed301_eddsa::edwards::BASEPOINT_TABLE | 48640 |
| 4.0.2/ed-v2 | ed301_eddsa::edwards::BASEPOINT_ODD_TABLE | 10240 |
| 4.0.2/x-v1 | ed301_eddsa::edwards::BASEPOINT_TABLE | 48640 |
| 4.0.2/x-v2 | x301_core::edwards::BASEPOINT_TABLE | 48640 |
| core-matrix/ed301-core-matrix-v1 | ed301_eddsa::edwards::BASEPOINT_TABLE | 48640 |
| core-matrix/ed301-core-matrix-v1 | ed301_eddsa::edwards::BASEPOINT_ODD_TABLE | 10240 |
| core-matrix/ed301-core-matrix-v2 | ed301_eddsa::edwards::BASEPOINT_TABLE | 48640 |
| core-matrix/ed301-core-matrix-v2 | ed301_eddsa::edwards::BASEPOINT_ODD_TABLE | 10240 |
| ed-core-resources/v1 | ed301_eddsa::edwards::BASEPOINT_TABLE | 48640 |
| ed-core-resources/v1 | ed301_eddsa::edwards::BASEPOINT_ODD_TABLE | 10240 |
| ed-core-resources/v2 | ed301_eddsa::edwards::BASEPOINT_TABLE | 48640 |
| ed-core-resources/v2 | ed301_eddsa::edwards::BASEPOINT_ODD_TABLE | 10240 |

## Provider-/TLS-Ressourcen 3.5.8

Ein einzelner zusätzlicher nativer 100-Operations-Lauf pro Fall, keine neunfache Core-RSS-Statistik.

| Schicht | Verfahren | Operation | Max RSS KiB |
| --- | --- | --- | --- |
| EVP-signature | Ed25519 | sign | 6600 |
| EVP-signature | Ed448 | sign | 6636 |
| EVP-signature | Ed301-v1 | sign | 7264 |
| EVP-signature | Ed301-v2 | sign | 7176 |
| EVP-XDH | X25519 | derive-steady | 6368 |
| EVP-XDH | X448 | derive-steady | 6116 |
| EVP-XDH | X301-v1 | derive-steady | 6528 |
| EVP-XDH | X301-v2 | derive-steady | 6372 |
| EVP-codec | Ed25519 | decode-private-DER | 7188 |
| EVP-codec | Ed448 | decode-private-DER | 7104 |
| EVP-codec | Ed301-v1 | decode-private-DER | 7456 |
| EVP-codec | Ed301-v2 | decode-private-DER | 7504 |
| EVP-codec | X25519 | decode-private-DER | 6904 |
| EVP-codec | X448 | decode-private-DER | 6644 |
| EVP-codec | X301-v2 | decode-private-DER | 7520 |
| TLS-engine | Ed25519-X25519 | full-handshake-warm-context | 8244 |
| TLS-engine | Ed448-X25519 | full-handshake-warm-context | 8476 |
| TLS-engine | Ed-v1-X25519 | full-handshake-warm-context | 9196 |
| TLS-engine | Ed-v2-X25519 | full-handshake-warm-context | 9168 |
| TLS-engine | Ed-v1-Hybrid-v1 | full-handshake-warm-context | 9640 |
| TLS-engine | Ed-v2-Hybrid-v2 | full-handshake-warm-context | 9764 |
| TLS-engine | Ed-v2-Raw-v2 | full-handshake-warm-context | 9712 |
| TLS-engine | ECDSA-X25519 | full-handshake-warm-context | 8744 |
| TLS-engine | ECDSA-Hybrid-v1 | full-handshake-warm-context | 9220 |
| TLS-engine | ECDSA-Hybrid-v2 | full-handshake-warm-context | 9092 |
| TLS-engine | ECDSA-Raw-v2 | full-handshake-warm-context | 9084 |

DSO-Sektionsgrößen in Byte; keine Addition zu einer isolierten Kryptokern- oder residenten Speichergröße. Vollständige size -A und readelf -SW-Ausgaben bleiben im Receipt.

| Modul | .text | .rodata | .data | .bss |
| --- | --- | --- | --- | --- |
| modules/ed301_eddsa_v2.so | 378530 | 82183 | 2424 | 96 |
| modules/ed301_eddsa_v2_failpoint.so | 381410 | 82535 | 2424 | 96 |
| modules/ed301_eddsa_v2_pki_test.so | 383650 | 83463 | 2424 | 96 |
| modules/ed301_eddsa_v2_tls_collider.so | 387796 | 84263 | 2424 | 96 |
| modules/ed301_eddsa_v2_tls_test.so | 389954 | 84647 | 2424 | 96 |
| modules/x301_v2.so | 304638 | 69515 | 2424 | 96 |
| modules/x301_v2_failpoint.so | 307902 | 69895 | 2424 | 96 |
| modules/x301_v2_pki_test.so | 309542 | 70692 | 2424 | 96 |
| modules/x301_v2_tls_test.so | 321522 | 73478 | 2424 | 96 |
| ed-normal/ed301_eddsa_v1.so | 366498 | 81521 | 2424 | 96 |
| ed-pki/ed301_eddsa_v1_pki_test.so | 371746 | 82865 | 2424 | 96 |
| ed-tls/ed301_eddsa_v1_tls_test.so | 378050 | 83985 | 2424 | 96 |
| x-normal/x301.so | 335018 | 69269 | 2424 | 96 |
| x-tls/x301.so | 343901 | 71347 | 2424 | 96 |

## Provider-/TLS-Ressourcen 4.0.2

Ein einzelner zusätzlicher nativer 100-Operations-Lauf pro Fall, keine neunfache Core-RSS-Statistik.

| Schicht | Verfahren | Operation | Max RSS KiB |
| --- | --- | --- | --- |
| EVP-signature | Ed25519 | sign | 6656 |
| EVP-signature | Ed448 | sign | 6644 |
| EVP-signature | Ed301-v1 | sign | 7020 |
| EVP-signature | Ed301-v2 | sign | 7036 |
| EVP-XDH | X25519 | derive-steady | 6156 |
| EVP-XDH | X448 | derive-steady | 6188 |
| EVP-XDH | X301-v1 | derive-steady | 6548 |
| EVP-XDH | X301-v2 | derive-steady | 6420 |
| EVP-codec | Ed25519 | decode-private-DER | 7148 |
| EVP-codec | Ed448 | decode-private-DER | 6940 |
| EVP-codec | Ed301-v1 | decode-private-DER | 7284 |
| EVP-codec | Ed301-v2 | decode-private-DER | 7496 |
| EVP-codec | X25519 | decode-private-DER | 6952 |
| EVP-codec | X448 | decode-private-DER | 6936 |
| EVP-codec | X301-v2 | decode-private-DER | 7460 |
| TLS-engine | Ed25519-X25519 | full-handshake-warm-context | 8528 |
| TLS-engine | Ed448-X25519 | full-handshake-warm-context | 8556 |
| TLS-engine | Ed-v1-X25519 | full-handshake-warm-context | 9096 |
| TLS-engine | Ed-v2-X25519 | full-handshake-warm-context | 9188 |
| TLS-engine | Ed-v1-Hybrid-v1 | full-handshake-warm-context | 9944 |
| TLS-engine | Ed-v2-Hybrid-v2 | full-handshake-warm-context | 9876 |
| TLS-engine | Ed-v2-Raw-v2 | full-handshake-warm-context | 9716 |
| TLS-engine | ECDSA-X25519 | full-handshake-warm-context | 8540 |
| TLS-engine | ECDSA-Hybrid-v1 | full-handshake-warm-context | 9152 |
| TLS-engine | ECDSA-Hybrid-v2 | full-handshake-warm-context | 9348 |
| TLS-engine | ECDSA-Raw-v2 | full-handshake-warm-context | 9176 |

DSO-Sektionsgrößen in Byte; keine Addition zu einer isolierten Kryptokern- oder residenten Speichergröße. Vollständige size -A und readelf -SW-Ausgaben bleiben im Receipt.

| Modul | .text | .rodata | .data | .bss |
| --- | --- | --- | --- | --- |
| modules/ed301_eddsa_v2.so | 378648 | 82183 | 2424 | 96 |
| modules/ed301_eddsa_v2_failpoint.so | 381528 | 82535 | 2424 | 96 |
| modules/ed301_eddsa_v2_pki_test.so | 383768 | 83463 | 2424 | 96 |
| modules/ed301_eddsa_v2_tls_collider.so | 387912 | 84263 | 2424 | 96 |
| modules/ed301_eddsa_v2_tls_test.so | 390069 | 84647 | 2424 | 96 |
| modules/x301_v2.so | 304638 | 69515 | 2424 | 96 |
| modules/x301_v2_failpoint.so | 307902 | 69895 | 2424 | 96 |
| modules/x301_v2_pki_test.so | 309542 | 70692 | 2424 | 96 |
| modules/x301_v2_tls_test.so | 321522 | 73478 | 2424 | 96 |
| ed-normal/ed301_eddsa_v1.so | 366040 | 81553 | 2424 | 96 |
| ed-pki/ed301_eddsa_v1_pki_test.so | 371288 | 82865 | 2424 | 96 |
| ed-tls/ed301_eddsa_v1_tls_test.so | 377589 | 84017 | 2424 | 96 |
| x-normal/x301.so | 335018 | 69269 | 2424 | 96 |
| x-tls/x301.so | 343901 | 71347 | 2424 | 96 |
