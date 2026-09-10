# Phase E: vollständige Ressourcenbeobachtungen

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

Receipt: `/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_final_02_2026-09-10/ED301-v2_resources_0jsa7m53`.

SHA-256: `2a77f81426daffb68d6aecd5b5264ef56612be5d39b06992302acebeada8d03a`.

| Version | Operation | Nachricht Byte | Context Byte | Stack Median B | Stack SD B | Stack Min B | Stack Max B | RSS Median KiB | RSS SD KiB | RSS Min KiB | RSS Max KiB |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| v1 | empty | 0 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2180.000 | 113.455 | 2016.000 | 2308.000 |
| v2 | empty | 0 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2128.000 | 118.549 | 2000.000 | 2272.000 |
| v1 | seed-expand | 0 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2236.000 | 35.125 | 2164.000 | 2292.000 |
| v2 | seed-expand | 0 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2244.000 | 79.725 | 2048.000 | 2328.000 |
| v1 | cold-sign | 0 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2240.000 | 104.807 | 2024.000 | 2304.000 |
| v2 | cold-sign | 0 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2252.000 | 40.961 | 2184.000 | 2312.000 |
| v1 | prepared-sign | 0 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2244.000 | 98.572 | 1976.000 | 2312.000 |
| v2 | prepared-sign | 0 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2252.000 | 115.990 | 2024.000 | 2344.000 |
| v1 | public-import | 0 | 0 | 57064.000 | 0.000 | 57064.000 | 57064.000 | 2244.000 | 49.951 | 2156.000 | 2336.000 |
| v2 | public-import | 0 | 0 | 47048.000 | 0.000 | 47048.000 | 47048.000 | 2252.000 | 82.680 | 2036.000 | 2344.000 |
| v1 | prepare-verifier | 0 | 0 | 35976.000 | 0.000 | 35976.000 | 35976.000 | 2240.000 | 112.517 | 2000.000 | 2300.000 |
| v2 | prepare-verifier | 0 | 0 | 35976.000 | 0.000 | 35976.000 | 35976.000 | 2252.000 | 96.370 | 2032.000 | 2344.000 |
| v1 | prepared-verify | 0 | 0 | 57448.000 | 0.000 | 57448.000 | 57448.000 | 2244.000 | 63.805 | 2128.000 | 2336.000 |
| v2 | prepared-verify | 0 | 0 | 47432.000 | 0.000 | 47432.000 | 47432.000 | 2248.000 | 89.847 | 2036.000 | 2312.000 |
| v1 | import-verify | 0 | 0 | 57480.000 | 0.000 | 57480.000 | 57480.000 | 2272.000 | 91.981 | 2040.000 | 2336.000 |
| v2 | import-verify | 0 | 0 | 47464.000 | 0.000 | 47464.000 | 47464.000 | 2248.000 | 48.351 | 2164.000 | 2300.000 |
| v1 | empty | 64 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2216.000 | 119.800 | 2004.000 | 2284.000 |
| v2 | empty | 64 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2040.000 | 113.045 | 1988.000 | 2296.000 |
| v1 | seed-expand | 64 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2244.000 | 68.773 | 2104.000 | 2292.000 |
| v2 | seed-expand | 64 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2280.000 | 89.844 | 2028.000 | 2312.000 |
| v1 | cold-sign | 64 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2240.000 | 86.181 | 2028.000 | 2304.000 |
| v2 | cold-sign | 64 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2272.000 | 83.693 | 2036.000 | 2312.000 |
| v1 | prepared-sign | 64 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2208.000 | 79.552 | 2040.000 | 2272.000 |
| v2 | prepared-sign | 64 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2268.000 | 81.807 | 2036.000 | 2280.000 |
| v1 | public-import | 64 | 0 | 57064.000 | 0.000 | 57064.000 | 57064.000 | 2272.000 | 37.041 | 2180.000 | 2304.000 |
| v2 | public-import | 64 | 0 | 47048.000 | 0.000 | 47048.000 | 47048.000 | 2252.000 | 120.067 | 2004.000 | 2324.000 |
| v1 | prepare-verifier | 64 | 0 | 35976.000 | 0.000 | 35976.000 | 35976.000 | 2236.000 | 136.969 | 1964.000 | 2336.000 |
| v2 | prepare-verifier | 64 | 0 | 35976.000 | 0.000 | 35976.000 | 35976.000 | 2244.000 | 32.870 | 2188.000 | 2300.000 |
| v1 | prepared-verify | 64 | 0 | 57448.000 | 0.000 | 57448.000 | 57448.000 | 2272.000 | 32.924 | 2236.000 | 2320.000 |
| v2 | prepared-verify | 64 | 0 | 47432.000 | 0.000 | 47432.000 | 47432.000 | 2256.000 | 15.930 | 2244.000 | 2280.000 |
| v1 | import-verify | 64 | 0 | 57480.000 | 0.000 | 57480.000 | 57480.000 | 2244.000 | 79.039 | 2028.000 | 2304.000 |
| v2 | import-verify | 64 | 0 | 47464.000 | 0.000 | 47464.000 | 47464.000 | 2244.000 | 108.977 | 2012.000 | 2328.000 |
| v1 | empty | 16384 | 255 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2140.000 | 131.833 | 1944.000 | 2308.000 |
| v2 | empty | 16384 | 255 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2252.000 | 140.073 | 1980.000 | 2312.000 |
| v1 | seed-expand | 16384 | 255 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2244.000 | 102.900 | 1976.000 | 2304.000 |
| v2 | seed-expand | 16384 | 255 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2252.000 | 108.000 | 1988.000 | 2344.000 |
| v1 | cold-sign | 16384 | 255 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2272.000 | 116.008 | 2012.000 | 2320.000 |
| v2 | cold-sign | 16384 | 255 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2280.000 | 56.561 | 2152.000 | 2328.000 |
| v1 | prepared-sign | 16384 | 255 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2272.000 | 49.441 | 2176.000 | 2336.000 |
| v2 | prepared-sign | 16384 | 255 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2280.000 | 112.107 | 2032.000 | 2344.000 |
| v1 | public-import | 16384 | 255 | 57064.000 | 0.000 | 57064.000 | 57064.000 | 2244.000 | 68.433 | 2092.000 | 2336.000 |
| v2 | public-import | 16384 | 255 | 47048.000 | 0.000 | 47048.000 | 47048.000 | 2248.000 | 73.352 | 2040.000 | 2280.000 |
| v1 | prepare-verifier | 16384 | 255 | 35976.000 | 0.000 | 35976.000 | 35976.000 | 2168.000 | 122.572 | 2008.000 | 2272.000 |
| v2 | prepare-verifier | 16384 | 255 | 35976.000 | 0.000 | 35976.000 | 35976.000 | 2248.000 | 77.883 | 2016.000 | 2252.000 |
| v1 | prepared-verify | 16384 | 255 | 57448.000 | 0.000 | 57448.000 | 57448.000 | 2244.000 | 103.314 | 2008.000 | 2336.000 |
| v2 | prepared-verify | 16384 | 255 | 47432.000 | 0.000 | 47432.000 | 47432.000 | 2248.000 | 124.608 | 1980.000 | 2344.000 |
| v1 | import-verify | 16384 | 255 | 57480.000 | 0.000 | 57480.000 | 57480.000 | 2244.000 | 105.359 | 1976.000 | 2336.000 |
| v2 | import-verify | 16384 | 255 | 47464.000 | 0.000 | 47464.000 | 47464.000 | 2244.000 | 116.827 | 1960.000 | 2344.000 |
| v1 | stack-control | 64 | 0 | 263128.000 | 0.000 | 263128.000 | 263128.000 | 2296.000 | 128.359 | 2232.000 | 2556.000 |
| v2 | stack-control | 64 | 0 | 263128.000 | 0.000 | 263128.000 | 263128.000 | 2380.000 | 121.589 | 2264.000 | 2552.000 |
| v1 | rss-control | 64 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 10128.000 | 106.184 | 9924.000 | 10216.000 |
| v2 | rss-control | 64 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 10176.000 | 79.115 | 9960.000 | 10204.000 |

Gebundene Positivkontrollen:

```json
[
  {
    "version": "v1",
    "stack_control_delta_B": 255400,
    "rss_control_delta_KiB": 7912,
    "status": "PASS"
  },
  {
    "version": "v2",
    "stack_control_delta_B": 255400,
    "rss_control_delta_KiB": 8136,
    "status": "PASS"
  }
]
```

## x-core-resources

Receipt: `/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_final_02_2026-09-10/x-core-resources`.

SHA-256: `ed84e951a1e6b05362d3fc49f2be765af51a300863d57e16709f81b51015cb42`.

| Version | Operation | Stack Median B | Stack SD B | Stack Min B | Stack Max B | RSS Median KiB | RSS SD KiB | RSS Min KiB | RSS Max KiB |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| v1 | public | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2220.000 | 92.043 | 2008.000 | 2288.000 |
| v2 | public | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2252.000 | 107.897 | 2044.000 | 2300.000 |
| v1 | shared | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2228.000 | 32.049 | 2212.000 | 2288.000 |
| v2 | shared | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2228.000 | 108.519 | 2028.000 | 2300.000 |
| v1 | validate-public | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2220.000 | 80.747 | 2020.000 | 2272.000 |
| v2 | validate-public | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2264.000 | 110.208 | 2036.000 | 2300.000 |
| v1 | canonical-public | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2156.000 | 112.008 | 2008.000 | 2292.000 |
| v2 | canonical-public | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2200.000 | 126.324 | 2024.000 | 2344.000 |
| v2 | import-secret | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2208.000 | 93.754 | 2028.000 | 2272.000 |
| v2 | import-public | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2232.000 | 116.375 | 1992.000 | 2300.000 |
| v2 | prepared-shared | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2256.000 | 76.472 | 2056.000 | 2300.000 |
| v2 | prepared-public | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2268.000 | 112.125 | 2036.000 | 2300.000 |
| control | empty | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2232.000 | 82.389 | 2028.000 | 2300.000 |
| control | stack-control | 263128.000 | 0.000 | 263128.000 | 263128.000 | 2448.000 | 131.262 | 2232.000 | 2560.000 |
| control | rss-control | 7728.000 | 0.000 | 7728.000 | 7728.000 | 10172.000 | 116.790 | 9912.000 | 10344.000 |

Gebundene Positivkontrollen:

```json
{
  "stack_delta_B": 255400,
  "rss_delta_KiB": 7940,
  "status": "PASS"
}
```

## Objektgrößen und Core-Binärgrößen

| Version | Ed301 size_of |
| --- | --- |
| v1 | SIZES SigningKey=38 ExpandedSigningKey=280 VerifyingKey=10280 Signature=76 |
| v2 | SIZES SigningKey=38 ExpandedSigningKey=280 VerifyingKey=10280 Signature=76 |

X301 size_of: SecretKey=76, PublicKey=80, SharedSecret=38 Byte. Objektgrößen sind weder Stackspitzen noch Prozess-RSS.

Frische ELF-Inspektion: `/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_final_02_2026-09-10/core-layout`.

Receipt-SHA-256: `81a091c75ee79a2e1ed52ea0565d023588305bbc469dbeda958b5f124e55e2c9`.

| Messbinary | GNU text inkl. RO Byte | data Byte | bss Byte |
| --- | --- | --- | --- |
| 3.5.8/ed-v1 | 530349 | 13904 | 264 |
| 3.5.8/ed-v2 | 537753 | 13904 | 264 |
| 3.5.8/x-v1 | 492389 | 13896 | 264 |
| 3.5.8/x-v2 | 468325 | 14008 | 264 |
| 4.0.2/ed-v1 | 530349 | 13904 | 264 |
| 4.0.2/ed-v2 | 537753 | 13904 | 264 |
| 4.0.2/x-v1 | 492389 | 13896 | 264 |
| 4.0.2/x-v2 | 468325 | 14008 | 264 |
| core-matrix/ed301-core-matrix-v1 | 536297 | 13960 | 264 |
| core-matrix/ed301-core-matrix-v2 | 543557 | 13960 | 264 |
| core-microbenchmarks/ed301-microbench-v1 | 408741 | 13872 | 264 |
| core-microbenchmarks/ed301-microbench-v2 | 409237 | 13872 | 264 |
| ed-core-resources/v1 | 510402 | 12456 | 264 |
| ed-core-resources/v2 | 517662 | 12456 | 264 |

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
| EVP-signature | Ed25519 | sign | 6592 |
| EVP-signature | Ed448 | sign | 6648 |
| EVP-signature | Ed301-v1 | sign | 7236 |
| EVP-signature | Ed301-v2 | sign | 7244 |
| EVP-XDH | X25519 | derive-steady | 6036 |
| EVP-XDH | X448 | derive-steady | 6128 |
| EVP-XDH | X301-v1 | derive-steady | 6372 |
| EVP-XDH | X301-v2 | derive-steady | 6372 |
| EVP-codec | Ed25519 | decode-private-DER | 7112 |
| EVP-codec | Ed448 | decode-private-DER | 7108 |
| EVP-codec | Ed301-v1 | decode-private-DER | 7456 |
| EVP-codec | Ed301-v2 | decode-private-DER | 7468 |
| EVP-codec | X25519 | decode-private-DER | 6884 |
| EVP-codec | X448 | decode-private-DER | 6636 |
| EVP-codec | X301-v2 | decode-private-DER | 7484 |
| TLS-engine | Ed25519-X25519 | full-handshake-warm-context | 8220 |
| TLS-engine | Ed448-X25519 | full-handshake-warm-context | 8504 |
| TLS-engine | Ed-v1-X25519 | full-handshake-warm-context | 9056 |
| TLS-engine | Ed-v2-X25519 | full-handshake-warm-context | 9136 |
| TLS-engine | Ed-v1-Hybrid-v1 | full-handshake-warm-context | 9584 |
| TLS-engine | Ed-v2-Hybrid-v2 | full-handshake-warm-context | 9612 |
| TLS-engine | Ed-v2-Raw-v2 | full-handshake-warm-context | 9416 |
| TLS-engine | ECDSA-X25519 | full-handshake-warm-context | 8732 |
| TLS-engine | ECDSA-Hybrid-v1 | full-handshake-warm-context | 9124 |
| TLS-engine | ECDSA-Hybrid-v2 | full-handshake-warm-context | 9048 |
| TLS-engine | ECDSA-Raw-v2 | full-handshake-warm-context | 9088 |

DSO-Sektionsgrößen in Byte; keine Addition zu einer isolierten Kryptokern- oder residenten Speichergröße. Vollständige size -A und readelf -SW-Ausgaben bleiben im Receipt.

| Modul | .text | .rodata | .data | .bss |
| --- | --- | --- | --- | --- |
| modules/ed301_eddsa_v2.so | 373666 | 81575 | 2424 | 96 |
| modules/ed301_eddsa_v2_failpoint.so | 376674 | 81927 | 2424 | 96 |
| modules/ed301_eddsa_v2_pki_test.so | 378786 | 82887 | 2424 | 96 |
| modules/ed301_eddsa_v2_tls_collider.so | 382932 | 83687 | 2424 | 96 |
| modules/ed301_eddsa_v2_tls_test.so | 385154 | 84039 | 2424 | 96 |
| modules/x301_v2.so | 304702 | 69435 | 2424 | 96 |
| modules/x301_v2_failpoint.so | 307966 | 69831 | 2424 | 96 |
| modules/x301_v2_pki_test.so | 309670 | 70628 | 2424 | 96 |
| modules/x301_v2_tls_test.so | 321698 | 73382 | 2424 | 96 |
| ed-normal/ed301_eddsa_v1.so | 366498 | 81521 | 2424 | 96 |
| ed-pki/ed301_eddsa_v1_pki_test.so | 371746 | 82865 | 2424 | 96 |
| ed-tls/ed301_eddsa_v1_tls_test.so | 378114 | 83985 | 2424 | 96 |
| x-normal/x301.so | 335018 | 69253 | 2424 | 96 |
| x-tls/x301.so | 343901 | 71315 | 2424 | 96 |

## Provider-/TLS-Ressourcen 4.0.2

Ein einzelner zusätzlicher nativer 100-Operations-Lauf pro Fall, keine neunfache Core-RSS-Statistik.

| Schicht | Verfahren | Operation | Max RSS KiB |
| --- | --- | --- | --- |
| EVP-signature | Ed25519 | sign | 6696 |
| EVP-signature | Ed448 | sign | 6696 |
| EVP-signature | Ed301-v1 | sign | 6992 |
| EVP-signature | Ed301-v2 | sign | 6976 |
| EVP-XDH | X25519 | derive-steady | 6188 |
| EVP-XDH | X448 | derive-steady | 6188 |
| EVP-XDH | X301-v1 | derive-steady | 6492 |
| EVP-XDH | X301-v2 | derive-steady | 6444 |
| EVP-codec | Ed25519 | decode-private-DER | 6948 |
| EVP-codec | Ed448 | decode-private-DER | 6900 |
| EVP-codec | Ed301-v1 | decode-private-DER | 7516 |
| EVP-codec | Ed301-v2 | decode-private-DER | 7504 |
| EVP-codec | X25519 | decode-private-DER | 6904 |
| EVP-codec | X448 | decode-private-DER | 6932 |
| EVP-codec | X301-v2 | decode-private-DER | 7480 |
| TLS-engine | Ed25519-X25519 | full-handshake-warm-context | 8532 |
| TLS-engine | Ed448-X25519 | full-handshake-warm-context | 8508 |
| TLS-engine | Ed-v1-X25519 | full-handshake-warm-context | 9304 |
| TLS-engine | Ed-v2-X25519 | full-handshake-warm-context | 9104 |
| TLS-engine | Ed-v1-Hybrid-v1 | full-handshake-warm-context | 9732 |
| TLS-engine | Ed-v2-Hybrid-v2 | full-handshake-warm-context | 9708 |
| TLS-engine | Ed-v2-Raw-v2 | full-handshake-warm-context | 9604 |
| TLS-engine | ECDSA-X25519 | full-handshake-warm-context | 8512 |
| TLS-engine | ECDSA-Hybrid-v1 | full-handshake-warm-context | 9224 |
| TLS-engine | ECDSA-Hybrid-v2 | full-handshake-warm-context | 9368 |
| TLS-engine | ECDSA-Raw-v2 | full-handshake-warm-context | 9160 |

DSO-Sektionsgrößen in Byte; keine Addition zu einer isolierten Kryptokern- oder residenten Speichergröße. Vollständige size -A und readelf -SW-Ausgaben bleiben im Receipt.

| Modul | .text | .rodata | .data | .bss |
| --- | --- | --- | --- | --- |
| modules/ed301_eddsa_v2.so | 373208 | 81575 | 2424 | 96 |
| modules/ed301_eddsa_v2_failpoint.so | 376216 | 81927 | 2424 | 96 |
| modules/ed301_eddsa_v2_pki_test.so | 378328 | 82887 | 2424 | 96 |
| modules/ed301_eddsa_v2_tls_collider.so | 382472 | 83687 | 2424 | 96 |
| modules/ed301_eddsa_v2_tls_test.so | 384693 | 84071 | 2424 | 96 |
| modules/x301_v2.so | 304702 | 69435 | 2424 | 96 |
| modules/x301_v2_failpoint.so | 307966 | 69831 | 2424 | 96 |
| modules/x301_v2_pki_test.so | 309670 | 70628 | 2424 | 96 |
| modules/x301_v2_tls_test.so | 321698 | 73382 | 2424 | 96 |
| ed-normal/ed301_eddsa_v1.so | 366040 | 81553 | 2424 | 96 |
| ed-pki/ed301_eddsa_v1_pki_test.so | 371288 | 82865 | 2424 | 96 |
| ed-tls/ed301_eddsa_v1_tls_test.so | 377589 | 84017 | 2424 | 96 |
| x-normal/x301.so | 335018 | 69253 | 2424 | 96 |
| x-tls/x301.so | 343901 | 71315 | 2424 | 96 |
