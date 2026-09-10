# E7: vollständige Ressourcenbeobachtungen

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

Receipt: `/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e7_final_02_2026-09-10/ED301-v2_resources_7_6t8hc0`.

SHA-256: `19d392478cdf2714227ec4e3272af35aab247e4ed311c208f17aff46570746dc`.

| Version | Operation | Nachricht Byte | Context Byte | Stack Median B | Stack SD B | Stack Min B | Stack Max B | RSS Median KiB | RSS SD KiB | RSS Min KiB | RSS Max KiB |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| v1 | empty | 0 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2216.000 | 121.201 | 1976.000 | 2296.000 |
| v2 | empty | 0 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2036.000 | 131.409 | 1968.000 | 2300.000 |
| v1 | seed-expand | 0 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2244.000 | 33.045 | 2160.000 | 2272.000 |
| v2 | seed-expand | 0 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2248.000 | 34.667 | 2184.000 | 2304.000 |
| v1 | cold-sign | 0 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2244.000 | 120.063 | 1964.000 | 2292.000 |
| v2 | cold-sign | 0 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2276.000 | 85.370 | 2040.000 | 2340.000 |
| v1 | prepared-sign | 0 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2244.000 | 109.818 | 2008.000 | 2336.000 |
| v2 | prepared-sign | 0 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2276.000 | 64.087 | 2120.000 | 2340.000 |
| v1 | public-import | 0 | 0 | 57064.000 | 0.000 | 57064.000 | 57064.000 | 2244.000 | 123.819 | 2008.000 | 2304.000 |
| v2 | public-import | 0 | 0 | 47032.000 | 0.000 | 47032.000 | 47032.000 | 2232.000 | 107.526 | 2012.000 | 2308.000 |
| v1 | prepare-verifier | 0 | 0 | 35976.000 | 0.000 | 35976.000 | 35976.000 | 2272.000 | 95.863 | 2012.000 | 2336.000 |
| v2 | prepare-verifier | 0 | 0 | 35976.000 | 0.000 | 35976.000 | 35976.000 | 2176.000 | 117.830 | 2016.000 | 2340.000 |
| v1 | prepared-verify | 0 | 0 | 57448.000 | 0.000 | 57448.000 | 57448.000 | 2168.000 | 106.241 | 2004.000 | 2256.000 |
| v2 | prepared-verify | 0 | 0 | 47416.000 | 0.000 | 47416.000 | 47416.000 | 2232.000 | 88.584 | 2016.000 | 2276.000 |
| v1 | import-verify | 0 | 0 | 57480.000 | 0.000 | 57480.000 | 57480.000 | 2180.000 | 127.071 | 1988.000 | 2292.000 |
| v2 | import-verify | 0 | 0 | 47448.000 | 0.000 | 47448.000 | 47448.000 | 2248.000 | 19.333 | 2228.000 | 2276.000 |
| v1 | empty | 64 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2156.000 | 98.403 | 1988.000 | 2252.000 |
| v2 | empty | 64 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2192.000 | 125.610 | 2008.000 | 2300.000 |
| v1 | seed-expand | 64 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2244.000 | 36.986 | 2240.000 | 2336.000 |
| v2 | seed-expand | 64 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2276.000 | 52.183 | 2172.000 | 2340.000 |
| v1 | cold-sign | 64 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2272.000 | 114.282 | 2016.000 | 2336.000 |
| v2 | cold-sign | 64 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2268.000 | 120.516 | 1960.000 | 2340.000 |
| v1 | prepared-sign | 64 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2240.000 | 85.824 | 2012.000 | 2304.000 |
| v2 | prepared-sign | 64 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2244.000 | 59.867 | 2120.000 | 2340.000 |
| v1 | public-import | 64 | 0 | 57064.000 | 0.000 | 57064.000 | 57064.000 | 2244.000 | 104.995 | 2012.000 | 2300.000 |
| v2 | public-import | 64 | 0 | 47032.000 | 0.000 | 47032.000 | 47032.000 | 2276.000 | 103.127 | 2000.000 | 2340.000 |
| v1 | prepare-verifier | 64 | 0 | 35976.000 | 0.000 | 35976.000 | 35976.000 | 2244.000 | 83.971 | 2040.000 | 2304.000 |
| v2 | prepare-verifier | 64 | 0 | 35976.000 | 0.000 | 35976.000 | 35976.000 | 2244.000 | 119.618 | 2008.000 | 2308.000 |
| v1 | prepared-verify | 64 | 0 | 57448.000 | 0.000 | 57448.000 | 57448.000 | 2240.000 | 138.508 | 1976.000 | 2336.000 |
| v2 | prepared-verify | 64 | 0 | 47416.000 | 0.000 | 47416.000 | 47416.000 | 2276.000 | 78.404 | 2084.000 | 2340.000 |
| v1 | import-verify | 64 | 0 | 57480.000 | 0.000 | 57480.000 | 57480.000 | 2240.000 | 121.091 | 2012.000 | 2336.000 |
| v2 | import-verify | 64 | 0 | 47448.000 | 0.000 | 47448.000 | 47448.000 | 2248.000 | 40.105 | 2180.000 | 2304.000 |
| v1 | empty | 16384 | 255 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2092.000 | 121.951 | 1964.000 | 2268.000 |
| v2 | empty | 16384 | 255 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2252.000 | 97.743 | 2028.000 | 2288.000 |
| v1 | seed-expand | 16384 | 255 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2220.000 | 82.932 | 2024.000 | 2304.000 |
| v2 | seed-expand | 16384 | 255 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2232.000 | 89.331 | 2016.000 | 2340.000 |
| v1 | cold-sign | 16384 | 255 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2256.000 | 82.656 | 2040.000 | 2336.000 |
| v2 | cold-sign | 16384 | 255 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2276.000 | 87.104 | 2044.000 | 2340.000 |
| v1 | prepared-sign | 16384 | 255 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2232.000 | 108.415 | 2016.000 | 2304.000 |
| v2 | prepared-sign | 16384 | 255 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2276.000 | 96.708 | 2028.000 | 2340.000 |
| v1 | public-import | 16384 | 255 | 57064.000 | 0.000 | 57064.000 | 57064.000 | 2272.000 | 91.126 | 2040.000 | 2336.000 |
| v2 | public-import | 16384 | 255 | 47032.000 | 0.000 | 47032.000 | 47032.000 | 2276.000 | 17.601 | 2244.000 | 2304.000 |
| v1 | prepare-verifier | 16384 | 255 | 35976.000 | 0.000 | 35976.000 | 35976.000 | 2264.000 | 89.376 | 2036.000 | 2336.000 |
| v2 | prepare-verifier | 16384 | 255 | 35976.000 | 0.000 | 35976.000 | 35976.000 | 2260.000 | 125.190 | 2004.000 | 2340.000 |
| v1 | prepared-verify | 16384 | 255 | 57448.000 | 0.000 | 57448.000 | 57448.000 | 2248.000 | 37.351 | 2228.000 | 2336.000 |
| v2 | prepared-verify | 16384 | 255 | 47416.000 | 0.000 | 47416.000 | 47416.000 | 2248.000 | 143.122 | 1972.000 | 2340.000 |
| v1 | import-verify | 16384 | 255 | 57480.000 | 0.000 | 57480.000 | 57480.000 | 2236.000 | 75.419 | 2092.000 | 2304.000 |
| v2 | import-verify | 16384 | 255 | 47448.000 | 0.000 | 47448.000 | 47448.000 | 2084.000 | 130.140 | 2000.000 | 2308.000 |
| v1 | stack-control | 64 | 0 | 263128.000 | 0.000 | 263128.000 | 263128.000 | 2468.000 | 116.707 | 2256.000 | 2560.000 |
| v2 | stack-control | 64 | 0 | 263128.000 | 0.000 | 263128.000 | 263128.000 | 2304.000 | 121.964 | 2216.000 | 2528.000 |
| v1 | rss-control | 64 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 10168.000 | 93.212 | 9924.000 | 10208.000 |
| v2 | rss-control | 64 | 0 | 7728.000 | 0.000 | 7728.000 | 7728.000 | 10160.000 | 99.889 | 9952.000 | 10340.000 |

Gebundene Positivkontrollen:

```json
[
  {
    "version": "v1",
    "stack_control_delta_B": 255400,
    "rss_control_delta_KiB": 8012,
    "status": "PASS"
  },
  {
    "version": "v2",
    "stack_control_delta_B": 255400,
    "rss_control_delta_KiB": 7968,
    "status": "PASS"
  }
]
```

## x-core-resources

Receipt: `/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e7_final_02_2026-09-10/x-core-resources`.

SHA-256: `b7d49514a73f8c3f57f1f23d7861cb479859772acc8d982f624d5e46c9b5f08b`.

| Version | Operation | Stack Median B | Stack SD B | Stack Min B | Stack Max B | RSS Median KiB | RSS SD KiB | RSS Min KiB | RSS Max KiB |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| v1 | public | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2224.000 | 63.816 | 2096.000 | 2284.000 |
| v2 | public | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2180.000 | 114.037 | 2020.000 | 2292.000 |
| v1 | shared | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2224.000 | 94.208 | 2020.000 | 2368.000 |
| v2 | shared | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2268.000 | 30.383 | 2208.000 | 2292.000 |
| v1 | validate-public | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2092.000 | 121.058 | 2008.000 | 2288.000 |
| v2 | validate-public | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2252.000 | 78.613 | 2048.000 | 2272.000 |
| v1 | canonical-public | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2220.000 | 123.968 | 1988.000 | 2292.000 |
| v2 | canonical-public | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2264.000 | 89.906 | 2064.000 | 2300.000 |
| v2 | import-secret | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2208.000 | 109.126 | 1968.000 | 2272.000 |
| v2 | import-public | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2256.000 | 106.410 | 2024.000 | 2300.000 |
| v2 | prepared-shared | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2256.000 | 84.675 | 2008.000 | 2268.000 |
| v2 | prepared-public | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2264.000 | 74.075 | 2048.000 | 2292.000 |
| control | empty | 7728.000 | 0.000 | 7728.000 | 7728.000 | 2128.000 | 129.277 | 1964.000 | 2296.000 |
| control | stack-control | 263128.000 | 0.000 | 263128.000 | 263128.000 | 2280.000 | 108.820 | 2240.000 | 2532.000 |
| control | rss-control | 7728.000 | 0.000 | 7728.000 | 7728.000 | 10192.000 | 82.254 | 9952.000 | 10212.000 |

Gebundene Positivkontrollen:

```json
{
  "stack_delta_B": 255400,
  "rss_delta_KiB": 8064,
  "status": "PASS"
}
```

## Objektgrößen und Core-Binärgrößen

| Version | Ed301 size_of |
| --- | --- |
| v1 | SIZES SigningKey=38 ExpandedSigningKey=280 VerifyingKey=10280 Signature=76 |
| v2 | SIZES SigningKey=38 ExpandedSigningKey=280 VerifyingKey=10280 Signature=76 |

X301 size_of: SecretKey=76, PublicKey=80, SharedSecret=38 Byte. Objektgrößen sind weder Stackspitzen noch Prozess-RSS.

Frische ELF-Inspektion: `/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e7_final_02_2026-09-10/core-layout`.

Receipt-SHA-256: `ea5663e17088af55d8ebd430e99cd9b97fc73b22e0cb13df9dbba3ecb2214f2c`.

| Messbinary | GNU text inkl. RO Byte | data Byte | bss Byte |
| --- | --- | --- | --- |
| 3.5.8/ed-v1 | 530349 | 13904 | 264 |
| 3.5.8/ed-v2 | 536953 | 13904 | 264 |
| 3.5.8/x-v1 | 492405 | 13896 | 264 |
| 3.5.8/x-v2 | 467509 | 14008 | 264 |
| 4.0.2/ed-v1 | 530349 | 13904 | 264 |
| 4.0.2/ed-v2 | 536953 | 13904 | 264 |
| 4.0.2/x-v1 | 492405 | 13896 | 264 |
| 4.0.2/x-v2 | 467509 | 14008 | 264 |
| core-matrix/ed301-core-matrix-v1 | 536297 | 13960 | 264 |
| core-matrix/ed301-core-matrix-v2 | 542773 | 13960 | 264 |
| core-microbenchmarks/ed301-microbench-v1 | 408741 | 13872 | 264 |
| core-microbenchmarks/ed301-microbench-v2 | 408533 | 13872 | 264 |
| ed-core-resources/v1 | 510402 | 12456 | 264 |
| ed-core-resources/v2 | 516878 | 12456 | 264 |

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
| EVP-signature | Ed25519 | sign | 6772 |
| EVP-signature | Ed448 | sign | 6772 |
| EVP-signature | Ed301-v1 | sign | 7372 |
| EVP-signature | Ed301-v2 | sign | 7404 |
| EVP-XDH | X25519 | derive-steady | 6308 |
| EVP-XDH | X448 | derive-steady | 6268 |
| EVP-XDH | X301-v1 | derive-steady | 6656 |
| EVP-XDH | X301-v2 | derive-steady | 6564 |
| EVP-codec | Ed25519 | decode-private-DER | 7288 |
| EVP-codec | Ed448 | decode-private-DER | 7064 |
| EVP-codec | Ed301-v1 | decode-private-DER | 7776 |
| EVP-codec | Ed301-v2 | decode-private-DER | 7792 |
| EVP-codec | X25519 | decode-private-DER | 7020 |
| EVP-codec | X448 | decode-private-DER | 6776 |
| EVP-codec | X301-v2 | decode-private-DER | 7560 |
| TLS-engine | Ed25519-X25519 | full-handshake-warm-context | 8420 |
| TLS-engine | Ed448-X25519 | full-handshake-warm-context | 8376 |
| TLS-engine | Ed-v1-X25519 | full-handshake-warm-context | 9048 |
| TLS-engine | Ed-v2-X25519 | full-handshake-warm-context | 9024 |
| TLS-engine | Ed-v1-Hybrid-v1 | full-handshake-warm-context | 9512 |
| TLS-engine | Ed-v2-Hybrid-v2 | full-handshake-warm-context | 9536 |
| TLS-engine | Ed-v2-Raw-v2 | full-handshake-warm-context | 9596 |
| TLS-engine | ECDSA-X25519 | full-handshake-warm-context | 8628 |
| TLS-engine | ECDSA-Hybrid-v1 | full-handshake-warm-context | 8996 |
| TLS-engine | ECDSA-Hybrid-v2 | full-handshake-warm-context | 9164 |
| TLS-engine | ECDSA-Raw-v2 | full-handshake-warm-context | 9276 |

DSO-Sektionsgrößen in Byte; keine Addition zu einer isolierten Kryptokern- oder residenten Speichergröße. Vollständige size -A und readelf -SW-Ausgaben bleiben im Receipt.

| Modul | .text | .rodata | .data | .bss |
| --- | --- | --- | --- | --- |
| modules/ed301_eddsa_v2.so | 372898 | 81575 | 2424 | 96 |
| modules/ed301_eddsa_v2_failpoint.so | 375906 | 81927 | 2424 | 96 |
| modules/ed301_eddsa_v2_pki_test.so | 378018 | 82887 | 2424 | 96 |
| modules/ed301_eddsa_v2_tls_collider.so | 382164 | 83687 | 2424 | 96 |
| modules/ed301_eddsa_v2_tls_test.so | 384386 | 84039 | 2424 | 96 |
| modules/x301_v2.so | 303870 | 69435 | 2424 | 96 |
| modules/x301_v2_failpoint.so | 307134 | 69831 | 2424 | 96 |
| modules/x301_v2_pki_test.so | 308838 | 70628 | 2424 | 96 |
| modules/x301_v2_tls_test.so | 320866 | 73382 | 2424 | 96 |
| ed-normal/ed301_eddsa_v1.so | 366498 | 81521 | 2424 | 96 |
| ed-pki/ed301_eddsa_v1_pki_test.so | 371746 | 82865 | 2424 | 96 |
| ed-tls/ed301_eddsa_v1_tls_test.so | 378050 | 83985 | 2424 | 96 |
| x-normal/x301.so | 335018 | 69269 | 2424 | 96 |
| x-tls/x301.so | 343901 | 71347 | 2424 | 96 |

## Provider-/TLS-Ressourcen 4.0.2

Ein einzelner zusätzlicher nativer 100-Operations-Lauf pro Fall, keine neunfache Core-RSS-Statistik.

| Schicht | Verfahren | Operation | Max RSS KiB |
| --- | --- | --- | --- |
| EVP-signature | Ed25519 | sign | 6684 |
| EVP-signature | Ed448 | sign | 6656 |
| EVP-signature | Ed301-v1 | sign | 7192 |
| EVP-signature | Ed301-v2 | sign | 6928 |
| EVP-XDH | X25519 | derive-steady | 6132 |
| EVP-XDH | X448 | derive-steady | 6136 |
| EVP-XDH | X301-v1 | derive-steady | 6492 |
| EVP-XDH | X301-v2 | derive-steady | 6508 |
| EVP-codec | Ed25519 | decode-private-DER | 6936 |
| EVP-codec | Ed448 | decode-private-DER | 6912 |
| EVP-codec | Ed301-v1 | decode-private-DER | 7548 |
| EVP-codec | Ed301-v2 | decode-private-DER | 7536 |
| EVP-codec | X25519 | decode-private-DER | 7140 |
| EVP-codec | X448 | decode-private-DER | 6948 |
| EVP-codec | X301-v2 | decode-private-DER | 7268 |
| TLS-engine | Ed25519-X25519 | full-handshake-warm-context | 8548 |
| TLS-engine | Ed448-X25519 | full-handshake-warm-context | 8556 |
| TLS-engine | Ed-v1-X25519 | full-handshake-warm-context | 9304 |
| TLS-engine | Ed-v2-X25519 | full-handshake-warm-context | 9128 |
| TLS-engine | Ed-v1-Hybrid-v1 | full-handshake-warm-context | 9836 |
| TLS-engine | Ed-v2-Hybrid-v2 | full-handshake-warm-context | 9928 |
| TLS-engine | Ed-v2-Raw-v2 | full-handshake-warm-context | 9684 |
| TLS-engine | ECDSA-X25519 | full-handshake-warm-context | 8516 |
| TLS-engine | ECDSA-Hybrid-v1 | full-handshake-warm-context | 9160 |
| TLS-engine | ECDSA-Hybrid-v2 | full-handshake-warm-context | 9348 |
| TLS-engine | ECDSA-Raw-v2 | full-handshake-warm-context | 9112 |

DSO-Sektionsgrößen in Byte; keine Addition zu einer isolierten Kryptokern- oder residenten Speichergröße. Vollständige size -A und readelf -SW-Ausgaben bleiben im Receipt.

| Modul | .text | .rodata | .data | .bss |
| --- | --- | --- | --- | --- |
| modules/ed301_eddsa_v2.so | 372440 | 81575 | 2424 | 96 |
| modules/ed301_eddsa_v2_failpoint.so | 375448 | 81927 | 2424 | 96 |
| modules/ed301_eddsa_v2_pki_test.so | 377560 | 82887 | 2424 | 96 |
| modules/ed301_eddsa_v2_tls_collider.so | 381704 | 83687 | 2424 | 96 |
| modules/ed301_eddsa_v2_tls_test.so | 383925 | 84071 | 2424 | 96 |
| modules/x301_v2.so | 303870 | 69435 | 2424 | 96 |
| modules/x301_v2_failpoint.so | 307134 | 69831 | 2424 | 96 |
| modules/x301_v2_pki_test.so | 308838 | 70628 | 2424 | 96 |
| modules/x301_v2_tls_test.so | 320866 | 73382 | 2424 | 96 |
| ed-normal/ed301_eddsa_v1.so | 366040 | 81553 | 2424 | 96 |
| ed-pki/ed301_eddsa_v1_pki_test.so | 371288 | 82865 | 2424 | 96 |
| ed-tls/ed301_eddsa_v1_tls_test.so | 377589 | 84017 | 2424 | 96 |
| x-normal/x301.so | 335018 | 69269 | 2424 | 96 |
| x-tls/x301.so | 343901 | 71347 | 2424 | 96 |
