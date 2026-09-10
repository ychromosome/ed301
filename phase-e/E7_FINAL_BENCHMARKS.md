# E7: vollständige abschließende Benchmarktabellen

Alle Werte sind frisch auf AMD Ryzen 9 5950X, x86-64, CPU 2 erhoben.
Rust 1.98.0 / LLVM 21.1.8, O3, ThinLTO, CGU1, panic=unwind; v2 durchgehend mit
Overflow-Checks. Der historische X301-v1-Vergleich behält seine ausgewiesene
crypto-bigint-Ausnahme und sein originales C-O0-Profil. Keine Assembler-/SIMD-
Erweiterung; Governor/Boost unverändert. Andere Hostlast ist nicht ausgeschlossen.
Messjobs wurden untereinander seriell ausgeführt.

Median, Stichproben-SD und Min/Max beziehen sich auf neun Laufmittel, nicht auf
Einzelaufruf-Perzentile oder Konfidenzintervalle. Der 128-Fälle-Runner verwendet
100 Aufwärmoperationen, 200-ms-Kalibrierziel und rotierende/wechselnde Reihenfolge.
Die zusätzliche Matrix und die Mikrobenchmarks verwenden unverändert die
100-ms-Methodik von Gate C. Jede Vergleichszeile hat ihren eigenen frisch
gemessenen v1-Bezugswert; ABI-Läufe werden nicht zusammengelegt.

EVP ist die API-Schicht, nicht die Rechenimplementierung. TLS-engine misst
echte TLS-1.3-Zustandsmaschinen über Memory-BIO, vorbereitete SSL_CTX, aber
einschließlich SSL-/BIO-Allokation und Freigabe, ohne Resumption. Das ist keine
TCP-Latenzmessung. Codec-Fälle schließen Context-Konstruktion und Abbau ein;
Objekte sind gültig und neu generiert. X301-v1 hat keine vergleichbaren
persistent-codec- oder Raw-TLS-Lanes; fehlende Verfahren werden nicht erfunden.

Die Tabellen enthalten sämtliche 392 endgültigen Geschwindigkeitsfälle.
Der neue gepaarte 32-Fälle-E7-Vergleich bleibt zusätzlich vollständig im Paket.

## Vollständiger ABI-Lauf 3.5.8

Receipt: `/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e7_final_02_2026-09-10/benchmarks-3.5.8`.

SHA-256 des Receipt-Manifests: `98b20d2f955f848da02a3fe03cf579bcc56266ff4f6701de6052d0f075fd090e`.

| Schicht | Verfahren | Operation | Median µs | SD µs | Min µs | Max µs |
| --- | --- | --- | --- | --- | --- | --- |
| Rust-Ed | Ed301-v1 | expand | 28.268333 | 3.134074 | 27.571734 | 35.441397 |
| Rust-Ed | Ed301-v2 | expand | 28.285747 | 2.390438 | 27.572777 | 35.099753 |
| Rust-Ed | Ed301-v1 | sign | 29.132135 | 0.579462 | 28.770637 | 30.604565 |
| Rust-Ed | Ed301-v2 | sign | 29.697896 | 0.593754 | 28.638088 | 30.223222 |
| Rust-Ed | Ed301-v1 | verify | 87.375733 | 3.198480 | 85.942175 | 95.449139 |
| Rust-Ed | Ed301-v2 | verify | 83.506851 | 4.681280 | 81.640640 | 94.365318 |
| Rust-Ed | Ed301-v1 | import | 98.739871 | 9.481946 | 96.451657 | 126.482762 |
| Rust-Ed | Ed301-v2 | import | 63.081360 | 1.440451 | 61.380453 | 66.141513 |
| Rust-X | X301-v1 | public | 28.100456 | 0.384079 | 27.448145 | 28.635035 |
| Rust-X | X301-v2 | public | 27.587280 | 2.877817 | 27.119899 | 35.651683 |
| Rust-X | X301-v1 | shared | 57.866651 | 0.927871 | 56.482188 | 59.625901 |
| Rust-X | X301-v2 | shared | 59.700955 | 3.776184 | 59.350295 | 70.971014 |
| Rust-X | X301-v1 | validate-public | 0.004512 | 0.000680 | 0.004119 | 0.006458 |
| Rust-X | X301-v2 | validate-public | 0.001439 | 0.000083 | 0.001320 | 0.001598 |
| Rust-X | X301-v1 | canonical-public | 0.008557 | 0.000972 | 0.008180 | 0.010364 |
| Rust-X | X301-v2 | canonical-public | 0.003328 | 0.000958 | 0.002821 | 0.005986 |
| Rust-X | X301-v2 | import-secret | 0.032560 | 0.000634 | 0.031530 | 0.033312 |
| Rust-X | X301-v2 | import-public | 0.005798 | 0.001131 | 0.004795 | 0.008061 |
| Rust-X | X301-v2 | prepared-public | 28.309041 | 2.122012 | 26.976938 | 33.905601 |
| Rust-X | X301-v2 | prepared-shared | 59.213586 | 0.595421 | 58.686210 | 60.268097 |
| EVP-signature | Ed25519 | keygen | 24.739700 | 0.427778 | 24.278500 | 25.692900 |
| EVP-signature | Ed448 | keygen | 148.181600 | 2.869644 | 145.264300 | 154.424500 |
| EVP-signature | Ed301-v1 | keygen | 57.052200 | 0.710340 | 55.937600 | 58.012100 |
| EVP-signature | Ed301-v2 | keygen | 56.928600 | 1.971488 | 56.191900 | 62.211400 |
| EVP-signature | Ed25519 | sign | 24.060300 | 0.233599 | 23.742200 | 24.473500 |
| EVP-signature | Ed448 | sign | 147.857400 | 1.521946 | 145.614300 | 150.934300 |
| EVP-signature | Ed301-v1 | sign | 29.862600 | 0.931398 | 29.284100 | 32.189100 |
| EVP-signature | Ed301-v2 | sign | 29.926100 | 0.849036 | 29.393300 | 32.217300 |
| EVP-signature | Ed25519 | verify | 80.221700 | 1.603853 | 78.502900 | 83.784700 |
| EVP-signature | Ed448 | verify | 157.989600 | 6.197788 | 153.599700 | 174.791400 |
| EVP-signature | Ed301-v1 | verify | 87.409400 | 3.205903 | 84.883500 | 95.358500 |
| EVP-signature | Ed301-v2 | verify | 84.835500 | 1.516032 | 82.083400 | 86.493200 |
| EVP-XDH | X25519 | keygen | 24.013200 | 0.364485 | 23.526900 | 24.735700 |
| EVP-XDH | X448 | keygen | 146.138000 | 2.241685 | 143.604700 | 150.434400 |
| EVP-XDH | X301-v1 | keygen | 29.299400 | 0.416632 | 29.028400 | 30.232900 |
| EVP-XDH | X301-v2 | keygen | 29.610100 | 0.436045 | 28.888100 | 30.089600 |
| EVP-XDH | X25519 | derive-setup | 1.258000 | 0.031102 | 1.234600 | 1.336600 |
| EVP-XDH | X448 | derive-setup | 1.243300 | 0.011419 | 1.219700 | 1.249700 |
| EVP-XDH | X301-v1 | derive-setup | 1.740200 | 0.018348 | 1.712600 | 1.781100 |
| EVP-XDH | X301-v2 | derive-setup | 1.820700 | 0.029576 | 1.798800 | 1.900200 |
| EVP-XDH | X25519 | derive-first | 23.966200 | 0.784311 | 23.709500 | 26.241800 |
| EVP-XDH | X448 | derive-first | 121.414200 | 1.902740 | 120.400200 | 125.993700 |
| EVP-XDH | X301-v1 | derive-first | 57.853900 | 0.927999 | 57.047900 | 59.649500 |
| EVP-XDH | X301-v2 | derive-first | 59.404000 | 1.050389 | 58.219200 | 61.708100 |
| EVP-XDH | X25519 | derive-second | 23.823600 | 0.208188 | 23.432000 | 24.055900 |
| EVP-XDH | X448 | derive-second | 120.258600 | 1.140341 | 118.564400 | 122.531600 |
| EVP-XDH | X301-v1 | derive-second | 57.422700 | 0.602286 | 56.506100 | 58.465400 |
| EVP-XDH | X301-v2 | derive-second | 59.328100 | 1.202803 | 58.118300 | 62.256500 |
| EVP-XDH | X25519 | derive-steady | 23.725100 | 0.285822 | 23.514500 | 24.240300 |
| EVP-XDH | X448 | derive-steady | 120.512900 | 1.733183 | 118.690500 | 124.188700 |
| EVP-XDH | X301-v1 | derive-steady | 57.492800 | 0.510851 | 56.849500 | 58.455300 |
| EVP-XDH | X301-v2 | derive-steady | 59.104100 | 0.387333 | 58.365700 | 59.457800 |
| EVP-KEM | ML-KEM-1024 | kem-keygen | 38.462900 | 0.522614 | 37.723300 | 39.186800 |
| EVP-KEM | Hybrid-v1 | kem-keygen | 67.929000 | 0.555800 | 67.411800 | 68.798400 |
| EVP-KEM | Hybrid-v2 | kem-keygen | 68.090200 | 0.602487 | 67.302200 | 69.115200 |
| EVP-KEM | ML-KEM-1024 | encaps | 20.449000 | 0.299740 | 20.035500 | 21.013400 |
| EVP-KEM | Hybrid-v1 | encaps | 107.196900 | 3.243234 | 105.586200 | 116.105300 |
| EVP-KEM | Hybrid-v2 | encaps | 108.701600 | 1.621919 | 106.731800 | 111.283400 |
| EVP-KEM | ML-KEM-1024 | decaps | 30.370600 | 0.982220 | 29.763900 | 32.868600 |
| EVP-KEM | Hybrid-v1 | decaps | 88.681100 | 1.577957 | 87.029000 | 92.351600 |
| EVP-KEM | Hybrid-v2 | decaps | 90.172600 | 1.234333 | 88.995500 | 93.061000 |
| EVP-codec | Ed25519 | encode-private-DER | 8.057612 | 1.042444 | 7.912128 | 11.155557 |
| EVP-codec | Ed448 | encode-private-DER | 8.026900 | 0.152813 | 7.881142 | 8.418569 |
| EVP-codec | Ed301-v1 | encode-private-DER | 40.231381 | 2.228649 | 39.026353 | 46.502163 |
| EVP-codec | Ed301-v2 | encode-private-DER | 56.146435 | 0.728289 | 54.619307 | 57.101419 |
| EVP-codec | X25519 | encode-private-DER | 8.012486 | 0.204780 | 7.690336 | 8.412598 |
| EVP-codec | X448 | encode-private-DER | 8.091457 | 0.120014 | 7.950196 | 8.340639 |
| EVP-codec | X301-v2 | encode-private-DER | 54.832156 | 1.137714 | 53.526366 | 57.089226 |
| EVP-codec | Ed25519 | decode-private-DER | 27.790671 | 0.444191 | 27.291108 | 28.612069 |
| EVP-codec | Ed448 | decode-private-DER | 150.600066 | 1.978321 | 147.731370 | 155.193677 |
| EVP-codec | Ed301-v1 | decode-private-DER | 59.753177 | 2.451500 | 58.245561 | 65.840433 |
| EVP-codec | Ed301-v2 | decode-private-DER | 58.899771 | 0.999426 | 58.135810 | 60.953796 |
| EVP-codec | X25519 | decode-private-DER | 27.079973 | 0.356642 | 26.826774 | 27.847791 |
| EVP-codec | X448 | decode-private-DER | 150.189892 | 6.518683 | 148.104573 | 168.879147 |
| EVP-codec | X301-v2 | decode-private-DER | 32.659058 | 0.921140 | 31.712051 | 34.927826 |
| EVP-codec | Ed25519 | encode-public-DER | 7.364662 | 0.111036 | 7.268727 | 7.615037 |
| EVP-codec | Ed448 | encode-public-DER | 7.270221 | 0.123898 | 7.061803 | 7.420378 |
| EVP-codec | Ed301-v1 | encode-public-DER | 39.088988 | 0.617150 | 38.745739 | 40.395715 |
| EVP-codec | Ed301-v2 | encode-public-DER | 55.731815 | 1.261879 | 54.242826 | 58.392503 |
| EVP-codec | X25519 | encode-public-DER | 7.362676 | 0.217199 | 7.303286 | 7.905292 |
| EVP-codec | X448 | encode-public-DER | 7.333819 | 0.109008 | 7.232424 | 7.593315 |
| EVP-codec | X301-v2 | encode-public-DER | 53.382698 | 0.653125 | 52.403988 | 54.001933 |
| EVP-codec | Ed25519 | decode-public-DER | 5.375302 | 0.554756 | 5.287967 | 7.031641 |
| EVP-codec | Ed448 | decode-public-DER | 5.410211 | 0.148109 | 5.189011 | 5.664531 |
| EVP-codec | Ed301-v1 | decode-public-DER | 106.450277 | 6.501822 | 101.732578 | 123.861272 |
| EVP-codec | Ed301-v2 | decode-public-DER | 67.641032 | 1.499623 | 66.247464 | 71.071742 |
| EVP-codec | X25519 | decode-public-DER | 5.310387 | 0.071888 | 5.200404 | 5.414239 |
| EVP-codec | X448 | decode-public-DER | 5.418074 | 0.121124 | 5.296336 | 5.693478 |
| EVP-codec | X301-v2 | decode-public-DER | 5.351456 | 0.095095 | 5.247945 | 5.579735 |
| EVP-codec | Ed25519 | encode-private-PEM | 10.547797 | 0.177819 | 10.248289 | 10.886494 |
| EVP-codec | Ed448 | encode-private-PEM | 10.629566 | 0.087268 | 10.478019 | 10.744061 |
| EVP-codec | Ed301-v1 | encode-private-PEM | 42.649378 | 0.474186 | 42.034605 | 43.746620 |
| EVP-codec | Ed301-v2 | encode-private-PEM | 58.720791 | 0.797916 | 57.532314 | 59.871575 |
| EVP-codec | X25519 | encode-private-PEM | 10.560820 | 0.169355 | 10.445272 | 10.862299 |
| EVP-codec | X448 | encode-private-PEM | 10.589416 | 0.161756 | 10.420010 | 10.834120 |
| EVP-codec | X301-v2 | encode-private-PEM | 56.602196 | 1.021484 | 55.505862 | 58.584077 |
| EVP-codec | Ed25519 | decode-private-PEM | 28.322597 | 0.622357 | 27.766827 | 29.657592 |
| EVP-codec | Ed448 | decode-private-PEM | 151.259721 | 1.688931 | 149.059169 | 154.204794 |
| EVP-codec | Ed301-v1 | decode-private-PEM | 60.368645 | 0.940035 | 59.221034 | 62.011795 |
| EVP-codec | Ed301-v2 | decode-private-PEM | 60.599481 | 1.212426 | 58.758492 | 62.630093 |
| EVP-codec | X25519 | decode-private-PEM | 27.717182 | 0.310577 | 27.251502 | 28.182417 |
| EVP-codec | X448 | decode-private-PEM | 151.247250 | 2.737490 | 149.726428 | 155.910354 |
| EVP-codec | X301-v2 | decode-private-PEM | 33.399402 | 2.315633 | 32.524676 | 40.011697 |
| EVP-codec | Ed25519 | encode-encrypted-PEM | 248.494017 | 4.092387 | 244.997879 | 257.005747 |
| EVP-codec | Ed448 | encode-encrypted-PEM | 247.578050 | 3.808544 | 246.009435 | 255.534014 |
| EVP-codec | Ed301-v1 | encode-encrypted-PEM | 284.260529 | 7.615541 | 278.369341 | 296.518740 |
| EVP-codec | Ed301-v2 | encode-encrypted-PEM | 299.984227 | 15.950754 | 292.308705 | 342.781226 |
| EVP-codec | X25519 | encode-encrypted-PEM | 250.216653 | 4.249113 | 244.422553 | 257.484156 |
| EVP-codec | X448 | encode-encrypted-PEM | 268.446568 | 4.566340 | 263.360129 | 277.283789 |
| EVP-codec | X301-v2 | encode-encrypted-PEM | 294.865244 | 9.721636 | 290.175147 | 322.976959 |
| EVP-codec | Ed25519 | decode-encrypted-PEM | 267.667867 | 6.310731 | 259.359622 | 279.653945 |
| EVP-codec | Ed448 | decode-encrypted-PEM | 385.779813 | 5.815663 | 382.530432 | 398.584322 |
| EVP-codec | Ed301-v1 | decode-encrypted-PEM | 296.049485 | 10.270212 | 290.712203 | 319.265899 |
| EVP-codec | Ed301-v2 | decode-encrypted-PEM | 297.955167 | 12.686989 | 287.686892 | 328.173809 |
| EVP-codec | X25519 | decode-encrypted-PEM | 260.141455 | 4.013965 | 257.207479 | 270.291655 |
| EVP-codec | X448 | decode-encrypted-PEM | 390.528059 | 6.108995 | 379.461580 | 395.610925 |
| EVP-codec | X301-v2 | decode-encrypted-PEM | 266.856572 | 1.463641 | 265.208447 | 269.812030 |
| TLS-engine | Ed25519-X25519 | full-handshake-warm-context | 381.675482 | 7.579487 | 370.838946 | 397.151181 |
| TLS-engine | Ed448-X25519 | full-handshake-warm-context | 585.476814 | 48.913092 | 571.689302 | 730.034639 |
| TLS-engine | Ed-v1-X25519 | full-handshake-warm-context | 510.255689 | 14.896268 | 483.905896 | 540.788995 |
| TLS-engine | Ed-v2-X25519 | full-handshake-warm-context | 459.260495 | 9.197223 | 445.861638 | 478.305716 |
| TLS-engine | Ed-v1-Hybrid-v1 | full-handshake-warm-context | 722.512811 | 15.408392 | 693.339887 | 737.735829 |
| TLS-engine | Ed-v2-Hybrid-v2 | full-handshake-warm-context | 683.026773 | 17.387490 | 656.903000 | 711.509500 |
| TLS-engine | Ed-v2-Raw-v2 | full-handshake-warm-context | 547.058301 | 9.436281 | 540.432610 | 569.346917 |
| TLS-engine | ECDSA-X25519 | full-handshake-warm-context | 373.073063 | 9.615975 | 360.238510 | 387.314261 |
| TLS-engine | ECDSA-Hybrid-v1 | full-handshake-warm-context | 583.197095 | 14.078771 | 567.555127 | 610.798121 |
| TLS-engine | ECDSA-Hybrid-v2 | full-handshake-warm-context | 579.424797 | 6.990626 | 571.821244 | 595.845706 |
| TLS-engine | ECDSA-Raw-v2 | full-handshake-warm-context | 452.423549 | 7.656445 | 440.501237 | 462.101359 |

## Vollständiger ABI-Lauf 4.0.2

Receipt: `/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e7_final_02_2026-09-10/benchmarks-4.0.2`.

SHA-256 des Receipt-Manifests: `4e2e48d29ec87eb640fb2fef43a88fb1cd74c90d32d4182dc13e0423003ec38e`.

| Schicht | Verfahren | Operation | Median µs | SD µs | Min µs | Max µs |
| --- | --- | --- | --- | --- | --- | --- |
| Rust-Ed | Ed301-v1 | expand | 28.336460 | 2.020166 | 27.500705 | 34.114161 |
| Rust-Ed | Ed301-v2 | expand | 28.235104 | 0.900278 | 27.567932 | 30.005848 |
| Rust-Ed | Ed301-v1 | sign | 29.411091 | 0.651306 | 28.748017 | 30.662312 |
| Rust-Ed | Ed301-v2 | sign | 29.117105 | 0.613457 | 28.346041 | 30.430654 |
| Rust-Ed | Ed301-v1 | verify | 87.352064 | 1.305372 | 85.385124 | 88.944656 |
| Rust-Ed | Ed301-v2 | verify | 83.433324 | 1.309544 | 82.956385 | 86.269981 |
| Rust-Ed | Ed301-v1 | import | 98.094883 | 1.183803 | 97.033741 | 100.645564 |
| Rust-Ed | Ed301-v2 | import | 62.539953 | 0.877611 | 61.676933 | 64.045542 |
| Rust-X | X301-v1 | public | 27.553107 | 1.301786 | 27.312417 | 30.531070 |
| Rust-X | X301-v2 | public | 27.773344 | 0.827549 | 27.212916 | 29.574002 |
| Rust-X | X301-v1 | shared | 57.473484 | 0.870650 | 56.868413 | 59.721898 |
| Rust-X | X301-v2 | shared | 60.447131 | 1.444662 | 58.687192 | 63.109431 |
| Rust-X | X301-v1 | validate-public | 0.004309 | 0.000523 | 0.003989 | 0.005701 |
| Rust-X | X301-v2 | validate-public | 0.001448 | 0.000066 | 0.001329 | 0.001527 |
| Rust-X | X301-v1 | canonical-public | 0.008674 | 0.000781 | 0.007452 | 0.010124 |
| Rust-X | X301-v2 | canonical-public | 0.003317 | 0.000355 | 0.002898 | 0.003957 |
| Rust-X | X301-v2 | import-secret | 0.032356 | 0.000772 | 0.031725 | 0.034051 |
| Rust-X | X301-v2 | import-public | 0.006011 | 0.000973 | 0.005278 | 0.007707 |
| Rust-X | X301-v2 | prepared-public | 27.661721 | 0.642852 | 27.093649 | 28.662418 |
| Rust-X | X301-v2 | prepared-shared | 59.988179 | 1.305737 | 58.511358 | 62.175328 |
| EVP-signature | Ed25519 | keygen | 24.505800 | 0.394710 | 24.192500 | 25.393600 |
| EVP-signature | Ed448 | keygen | 147.414200 | 6.882624 | 146.436600 | 167.614600 |
| EVP-signature | Ed301-v1 | keygen | 57.408700 | 0.877077 | 56.267600 | 58.858700 |
| EVP-signature | Ed301-v2 | keygen | 56.709000 | 0.811753 | 56.025300 | 58.785400 |
| EVP-signature | Ed25519 | sign | 24.085300 | 0.241585 | 23.618800 | 24.317700 |
| EVP-signature | Ed448 | sign | 148.176300 | 2.037290 | 146.176600 | 152.897300 |
| EVP-signature | Ed301-v1 | sign | 30.413800 | 0.598897 | 29.654200 | 31.148900 |
| EVP-signature | Ed301-v2 | sign | 29.742000 | 0.410760 | 29.479100 | 30.696800 |
| EVP-signature | Ed25519 | verify | 79.861100 | 1.535898 | 77.759200 | 82.906600 |
| EVP-signature | Ed448 | verify | 157.976400 | 4.224504 | 154.680600 | 169.204400 |
| EVP-signature | Ed301-v1 | verify | 87.076300 | 0.785136 | 85.634100 | 88.287400 |
| EVP-signature | Ed301-v2 | verify | 84.143500 | 1.882531 | 82.475700 | 88.374000 |
| EVP-XDH | X25519 | keygen | 23.981800 | 0.384425 | 23.616000 | 24.741900 |
| EVP-XDH | X448 | keygen | 145.967500 | 2.686716 | 144.220100 | 151.225300 |
| EVP-XDH | X301-v1 | keygen | 30.102300 | 1.938554 | 28.831200 | 34.721600 |
| EVP-XDH | X301-v2 | keygen | 29.724900 | 0.441666 | 28.904800 | 30.342600 |
| EVP-XDH | X25519 | derive-setup | 1.066700 | 0.027638 | 1.042300 | 1.109700 |
| EVP-XDH | X448 | derive-setup | 1.042500 | 0.018120 | 1.027300 | 1.077600 |
| EVP-XDH | X301-v1 | derive-setup | 1.600700 | 0.306353 | 1.525100 | 2.492700 |
| EVP-XDH | X301-v2 | derive-setup | 1.672400 | 0.145231 | 1.646000 | 2.106700 |
| EVP-XDH | X25519 | derive-first | 23.973200 | 0.411455 | 23.390400 | 24.547300 |
| EVP-XDH | X448 | derive-first | 121.261200 | 2.073331 | 118.158300 | 124.382000 |
| EVP-XDH | X301-v1 | derive-first | 58.237000 | 0.795084 | 56.468000 | 59.312700 |
| EVP-XDH | X301-v2 | derive-first | 58.803300 | 1.354884 | 58.428000 | 62.138500 |
| EVP-XDH | X25519 | derive-second | 23.673900 | 0.372419 | 23.465400 | 24.602300 |
| EVP-XDH | X448 | derive-second | 121.694200 | 1.685363 | 119.424600 | 124.852500 |
| EVP-XDH | X301-v1 | derive-second | 58.050000 | 0.618478 | 56.886900 | 58.957300 |
| EVP-XDH | X301-v2 | derive-second | 59.400100 | 0.736943 | 58.694800 | 60.825200 |
| EVP-XDH | X25519 | derive-steady | 23.740200 | 0.366082 | 23.619200 | 24.759300 |
| EVP-XDH | X448 | derive-steady | 120.328000 | 1.432564 | 118.972200 | 123.618800 |
| EVP-XDH | X301-v1 | derive-steady | 57.731900 | 0.824497 | 56.734700 | 59.292500 |
| EVP-XDH | X301-v2 | derive-steady | 59.591700 | 1.267669 | 58.303700 | 62.308200 |
| EVP-KEM | ML-KEM-1024 | kem-keygen | 38.231200 | 0.631922 | 37.377800 | 39.456600 |
| EVP-KEM | Hybrid-v1 | kem-keygen | 67.956900 | 3.701067 | 67.214000 | 78.991400 |
| EVP-KEM | Hybrid-v2 | kem-keygen | 67.695600 | 1.004153 | 66.000800 | 69.278100 |
| EVP-KEM | ML-KEM-1024 | encaps | 20.126100 | 0.340090 | 19.756000 | 20.680800 |
| EVP-KEM | Hybrid-v1 | encaps | 107.718500 | 5.503057 | 105.209100 | 120.899300 |
| EVP-KEM | Hybrid-v2 | encaps | 109.302200 | 2.473759 | 107.069200 | 113.768100 |
| EVP-KEM | ML-KEM-1024 | decaps | 29.740000 | 0.580065 | 29.462900 | 31.291000 |
| EVP-KEM | Hybrid-v1 | decaps | 89.082700 | 1.847486 | 87.484500 | 92.904600 |
| EVP-KEM | Hybrid-v2 | decaps | 89.232200 | 2.682174 | 88.176800 | 96.653400 |
| EVP-codec | Ed25519 | encode-private-DER | 8.646891 | 0.310632 | 8.394988 | 9.221216 |
| EVP-codec | Ed448 | encode-private-DER | 8.900594 | 0.228019 | 8.660568 | 9.357205 |
| EVP-codec | Ed301-v1 | encode-private-DER | 23.353329 | 0.817464 | 22.808956 | 25.531210 |
| EVP-codec | Ed301-v2 | encode-private-DER | 32.738872 | 0.643149 | 31.768775 | 33.806128 |
| EVP-codec | X25519 | encode-private-DER | 8.795189 | 0.458080 | 8.482820 | 10.049143 |
| EVP-codec | X448 | encode-private-DER | 8.683058 | 0.209997 | 8.599714 | 9.183293 |
| EVP-codec | X301-v2 | encode-private-DER | 27.307979 | 0.724084 | 26.740876 | 28.896872 |
| EVP-codec | Ed25519 | decode-private-DER | 27.119694 | 0.326598 | 26.822185 | 27.897562 |
| EVP-codec | Ed448 | decode-private-DER | 153.186484 | 3.426723 | 149.623585 | 159.916870 |
| EVP-codec | Ed301-v1 | decode-private-DER | 59.000538 | 1.796650 | 58.163705 | 63.965462 |
| EVP-codec | Ed301-v2 | decode-private-DER | 59.227673 | 1.111934 | 58.273801 | 61.791692 |
| EVP-codec | X25519 | decode-private-DER | 26.623837 | 4.830134 | 26.306626 | 38.564904 |
| EVP-codec | X448 | decode-private-DER | 149.851114 | 2.945949 | 147.004898 | 157.413715 |
| EVP-codec | X301-v2 | decode-private-DER | 31.857286 | 0.300446 | 31.403336 | 32.346305 |
| EVP-codec | Ed25519 | encode-public-DER | 8.372251 | 0.158734 | 8.065412 | 8.537612 |
| EVP-codec | Ed448 | encode-public-DER | 8.273087 | 0.153581 | 8.101627 | 8.599919 |
| EVP-codec | Ed301-v1 | encode-public-DER | 22.769114 | 1.497715 | 22.504549 | 27.174002 |
| EVP-codec | Ed301-v2 | encode-public-DER | 32.282632 | 1.883226 | 31.301539 | 36.915399 |
| EVP-codec | X25519 | encode-public-DER | 8.356545 | 0.412629 | 7.923465 | 9.224657 |
| EVP-codec | X448 | encode-public-DER | 8.076250 | 0.289885 | 7.847710 | 8.776371 |
| EVP-codec | X301-v2 | encode-public-DER | 26.822210 | 0.423874 | 26.434996 | 27.884380 |
| EVP-codec | Ed25519 | decode-public-DER | 5.014615 | 0.060215 | 4.914653 | 5.124781 |
| EVP-codec | Ed448 | decode-public-DER | 5.047276 | 0.050129 | 4.959383 | 5.117159 |
| EVP-codec | Ed301-v1 | decode-public-DER | 103.450600 | 1.425849 | 100.963842 | 105.892827 |
| EVP-codec | Ed301-v2 | decode-public-DER | 67.106437 | 0.936794 | 66.092383 | 69.107447 |
| EVP-codec | X25519 | decode-public-DER | 4.977277 | 0.232451 | 4.921142 | 5.656384 |
| EVP-codec | X448 | decode-public-DER | 5.077586 | 0.120053 | 4.926457 | 5.302785 |
| EVP-codec | X301-v2 | decode-public-DER | 5.019363 | 0.199470 | 4.850114 | 5.410986 |
| EVP-codec | Ed25519 | encode-private-PEM | 9.491189 | 0.201247 | 9.197540 | 9.743702 |
| EVP-codec | Ed448 | encode-private-PEM | 9.803660 | 0.425498 | 9.493977 | 10.916567 |
| EVP-codec | Ed301-v1 | encode-private-PEM | 24.573060 | 1.965229 | 24.012880 | 30.385420 |
| EVP-codec | Ed301-v2 | encode-private-PEM | 33.477808 | 0.639987 | 32.998293 | 35.018692 |
| EVP-codec | X25519 | encode-private-PEM | 9.503925 | 0.217345 | 9.284351 | 9.898636 |
| EVP-codec | X448 | encode-private-PEM | 9.519766 | 0.111479 | 9.428565 | 9.733124 |
| EVP-codec | X301-v2 | encode-private-PEM | 28.557829 | 1.660447 | 28.057877 | 33.477891 |
| EVP-codec | Ed25519 | decode-private-PEM | 28.175444 | 1.099315 | 27.111891 | 30.825550 |
| EVP-codec | Ed448 | decode-private-PEM | 152.618054 | 4.173164 | 148.449445 | 161.704374 |
| EVP-codec | Ed301-v1 | decode-private-PEM | 59.413508 | 1.425745 | 58.719132 | 63.076259 |
| EVP-codec | Ed301-v2 | decode-private-PEM | 58.942561 | 0.728168 | 58.402217 | 60.852742 |
| EVP-codec | X25519 | decode-private-PEM | 27.414098 | 0.511416 | 26.832808 | 28.179592 |
| EVP-codec | X448 | decode-private-PEM | 150.154362 | 1.597512 | 147.902297 | 152.792532 |
| EVP-codec | X301-v2 | decode-private-PEM | 32.829360 | 3.283376 | 31.789447 | 39.224762 |
| EVP-codec | Ed25519 | encode-encrypted-PEM | 237.642924 | 4.611252 | 234.636291 | 248.512207 |
| EVP-codec | Ed448 | encode-encrypted-PEM | 237.675475 | 3.773479 | 234.451547 | 245.213127 |
| EVP-codec | Ed301-v1 | encode-encrypted-PEM | 257.270153 | 3.561007 | 251.340572 | 262.428411 |
| EVP-codec | Ed301-v2 | encode-encrypted-PEM | 266.700514 | 3.900763 | 259.088194 | 271.093062 |
| EVP-codec | X25519 | encode-encrypted-PEM | 235.762717 | 6.116257 | 234.410717 | 251.513825 |
| EVP-codec | X448 | encode-encrypted-PEM | 237.371986 | 6.268670 | 233.544702 | 254.288739 |
| EVP-codec | X301-v2 | encode-encrypted-PEM | 261.114076 | 9.900290 | 253.959534 | 286.379022 |
| EVP-codec | Ed25519 | decode-encrypted-PEM | 253.999812 | 15.400025 | 249.677080 | 299.474899 |
| EVP-codec | Ed448 | decode-encrypted-PEM | 376.827315 | 10.735464 | 367.751251 | 402.073910 |
| EVP-codec | Ed301-v1 | decode-encrypted-PEM | 286.711357 | 2.746968 | 284.549828 | 292.638767 |
| EVP-codec | Ed301-v2 | decode-encrypted-PEM | 291.104409 | 29.391169 | 283.051249 | 376.777065 |
| EVP-codec | X25519 | decode-encrypted-PEM | 254.969052 | 29.118869 | 246.600025 | 340.349805 |
| EVP-codec | X448 | decode-encrypted-PEM | 378.009410 | 10.812545 | 371.654155 | 401.743498 |
| EVP-codec | X301-v2 | decode-encrypted-PEM | 259.473338 | 3.410791 | 252.865077 | 263.259859 |
| TLS-engine | Ed25519-X25519 | full-handshake-warm-context | 372.065936 | 22.562715 | 361.919271 | 427.629049 |
| TLS-engine | Ed448-X25519 | full-handshake-warm-context | 576.985491 | 17.089602 | 563.658661 | 620.329129 |
| TLS-engine | Ed-v1-X25519 | full-handshake-warm-context | 491.775583 | 7.299896 | 477.967648 | 500.893839 |
| TLS-engine | Ed-v2-X25519 | full-handshake-warm-context | 459.237661 | 8.629132 | 448.338893 | 470.691434 |
| TLS-engine | Ed-v1-Hybrid-v1 | full-handshake-warm-context | 704.687408 | 76.796235 | 686.017346 | 932.694422 |
| TLS-engine | Ed-v2-Hybrid-v2 | full-handshake-warm-context | 665.482351 | 57.758105 | 651.875431 | 836.319940 |
| TLS-engine | Ed-v2-Raw-v2 | full-handshake-warm-context | 537.671678 | 91.146734 | 530.834927 | 813.109436 |
| TLS-engine | ECDSA-X25519 | full-handshake-warm-context | 358.344554 | 54.924884 | 345.346121 | 520.700768 |
| TLS-engine | ECDSA-Hybrid-v1 | full-handshake-warm-context | 570.425494 | 40.018768 | 554.548754 | 678.930006 |
| TLS-engine | ECDSA-Hybrid-v2 | full-handshake-warm-context | 575.526125 | 85.354934 | 560.535057 | 826.703307 |
| TLS-engine | ECDSA-Raw-v2 | full-handshake-warm-context | 449.328811 | 12.347326 | 434.452432 | 469.451067 |

## Erweiterte Nachrichten-/Context-Matrix

Receipt: `/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e7_final_02_2026-09-10/ED301-v2_core-matrix_45ebwkhy`.

SHA-256: `b842e4e7313d64d85237627963a7729728c96f5e84aa61133e488909ebd411bb`.

cold-sign enthält Seedimport und Expansion; prepared-sign/prepared-verify verwenden vorbereitete Schlüssel. import-verify enthält die erneute Public-Key-Prüfung. Nachricht i=(29i+7) mod 256, Context i=(17i+3) mod 256. Kalt bezeichnet den Schlüssel-Lifecycle, keinen geleerten CPU-Cache.

| Version | Operation | Nachricht Byte | Context Byte | Median µs | SD µs | Min µs | Max µs |
| --- | --- | --- | --- | --- | --- | --- | --- |
| v1 | cold-sign | 0 | 0 | 56.959394 | 2.564667 | 56.415624 | 64.440367 |
| v2 | cold-sign | 0 | 0 | 56.784142 | 2.670486 | 56.442481 | 63.451814 |
| v1 | prepared-sign | 0 | 0 | 28.872995 | 2.741130 | 28.393513 | 36.398401 |
| v2 | prepared-sign | 0 | 0 | 28.642640 | 1.924064 | 28.386377 | 34.435933 |
| v1 | prepared-verify | 0 | 0 | 86.339630 | 1.894980 | 85.918974 | 91.534422 |
| v2 | prepared-verify | 0 | 0 | 84.764275 | 2.337989 | 82.444710 | 89.250608 |
| v1 | import-verify | 0 | 0 | 185.528435 | 5.930820 | 182.656346 | 200.386792 |
| v2 | import-verify | 0 | 0 | 147.565111 | 3.490021 | 144.134786 | 153.173630 |
| v1 | cold-sign | 0 | 16 | 57.063974 | 2.051025 | 56.356452 | 61.823857 |
| v2 | cold-sign | 0 | 16 | 57.103158 | 1.033963 | 56.435690 | 59.257166 |
| v1 | prepared-sign | 0 | 16 | 28.821289 | 0.656442 | 28.460715 | 30.394233 |
| v2 | prepared-sign | 0 | 16 | 28.829256 | 0.415836 | 28.432391 | 29.711031 |
| v1 | prepared-verify | 0 | 16 | 89.496588 | 4.388312 | 84.837283 | 97.668178 |
| v2 | prepared-verify | 0 | 16 | 83.712216 | 2.743324 | 83.218902 | 89.670757 |
| v1 | import-verify | 0 | 16 | 184.428598 | 5.291692 | 182.894037 | 196.649559 |
| v2 | import-verify | 0 | 16 | 148.442447 | 8.619746 | 145.276476 | 172.653513 |
| v1 | cold-sign | 0 | 255 | 57.964414 | 3.898536 | 57.333723 | 68.150580 |
| v2 | cold-sign | 0 | 255 | 57.846349 | 0.741235 | 57.534808 | 59.947061 |
| v1 | prepared-sign | 0 | 255 | 29.813220 | 3.814642 | 29.499062 | 41.278763 |
| v2 | prepared-sign | 0 | 255 | 30.023901 | 0.915028 | 29.541546 | 32.426677 |
| v1 | prepared-verify | 0 | 255 | 86.889500 | 2.316898 | 85.932249 | 92.921707 |
| v2 | prepared-verify | 0 | 255 | 83.980074 | 2.251087 | 82.623770 | 89.846932 |
| v1 | import-verify | 0 | 255 | 185.436974 | 1.716973 | 184.212327 | 188.876103 |
| v2 | import-verify | 0 | 255 | 146.108939 | 3.091821 | 143.348308 | 153.742734 |
| v1 | cold-sign | 64 | 0 | 57.709409 | 0.908390 | 56.778688 | 59.353693 |
| v2 | cold-sign | 64 | 0 | 57.357333 | 0.879331 | 56.685055 | 59.477250 |
| v1 | prepared-sign | 64 | 0 | 28.924903 | 0.350946 | 28.643794 | 29.724119 |
| v2 | prepared-sign | 64 | 0 | 29.047055 | 0.747889 | 28.639919 | 30.970790 |
| v1 | prepared-verify | 64 | 0 | 85.456508 | 1.580178 | 84.666874 | 89.737247 |
| v2 | prepared-verify | 64 | 0 | 83.942072 | 2.083275 | 83.580379 | 90.045719 |
| v1 | import-verify | 64 | 0 | 183.656205 | 3.873971 | 182.399331 | 194.936181 |
| v2 | import-verify | 64 | 0 | 146.415435 | 4.969703 | 144.633535 | 159.639068 |
| v1 | cold-sign | 64 | 16 | 57.261360 | 3.588255 | 56.393062 | 66.836053 |
| v2 | cold-sign | 64 | 16 | 56.933918 | 1.605813 | 56.437969 | 60.709576 |
| v1 | prepared-sign | 64 | 16 | 28.900273 | 2.989191 | 28.682948 | 37.909235 |
| v2 | prepared-sign | 64 | 16 | 29.026263 | 6.257914 | 28.758096 | 47.980092 |
| v1 | prepared-verify | 64 | 16 | 85.842438 | 2.462086 | 85.030733 | 92.201419 |
| v2 | prepared-verify | 64 | 16 | 82.158522 | 14.206464 | 81.668367 | 124.821817 |
| v1 | import-verify | 64 | 16 | 183.777227 | 3.936805 | 182.879843 | 194.576125 |
| v2 | import-verify | 64 | 16 | 144.320842 | 2.040975 | 142.196587 | 149.339857 |
| v1 | cold-sign | 64 | 255 | 57.726278 | 2.120377 | 57.179607 | 64.004216 |
| v2 | cold-sign | 64 | 255 | 58.949067 | 1.093251 | 57.508584 | 60.754211 |
| v1 | prepared-sign | 64 | 255 | 30.615693 | 1.744478 | 29.597841 | 34.987056 |
| v2 | prepared-sign | 64 | 255 | 30.266014 | 0.441965 | 29.869732 | 31.155407 |
| v1 | prepared-verify | 64 | 255 | 87.162894 | 3.737056 | 85.472241 | 98.028692 |
| v2 | prepared-verify | 64 | 255 | 83.736521 | 2.241430 | 82.468116 | 89.271787 |
| v1 | import-verify | 64 | 255 | 186.000270 | 5.203474 | 183.881049 | 196.689792 |
| v2 | import-verify | 64 | 255 | 145.094074 | 5.491259 | 143.716638 | 161.025157 |
| v1 | cold-sign | 1024 | 0 | 60.638529 | 1.631045 | 60.364604 | 64.315054 |
| v2 | cold-sign | 1024 | 0 | 60.994783 | 2.238210 | 60.236017 | 67.315463 |
| v1 | prepared-sign | 1024 | 0 | 33.034558 | 1.157202 | 32.089888 | 36.007376 |
| v2 | prepared-sign | 1024 | 0 | 32.757086 | 0.627044 | 32.495296 | 34.347490 |
| v1 | prepared-verify | 1024 | 0 | 88.960488 | 3.195437 | 87.591337 | 95.371345 |
| v2 | prepared-verify | 1024 | 0 | 84.876409 | 2.054558 | 84.095624 | 89.419917 |
| v1 | import-verify | 1024 | 0 | 186.309680 | 3.510978 | 185.304084 | 193.681363 |
| v2 | import-verify | 1024 | 0 | 147.613030 | 2.733629 | 146.640846 | 154.139241 |
| v1 | cold-sign | 1024 | 16 | 61.035065 | 1.221796 | 60.693621 | 63.845263 |
| v2 | cold-sign | 1024 | 16 | 61.080566 | 0.832250 | 60.887549 | 63.283835 |
| v1 | prepared-sign | 1024 | 16 | 32.964315 | 0.528438 | 32.539811 | 34.366939 |
| v2 | prepared-sign | 1024 | 16 | 33.386694 | 2.974382 | 32.835693 | 40.563237 |
| v1 | prepared-verify | 1024 | 16 | 88.154262 | 3.246617 | 87.433154 | 95.778824 |
| v2 | prepared-verify | 1024 | 16 | 84.819683 | 3.432762 | 84.413638 | 95.219552 |
| v1 | import-verify | 1024 | 16 | 186.090587 | 2.630905 | 185.254238 | 191.893128 |
| v2 | import-verify | 1024 | 16 | 147.315411 | 0.626730 | 146.140693 | 148.099062 |
| v1 | cold-sign | 1024 | 255 | 61.843960 | 2.477337 | 61.229311 | 67.439845 |
| v2 | cold-sign | 1024 | 255 | 62.316625 | 1.091554 | 61.348943 | 64.387252 |
| v1 | prepared-sign | 1024 | 255 | 33.795390 | 0.522500 | 33.363207 | 35.150432 |
| v2 | prepared-sign | 1024 | 255 | 34.016076 | 0.703837 | 33.468321 | 35.641409 |
| v1 | prepared-verify | 1024 | 255 | 87.177144 | 0.972527 | 86.820080 | 89.962614 |
| v2 | prepared-verify | 1024 | 255 | 85.292615 | 2.989330 | 84.548093 | 93.726230 |
| v1 | import-verify | 1024 | 255 | 185.961223 | 2.143157 | 184.853757 | 191.525130 |
| v2 | import-verify | 1024 | 255 | 149.854082 | 2.787689 | 146.891617 | 154.500928 |
| v1 | cold-sign | 16384 | 0 | 120.818679 | 0.988828 | 118.710317 | 121.560670 |
| v2 | cold-sign | 16384 | 0 | 120.559433 | 1.488537 | 118.162342 | 123.486098 |
| v1 | prepared-sign | 16384 | 0 | 92.114365 | 1.426056 | 90.926816 | 94.385500 |
| v2 | prepared-sign | 16384 | 0 | 92.048348 | 1.857930 | 91.199155 | 96.901950 |
| v1 | prepared-verify | 16384 | 0 | 117.519649 | 2.220327 | 116.846213 | 122.307048 |
| v2 | prepared-verify | 16384 | 0 | 114.305016 | 3.614968 | 112.248172 | 124.068999 |
| v1 | import-verify | 16384 | 0 | 215.341343 | 2.239710 | 214.375140 | 221.524884 |
| v2 | import-verify | 16384 | 0 | 177.137933 | 6.386504 | 174.970028 | 193.154891 |
| v1 | cold-sign | 16384 | 16 | 120.239777 | 2.375481 | 118.522096 | 125.677818 |
| v2 | cold-sign | 16384 | 16 | 122.115673 | 4.680145 | 118.546207 | 134.196706 |
| v1 | prepared-sign | 16384 | 16 | 91.254470 | 1.978452 | 90.555377 | 96.530229 |
| v2 | prepared-sign | 16384 | 16 | 91.086898 | 1.140201 | 90.760276 | 94.319241 |
| v1 | prepared-verify | 16384 | 16 | 117.138025 | 3.184497 | 116.177984 | 125.145254 |
| v2 | prepared-verify | 16384 | 16 | 117.258280 | 2.271387 | 113.589468 | 119.663182 |
| v1 | import-verify | 16384 | 16 | 216.598615 | 3.635715 | 212.982424 | 222.906747 |
| v2 | import-verify | 16384 | 16 | 178.764563 | 2.625271 | 176.320430 | 183.139196 |
| v1 | cold-sign | 16384 | 255 | 122.786995 | 2.373011 | 119.122073 | 125.804925 |
| v2 | cold-sign | 16384 | 255 | 121.364024 | 1.927569 | 119.227687 | 124.714418 |
| v1 | prepared-sign | 16384 | 255 | 95.623323 | 23.705082 | 91.746354 | 165.529990 |
| v2 | prepared-sign | 16384 | 255 | 92.649942 | 0.928170 | 91.556827 | 94.849328 |
| v1 | prepared-verify | 16384 | 255 | 117.411936 | 3.788892 | 116.354724 | 126.685692 |
| v2 | prepared-verify | 16384 | 255 | 115.537125 | 3.058234 | 114.960855 | 124.593232 |
| v1 | import-verify | 16384 | 255 | 215.618893 | 16.765453 | 213.533635 | 266.233085 |
| v2 | import-verify | 16384 | 255 | 178.152989 | 13.174563 | 176.493841 | 217.207674 |
| v1 | prepare-verifier | 0 | 0 | 26.650814 | 0.509504 | 26.277470 | 27.943688 |
| v2 | prepare-verifier | 0 | 0 | 26.154107 | 0.651249 | 26.027347 | 28.083966 |

## Arithmetik-Mikrobenchmarks

Receipt: `/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e7_final_02_2026-09-10/ED301-v2_microbench_rih_0li7`.

SHA-256: `7526cc8216a8ee587337871a87c4a7fd7e007f8c453f939d4f5fa7c67eb1c827`.

Identischer privater Harness auf unveränderten Modulquellen, 16 rotierende Operanden und Kopierkontrolle. Loop, Operandenwahl, black_box und Ergebnis-Drop sind enthalten. Kein Produkt-API- oder Seitenkanal-Gate. field-mul-d misst weiterhin den ursprünglichen einzelnen Feldoperator, nicht den algebraischen E5-Gesamtgewinn.

| Version | Operation | Median ns | SD ns | Min ns | Max ns |
| --- | --- | --- | --- | --- | --- |
| v1 | control-field-copy | 1.261000 | 0.015116 | 1.254000 | 1.302000 |
| v2 | control-field-copy | 1.260000 | 0.010794 | 1.252000 | 1.284000 |
| v1 | field-add | 6.984000 | 0.306420 | 6.913000 | 7.860000 |
| v2 | field-add | 6.715000 | 0.150383 | 6.591000 | 7.018000 |
| v1 | field-sub | 6.006000 | 0.103577 | 5.911000 | 6.192000 |
| v2 | field-sub | 5.985000 | 0.109527 | 5.900000 | 6.174000 |
| v1 | field-mul | 25.880000 | 0.544239 | 25.544000 | 26.839000 |
| v2 | field-mul | 25.454000 | 1.874486 | 24.904000 | 30.959000 |
| v1 | field-square | 24.822000 | 0.417924 | 24.352000 | 25.664000 |
| v2 | field-square | 23.212000 | 0.444473 | 22.780000 | 24.089000 |
| v1 | field-mul-301 | 11.109000 | 0.339257 | 10.726000 | 11.721000 |
| v2 | field-mul-301 | 11.232000 | 0.178112 | 11.036000 | 11.594000 |
| v1 | field-mul-a | 11.151000 | 0.147461 | 10.957000 | 11.371000 |
| v2 | field-mul-a | 9.933000 | 0.172887 | 9.760000 | 10.250000 |
| v1 | field-mul-d | 10.700000 | 0.235895 | 10.507000 | 11.295000 |
| v2 | field-mul-d | 14.923000 | 0.190949 | 14.695000 | 15.269000 |
| v1 | field-invert | 2710.119000 | 51.602577 | 2681.006000 | 2842.690000 |
| v2 | field-invert | 2721.539000 | 87.221441 | 2688.322000 | 2923.804000 |
| v1 | field-sqrt-ratio | 9233.350000 | 352.493185 | 9174.065000 | 10261.090000 |
| v2 | field-sqrt-ratio | 8853.706000 | 164.800736 | 8719.449000 | 9151.955000 |
| v1 | lazy-mul | 21.750000 | 1.294955 | 21.304000 | 25.477000 |
| v2 | lazy-mul | 21.486000 | 0.381884 | 21.082000 | 22.263000 |
| v1 | lazy-square | 20.394000 | 0.432682 | 20.171000 | 21.589000 |
| v2 | lazy-square | 18.918000 | 0.276607 | 18.816000 | 19.619000 |
| v1 | lazy-mul-a | 6.636000 | 0.131399 | 6.584000 | 6.915000 |
| v2 | lazy-mul-a | 6.615000 | 0.181960 | 6.557000 | 7.060000 |
| v1 | lazy-loose-mul | 25.459000 | 0.474054 | 25.306000 | 26.804000 |
| v2 | lazy-loose-mul | 26.645000 | 0.286912 | 26.367000 | 27.186000 |
| v1 | scalar-add | 4.785000 | 0.099088 | 4.756000 | 5.031000 |
| v2 | scalar-add | 4.803000 | 0.051963 | 4.754000 | 4.915000 |
| v1 | scalar-mul | 116.811000 | 2.368041 | 113.893000 | 122.234000 |
| v2 | scalar-mul | 116.479000 | 3.015044 | 114.127000 | 122.931000 |
| v1 | scalar-reduce-pruned | 62.559000 | 1.957817 | 59.756000 | 65.775000 |
| v2 | scalar-reduce-pruned | 61.599000 | 1.647650 | 59.978000 | 65.734000 |
| v1 | scalar-reduce-hash | 156.460000 | 5.623296 | 152.446000 | 170.787000 |
| v2 | scalar-reduce-hash | 156.360000 | 3.153200 | 153.149000 | 162.587000 |
| v1 | scalar-wnaf-public | 592.448000 | 7.611671 | 586.420000 | 608.103000 |
| v2 | scalar-wnaf-public | 587.956000 | 13.437008 | 582.718000 | 624.489000 |

## Gepaarter E7-Schrittvergleich

| API | Version | Operation | Median µs | SD µs | Min µs | Max µs |
| --- | --- | --- | --- | --- | --- | --- |
| ed | v1 | expand | 28.213370 | 0.941524 | 27.875835 | 30.086641 |
| ed | before | expand | 28.253496 | 0.814594 | 27.603038 | 30.279910 |
| ed | after | expand | 28.881739 | 1.300966 | 28.030051 | 32.437830 |
| ed | v1 | sign | 29.277438 | 0.767791 | 28.789771 | 31.354764 |
| ed | before | sign | 29.799042 | 1.381265 | 28.808081 | 32.305640 |
| ed | after | sign | 29.514521 | 2.813221 | 28.885654 | 37.877444 |
| ed | v1 | verify | 89.010746 | 1.893563 | 85.839346 | 92.690494 |
| ed | before | verify | 87.092226 | 3.706403 | 84.702968 | 94.795318 |
| ed | after | verify | 83.335425 | 1.479756 | 82.669348 | 86.723410 |
| ed | v1 | import | 98.168513 | 2.346481 | 97.069564 | 103.011279 |
| ed | before | import | 66.774133 | 1.932010 | 64.433516 | 69.980626 |
| ed | after | import | 62.416451 | 2.064310 | 61.530835 | 68.378948 |
| x | v1 | public | 28.528298 | 0.317017 | 27.933952 | 28.899082 |
| x | before | public | 28.072040 | 3.381746 | 27.235210 | 38.124205 |
| x | after | public | 28.032819 | 1.579674 | 27.071145 | 32.370439 |
| x | v1 | shared | 58.120661 | 2.563253 | 57.118534 | 65.321388 |
| x | before | shared | 66.091234 | 6.792606 | 62.827524 | 81.085185 |
| x | after | shared | 60.212009 | 2.342877 | 59.485508 | 65.025217 |
| x | v1 | validate-public | 0.003874 | 0.000301 | 0.003808 | 0.004562 |
| x | before | validate-public | 0.001073 | 0.000124 | 0.001057 | 0.001395 |
| x | after | validate-public | 0.001079 | 0.000184 | 0.001060 | 0.001634 |
| x | v1 | canonical-public | 0.007639 | 0.000824 | 0.007006 | 0.009762 |
| x | before | canonical-public | 0.002672 | 0.000139 | 0.002545 | 0.003038 |
| x | after | canonical-public | 0.002716 | 0.000246 | 0.002535 | 0.003139 |
| x | before | import-secret | 0.032873 | 0.001113 | 0.031514 | 0.035313 |
| x | after | import-secret | 0.031879 | 0.000968 | 0.031399 | 0.033826 |
| x | before | import-public | 0.004641 | 0.000831 | 0.004598 | 0.006601 |
| x | after | import-public | 0.004693 | 0.000879 | 0.004623 | 0.006478 |
| x | before | prepared-shared | 64.948780 | 1.322352 | 62.545111 | 67.157176 |
| x | after | prepared-shared | 60.630632 | 1.864457 | 58.368535 | 63.672982 |
| x | before | prepared-public | 27.643731 | 2.542283 | 26.979351 | 34.735186 |
| x | after | prepared-public | 27.743378 | 1.331001 | 27.458235 | 31.684550 |
