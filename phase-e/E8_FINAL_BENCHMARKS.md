# E8: vollständige abschließende Benchmarktabellen

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
Der neue gepaarte 32-Fälle-E8-Vergleich bleibt zusätzlich vollständig im Paket.

## Vollständiger ABI-Lauf 3.5.8

Receipt: `/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e8_final_01_2026-09-10/benchmarks-3.5.8`.

SHA-256 des Receipt-Manifests: `721c2c5a5bf87ad4aa4e7764ee0fa3dabc8643cc7c03efda371604359d5919c2`.

| Schicht | Verfahren | Operation | Median µs | SD µs | Min µs | Max µs |
| --- | --- | --- | --- | --- | --- | --- |
| Rust-Ed | Ed301-v1 | expand | 28.370744 | 2.004917 | 27.781805 | 34.244844 |
| Rust-Ed | Ed301-v2 | expand | 28.320680 | 2.102231 | 27.808121 | 34.484099 |
| Rust-Ed | Ed301-v1 | sign | 29.046959 | 0.530424 | 28.634064 | 30.387409 |
| Rust-Ed | Ed301-v2 | sign | 29.191607 | 0.401581 | 28.458279 | 29.855386 |
| Rust-Ed | Ed301-v1 | verify | 86.925736 | 0.998552 | 84.990514 | 88.289680 |
| Rust-Ed | Ed301-v2 | verify | 85.145214 | 4.512802 | 83.959970 | 96.986894 |
| Rust-Ed | Ed301-v1 | import | 99.561405 | 2.011628 | 96.643191 | 103.216759 |
| Rust-Ed | Ed301-v2 | import | 50.779526 | 0.997314 | 49.467148 | 52.722813 |
| Rust-X | X301-v1 | public | 27.942615 | 0.806459 | 27.207981 | 29.886780 |
| Rust-X | X301-v2 | public | 28.766837 | 1.286506 | 27.024551 | 31.191777 |
| Rust-X | X301-v1 | shared | 58.000873 | 1.574650 | 56.389217 | 61.826372 |
| Rust-X | X301-v2 | shared | 58.604700 | 10.295865 | 57.376525 | 89.285402 |
| Rust-X | X301-v1 | validate-public | 0.004456 | 0.000735 | 0.003689 | 0.006253 |
| Rust-X | X301-v2 | validate-public | 0.001323 | 0.000183 | 0.001097 | 0.001722 |
| Rust-X | X301-v1 | canonical-public | 0.008131 | 0.001053 | 0.007423 | 0.010007 |
| Rust-X | X301-v2 | canonical-public | 0.003204 | 0.000202 | 0.002909 | 0.003555 |
| Rust-X | X301-v2 | import-secret | 0.032615 | 0.003153 | 0.031078 | 0.041237 |
| Rust-X | X301-v2 | import-public | 0.005354 | 0.000418 | 0.004671 | 0.005854 |
| Rust-X | X301-v2 | prepared-public | 27.774355 | 3.938443 | 26.955603 | 39.276697 |
| Rust-X | X301-v2 | prepared-shared | 58.769444 | 1.738622 | 57.375739 | 62.338767 |
| EVP-signature | Ed25519 | keygen | 24.963800 | 1.376191 | 24.317400 | 28.691900 |
| EVP-signature | Ed448 | keygen | 149.429600 | 20.748640 | 144.849400 | 210.201500 |
| EVP-signature | Ed301-v1 | keygen | 56.966400 | 6.811713 | 56.043100 | 75.909100 |
| EVP-signature | Ed301-v2 | keygen | 29.967500 | 2.203176 | 29.353200 | 36.393800 |
| EVP-signature | Ed25519 | sign | 23.947800 | 2.185330 | 23.625100 | 30.497100 |
| EVP-signature | Ed448 | sign | 148.747900 | 25.569537 | 146.340900 | 225.373800 |
| EVP-signature | Ed301-v1 | sign | 29.880400 | 6.382213 | 29.273900 | 48.972500 |
| EVP-signature | Ed301-v2 | sign | 29.925400 | 3.866447 | 29.228000 | 40.125000 |
| EVP-signature | Ed25519 | verify | 78.378700 | 8.569295 | 77.676600 | 103.984000 |
| EVP-signature | Ed448 | verify | 157.535600 | 11.677673 | 155.380200 | 192.430500 |
| EVP-signature | Ed301-v1 | verify | 87.186400 | 3.679301 | 84.996200 | 97.609100 |
| EVP-signature | Ed301-v2 | verify | 83.612500 | 3.774572 | 81.935400 | 93.898700 |
| EVP-XDH | X25519 | keygen | 23.942700 | 0.555247 | 23.594900 | 25.225300 |
| EVP-XDH | X448 | keygen | 147.212200 | 9.826710 | 143.898300 | 174.767000 |
| EVP-XDH | X301-v1 | keygen | 29.673800 | 0.186292 | 29.290500 | 29.883600 |
| EVP-XDH | X301-v2 | keygen | 29.481300 | 2.223848 | 28.800700 | 35.394200 |
| EVP-XDH | X25519 | derive-setup | 1.253600 | 0.012270 | 1.242600 | 1.276500 |
| EVP-XDH | X448 | derive-setup | 1.239000 | 0.013013 | 1.218900 | 1.257000 |
| EVP-XDH | X301-v1 | derive-setup | 1.729100 | 0.028388 | 1.697900 | 1.784300 |
| EVP-XDH | X301-v2 | derive-setup | 1.812200 | 0.042453 | 1.778200 | 1.915300 |
| EVP-XDH | X25519 | derive-first | 23.786300 | 0.334005 | 23.526100 | 24.656300 |
| EVP-XDH | X448 | derive-first | 120.575300 | 2.154691 | 118.545500 | 125.254400 |
| EVP-XDH | X301-v1 | derive-first | 57.514000 | 0.928700 | 56.622400 | 59.727700 |
| EVP-XDH | X301-v2 | derive-first | 58.197100 | 0.588355 | 57.097500 | 59.149000 |
| EVP-XDH | X25519 | derive-second | 23.783500 | 0.357331 | 23.389100 | 24.406200 |
| EVP-XDH | X448 | derive-second | 121.096500 | 2.493384 | 118.355300 | 127.310900 |
| EVP-XDH | X301-v1 | derive-second | 57.518100 | 0.640704 | 56.605400 | 58.505200 |
| EVP-XDH | X301-v2 | derive-second | 58.006200 | 0.623520 | 57.144400 | 58.819800 |
| EVP-XDH | X25519 | derive-steady | 23.879400 | 0.658317 | 23.732900 | 25.791600 |
| EVP-XDH | X448 | derive-steady | 120.310700 | 2.188085 | 118.407400 | 124.498500 |
| EVP-XDH | X301-v1 | derive-steady | 57.389600 | 1.429958 | 56.363000 | 60.972300 |
| EVP-XDH | X301-v2 | derive-steady | 58.145700 | 0.613226 | 57.447900 | 59.692800 |
| EVP-KEM | ML-KEM-1024 | kem-keygen | 38.316800 | 0.459087 | 38.029400 | 39.310600 |
| EVP-KEM | Hybrid-v1 | kem-keygen | 68.554100 | 0.999182 | 66.771700 | 69.377800 |
| EVP-KEM | Hybrid-v2 | kem-keygen | 67.919300 | 4.119507 | 66.853100 | 80.117100 |
| EVP-KEM | ML-KEM-1024 | encaps | 20.323500 | 0.672461 | 20.004700 | 22.216800 |
| EVP-KEM | Hybrid-v1 | encaps | 107.191800 | 1.908284 | 105.521000 | 111.075300 |
| EVP-KEM | Hybrid-v2 | encaps | 107.664700 | 2.100160 | 105.625400 | 111.202600 |
| EVP-KEM | ML-KEM-1024 | decaps | 30.416200 | 0.355907 | 29.735500 | 30.728100 |
| EVP-KEM | Hybrid-v1 | decaps | 88.768900 | 0.728475 | 87.302900 | 89.368400 |
| EVP-KEM | Hybrid-v2 | decaps | 88.951800 | 1.483254 | 87.684600 | 92.863100 |
| EVP-codec | Ed25519 | encode-private-DER | 7.994627 | 0.404650 | 7.632930 | 9.018308 |
| EVP-codec | Ed448 | encode-private-DER | 7.965320 | 0.631854 | 7.685105 | 9.778608 |
| EVP-codec | Ed301-v1 | encode-private-DER | 40.139597 | 1.454189 | 39.131903 | 43.871277 |
| EVP-codec | Ed301-v2 | encode-private-DER | 55.128923 | 1.607947 | 54.421971 | 59.709010 |
| EVP-codec | X25519 | encode-private-DER | 8.014916 | 0.169627 | 7.920700 | 8.402405 |
| EVP-codec | X448 | encode-private-DER | 7.982866 | 0.110983 | 7.890388 | 8.228600 |
| EVP-codec | X301-v2 | encode-private-DER | 54.386953 | 1.082023 | 52.913427 | 56.244329 |
| EVP-codec | Ed25519 | decode-private-DER | 27.672849 | 1.192754 | 27.239439 | 31.097655 |
| EVP-codec | Ed448 | decode-private-DER | 150.462439 | 1.380141 | 149.353152 | 153.621288 |
| EVP-codec | Ed301-v1 | decode-private-DER | 59.547854 | 0.734564 | 58.801841 | 60.683344 |
| EVP-codec | Ed301-v2 | decode-private-DER | 32.400053 | 0.557505 | 31.943600 | 33.546595 |
| EVP-codec | X25519 | decode-private-DER | 27.420021 | 0.306977 | 26.834780 | 27.652538 |
| EVP-codec | X448 | decode-private-DER | 149.129919 | 2.485409 | 147.792452 | 155.308702 |
| EVP-codec | X301-v2 | decode-private-DER | 32.445795 | 5.401496 | 31.677783 | 48.463370 |
| EVP-codec | Ed25519 | encode-public-DER | 7.450675 | 0.258914 | 7.053845 | 7.855251 |
| EVP-codec | Ed448 | encode-public-DER | 7.341909 | 0.124464 | 7.028310 | 7.444936 |
| EVP-codec | Ed301-v1 | encode-public-DER | 39.412516 | 0.772306 | 38.658889 | 40.965370 |
| EVP-codec | Ed301-v2 | encode-public-DER | 54.807752 | 0.688853 | 53.944571 | 56.141222 |
| EVP-codec | X25519 | encode-public-DER | 7.404050 | 0.276959 | 7.055398 | 7.840539 |
| EVP-codec | X448 | encode-public-DER | 7.350639 | 0.170149 | 7.205045 | 7.712685 |
| EVP-codec | X301-v2 | encode-public-DER | 53.977196 | 0.973025 | 52.450591 | 55.342106 |
| EVP-codec | Ed25519 | decode-public-DER | 5.414881 | 0.070148 | 5.258134 | 5.494957 |
| EVP-codec | Ed448 | decode-public-DER | 5.368746 | 0.032408 | 5.328972 | 5.411170 |
| EVP-codec | Ed301-v1 | decode-public-DER | 103.770931 | 9.234872 | 102.244514 | 131.139567 |
| EVP-codec | Ed301-v2 | decode-public-DER | 29.415680 | 0.465755 | 28.696639 | 30.026447 |
| EVP-codec | X25519 | decode-public-DER | 5.336465 | 0.611908 | 5.280597 | 7.166078 |
| EVP-codec | X448 | decode-public-DER | 5.415554 | 1.213143 | 5.303835 | 9.039238 |
| EVP-codec | X301-v2 | decode-public-DER | 5.414366 | 0.669277 | 5.320414 | 7.395064 |
| EVP-codec | Ed25519 | encode-private-PEM | 10.463781 | 0.229866 | 10.283541 | 11.016864 |
| EVP-codec | Ed448 | encode-private-PEM | 10.547495 | 0.165672 | 10.219411 | 10.808389 |
| EVP-codec | Ed301-v1 | encode-private-PEM | 42.569646 | 0.661034 | 41.604521 | 43.635658 |
| EVP-codec | Ed301-v2 | encode-private-PEM | 58.601706 | 3.413655 | 57.052383 | 68.118292 |
| EVP-codec | X25519 | encode-private-PEM | 10.618938 | 0.246160 | 10.123802 | 10.928506 |
| EVP-codec | X448 | encode-private-PEM | 10.565784 | 0.186466 | 10.400891 | 10.918501 |
| EVP-codec | X301-v2 | encode-private-PEM | 56.869948 | 5.207714 | 55.700127 | 72.200918 |
| EVP-codec | Ed25519 | decode-private-PEM | 28.249452 | 0.563486 | 27.733466 | 29.701568 |
| EVP-codec | Ed448 | decode-private-PEM | 151.450793 | 2.164219 | 149.064366 | 155.806555 |
| EVP-codec | Ed301-v1 | decode-private-PEM | 60.446106 | 3.722240 | 59.088851 | 71.040430 |
| EVP-codec | Ed301-v2 | decode-private-PEM | 32.825312 | 2.227450 | 32.415853 | 39.463463 |
| EVP-codec | X25519 | decode-private-PEM | 27.632099 | 0.257173 | 27.295770 | 28.086379 |
| EVP-codec | X448 | decode-private-PEM | 149.668934 | 1.437128 | 146.691253 | 150.879648 |
| EVP-codec | X301-v2 | decode-private-PEM | 33.060150 | 0.460907 | 32.299700 | 33.681345 |
| EVP-codec | Ed25519 | encode-encrypted-PEM | 247.465908 | 4.785394 | 243.853312 | 258.550072 |
| EVP-codec | Ed448 | encode-encrypted-PEM | 248.027322 | 2.927421 | 241.581164 | 250.163600 |
| EVP-codec | Ed301-v1 | encode-encrypted-PEM | 281.651185 | 3.829657 | 275.193717 | 286.570031 |
| EVP-codec | Ed301-v2 | encode-encrypted-PEM | 315.796381 | 7.422900 | 307.757291 | 333.475112 |
| EVP-codec | X25519 | encode-encrypted-PEM | 249.511182 | 4.057392 | 245.746343 | 258.386368 |
| EVP-codec | X448 | encode-encrypted-PEM | 265.154781 | 4.382144 | 261.570455 | 272.768024 |
| EVP-codec | X301-v2 | encode-encrypted-PEM | 296.691584 | 4.753577 | 291.302276 | 307.543563 |
| EVP-codec | Ed25519 | decode-encrypted-PEM | 264.700727 | 3.595102 | 260.042551 | 271.433106 |
| EVP-codec | Ed448 | decode-encrypted-PEM | 391.013650 | 8.748596 | 381.615157 | 409.556760 |
| EVP-codec | Ed301-v1 | decode-encrypted-PEM | 292.578289 | 8.591764 | 288.875771 | 315.064048 |
| EVP-codec | Ed301-v2 | decode-encrypted-PEM | 267.675153 | 10.873940 | 263.113413 | 297.878777 |
| EVP-codec | X25519 | decode-encrypted-PEM | 262.249088 | 2.841327 | 260.377466 | 269.860565 |
| EVP-codec | X448 | decode-encrypted-PEM | 386.493066 | 4.474913 | 382.543880 | 395.913536 |
| EVP-codec | X301-v2 | decode-encrypted-PEM | 266.820936 | 5.344780 | 262.208719 | 278.629186 |
| TLS-engine | Ed25519-X25519 | full-handshake-warm-context | 375.931358 | 3.489398 | 372.000723 | 381.896298 |
| TLS-engine | Ed448-X25519 | full-handshake-warm-context | 583.106684 | 7.474556 | 575.271098 | 596.562431 |
| TLS-engine | Ed-v1-X25519 | full-handshake-warm-context | 495.314325 | 6.689914 | 483.427478 | 505.967406 |
| TLS-engine | Ed-v2-X25519 | full-handshake-warm-context | 449.924432 | 8.082035 | 439.490570 | 459.864817 |
| TLS-engine | Ed-v1-Hybrid-v1 | full-handshake-warm-context | 710.474647 | 15.825241 | 698.480356 | 743.307730 |
| TLS-engine | Ed-v2-Hybrid-v2 | full-handshake-warm-context | 659.030675 | 9.189038 | 646.964705 | 672.511848 |
| TLS-engine | Ed-v2-Raw-v2 | full-handshake-warm-context | 534.454651 | 7.205840 | 523.791427 | 546.460839 |
| TLS-engine | ECDSA-X25519 | full-handshake-warm-context | 360.243610 | 15.133033 | 354.423246 | 402.087504 |
| TLS-engine | ECDSA-Hybrid-v1 | full-handshake-warm-context | 577.158679 | 13.618669 | 561.797970 | 609.234006 |
| TLS-engine | ECDSA-Hybrid-v2 | full-handshake-warm-context | 574.629226 | 25.607737 | 567.099274 | 649.234611 |
| TLS-engine | ECDSA-Raw-v2 | full-handshake-warm-context | 451.982484 | 26.005139 | 438.506805 | 523.877350 |

## Vollständiger ABI-Lauf 4.0.2

Receipt: `/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e8_final_01_2026-09-10/benchmarks-4.0.2`.

SHA-256 des Receipt-Manifests: `f2d9c3598a18a5fa186340c737e03a16d351100818e769b68db4f87002c1d1ce`.

| Schicht | Verfahren | Operation | Median µs | SD µs | Min µs | Max µs |
| --- | --- | --- | --- | --- | --- | --- |
| Rust-Ed | Ed301-v1 | expand | 28.102253 | 0.254022 | 27.825894 | 28.705881 |
| Rust-Ed | Ed301-v2 | expand | 28.723231 | 0.975217 | 27.923552 | 30.637543 |
| Rust-Ed | Ed301-v1 | sign | 29.281941 | 0.553543 | 28.660299 | 30.204808 |
| Rust-Ed | Ed301-v2 | sign | 29.175429 | 0.145551 | 28.856030 | 29.317435 |
| Rust-Ed | Ed301-v1 | verify | 86.607092 | 1.687580 | 85.418841 | 91.152383 |
| Rust-Ed | Ed301-v2 | verify | 83.461143 | 1.279639 | 82.213708 | 86.726003 |
| Rust-Ed | Ed301-v1 | import | 98.228798 | 5.304513 | 96.780901 | 114.064996 |
| Rust-Ed | Ed301-v2 | import | 51.024464 | 0.684558 | 49.735502 | 52.071014 |
| Rust-X | X301-v1 | public | 27.889040 | 0.402617 | 27.577689 | 28.778447 |
| Rust-X | X301-v2 | public | 27.678694 | 0.394961 | 27.480224 | 28.736298 |
| Rust-X | X301-v1 | shared | 57.406325 | 0.584425 | 57.251001 | 58.859374 |
| Rust-X | X301-v2 | shared | 58.523505 | 0.720841 | 57.486730 | 59.755152 |
| Rust-X | X301-v1 | validate-public | 0.004545 | 0.000427 | 0.003663 | 0.005195 |
| Rust-X | X301-v2 | validate-public | 0.001321 | 0.000116 | 0.001028 | 0.001341 |
| Rust-X | X301-v1 | canonical-public | 0.007970 | 0.000523 | 0.007419 | 0.008963 |
| Rust-X | X301-v2 | canonical-public | 0.003239 | 0.000315 | 0.003106 | 0.003931 |
| Rust-X | X301-v2 | import-secret | 0.032360 | 0.000867 | 0.031574 | 0.034218 |
| Rust-X | X301-v2 | import-public | 0.005941 | 0.001007 | 0.005583 | 0.008243 |
| Rust-X | X301-v2 | prepared-public | 27.726841 | 0.421198 | 27.365501 | 28.672075 |
| Rust-X | X301-v2 | prepared-shared | 58.397459 | 0.450825 | 57.546136 | 59.071742 |
| EVP-signature | Ed25519 | keygen | 24.580800 | 0.642054 | 24.386200 | 26.128600 |
| EVP-signature | Ed448 | keygen | 147.847300 | 19.848084 | 145.364600 | 207.219600 |
| EVP-signature | Ed301-v1 | keygen | 57.306000 | 0.798225 | 56.917300 | 59.000800 |
| EVP-signature | Ed301-v2 | keygen | 30.514000 | 2.003446 | 30.043700 | 36.235000 |
| EVP-signature | Ed25519 | sign | 24.037900 | 0.349751 | 23.667900 | 24.780200 |
| EVP-signature | Ed448 | sign | 148.630400 | 1.803487 | 145.677600 | 152.036400 |
| EVP-signature | Ed301-v1 | sign | 29.973400 | 1.991169 | 29.573400 | 35.774300 |
| EVP-signature | Ed301-v2 | sign | 30.043700 | 2.723883 | 29.554000 | 38.112100 |
| EVP-signature | Ed25519 | verify | 78.921000 | 1.027589 | 77.628000 | 81.173000 |
| EVP-signature | Ed448 | verify | 156.644200 | 1.377879 | 155.212200 | 159.067700 |
| EVP-signature | Ed301-v1 | verify | 87.618300 | 1.595353 | 85.295700 | 89.997000 |
| EVP-signature | Ed301-v2 | verify | 84.965000 | 1.864389 | 82.788900 | 89.156300 |
| EVP-XDH | X25519 | keygen | 24.358800 | 0.434399 | 23.917500 | 25.114900 |
| EVP-XDH | X448 | keygen | 146.737900 | 1.944592 | 144.908700 | 151.444200 |
| EVP-XDH | X301-v1 | keygen | 30.043500 | 0.458731 | 29.120200 | 30.521800 |
| EVP-XDH | X301-v2 | keygen | 29.505300 | 0.791423 | 29.196700 | 31.569400 |
| EVP-XDH | X25519 | derive-setup | 1.071300 | 0.053862 | 1.050900 | 1.224500 |
| EVP-XDH | X448 | derive-setup | 1.045800 | 0.064934 | 1.027600 | 1.234600 |
| EVP-XDH | X301-v1 | derive-setup | 1.616800 | 0.116157 | 1.531300 | 1.928700 |
| EVP-XDH | X301-v2 | derive-setup | 1.718600 | 0.126351 | 1.658800 | 2.074600 |
| EVP-XDH | X25519 | derive-first | 24.040000 | 1.003096 | 23.383900 | 26.863400 |
| EVP-XDH | X448 | derive-first | 122.581700 | 13.949670 | 119.324800 | 163.610500 |
| EVP-XDH | X301-v1 | derive-first | 58.101800 | 0.843066 | 56.762300 | 59.319500 |
| EVP-XDH | X301-v2 | derive-first | 58.023600 | 0.739069 | 57.254200 | 59.789400 |
| EVP-XDH | X25519 | derive-second | 24.023900 | 0.700395 | 23.685000 | 25.836500 |
| EVP-XDH | X448 | derive-second | 121.591500 | 1.166886 | 118.951400 | 122.708100 |
| EVP-XDH | X301-v1 | derive-second | 57.396800 | 1.101383 | 56.575400 | 60.135100 |
| EVP-XDH | X301-v2 | derive-second | 58.681300 | 0.838030 | 57.250800 | 59.877600 |
| EVP-XDH | X25519 | derive-steady | 23.888600 | 0.439041 | 23.463400 | 24.845900 |
| EVP-XDH | X448 | derive-steady | 120.748200 | 6.544970 | 118.711400 | 140.009000 |
| EVP-XDH | X301-v1 | derive-steady | 57.758900 | 0.887716 | 56.943800 | 59.444100 |
| EVP-XDH | X301-v2 | derive-steady | 58.464300 | 1.251685 | 57.405800 | 61.020600 |
| EVP-KEM | ML-KEM-1024 | kem-keygen | 38.131600 | 1.458780 | 37.843300 | 42.495200 |
| EVP-KEM | Hybrid-v1 | kem-keygen | 68.839100 | 1.683774 | 67.482800 | 73.064600 |
| EVP-KEM | Hybrid-v2 | kem-keygen | 68.515500 | 2.443864 | 66.374800 | 74.458100 |
| EVP-KEM | ML-KEM-1024 | encaps | 20.187300 | 0.284667 | 19.653500 | 20.699100 |
| EVP-KEM | Hybrid-v1 | encaps | 107.202400 | 3.550328 | 105.526100 | 115.637600 |
| EVP-KEM | Hybrid-v2 | encaps | 107.083400 | 1.904994 | 105.858300 | 111.606200 |
| EVP-KEM | ML-KEM-1024 | decaps | 30.160400 | 0.452317 | 29.793900 | 31.041000 |
| EVP-KEM | Hybrid-v1 | decaps | 87.911500 | 1.345801 | 86.741800 | 91.016600 |
| EVP-KEM | Hybrid-v2 | decaps | 89.201000 | 1.209488 | 87.462000 | 91.397100 |
| EVP-codec | Ed25519 | encode-private-DER | 8.781370 | 0.202610 | 8.437824 | 9.040849 |
| EVP-codec | Ed448 | encode-private-DER | 8.790320 | 0.184620 | 8.723597 | 9.186917 |
| EVP-codec | Ed301-v1 | encode-private-DER | 23.688579 | 0.410373 | 22.884814 | 24.171126 |
| EVP-codec | Ed301-v2 | encode-private-DER | 32.413387 | 0.287741 | 31.975876 | 32.868164 |
| EVP-codec | X25519 | encode-private-DER | 8.936244 | 0.152615 | 8.687069 | 9.093434 |
| EVP-codec | X448 | encode-private-DER | 8.862769 | 0.162962 | 8.610841 | 9.063635 |
| EVP-codec | X301-v2 | encode-private-DER | 27.798358 | 0.444699 | 26.944491 | 28.575453 |
| EVP-codec | Ed25519 | decode-private-DER | 27.493357 | 1.032799 | 26.688347 | 29.979006 |
| EVP-codec | Ed448 | decode-private-DER | 152.184557 | 3.872274 | 147.285002 | 160.000199 |
| EVP-codec | Ed301-v1 | decode-private-DER | 59.053561 | 0.729701 | 58.724431 | 61.109828 |
| EVP-codec | Ed301-v2 | decode-private-DER | 32.989365 | 2.797313 | 31.924401 | 39.200507 |
| EVP-codec | X25519 | decode-private-DER | 26.920041 | 1.325910 | 26.457914 | 30.778495 |
| EVP-codec | X448 | decode-private-DER | 149.086695 | 2.000924 | 147.089815 | 153.394555 |
| EVP-codec | X301-v2 | decode-private-DER | 32.086112 | 0.558644 | 31.797053 | 33.571454 |
| EVP-codec | Ed25519 | encode-public-DER | 8.322438 | 0.328163 | 7.942693 | 8.948933 |
| EVP-codec | Ed448 | encode-public-DER | 8.303068 | 0.159103 | 8.101478 | 8.650622 |
| EVP-codec | Ed301-v1 | encode-public-DER | 23.362087 | 0.422284 | 22.848180 | 24.182655 |
| EVP-codec | Ed301-v2 | encode-public-DER | 31.971161 | 0.589130 | 31.580359 | 33.542401 |
| EVP-codec | X25519 | encode-public-DER | 8.313429 | 0.275171 | 8.108819 | 8.869270 |
| EVP-codec | X448 | encode-public-DER | 8.163323 | 0.180087 | 8.058364 | 8.661538 |
| EVP-codec | X301-v2 | encode-public-DER | 27.414670 | 2.424782 | 26.683363 | 33.789090 |
| EVP-codec | Ed25519 | decode-public-DER | 5.059868 | 0.123074 | 4.984965 | 5.396463 |
| EVP-codec | Ed448 | decode-public-DER | 5.052319 | 0.343432 | 4.943686 | 6.043397 |
| EVP-codec | Ed301-v1 | decode-public-DER | 103.299589 | 1.942532 | 101.335475 | 106.826773 |
| EVP-codec | Ed301-v2 | decode-public-DER | 29.329689 | 0.377385 | 28.495925 | 29.678275 |
| EVP-codec | X25519 | decode-public-DER | 5.005589 | 0.135796 | 4.945409 | 5.368200 |
| EVP-codec | X448 | decode-public-DER | 5.058646 | 0.037724 | 4.984749 | 5.091264 |
| EVP-codec | X301-v2 | decode-public-DER | 5.024486 | 0.376365 | 4.873072 | 6.101897 |
| EVP-codec | Ed25519 | encode-private-PEM | 9.568921 | 0.541833 | 9.213802 | 11.130611 |
| EVP-codec | Ed448 | encode-private-PEM | 9.684339 | 0.174082 | 9.595831 | 10.049034 |
| EVP-codec | Ed301-v1 | encode-private-PEM | 24.782222 | 0.666596 | 24.031118 | 26.082156 |
| EVP-codec | Ed301-v2 | encode-private-PEM | 33.464758 | 2.295283 | 33.219301 | 40.362071 |
| EVP-codec | X25519 | encode-private-PEM | 9.537313 | 0.241263 | 9.277135 | 9.970039 |
| EVP-codec | X448 | encode-private-PEM | 9.605479 | 0.182065 | 9.274739 | 9.844114 |
| EVP-codec | X301-v2 | encode-private-PEM | 28.650853 | 0.547103 | 27.995731 | 29.510983 |
| EVP-codec | Ed25519 | decode-private-PEM | 28.058514 | 0.469983 | 27.162597 | 28.784389 |
| EVP-codec | Ed448 | decode-private-PEM | 151.561562 | 1.992505 | 148.471369 | 154.954197 |
| EVP-codec | Ed301-v1 | decode-private-PEM | 59.381108 | 0.871714 | 58.639799 | 61.787260 |
| EVP-codec | Ed301-v2 | decode-private-PEM | 32.622072 | 0.484952 | 31.948361 | 33.537286 |
| EVP-codec | X25519 | decode-private-PEM | 27.355756 | 0.612459 | 26.948207 | 28.976308 |
| EVP-codec | X448 | decode-private-PEM | 149.890490 | 1.793234 | 148.012426 | 153.519668 |
| EVP-codec | X301-v2 | decode-private-PEM | 32.599102 | 0.677590 | 31.918977 | 33.786738 |
| EVP-codec | Ed25519 | encode-encrypted-PEM | 243.834106 | 29.868122 | 237.130999 | 327.754368 |
| EVP-codec | Ed448 | encode-encrypted-PEM | 240.672259 | 3.558566 | 235.630852 | 248.373893 |
| EVP-codec | Ed301-v1 | encode-encrypted-PEM | 257.037055 | 2.887284 | 252.985747 | 261.977129 |
| EVP-codec | Ed301-v2 | encode-encrypted-PEM | 281.287933 | 4.299576 | 277.054857 | 289.558624 |
| EVP-codec | X25519 | encode-encrypted-PEM | 238.403000 | 3.653096 | 235.955848 | 247.670608 |
| EVP-codec | X448 | encode-encrypted-PEM | 239.266492 | 3.581304 | 236.364708 | 246.891027 |
| EVP-codec | X301-v2 | encode-encrypted-PEM | 260.665706 | 2.885594 | 257.588261 | 266.745992 |
| EVP-codec | Ed25519 | decode-encrypted-PEM | 253.309864 | 2.152927 | 250.004824 | 256.801182 |
| EVP-codec | Ed448 | decode-encrypted-PEM | 378.537584 | 6.495585 | 371.525549 | 394.525506 |
| EVP-codec | Ed301-v1 | decode-encrypted-PEM | 285.683014 | 6.774839 | 282.076164 | 304.644919 |
| EVP-codec | Ed301-v2 | decode-encrypted-PEM | 275.812658 | 6.004272 | 270.761445 | 290.197121 |
| EVP-codec | X25519 | decode-encrypted-PEM | 251.316113 | 4.105051 | 246.264194 | 259.784062 |
| EVP-codec | X448 | decode-encrypted-PEM | 371.481796 | 3.544534 | 365.265380 | 376.246592 |
| EVP-codec | X301-v2 | decode-encrypted-PEM | 258.741924 | 5.539703 | 253.170467 | 268.183212 |
| TLS-engine | Ed25519-X25519 | full-handshake-warm-context | 375.003495 | 8.390868 | 362.077925 | 388.544197 |
| TLS-engine | Ed448-X25519 | full-handshake-warm-context | 576.001194 | 13.845344 | 565.011556 | 603.809983 |
| TLS-engine | Ed-v1-X25519 | full-handshake-warm-context | 493.929913 | 18.876069 | 481.661692 | 543.638106 |
| TLS-engine | Ed-v2-X25519 | full-handshake-warm-context | 441.077822 | 10.402696 | 426.345274 | 455.708697 |
| TLS-engine | Ed-v1-Hybrid-v1 | full-handshake-warm-context | 696.461293 | 13.372030 | 688.197830 | 730.091985 |
| TLS-engine | Ed-v2-Hybrid-v2 | full-handshake-warm-context | 650.327751 | 13.798565 | 641.525538 | 685.707538 |
| TLS-engine | Ed-v2-Raw-v2 | full-handshake-warm-context | 521.362561 | 6.567478 | 510.534423 | 531.440337 |
| TLS-engine | ECDSA-X25519 | full-handshake-warm-context | 351.614583 | 5.300135 | 346.805940 | 365.106439 |
| TLS-engine | ECDSA-Hybrid-v1 | full-handshake-warm-context | 570.911896 | 15.276986 | 561.349832 | 609.235295 |
| TLS-engine | ECDSA-Hybrid-v2 | full-handshake-warm-context | 565.718217 | 12.877732 | 556.771559 | 597.711142 |
| TLS-engine | ECDSA-Raw-v2 | full-handshake-warm-context | 438.654086 | 7.119790 | 433.112166 | 457.179688 |

## Erweiterte Nachrichten-/Context-Matrix

Receipt: `/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e8_final_01_2026-09-10/ED301-v2_core-matrix_ug_inbwh`.

SHA-256: `a6597c686b4cdeed71e968815d82423c0facd502d9a41579eef4319b966f8cb2`.

cold-sign enthält Seedimport und Expansion; prepared-sign/prepared-verify verwenden vorbereitete Schlüssel. import-verify enthält die erneute Public-Key-Prüfung. Nachricht i=(29i+7) mod 256, Context i=(17i+3) mod 256. Kalt bezeichnet den Schlüssel-Lifecycle, keinen geleerten CPU-Cache.

| Version | Operation | Nachricht Byte | Context Byte | Median µs | SD µs | Min µs | Max µs |
| --- | --- | --- | --- | --- | --- | --- | --- |
| v1 | cold-sign | 0 | 0 | 56.526946 | 0.739261 | 55.887808 | 58.263010 |
| v2 | cold-sign | 0 | 0 | 58.204064 | 2.652799 | 56.126761 | 64.634417 |
| v1 | prepared-sign | 0 | 0 | 28.788794 | 0.675253 | 28.290653 | 30.403004 |
| v2 | prepared-sign | 0 | 0 | 28.900285 | 1.054012 | 28.473543 | 31.838733 |
| v1 | prepared-verify | 0 | 0 | 86.565031 | 1.634002 | 85.232237 | 89.857323 |
| v2 | prepared-verify | 0 | 0 | 83.128015 | 2.232718 | 82.131476 | 89.554380 |
| v1 | import-verify | 0 | 0 | 184.318410 | 4.213560 | 181.402000 | 192.645007 |
| v2 | import-verify | 0 | 0 | 134.156922 | 2.622997 | 132.228224 | 139.839430 |
| v1 | cold-sign | 0 | 16 | 56.983815 | 2.732802 | 56.291735 | 64.091971 |
| v2 | cold-sign | 0 | 16 | 56.926676 | 2.196822 | 56.286603 | 63.421285 |
| v1 | prepared-sign | 0 | 16 | 28.691552 | 0.383810 | 28.380821 | 29.530016 |
| v2 | prepared-sign | 0 | 16 | 28.609266 | 1.211934 | 28.217827 | 31.698881 |
| v1 | prepared-verify | 0 | 16 | 85.420172 | 1.365013 | 84.195030 | 88.838808 |
| v2 | prepared-verify | 0 | 16 | 84.050608 | 2.125613 | 82.744304 | 89.251075 |
| v1 | import-verify | 0 | 16 | 182.513590 | 4.121633 | 180.129377 | 194.148889 |
| v2 | import-verify | 0 | 16 | 134.681184 | 3.520472 | 132.138392 | 143.939245 |
| v1 | cold-sign | 0 | 255 | 57.838393 | 0.779118 | 57.513319 | 59.980515 |
| v2 | cold-sign | 0 | 255 | 57.724489 | 2.533942 | 57.137949 | 65.246164 |
| v1 | prepared-sign | 0 | 255 | 29.747494 | 0.646322 | 29.271649 | 31.475276 |
| v2 | prepared-sign | 0 | 255 | 29.757362 | 0.614109 | 29.360348 | 31.491949 |
| v1 | prepared-verify | 0 | 255 | 87.856733 | 2.831341 | 85.259477 | 93.073481 |
| v2 | prepared-verify | 0 | 255 | 83.229068 | 2.056260 | 81.994418 | 87.880082 |
| v1 | import-verify | 0 | 255 | 185.146259 | 3.245113 | 182.026118 | 192.980930 |
| v2 | import-verify | 0 | 255 | 134.917307 | 3.555589 | 131.727202 | 142.681304 |
| v1 | cold-sign | 64 | 0 | 57.946553 | 2.649459 | 56.553067 | 64.959300 |
| v2 | cold-sign | 64 | 0 | 57.159440 | 2.818622 | 56.823649 | 65.067868 |
| v1 | prepared-sign | 64 | 0 | 29.125157 | 0.321695 | 28.884398 | 29.843401 |
| v2 | prepared-sign | 64 | 0 | 29.074846 | 1.027461 | 28.804013 | 32.036278 |
| v1 | prepared-verify | 64 | 0 | 85.681187 | 2.808663 | 84.122203 | 92.240331 |
| v2 | prepared-verify | 64 | 0 | 84.518840 | 16.926986 | 83.803585 | 135.385676 |
| v1 | import-verify | 64 | 0 | 183.427916 | 7.111806 | 180.570696 | 204.015195 |
| v2 | import-verify | 64 | 0 | 134.878255 | 1.297986 | 132.750360 | 137.015324 |
| v1 | cold-sign | 64 | 16 | 57.137195 | 0.720143 | 56.082058 | 58.486577 |
| v2 | cold-sign | 64 | 16 | 57.065161 | 2.485342 | 56.377188 | 64.086579 |
| v1 | prepared-sign | 64 | 16 | 28.809337 | 0.229339 | 28.404937 | 29.094827 |
| v2 | prepared-sign | 64 | 16 | 29.027091 | 0.791865 | 28.711596 | 30.849506 |
| v1 | prepared-verify | 64 | 16 | 85.232227 | 6.412432 | 84.409872 | 104.303318 |
| v2 | prepared-verify | 64 | 16 | 82.157903 | 4.386809 | 81.603127 | 95.238755 |
| v1 | import-verify | 64 | 16 | 182.647462 | 4.181237 | 181.065218 | 192.906216 |
| v2 | import-verify | 64 | 16 | 138.744093 | 3.545766 | 132.333131 | 142.300570 |
| v1 | cold-sign | 64 | 255 | 57.971380 | 1.685144 | 57.350691 | 62.081440 |
| v2 | cold-sign | 64 | 255 | 58.451261 | 1.913618 | 57.458085 | 63.482231 |
| v1 | prepared-sign | 64 | 255 | 30.386262 | 0.534405 | 29.687106 | 31.184307 |
| v2 | prepared-sign | 64 | 255 | 30.075948 | 0.777220 | 29.831150 | 32.348114 |
| v1 | prepared-verify | 64 | 255 | 87.112772 | 2.128326 | 86.077081 | 92.248837 |
| v2 | prepared-verify | 64 | 255 | 84.187758 | 1.631583 | 82.665295 | 86.790881 |
| v1 | import-verify | 64 | 255 | 185.797643 | 2.404655 | 182.562989 | 190.981013 |
| v2 | import-verify | 64 | 255 | 134.805358 | 4.481454 | 133.565586 | 147.352668 |
| v1 | cold-sign | 1024 | 0 | 62.447661 | 4.040293 | 59.806800 | 72.622546 |
| v2 | cold-sign | 1024 | 0 | 64.257719 | 3.584444 | 60.020754 | 69.528715 |
| v1 | prepared-sign | 1024 | 0 | 33.120085 | 1.602708 | 32.489729 | 37.531016 |
| v2 | prepared-sign | 1024 | 0 | 34.223057 | 3.302262 | 32.238259 | 40.854088 |
| v1 | prepared-verify | 1024 | 0 | 88.611832 | 4.135738 | 86.942367 | 99.654849 |
| v2 | prepared-verify | 1024 | 0 | 86.191839 | 2.711032 | 83.937980 | 92.197368 |
| v1 | import-verify | 1024 | 0 | 188.241353 | 3.569622 | 183.523509 | 194.164960 |
| v2 | import-verify | 1024 | 0 | 136.342674 | 3.446017 | 133.880160 | 144.795718 |
| v1 | cold-sign | 1024 | 16 | 61.004195 | 0.884649 | 59.688602 | 62.510170 |
| v2 | cold-sign | 1024 | 16 | 61.360830 | 2.175867 | 59.789994 | 65.517867 |
| v1 | prepared-sign | 1024 | 16 | 34.038812 | 1.071821 | 32.404515 | 35.784859 |
| v2 | prepared-sign | 1024 | 16 | 33.221957 | 1.145469 | 32.528864 | 35.905854 |
| v1 | prepared-verify | 1024 | 16 | 88.982693 | 3.505277 | 86.904938 | 97.924017 |
| v2 | prepared-verify | 1024 | 16 | 84.971121 | 2.122066 | 84.102669 | 89.553341 |
| v1 | import-verify | 1024 | 16 | 187.352415 | 3.071770 | 184.670943 | 193.007892 |
| v2 | import-verify | 1024 | 16 | 135.625311 | 1.762684 | 133.767273 | 140.194155 |
| v1 | cold-sign | 1024 | 255 | 61.432523 | 0.879069 | 61.212256 | 64.014533 |
| v2 | cold-sign | 1024 | 255 | 61.411249 | 1.068681 | 61.140088 | 64.524134 |
| v1 | prepared-sign | 1024 | 255 | 33.905411 | 0.845500 | 32.989626 | 35.725752 |
| v2 | prepared-sign | 1024 | 255 | 34.385397 | 0.824850 | 33.338642 | 36.108612 |
| v1 | prepared-verify | 1024 | 255 | 89.035227 | 1.691982 | 86.690508 | 92.118790 |
| v2 | prepared-verify | 1024 | 255 | 86.352287 | 2.563821 | 84.388244 | 92.490618 |
| v1 | import-verify | 1024 | 255 | 185.991456 | 2.677698 | 183.923077 | 191.280751 |
| v2 | import-verify | 1024 | 255 | 135.713846 | 3.076008 | 134.870382 | 143.868522 |
| v1 | cold-sign | 16384 | 0 | 120.051969 | 2.291718 | 118.253572 | 124.831628 |
| v2 | cold-sign | 16384 | 0 | 120.100000 | 3.444286 | 118.568648 | 129.274695 |
| v1 | prepared-sign | 16384 | 0 | 91.561379 | 1.583565 | 90.349271 | 95.010349 |
| v2 | prepared-sign | 16384 | 0 | 91.716452 | 1.762054 | 91.304665 | 96.469260 |
| v1 | prepared-verify | 16384 | 0 | 118.053195 | 4.153154 | 115.995682 | 127.154645 |
| v2 | prepared-verify | 16384 | 0 | 114.660069 | 3.515163 | 111.711765 | 122.216277 |
| v1 | import-verify | 16384 | 0 | 221.276565 | 5.409460 | 211.886285 | 227.499373 |
| v2 | import-verify | 16384 | 0 | 164.576828 | 7.801110 | 162.353899 | 183.879250 |
| v1 | cold-sign | 16384 | 16 | 120.393158 | 3.396987 | 117.947570 | 127.284966 |
| v2 | cold-sign | 16384 | 16 | 124.274040 | 5.246105 | 117.552758 | 132.897996 |
| v1 | prepared-sign | 16384 | 16 | 92.187628 | 2.305806 | 90.254658 | 97.420287 |
| v2 | prepared-sign | 16384 | 16 | 91.126182 | 2.044215 | 90.414828 | 97.026097 |
| v1 | prepared-verify | 16384 | 16 | 117.721585 | 2.731082 | 116.448382 | 123.685768 |
| v2 | prepared-verify | 16384 | 16 | 114.719160 | 3.564832 | 113.575918 | 124.847781 |
| v1 | import-verify | 16384 | 16 | 217.472218 | 3.751356 | 211.764270 | 222.838057 |
| v2 | import-verify | 16384 | 16 | 167.749313 | 3.269292 | 162.966748 | 172.312974 |
| v1 | cold-sign | 16384 | 255 | 122.220123 | 3.667306 | 120.149044 | 132.243435 |
| v2 | cold-sign | 16384 | 255 | 122.554322 | 1.657417 | 119.000444 | 123.885250 |
| v1 | prepared-sign | 16384 | 255 | 92.585165 | 3.566002 | 91.548623 | 100.798579 |
| v2 | prepared-sign | 16384 | 255 | 92.208675 | 1.175097 | 91.089610 | 95.052011 |
| v1 | prepared-verify | 16384 | 255 | 116.411734 | 2.893356 | 115.234764 | 123.952619 |
| v2 | prepared-verify | 16384 | 255 | 114.642410 | 1.128680 | 113.484534 | 116.961808 |
| v1 | import-verify | 16384 | 255 | 214.761019 | 2.749125 | 211.668878 | 218.961874 |
| v2 | import-verify | 16384 | 255 | 165.608590 | 3.973836 | 163.839798 | 174.335835 |
| v1 | prepare-verifier | 0 | 0 | 26.583419 | 0.498757 | 26.125077 | 27.518673 |
| v2 | prepare-verifier | 0 | 0 | 26.240196 | 0.828502 | 26.002116 | 28.370618 |

## Arithmetik-Mikrobenchmarks

Receipt: `/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e8_final_01_2026-09-10/ED301-v2_microbench_q5ji_gp5`.

SHA-256: `8cf30d22804955bf3957069863009dfd0d4745403358fd9eec7d73301ac95edf`.

Identischer privater Harness auf unveränderten Modulquellen, 16 rotierende Operanden und Kopierkontrolle. Loop, Operandenwahl, black_box und Ergebnis-Drop sind enthalten. Kein Produkt-API- oder Seitenkanal-Gate. field-mul-d misst weiterhin den ursprünglichen einzelnen Feldoperator, nicht den algebraischen E5-Gesamtgewinn.

| Version | Operation | Median ns | SD ns | Min ns | Max ns |
| --- | --- | --- | --- | --- | --- |
| v1 | control-field-copy | 1.263000 | 0.045645 | 1.257000 | 1.356000 |
| v2 | control-field-copy | 1.264000 | 0.016667 | 1.257000 | 1.305000 |
| v1 | field-add | 6.979000 | 0.104157 | 6.944000 | 7.204000 |
| v2 | field-add | 6.626000 | 0.070998 | 6.603000 | 6.823000 |
| v1 | field-sub | 5.960000 | 0.101563 | 5.931000 | 6.192000 |
| v2 | field-sub | 5.947000 | 0.095360 | 5.926000 | 6.181000 |
| v1 | field-mul | 25.729000 | 0.521563 | 25.451000 | 26.972000 |
| v2 | field-mul | 25.184000 | 0.549228 | 25.019000 | 26.765000 |
| v1 | field-square | 24.687000 | 0.540536 | 24.520000 | 25.912000 |
| v2 | field-square | 22.983000 | 0.284472 | 22.894000 | 23.650000 |
| v1 | field-mul-301 | 10.692000 | 0.140171 | 10.505000 | 10.994000 |
| v2 | field-mul-301 | 11.103000 | 0.121092 | 11.048000 | 11.425000 |
| v1 | field-mul-a | 10.995000 | 0.163625 | 10.959000 | 11.484000 |
| v2 | field-mul-a | 9.867000 | 0.104696 | 9.814000 | 10.096000 |
| v1 | field-mul-d | 10.666000 | 0.110769 | 10.583000 | 10.925000 |
| v2 | field-mul-d | 14.746000 | 0.324216 | 14.670000 | 15.669000 |
| v1 | field-invert | 2695.744000 | 129.617545 | 2678.754000 | 3073.024000 |
| v2 | field-invert | 2698.660000 | 42.672620 | 2691.108000 | 2822.504000 |
| v1 | field-sqrt-ratio | 9222.739000 | 75.426603 | 9187.877000 | 9433.448000 |
| v2 | field-sqrt-ratio | 8775.387000 | 84.897493 | 8704.468000 | 8950.395000 |
| v1 | lazy-mul | 21.415000 | 0.224842 | 21.306000 | 22.036000 |
| v2 | lazy-mul | 21.188000 | 0.148161 | 21.086000 | 21.480000 |
| v1 | lazy-square | 20.430000 | 0.649849 | 20.215000 | 21.967000 |
| v2 | lazy-square | 18.915000 | 0.083384 | 18.836000 | 19.063000 |
| v1 | lazy-mul-a | 6.608000 | 0.028041 | 6.571000 | 6.655000 |
| v2 | lazy-mul-a | 6.600000 | 0.062867 | 6.533000 | 6.762000 |
| v1 | lazy-loose-mul | 25.474000 | 0.207653 | 25.326000 | 25.956000 |
| v2 | lazy-loose-mul | 26.616000 | 0.124597 | 26.491000 | 26.780000 |
| v1 | scalar-add | 4.787000 | 0.028301 | 4.770000 | 4.861000 |
| v2 | scalar-add | 4.795000 | 0.110635 | 4.774000 | 5.111000 |
| v1 | scalar-mul | 115.370000 | 2.474833 | 114.562000 | 121.552000 |
| v2 | scalar-mul | 115.912000 | 1.493711 | 114.723000 | 119.017000 |
| v1 | scalar-reduce-pruned | 61.505000 | 2.050801 | 59.901000 | 66.779000 |
| v2 | scalar-reduce-pruned | 61.378000 | 1.180798 | 59.664000 | 63.482000 |
| v1 | scalar-reduce-hash | 155.413000 | 1.597979 | 152.718000 | 156.805000 |
| v2 | scalar-reduce-hash | 153.817000 | 1.586917 | 151.028000 | 155.822000 |
| v1 | scalar-wnaf-public | 588.529000 | 16.871925 | 585.934000 | 638.982000 |
| v2 | scalar-wnaf-public | 589.122000 | 8.509427 | 587.073000 | 614.124000 |

## Gepaarter E8-Schrittvergleich

| API | Version | Operation | Median µs | SD µs | Min µs | Max µs |
| --- | --- | --- | --- | --- | --- | --- |
| ed | v1 | expand | 27.716240 | 0.335557 | 27.427079 | 28.545778 |
| ed | before | expand | 27.808352 | 0.539572 | 27.260269 | 29.116019 |
| ed | after | expand | 27.940239 | 0.607279 | 27.416378 | 29.256815 |
| ed | v1 | sign | 28.606667 | 0.456942 | 28.228355 | 29.449628 |
| ed | before | sign | 28.827272 | 1.979585 | 28.384982 | 34.663826 |
| ed | after | sign | 28.795025 | 2.162048 | 28.352743 | 35.291600 |
| ed | v1 | verify | 86.270272 | 1.641987 | 85.085674 | 90.528911 |
| ed | before | verify | 82.927333 | 0.986311 | 81.726783 | 84.415933 |
| ed | after | verify | 84.052430 | 2.339215 | 81.596803 | 88.223391 |
| ed | v1 | import | 96.522255 | 4.334478 | 95.746607 | 109.500184 |
| ed | before | import | 61.509447 | 0.526334 | 60.898847 | 62.321808 |
| ed | after | import | 50.371274 | 0.424932 | 49.841242 | 51.057115 |
| x | v1 | public | 27.170005 | 0.491207 | 26.908159 | 28.209001 |
| x | before | public | 27.236319 | 0.684787 | 26.991767 | 29.121741 |
| x | after | public | 27.414418 | 0.697603 | 26.968580 | 29.147329 |
| x | v1 | shared | 56.677302 | 0.602859 | 56.229398 | 58.032506 |
| x | before | shared | 58.693491 | 0.468409 | 58.210699 | 59.655825 |
| x | after | shared | 57.804881 | 0.720789 | 57.120516 | 59.384114 |
| x | v1 | validate-public | 0.003835 | 0.000025 | 0.003799 | 0.003868 |
| x | before | validate-public | 0.001058 | 0.000014 | 0.001053 | 0.001099 |
| x | after | validate-public | 0.001061 | 0.000029 | 0.001054 | 0.001141 |
| x | v1 | canonical-public | 0.007524 | 0.000713 | 0.006921 | 0.008861 |
| x | before | canonical-public | 0.002710 | 0.000266 | 0.002518 | 0.003249 |
| x | after | canonical-public | 0.002684 | 0.001608 | 0.002544 | 0.007522 |
| x | before | import-secret | 0.031651 | 0.000563 | 0.030875 | 0.032664 |
| x | after | import-secret | 0.031101 | 0.000496 | 0.030915 | 0.032364 |
| x | before | import-public | 0.004556 | 0.000625 | 0.004532 | 0.006448 |
| x | after | import-public | 0.004602 | 0.000785 | 0.004532 | 0.006440 |
| x | before | prepared-shared | 58.712357 | 0.518828 | 57.989442 | 59.611595 |
| x | after | prepared-shared | 57.821552 | 0.881401 | 57.235452 | 59.571940 |
| x | before | prepared-public | 27.152308 | 0.310487 | 26.799066 | 27.711803 |
| x | after | prepared-public | 27.435229 | 0.458485 | 26.786437 | 28.095759 |
