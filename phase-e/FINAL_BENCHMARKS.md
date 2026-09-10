# Phase E: vollständige abschließende Benchmarktabellen

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
Die fünf getrennten 32-Fälle-Schrittvergleiche bleiben zusätzlich im Paket.

## Vollständiger ABI-Lauf 3.5.8

Receipt: `/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_final_02_2026-09-10/benchmarks-3.5.8`.

SHA-256 des Receipt-Manifests: `e00e1b4f98056fddd883fdea700a89c7c883f1e2f78c99275ad41c56b41e8d32`.

| Schicht | Verfahren | Operation | Median µs | SD µs | Min µs | Max µs |
| --- | --- | --- | --- | --- | --- | --- |
| Rust-Ed | Ed301-v1 | expand | 28.555503 | 0.288884 | 28.138721 | 29.133215 |
| Rust-Ed | Ed301-v2 | expand | 28.477368 | 0.436530 | 27.889694 | 29.142897 |
| Rust-Ed | Ed301-v1 | sign | 29.252734 | 0.530056 | 29.089906 | 30.518460 |
| Rust-Ed | Ed301-v2 | sign | 29.979550 | 1.466604 | 29.004827 | 33.579307 |
| Rust-Ed | Ed301-v1 | verify | 87.950564 | 2.953865 | 85.991016 | 93.835669 |
| Rust-Ed | Ed301-v2 | verify | 86.800313 | 1.013833 | 85.250035 | 88.697878 |
| Rust-Ed | Ed301-v1 | import | 98.993170 | 2.497846 | 96.523248 | 104.410877 |
| Rust-Ed | Ed301-v2 | import | 65.760546 | 0.834431 | 64.448289 | 67.159843 |
| Rust-X | X301-v1 | public | 28.003621 | 0.700988 | 27.464856 | 29.655339 |
| Rust-X | X301-v2 | public | 27.993124 | 1.090340 | 27.371295 | 30.737791 |
| Rust-X | X301-v1 | shared | 58.119736 | 2.930914 | 56.929462 | 66.040910 |
| Rust-X | X301-v2 | shared | 64.573765 | 1.465608 | 62.609074 | 67.141114 |
| Rust-X | X301-v1 | validate-public | 0.004574 | 0.000327 | 0.004080 | 0.005014 |
| Rust-X | X301-v2 | validate-public | 0.001323 | 0.000166 | 0.001185 | 0.001785 |
| Rust-X | X301-v1 | canonical-public | 0.008490 | 0.001146 | 0.007702 | 0.011249 |
| Rust-X | X301-v2 | canonical-public | 0.003401 | 0.000333 | 0.003065 | 0.003934 |
| Rust-X | X301-v2 | import-secret | 0.032975 | 0.001446 | 0.031405 | 0.036508 |
| Rust-X | X301-v2 | import-public | 0.005819 | 0.000994 | 0.004811 | 0.007659 |
| Rust-X | X301-v2 | prepared-public | 28.491469 | 2.209899 | 27.505072 | 34.074632 |
| Rust-X | X301-v2 | prepared-shared | 63.509255 | 3.320557 | 62.832615 | 72.248059 |
| EVP-signature | Ed25519 | keygen | 25.089500 | 0.869007 | 24.800900 | 27.613800 |
| EVP-signature | Ed448 | keygen | 149.407300 | 10.385031 | 146.634500 | 180.253000 |
| EVP-signature | Ed301-v1 | keygen | 58.399500 | 5.442218 | 56.542000 | 72.584100 |
| EVP-signature | Ed301-v2 | keygen | 58.498900 | 1.239159 | 56.404200 | 60.211300 |
| EVP-signature | Ed25519 | sign | 24.391600 | 0.499669 | 23.968200 | 25.537200 |
| EVP-signature | Ed448 | sign | 149.278900 | 20.845010 | 147.369600 | 205.772300 |
| EVP-signature | Ed301-v1 | sign | 30.353500 | 0.817808 | 29.805500 | 32.189000 |
| EVP-signature | Ed301-v2 | sign | 31.031800 | 2.674793 | 29.492800 | 38.161100 |
| EVP-signature | Ed25519 | verify | 80.344600 | 1.828920 | 78.822000 | 83.503400 |
| EVP-signature | Ed448 | verify | 157.148800 | 4.742296 | 154.740500 | 169.086700 |
| EVP-signature | Ed301-v1 | verify | 88.477900 | 3.401755 | 85.928900 | 97.033900 |
| EVP-signature | Ed301-v2 | verify | 87.520900 | 0.810449 | 85.397500 | 88.133200 |
| EVP-XDH | X25519 | keygen | 24.164500 | 0.381727 | 23.704900 | 24.749300 |
| EVP-XDH | X448 | keygen | 149.764800 | 3.440032 | 144.368800 | 154.524700 |
| EVP-XDH | X301-v1 | keygen | 29.843400 | 0.599916 | 29.250200 | 31.200500 |
| EVP-XDH | X301-v2 | keygen | 29.801400 | 0.930200 | 29.096600 | 31.888700 |
| EVP-XDH | X25519 | derive-setup | 1.273400 | 0.016985 | 1.252700 | 1.300500 |
| EVP-XDH | X448 | derive-setup | 1.270300 | 0.040848 | 1.237700 | 1.352400 |
| EVP-XDH | X301-v1 | derive-setup | 1.808700 | 0.058781 | 1.709200 | 1.885500 |
| EVP-XDH | X301-v2 | derive-setup | 1.851800 | 0.059300 | 1.812900 | 1.999900 |
| EVP-XDH | X25519 | derive-first | 23.931900 | 0.287070 | 23.686500 | 24.563100 |
| EVP-XDH | X448 | derive-first | 121.667500 | 2.686182 | 120.506700 | 128.340400 |
| EVP-XDH | X301-v1 | derive-first | 58.812900 | 1.392865 | 57.205400 | 61.035600 |
| EVP-XDH | X301-v2 | derive-first | 63.915900 | 1.511064 | 62.771900 | 67.017300 |
| EVP-XDH | X25519 | derive-second | 23.880200 | 0.298851 | 23.712400 | 24.598900 |
| EVP-XDH | X448 | derive-second | 121.951400 | 5.242870 | 119.756100 | 136.268700 |
| EVP-XDH | X301-v1 | derive-second | 57.754500 | 2.852891 | 56.748500 | 64.447600 |
| EVP-XDH | X301-v2 | derive-second | 64.851400 | 2.806249 | 63.388200 | 71.577900 |
| EVP-XDH | X25519 | derive-steady | 24.019700 | 0.870775 | 23.745000 | 26.302800 |
| EVP-XDH | X448 | derive-steady | 122.531900 | 1.760382 | 120.369500 | 125.516100 |
| EVP-XDH | X301-v1 | derive-steady | 58.137500 | 1.446458 | 56.697100 | 61.698900 |
| EVP-XDH | X301-v2 | derive-steady | 63.820600 | 2.182807 | 62.662600 | 69.426600 |
| EVP-KEM | ML-KEM-1024 | kem-keygen | 39.089400 | 1.641699 | 38.215600 | 43.680300 |
| EVP-KEM | Hybrid-v1 | kem-keygen | 68.950000 | 2.886235 | 67.908700 | 75.387600 |
| EVP-KEM | Hybrid-v2 | kem-keygen | 70.361100 | 3.446323 | 67.810800 | 76.481000 |
| EVP-KEM | ML-KEM-1024 | encaps | 20.640300 | 0.675511 | 20.413900 | 22.242700 |
| EVP-KEM | Hybrid-v1 | encaps | 108.537300 | 1.674427 | 106.339300 | 110.902600 |
| EVP-KEM | Hybrid-v2 | encaps | 114.085500 | 1.995494 | 113.024200 | 119.378700 |
| EVP-KEM | ML-KEM-1024 | decaps | 30.995600 | 0.586512 | 30.347300 | 32.145500 |
| EVP-KEM | Hybrid-v1 | decaps | 89.575700 | 6.954227 | 88.027000 | 110.292900 |
| EVP-KEM | Hybrid-v2 | decaps | 96.295800 | 3.573678 | 94.151200 | 105.422900 |
| EVP-codec | Ed25519 | encode-private-DER | 8.212769 | 0.359948 | 7.956076 | 9.151848 |
| EVP-codec | Ed448 | encode-private-DER | 8.109000 | 0.419728 | 7.708618 | 9.106667 |
| EVP-codec | Ed301-v1 | encode-private-DER | 40.838909 | 1.068862 | 39.753675 | 43.096197 |
| EVP-codec | Ed301-v2 | encode-private-DER | 56.787227 | 0.738818 | 55.462365 | 57.687446 |
| EVP-codec | X25519 | encode-private-DER | 8.113150 | 0.381147 | 7.909745 | 9.039571 |
| EVP-codec | X448 | encode-private-DER | 8.120888 | 0.771227 | 7.972128 | 10.207110 |
| EVP-codec | X301-v2 | encode-private-DER | 54.852359 | 1.274213 | 54.075001 | 57.548219 |
| EVP-codec | Ed25519 | decode-private-DER | 28.376451 | 0.405148 | 27.577398 | 28.935479 |
| EVP-codec | Ed448 | decode-private-DER | 153.916194 | 5.810405 | 149.197499 | 169.289070 |
| EVP-codec | Ed301-v1 | decode-private-DER | 60.682304 | 1.460865 | 58.920461 | 63.163134 |
| EVP-codec | Ed301-v2 | decode-private-DER | 59.740397 | 0.957396 | 59.216571 | 62.193939 |
| EVP-codec | X25519 | decode-private-DER | 27.581164 | 3.182076 | 27.250260 | 36.134883 |
| EVP-codec | X448 | decode-private-DER | 151.937434 | 19.849126 | 150.723392 | 212.069540 |
| EVP-codec | X301-v2 | decode-private-DER | 32.663494 | 2.280223 | 32.316833 | 39.294433 |
| EVP-codec | Ed25519 | encode-public-DER | 7.578201 | 0.239310 | 7.107117 | 7.868737 |
| EVP-codec | Ed448 | encode-public-DER | 7.489339 | 0.277796 | 7.278581 | 8.076897 |
| EVP-codec | Ed301-v1 | encode-public-DER | 40.183757 | 1.109325 | 38.974792 | 42.491864 |
| EVP-codec | Ed301-v2 | encode-public-DER | 56.256951 | 0.933090 | 55.280119 | 57.608111 |
| EVP-codec | X25519 | encode-public-DER | 7.796754 | 0.359689 | 7.296255 | 8.492748 |
| EVP-codec | X448 | encode-public-DER | 7.588416 | 0.138992 | 7.390042 | 7.761850 |
| EVP-codec | X301-v2 | encode-public-DER | 54.172657 | 2.256368 | 53.294957 | 60.635405 |
| EVP-codec | Ed25519 | decode-public-DER | 5.413032 | 0.297390 | 5.360356 | 6.268879 |
| EVP-codec | Ed448 | decode-public-DER | 5.469423 | 0.379347 | 5.261049 | 6.523124 |
| EVP-codec | Ed301-v1 | decode-public-DER | 105.908518 | 10.707908 | 104.398715 | 137.440266 |
| EVP-codec | Ed301-v2 | decode-public-DER | 71.512430 | 1.453459 | 70.001809 | 74.267163 |
| EVP-codec | X25519 | decode-public-DER | 5.419296 | 0.118767 | 5.305716 | 5.665079 |
| EVP-codec | X448 | decode-public-DER | 5.445147 | 0.110948 | 5.367461 | 5.686940 |
| EVP-codec | X301-v2 | decode-public-DER | 5.431502 | 0.104211 | 5.276298 | 5.634699 |
| EVP-codec | Ed25519 | encode-private-PEM | 10.609210 | 0.484931 | 10.250823 | 11.652357 |
| EVP-codec | Ed448 | encode-private-PEM | 10.800971 | 0.220877 | 10.549937 | 11.177465 |
| EVP-codec | Ed301-v1 | encode-private-PEM | 44.408266 | 1.511476 | 42.479543 | 47.934984 |
| EVP-codec | Ed301-v2 | encode-private-PEM | 60.419483 | 2.541582 | 58.868718 | 67.447128 |
| EVP-codec | X25519 | encode-private-PEM | 10.843616 | 1.401747 | 10.498815 | 14.932020 |
| EVP-codec | X448 | encode-private-PEM | 10.742873 | 0.757748 | 10.542887 | 12.991878 |
| EVP-codec | X301-v2 | encode-private-PEM | 57.817884 | 1.268679 | 56.461832 | 60.728366 |
| EVP-codec | Ed25519 | decode-private-PEM | 28.899021 | 0.634223 | 28.255308 | 30.223700 |
| EVP-codec | Ed448 | decode-private-PEM | 155.393892 | 2.924426 | 151.306794 | 159.248150 |
| EVP-codec | Ed301-v1 | decode-private-PEM | 62.557991 | 4.955624 | 59.903155 | 74.088137 |
| EVP-codec | Ed301-v2 | decode-private-PEM | 61.234614 | 1.815796 | 59.942706 | 65.220755 |
| EVP-codec | X25519 | decode-private-PEM | 28.538430 | 0.953068 | 27.814554 | 31.031253 |
| EVP-codec | X448 | decode-private-PEM | 156.377752 | 5.887057 | 149.834541 | 168.169551 |
| EVP-codec | X301-v2 | decode-private-PEM | 33.572168 | 1.587905 | 32.752682 | 37.576035 |
| EVP-codec | Ed25519 | encode-encrypted-PEM | 257.310686 | 8.604637 | 246.284788 | 266.500983 |
| EVP-codec | Ed448 | encode-encrypted-PEM | 253.171428 | 19.207848 | 247.296529 | 303.938668 |
| EVP-codec | Ed301-v1 | encode-encrypted-PEM | 286.085619 | 4.387901 | 282.980775 | 295.584068 |
| EVP-codec | Ed301-v2 | encode-encrypted-PEM | 303.114297 | 4.286352 | 297.610478 | 311.567114 |
| EVP-codec | X25519 | encode-encrypted-PEM | 253.358916 | 6.509154 | 247.027783 | 267.036240 |
| EVP-codec | X448 | encode-encrypted-PEM | 272.235176 | 7.111095 | 265.356033 | 283.635785 |
| EVP-codec | X301-v2 | encode-encrypted-PEM | 305.271275 | 13.013288 | 297.613522 | 339.714106 |
| EVP-codec | Ed25519 | decode-encrypted-PEM | 270.118236 | 5.813336 | 263.726659 | 281.552899 |
| EVP-codec | Ed448 | decode-encrypted-PEM | 397.345593 | 12.985730 | 390.752431 | 425.175162 |
| EVP-codec | Ed301-v1 | decode-encrypted-PEM | 296.128791 | 7.270480 | 293.439710 | 312.108835 |
| EVP-codec | Ed301-v2 | decode-encrypted-PEM | 298.759700 | 27.555739 | 291.437019 | 379.805786 |
| EVP-codec | X25519 | decode-encrypted-PEM | 266.483610 | 6.661661 | 263.573704 | 280.365124 |
| EVP-codec | X448 | decode-encrypted-PEM | 392.219391 | 22.445101 | 386.989460 | 457.240051 |
| EVP-codec | X301-v2 | decode-encrypted-PEM | 270.879561 | 4.760948 | 266.965234 | 280.408938 |
| TLS-engine | Ed25519-X25519 | full-handshake-warm-context | 391.612196 | 14.059620 | 377.820207 | 422.349857 |
| TLS-engine | Ed448-X25519 | full-handshake-warm-context | 595.973361 | 8.292979 | 586.295116 | 615.016408 |
| TLS-engine | Ed-v1-X25519 | full-handshake-warm-context | 509.873157 | 22.146450 | 496.722576 | 562.209623 |
| TLS-engine | Ed-v2-X25519 | full-handshake-warm-context | 477.323803 | 7.129983 | 467.694353 | 492.716373 |
| TLS-engine | Ed-v1-Hybrid-v1 | full-handshake-warm-context | 736.244328 | 23.678755 | 696.403929 | 773.688942 |
| TLS-engine | Ed-v2-Hybrid-v2 | full-handshake-warm-context | 699.849185 | 17.804307 | 686.746687 | 735.569225 |
| TLS-engine | Ed-v2-Raw-v2 | full-handshake-warm-context | 568.311405 | 18.147538 | 556.627143 | 611.942179 |
| TLS-engine | ECDSA-X25519 | full-handshake-warm-context | 367.476793 | 42.061602 | 359.859551 | 492.372571 |
| TLS-engine | ECDSA-Hybrid-v1 | full-handshake-warm-context | 583.738558 | 6.792756 | 572.014755 | 594.037185 |
| TLS-engine | ECDSA-Hybrid-v2 | full-handshake-warm-context | 603.492074 | 31.027859 | 586.163062 | 689.877136 |
| TLS-engine | ECDSA-Raw-v2 | full-handshake-warm-context | 468.518988 | 27.868748 | 459.754466 | 548.499442 |

## Vollständiger ABI-Lauf 4.0.2

Receipt: `/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_final_02_2026-09-10/benchmarks-4.0.2`.

SHA-256 des Receipt-Manifests: `bc03a6a074c5578f374c2a0b6d9afe3fe88dbfa944763a58715ae03468520fa8`.

| Schicht | Verfahren | Operation | Median µs | SD µs | Min µs | Max µs |
| --- | --- | --- | --- | --- | --- | --- |
| Rust-Ed | Ed301-v1 | expand | 27.888167 | 1.726682 | 27.459621 | 32.998688 |
| Rust-Ed | Ed301-v2 | expand | 28.425528 | 2.150504 | 27.830757 | 34.402681 |
| Rust-Ed | Ed301-v1 | sign | 29.131439 | 0.403959 | 28.467990 | 29.666774 |
| Rust-Ed | Ed301-v2 | sign | 28.999268 | 0.508293 | 28.722157 | 30.077773 |
| Rust-Ed | Ed301-v1 | verify | 86.961010 | 2.850582 | 85.689753 | 95.052397 |
| Rust-Ed | Ed301-v2 | verify | 85.502459 | 1.599836 | 84.473183 | 89.346454 |
| Rust-Ed | Ed301-v1 | import | 98.866831 | 1.264520 | 96.581653 | 100.143423 |
| Rust-Ed | Ed301-v2 | import | 65.213853 | 0.747475 | 64.205335 | 66.684558 |
| Rust-X | X301-v1 | public | 28.044990 | 0.542908 | 27.486384 | 29.161876 |
| Rust-X | X301-v2 | public | 27.743499 | 2.110748 | 27.029476 | 33.807731 |
| Rust-X | X301-v1 | shared | 57.436946 | 0.447618 | 56.877708 | 58.106084 |
| Rust-X | X301-v2 | shared | 62.954397 | 1.355290 | 62.331487 | 66.670990 |
| Rust-X | X301-v1 | validate-public | 0.004085 | 0.000235 | 0.003885 | 0.004569 |
| Rust-X | X301-v2 | validate-public | 0.001197 | 0.000067 | 0.001056 | 0.001283 |
| Rust-X | X301-v1 | canonical-public | 0.008070 | 0.001120 | 0.006785 | 0.009917 |
| Rust-X | X301-v2 | canonical-public | 0.003017 | 0.000420 | 0.002521 | 0.003861 |
| Rust-X | X301-v2 | import-secret | 0.031418 | 0.000386 | 0.030847 | 0.032128 |
| Rust-X | X301-v2 | import-public | 0.005334 | 0.000792 | 0.005071 | 0.006943 |
| Rust-X | X301-v2 | prepared-public | 27.909254 | 1.571666 | 27.281265 | 32.334021 |
| Rust-X | X301-v2 | prepared-shared | 62.518814 | 0.786627 | 62.091687 | 64.646178 |
| EVP-signature | Ed25519 | keygen | 24.243000 | 0.292980 | 23.998600 | 24.911500 |
| EVP-signature | Ed448 | keygen | 146.991100 | 1.500251 | 146.012000 | 150.844300 |
| EVP-signature | Ed301-v1 | keygen | 56.852700 | 2.058664 | 56.271100 | 62.890200 |
| EVP-signature | Ed301-v2 | keygen | 57.059000 | 2.376403 | 56.517300 | 64.094600 |
| EVP-signature | Ed25519 | sign | 23.692700 | 1.188331 | 23.613500 | 27.317700 |
| EVP-signature | Ed448 | sign | 147.432100 | 1.035237 | 145.790700 | 149.091200 |
| EVP-signature | Ed301-v1 | sign | 29.671900 | 2.433069 | 29.291400 | 36.943500 |
| EVP-signature | Ed301-v2 | sign | 29.668200 | 0.876203 | 29.357200 | 31.657100 |
| EVP-signature | Ed25519 | verify | 78.361100 | 1.102136 | 77.565700 | 80.987900 |
| EVP-signature | Ed448 | verify | 155.552600 | 1.076779 | 154.776700 | 157.655300 |
| EVP-signature | Ed301-v1 | verify | 86.923000 | 1.418726 | 85.986400 | 90.781200 |
| EVP-signature | Ed301-v2 | verify | 88.391900 | 1.960675 | 84.914600 | 90.396100 |
| EVP-XDH | X25519 | keygen | 24.126400 | 0.215653 | 23.668600 | 24.298700 |
| EVP-XDH | X448 | keygen | 145.206500 | 1.493588 | 143.418600 | 147.994400 |
| EVP-XDH | X301-v1 | keygen | 29.228900 | 1.795289 | 28.918400 | 34.620100 |
| EVP-XDH | X301-v2 | keygen | 29.490600 | 0.405882 | 28.853600 | 30.131400 |
| EVP-XDH | X25519 | derive-setup | 1.060200 | 0.014378 | 1.039500 | 1.086800 |
| EVP-XDH | X448 | derive-setup | 1.040000 | 0.009913 | 1.027600 | 1.055800 |
| EVP-XDH | X301-v1 | derive-setup | 1.597500 | 0.040707 | 1.523800 | 1.623300 |
| EVP-XDH | X301-v2 | derive-setup | 1.675800 | 0.070752 | 1.646000 | 1.866700 |
| EVP-XDH | X25519 | derive-first | 23.653000 | 0.258327 | 23.486100 | 24.239300 |
| EVP-XDH | X448 | derive-first | 120.875000 | 5.898861 | 118.897200 | 137.781500 |
| EVP-XDH | X301-v1 | derive-first | 57.032900 | 0.350385 | 56.678100 | 57.607100 |
| EVP-XDH | X301-v2 | derive-first | 62.813600 | 0.724053 | 62.342600 | 64.239400 |
| EVP-XDH | X25519 | derive-second | 23.713800 | 0.168789 | 23.502500 | 24.007400 |
| EVP-XDH | X448 | derive-second | 120.003100 | 0.803708 | 119.043600 | 121.655300 |
| EVP-XDH | X301-v1 | derive-second | 57.673400 | 0.378550 | 57.141200 | 58.187800 |
| EVP-XDH | X301-v2 | derive-second | 62.846600 | 0.740329 | 62.295600 | 64.444500 |
| EVP-XDH | X25519 | derive-steady | 23.690900 | 0.123487 | 23.547100 | 23.941000 |
| EVP-XDH | X448 | derive-steady | 120.112700 | 1.427976 | 118.740300 | 122.860800 |
| EVP-XDH | X301-v1 | derive-steady | 57.381800 | 0.755784 | 56.914600 | 59.430900 |
| EVP-XDH | X301-v2 | derive-steady | 62.873700 | 0.315049 | 62.355800 | 63.367900 |
| EVP-KEM | ML-KEM-1024 | kem-keygen | 37.487100 | 0.343192 | 37.320800 | 38.220300 |
| EVP-KEM | Hybrid-v1 | kem-keygen | 68.844700 | 1.281532 | 66.671500 | 70.048500 |
| EVP-KEM | Hybrid-v2 | kem-keygen | 67.331600 | 2.437907 | 66.054100 | 74.176500 |
| EVP-KEM | ML-KEM-1024 | encaps | 19.979800 | 0.157258 | 19.762300 | 20.268000 |
| EVP-KEM | Hybrid-v1 | encaps | 107.124100 | 1.487464 | 105.524400 | 109.636900 |
| EVP-KEM | Hybrid-v2 | encaps | 111.932700 | 1.082212 | 111.204500 | 114.366800 |
| EVP-KEM | ML-KEM-1024 | decaps | 30.207100 | 0.226005 | 29.826300 | 30.427100 |
| EVP-KEM | Hybrid-v1 | decaps | 87.836300 | 4.539512 | 86.856700 | 101.249800 |
| EVP-KEM | Hybrid-v2 | decaps | 93.198200 | 1.784714 | 92.321900 | 97.028500 |
| EVP-codec | Ed25519 | encode-private-DER | 8.862959 | 0.170178 | 8.679516 | 9.228391 |
| EVP-codec | Ed448 | encode-private-DER | 8.895513 | 0.193249 | 8.593060 | 9.168036 |
| EVP-codec | Ed301-v1 | encode-private-DER | 23.261411 | 0.143401 | 23.097168 | 23.601145 |
| EVP-codec | Ed301-v2 | encode-private-DER | 32.353384 | 0.597006 | 32.044301 | 33.842957 |
| EVP-codec | X25519 | encode-private-DER | 8.911998 | 0.249216 | 8.612312 | 9.427294 |
| EVP-codec | X448 | encode-private-DER | 8.778321 | 0.446102 | 8.530991 | 9.992286 |
| EVP-codec | X301-v2 | encode-private-DER | 27.509570 | 0.639985 | 27.300341 | 29.310426 |
| EVP-codec | Ed25519 | decode-private-DER | 27.102852 | 0.367008 | 26.758687 | 27.837201 |
| EVP-codec | Ed448 | decode-private-DER | 149.824738 | 2.457252 | 148.191324 | 154.990996 |
| EVP-codec | Ed301-v1 | decode-private-DER | 59.456575 | 1.312335 | 58.407042 | 62.523818 |
| EVP-codec | Ed301-v2 | decode-private-DER | 59.887814 | 2.285167 | 58.200311 | 65.569300 |
| EVP-codec | X25519 | decode-private-DER | 27.087881 | 1.184273 | 26.398037 | 30.120314 |
| EVP-codec | X448 | decode-private-DER | 149.030641 | 7.381837 | 146.928202 | 170.097267 |
| EVP-codec | X301-v2 | decode-private-DER | 32.223991 | 0.504770 | 31.645238 | 33.018775 |
| EVP-codec | Ed25519 | encode-public-DER | 8.269596 | 1.164827 | 8.124930 | 11.781719 |
| EVP-codec | Ed448 | encode-public-DER | 8.209100 | 0.257324 | 7.800067 | 8.557787 |
| EVP-codec | Ed301-v1 | encode-public-DER | 22.760733 | 0.272638 | 22.375315 | 23.312430 |
| EVP-codec | Ed301-v2 | encode-public-DER | 31.798112 | 1.664430 | 31.523225 | 36.718746 |
| EVP-codec | X25519 | encode-public-DER | 8.239860 | 0.272041 | 7.875700 | 8.733911 |
| EVP-codec | X448 | encode-public-DER | 8.032188 | 0.195040 | 7.918211 | 8.434195 |
| EVP-codec | X301-v2 | encode-public-DER | 27.016711 | 0.633558 | 26.533213 | 28.270741 |
| EVP-codec | Ed25519 | decode-public-DER | 5.017644 | 0.094682 | 4.940547 | 5.207351 |
| EVP-codec | Ed448 | decode-public-DER | 5.001990 | 0.133142 | 4.957966 | 5.367966 |
| EVP-codec | Ed301-v1 | decode-public-DER | 102.627954 | 1.263879 | 101.385708 | 105.878918 |
| EVP-codec | Ed301-v2 | decode-public-DER | 70.142624 | 1.094423 | 69.096021 | 72.780587 |
| EVP-codec | X25519 | decode-public-DER | 4.959143 | 0.052808 | 4.897872 | 5.051318 |
| EVP-codec | X448 | decode-public-DER | 4.992918 | 0.057471 | 4.952951 | 5.137394 |
| EVP-codec | X301-v2 | decode-public-DER | 4.949012 | 0.157294 | 4.841668 | 5.333847 |
| EVP-codec | Ed25519 | encode-private-PEM | 9.443970 | 0.290733 | 9.175187 | 10.160750 |
| EVP-codec | Ed448 | encode-private-PEM | 9.802683 | 0.153959 | 9.546316 | 9.951940 |
| EVP-codec | Ed301-v1 | encode-private-PEM | 24.914805 | 0.404438 | 24.266862 | 25.402216 |
| EVP-codec | Ed301-v2 | encode-private-PEM | 33.525146 | 0.408699 | 32.928230 | 34.129953 |
| EVP-codec | X25519 | encode-private-PEM | 9.575324 | 0.136646 | 9.418579 | 9.830346 |
| EVP-codec | X448 | encode-private-PEM | 9.561882 | 0.213337 | 9.212091 | 9.837645 |
| EVP-codec | X301-v2 | encode-private-PEM | 28.458230 | 0.561617 | 27.796603 | 29.820022 |
| EVP-codec | Ed25519 | decode-private-PEM | 27.922000 | 1.614926 | 27.436046 | 32.558687 |
| EVP-codec | Ed448 | decode-private-PEM | 151.807374 | 9.809300 | 148.180335 | 179.898480 |
| EVP-codec | Ed301-v1 | decode-private-PEM | 59.955126 | 3.003034 | 58.593958 | 68.361599 |
| EVP-codec | Ed301-v2 | decode-private-PEM | 60.479251 | 1.199483 | 58.375714 | 61.755647 |
| EVP-codec | X25519 | decode-private-PEM | 27.393052 | 0.787539 | 26.787340 | 29.022013 |
| EVP-codec | X448 | decode-private-PEM | 149.034116 | 4.336718 | 147.621862 | 160.992382 |
| EVP-codec | X301-v2 | decode-private-PEM | 32.136275 | 2.605732 | 31.863929 | 38.430188 |
| EVP-codec | Ed25519 | encode-encrypted-PEM | 239.410368 | 5.031924 | 232.989486 | 246.554042 |
| EVP-codec | Ed448 | encode-encrypted-PEM | 239.321713 | 2.403974 | 235.355341 | 243.418118 |
| EVP-codec | Ed301-v1 | encode-encrypted-PEM | 254.884242 | 2.134834 | 251.017959 | 257.958665 |
| EVP-codec | Ed301-v2 | encode-encrypted-PEM | 268.015948 | 8.336214 | 260.501057 | 284.893043 |
| EVP-codec | X25519 | encode-encrypted-PEM | 243.163935 | 3.239847 | 234.826150 | 244.768883 |
| EVP-codec | X448 | encode-encrypted-PEM | 243.492037 | 6.568185 | 233.468909 | 258.322858 |
| EVP-codec | X301-v2 | encode-encrypted-PEM | 259.024623 | 8.526493 | 254.811173 | 282.629986 |
| EVP-codec | Ed25519 | decode-encrypted-PEM | 253.419727 | 4.967959 | 248.977794 | 265.693251 |
| EVP-codec | Ed448 | decode-encrypted-PEM | 377.034495 | 16.769853 | 369.782428 | 424.401749 |
| EVP-codec | Ed301-v1 | decode-encrypted-PEM | 288.535516 | 16.804415 | 282.448828 | 336.663144 |
| EVP-codec | Ed301-v2 | decode-encrypted-PEM | 290.090119 | 6.663839 | 281.472538 | 299.509348 |
| EVP-codec | X25519 | decode-encrypted-PEM | 255.814599 | 12.558232 | 251.238401 | 285.366951 |
| EVP-codec | X448 | decode-encrypted-PEM | 374.049559 | 18.250836 | 368.763848 | 427.057578 |
| EVP-codec | X301-v2 | decode-encrypted-PEM | 256.335925 | 5.289358 | 253.708847 | 268.662109 |
| TLS-engine | Ed25519-X25519 | full-handshake-warm-context | 375.172648 | 8.472299 | 365.943428 | 388.788312 |
| TLS-engine | Ed448-X25519 | full-handshake-warm-context | 582.744146 | 22.844177 | 569.053259 | 645.675424 |
| TLS-engine | Ed-v1-X25519 | full-handshake-warm-context | 492.782426 | 23.398096 | 478.377597 | 556.830955 |
| TLS-engine | Ed-v2-X25519 | full-handshake-warm-context | 454.650538 | 15.991658 | 447.728415 | 493.268313 |
| TLS-engine | Ed-v1-Hybrid-v1 | full-handshake-warm-context | 713.078320 | 16.636167 | 687.457915 | 739.808799 |
| TLS-engine | Ed-v2-Hybrid-v2 | full-handshake-warm-context | 690.960099 | 29.808311 | 666.291271 | 764.324695 |
| TLS-engine | Ed-v2-Raw-v2 | full-handshake-warm-context | 550.702670 | 43.428548 | 538.791173 | 675.658886 |
| TLS-engine | ECDSA-X25519 | full-handshake-warm-context | 357.841860 | 7.350467 | 344.041435 | 363.800867 |
| TLS-engine | ECDSA-Hybrid-v1 | full-handshake-warm-context | 568.660997 | 13.758341 | 551.479028 | 592.581345 |
| TLS-engine | ECDSA-Hybrid-v2 | full-handshake-warm-context | 583.870398 | 44.424484 | 569.228788 | 712.697052 |
| TLS-engine | ECDSA-Raw-v2 | full-handshake-warm-context | 449.224027 | 8.876053 | 441.147077 | 469.218363 |

## Erweiterte Nachrichten-/Context-Matrix

Receipt: `/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_final_02_2026-09-10/ED301-v2_core-matrix_tea98dtt`.

SHA-256: `a06fc62093688d688061f9f2301159cd9d24f71ef13fbfe39347797512a89aa1`.

cold-sign enthält Seedimport und Expansion; prepared-sign/prepared-verify verwenden vorbereitete Schlüssel. import-verify enthält die erneute Public-Key-Prüfung. Nachricht i=(29i+7) mod 256, Context i=(17i+3) mod 256. Kalt bezeichnet den Schlüssel-Lifecycle, keinen geleerten CPU-Cache.

| Version | Operation | Nachricht Byte | Context Byte | Median µs | SD µs | Min µs | Max µs |
| --- | --- | --- | --- | --- | --- | --- | --- |
| v1 | cold-sign | 0 | 0 | 56.920401 | 8.014712 | 56.094506 | 80.741338 |
| v2 | cold-sign | 0 | 0 | 57.439717 | 3.102003 | 56.036449 | 64.144707 |
| v1 | prepared-sign | 0 | 0 | 28.565018 | 3.564738 | 28.153312 | 37.364799 |
| v2 | prepared-sign | 0 | 0 | 28.714113 | 2.518547 | 28.458200 | 36.264844 |
| v1 | prepared-verify | 0 | 0 | 89.253217 | 11.753993 | 85.322019 | 122.370317 |
| v2 | prepared-verify | 0 | 0 | 89.906914 | 10.083531 | 84.592034 | 116.916080 |
| v1 | import-verify | 0 | 0 | 184.288474 | 11.929320 | 181.858583 | 213.969358 |
| v2 | import-verify | 0 | 0 | 150.433407 | 6.250325 | 148.945312 | 168.502581 |
| v1 | cold-sign | 0 | 16 | 57.797937 | 2.876021 | 56.202643 | 65.145043 |
| v2 | cold-sign | 0 | 16 | 56.712502 | 1.312853 | 56.275943 | 59.795139 |
| v1 | prepared-sign | 0 | 16 | 28.701746 | 2.348008 | 28.381188 | 35.342354 |
| v2 | prepared-sign | 0 | 16 | 28.752471 | 4.409186 | 28.340180 | 41.949656 |
| v1 | prepared-verify | 0 | 16 | 85.761742 | 5.042050 | 84.460403 | 100.607397 |
| v2 | prepared-verify | 0 | 16 | 85.716662 | 2.175234 | 84.349806 | 89.762039 |
| v1 | import-verify | 0 | 16 | 183.869920 | 22.709861 | 181.112719 | 251.788537 |
| v2 | import-verify | 0 | 16 | 152.176841 | 10.589543 | 148.864319 | 181.911445 |
| v1 | cold-sign | 0 | 255 | 58.636333 | 9.719401 | 56.968948 | 87.304543 |
| v2 | cold-sign | 0 | 255 | 61.389680 | 6.370572 | 57.388880 | 77.529082 |
| v1 | prepared-sign | 0 | 255 | 30.271821 | 2.625369 | 29.483312 | 37.783066 |
| v2 | prepared-sign | 0 | 255 | 29.868616 | 3.802107 | 29.357805 | 39.354493 |
| v1 | prepared-verify | 0 | 255 | 86.225308 | 9.776886 | 85.650814 | 110.095219 |
| v2 | prepared-verify | 0 | 255 | 84.988382 | 9.608245 | 84.222850 | 107.513563 |
| v1 | import-verify | 0 | 255 | 184.028438 | 16.055457 | 182.644405 | 228.341295 |
| v2 | import-verify | 0 | 255 | 150.833652 | 19.420001 | 148.844961 | 207.366539 |
| v1 | cold-sign | 64 | 0 | 56.679221 | 9.329461 | 56.249719 | 80.837117 |
| v2 | cold-sign | 64 | 0 | 57.810266 | 8.330752 | 56.524616 | 79.962755 |
| v1 | prepared-sign | 64 | 0 | 29.267433 | 1.332917 | 28.545293 | 32.097643 |
| v2 | prepared-sign | 64 | 0 | 29.221743 | 2.086666 | 28.637723 | 34.650996 |
| v1 | prepared-verify | 64 | 0 | 86.415385 | 12.636431 | 84.118227 | 123.324315 |
| v2 | prepared-verify | 64 | 0 | 87.207371 | 14.490861 | 84.963055 | 129.850602 |
| v1 | import-verify | 64 | 0 | 182.623451 | 26.556965 | 180.800225 | 262.524982 |
| v2 | import-verify | 64 | 0 | 150.798882 | 22.514097 | 149.593593 | 215.257840 |
| v1 | cold-sign | 64 | 16 | 56.828461 | 9.780264 | 56.415183 | 85.535131 |
| v2 | cold-sign | 64 | 16 | 59.382745 | 11.235871 | 56.830127 | 87.553299 |
| v1 | prepared-sign | 64 | 16 | 29.256988 | 2.270276 | 28.807717 | 35.873062 |
| v2 | prepared-sign | 64 | 16 | 29.590996 | 5.290187 | 29.170742 | 42.844462 |
| v1 | prepared-verify | 64 | 16 | 85.703397 | 8.045641 | 84.724733 | 105.379362 |
| v2 | prepared-verify | 64 | 16 | 84.890018 | 9.405805 | 84.035364 | 108.611688 |
| v1 | import-verify | 64 | 16 | 185.793980 | 32.955310 | 182.099190 | 280.198452 |
| v2 | import-verify | 64 | 16 | 155.444469 | 8.330027 | 147.769054 | 174.315600 |
| v1 | cold-sign | 64 | 255 | 59.266397 | 3.935048 | 57.324463 | 69.911008 |
| v2 | cold-sign | 64 | 255 | 58.402135 | 4.189828 | 57.536896 | 70.270039 |
| v1 | prepared-sign | 64 | 255 | 30.279714 | 5.204876 | 29.760488 | 42.809072 |
| v2 | prepared-sign | 64 | 255 | 30.420062 | 5.333130 | 29.618371 | 45.809036 |
| v1 | prepared-verify | 64 | 255 | 86.312487 | 11.635683 | 85.746331 | 117.537327 |
| v2 | prepared-verify | 64 | 255 | 88.966479 | 11.288917 | 84.184837 | 113.842224 |
| v1 | import-verify | 64 | 255 | 184.069212 | 22.554930 | 182.563534 | 243.723886 |
| v2 | import-verify | 64 | 255 | 149.168558 | 11.692244 | 148.300696 | 184.748759 |
| v1 | cold-sign | 1024 | 0 | 61.237505 | 9.054641 | 59.980773 | 85.941311 |
| v2 | cold-sign | 1024 | 0 | 60.550993 | 9.788280 | 60.199415 | 90.275160 |
| v1 | prepared-sign | 1024 | 0 | 32.643472 | 1.169688 | 32.253427 | 35.949621 |
| v2 | prepared-sign | 1024 | 0 | 32.486366 | 4.612441 | 32.106145 | 46.147039 |
| v1 | prepared-verify | 1024 | 0 | 87.077984 | 4.363996 | 86.874382 | 99.172996 |
| v2 | prepared-verify | 1024 | 0 | 86.468479 | 13.032413 | 85.998759 | 125.689210 |
| v1 | import-verify | 1024 | 0 | 184.924593 | 23.622503 | 183.493074 | 256.097063 |
| v2 | import-verify | 1024 | 0 | 151.277464 | 19.790996 | 150.441799 | 211.052735 |
| v1 | cold-sign | 1024 | 16 | 60.452848 | 4.392343 | 59.935610 | 73.590563 |
| v2 | cold-sign | 1024 | 16 | 60.669007 | 9.137634 | 60.269177 | 88.111042 |
| v1 | prepared-sign | 1024 | 16 | 33.418102 | 2.498429 | 32.396230 | 40.341329 |
| v2 | prepared-sign | 1024 | 16 | 32.957902 | 1.800750 | 32.487251 | 37.279658 |
| v1 | prepared-verify | 1024 | 16 | 88.073135 | 3.594534 | 86.561640 | 96.255237 |
| v2 | prepared-verify | 1024 | 16 | 86.299174 | 6.227587 | 85.961570 | 105.082286 |
| v1 | import-verify | 1024 | 16 | 184.997940 | 2.762096 | 183.192171 | 190.876749 |
| v2 | import-verify | 1024 | 16 | 151.981293 | 11.141230 | 150.458467 | 185.318760 |
| v1 | cold-sign | 1024 | 255 | 61.467761 | 0.981728 | 60.643809 | 63.466778 |
| v2 | cold-sign | 1024 | 255 | 62.918408 | 7.482846 | 61.116109 | 83.446146 |
| v1 | prepared-sign | 1024 | 255 | 33.581891 | 5.077934 | 33.422138 | 49.066246 |
| v2 | prepared-sign | 1024 | 255 | 33.728600 | 2.050491 | 33.369259 | 39.673114 |
| v1 | prepared-verify | 1024 | 255 | 86.634671 | 11.364428 | 85.966977 | 121.054563 |
| v2 | prepared-verify | 1024 | 255 | 86.847382 | 8.917694 | 86.049576 | 113.406448 |
| v1 | import-verify | 1024 | 255 | 184.635765 | 21.380344 | 183.106433 | 237.585251 |
| v2 | import-verify | 1024 | 255 | 150.955829 | 7.302622 | 150.241360 | 170.664670 |
| v1 | cold-sign | 16384 | 0 | 122.807025 | 11.675767 | 119.193766 | 156.778522 |
| v2 | cold-sign | 16384 | 0 | 119.699229 | 19.405257 | 118.782042 | 169.598336 |
| v1 | prepared-sign | 16384 | 0 | 91.060567 | 13.495787 | 90.624458 | 132.048849 |
| v2 | prepared-sign | 16384 | 0 | 92.039501 | 7.189084 | 90.674653 | 108.302441 |
| v1 | prepared-verify | 16384 | 0 | 116.165613 | 20.592067 | 115.489887 | 178.284249 |
| v2 | prepared-verify | 16384 | 0 | 115.019045 | 4.204376 | 114.615424 | 125.683472 |
| v1 | import-verify | 16384 | 0 | 214.171946 | 6.155526 | 212.591315 | 230.989084 |
| v2 | import-verify | 16384 | 0 | 181.437949 | 23.686476 | 178.202820 | 252.512584 |
| v1 | cold-sign | 16384 | 16 | 119.466073 | 6.955209 | 118.069103 | 140.092249 |
| v2 | cold-sign | 16384 | 16 | 119.892663 | 4.025760 | 118.742759 | 129.986123 |
| v1 | prepared-sign | 16384 | 16 | 91.062992 | 1.311810 | 90.469645 | 94.599308 |
| v2 | prepared-sign | 16384 | 16 | 92.128677 | 3.196738 | 90.560932 | 100.484584 |
| v1 | prepared-verify | 16384 | 16 | 118.472156 | 10.071045 | 115.360948 | 147.476827 |
| v2 | prepared-verify | 16384 | 16 | 116.309743 | 9.344374 | 115.587607 | 144.570743 |
| v1 | import-verify | 16384 | 16 | 216.105654 | 17.972939 | 212.684965 | 269.310275 |
| v2 | import-verify | 16384 | 16 | 181.926504 | 22.889595 | 180.053188 | 248.529640 |
| v1 | cold-sign | 16384 | 255 | 121.050286 | 15.966964 | 119.470732 | 168.508096 |
| v2 | cold-sign | 16384 | 255 | 122.199119 | 25.329964 | 119.649350 | 193.948882 |
| v1 | prepared-sign | 16384 | 255 | 92.817836 | 11.505585 | 91.661226 | 127.292894 |
| v2 | prepared-sign | 16384 | 255 | 91.999693 | 5.711293 | 91.585615 | 106.048399 |
| v1 | prepared-verify | 16384 | 255 | 119.165729 | 16.604500 | 115.501851 | 167.676881 |
| v2 | prepared-verify | 16384 | 255 | 117.475167 | 13.413954 | 116.009120 | 157.765644 |
| v1 | import-verify | 16384 | 255 | 217.947905 | 30.228315 | 212.164911 | 306.986769 |
| v2 | import-verify | 16384 | 255 | 183.089815 | 23.017892 | 180.693239 | 251.803716 |
| v1 | prepare-verifier | 0 | 0 | 26.882896 | 4.522572 | 26.330713 | 38.115989 |
| v2 | prepare-verifier | 0 | 0 | 26.209609 | 2.553162 | 25.781836 | 33.738075 |

## Arithmetik-Mikrobenchmarks

Receipt: `/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_final_02_2026-09-10/ED301-v2_microbench_t6jpj9uj`.

SHA-256: `f3472628fb15e0d54f95aef619399118312e29718475fc4f10e5af9c4ff10f69`.

Identischer privater Harness auf unveränderten Modulquellen, 16 rotierende Operanden und Kopierkontrolle. Loop, Operandenwahl, black_box und Ergebnis-Drop sind enthalten. Kein Produkt-API- oder Seitenkanal-Gate. field-mul-d misst weiterhin den ursprünglichen einzelnen Feldoperator, nicht den algebraischen E5-Gesamtgewinn.

| Version | Operation | Median ns | SD ns | Min ns | Max ns |
| --- | --- | --- | --- | --- | --- |
| v1 | control-field-copy | 1.268000 | 0.016263 | 1.259000 | 1.313000 |
| v2 | control-field-copy | 1.266000 | 0.011314 | 1.259000 | 1.296000 |
| v1 | field-add | 7.009000 | 0.178434 | 6.948000 | 7.519000 |
| v2 | field-add | 6.679000 | 0.144744 | 6.561000 | 7.022000 |
| v1 | field-sub | 6.047000 | 0.094198 | 5.937000 | 6.242000 |
| v2 | field-sub | 5.946000 | 0.043898 | 5.876000 | 6.009000 |
| v1 | field-mul | 26.027000 | 0.374843 | 25.615000 | 26.800000 |
| v2 | field-mul | 25.370000 | 0.585772 | 25.061000 | 26.638000 |
| v1 | field-square | 24.944000 | 0.470064 | 24.662000 | 26.098000 |
| v2 | field-square | 25.248000 | 0.692169 | 24.818000 | 27.014000 |
| v1 | field-mul-301 | 10.928000 | 0.455397 | 10.707000 | 12.195000 |
| v2 | field-mul-301 | 11.230000 | 0.893760 | 10.969000 | 13.840000 |
| v1 | field-mul-a | 11.221000 | 0.121981 | 11.000000 | 11.418000 |
| v2 | field-mul-a | 10.033000 | 0.152598 | 9.882000 | 10.308000 |
| v1 | field-mul-d | 11.002000 | 0.149214 | 10.724000 | 11.133000 |
| v2 | field-mul-d | 15.156000 | 0.200379 | 14.904000 | 15.476000 |
| v1 | field-invert | 2757.504000 | 71.179636 | 2672.735000 | 2894.099000 |
| v2 | field-invert | 2719.577000 | 46.987736 | 2700.323000 | 2847.451000 |
| v1 | field-sqrt-ratio | 9374.724000 | 715.627968 | 9224.340000 | 11453.203000 |
| v2 | field-sqrt-ratio | 9154.750000 | 1260.110003 | 9047.794000 | 12954.475000 |
| v1 | lazy-mul | 21.553000 | 0.942239 | 21.440000 | 24.301000 |
| v2 | lazy-mul | 22.148000 | 0.930606 | 21.421000 | 24.424000 |
| v1 | lazy-square | 21.412000 | 2.544041 | 20.254000 | 28.416000 |
| v2 | lazy-square | 21.301000 | 4.471683 | 20.128000 | 34.263000 |
| v1 | lazy-mul-a | 6.627000 | 0.048598 | 6.593000 | 6.739000 |
| v2 | lazy-mul-a | 6.614000 | 0.062444 | 6.567000 | 6.757000 |
| v1 | lazy-loose-mul | 25.687000 | 0.369189 | 25.453000 | 26.655000 |
| v2 | lazy-loose-mul | 26.703000 | 0.370829 | 26.497000 | 27.624000 |
| v1 | scalar-add | 4.836000 | 0.124678 | 4.779000 | 5.176000 |
| v2 | scalar-add | 4.833000 | 0.025065 | 4.802000 | 4.883000 |
| v1 | scalar-mul | 116.282000 | 10.042666 | 115.157000 | 146.352000 |
| v2 | scalar-mul | 117.160000 | 14.146327 | 114.779000 | 159.656000 |
| v1 | scalar-reduce-pruned | 60.992000 | 1.094654 | 60.076000 | 63.479000 |
| v2 | scalar-reduce-pruned | 62.016000 | 8.654864 | 60.425000 | 87.427000 |
| v1 | scalar-reduce-hash | 157.403000 | 30.124820 | 153.407000 | 247.737000 |
| v2 | scalar-reduce-hash | 154.173000 | 12.695063 | 152.403000 | 192.621000 |
| v1 | scalar-wnaf-public | 601.307000 | 16.145622 | 587.705000 | 630.549000 |
| v2 | scalar-wnaf-public | 596.146000 | 142.430733 | 586.827000 | 1021.933000 |
