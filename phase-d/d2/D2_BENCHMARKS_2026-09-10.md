# D2-Benchmarkauszug

Stand: 10. September 2026. Beide ABI-Lanes sind vollständig bestanden: je 128
Fälle und neun rotierte Wiederholungen, insgesamt 2.304 ausgewertete Messblöcke
zusätzlich zu Kalibrierung und Ressourcenstichproben. Plattform: AMD Ryzen 9
5950X, native x86-64, CPU 2, Governor unverändert `powersave`.

Jede Zelle nennt **Median / Standardabweichung in Mikrosekunden** über die neun
Blockmittelwerte. Die Standardabweichung ist keine Fehlerschranke des Medians.
Alle 128 Fälle einschließlich Ed25519/Ed448/X25519/X448/ML-KEM-1024, Min/Max,
Mittelwerte, Fallzahlen und Rohwerte stehen in den beiden vollständigen Receipts:

- /home/martin/Dokumente/ED301/ED301-v2_D2-matrix_2026-09-10_06/benchmarks-3.5.8,
  Manifest-SHA-256 `d0e8cdfac1eda3c1550ba83fa22639514e5460cf9f2271359ce910541b07ecbc`.
- /home/martin/Dokumente/ED301/ED301-v2_D2-matrix_2026-09-10_06/benchmarks-4.0.2,
  Manifest-SHA-256 `041353414ee0cce5f28007cecf056c3037da90e3319562a25e44b4aca2439496`.

| Fall | 3.5.8 v1 | 3.5.8 v2 | 4.0.2 v1 | 4.0.2 v2 |
| --- | ---: | ---: | ---: | ---: |
| Rust-Ed sign | 28.73 / 1.99 | 28.78 / 2.56 | 29.11 / 0.69 | 28.66 / 0.72 |
| Rust-Ed verify | 85.41 / 1.45 | 84.37 / 1.28 | 86.09 / 1.79 | 88.29 / 3.64 |
| Rust-X public | 27.35 / 2.04 | 80.56 / 0.75 | 27.33 / 0.54 | 80.86 / 0.54 |
| Rust-X shared | 56.56 / 0.77 | 80.56 / 1.10 | 57.55 / 0.75 | 80.74 / 3.33 |
| EVP Ed301 keygen | 56.88 / 2.02 | 56.31 / 0.75 | 56.14 / 0.95 | 56.17 / 0.64 |
| EVP Ed301 sign | 29.60 / 0.33 | 29.58 / 0.44 | 29.28 / 0.25 | 29.35 / 0.47 |
| EVP Ed301 verify | 86.01 / 1.55 | 84.96 / 2.94 | 86.37 / 1.57 | 84.89 / 0.98 |
| EVP X301 derive-steady | 57.46 / 0.61 | 80.74 / 1.49 | 56.95 / 0.44 | 80.65 / 1.07 |
| EVP Hybrid keygen | 67.02 / 0.81 | 121.19 / 2.00 | 67.60 / 1.23 | 120.08 / 1.08 |
| EVP Hybrid encaps | 105.56 / 1.34 | 182.45 / 2.23 | 105.52 / 6.49 | 184.03 / 4.30 |
| EVP Hybrid decaps | 87.79 / 2.32 | 111.08 / 5.55 | 87.17 / 1.35 | 111.08 / 8.43 |
| EVP Ed301 encode-private-DER | 39.80 / 0.33 | 55.22 / 0.51 | 23.18 / 0.21 | 32.49 / 0.29 |
| EVP Ed301 decode-private-DER | 59.33 / 1.01 | 58.78 / 0.69 | 58.22 / 3.64 | 58.88 / 1.39 |
| TLS Ed301 + X25519 | 497.26 / 25.61 | 491.70 / 6.65 | 473.13 / 4.56 | 477.17 / 6.09 |
| TLS Ed301 + Hybrid | 696.78 / 8.35 | 848.64 / 9.97 | 687.37 / 11.28 | 832.49 / 4.75 |
| TLS Ed301 + Raw-X301 | nicht vorhanden | 722.69 / 17.66 | nicht vorhanden | 711.73 / 21.76 |

Ed301-KeyGen/Sign/Verify über EVP liegen nahe v1. X301-Public ist wegen des
unveränderten D1-Pfades ungefähr dreimal so teuer wie v1; Shared bleibt etwa
40–42 % darüber. Auch die Hybridkosten und der vollständige Ed301-Hybrid-
Handshake steigen entsprechend. Für Ed301-DER-Encoding zeigt sich unabhängig
davon ein Mehrbedarf von ungefähr 39–40 %; der Decoder bleibt nahe v1.
Das ist ein offener Performancebefund, keine nachgewiesene Ursachenanalyse und
kein Anlass, die gesondert freizugebende Optimierung in D2 vorzuziehen.

Die Ebenen sind nicht untereinander als Algorithmusvergleiche zu lesen. Rust-
Kern und EVP messen unterschiedliche Arbeit; TLS umfasst zwei Endpunkte,
Protokoll-/Zertifikatsarbeit und SSL/BIO-Allokation/Freigabe. SSL_CTX ist warm,
Resumption aus, Transport Memory-BIO. Die Zeiten sind keine TCP-Latenzen.
Codecs messen Kontextaufbau und -abbau mit; die strikte Complete-file-Vorprüfung
ist separat getestet und nicht zusätzlich in diese Codeczeiten eingerechnet.

Historische v1-Profile bleiben erhalten, insbesondere X301-v1 C O0 und die
crypto-bigint-Overflow-Ausnahme; v2 hat C O3 und alle Rust-Crates Overflow-on.
Kalibrierung: 200 ms Ziel, 100 bis 1.000.000 Operationen. Sehr schnelle Fälle
können deshalb unter der Zieldauer liegen. Es gab kein Host-Tuning und keine
parallele zweite Messlane; normale Hintergrundlast ist in den Identitäten
protokolliert. Aus diesen neun Wiederholungen folgt keine produktübergreifende
Reproduzierbarkeits- oder Regressionsfreigabe.

Als Ressourcenstichprobe meldet GNU time unter 3.5.8 für Ed301-v2-Sign 8.260,
für X301-v2-Derive 7.548 und für Ed301-v2+Hybrid 10.192 kbytes MaxRSS. Das sind
Prozesswerte einschließlich OpenSSL, keine isolierten Providerallokationen.
Die ordinary/TLS-DSOs messen unter 3.5.8 für Ed301 615.264/639.832 und für
X301 458.704/493.328 Byte. Alle Modulsektionen und Ressourcenaufrufe beider
ABIs sind in den Receipts enthalten; diese Auswahl ersetzt sie nicht.
