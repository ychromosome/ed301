# Adversariales Review Ed301-EdDSA-v2 und X301-v2

Repository: `ychromosome/ed301`, Branch `Testing`, Commit `698848712662564c91015002522e242ff8c2f690` (2026-09-12).
Gelesen aus einem lokalen Clone unter `/tmp/ed301-review`. Nichts wurde gepusht, kein Pull Request.

Normativ waren `specifications/Ed301-EdDSA-v2.md`, `specifications/X301-v2.md`, `phase-b/inputs/X301-v2_EINGABEVERTRAG_2026-09-10.md` und die Gate-A-Parameter unter `provenance/phase-a/`. Implementierung unter `rust/crates/` und `provider/`, Nachweise unter `phase-c/`, `phase-d/` und `phase-e/`.

## 1. Mittel — SHAKE256 auf AArch64 nimmt die SHA3-SIMD-Implementierung

Die Ed301-Signatur hashst über das vendorte `shake`/`keccak`. Auf AArch64 schaltet `Keccak::with_backend` zur Laufzeit auf FEAT_SHA3 um, sobald das CPU-Bit gesetzt ist:

```rust
// rust/vendor/keccak/src/lib.rs:77-84
#[cfg(target_arch = "aarch64")]
if self.armv8_sha3.get() {
    #[target_feature(enable = "sha3")]
    unsafe fn aarch64_sha3_inner(f: impl BackendClosure) {
        f.call_once::<aarch64_sha3::Backend>();
    }
    return unsafe { aarch64_sha3_inner(f) };
}
```

`p1600_armv8_sha3_times2` in `rust/vendor/keccak/src/backends/aarch64_sha3.rs:56` ist die XKCP-Folge aus `veor3q_u64`, `vrax1q_u64` und `vxarq_u64`. `ed301-eddsa` bindet `shake` in `rust/crates/ed301-eddsa/Cargo.toml:25`. `rust/.cargo/config.toml` setzt `keccak_backend="soft"` nicht; das ist laut `rust/vendor/keccak/README.md` der einzige Schalter für das portable Backend.

Der E8-Lauf, der „keine Assembler-/SIMD-Erweiterung“ ausweist, ist auf einem Ryzen 9 5950X gemessen (`phase-e/E8_FINAL_BENCHMARKS.md`, Zeilen 2–6). Dort ist der AArch64-Zweig tot. Für diese Plattform gibt es keine Messung und keinen Codegen-Nachweis des Signierpfads.

## 2. Mittel — verschlüsseltes PKCS#8 steht fest auf 2048 PBKDF2-Runden

`curve301_codec_write_encrypted_pkcs8` ruft `PKCS5_pbe2_set_iv_ex` mit `PKCS5_DEFAULT_ITER` auf (`provider/common/provider_codec.h:528`). In OpenSSL 4.0.2 ist das Makro 2048 (`/usr/include/openssl/evp.h:45`). Die setzbaren Encoder-Parameter sind nur `cipher` und `properties` (`provider/common/provider_codec.h:214–216`). Eine Iterationszahl kann der Aufrufer nicht übergeben.

`provider-encoder(7)` von OpenSSL 4.0.2 kennt als Encoder-Parameter nur `cipher`, `properties` und `save-parameters` (letzteres nur für DSA). Eine Iterationszahl steht in diesem Vertrag nicht. Das Fehlen des Parameters ist deshalb kein Verstoß gegen die dort aufgezählten Namen.

Dasselbe Default liefert der eingebaute Encoder. Frisch erzeugt mit OpenSSL 4.0.2:

```text
openssl genpkey -algorithm ED25519 -aes-256-cbc -pass pass:review-only
openssl asn1parse
```

Die PBKDF2-Iteration im DER ist `INTEGER :0800`, also 2048. Dieselbe Zahl steht in einem ebenso erzeugten X25519-PEM. `openssl pkcs8 -iter` kann die Zahl für den eingebauten Weg anheben (die Manpage zeigt 1_000_000). Dieser Encoder hat den Parameter nicht. Pro Passwortversuch kostet ein Offline-Angriff 2048 HMAC-SHA256.

## 3. Niedrig — der Provider-DRBG hängt am Kindkontext, nicht an der RAND-Konfiguration der Anwendung

Beide Provider legen das Libctx mit `OSSL_LIB_CTX_new_child` an (`provider/crates/x301-provider/c/provider_shim.c:1444`, `provider/crates/ed301-eddsa-provider/c/provider_shim.c:1959`). `curve301_drbg_new` zieht den Parent aus `RAND_get0_primary(libctx)` dieses Kindkontexts (`provider/common/provider_rand.h:12`). Der Kommentar direkt darüber sagt, dass `rand.seed` und `seed_strict` der Anwendung nicht in den Kindkontext übernommen werden (`provider/crates/x301-provider/c/provider_shim.c:740–741`).

`OSSL_LIB_CTX(3)` von OpenSSL 4.0.2 zählt als gespiegelten Zustand die Provider und die Default-Properties. RAND steht nicht dabei. Schlüssel entstehen weiter aus dem Primary-DRBG des Kindkontexts und damit aus dessen Seed-Quelle. Eine Anwendung, die am Elternkontext eine andere Seed-Quelle oder `seed_strict` festlegt, bindet damit diese Schlüssel nicht. Einen abweichenden Bytestrom mit geladenem Provider hat dieses Review nicht gefahren.

## Gerechnet, ohne weiteren Befund

Gate-A-Datei `provenance/phase-a/2026-09-09/parameter/ed301-v2.json`, unabhängig in Python nachgerechnet:

- `p = 2^301 - 2^89 + 907`, `a = 247399²`.
- `A24_minus = (A-2)/4 = d/(a-d)`. Die fünf Wörter in `rust/crates/x301/src/x_generated_parameters.rs:9` sind das Little-Endian dieser Zahl. Die Produktionsleiter skaliert mit `a-d` und `|d|` (`rust/crates/x301/src/x301.rs:19–22` und `291–296`); das ist dieselbe Größe.
- `N_t` liegt im Clamp-Intervall, ist durch 4 teilbar, `2·N_t` und `4q` liegen außerhalb. `chi(d·(a-d)) = +1` und `chi(B) = -1`, die Voraussetzung des halvierungsfreien Untergruppentests.
- Die Prüfgleichung in `rust/crates/ed301-eddsa/src/signature.rs:200–207` ist `4([S]B - [k]A - R) = O`, also `[4S]B = [4]R + [4k]A`.
- Die PKCS#8- und SPKI-Präfixe sind 62 und 58 Byte, AlgorithmIdentifier ohne NULL, OID-Ende `.301.5` bzw. `.301.6`.

Heiße Pfade aus dem E8-Lauf auf dem Ryzen, Median in µs, nicht hier wiederholt: Signieren Ed301-v2 29,93 gegen v1 29,88, Ed25519 23,95, Ed448 148,75. Prüfen 83,61 gegen 87,19, 78,38 und 157,54. X301-`derive-steady` 58,15 gegen v1 57,39, X25519 23,88 und X448 120,31. Receipt-SHA-256 `721c2c5a5bf87ad4aa4e7764ee0fa3dabc8643cc7c03efda371604359d5919c2`.
