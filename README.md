# Ed301-EdDSA and X301

Experimental signatures and key exchange over a 301-bit field, with Rust
cores and OpenSSL providers. This repository implements the **v2 profiles**;
they are not wire-compatible with either earlier Ed301 generation.
The algorithms are not standardized or approved for production use.

## Features

- EdDSA-style deterministic signatures using SHAKE256: 38-byte seeds,
  38-byte public keys and 76-byte signatures; binary contexts of 0–255 bytes.
- Strict X301 key exchange: 38-byte secrets, public keys and shared secrets;
  canonical peer encodings, a full 301-round ladder and all-zero rejection.
- `no_std` Rust cores with `forbid(unsafe_code)`. The provider FFI and C
  adapters are separate from this safe-Rust boundary.
- OpenSSL key management, signing, key exchange, DER/PEM codecs and TLS 1.3
  integration, including the `X301MLKEM1024` hybrid group.
- Vendored Rust dependencies, Python references, independent Node.js vector
  checks, and source- and binary-bound verification tools.

Ed301 supports one-shot signing, not prehash or streaming modes. X301 returns
raw Diffie–Hellman output: applications still need a KDF and authentication.
Ed301 and raw X301 are classical, not post-quantum, algorithms; the hybrid
delegates ML-KEM-1024 to OpenSSL.

## Curve and provenance

The twisted Edwards curve is `a·x² + y² = 1 + d·x²·y²` over `F_p`:

| Parameter | Value |
| --- | --- |
| Field prime | `p = 2^301 − 2^89 + 907` |
| `a` | `61206265201 = 247399²` |
| `d` | `−301` |
| Curve order | `4q`, with prime `q` of 300 bits |
| Twist order | `4q_t`, with prime `q_t` of 299 bits |
| Cofactor | 4 on both curve and twist |

Compressed base point (38 bytes, hexadecimal):

```text
c67f33b932f3097533c5ebca430d01b9c000ba91025af84747afd17d6a9b242bf2b1fe6e350e
```

The generic negation-aware Pollard-rho estimate is about `2^149.326` group
operations. This is an attack-cost estimate, not a security proof.

The [frozen parameter package](provenance/phase-a/2026-09-09/README.md)
contains the full orders, certificates and independent order witnesses.
The [signed search record](provenance/v2-search/README.md) documents the
predeclared confirmation search and the exploratory work that preceded it.

## Profiles and interoperability

| Profile | Public OpenSSL name | OID | TLS private-use value |
| --- | --- | --- | --- |
| Ed301-EdDSA-v2 | `Ed301-EdDSA` | `1.3.6.1.4.1.66282.301.5` | SignatureScheme `0xFE85` |
| X301-v2 | `X301` | `1.3.6.1.4.1.66282.301.6` | NamedGroup `0xFE30` |
| X301/ML-KEM-1024 hybrid | `X301MLKEM1024` | No persistent-key OID | NamedGroup `0xFE2F` |

Both key AlgorithmIdentifiers have absent parameters, not ASN.1 NULL.
Canonical SPKI is 58 bytes; PKCS#8 version 0 is 62 bytes and retains the
original 38-byte seed/secret. The TLS values are project assignments, not
IANA registrations.

Normative contracts: [current Ed301/X301 v2 profile](specifications/CURRENT_PROFILE.md),
[identifiers](docs/OID_REGISTRY.md) and [OpenSSL integration](docs/INTEGRATION.md).
The current profile identifies the frozen mathematical/byte specifications
and supersedes their historical phase-status and future-allocation statements.

## Performance

Selected E8 measurements on an AMD Ryzen 9 5950X, x86-64, CPU 2, using
Rust 1.98.0 / LLVM 21.1.8, O3, ThinLTO and one codegen unit. Values are
microseconds, rounded to three decimals, and are medians of nine run means.
These are the recorded E8 results, not measurements of the Fedora RPMs.

### Rust core

| Operation | v1 | v2 |
| --- | ---: | ---: |
| Ed301 key expansion | 28.371 | 28.321 |
| Ed301 prepared sign | 29.047 | 29.192 |
| Ed301 prepared verify | 86.926 | 85.145 |
| Ed301 public-key import | 99.561 | 50.780 |
| X301 public-key derivation | 27.943 | 28.767 |
| X301 shared-secret derivation | 58.001 | 58.605 |

### OpenSSL EVP, 3.5.8 lane

| Signature algorithm | Keygen | Sign | Verify |
| --- | ---: | ---: | ---: |
| Ed25519 | 24.964 | 23.948 | 78.379 |
| Ed301-v1 | 56.966 | 29.880 | 87.186 |
| Ed301-v2 | 29.968 | 29.925 | 83.613 |
| Ed448 | 149.430 | 148.748 | 157.536 |

| Key exchange | Keygen | Derive, steady state |
| --- | ---: | ---: |
| X25519 | 23.943 | 23.879 |
| X301-v1 | 29.674 | 57.390 |
| X301-v2 | 29.481 | 58.146 |
| X448 | 147.212 | 120.311 |

Public-key import and EVP Ed301 key generation are substantially faster than
v1; not every v2 median is lower. All v2 builds use overflow checks; the
historical X301-v1 comparison retains its documented crypto-bigint exception
and C-O0 profile. Results depend on the platform, build and API layer.
The [full benchmark tables](phase-e/E8_FINAL_BENCHMARKS.md) include dispersion,
both OpenSSL lanes, hybrid KEM, codecs and TLS-engine measurements;
[resource measurements](phase-e/E8_FINAL_RESOURCES.md) cover size and memory.

## Build and test

The declared minimum Rust/Cargo version is 1.91. For an offline core build
from the repository root, keep Cargo's cache and build products outside the
checkout:

```sh
export CARGO_HOME="$(mktemp -d)"
export CARGO_TARGET_DIR="$(mktemp -d)"
cd rust
cargo test --locked --offline --release
cargo test --locked --offline --release --features sign-self-verify
cargo test --manifest-path crates/x301/Cargo.toml --locked --offline --release
```

This runs 65 Ed301 tests in each feature configuration and 58 X301 tests.
It is a correctness smoke test, not the complete release-profile or
side-channel gate. The [Rust guide](rust/README.md) and
[Phase-E verification guide](phase-e/README.md) cover the full checks.

Reference checks, from the repository root, require Python 3.10+ and Node.js
with SHAKE256 support:

```sh
python3 -B -m unittest discover -s tests -v
node reference/node/check_vectors.mjs
node reference/node/check_x301_vectors.mjs
node reference/node/check_x301_error_precedence.mjs
```

The Python and Node implementations are variable-time references for public
test data, not implementations for real secret keys. Historical phase
manifests and runners must be used with their recorded source snapshots.

## OpenSSL providers and Fedora packages

The ordinary modules are `ed301_eddsa_v2` and `x301_v2`; TLS-capable builds are
`ed301_eddsa_v2_tls` and `x301_v2_tls`. Normal modules have no `_test` aliases.
Load providers before creating `SSL_CTX` objects, in the same `OSSL_LIB_CTX`.
Do not co-load v1 and v2 generations in one context.

The tested E8 OpenSSL lanes are 3.5.8 and 4.0.2; the integration's minimum
supported combined-stack patch levels are 3.5.7 and 4.0.1 respectively;
[module guards differ](docs/INTEGRATION.md#versions-and-deployment). Applications select
`X301MLKEM1024` explicitly to require the hybrid. Loading providers does not
change OpenSSL's `DEFAULT` group list; raw `X301` has no ML-KEM protection.

Fedora 45 packaging combines Ed301 and X301:

| Package | Purpose |
| --- | --- |
| `openssl-provider-ed301` | Software and four modules; inactive on its own |
| `openssl-provider-ed301-policy` | Matching OpenSSL provider activation |
| `ed301` | Meta-package requiring both at the same version/release |

The [Fedora build guide](packaging/fedora/README.md) records successful
build, functional and package-activation tests. Acceptance of the actual
Fedora LLVM-22 compiler output remains open; the RPMs are test candidates.

## Review status

The [E8 review decision](phase-e/reference/e8_followup/CLAUDE_GATE_E8.md)
and [follow-up checks](phase-e/E8_REVIEW_FOLLOWUP.md) cover their recorded
sources and binaries. A later [four-pass static review](phase-e/SECURITY_DEEP_REVIEW_CLOSURE.md)
of both Rust cores and the providers reported no confirmed vulnerabilities.
It did not establish universal constant-time behaviour or complete erasure
of all secret intermediates. Codegen rules remain compiler- and
artifact-specific; see the [codegen policy](phase-e/CODEGEN_POLICY.md).

The [focused engineering assessment](docs/ASSESSMENT_20260912.md) covers
lifecycle costs, cross-version key containers and isolated ownership tests.
The [tooling follow-up](docs/TOOLING_FOLLOWUP_20260912.md) adds call/tail closure,
byte-wipe and X301 import-taint checks, with fresh provider regression runs.

Development history is on `Testing`, condensed review snapshots on `Review`;
`main` is reserved for an explicitly approved product release.

## License

Apache-2.0. See [LICENSE](LICENSE) and
[third-party notices](rust/THIRD_PARTY_NOTICES.md).
