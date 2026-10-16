# Ed301-EdDSA and X301

Experimental digital signatures (Ed301-EdDSA) and key exchange (X301) over a
301-bit prime field, with Rust implementations and OpenSSL providers. The
algorithms are not standardized and not intended for production use.

**Author:** Martin Wolf. **Co-authors:** OpenAI ChatGPT and Anthropic Claude
(AI assistants). See [NOTICE](NOTICE).

## Overview

- **Ed301-EdDSA-v2:** deterministic EdDSA-style signatures with SHAKE256;
  38-byte seeds and public keys, 76-byte signatures, binary contexts of 0–255
  bytes. [Specification](specifications/Ed301-EdDSA-v2.md).
- **X301-v2:** raw Diffie–Hellman on the Montgomery form; 38-byte secrets and
  public values, strictly canonical peer inputs, a full 301-step ladder and
  mandatory all-zero rejection. [Specification](specifications/X301-v2.md).
- **Rust cores:** `no_std`, `#![forbid(unsafe_code)]`, secret-independent
  control flow on secret paths.
- **OpenSSL providers** for OpenSSL 3.5 and 4.0: key management, signatures,
  key exchange, DER/PEM codecs and TLS 1.3, including the `X301MLKEM1024`
  hybrid with ML-KEM-1024. [Integration](docs/INTEGRATION.md).

Both algorithms are classical, not post-quantum. X301 output is raw DH
material and needs a KDF and authentication around it.

## The curve

`a·x² + y² = 1 + d·x²·y²` over `F_p`:

| Parameter | Value |
| --- | --- |
| `p` | `2^301 − 2^89 + 907` |
| `a`, `d` | `247399²`, `−301` |
| Order | `4q`, `q` prime of 300 bits |
| Twist order | `4q_t`, `q_t` prime of 299 bits |
| Generic attack cost | about `2^149.3` group operations (Pollard rho) |

The coefficient `a` is the first candidate of a published, signed selection
rule; primality certificates, the search record and scripts to check every
value are in [`math/`](math). See [the mathematics](docs/MATHEMATICS.md).

## Repository layout

| Path | Contents |
| --- | --- |
| `specifications/` | Byte-level specifications of both algorithms |
| `docs/` | [Mathematics](docs/MATHEMATICS.md), [OpenSSL integration](docs/INTEGRATION.md), [benchmarks](docs/BENCHMARKS.md) |
| `math/` | Parameter file, selection rule and search tools, certificates, verification scripts |
| `rust/crates/` | `ed301-eddsa` (signatures) and `x301` (key exchange) |
| `rust/vendor/` | Patched forks of `crypto-bigint` and `cpufeatures` |
| `rust/performance/`, `benchmarks/` | Benchmark harnesses and runner |
| `rust/secret-taint/`, `rust/x301-secret-taint/` | Valgrind secret-taint harnesses |
| `provider/`, `provider-tests/` | OpenSSL providers and their C test suite |
| `reference/`, `tests/` | Python reference implementations and their tests |
| `vectors/` | Test vectors |
| `tools/` | Generators for embedded constants and test vectors |

## Building and testing

Requirements: Rust 1.91 or later, Python 3.10 or later, gcc, OpenSSL 3.5.7+
or 4.0.1+ with headers, and access to crates.io. Valgrind with its headers is
needed for the taint harnesses.

```sh
# Rust cores
cd rust
cargo test --release --locked
cargo test --release --locked --features sign-self-verify
cargo test --release --locked --manifest-path crates/x301/Cargo.toml
cd ..

# Python references
python3 -B -m unittest discover -s tests

# OpenSSL providers: nine module builds and the C test suite
python3 -I provider-tests/run.py --workdir /tmp/ed301-provider

# Secret-dependent branches and memory accesses, under Valgrind
python3 -I rust/run_secret_taint.py
```

On the current tree these run 71 Ed301 tests in each configuration, 63 X301
tests, 29 Python tests, 111 provider build and test steps, and 562 Valgrind
runs.

## Performance

AMD Ryzen 9 5950X, one core, microseconds (median of 9 runs):

| Operation | Ed301 / X301 | Ed25519 / X25519 | Ed448 / X448 |
| --- | ---: | ---: | ---: |
| Sign (EVP) | 30.0 | 28.2 | 162.7 |
| Verify (EVP) | 69.0 | 78.1 | 176.9 |
| Key exchange, derive (EVP) | 58.3 | 23.7 | 169.7 |

Details and the method are in [benchmarks](docs/BENCHMARKS.md).

## Security notes

- Secret-dependent code paths are written to be constant-time and are checked
  with the Valgrind taint harnesses above. Whether a particular compiled
  binary is constant-time depends on the compiler and target and is not
  established in general.
- Public-key import and signature verification run in variable time on
  public data only.
- Secret values are zeroized by their owning types; temporary copies made by
  the compiler or inside dependencies are not guaranteed to be erased.
- No independent third-party audit is claimed.

## License

Apache-2.0. See [LICENSE](LICENSE), [NOTICE](NOTICE) and the
[third-party notices](rust/THIRD_PARTY_NOTICES.md).
