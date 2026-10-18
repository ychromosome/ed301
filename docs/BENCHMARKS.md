# Benchmarks

Measured on 2026-10-19 from this source tree: AMD Ryzen 9 5950X, x86-64,
Fedora 45 (kernel 7.2.11), rustc 1.99.1, OpenSSL 4.0.3, libsodium 1.0.22,
governor `powersave`,
boost unchanged, other host load not excluded. The Rust cores and provider
modules use `opt-level = 3`, thin LTO, one codegen unit, `panic = "unwind"` and
overflow checks.

Each case ran 9 times pinned to CPU 2. Each run used an iteration count
calibrated to about 200 ms and reports its mean. Values are the median (and
minimum) of the 9 run means, in microseconds. These are throughput means, not
per-call latency percentiles.

## Rust core

libsodium is the optimized Ed25519/X25519 reference: 64-bit field
arithmetic, and x86-64 assembly for X25519. There is no comparable Ed448
library; OpenSSL's Ed448 below is Mike Hamburg's Goldilocks code.

| Operation | Ed301 / X301 | Ed25519 / X25519 (libsodium) |
| --- | ---: | ---: |
| Key expansion | 23.2 (23.1) | 12.2 (12.1) |
| Sign | 24.9 (24.3) | 13.1 (13.0) |
| Verify | 68.0 (67.9) | 40.1 (39.1) |
| Public-key import | 44.0 (43.6) | 28.2 (27.9) |
| X public key from secret | 22.0 (21.9) | 11.9 (11.9) |
| X shared secret | 57.7 (57.6) | 23.1 (23.1) |
| X public-key import | 0.005 (0.005) | – |

libsodium is about twice as fast throughout, although Ed301 signs and
verifies with a prepared key: libsodium hashes the seed on every signature
and decodes the public key on every verification. Ed301 public-key import
includes the full prime-order subgroup check and builds the verification
table; libsodium's `crypto_core_ed25519_is_valid_point` checks the encoding,
the curve and the subgroup. X301 public-key import is only the
canonical-encoding check; the small-order and all-zero checks happen in the
shared-secret computation.

## OpenSSL EVP

The same measurement through the EVP API, with the provider modules of this
tree. Ed25519, Ed448, X25519 and X448 are OpenSSL's built-in implementations
and serve as reference points. OpenSSL computes Ed25519 and the X25519 public
key with the 32-bit ref10 field arithmetic and the X25519 shared secret with
x86-64 assembly; that is why Ed301 is faster than OpenSSL's Ed25519 here but
not than libsodium.

| Signature | Keygen | Sign | Verify |
| --- | ---: | ---: | ---: |
| Ed25519 | 28.2 (28.2) | 27.8 (27.7) | 77.5 (76.7) |
| Ed301 | 25.0 (25.0) | 24.9 (24.9) | 68.0 (67.5) |
| Ed448 | 160.7 (160.3) | 162.7 (162.1) | 177.4 (175.9) |

| Key exchange | Keygen | Derive (steady state) |
| --- | ---: | ---: |
| X25519 | 27.8 (27.7) | 23.6 (23.6) |
| X301 | 23.7 (23.6) | 57.8 (57.8) |
| X448 | 159.7 (158.9) | 168.2 (166.8) |

X301 derivation takes about 2.4 times as long as X25519. X301 runs 301
ladder steps over a 301-bit field in portable Rust; X25519 runs 255 steps
over a 255-bit field in assembly. Ed301 verification
uses a variable-time multi-scalar method on public data; signing and key
generation use constant-time fixed-base arithmetic.

## Reproducing

Build the provider modules (for example with the provider test suite, which
leaves them in its work directory), then run the measurement:

```sh
python3 -I provider-tests/run.py --workdir /tmp/ed301-provider
python3 -I benchmarks/run.py --modules /tmp/ed301-provider/modules --workdir /tmp/ed301-bench
```

`benchmarks/run.py` builds `rust/performance/ed301-bench`,
`rust/performance/x301-bench`, the EVP harnesses in `benchmarks/evp/` and the
libsodium harness in `benchmarks/native/`, then prints the tables above. Results depend on CPU, compiler, OpenSSL version and
host load.
