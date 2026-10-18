# Benchmarks

Measured on 2026-10-19 from this source tree: AMD Ryzen 9 5950X, x86-64,
Fedora 45 (kernel 7.2.11), rustc 1.99.1, OpenSSL 4.0.3, governor `powersave`,
boost unchanged, other host load not excluded. The Rust cores and provider
modules use `opt-level = 3`, thin LTO, one codegen unit, `panic = "unwind"` and
overflow checks.

Each case ran 9 times pinned to CPU 2. Each run used an iteration count
calibrated to about 200 ms and reports its mean. Values are the median (and
minimum) of the 9 run means, in microseconds. These are throughput means, not
per-call latency percentiles.

## Rust core

| Operation | Median (min) µs |
| --- | ---: |
| Ed301 key expansion | 23.5 (23.1) |
| Ed301 sign (prepared key) | 24.2 (24.0) |
| Ed301 verify (prepared key) | 69.6 (68.0) |
| Ed301 public-key import | 43.8 (43.6) |
| X301 public key from secret | 22.0 (21.9) |
| X301 shared secret | 57.9 (57.7) |
| X301 public-key import | 0.006 (0.005) |

Ed301 public-key import includes the full prime-order subgroup check. X301
public-key import is only the canonical-encoding check; the small-order and
all-zero checks happen in the shared-secret computation.

## OpenSSL EVP

The same measurement through the EVP API, with the provider modules of this
tree. Ed25519, Ed448, X25519 and X448 are OpenSSL's built-in implementations
and serve as reference points.

| Signature | Keygen | Sign | Verify |
| --- | ---: | ---: | ---: |
| Ed25519 | 28.2 (28.2) | 28.5 (28.2) | 78.0 (77.1) |
| Ed301 | 25.6 (25.0) | 25.1 (24.9) | 68.9 (67.8) |
| Ed448 | 160.4 (159.4) | 161.4 (160.8) | 186.4 (175.8) |

| Key exchange | Keygen | Derive (steady state) |
| --- | ---: | ---: |
| X25519 | 27.7 (27.6) | 23.6 (23.5) |
| X301 | 23.6 (23.5) | 57.6 (57.5) |
| X448 | 158.4 (157.5) | 171.2 (166.1) |

X301 derivation takes about 2.4 times as long as X25519. For comparison,
X301 runs 301 ladder steps over a 301-bit field in portable Rust; X25519 runs
255 steps over a 255-bit field in OpenSSL's own implementation. Ed301 verification
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
`rust/performance/x301-bench` and the EVP harnesses in `benchmarks/evp/`, then
prints the tables above. Results depend on CPU, compiler, OpenSSL version and
host load.
