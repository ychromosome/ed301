# Benchmarks

Measured on 2026-10-16 from this source tree: AMD Ryzen 9 5950X, x86-64,
Fedora 45 (kernel 7.2.8), rustc 1.99.0, OpenSSL 4.0.3, governor `powersave`,
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
| Ed301 key expansion | 28.1 (27.9) |
| Ed301 sign (prepared key) | 29.3 (29.1) |
| Ed301 verify (prepared key) | 68.8 (68.7) |
| Ed301 public-key import | 44.6 (44.5) ¹ |
| X301 public key from secret | 28.0 (27.8) |
| X301 shared secret | 58.3 (58.2) |
| X301 public-key import | 0.005 (0.005) |

¹ Re-measured on 2026-10-17 with the same method after the subgroup check
dropped its redundant first Euler symbol (50.4 µs before). The other rows
are unaffected by that change and were not re-measured.

Ed301 public-key import includes the full prime-order subgroup check. X301
public-key import is only the canonical-encoding check; the small-order and
all-zero checks happen in the shared-secret computation.

## OpenSSL EVP

The same measurement through the EVP API, with the provider modules of this
tree. Ed25519, Ed448, X25519 and X448 are OpenSSL's built-in implementations
and serve as reference points.

| Signature | Keygen | Sign | Verify |
| --- | ---: | ---: | ---: |
| Ed25519 | 28.4 (28.4) | 28.2 (28.1) | 78.1 (76.6) |
| Ed301 | 30.2 (29.9) | 30.0 (29.9) | 69.0 (67.2) |
| Ed448 | 161.1 (160.5) | 162.7 (162.1) | 176.9 (176.3) |

| Key exchange | Keygen | Derive (steady state) |
| --- | ---: | ---: |
| X25519 | 28.0 (28.0) | 23.7 (23.6) |
| X301 | 29.7 (29.5) | 58.3 (58.3) |
| X448 | 159.8 (159.1) | 169.7 (168.3) |

X301 derivation takes about 2.5 times as long as X25519. For comparison,
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
