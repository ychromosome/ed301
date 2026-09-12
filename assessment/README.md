# Focused engineering assessments

These tools measure lifecycle costs, check the agreed OpenSSL container
surface, and exercise the provider's actual `Shared<T>` implementation.
They do not change cryptographic parameters or provider runtime code.
Results belong outside the checkout.

## Performance

Reuse the source-bound runners with immutable source trees and clean v1
baselines. Each runner records compiler/profile, CPU, raw repetitions and
source/binary hashes:

- [Ed301 lifecycle matrix](../phase-c/tools/run_core_matrix.py)
- [Field/scalar microbenchmarks](../phase-c/tools/run_core_microbenchmarks.py)
- [X301 public/raw/prepared operations](../phase-d/tools/run_x301_benchmarks.py)

Run measurements serially. An isolated operation cost does not establish
the end-to-end benefit of a different curve representation.

## Container exchange

From the repository root:

```sh
python3 -I -B assessment/interop.py --evidence "$FUNCTIONAL_RECEIPTS" --output "$NEW_RESULTS"
```

The evidence directory must contain the two authenticated `functional-*`
receipts listed in [the review index](../docs/REVIEW_FOLLOWUP_20260912.json).
The tool checks that their compiled inputs still match the current source.
It creates new test keys and process-local configurations, then checks both
same-version and cross-version imports for Ed301 and X301. Public identities
and original private bytes must survive each accepted roundtrip.

Canonical DER/PEM, CRLF, encrypted PKCS#8 and PKCS#12 are supported test cases.
Attributes, OneAsymmetricKey, NULL parameters and outer extra material are
separate boundary observations; the strict profile is not widened.

## Ownership

[The standalone crate](shared/Cargo.toml) directly includes
[the production allocation module](../provider/common/allocation.rs).
There is no copied implementation and no external crate dependency.

Prepare a dated official Miri toolchain with separate `CARGO_HOME` and
`RUSTUP_HOME`, without modifying the host PATH or default toolchain. Run
`cargo miri setup` in that isolated environment, then:

```sh
python3 -I -B assessment/run_shared.py --toolchain-root "$ISOLATED_TOOLCHAIN" --output "$NEW_RESULTS"
```

The runner uses native release tests, 16 Miri seeds for each of the default
and Tree Borrows modes, controlled allocator failures, and compile-fail
Send/Sync checks. Provenance, alignment and race detectors remain enabled.
These are bounded executions, not an exhaustive proof of soundness or
optimized secret-memory erasure. See [Miri's limitations](https://github.com/rust-lang/miri#readme).
