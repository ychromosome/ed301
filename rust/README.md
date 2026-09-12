# Rust cores

`ed301-eddsa` implements v2 signatures; `x301-core` implements strict X301-v2
key exchange. Both are `no_std` and forbid unsafe Rust. Provider FFI code is
in the separate [provider workspace](../provider).

Use the offline build commands in the [project README](../README.md).
Run Cargo from this directory so that `.cargo/config.toml` selects the
vendored dependencies; keep `CARGO_HOME` and `CARGO_TARGET_DIR` outside the
checkout. The declared minimum Rust version is 1.91.

Public-key import is variable-time and must receive only public data.
Secret-key derivation and signing do not use that import path.

`sign-self-verify` adds verification before returning a signature.
`secret-taint-instrumentation` is a diagnostic feature for the controlled
Valgrind harness, not a normal distribution feature.

The [Phase-E runner](../phase-e/README.md) checks both cores, feature variants,
generated parameters, field bounds, dependency integrity, release-profile
markers, Clippy, formatting and a downstream `no_std` consumer. Historical
Phase-C results describe the original signature core, not the current
optimized binary.
