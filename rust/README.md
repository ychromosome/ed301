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

## Hash backends and platform coverage

Ed301 uses the vendored `shake`/`keccak` implementation. With the default
build configuration, Keccak uses its software backend on x86-64. On AArch64
it selects the SHA3-intrinsics backend when the public CPU feature is present,
otherwise the software backend. The local `forbid(unsafe_code)` rule does not
extend to dependencies or forbid their intrinsics.

The recorded E8 measurements and codegen acceptance cover their named x86-64
binaries and toolchain. Their statements about no added assembler/SIMD do
not establish that every dependency on every architecture uses scalar code.
An AArch64 release needs its own whole-signing-path checks, including both
Keccak dispatch outcomes. CPU-based dispatch alone is not a demonstrated
secret-dependent branch or timing leak.

The dependency supports `keccak_backend="soft"` as an explicit build option;
the project does not force it. That option still requires separate binary
acceptance and does not prohibit compiler auto-vectorization. Cargo settings
must be applied to each intended core/provider build; the controlled runners
generate their own Cargo configuration.

`sign-self-verify` adds verification before returning a signature.
`secret-taint-instrumentation` is a diagnostic feature for the controlled
Valgrind harness, not a normal distribution feature.

The [Phase-E runner](../phase-e/README.md) checks both cores, feature variants,
generated parameters, field bounds, dependency integrity, release-profile
markers, Clippy, formatting and a downstream `no_std` consumer. Historical
Phase-C results describe the original signature core, not the current
optimized binary.
