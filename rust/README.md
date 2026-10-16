# Rust cores

`crates/ed301-eddsa` implements Ed301-EdDSA-v2 and `crates/x301` implements
X301-v2. Both are `no_std` and forbid unsafe code. `x301` reuses the field,
curve and scalar sources of `ed301-eddsa` through `#[path]` modules; it has
its own Cargo workspace. The OpenSSL provider FFI lives in
[`../provider`](../provider).

The minimum Rust version is 1.91: the field arithmetic uses
`u64::borrowing_sub` for its branch-free borrow chain.

## Dependencies

Dependencies come from crates.io, pinned by `Cargo.lock`. Two are patched
forks kept in [`vendor/`](vendor), each with an `ED301_PATCHES.md`:

- `crypto-bigint 0.7.5`, used as a path dependency: explicit wrapping
  arithmetic in ten places so that workspace-wide overflow checks do not add
  secret-dependent panic branches;
- `cpufeatures 0.3.0`, applied with `[patch.crates-io]`: correct AArch64
  HWCAP checks for composite target features.

## Features

- `sign-self-verify` verifies each signature before returning it, as a guard
  against faults in deterministic signing.
- `secret-taint-instrumentation` is used only by the Valgrind harnesses in
  `secret-taint/` and `x301-secret-taint/`; run them with
  [`run_secret_taint.py`](run_secret_taint.py).

## Hash backend

SHAKE256 comes from the `shake`/`keccak` crates. On x86-64 they use a software
backend. On AArch64 they select the SHA-3 instructions when the CPU reports
them, otherwise software; `forbid(unsafe_code)` does not extend to
dependencies. The `keccak_backend="soft"` configuration forces the software
backend.

## Security properties

Signing, key derivation and the X301 ladder avoid branches and memory
indices that depend on secrets; the taint harnesses check this under
Valgrind for every test vector. Public-key import and verification are
variable-time and must receive public data only.
