# Fedora 45 RPMs

Ed301 and X301 share one software package. Version `0.2.0` is the provider
software version; the cryptographic profile identifier remains v2.

| Package | Purpose |
| --- | --- |
| `openssl-provider-ed301` | Four ordinary/TLS provider modules; inactive when installed alone |
| `openssl-provider-ed301-policy` | Loads the two TLS-capable modules through Fedora's OpenSSL configuration hook |
| `ed301` | Meta-package requiring both packages at the same version/release |

The policy does not change Fedora's selected crypto-policy or OpenSSL's
`DEFAULT` groups. Applications must select `X301MLKEM1024` explicitly to
require the hybrid. v1 packages conflict with these candidates; this is not
an automatic or wire-compatible v1 migration.

## Source and build

[`openssl-provider-ed301.spec`](openssl-provider-ed301.spec) pins source
commit `1ebf575a43ad60dec3efdd4ec5363c15753e33ec` and its archive digest.
Create `Source0` with `git archive --format=tar.gz` and prefix
`ed301-1ebf575a43ad60dec3efdd4ec5363c15753e33ec/` from that exact commit.
The packaging patch permits Fedora's native build flags through an explicit
opt-in; it does not change cryptographic arithmetic or provider runtime code.

The spec builds x86-64 modules and noarch policy/meta packages with vendored
dependencies. It excludes diagnostic/failpoint variants. `%check` runs the
Rust suites and [`check-rpm.py`](check-rpm.py); installed-package activation
and TLS checks were performed separately in the isolated Fedora build root.

## Candidate results, 12 September 2026

NVR: `0.2.0-0.1.20260912git1ebf575.fc45`.
Toolchain: Rust 1.97.1 / LLVM 22.1.8; OpenSSL 4.0.1.

| Check | Result |
| --- | --- |
| RPM build and Rust tests | PASS; 214 test executions |
| Functional controller | PASS; 56 steps |
| Installed software, meta-policy activation and policy removal | PASS |
| Installed TLS/TCP integration | PASS; 95 checks |
| rpmlint | 0 errors; 1 warning for the local Git-archive Source0 URL |
| Four existing LLVM-21 codegen gates | FAIL on the new compiler output; later checks not reached |

The RPMs remain test candidates pending acceptance of their actual compiler
output and fresh binary-bound side-channel checks. No allowlist was relaxed.
The workstation was not activated, and no RPMs were signed or published.

Full results, package hashes and source/binary bindings:
/home/martin/Dokumente/ED301/03_Ed301-EdDSA-v2/RPM/Fedora45_2026-09-12/ERGEBNIS.md
