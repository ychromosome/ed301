# Third-party notices

Rust dependencies are fetched from crates.io and pinned with checksums in
each `Cargo.lock`. Two crates are included as patched forks under
[`vendor/`](vendor); each keeps its upstream license files, Cargo metadata
and an `ED301_PATCHES.md` describing the local changes.

Direct dependencies and their declared licenses:

| Crate | Role | License |
| --- | --- | --- |
| `crypto-bigint 0.7.5` (fork) | Big-integer and Montgomery arithmetic | Apache-2.0 OR MIT |
| `cpufeatures 0.3.0` (fork) | CPU feature detection, via `keccak` | Apache-2.0 OR MIT |
| `shake 0.1.0` | SHAKE256 | MIT OR Apache-2.0 |
| `zeroize 1.9.0` | Erasing secrets | Apache-2.0 OR MIT |
| `cc 1.2.66` | Build dependency of the providers and the Valgrind client | MIT OR Apache-2.0 |
| `serde_json 1.0.150` | Tests only | MIT OR Apache-2.0 |

Transitive dependencies keep their own notices and terms. The project license
does not relicense third-party code or standards.
