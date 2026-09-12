# Third-party notices

The Rust crate uses exactly pinned third-party sources. Registry crates retain
their license, Cargo metadata and registry checksum files. The source-bound
`crypto-bigint` and `cpufeatures` forks preserve upstream hashes and document
their local changes under their vendor directories.

Current direct dependency roles are generated in the
[Cargo inventory](../docs/DEPENDENCIES.md). License declarations include:

- source-bound fork of `crypto-bigint 0.7.5`: Apache-2.0 OR MIT
- `shake 0.1.0`: MIT OR Apache-2.0
- `zeroize 1.9.0`: Apache-2.0 OR MIT
- retained vendor source `getrandom 0.4.3` (not in active lockfiles): MIT OR Apache-2.0
- retained vendor source `r-efi 6.0.0` (not in active lockfiles): MIT OR Apache-2.0 OR
  LGPL-2.1-or-later
- test-only `serde_json 1.0.150`: MIT OR Apache-2.0
- provider and diagnostic build dependency `cc 1.2.66`: MIT OR Apache-2.0

[dudect](../phase-c/timing/third_party/dudect/dudect.h) is by Oscar Reparaz
(https://github.com/oreparaz/dudect, commit
`dc269651fb2567e46755cfb2a13d3875592968b5`). The retained LICENSE is MIT;
the header also carries its public-domain dedication. Its adjacent provenance records
the test-only AArch64 timer adaptation. It is not linked into provider modules
or packages.

Transitive packages retain their own notices and terms. The project license
does not relicense third-party code, standards or imported provenance inputs.
The local `cpufeatures 0.3.0` HWCAP-mask correction is documented under that
package and remains under its Apache-2.0 OR MIT license.
