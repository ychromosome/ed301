# E8 implementation and review boundary

Base: Testing commit 74d30ba7f463ea7898249dc5560032f39358569b.
This is a local implementation record, not Claude's Gate-E approval or a release.

## Authorized scope

Martin requested the supplied E8 optimization instructions, then added the
third review and expanded the implementation to E8a through E8e. The appended
E8c table-cache item supersedes the earlier reused heading; radix changes,
larger signing windows, clamp shortcuts, assembler and contract changes remain
excluded. Original instructions, patch, measurements, review and assessment
are retained byte-for-byte in phase-e/reference/e8.

The first Jacobi candidate reproduced E3's result-dependent enum-conversion
branch. Work paused for Martin's decision. After reviewing Claude's response
and the actual secret/public call paths, Martin approved option c: unchanged
library Jacobi, explicitly public-only import, retained Euler oracle, and fresh
boundary tests plus all common gates. No vendor workaround or claim of fixed
Jacobi binary structure is authorized or introduced.

## Runtime changes

- E8a: use the bound library Jacobi symbol for the two public halving symbols.
  Public-input timing is documented. The parser/predicate have explicit
  no-inline audit boundaries; diagnostic builds check input V-bits without
  declassifying the input. Sign/key-derivation tests require zero import calls.
- E8b: the supplied R1 ladder-round reordering, with identical operations,
  field bounds, swaps and 301 rounds. The new counter/register lowering is
  checked explicitly; no timing improvement is assumed from the source diff.
- E8c: a small fully validated public representation, separate from the
  verification table. The provider lazily caches one fallibly allocated table
  under a mutex. Public-only duplicates retain no private owner. Failed
  allocation leaves the cache empty; published snapshots remain immutable.
- E8d: returned projective points and the encoding inverse stay in zeroizing
  owners through the canonical public-output boundary. Borrowing avoids the
  named by-value encoder copies. Actual-owner return/unwind tests are added;
  no claim is made about all compiler temporaries or register residues.
- E8e: unknown OSSL_PARAM keys are ignored without interpreting their values.
  Known unsupported signature, raw-exchange and KEM modes remain rejected.
  Context/TLS parsing, duplicate rejection and atomic context replacement
  remain strict. The cited Ed301 key-generation initializer likewise ignores
  unknown metadata but does not admit group/size changes.

OSSL_PARAM(3) describes ignoring unknown keys as recommended behavior, not as
an unconditional normative MUST. See its [notes](https://docs.openssl.org/3.5/man3/OSSL_PARAM/#notes).

## Review and verification requirements

The fix-finding workflow applies to the named ownership and parameter-boundary
findings: independent read-only investigation, parent call-path analysis,
focused regression controls, one independent candidate review, then fresh
final checks. No observed secret disclosure was claimed by the third review.

The original signature acceptance contract remains: a cofactored equation,
no added R-subgroup requirement, and no ban on S=0. These prohibitions were
already explicit in specifications/Ed301-EdDSA-v2.md; no duplicate rule or new
signature restriction is added. Same-sized raw bytes still lack a generation
tag. Strict external public-key validation is not deferred with the table.

Earlier failed or preliminary candidates remain separate evidence and are
not substituted for the final common gate set. All existing named tests must
remain, except the explicitly changed expectation for an unknown TLS-adjacent
metadata key, which now succeeds with the same signature bytes.

Final codegen, memory/taint, timing, benchmarks, resources and provider/TLS
receipts must bind the new common source and actual artifacts. Claude's new
Gate-E decision remains external. No push, release-asset upload, installation,
activation, RPM work or Stage 2 is authorized by this implementation request.
