# Phase-E x86-64 code-generation policy

The additive checker applies to actual measured core executables and ordinary
and TLS provider DSOs. It does not edit the historical Phase-C/D1/D2 checkers,
Rust arithmetic, instrumentation declassification or compiler configuration.
The final controller binds one immutable source manifest, the functional DSO
receipt and the receipt of the exact measured core binaries, before and after
inspection. This remains a bounded regression gate, not a universal CT proof.

## Audited toolchain and required tools

The current instruction/call allowlists are reviewed for native x86-64,
Fedora Rust 1.98.0 with LLVM 21.1.8, and the recorded release profile
(O3, ThinLTO, one codegen unit, panic=unwind, overflow checks enabled).
They are not a compiler-independent description of all valid lowerings.
In the external LLVM 22.1.8 build, for example, the Ed301 fixed-base symbol
has four memcpy calls instead of eight and no _Unwind_Resume call. That
explains a policy rejection; it neither proves a cryptographic defect nor
constitutes approval of the new machine code. A different compiler requires
separate inspection of its actual binaries and a newly reviewed policy with
all applicable negative controls, not weakened or skipped checks.

The shell driver needs POSIX sh, awk, cat, grep, mkdir, sha256sum, the GNU
binutils tools nm/objdump/readelf, and Python 3 for the dataflow checks.
X301 additionally requires GNU awk at /usr/bin/gawk: its strtonum-based
address checks cannot be replaced by an arbitrary /usr/bin/awk. The driver
checks this X-only dependency before creating evidence or disassembling.
The supplied build marker must name Rust 1.98.0, LLVM 21.1.8 and the
x86_64-unknown-linux-gnu host exactly once. Missing, duplicate or unsupported
fields fail before evidence creation. Replay does not require the same
compiler to be installed locally; receipt hashes still provide the binding
between the recorded build marker and its binary.

## Inherited rules

The D2 parser, legacy/v0 symbol-name normalization, local relative-GOT
resolution, exact call sequences (including unwind/panic paths), division/trap
rejection and terminal-padding distinction are retained. Every original
borrow/select minimum remains unchanged. An emitted field helper must still
be branch-free; an absent named helper must have no remaining resolved call or
external tail. Unresolved transfers fail within each checked callee closure;
the whole-binary helper-name search does not classify unrelated FFI callbacks.
The new X301 Edwards leaves use the same minima as their Ed301 counterparts.
X301's inlined cached-point negation keeps the original negation minima inside
its branch-free, non-indexed selector.

Memcpy's additional callee-saved registers r12/r14/r15 are resolved only from a
named memcpy GOT load. Narrow aliases and exchange instructions invalidate
that provenance. Only full-width named GOT loads establish a pointer origin;
every direct control-flow predecessor must preserve such an origin before a
register transfer. Skipped, conditional-only and partial-width origins fail.
Four positive controls and eight alias/exchange negative
controls supplement the existing unexpected-call, suffix-confusion, missing
helper, terminal-trap and same-binary public-branch controls.

All three transfer consumers use the same parser: helper-presence checks,
allowed-callee checks and exact call/tail sequences. A direct jump is internal
only if its numeric destination is an instruction start in that same symbol
instance. External tails enter the callee policy; unresolved indirect tails
fail. Duplicate symbol instances do not share register provenance or internal
address sets. The existing X301 drop-to-zeroizer tail is now included in its
exact sequence as well as its separate shape check.

## Byte zeroizers and X301 owner offsets

Each linked 38-byte zeroizer instance must write zero exactly once to every
offset 0 through 37 relative to its entry pointer. Unknown writes, other bases,
nonzero values, incomplete coverage and premature pointer changes fail.
X301's reviewed drop body additionally binds the first owner at offset 0 and
the second owner at offset 38 in both the normal and landing-pad sequences.
These checks cover the named bodies and call targets, not all other wipe
callers, exception-table routing, compiler-created copies or process-wide
remanence. The older 76-byte digit-loop checks remain separate.

Inert parser controls run with `test_codegen_boundaries.py`; build-marker
admission controls run with `test_codegen_prerequisites.py`. The linked-binary
dataflow gate also exercises missing/nonzero/misaddressed byte writes and
incorrect X301 owner offsets on in-memory instruction copies.

## E1: fixed base and shared finalization

The secret scalar's recoding still visits 38 bytes and 76 signed radix-16
digits. The accumulated point now has an explicit zeroizing owner, which adds
copies and changes the accumulation counter register from rbp to rbx. Both
new call sequences are reviewed explicitly; there is no unrestricted helper
allowlist for these paths.

The two accumulation loops initialize rbx to -1 and -2 respectively, add two
per iteration and compare against 74. The encoded digit addresses therefore
visit odd positions 1..75 and even positions 0..74. Separate public row
counters start at zero, increase by one and are the exact argument passed to
the constant-time table scanner. Each loop visits all 38 rows. The scanner
has no indexed loads; conditional selection scans all eight magnitudes.
Four doubles occur between the two accumulation loops. Normal and unwind
paths wipe all 76 digits using independently checked zero-origin counters.

X301 inlines this work in SecretKey::public_key. Its first five conditional
edges are fixed recoding, accumulation and wipe loops. The subsequent status
and canonicality branches follow finalize_projective and consume the declared
public-key result; the final conditional edge belongs to the unwind wipe.
The source's completed-public-output declassification is unchanged and is
checked separately by fresh input-Vbit taint runs. Shared-secret bytes are
not declassified. finalize_projective contains the two fixed safegcd loops
and the existing published all-zero predicate branch. Core raw/public API
wrappers and every linked SecretKey drop are checked separately.

## E2: lazy ladder

The full ladder still has one backward carry edge and no other jump. After
E8b R1, its initial counter is 300 in ecx; rcx is saved once per iteration at
the reviewed stack slot and reloaded before decrement. The only scaled
memory access reads scalar[counter >> 3]; its bit position is counter & 7.
No function is called inside the loop. The original >=20 conditional-move
minimum is unchanged; lazy arithmetic eliminates redundant canonical
corrections, leaving the 20 swap selections inside each round. The entire
ladder, including final corrections outside the loop, rejects division/traps.
Wrong-counter and earlier-decoy-counter controls both must fail.

## E3/E8a: public exponents and the public-only import boundary

The production exponentiator has no call. It precomputes powers 1..15 with a
fixed 40-byte stride, then visits 75 four-bit windows. Its digit branch and
power-table index come only from the public exponent, never the field input.
Both zero/nonzero digit paths decrement the same preserved public counters.
All 16 scaled-memory instructions are explicitly classified; counter and
exponent-pointer stack slots have exact checked write inventories.

Every linked call site's exponent-pointer origin is followed to read-only
allocated ELF bytes. The decoder has one (p-3)/4 call and the importer one
(p+1)/4 call, for p = 2^301 - 2^89 + 907. Wrong read-only exponent bytes and a
shortened window counter remain negative controls. Both Legendre symbols now
use the unchanged, bound crypto-bigint Jacobi implementation. The earlier
Euler implementation remains an independent cfg(test) oracle and must not
appear in ordinary linked artifacts.

Martin explicitly approved E8a option c after the fresh result-dependent enum
branch had been reported. Public-key validation and its Jacobi predicate are
public-input-only, like the existing variable-time verification path. Their
timing may depend on the input key. This is not a claim that Jacobi has a
fixed binary structure and is not an exception for secret arithmetic.

ValidatedPublicKey::from_bytes and Fe301::is_nonzero_square retain explicit
no-inline boundaries. The linked-code gate records every direct and
relative-GOT incoming edge, rejects unclassified callers, and rejects escaped
public-helper addresses or unaccounted function-pointer relocations. The two
mixed provider callbacks key_import/key_set_encoded_public are NOT themselves
classified as public-only: only their supplied public-key argument reaches
the public parser. Both Jacobi calls remain inside that parser. Direct and
GOT-based secret-to-public calls and function-pointer escapes are negative
controls. This bounded call-site check is complemented by source review,
unit call counters and instrumented input-Vbit admission checks; it is not a
universal whole-program information-flow proof.

The ordinary and sign-self-verify core tests require key derivation and
signing to make zero parser calls, with a real public import as the observer
control. Instrumented core taint tests retain the same zero-call check while
the seed is tainted. At the public parser, instrumentation observes the
input's shadow bits before arithmetic and does not declassify the input.
A tagged synthetic public input must be rejected by that diagnostic boundary;
defined public inputs succeed before and after it. No diagnostic counters or
input-admission hooks may appear in ordinary production-profile binaries.

E8c keeps strict validation eager but builds the public verification table on
first provider verification. It does not change the public-only boundary or
allow unvalidated keys. Secret signing material is never retained by the
public-only cache.

## E8d: named returned owners

The returned fixed-base signing/derivation points and encoding inverse have
non-Copy zeroizing owners. Normal and controlled-unwind tests observe the
actual payload's zeroization; encoding helpers borrow those owners. The
canonical affine public output is separate from secret projective state.
This closes the named ownership gaps, not every possible compiler-generated
copy, register or stack spill. Existing secret-path branch/call/minimum-count
rules remain in force and all codegen, taint and memory checks are rerun.

## Measurements and evidence

The new provider benchmark controller changes only its import path and its
diagnostic/profile descriptions from the D2 controller. Its 128 cases, harnesses, CPU 2,
nine rotated repetitions, >=200 ms calibration, native v1 profiles and
resource measurements are unchanged. No runtime change is justified by the
codegen tooling. The final matrix is rerun after freezing these additive
tools; preliminary diagnostic passes are not substituted for that matrix.
