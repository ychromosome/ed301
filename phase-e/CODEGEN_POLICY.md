# Phase-E x86-64 code-generation policy

The additive checker applies to actual measured core executables and ordinary
and TLS provider DSOs. It does not edit the historical Phase-C/D1/D2 checkers,
Rust arithmetic, instrumentation declassification or compiler configuration.
The final controller binds one immutable source manifest, the functional DSO
receipt and the receipt of the exact measured core binaries, before and after
inspection. This remains a bounded regression gate, not a universal CT proof.

## Inherited rules

The D2 parser, legacy/v0 symbol-name normalization, local relative-GOT
resolution, exact call sequences (including unwind/panic paths), division/trap
rejection and terminal-padding distinction are retained. Every original
borrow/select minimum remains unchanged. An emitted field helper must still
be branch-free; an absent helper must have no unresolved call anywhere.
The new X301 Edwards leaves use the same minima as their Ed301 counterparts.
X301's inlined cached-point negation keeps the original negation minima inside
its branch-free, non-indexed selector.

Memcpy's additional callee-saved registers r12/r14/r15 are resolved only from a
named memcpy GOT load. Narrow aliases and exchange instructions invalidate
that provenance. Four positive controls and eight alias/exchange negative
controls supplement the existing unexpected-call, suffix-confusion, missing
helper, terminal-trap and same-binary public-branch controls.

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

The full ladder still has one backward carry edge and no other jump. Its
initial counter is 300 in eax; rax is saved exactly once per iteration at
the reviewed stack slot and reloaded before decrement. The only scaled
memory access reads scalar[counter >> 3]; its bit position is counter & 7.
No function is called inside the loop. The original >=20 conditional-move
minimum is unchanged; lazy arithmetic eliminates redundant canonical
corrections, leaving the 20 swap selections inside each round. The entire
ladder, including final corrections outside the loop, rejects division/traps.
Wrong-counter and earlier-decoy-counter controls both must fail.

## E3: public exponents and acceptance order

The production exponentiator has no call. It precomputes powers 1..15 with a
fixed 40-byte stride, then visits 75 four-bit windows. Its digit branch and
power-table index come only from the public exponent, never the field input.
Both zero/nonzero digit paths decrement the same preserved public counters.
All 16 scaled-memory instructions are explicitly classified; counter and
exponent-pointer stack slots have exact checked write inventories.

Every linked call site's exponent-pointer origin is followed to read-only
allocated ELF bytes. The decoder has exactly one (p-3)/4 call. The importer
has exactly (p+1)/4, (p-1)/2, (p-1)/2 in that order, for
p = 2^301 - 2^89 + 907. There is no branch between the three importer calls;
the combined subgroup decision follows both Euler computations. Wrong
read-only exponent bytes, a shortened window counter and an early symbol
exit are negative controls. These mutations exist only in memory, never in
the measured ELF. Test-only Jacobi and old subgroup-oracle symbols must not
appear in the production binary.

Thin LTO keeps the public verification-table builder separate in provider
DSOs but inlines it into the measured Ed301 core importer. The latter's six
additional, exact table-building loops begin after subgroup acceptance and
are bound by a separate complete branch/call sequence. This is not permission
to add an early branch in either symbol test.

## Measurements and evidence

The new provider benchmark controller changes only its import path and its
diagnostic/profile descriptions from the D2 controller. Its 128 cases, harnesses, CPU 2,
nine rotated repetitions, >=200 ms calibration, native v1 profiles and
resource measurements are unchanged. No runtime change is justified by the
codegen tooling. The final matrix is rerun after freezing these additive
tools; preliminary diagnostic passes are not substituted for that matrix.
