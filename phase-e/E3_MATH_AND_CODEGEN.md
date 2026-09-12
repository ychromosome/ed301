# E3: selection-free halving, implementation boundary

For the approved cyclic group of order 4q and a canonically decoded affine
nonidentity point, the production import checks membership in 4E = E[q].
The decoder and its length, reserved-bit, canonicality, square-root, sign and
curve-equation checks are unchanged. Identity rejection remains before subgroup
testing; the verification table is now built only after subgroup acceptance.
The old table-based [q] test is retained byte-for-byte under cfg(test), as is
the separate sparse-order oracle and optional signing self-check.

With Y the affine y-coordinate, the implementation computes:

- yy = Y^2; w = B(1-yy).
- delta = (a-d)(a-d*yy); candidate = delta^((p+1)/4).
- second = B*d*(Y+1)*((d-a)-candidate).
- acceptance = chi(w)=1 AND chi(second)=1 AND candidate^2=delta,
  excluding Y=-1 and the identity.

Both symbol tests are evaluated before combining Choice masks, including for
torsion and nonmembers. There is no inversion of d(Y+1), no halving-root
selection and no early exit on the first symbol. All intermediates use the
existing canonical field domain, so no reducer or loose arithmetic bounds
change. The generator computes and checks p mod 4=3, chi(B)=-1 and
chi(d(a-d))=1 directly from the hash-bound Gate-A JSON. Generated declarations
are checked by compile-time assertions; no parameter JSON is read at runtime.

## Why production uses Euler, not the available Jacobi API

The bound crypto-bigint offers Uint::jacobi_symbol. Equal five-limb operands
avoid its unequal-width remainder path. Its binary-GCD source has 639 total
iterations in fixed batches of at most 62, and constant-time compaction; the
helper named div_2k_vartime varies only with the public batch size here.
However, the actual Thin-LTO x86-64 binary retains a result-dependent branch
in JacobiSymbol::from_i8: the path for symbol -1 executes an extra comparison
relative to 0/+1. Thus source-level fixed scheduling is insufficient to claim
the requested fixed binary structure. The inputs at this boundary are public;
this observation is not evidence of a secret-key disclosure vulnerability.

The Jacobi prototype is retained as an immutable measured candidate, not the
accepted E3 implementation. Its disassembly and binary/source bindings are in
`/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_jacobi_codegen_2026-09-10`.
The production implementation instead evaluates the fixed exponent (p-1)/2
through the existing four-bit exponentiator and compares the result with ONE
using Choice. No library fork, enum-conversion workaround or new bigint
algorithm is introduced. Jacobi remains an additional cfg(test) oracle.
Final codegen, timing and taint gates still apply to the final Phase-E binaries.

## Independent supplied reference

The supplied proof and its full helper are copied without changing a byte.
Their relative layout is preserved, so the proof itself continues to select
only the helper's first 57 lines and substitute the source root argument.
The wrapper binds both files, the original parameter JSON and the supplied
vector JSON by SHA-256 before execution. Its 156 sample points and three
explicit torsion cases pass; all 25 vectors reproduce byte-for-byte. The
original files outside this repository are unchanged.

The Rust tests compare every supplied intermediate, including both test-only
halving roots and both symbols. Another test compares 100000 deterministic
points [k]G+torsion with the unchanged [q] oracle, exactly 6250 in each of the
16 independent k-mod-4/torsion classes. Directed identity, torsion, inverse
and mixed points and every one of the 15 Gate-B point cases are included.
For 100000 deterministic field values plus 0,1,-1, production Euler and sqrt
are compared with the independent Montgomery/Euler backend; Jacobi supplies
an additional symbol oracle. These are differential checks, not a replacement
for the group-order evidence or Claude's independent Gate E.
