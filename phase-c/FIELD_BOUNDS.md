# C1: five-limb reduction bounds for the approved field

Let b=2^64, S=2^301 and K=2^89-907, so p=S-K. Canonical field elements
are in [0,p), lazy values in [0,2p), and loose linear values in [0,4p).
These are representation preconditions, not properties of arbitrary five-word
arrays. The exact public constants are generated from the Gate-A JSON.

## General multiplication and squaring

For two loose operands, T < (4p)^2 < 2^606. Split T=l_0+S*h_0, where
0<=l_0<S and h_0<2^305. The first fold l_0+K*h_0 is congruent to T mod p
and less than 2^301+2^394<2^395, fitting seven 64-bit words. Splitting again
gives h_1<2^94, fitting two words. The second fold is below
2^301+2^183<2p, so it fits five words and one conditional subtraction
produces the canonical representative. The lazy consumer omits only this
last subtraction and retains [0,2p).

The positive fold constant has words b-907 and 2^25-1. Addition-only carry
chains evaluate l+K*h; their fixed loop widths are unchanged. A multiply-
accumulate fits u128 because (b-1)^2+2(b-1)=b^2-1. The historical squared-column
accumulator has at most five word products and a carried column contribution,
bounded by 5(b-1)^2+5(b-1)<2^131, well below its 192-bit capacity.

### Phase E / E4: existing specialized square, exact intermediate bounds

The Gate-D source already uses five diagonal products and ten doubled cross
products, not a 25-product multiplication. The bound Ed301-v1 donor uses the
same schedule. The actual X301-v1 integration donor instead uses the row-wise
schedule adopted in E7 below. E4 verified the Ed301 donor's existing schedule;
its earlier unqualified statement about the v1 donor did not cover X301-v1.
Both v2 cores include this same source. After E7 the column schedule and its
helpers are retained under cfg(test), not used by production arithmetic.

For unrestricted words 0<=a_i<b (a stronger input domain than the field types),
the nine columns have weighted product counts 1,2,3,4,5,4,3,2,1. A doubled
cross product needs **129 bits**: its u128 product is split into three words
before doubling, with the top bit retained as `high >> 63`. Doubling the
complete product inside u128 would be insufficient. Diagonals need 128 bits.

Let C_0=0, M_j=C_j+n_j(b-1)^2 and C_(j+1)=floor(M_j/b). These are exact
inclusive column and carry maxima: setting all five words to b-1 attains them
simultaneously. The checker emits all nine rows. Inductively C_j<=5(b-1),
so every complete column is at most 5(b-1)^2+5(b-1)=5b(b-1)<2^131.
All partial additions are nonnegative and no larger than the complete column.
The low-word addition is <=2b-2; the middle-word addition plus carry is
<=2b-1. Both fit u128. The high accumulator word is <=4, so the two
`wrapping_add` operations cannot wrap on this path. After column eight the
remaining carry is <b; hence output word nine is sufficient and no high word
is discarded. The 192-bit accumulator has at least 61 spare bits.

The specialized wide-square test compares the unreduced ten-word result with
both schoolbook multiplication and crypto-bigint wide multiplication, including
all-max words, every single-bit operand and 100000 full-width deterministic
samples. Existing field-domain oracle tests still cover the unchanged reducer.

### Phase E / E7: row-wise square, full-width carry proof

The production `square_wide` is copied byte-for-byte from the bound
X301-v1 integration donor, commit 569dc4ff10e0e5e19d106cbe490d2a5aaeac935e.
It uses ten cross products, a shift of the complete ten-word value, then five
diagonal products. No field reduction rule changes. Write

    x = sum(a_i*b^i), 0 <= a_i < b, i=0..4
    C = sum(a_i*a_j*b^(i+j), i<j)
    D = sum(a_i^2*b^(2i))
    x^2 = 2C + D < b^10 = 2^640.

In row i, each multiply-accumulate consists of one word product, one existing
output word and a word carry. Its inclusive maximum is
(b-1)^2+2(b-1)=b^2-1, so u128 is sufficient and the outgoing carry is at most
b-1. Row i's final carry is written at i+5. Earlier rows write no higher than
i+4, and this row's inner loop ends at i+4: the destination has not previously
been written. No nonzero output word is overwritten. All ten (i,j) positions
with i<j occur exactly once.

The first stage therefore represents C exactly. Since 2C <= x^2 < 2^640,
C < 2^639 and shifting the ten-word value loses no final high bit. Each limb
shift explicitly carries its previous top bit into the next word. Unlike the
old schedule, it never doubles an individual 128-bit product inside u128.

For each diagonal, a_i^2 has high word at most b-2. The low-word addition is
at most (b-1)+(b-1)+1=2b-1; its carry is at most one. The following high-word
addition is at most (b-1)+(b-2)+1=2b-2, again with carry at most one. Both
intermediates fit 65 bits, well within u128. Every partial diagonal addition
is nonnegative and no greater than x^2. The final carry is therefore zero,
not an ignored overflow. These bounds hold for unrestricted five-word inputs,
a strict superset of canonical, lazy and loose field representations.

The checker emits all ten row positions, the exact all-max cross and diagonal
totals, both local addition bounds and the full-square maximum. The existing
100000-case full-word test now also compares the new square with the retained
column oracle, in addition to schoolbook and crypto-bigint widening products.
No old named test or directed input is removed.

## Public small multiplication

The argument is widened to u64 but explicitly restricted to 0<=m<2^36.
This includes the new a=61206265201 and the magnitude of d=-301; it does
not claim to support an arbitrary u64 multiplier. Canonical and lazy entry
points check this PUBLIC argument; fixed curve call sites use constants.
The const path enforces the same bound.

For a lazy operand x<2p and m<2^36, T=x*m<2^338. Thus h=T>>301<2^37
fits one word and 907*h<2^47 fits the low-word penalty subtraction.
The positive sum l+h*2^89 is below 2^301+2^126<2p and fits five words.
The fold l+h*(2^89-907) is nonnegative for valid inputs. The inherited
fixed-schedule borrow correction is retained; no full-width underflow occurs
for valid inputs (individual word borrows still propagate). Canonical callers then
perform one conditional subtraction, lazy callers retain [0,2p).

The original multiplication by d uses multiplication by 301 followed by
negation. This remains in the canonical `add_const` test oracle. Lazy
negation is now test-only; it computes a bounded subtraction from zero and
tightens the possible 2p representative of zero, including zero and 2p-1.

### Phase E / E5: folded negative-d addition

Runtime addition instead computes H=301*T1*T2 mod p in the lazy domain,
then F=Z1Z2+H and G=Z1Z2-H. Mixed addition caches `dt_abs=301*x*y`
canonically and computes H=T1*dt_abs. These are the same residues as the
old F=Z1Z2-d*T1*T2 and G=Z1Z2+d*T1*T2 because d=-301. Both H and the
Z product are below 2p, so their sum is at most 4p-2 and their augmented
subtraction at most 4p-1. Swapping the plus/minus operations therefore
preserves the existing loose-domain bounds and all subsequent product
bounds. The cached constant and runtime tables use the same positive
magnitude convention; point negation still negates the cached product.

The validity equation uses Z^4-301*X^2*Y^2 instead of adding a negated
product. Dedicated doubling contains no d term and is unchanged. The
canonical `add_const` and `double_const` are unchanged oracles for 5000
random points and directed identity, torsion, mixed and inverse cases.

## Phase E / E2: original lazy X301 ladder induction

This is the E2 formula. E7 replaces only its doubling tail as derived below;
the addition, swap, round count and wide-reducer invariants remain unchanged.

Let L=2p-1 and H=4p-1 be inclusive maxima for lazy and loose values.
At entry, all five state coordinates are canonical and hence at most L.
The conditional swap selects complete five-word representations, preserving
this bound. For each of the **301 rounds**, including any leading zero bits:

| Intermediate | Operation | Inclusive bound before reduction | Output domain |
|---|---|---:|---|
| a, c | x+z | 2L=4p-2 | loose |
| b, d | x+2p-z | L+2p=4p-1 | loose |
| aa, bb | a², b² | H² | lazy |
| e | aa+2p-bb | H | loose |
| da, cb | d*a, c*b | H² | lazy |
| x3 | (da+cb)² | (2L)² | lazy |
| difference square | (da+2p-cb)² | H² | lazy |
| z3 | x1*difference_square | L² | lazy |
| x2 | aa*bb | L² | lazy |
| A24 product | e*A24_MINUS | H*(p-1) | lazy |
| final z2 sum | aa+A24_product | 2L | loose |
| z2 | e*final_sum | H*(2L) | lazy |

Every product in this table is <=H²<(4p)²<2^606, so the same two-fold
reducer returns a value below 2p. Thus all five state coordinates again
satisfy the induction hypothesis. No loose value becomes a summand or
subtrahend of another loose addition: both inputs to each addition or
subtraction are lazy. No extra `tighten` operation is necessary.

The sums and augmented subtractions are at most 4p-1<2^303<2^320;
their five-word carries are zero. The augmented subtraction is nonnegative
(in fact at least one), so its terminal borrow is zero. A24 remains a full
five-limb field multiplication by the canonical generated constant, not a
small-integer shortcut at E2. The final swap preserves the same bounds, then one
conditional subtraction of p canonicalises each returned coordinate.
The inversion, affine conversion, zero-result check and error boundary are
unchanged. The ladder state retains its volatile Zeroize-on-scope-exit owner.

The exact-integer checker emits every product bound above. Tests additionally
assert all five state bounds after every round and compare the complete result
or error with the pre-E2 canonical ladder on Gate-B curve/twist/error cases and
10000 deterministic random secret/peer inputs, including u=0,1,2.

## Phase E / E7: scaled doubling and narrow loose multiplication

Let K=a-d=a+301=61206265502. It is nonzero modulo p and at most the existing
MAX_SMALL_MULTIPLIER=2^36-1. With A=2(a+d)/(a-d), the minus convention gives
A24=(A-2)/4=d/(a-d). Both the parameter generator and exact-integer checker
verify A*K=2(a+d) and A24*K=d modulo p against the bound Gate-A values.
A dedicated Rust test checks the latter identity and 10000 random plus four
exceptional pairs of doubling inputs against the old canonical formula.

The old tail is X2=AA*BB and Z2=E*(AA+A24*E). Multiplying both outputs by
the same nonzero K yields

    scaled_aa = K*AA
    scaled_e = 301*E
    X2 = scaled_aa*BB
    Z2 = E*(scaled_aa-scaled_e).

Their projective ratio is unchanged, including zero/infinity cases. Scaling
the two coordinates of a ladder point leaves differential addition invariant:
its outputs acquire only a common scale. Subsequent doubling is homogeneous
as well. Thus induction applies to curve and twist inputs, and the existing
final zero-result predicate and error ordering are preserved. The canonical
301-round ladder remains the independent full-result test oracle.

AA is lazy, so K*AA is covered by the existing 36-bit small-product bound.
E is loose, E<4p<2^303. The new crate-private mul_small_narrow accepts only
a PUBLIC m<2^32, checked by a non-debug assertion. Its product satisfies
T<2^335<2^338, the existing small-reducer input bound. More explicitly,
h=T>>301<2^34, 907h<2^44 and the positive fold sum is less than
2^301+2^123<2p; five words suffice and the retained borrow correction is
unchanged. Its per-word multiply-accumulate is below 2^96. The result is
lazy without first tightening E. The actual numerator 301 is also bound by
a compile-time assertion, as is K's original 36-bit limit.

| E7 tail intermediate | Inclusive pre-reduction bound | Output domain |
|---|---:|---|
| scaled_aa | (2p-1)*K < 2^338 | lazy |
| scaled_e | (4p-1)*301 < 2^335 | lazy |
| final difference | (2p-1)+2p = 4p-1 | loose |
| X2 | (2p-1)^2 < 2^606 | lazy |
| Z2 | (4p-1)^2 < 2^606 | lazy |

All five state coordinates again lie in [0,2p). Existing per-round tests still
assert this after each of all 301 iterations. The narrow method additionally
has directed full-domain checks through 4p-1 and 2^32-1, 100000 random
operand/multiplier comparisons against the independent Montgomery oracle,
and a rejection test at the first invalid multiplier 2^32. Existing random
corpora are unchanged; the added multipliers have a separate deterministic
generator. No clamp-bit shortcut, changed swap or loop restructuring is used.

## Reproducible checks and implementation limits

`phase-c/tools/check_field_bounds.py` evaluates the stated exact inclusive
upper bounds and word-capacity inequalities directly from the hash-bound p.
Its inequalities are the machine-checkable companion to the derivation;
random testing is not offered as a proof of these bounds.

Rust tests additionally cover canonical/lazy/loose extrema, every one-hot bit
through the 606-bit product range, 100000 full-domain samples, sparse products
with 36-bit multipliers, const/runtime agreement, negative d, and rejection
outside the multiplier bound. The independent arithmetic oracle is the
unchanged crypto-bigint Montgomery implementation and its wide calculations.

These bounds establish arithmetic capacity and reduction preconditions.
They are not a constant-time, code-generation, timing-leak or performance
result. Those gates must be run on the actual v2 binaries with their toolchain
and build profile recorded. No historical v1 result is transferred.
