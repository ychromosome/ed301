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
accumulate fits u128 because (b-1)^2+2(b-1)=b^2-1. The squared-column
accumulator has at most five word products and a carried column contribution,
bounded by 5(b-1)^2+5(b-1)<2^131, well below its 192-bit capacity.

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

Multiplication by d uses multiplication by 301 followed by negation. Lazy
negation computes a bounded subtraction from zero and tightens the possible
2p representative of zero; tests include zero and 2p-1. Const tables use
the corresponding canonical negation and are regenerated for the v2 base.

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
