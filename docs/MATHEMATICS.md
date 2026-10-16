# The Ed301 curve

This document describes the curve behind Ed301-EdDSA-v2 and X301-v2, how its
parameters were chosen, and how to check every claim with the files in
[`math/`](../math). The authoritative values are in
[`math/ed301-v2.json`](../math/ed301-v2.json), SHA-256
`13f0eaf541919a1447b9d3c58e6d57eb77ffab94ebe37539c70301d6fddcfaa0`. The file is
unchanged since its publication on 2026-09-09; its status and review fields
describe that moment.

## Field

```text
p = 2^301 − 2^89 + 907
  = 0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffe000000000000000000038b
```

`p` is prime (ECPP certificate below), has 301 bits and satisfies
`p ≡ 3 (mod 8)`. Reduction uses `2^301 ≡ 2^89 − 907 (mod p)`. Because
`p ≡ 3 (mod 4)`, square roots are `x^((p+1)/4)`, and the square-root ratio
used in point decoding has exponent `(p − 3)/4`. Field elements occupy 38 bytes.

## Curve

The twisted Edwards curve

```text
E:  a·x² + y² = 1 + d·x²·y²   over F_p,   a = 247399² = 61206265201,   d = −301
```

has `a` a square and `d` a non-square in `F_p`, so the addition law is complete:
it has no exceptional cases on `E(F_p)`.

| Quantity | Value |
| --- | --- |
| `#E(F_p)` | `4q` |
| `q` | `1018517988167243043134222844204689080525734197161172607405736521898659399129740227070627621` (300 bits, prime) |
| Trace `t` | `−1312817928350665189504845016634977633365276936` |
| Twist order | `4·q_t` |
| `q_t` | `1018517988167243043134222844204689080525734196504763643230403927146236890812251410387989153` (299 bits, prime) |
| Group structure | cyclic, `Z/4q` |
| Torsion | `(0, −1)` of order 2; `(±1/247399, 0)` of order 4 |

The birationally equivalent Montgomery curve `B·v² = u³ + A·u² + u` has
`A = 2(a + d)/(a − d)` and `B = 4/(a − d)`. X301 uses the ladder constant
`A24_minus = (A − 2)/4 = d/(a − d)`. `A² − 4` is a non-square, so the Montgomery
curve has a single point of order two, `u = 0`.

## Security properties

| Property | Curve | Twist |
| --- | --- | --- |
| Prime subgroup | `q`, 300 bits | `q_t`, 299 bits |
| Cofactor | 4 | 4 |
| Pollard rho, negation map (`log2 √(πq/4)`) | ≈ 2^149.3 | ≈ 2^149.3 |
| Embedding degree | `(q − 1)/4` | `(q_t − 1)/2` |
| Anomalous | no | no |

The fundamental CM discriminant of `t² − 4p` has 290 bits; the Frobenius
conductor is 94. The rho figure is a generic attack-cost estimate, not a
security proof. Both algorithms are classical and offer no post-quantum
security; the TLS hybrid relies on ML-KEM-1024 for that.

## How the parameters were chosen

`p` and `d = −301` are fixed by the author. The remaining coefficient is the
first candidate of a rigid sequence:

```text
c = 0, 1, 2, …     s = 907 + c     a = s² mod p
```

accepted as soon as all of the following hold, checked in this order:

1. `a ≠ 0`, `a ≠ d`, `a` a square, `d` a non-square (complete addition);
2. Montgomery form valid and `A² − 4` a non-square;
3. `j ∉ {0, 1728}`;
4. exact orders `N` and `N_t = 2p + 2 − N` by SEA, both `≡ 4 (mod 8)`;
5. `q = N/4` has exactly 300 bits and `q_t = N_t/4` at least 299 bits;
6. `q` and `q_t` are proven prime;
7. `p^k ≢ 1` modulo `q` and `q_t` for all `1 ≤ k ≤ 100`;
8. Hasse bound holds and neither `N` nor `N_t` equals `p`;
9. the fundamental CM discriminant exceeds `2^100` in absolute value.

Criterion 5 gives `4q ≥ 2^301`, which keeps every pruned signing scalar
(`2^300 ≤ s < 2^301`) from being a multiple of `q`. Criterion 2 follows from
criterion 1, because `A² − 4 = 16ad/(a − d)²`.

The first passing counter is **c = 246492**, giving `s = 247399`.

**Record.** The rule, the search tools and the expected result were committed
and published before the confirmation run: Martin Wolf's GPG-signed tag
`v2-search-rule-2026-09-09` (commit `0bf9b59`) and a GitHub release of
2026-09-09 18:11 UTC. The run started at 18:14 UTC, tested all 246,912
counters 0–246911 in 3,858 blocks without gaps or failures and found exactly
one valid counter, 246492. An exploratory search had preceded it on the same
day; it examined the families `d = 145`, `89` and `−301` and earlier versions of
the rule, and is disclosed in full at the tag (`provenance/v2-search/`). The
confirmation run therefore confirms a disclosed choice; it is not an unseen
first selection. An OpenTimestamps receipt was obtained afterwards and is
supplemental.

The files in [`math/selection/`](../math/selection) are byte-identical to
those at the signed tag, except for `search_result.json` (the run's verified
result, whose SHA-256 is recorded in the parameter file) and
`audit_c246492.txt` (the PARI audit of the winning candidate). The rule text
`REGELDATEI_ED301-v2.md` is in German and binding as signed.

No counter below 907 (that is, `s ∈ [1, 906]`, including `a = 1`) satisfies the
rule either, so the starting offset skips no simpler candidate.

## Base point

`G` is derived, not chosen: for counter `i = 0, 1, …`, take
`SHAKE256("ED301-BASEPOINT-DERIVATION-v2" || BE32(i), 38)`, clear bits 301–303,
reject `y ≥ p` and non-points, take the even square root for `x`, set
`G = [4]P` and reject the identity. Counter 0 succeeds. `G` has order `q`:

```text
G (compressed) = c67f33b932f3097533c5ebca430d01b9c000ba91025af84747afd17d6a9b242bf2b1fe6e350e
```

## Encodings

Field elements, points and scalars use 38 little-endian bytes. A point
stores canonical `y` in bits 0–300, zeros in bits 301–302 and the parity of
canonical `x` in bit 303; `x = 0` with sign 1 is invalid. Decoding never
reduces its input. X301 transmits only the canonical Montgomery `u`.

## Prime-order check for public keys

Ed301 accepts a public key only if it lies in the order-`q` subgroup. Since the
group is cyclic of order `4q`, this is equivalent to the point being divisible
by 4. The implementation tests this with two halving steps, each decided by a
quadratic-residue test (Euler's criterion with the fixed exponent
`(p − 1)/2`), instead of computing `[q]P`. The result is checked against
`[q]P = O` in the tests; see
[`vectors/ed301-v2-subgroup-halving.json`](../vectors/ed301-v2-subgroup-halving.json).

The bundled `crypto-bigint 0.7.5` `jacobi_symbol` returns wrong signs for some
structured inputs with four or more limbs
([RustCrypto/crypto-bigint#1295](https://github.com/RustCrypto/crypto-bigint/issues/1295));
it is not used for this check.

## Verifying the claims

From the repository root, with Python 3 and PARI/GP 2.17 where noted:

```sh
cd math/verify
# Primality: ECPP for p, q, q_t; N−1 (BLS) for q and q_t. Pure Python.
python3 verify_ecpp_independent.py ../certificates/p_ecpp_internal.pari "$(python3 -c 'print(2**301-2**89+907)')"
python3 verify_ecpp_independent.py ../certificates/q_ecpp_internal.pari <q>
python3 verify_ecpp_independent.py ../certificates/q_twist_ecpp_internal.pari <q_t>
python3 verify_nminus1_independent.py ../certificates/q_nminus1_bls_internal.pari <q>
python3 verify_nminus1_independent.py ../certificates/q_twist_nminus1_bls_internal.pari <q_t>
# Group orders of curve and twist, by an order witness in integer arithmetic.
python3 verify_curve_orders.py ../selection/search_result.json
# Base point derivation, printing every intermediate.
python3 derive_basepoint.py ../selection/search_result.json
```

`certificates/*_primo.txt` are the same certificates in PRIMO format for
external checkers. The confirmation search can be repeated with
`math/selection/search_v3.py` and PARI/GP with `pari-seadata` (about 45
minutes on 10 cores); its arguments are in `RUN_PARAMETERS.json`.

The Rust and C constants are generated from the parameter file and can be
regenerated and compared:

```sh
python3 tools/generate_rust_parameters.py --check rust/crates/ed301-eddsa/src/generated_parameters.rs
python3 tools/generate_x301_parameters.py --check rust/crates/x301/src/x_generated_parameters.rs
python3 tools/generate_provider_profiles.py ed301 --check provider/common/generated_ed301_profile.h
python3 tools/generate_provider_profiles.py x301 --check provider/common/generated_x301_profile.h
```
