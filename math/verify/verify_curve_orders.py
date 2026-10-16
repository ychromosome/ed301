#!/usr/bin/env python3
"""Independent order witness for the selected ED301-v2 curve and its twist.

Uses only Python integer arithmetic: no PARI, no curve library and no point
counting. For the curve and its quadratic twist it constructs a nontrivial
point Q with [q]Q = O. Because the Hasse interval contains exactly one
multiple of the separately ECPP-certified prime q, this fixes each group order.
"""

from __future__ import annotations

from math import isqrt
import sys

from confirmed_parameters import load_candidate


if len(sys.argv) != 2:
    raise SystemExit(f"usage: {sys.argv[0]} SEARCH_RESULT_JSON")
PARAMETERS = load_candidate(sys.argv[1])
P = PARAMETERS["p"]
D_EDWARDS = PARAMETERS["d"] - P
C = PARAMETERS["c"]
S = PARAMETERS["s"]
A_EDWARDS = PARAMETERS["a"]

A_MONTGOMERY = 2 * (A_EDWARDS + D_EDWARDS) * pow(
    A_EDWARDS - D_EDWARDS, -1, P
) % P
B_MONTGOMERY = 4 * pow(A_EDWARDS - D_EDWARDS, -1, P) % P

# B*v^2 = u^3 + A*u^2 + u wird mit X=B*u, Y=B^2*v zu
# Y^2 = X^3 + (A*B)X^2 + B^2*X skaliert.
A2 = A_MONTGOMERY * B_MONTGOMERY % P
A4 = B_MONTGOMERY * B_MONTGOMERY % P

TWIST_Z = 2
A2_TWIST = TWIST_Z * A2 % P
A4_TWIST = TWIST_Z * TWIST_Z * A4 % P

Q = PARAMETERS["q"]
N = 4 * Q
Q_TWIST = PARAMETERS["qt"]
N_TWIST = 4 * Q_TWIST

Point = tuple[int, int] | None


def require(condition: bool, message: str) -> None:
    """Enforce a proof invariant even when Python assertions are disabled."""

    if not condition:
        raise RuntimeError(message)


def inv(value: int) -> int:
    return pow(value % P, -1, P)


def legendre(value: int) -> int:
    result = pow(value % P, (P - 1) // 2, P)
    return -1 if result == P - 1 else result


def sqrt_mod(value: int) -> int:
    value %= P
    root = pow(value, (P + 1) // 4, P)
    if root * root % P != value:
        raise ValueError("kein Quadrat")
    return min(root, P - root)


def is_on_curve(point: Point, a2: int, a4: int) -> bool:
    if point is None:
        return True
    x, y = point
    return (y * y - (x * x * x + a2 * x * x + a4 * x)) % P == 0


def add(first: Point, second: Point, a2: int, a4: int) -> Point:
    if first is None:
        return second
    if second is None:
        return first
    x1, y1 = first
    x2, y2 = second
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if first == second:
        if y1 == 0:
            return None
        slope = (3 * x1 * x1 + 2 * a2 * x1 + a4) * inv(2 * y1) % P
    else:
        slope = (y2 - y1) * inv(x2 - x1) % P
    x3 = (slope * slope - a2 - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    result = (x3, y3)
    require(
        is_on_curve(result, a2, a4),
        "Weierstrass addition produced an off-curve point",
    )
    return result


def multiply(scalar: int, point: Point, a2: int, a4: int) -> Point:
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = add(result, addend, a2, a4)
        addend = add(addend, addend, a2, a4)
        scalar >>= 1
    return result


def first_affine_point(a2: int, a4: int) -> tuple[int, Point]:
    for x in range(1, 1_000_000):
        rhs = (x * x * x + a2 * x * x + a4 * x) % P
        if rhs and legendre(rhs) == 1:
            point = (x, sqrt_mod(rhs))
            require(
                is_on_curve(point, a2, a4),
                "deterministically selected point is off the requested curve",
            )
            return x, point
    raise RuntimeError("kein deterministischer Punkt gefunden")


def unique_hasse_multiple(order: int, prime_factor: int) -> tuple[int, int, int]:
    # floor(2*sqrt(p)) liefert einen sicheren ganzzahligen Hasse-Radius.
    radius = isqrt(4 * P)
    lower = P + 1 - radius
    upper = P + 1 + radius
    first_multiplier = (lower + prime_factor - 1) // prime_factor
    last_multiplier = upper // prime_factor
    require(
        first_multiplier == last_multiplier,
        "prime factor does not have a unique multiplier in the Hasse interval",
    )
    require(
        first_multiplier * prime_factor == order,
        "claimed order does not equal the unique Hasse-interval multiple",
    )
    return lower, upper, first_multiplier


def verify_curve(
    label: str,
    a2: int,
    a4: int,
    order: int,
    prime_factor: int,
) -> None:
    seed_x, seed_point = first_affine_point(a2, a4)
    witness = multiply(4, seed_point, a2, a4)
    require(witness is not None, f"{label}: subgroup witness is infinity")
    require(
        is_on_curve(witness, a2, a4),
        f"{label}: subgroup witness is off curve",
    )
    require(
        multiply(prime_factor, witness, a2, a4) is None,
        f"{label}: prime factor does not annihilate the subgroup witness",
    )
    lower, upper, multiplier = unique_hasse_multiple(order, prime_factor)
    require(
        multiplier == 4,
        f"{label}: unique Hasse multiplier does not equal cofactor four",
    )
    print(f"{label}_seed_x={seed_x}")
    print(f"{label}_seed_point={seed_point}")
    print(f"{label}_subgroup_witness={witness}")
    print(f"{label}_q_times_witness=infinity")
    print(f"{label}_hasse_lower={lower}")
    print(f"{label}_hasse_upper={upper}")
    print(f"{label}_unique_multiplier={multiplier}")
    print(f"{label}_verified_order={order}")


def main() -> None:
    require(S == 907 + C, "candidate seed derivation mismatch")
    require(
        A_EDWARDS == S*S % P,
        "candidate Edwards coefficient derivation mismatch",
    )
    require(P % 4 == 3, "field modulus must be congruent to 3 modulo 4")
    require(
        legendre(A_EDWARDS) == 1,
        "candidate Edwards coefficient a must be a quadratic residue",
    )
    require(
        legendre(D_EDWARDS) == -1,
        "Edwards coefficient d must be a quadratic nonresidue",
    )
    require(
        legendre(TWIST_Z) == -1,
        "twist parameter z must be a quadratic nonresidue",
    )
    require(
        N + N_TWIST == 2 * P + 2,
        "curve and twist orders violate the trace-sum identity",
    )
    print(f"p={P}")
    print(f"c={C}")
    print(f"s={S}")
    print(f"a={A_EDWARDS}")
    print(f"A={A_MONTGOMERY}")
    print(f"B={B_MONTGOMERY}")
    print(f"weierstrass_coefficients={(0, A2, 0, A4, 0)}")
    print(
        "twist_coefficients="
        f"{(0, A2_TWIST, 0, A4_TWIST, 0)}"
    )
    verify_curve("curve", A2, A4, N, Q)
    verify_curve("twist", A2_TWIST, A4_TWIST, N_TWIST, Q_TWIST)
    print("independent_order_verification=pass")


if __name__ == "__main__":
    main()
