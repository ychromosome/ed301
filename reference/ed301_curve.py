#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""ED301 curve reference for the internal ED301-v2 profile; NOT FOR PRODUCTION.

Modified from the v1 affine curve reference (see phase-b/SOURCES.md).
Only Python standard-library integer arithmetic is used. Operations are
variable-time and neither zeroize secrets nor provide side-channel protection.
This module defines curve encodings and a low-level canonical-u ladder,
not an external X301 input-acceptance policy.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Optional, Tuple


PRODUCTION_READY = False
SECURITY_WARNING = "REFERENCE ONLY: variable-time affine arithmetic; not production-ready"
PARAMETER_PATH = (Path(__file__).resolve().parents[1]
                  / "provenance/phase-a/2026-09-09/parameter/ed301-v2.json")
PARAMETER_SHA256 = "13f0eaf541919a1447b9d3c58e6d57eb77ffab94ebe37539c70301d6fddcfaa0"
_parameter_bytes = PARAMETER_PATH.read_bytes()
if hashlib.sha256(_parameter_bytes).hexdigest() != PARAMETER_SHA256:
    raise RuntimeError("Gate-A parameter file hash mismatch")
PARAMETERS = json.loads(_parameter_bytes)

# Every parameter-dependent constant comes from the immutable Gate-A JSON.
P = int(PARAMETERS["field"]["p_decimal"])
A_EDWARDS = int(PARAMETERS["edwards"]["a_decimal"])
D_EDWARDS = int(PARAMETERS["edwards"]["d_decimal"])
Q = int(PARAMETERS["group"]["q_decimal"])
H = PARAMETERS["group"]["cofactor_h"]
N = int(PARAMETERS["group"]["order_N_decimal"])
FIELD_BYTES = PARAMETERS["encoding"]["field_bytes"]
SCALAR_BYTES = PARAMETERS["encoding"]["scalar_bytes"]
LADDER_BITS = PARAMETERS["field"]["bit_length"]

Point = Tuple[int, int]
AffineMontgomeryPoint = Tuple[int, int]
MontgomeryPoint = Optional[AffineMontgomeryPoint]
IDENTITY: Point = tuple(int(PARAMETERS["edwards"]["identity"][k]) for k in ("x", "y"))
ORDER_2: Point = tuple(int(PARAMETERS["edwards"]["order_2_point"][k]) for k in ("x", "y"))
ORDER_4: Point = tuple(int(PARAMETERS["edwards"]["order_4_point"][k]) for k in ("x", "y"))
G: Point = tuple(int(PARAMETERS["basepoint"][f"G_edwards_{k}_decimal"]) for k in ("x", "y"))
G_ENCODING = bytes.fromhex(PARAMETERS["basepoint"]["G_compressed_edwards_hex"])


def _inverse(value: int) -> int:
    value %= P
    if value == 0:
        raise ZeroDivisionError("inverse of zero")
    return pow(value, -1, P)


def _canonical_field(value: int) -> bool:
    return isinstance(value, int) and 0 <= value < P


def is_on_curve(point: Point) -> bool:
    if not isinstance(point, tuple) or len(point) != 2:
        return False
    x, y = point
    if not _canonical_field(x) or not _canonical_field(y):
        return False
    x2 = x * x % P
    y2 = y * y % P
    return (A_EDWARDS * x2 + y2 - 1 - D_EDWARDS * x2 * y2) % P == 0


def _require_point(point: Point) -> None:
    if not is_on_curve(point):
        raise ValueError("point is not a canonical ED301 point")


def point_negate(point: Point) -> Point:
    _require_point(point)
    x, y = point
    return (-x % P, y)


def point_add(left: Point, right: Point) -> Point:
    """Complete affine twisted-Edwards addition for the Gate-A parameters."""

    _require_point(left)
    _require_point(right)
    x1, y1 = left
    x2, y2 = right
    product = D_EDWARDS * x1 * x2 * y1 * y2 % P
    denominator_x = (1 + product) % P
    denominator_y = (1 - product) % P
    # These cannot vanish for this complete curve. Keep the checks so a
    # parameter or arithmetic regression fails explicitly.
    if denominator_x == 0 or denominator_y == 0:
        raise ArithmeticError("complete Edwards denominator vanished")
    x3 = (x1 * y2 + y1 * x2) * _inverse(denominator_x) % P
    y3 = (y1 * y2 - A_EDWARDS * x1 * x2) * _inverse(denominator_y) % P
    result = (x3, y3)
    if not is_on_curve(result):
        raise ArithmeticError("addition produced an off-curve point")
    return result


def point_double(point: Point) -> Point:
    return point_add(point, point)


def point_subtract(left: Point, right: Point) -> Point:
    return point_add(left, point_negate(right))


def scalar_multiply(scalar: int, point: Point) -> Point:
    """Variable-time double-and-add multiplication; accepts negative scalars."""

    if not isinstance(scalar, int):
        raise TypeError("scalar must be an integer")
    _require_point(point)
    if scalar < 0:
        return scalar_multiply(-scalar, point_negate(point))
    result = IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_double(addend)
        scalar >>= 1
    return result


def clear_cofactor(point: Point) -> Point:
    return scalar_multiply(H, point)


def is_in_prime_subgroup(point: Point, *, allow_identity: bool = True) -> bool:
    if not is_on_curve(point):
        return False
    if point == IDENTITY and not allow_identity:
        return False
    return scalar_multiply(Q, point) == IDENTITY


def _sqrt_even(value: int) -> Optional[int]:
    value %= P
    root = pow(value, (P + 1) // 4, P)
    if root * root % P != value:
        return None
    return root if root & 1 == 0 else P - root


def recover_x(y: int, sign: int) -> int:
    """Recover canonical x having LSB ``sign`` from an Edwards y value."""

    if not _canonical_field(y):
        raise ValueError("non-canonical y")
    if sign not in (0, 1):
        raise ValueError("sign must be 0 or 1")
    y2 = y * y % P
    denominator = (A_EDWARDS - D_EDWARDS * y2) % P
    if denominator == 0:
        raise ValueError("invalid y: zero recovery denominator")
    x2 = (1 - y2) * _inverse(denominator) % P
    x_even = _sqrt_even(x2)
    if x_even is None:
        raise ValueError("invalid y: x^2 is not a square")
    if x_even == 0 and sign == 1:
        raise ValueError("non-canonical sign for x=0")
    x = x_even if (x_even & 1) == sign else P - x_even
    point = (x, y)
    if not is_on_curve(point):
        raise ValueError("recovered point is off curve")
    return x


def encode_field(value: int) -> bytes:
    if not _canonical_field(value):
        raise ValueError("field value must satisfy 0 <= value < p")
    encoded = value.to_bytes(FIELD_BYTES, "little")
    if encoded[37] & 0xE0:
        raise AssertionError("field bits 301..303 must be zero")
    return encoded


def decode_field(encoded: bytes) -> int:
    if not isinstance(encoded, bytes) or len(encoded) != FIELD_BYTES:
        raise ValueError("field encoding must be exactly 38 bytes")
    if encoded[37] & 0xE0:
        raise ValueError("field encoding has a nonzero bit 301, 302, or 303")
    value = int.from_bytes(encoded, "little")
    if value >= P:
        raise ValueError("non-canonical field encoding")
    return value


def encode_scalar(value: int) -> bytes:
    if not isinstance(value, int) or not 0 <= value < Q:
        raise ValueError("scalar must satisfy 0 <= value < q")
    return value.to_bytes(SCALAR_BYTES, "little")


def decode_scalar(encoded: bytes) -> int:
    if not isinstance(encoded, bytes) or len(encoded) != SCALAR_BYTES:
        raise ValueError("scalar encoding must be exactly 38 bytes")
    value = int.from_bytes(encoded, "little")
    if value >= Q:
        raise ValueError("non-canonical scalar encoding")
    return value


def encode_point(point: Point) -> bytes:
    _require_point(point)
    x, y = point
    encoded = bytearray(encode_field(y))
    encoded[37] |= (x & 1) << 7  # Overall bit 303.
    if encoded[37] & 0x60:
        raise AssertionError("point bits 301 and 302 must be zero")
    return bytes(encoded)


def decode_point(encoded: bytes, *, require_prime_order: bool = False) -> Point:
    """Decode a compressed point.

    Normal decoding permits the identity and torsion points.  Setting
    ``require_prime_order`` performs the strict optional policy: reject the
    identity and require membership in the subgroup of exact prime order q.
    """

    if not isinstance(encoded, bytes) or len(encoded) != FIELD_BYTES:
        raise ValueError("point encoding must be exactly 38 bytes")
    if encoded[37] & 0x60:
        raise ValueError("point encoding has a nonzero reserved bit 301 or 302")
    sign = (encoded[37] >> 7) & 1
    y_bytes = bytearray(encoded)
    y_bytes[37] &= 0x1F
    y = int.from_bytes(y_bytes, "little")
    if y >= P:
        raise ValueError("non-canonical point y")
    point = (recover_x(y, sign), y)
    if require_prime_order and not is_in_prime_subgroup(point, allow_identity=False):
        raise ValueError("point does not have prime order q")
    return point


# Birational Montgomery model: B*v^2 = u^3 + A*u^2 + u.
A_MONTGOMERY = int(PARAMETERS["montgomery"]["A_decimal"])
B_MONTGOMERY = int(PARAMETERS["montgomery"]["B_decimal"])
A24_MINUS = int(PARAMETERS["montgomery"]["A24_minus_decimal"])


def is_on_montgomery(point: MontgomeryPoint) -> bool:
    """Accept the Montgomery identity or a canonical affine point."""

    if point is None:
        return True
    if not isinstance(point, tuple) or len(point) != 2:
        return False
    u, v = point
    if not _canonical_field(u) or not _canonical_field(v):
        return False
    return (B_MONTGOMERY * v * v - (u * u * u + A_MONTGOMERY * u * u + u)) % P == 0


def edwards_to_montgomery(point: Point) -> MontgomeryPoint:
    """Map every rational Edwards point, representing ``O_M`` as ``None``."""

    _require_point(point)
    if point == IDENTITY:
        return None
    if point == ORDER_2:
        return (0, 0)
    x, y = point
    u = (1 + y) * _inverse(1 - y) % P
    v = u * _inverse(x) % P
    result = (u, v)
    if not is_on_montgomery(result):
        raise ArithmeticError("Edwards-to-Montgomery map produced an off-curve point")
    return result


def montgomery_to_edwards(point: MontgomeryPoint) -> Point:
    """Map ``O_M`` and every canonical affine Montgomery point to Edwards."""

    if not is_on_montgomery(point):
        raise ValueError("point is not a canonical Montgomery point")
    if point is None:
        return IDENTITY
    if point == (0, 0):
        return ORDER_2
    u, v = point
    if v == 0 or u == P - 1:
        raise ArithmeticError("unexpected zero denominator in Montgomery-to-Edwards map")
    x = u * _inverse(v) % P
    y = (u - 1) * _inverse(u + 1) % P
    result = (x, y)
    if not is_on_curve(result):
        raise ArithmeticError("Montgomery-to-Edwards map produced an off-curve point")
    return result


def montgomery_ladder_projective(scalar: int, u: int) -> Tuple[int, int]:
    """RFC 7748-form x-only ladder using A24_minus and 301 fixed bits.

    Returns projective ``(X, Z)`` with affine u-coordinate X/Z.  No scalar
    clamping and no XDH input policy are defined here.
    """

    if not isinstance(scalar, int) or not 0 <= scalar < 1 << LADDER_BITS:
        raise ValueError("ladder scalar must be a 301-bit nonnegative integer")
    if not _canonical_field(u):
        raise ValueError("ladder u-coordinate must be canonical")

    x1 = u
    x2, z2 = 1, 0
    x3, z3 = u, 1
    swap = 0
    for bit_index in range(LADDER_BITS - 1, -1, -1):
        bit = (scalar >> bit_index) & 1
        swap ^= bit
        if swap:  # Reference code only; Python cannot provide constant-time cswap.
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = bit

        a = (x2 + z2) % P
        aa = a * a % P
        b = (x2 - z2) % P
        bb = b * b % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = d * a % P
        cb = c * b % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + A24_MINUS * e) % P

    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return x2, z2


def montgomery_ladder_u(scalar: int, u: int) -> Optional[int]:
    """Return affine ladder output, or ``None`` for the point at infinity."""

    x, z = montgomery_ladder_projective(scalar, u)
    if z == 0:
        return None
    return x * _inverse(z) % P


def verify_basepoint() -> bool:
    if not is_on_curve(G) or G == IDENTITY:
        return False
    if scalar_multiply(Q, G) != IDENTITY:
        return False
    if encode_point(G) != G_ENCODING:
        return False
    if decode_point(G_ENCODING, require_prime_order=True) != G:
        return False
    montgomery = edwards_to_montgomery(G)
    if montgomery is None:
        return False
    if montgomery_to_edwards(montgomery) != G:
        return False
    return montgomery_ladder_u(1, montgomery[0]) == montgomery[0]


if __name__ == "__main__":
    print(SECURITY_WARNING)
    print(f"basepoint_ok={int(verify_basepoint())}")
    print(f"basepoint_encoding={G_ENCODING.hex()}")
