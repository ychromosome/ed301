# SPDX-License-Identifier: Apache-2.0
"""X301 reference for the internal v2 profile; NOT FOR PRODUCTION.

Adapted from the strict v1 reference under Martin's input contract, revision 2.
Python integers and the underlying ladder are variable-time. Library byte
comparisons do not make the surrounding reference constant-time or zeroizing.
All parameter-dependent constants come from the hash-bound Gate-A package.
"""

from collections.abc import Callable
from hmac import compare_digest
import os

import ed301_curve as curve

SPEC_IDENTIFIER = "X301-v2"
PRODUCTION_READY = False
SECRET_BYTES = curve.FIELD_BYTES
PUBLIC_BYTES = curve.FIELD_BYTES
SHARED_BYTES = curve.FIELD_BYTES
N_TWIST = int(curve.PARAMETERS["twist"]["order_decimal"])
N_TWIST_ENCODING = N_TWIST.to_bytes(SECRET_BYTES, "little")
BASE_U_ENCODING = bytes.fromhex(curve.PARAMETERS["basepoint"]["G_montgomery_u_little_endian_hex"])


class WeakSecretError(ValueError):
    """The clamped secret is the full twist order; KeyGen must resample."""


class AllZeroError(ValueError):
    """The ladder gave infinity or a zero coordinate; no output is returned."""


def clamp_secret_bytes(secret: bytes) -> bytes:
    if not isinstance(secret, bytes) or len(secret) != SECRET_BYTES:
        raise ValueError("X301 secret must be exactly 38 bytes")
    clamped = bytearray(secret)
    clamped[0] &= 0xFC
    clamped[-1] = (clamped[-1] & 0x0F) | 0x10
    clamped = bytes(clamped)
    if compare_digest(clamped, N_TWIST_ENCODING):
        raise WeakSecretError("X301 clamped secret equals the twist order")
    return clamped


def decode_secret_scalar(secret: bytes) -> int:
    return int.from_bytes(clamp_secret_bytes(secret), "little")


def import_secret(secret: bytes) -> bytes:
    """Validate a raw secret without changing its serialized bytes."""
    clamp_secret_bytes(secret)
    return secret


def x301(secret: bytes, u_encoding: bytes) -> bytes:
    """Return a canonical, nonzero raw shared coordinate or raise ValueError.

    Decode the public input before invoking the ladder. No normalization,
    curve/twist classification, KDF, fallback or partial-output API is used.
    """
    scalar = decode_secret_scalar(secret)
    u = curve.decode_field(u_encoding)
    result = curve.montgomery_ladder_u(scalar, u)
    if result is None:
        raise AllZeroError("X301 result is the point at infinity")
    encoded = curve.encode_field(result)
    if compare_digest(encoded, bytes(SHARED_BYTES)):
        raise AllZeroError("X301 result is all zero")
    return encoded


def public_from_secret(secret: bytes) -> bytes:
    return x301(secret, BASE_U_ENCODING)


def shared_secret(secret: bytes, peer_public: bytes) -> bytes:
    return x301(secret, peer_public)


def keygen(random_bytes: Callable[[int], bytes] = os.urandom) -> tuple[bytes, bytes]:
    """Use the system CSPRNG; only the excluded twist-order clamp is retried."""
    while True:
        secret = random_bytes(SECRET_BYTES)
        try:
            public = public_from_secret(secret)
        except WeakSecretError:
            continue
        return secret, public
