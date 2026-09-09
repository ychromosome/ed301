# SPDX-License-Identifier: Apache-2.0
"""Ed301-EdDSA reference for the internal v2 profile; NOT FOR PRODUCTION.

Adapted from the current v1 transcript reference, not the retired Ed301-Sig-v1
construction. Python's standard SHAKE256 and integers make the byte contract
auditable; this is variable-time test software with no secret-erasure claim.
See phase-b/SOURCES.md and specifications/Ed301-EdDSA-v2.md.
"""

from __future__ import annotations

from hashlib import shake_256

import ed301_curve as curve

SPEC_IDENTIFIER = "Ed301-EdDSA-v2"
DOMAIN_PREFIX = b"SigEd301-v2"
PHFLAG = 0
MAX_CONTEXT_BYTES = 255
SEED_BYTES = curve.FIELD_BYTES
PUBLIC_KEY_BYTES = curve.FIELD_BYTES
SIGNATURE_BYTES = 2 * curve.FIELD_BYTES
HASH_BYTES = 2 * curve.FIELD_BYTES


def require_bytes(value: bytes, label: str, length: int | None = None) -> bytes:
    if not isinstance(value, bytes):
        raise ValueError(f"{label} must be bytes")
    if length is not None and len(value) != length:
        raise ValueError(f"{label} must be exactly {length} bytes")
    return value


def domain(context: bytes = b"") -> bytes:
    require_bytes(context, "context")
    if len(context) > MAX_CONTEXT_BYTES:
        raise ValueError("context must contain at most 255 bytes")
    return DOMAIN_PREFIX + bytes((PHFLAG, len(context))) + context


def hash_parts(*parts: bytes) -> bytes:
    state = shake_256()
    for part in parts:
        state.update(part)
    return state.digest(HASH_BYTES)


def expand_seed(seed: bytes) -> tuple[int, bytes, bytes]:
    require_bytes(seed, "seed", SEED_BYTES)
    expanded = hash_parts(seed)
    lower = bytearray(expanded[:SEED_BYTES])
    lower[0] &= 0xFC
    lower[-1] = (lower[-1] & 0x0F) | 0x10
    return int.from_bytes(lower, "little"), expanded[SEED_BYTES:], expanded


def public_from_seed(seed: bytes) -> bytes:
    secret_scalar, _, _ = expand_seed(seed)
    return curve.encode_point(curve.scalar_multiply(secret_scalar, curve.G))


def sign_trace(seed: bytes, message: bytes, context: bytes = b"") -> dict[str, bytes]:
    """Expose transcript intermediates for public test seeds only."""
    require_bytes(message, "message")
    dom = domain(context)
    secret_scalar, prefix, expanded = expand_seed(seed)
    public_key = curve.encode_point(curve.scalar_multiply(secret_scalar, curve.G))
    nonce_hash = hash_parts(dom, prefix, message)
    nonce = int.from_bytes(nonce_hash, "little") % curve.Q
    commitment = curve.encode_point(curve.scalar_multiply(nonce, curve.G))
    challenge_hash = hash_parts(dom, commitment, public_key, message)
    challenge = int.from_bytes(challenge_hash, "little") % curve.Q
    response = curve.encode_scalar((nonce + challenge * secret_scalar) % curve.Q)
    return {
        "domain": dom,
        "expanded_hash": expanded,
        "pruned_secret_scalar": secret_scalar.to_bytes(SEED_BYTES, "little"),
        "prefix": prefix,
        "public_key": public_key,
        "nonce_hash": nonce_hash,
        "nonce_scalar": curve.encode_scalar(nonce),
        "commitment": commitment,
        "challenge_hash": challenge_hash,
        "challenge_scalar": curve.encode_scalar(challenge),
        "response": response,
        "signature": commitment + response,
    }


def sign(seed: bytes, message: bytes, context: bytes = b"") -> bytes:
    return sign_trace(seed, message, context)["signature"]


def validate_public_key(public_key: bytes) -> bool:
    try:
        curve.decode_point(public_key, require_prime_order=True)
        return True
    except (TypeError, ValueError):
        return False


def verify(public_key: bytes, message: bytes, signature: bytes, context: bytes = b"") -> bool:
    """Malformed inputs return False; arithmetic invariant failures propagate."""
    try:
        require_bytes(signature, "signature", SIGNATURE_BYTES)
        require_bytes(message, "message")
        dom = domain(context)
        public_point = curve.decode_point(public_key, require_prime_order=True)
        r_encoding = signature[:curve.FIELD_BYTES]
        commitment = curve.decode_point(r_encoding)
        response = curve.decode_scalar(signature[curve.FIELD_BYTES:])
        challenge = int.from_bytes(hash_parts(dom, r_encoding, public_key, message), "little") % curve.Q
    except (TypeError, ValueError):
        return False
    left = curve.scalar_multiply(curve.H * response, curve.G)
    right = curve.point_add(curve.scalar_multiply(curve.H, commitment),
                            curve.scalar_multiply(curve.H * challenge, public_point))
    return left == right
