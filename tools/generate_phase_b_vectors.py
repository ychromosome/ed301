#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Deterministic public-test-seed vectors; stdout only, no source-tree writes."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import ed301_curve as c
import ed301_sig as sig


def generate() -> dict:
    legacy = json.loads((ROOT / "tests/fixtures/v1/ed301-eddsa-v1.json").read_text())
    signing = []
    for old in legacy["cases"] + legacy["context_cases"]:
        case = {k: old[k] for k in ("id", "seed_hex", "message_hex", "context_hex")}
        case["trace"] = {k: v.hex() for k, v in sig.sign_trace(
            bytes.fromhex(case["seed_hex"]), bytes.fromhex(case["message_hex"]),
            bytes.fromhex(case["context_hex"])).items()}
        signing.append(case)
    for name, seed, message, context in (
        ("zero-seed", bytes(38), b"\x00", b"\x00"),
        ("ones-seed", b"\xff" * 38, b"Ed301-EdDSA", b"\xff"),
    ):
        signing.append({"id": name, "seed_hex": seed.hex(), "message_hex": message.hex(),
                        "context_hex": context.hex(),
                        "trace": {k: v.hex() for k, v in sig.sign_trace(seed, message, context).items()}})

    base = signing[0]
    seed = bytes.fromhex(base["seed_hex"])
    pk = bytes.fromhex(base["trace"]["public_key"])
    signature = bytes.fromhex(base["trace"]["signature"])
    verification = []

    def verify_case(name, *, public=pk, signature=signature, message=b"", context=b"", accepted=False):
        actual = sig.verify(public, message, signature, context)
        if actual != accepted:
            raise RuntimeError(f"vector construction mismatch: {name}: {actual}")
        verification.append({"id": name, "public_key_hex": public.hex(), "message_hex": message.hex(),
                             "context_hex": context.hex(), "signature_hex": signature.hex(),
                             "accepted": accepted})

    verify_case("positive-control", accepted=True)
    verify_case("changed-message", message=b"\x00")
    verify_case("changed-context", context=b"\x00")
    verify_case("context-256", context=bytes(range(256)))
    for length in (0, 75, 77):
        verify_case(f"signature-length-{length}", signature=(signature + b"\x00")[:length])
    for length in (0, 37, 39):
        verify_case(f"public-key-length-{length}", public=(pk + b"\x00")[:length])
    for name, scalar in (("zero-response-wrong-equation", 0), ("S-q", c.Q),
                         ("S-q-plus-one", c.Q + 1), ("S-max304", (1 << 304) - 1)):
        verify_case(name, signature=signature[:38] + scalar.to_bytes(38, "little"))

    invalid_points = [("y-p", c.P.to_bytes(38, "little")),
                      ("y-p-plus-one", (c.P + 1).to_bytes(38, "little")),
                      ("y-max301", ((1 << 301) - 1).to_bytes(38, "little")),
                      ("length-37", bytes(37)), ("length-39", bytes(39))]
    for bit in (301, 302):
        invalid_points.append((f"reserved-bit-{bit}", (1 | (1 << bit)).to_bytes(38, "little")))
    for name, y in (("negative-zero-identity", 1), ("negative-zero-order2", c.P - 1)):
        invalid_points.append((name, (y | (1 << 303)).to_bytes(38, "little")))
    for y in range(2, 100):
        encoded = y.to_bytes(38, "little")
        try:
            c.decode_point(encoded)
        except ValueError:
            invalid_points.append(("nonsquare-x", encoded))
            break
    else:
        raise RuntimeError("no deterministic non-point in first 100 y values")
    for name, encoded in invalid_points:
        verify_case("public-" + name, public=encoded)
        verify_case("R-" + name, signature=encoded + signature[38:])

    torsion = [("identity", c.IDENTITY), ("order2", c.ORDER_2),
               ("order4", c.ORDER_4), ("negative-order4", c.point_negate(c.ORDER_4))]
    secret, _, _ = sig.expand_seed(seed)
    for name, t in torsion:
        verify_case("public-" + name, public=c.encode_point(t))
        if t != c.IDENTITY:
            verify_case("public-mixed-" + name, public=c.encode_point(c.point_add(c.G, t)))
            verify_case("R-added-" + name + "-unchanged-S",
                        signature=c.encode_point(c.point_add(c.decode_point(signature[:38]), t)) + signature[38:])
        verify_case("R-" + name + "-wrong-equation", signature=c.encode_point(t) + signature[38:])
        for nonce in (0, 7):
            renc = c.encode_point(c.point_add(c.scalar_multiply(nonce, c.G), t))
            k = int.from_bytes(sig.hash_parts(sig.domain(), renc, pk, b""), "little") % c.Q
            response = c.encode_scalar((nonce + k * secret) % c.Q)
            verify_case(f"R-{name}-nonce-{nonce}-valid-cofactored", signature=renc + response, accepted=True)

    # These are signature-scheme conformance controls, not alternate profiles.
    # A verifier cannot demand deterministic nonces; only signer KATs can.
    scalar, prefix, _ = sig.expand_seed(seed)
    domain_controls = []
    for name, nonce_dom, challenge_dom, accepted in (
        ("missing-nonce-domain", b"", sig.domain(), True),
        ("missing-challenge-domain", sig.domain(), b"", False),
        ("missing-both-domains", b"", b"", False),
        ("v1-label-new-curve", b"SigEd301-v1\x00\x00", b"SigEd301-v1\x00\x00", False),
        ("prehash-flag", b"SigEd301-v2\x01\x00", b"SigEd301-v2\x01\x00", False),
    ):
        nonce_hash = sig.hash_parts(nonce_dom, prefix, b"")
        nonce = int.from_bytes(nonce_hash, "little") % c.Q
        renc = c.encode_point(c.scalar_multiply(nonce, c.G))
        k = int.from_bytes(sig.hash_parts(challenge_dom, renc, pk, b""), "little") % c.Q
        other = renc + c.encode_scalar((nonce + k * scalar) % c.Q)
        if other == signature:
            raise RuntimeError("domain control unexpectedly equals deterministic signature")
        verify_case(name, signature=other, accepted=accepted)
        domain_controls.append({"id": name, "nonce_hash_hex": nonce_hash.hex(),
                                "signature_hex": other.hex(), "matches_signer": False,
                                "accepted_by_verifier": accepted})

    point_cases = [{"id": name, "encoded_hex": encoded.hex(), "accepted": False}
                   for name, encoded in invalid_points]
    for name, point in [("base", c.G)] + torsion:
        point_cases.append({"id": name, "encoded_hex": c.encode_point(point).hex(), "accepted": True,
                            "x": str(point[0]), "y": str(point[1])})
    scalar_cases = [{"id": f"scalar-{name}", "encoded_hex": value.to_bytes(38, "little").hex(),
                     "accepted": value < c.Q, "value": str(value)}
                    for name, value in (("0", 0), ("1", 1), ("q-minus-one", c.Q - 1),
                                        ("q", c.Q), ("q-plus-one", c.Q + 1), ("max304", (1 << 304) - 1))]
    return {"schema": "Ed301-EdDSA-v2-reference-vectors-1", "parameter_sha256": c.PARAMETER_SHA256,
            "warning": "Public deterministic test seeds only; no production or Gate-B approval",
            "signing": signing, "verification": verification, "point_decoding": point_cases,
            "scalar_decoding": scalar_cases, "domain_controls": domain_controls,
            "signing_errors": [
                {"id": "context-256", "seed_hex": seed.hex(), "message_hex": "", "context_hex": bytes(range(256)).hex()},
                *({"id": f"seed-length-{n}", "seed_hex": bytes(n).hex(), "message_hex": "", "context_hex": ""}
                  for n in (0, 37, 39))]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", type=Path, help="compare exact bytes with an existing corpus")
    args = parser.parse_args()
    data = json.dumps(generate(), indent=2, sort_keys=True) + "\n"
    if args.check:
        if args.check.read_text() != data:
            raise SystemExit("FAIL: generated vectors differ")
        print("PASS: deterministic Ed301-EdDSA vector regeneration")
    else:
        print(data, end="")
