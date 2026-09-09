#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Public synthetic X301 vectors; stdout or exact check, no source writes."""

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import ed301_curve as c
import x301 as x

CONTRACT_SHA256 = "b33d3fe0bf6b5b026192695902902f4b7592d4271ca98161f47920b47c6a1c2c"


def generate():
    seeds = [("ascending", bytes(range(38))), ("descending", bytes(reversed(range(38)))),
             ("zeros", bytes(38)), ("ones", b"\xff" * 38), ("alternating", b"\xaa\x55" * 19),
             ("below-nt", (x.N_TWIST - 4).to_bytes(38, "little")),
             ("above-nt", (x.N_TWIST + 4).to_bytes(38, "little"))]
    keys = [{"id": name, "secret_hex": secret.hex(), "clamped_hex": x.clamp_secret_bytes(secret).hex(),
             "public_hex": x.public_from_secret(secret).hex()} for name, secret in seeds]
    dh = []
    for ia, ib in ((0, 1), (2, 3), (4, 0), (5, 6)):
        ka, kb = keys[ia], keys[ib]
        ab = x.shared_secret(bytes.fromhex(ka["secret_hex"]), bytes.fromhex(kb["public_hex"]))
        ba = x.shared_secret(bytes.fromhex(kb["secret_hex"]), bytes.fromhex(ka["public_hex"]))
        if ab != ba:
            raise RuntimeError("DH symmetry failed")
        dh.append({"id": f"{ka['id']}-{kb['id']}", "a": ka["id"], "b": kb["id"], "shared_hex": ab.hex()})

    def classification(u):
        rhs = (u ** 3 + c.A_MONTGOMERY * u * u + u) * pow(c.B_MONTGOMERY, -1, c.P) % c.P
        symbol = pow(rhs, (c.P - 1) // 2, c.P)
        return "torsion-root" if symbol == 0 else "curve" if symbol == 1 else "twist"

    us = [("base", int.from_bytes(x.BASE_U_ENCODING, "little")), ("p-minus-two", c.P - 2)]
    for kind in ("curve", "twist"):
        values = [u for u in range(2, 100) if classification(u) == kind][:2]
        if len(values) != 2:
            raise RuntimeError("missing deterministic public point class")
        us.extend((f"{kind}-u-{u}", u) for u in values)
    evaluations = []
    for name, u in us:
        for key in (keys[0], keys[2], keys[5], keys[6]):
            secret = bytes.fromhex(key["secret_hex"])
            encoded = c.encode_field(u)
            result = x.x301(secret, encoded)
            evaluations.append({"id": f"{key['id']}-{name}", "key": key["id"], "u_hex": encoded.hex(),
                                "classification": classification(u), "result_hex": result.hex()})

    errors = []
    secret = seeds[0][1]
    bad_u = [(f"u-{name}", n.to_bytes(38, "little")) for name, n in (
        ("p", c.P), ("p-plus-one", c.P + 1), ("p-plus-two", c.P + 2), ("max301", (1 << 301) - 1))]
    bad_u += [(f"u-length-{n}", bytes(n)) for n in (0, 37, 39)]
    # All seven combinations, both on a valid nonzero peer and the zero coordinate.
    for mask in range(0x20, 0x100, 0x20):
        for name, original in (("base", x.BASE_U_ENCODING), ("zero", bytes(38))):
            encoded = bytearray(original)
            encoded[-1] |= mask
            bad_u.append((f"u-reserved-{mask:02x}-{name}", bytes(encoded)))
    for name, encoded in bad_u:
        errors.append({"id": name, "secret_hex": secret.hex(), "u_hex": encoded.hex(), "stage": "decode-u"})
    for n in (0, 37, 39):
        errors.append({"id": f"secret-length-{n}", "secret_hex": bytes(n).hex(),
                       "u_hex": x.BASE_U_ENCODING.hex(), "stage": "decode-secret"})
    weak = []
    for low in range(4):
        for high in range(16):
            alias = bytearray(x.N_TWIST_ENCODING)
            alias[0] = (alias[0] & 0xFC) | low
            alias[-1] = (alias[-1] & 0x0F) | (high << 4)
            weak.append({"id": f"weak-low-{low}-high-{high}", "secret_hex": bytes(alias).hex()})
    for u in (0, 1, c.P - 1):
        for key in (keys[0], keys[2], keys[3]):
            errors.append({"id": f"allzero-u-{u}-{key['id']}", "secret_hex": key["secret_hex"],
                           "u_hex": c.encode_field(u).hex(), "stage": "result"})
    for case in errors:
        try:
            x.x301(bytes.fromhex(case["secret_hex"]), bytes.fromhex(case["u_hex"]))
        except ValueError as error:
            if (case["stage"] == "result") != isinstance(error, x.AllZeroError):
                raise RuntimeError(f"wrong rejection class: {case['id']}") from error
        else:
            raise RuntimeError(f"negative vector accepted: {case['id']}")

    k = u = x.BASE_U_ENCODING
    checkpoints = []
    for iteration in range(1, 1001):
        k, u = x.x301(k, u), k
        if iteration in (1, 10, 100, 1000):
            checkpoints.append({"count": iteration, "k_hex": k.hex(), "u_hex": u.hex()})
    return {"schema": "X301-v2-reference-vectors-1", "parameter_sha256": c.PARAMETER_SHA256,
            "contract_sha256": CONTRACT_SHA256, "keys": keys, "dh": dh, "evaluations": evaluations,
            "errors": errors, "weak_secrets": weak,
            "iteration": {"rule": "k_0=u_0=BASE_U_ENCODING; (k_i,u_i)=(X301(k_(i-1),u_(i-1)),k_(i-1))",
                          "checkpoints": checkpoints},
            "warning": "Public synthetic secrets only; variable-time references; Gate B review required"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", type=Path)
    args = parser.parse_args()
    output = json.dumps(generate(), indent=2, sort_keys=True) + "\n"
    if args.check:
        if args.check.read_text() != output:
            raise SystemExit("FAIL: X301 vector regeneration differs")
        print("PASS: deterministic X301 vector regeneration including 1000 iterations")
    else:
        print(output, end="")
