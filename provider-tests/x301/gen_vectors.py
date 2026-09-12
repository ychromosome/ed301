#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind v2 EVP fixtures to Phase B and retain the v1 boundary-test intentions."""

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
BOUND = {
    "vectors/x301-v2.json": "b675f677f0d717a09f3c1cc55bf0c2ad97d17ca14a7890565a41916222cc80f0",
    "reference/x301.py": "5ddcca043cb51c0c098b16b8d4a2b62907dbe7cc55e69648eb5f0a4b84dde367",
    "reference/ed301_curve.py": "b6e5f7d1788965f3efb40a9057b7d830b411ed806c82b765f0c2e47ee34c893f",
}
for name, expected in BOUND.items():
    if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != expected:
        raise SystemExit(f"unbound source: {name}")
sys.path.insert(0, str(ROOT / "reference"))
import ed301_curve as curve
import x301 as reference


def shake(label, index, length=38):
    return hashlib.shake_256(label + index.to_bytes(4, "little")).digest(length)


def evaluate(secret, public, operation):
    # The published Phase-B Python module remains untouched. This D2 adapter
    # enforces the later clarified secret-before-u precedence before calling it.
    if len(secret) != 38:
        return "invalid", "", "secret_length"
    try:
        reference.import_secret(secret)
    except reference.WeakSecretError:
        return "invalid", "", "weak_secret"
    if operation == "public_from_secret":
        public = reference.BASE_U_ENCODING
    if len(public) != 38:
        return "invalid", "", "length"
    try:
        curve.decode_field(public)
    except ValueError:
        return "invalid", "", "noncanonical"
    try:
        output = reference.x301(secret, public)
    except reference.AllZeroError:
        return "invalid", "", "all_zero"
    return "valid", output.hex(), ""


def c_array(name, data):
    lines = [f"static const unsigned char {name}[{len(data)}] = {{"]
    for offset in range(0, len(data), 12):
        lines.append("    " + ", ".join(f"0x{x:02x}" for x in data[offset:offset + 12]) + ",")
    return "\n".join(lines + ["};", ""])


def build():
    data = json.loads((ROOT / "vectors/x301-v2.json").read_text())
    keys = {row["id"]: row for row in data["keys"]}
    cases = []

    def add(family, label, secret, public=b"", operation="derive", expected_output=None):
        status, output, error = evaluate(secret, public, operation)
        if expected_output is not None and output != expected_output:
            raise SystemExit(f"Phase-B output mismatch: {label}")
        cases.append({"tc_id": len(cases) + 1, "family": family, "flags": label,
                      "operation": operation, "secret_hex": secret.hex(),
                      "public_hex": public.hex(), "expected": status,
                      "expected_output_hex": output, "expected_error": error})

    for row in data["keys"]:
        add("B-Keys", row["id"], bytes.fromhex(row["secret_hex"]),
            operation="public_from_secret", expected_output=row["public_hex"])
    for row in data["evaluations"]:
        add("B-" + row["classification"], row["id"],
            bytes.fromhex(keys[row["key"]]["secret_hex"]), bytes.fromhex(row["u_hex"]),
            expected_output=row["result_hex"])
    for row in data["dh"]:
        for a, b in ((row["a"], row["b"]), (row["b"], row["a"])):
            add("B-DH", row["id"] + ":" + a, bytes.fromhex(keys[a]["secret_hex"]),
                bytes.fromhex(keys[b]["public_hex"]), expected_output=row["shared_hex"])
    for row in data["errors"]:
        add("B-Errors", row["id"], bytes.fromhex(row["secret_hex"]), bytes.fromhex(row["u_hex"]))
        if cases[-1]["expected"] != "invalid":
            raise SystemExit(f"Phase-B error unexpectedly accepted: {row['id']}")
    for row in data["weak_secrets"]:
        secret = bytes.fromhex(row["secret_hex"])
        add("B-Weak", row["id"], secret, operation="public_from_secret")
        for public in (reference.BASE_U_ENCODING, curve.P.to_bytes(38, "little")):
            add("B-Weak-Precedence", row["id"], secret, public)
            if cases[-1]["expected_error"] != "weak_secret":
                raise SystemExit("weak-secret precedence drift")

    patterns = [bytes(38), bytes([255]) * 38,
                bytes([3]) + bytes(36) + bytes([0xe0]),
                bytes(37) + bytes([0x10]), bytes(37) + bytes([0x20]),
                bytes(37) + bytes([0x80]), bytes([0xaa]) * 38, bytes([0x55]) * 38]
    for index, secret in enumerate(patterns):
        add("W4-SpecialScalars", str(index), secret, operation="public_from_secret")
    for length in (0, 1, 37, 39, 76):
        add("W6-SecretLength", str(length), shake(b"X301-v2-D2-length/", length, length),
            operation="public_from_secret")
        add("W6-PublicLength", str(length), bytes.fromhex(keys["ascending"]["secret_hex"]),
            shake(b"X301-v2-D2-peer-length/", length, length))

    fixed = shake(b"X301-v2-D2-W5-fixed/", 0)
    counts = [0, 0]
    for index in range(100000):
        peer = reference.public_from_secret(shake(b"X301-v2-D2-W5-peer/", index))
        shared = reference.shared_secret(fixed, peer)
        for side, offset in enumerate((0, -1)):
            if shared[offset] == 0 and counts[side] < 4:
                add("W5-SharedSecretEdges", "low-zero" if side == 0 else "high-zero",
                    fixed, peer, expected_output=shared.hex())
                counts[side] += 1
        if counts == [4, 4]:
            break
    if counts != [4, 4]:
        raise SystemExit("W5 deterministic fixture budget exhausted")

    for index in range(512):
        a = shake(b"X301-v2-D2-random-a/", index)
        b = shake(b"X301-v2-D2-random-b/", index)
        public_b = reference.public_from_secret(b)
        shared_ba = reference.shared_secret(b, reference.public_from_secret(a))
        add("W-RandomValid", str(index), a, public_b, expected_output=shared_ba.hex())

    secret_a = bytes.fromhex(keys["ascending"]["secret_hex"])
    public_a = bytes.fromhex(keys["ascending"]["public_hex"])
    secret_b = bytes.fromhex(keys["descending"]["secret_hex"])
    public_b = bytes.fromhex(keys["descending"]["public_hex"])
    shared_aa = reference.shared_secret(secret_a, public_a)
    scalar = reference.decode_secret_scalar(secret_a)
    affine_aa = curve.edwards_to_montgomery(curve.scalar_multiply(scalar * scalar, curve.G))
    if affine_aa is None or shared_aa != curve.encode_field(affine_aa[0]):
        raise SystemExit("AA independent Edwards-path mismatch")
    rand_seed = bytes(range(0xa0, 0xa0 + 38))
    rand_public = reference.public_from_secret(rand_seed)
    affine_rand = curve.edwards_to_montgomery(
        curve.scalar_multiply(reference.decode_secret_scalar(rand_seed), curve.G))
    if affine_rand is None or rand_public != curve.encode_field(affine_rand[0]):
        raise SystemExit("RAND fixture independent Edwards-path mismatch")
    constants = {"SECRET_A": secret_a, "PUBLIC_A": public_a, "SECRET_B": secret_b,
                 "PUBLIC_B": public_b, "SHARED_AB": reference.shared_secret(secret_a, public_b),
                 "SHARED_AA": shared_aa, "FIELD_MODULUS": curve.P.to_bytes(38, "little"),
                 "TEST_RAND_SEED": rand_seed, "TEST_RAND_PUBLIC": rand_public}
    header = ["/* Generated from hash-bound v2 sources; public test seeds only. */",
              "#ifndef X301_V2_CONTRACT_VECTORS_H", "#define X301_V2_CONTRACT_VECTORS_H"]
    header.extend(c_array(name, value) for name, value in constants.items())
    header.append("static const unsigned char SMALL_ORDER_U[3][38] = {")
    for value in (0, 1, curve.P - 1):
        header.append("    { " + ", ".join(f"0x{x:02x}" for x in value.to_bytes(38, "little")) + " },")
    header.append("};")
    header.append("static const unsigned char WEAK_SECRETS[64][38] = {")
    for row in data["weak_secrets"]:
        header.append("    { " + ", ".join(f"0x{x:02x}" for x in bytes.fromhex(row["secret_hex"])) + " },")
    header.extend(["};", "#endif", ""])
    digest = hashlib.sha256(json.dumps(cases, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    corpus = ["/* Generated v2 EVP corpus; no v1 curve output is reused. */",
              "#ifndef X301_V2_ADVERSARIAL_VECTORS_H", "#define X301_V2_ADVERSARIAL_VECTORS_H",
              "typedef struct { unsigned int tc_id; const char *family; const char *flags;",
              "    const char *operation; const char *secret_hex; const char *public_hex;",
              "    const char *expected; const char *expected_output_hex; const char *expected_error;",
              "} X301_ADVERSARIAL_VECTOR;",
              f"#define X301_ADVERSARIAL_VECTOR_COUNT {len(cases)}u",
              f'#define X301_ADVERSARIAL_CASE_SHA256 "{digest}"',
              "static const X301_ADVERSARIAL_VECTOR x301_adversarial_vectors[] = {"]
    fields = ("family", "flags", "operation", "secret_hex", "public_hex", "expected",
              "expected_output_hex", "expected_error")
    for case in cases:
        corpus.append("    { " + str(case["tc_id"]) + "u, "
                      + ", ".join(json.dumps(case[field]) for field in fields) + " },")
    corpus.extend(["};", "#endif", ""])
    document = {"source_sha256": BOUND, "case_count": len(cases), "case_sha256": digest,
                "warning": "deterministic test-only values; not production keys", "cases": cases}
    return {"x301_contract_vectors.h": "\n".join(header),
            "x301_adversarial_vectors.h": "\n".join(corpus),
            "x301_corpus.json": json.dumps(document, indent=2) + "\n"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    outputs = build()
    for name, content in outputs.items():
        path = args.output / name
        if args.check:
            if path.read_text() != content:
                raise SystemExit(f"generated fixture differs: {path}")
        else:
            args.output.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
    print("PASS: bound X301 v2 EVP fixtures", flush=True)


if __name__ == "__main__":
    main()
