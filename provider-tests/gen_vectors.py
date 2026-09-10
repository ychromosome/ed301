#!/usr/bin/env python3
"""Generate v2 fixtures with the bound v1 emitter/test shapes.

Normative rows come from Phase B. Additional old mutations and mixed-order
policy intentions use the frozen v2 Python reference. Historical Ed301-Sig-v1
bytes remain negative controls only.
"""

import json
import sys
from pathlib import Path

if len(sys.argv) != 4:
    raise SystemExit(
        "usage: gen_vectors.py <repository> <vectors.h> <policy_vectors.rs>")

REPOSITORY = Path(sys.argv[1]).resolve()
OUT = Path(sys.argv[2]).resolve()
RUST_OUT = Path(sys.argv[3]).resolve()

# The emitter and mutations retain bound v1 test shapes. Curve values are v2.
import hashlib

BOUND = {
    "vectors/ed301-eddsa-v2.json": "4dbbd93f5814f4e676b8007b13973037a7924872d46d328cdaeb314cd3190e82",
    "reference/ed301_curve.py": "b6e5f7d1788965f3efb40a9057b7d830b411ed806c82b765f0c2e47ee34c893f",
    "reference/ed301_sig.py": "80b9137b49c54d7ff5511d0a9fb0622bab8fca2bc77513dd76420710435f21b5",
    "provider-tests/fixtures/ed301-sig-v1-positive.json": "6faaf9e2e5ec6d0f66c90a886ce387ce0ca4eca5d0c7e82ab75cfe1b4fa0ce0c",
}
for relative, expected in BOUND.items():
    if hashlib.sha256((REPOSITORY / relative).read_bytes()).hexdigest() != expected:
        raise SystemExit(f"unbound test input: {relative}")
sys.path.insert(0, str(REPOSITORY / "reference"))
import ed301_curve as curve
import ed301_sig as reference

V2 = json.loads((REPOSITORY / "vectors/ed301-eddsa-v2.json").read_text())
PARAM = curve.PARAMETERS
HIST = json.loads((REPOSITORY / "provider-tests/fixtures/ed301-sig-v1-positive.json").read_text())
POSITIVE = {"cases": [], "context_cases": []}
for original in V2["signing"]:
    case = {"id": original["id"], "seed_hex": original["seed_hex"],
            "message_hex": original["message_hex"], "context_hex": original["context_hex"],
            "public_key_hex": original["trace"]["public_key"],
            "signature_hex": original["trace"]["signature"]}
    if not case["context_hex"]:
        POSITIVE["cases"].append(case)
    else:
        case["empty_context_signature_hex"] = reference.sign(
            bytes.fromhex(case["seed_hex"]), bytes.fromhex(case["message_hex"])).hex()
        POSITIVE["context_cases"].append(case)

point_rows = {row["id"]: row for row in V2["point_decoding"]}


def point_case(identifier, encoding):
    try:
        curve.decode_point(encoding)
        commitment_ok = True
    except ValueError:
        commitment_ok = False
    return {"id": identifier, "encoding_hex": encoding.hex(),
            "expected": {"public_key_policy": "accept" if reference.validate_public_key(encoding) else "reject",
                         "commitment_policy": "accept" if commitment_ok else "reject"}}


# Historical indices 2..7 retain identity/torsion/mixed-order test intentions.
point_order = [("basepoint", "base"), ("canonical-y-nonsquare", "nonsquare-x"),
               ("identity", "identity"), ("order-two", "order2"), ("order-four", "order4")]
points = [point_case(identifier, bytes.fromhex(point_rows[source]["encoded_hex"]))
          for identifier, source in point_order]
points.extend([
    point_case("mixed-base-plus-order-two", curve.encode_point(curve.point_add(curve.G, curve.ORDER_2))),
    point_case("mixed-base-plus-order-four", curve.encode_point(curve.point_add(curve.G, curve.ORDER_4))),
    point_case("review-mixed-torsion-R", bytes.fromhex(next(
        row["signature_hex"][:76] for row in V2["verification"]
        if row["id"] == "R-order2-nonce-7-valid-cofactored"))),
])
used = {source for _, source in point_order}
for row in V2["point_decoding"]:
    if row["id"] not in used:
        points.append(point_case("y-equals-p" if row["id"] == "y-p" else row["id"],
                                 bytes.fromhex(row["encoded_hex"])))
    try:
        curve.decode_point(bytes.fromhex(row["encoded_hex"]))
        accepted = True
    except ValueError:
        accepted = False
    assert accepted == row["accepted"], row["id"]
scalar_names = {"scalar-0": "zero", "scalar-q": "L", "scalar-q-minus-one": "L-minus-one"}
EDGE = {"point_cases": points,
        "scalar_cases": [{"id": scalar_names.get(row["id"], row["id"]),
                          "encoding_hex": row["encoded_hex"],
                          "expected": "accept" if row["accepted"] else "reject"}
                         for row in V2["scalar_decoding"]],
        "verification_cases": [{"id": row["id"], "input": row,
                                "expected": "accept" if row["accepted"] else "reject"}
                               for row in V2["verification"]]}

FIELD_BYTES = 38


# Prime subgroup order L = q (group order N = 4 * q, cofactor 4).
L = int(PARAM["group"]["q_decimal"])
# Cross-check against the edge scalar case "L".
l_case = next(c for c in EDGE["scalar_cases"] if c["id"] == "L")
assert int.from_bytes(bytes.fromhex(l_case["encoding_hex"]), "little") == L, \
    "parameter JSON order and edge-case L disagree"

positive_by_id = {c["id"]: c for c in POSITIVE["cases"]}
points_by_id = {c["id"]: bytes.fromhex(c["encoding_hex"])
                for c in EDGE["point_cases"]}
scalars_by_id = {c["id"]: bytes.fromhex(c["encoding_hex"])
                 for c in EDGE["scalar_cases"]}


def scalar_octets(value):
    return value.to_bytes(FIELD_BYTES, "little")


def mutated(value, offset, mask=1):
    output = bytearray(value)
    output[offset] ^= mask
    return bytes(output)


def c_bytes(data):
    if not data:
        return "{ 0 }"
    body = ", ".join(f"0x{b:02x}" for b in data)
    return "{ " + body + " }"


lines = []
emit = lines.append
emit("/* Generated by provider-tests/gen_vectors.py from frozen repository vectors.")
emit(" * Do not edit by hand; regenerate instead. */")
emit("#ifndef ED301V2_TEST_VECTORS_H")
emit("#define ED301V2_TEST_VECTORS_H")
emit("#include <stddef.h>")
emit("")

# The inherited RAND-separation test fixes the public a0..c5 test seed.
# Recompute its public key from the bound v2 reference, not the v1 bytes.
rand_seed = bytes(range(0xa0, 0xa0 + 38))
emit(f"static const unsigned char ED301V2_TEST_RAND_PUBLIC[38] = "
     f"{c_bytes(reference.public_from_seed(rand_seed))};")
emit("")

# ---- positive cases -------------------------------------------------
emit("typedef struct positive_case_st {")
emit("    const char *id;")
emit("    unsigned char seed[38];")
emit("    unsigned char public_key[38];")
emit("    const unsigned char *message;")
emit("    size_t message_len;")
emit("    unsigned char signature[76];")
emit("} POSITIVE_CASE;")
emit("")
for case in POSITIVE["cases"]:
    message = bytes.fromhex(case["message_hex"])
    emit(f"static const unsigned char msg_{case['id'].replace('-', '_')}"
         f"[{max(1, len(message))}] = {c_bytes(message)};")
emit("")
emit(f"static const POSITIVE_CASE POSITIVE_CASES[{len(POSITIVE['cases'])}] = {{")
for case in POSITIVE["cases"]:
    cid = case["id"].replace("-", "_")
    message = bytes.fromhex(case["message_hex"])
    emit("    {")
    emit(f"        \"{case['id']}\",")
    emit(f"        {c_bytes(bytes.fromhex(case['seed_hex']))},")
    emit(f"        {c_bytes(bytes.fromhex(case['public_key_hex']))},")
    emit(f"        msg_{cid}, {len(message)},")
    emit(f"        {c_bytes(bytes.fromhex(case['signature_hex']))}")
    emit("    },")
emit("};")
emit("")

# ---- native-context cases ------------------------------------------
context_cases = POSITIVE["context_cases"]
emit("typedef struct context_case_st {")
emit("    const char *id;")
emit("    unsigned char seed[38];")
emit("    unsigned char public_key[38];")
emit("    const unsigned char *message;")
emit("    size_t message_len;")
emit("    unsigned char context[255];")
emit("    size_t context_len;")
emit("    unsigned char signature[76];")
emit("    unsigned char empty_context_signature[76];")
emit("} CONTEXT_CASE;")
emit("")
for index, case in enumerate(context_cases):
    message = bytes.fromhex(case["message_hex"])
    emit(f"static const unsigned char context_msg_{index}"
         f"[{max(1, len(message))}] = {c_bytes(message)};")
emit("")
emit(f"static const CONTEXT_CASE CONTEXT_CASES[{len(context_cases)}] = {{")
for index, case in enumerate(context_cases):
    message = bytes.fromhex(case["message_hex"])
    context = bytes.fromhex(case["context_hex"])
    padded_context = context + b"\x00" * (255 - len(context))
    emit("    {")
    emit(f"        \"{case['id']}\",")
    emit(f"        {c_bytes(bytes.fromhex(case['seed_hex']))},")
    emit(f"        {c_bytes(bytes.fromhex(case['public_key_hex']))},")
    emit(f"        context_msg_{index}, {len(message)},")
    emit(f"        {c_bytes(padded_context)}, {len(context)},")
    emit(f"        {c_bytes(bytes.fromhex(case['signature_hex']))},")
    emit(f"        {c_bytes(bytes.fromhex(case['empty_context_signature_hex']))}")
    emit("    },")
emit("};")
emit("")

# ---- point acceptance matrix (provider surface: public-key policy) --
emit("typedef struct point_case_st {")
emit("    const char *id;")
emit("    unsigned char encoding[39];")
emit("    size_t encoding_len;")
emit("    int expect_public_key_policy_accept;")
emit("    int expect_commitment_policy_accept;")
emit("} POINT_CASE;")
emit("")
emit(f"static const POINT_CASE POINT_CASES[{len(EDGE['point_cases'])}] = {{")
for case in EDGE["point_cases"]:
    enc = bytes.fromhex(case["encoding_hex"])
    pk = 1 if case["expected"]["public_key_policy"] == "accept" else 0
    cm = 1 if case["expected"]["commitment_policy"] == "accept" else 0
    padded = enc + b"\x00" * (39 - len(enc))
    emit(f"    {{ \"{case['id']}\", {c_bytes(padded)}, {len(enc)}, {pk}, {cm} }},")
emit("};")
emit("")

# ---- scalar acceptance matrix (provider surface: S substitution) ----
emit("typedef struct scalar_case_st {")
emit("    const char *id;")
emit("    unsigned char encoding[39];")
emit("    size_t encoding_len;")
emit("    int expect_syntax_accept;")
emit("} SCALAR_CASE;")
emit("")
emit(f"static const SCALAR_CASE SCALAR_CASES[{len(EDGE['scalar_cases'])}] = {{")
for case in EDGE["scalar_cases"]:
    enc = bytes.fromhex(case["encoding_hex"])
    ok = 1 if case["expected"] == "accept" else 0
    padded = enc + b"\x00" * (39 - len(enc))
    emit(f"    {{ \"{case['id']}\", {c_bytes(padded)}, {len(enc)}, {ok} }},")
emit("};")
emit("")


# ---- complete Phase-B verification matrix, fully materialised -------
def verification_input(case):
    if "input" in case:
        direct = case["input"]
        return (bytes.fromhex(direct["public_key_hex"]),
                bytes.fromhex(direct["message_hex"]),
                bytes.fromhex(direct["signature_hex"]))
    base = positive_by_id[case["base_case"]]
    message = bytes.fromhex(base["message_hex"])
    public_key = bytes.fromhex(base["public_key_hex"])
    signature = bytes.fromhex(base["signature_hex"])
    mutation = case["mutation"]
    operation = mutation["operation"]
    if operation == "none":
        pass
    elif operation == "append-byte":
        extra = bytes.fromhex(mutation["byte_hex"])
        field = mutation["field"]
        if field == "message":
            message += extra
        elif field == "public_key":
            public_key += extra
        elif field == "signature":
            signature += extra
        else:
            raise SystemExit(f"unknown append field {field}")
    elif operation == "truncate":
        amount = mutation["bytes"]
        field = mutation["field"]
        if field == "public_key":
            public_key = public_key[:-amount]
        elif field == "signature":
            signature = signature[:-amount]
        elif field == "message":
            message = message[:-amount]
        else:
            raise SystemExit(f"unknown truncate field {field}")
    elif operation == "xor-byte":
        field = mutation["field"]
        values = {"message": bytearray(message),
                  "public_key": bytearray(public_key),
                  "signature": bytearray(signature)}
        values[field][mutation["offset"]] ^= mutation["mask"]
        message = bytes(values["message"])
        public_key = bytes(values["public_key"])
        signature = bytes(values["signature"])
    elif operation == "replace-response":
        signature = signature[:FIELD_BYTES] + \
            scalars_by_id[mutation["scalar_case"]]
    elif operation == "replace-commitment":
        signature = points_by_id[mutation["point_case"]] + \
            signature[FIELD_BYTES:]
    elif operation == "replace-public-key":
        public_key = points_by_id[mutation["point_case"]]
    elif operation == "replace-signature":
        signature = bytes.fromhex(
            positive_by_id[mutation["source_case"]]["signature_hex"])
    else:
        raise SystemExit(f"unknown mutation {operation}")
    return public_key, message, signature


emit("typedef struct verification_case_st {")
emit("    const char *id;")
emit("    unsigned char public_key[40];")
emit("    size_t public_key_len;")
emit("    const unsigned char *message;")
emit("    size_t message_len;")
emit("    unsigned char signature[80];")
emit("    size_t signature_len;")
emit("    int expect_accept;")
emit("    const unsigned char *context;")
emit("    size_t context_len;")
emit("} VERIFICATION_CASE;")
emit("")
verification_cases = EDGE["verification_cases"]
for index, case in enumerate(verification_cases):
    _, message, _ = verification_input(case)
    context = bytes.fromhex(case["input"].get("context_hex", ""))
    emit(f"static const unsigned char vctx_{index}[{max(1, len(context))}] = {c_bytes(context)};")
    emit(f"static const unsigned char vmsg_{index}"
         f"[{max(1, len(message))}] = {c_bytes(message)};")
emit("")
emit(f"static const VERIFICATION_CASE VERIFICATION_CASES"
     f"[{len(verification_cases)}] = {{")
for index, case in enumerate(verification_cases):
    public_key, message, signature = verification_input(case)
    ok = 1 if case["expected"] == "accept" else 0
    pk_padded = public_key + b"\x00" * (40 - len(public_key))
    sig_padded = signature + b"\x00" * (80 - len(signature))
    emit("    {")
    emit(f"        \"{case['id']}\",")
    emit(f"        {c_bytes(pk_padded)}, {len(public_key)},")
    emit(f"        vmsg_{index}, {len(message)},")
    emit(f"        {c_bytes(sig_padded)}, {len(signature)},")
    context = bytes.fromhex(case["input"].get("context_hex", ""))
    emit(f"        {ok}, vctx_{index}, {len(context)}")
    emit("    },")
emit("};")
emit("")

# ---- negative mutation lane (77 cases) ------------------------------
emit("typedef enum negative_kind_st {")
emit("    NEGATIVE_PLAIN = 0,")
emit("    NEGATIVE_NULL_MESSAGE = 1,     /* was: message wrong type */")
emit("    NEGATIVE_WRONG_PARAM_TYPE = 2  /* was: public wrong type  */")
emit("} NEGATIVE_KIND;")
emit("")
emit("typedef struct negative_case_st {")
emit("    const char *label;")
emit("    int kind;")
emit("    unsigned char public_key[40];")
emit("    size_t public_key_len;")
emit("    const unsigned char *message;")
emit("    size_t message_len;")
emit("    unsigned char signature[80];")
emit("    size_t signature_len;")
emit("} NEGATIVE_CASE;")
emit("")

negatives = []


def rejected(label, public_key, message, signature, kind=0):
    negatives.append((label, kind, public_key, message, signature))


decoded_cases = []
for case in POSITIVE["cases"]:
    label = case["id"]
    message = bytes.fromhex(case["message_hex"])
    public_key = bytes.fromhex(case["public_key_hex"])
    signature = bytes.fromhex(case["signature_hex"])
    decoded_cases.append((label, message, public_key, signature))

    rejected(f"{label}: short public", public_key[:-1], message, signature)
    rejected(f"{label}: long public", public_key + b"\x00", message, signature)
    rejected(f"{label}: short signature", public_key, message, signature[:-1])
    rejected(f"{label}: long signature", public_key, message,
             signature + b"\x00")
    rejected(f"{label}: message append", public_key, message + b"\x00",
             signature)

    for offset in (0, FIELD_BYTES - 1, FIELD_BYTES, 2 * FIELD_BYTES - 1):
        rejected(f"{label}: signature byte {offset}", public_key, message,
                 mutated(signature, offset))
    for offset in (0, FIELD_BYTES - 1):
        rejected(f"{label}: public byte {offset}",
                 mutated(public_key, offset), message, signature)
    if message:
        for offset in sorted({0, len(message) // 2, len(message) - 1}):
            rejected(f"{label}: message byte {offset}", public_key,
                     mutated(message, offset), signature)

    noncanonical_s = signature[:FIELD_BYTES] + scalar_octets(L)
    rejected(f"{label}: S equals L", public_key, message, noncanonical_s)

    reserved_public = bytearray(public_key)
    reserved_public[-1] |= 0x20
    rejected(f"{label}: public reserved bit", bytes(reserved_public),
             message, signature)
    reserved_r = bytearray(signature)
    reserved_r[FIELD_BYTES - 1] |= 0x40
    rejected(f"{label}: R reserved bit", public_key, message,
             bytes(reserved_r))

first_label, first_message, first_public, first_signature = decoded_cases[0]
assert first_label == "empty", "expected first vector label"
identity_encoding = points_by_id["identity"]
order_two_encoding = points_by_id["order-two"]
rejected("identity public", identity_encoding, first_message,
         first_signature)
rejected("order-two public", order_two_encoding, first_message,
         first_signature)
torsion_r = order_two_encoding + first_signature[FIELD_BYTES:]
rejected("order-two R", first_public, first_message, torsion_r)
identity_r = identity_encoding + first_signature[FIELD_BYTES:]
rejected("substituted identity R", first_public, first_message, identity_r)

p_case = next(c for c in EDGE["point_cases"] if c["id"] == "y-equals-p")
y_equal_p = bytes.fromhex(p_case["encoding_hex"])
rejected("public y equals p", y_equal_p, first_message, first_signature)
negative_zero = bytearray(identity_encoding)
negative_zero[-1] |= 0x80
rejected("negative zero x", bytes(negative_zero), first_message,
         first_signature)
rejected("message wrong type (C mapping: NULL message pointer)",
         first_public, b"not bytes", first_signature, kind=1)
rejected("public wrong type (C mapping: UTF8 param import)",
         first_public, first_message, first_signature, kind=2)

for index, (label, message, public_key, _) in enumerate(decoded_cases):
    other_signature = decoded_cases[(index + 1) % len(decoded_cases)][3]
    rejected(f"{label}: signature from another vector", public_key, message,
             other_signature)

assert len(negatives) == 77, f"expected 77 negatives, got {len(negatives)}"

for index, (label, kind, public_key, message, signature) in \
        enumerate(negatives):
    emit(f"static const unsigned char nmsg_{index}"
         f"[{max(1, len(message))}] = {c_bytes(message)};")
emit("")
emit(f"static const NEGATIVE_CASE NEGATIVE_CASES[{len(negatives)}] = {{")
for index, (label, kind, public_key, message, signature) in \
        enumerate(negatives):
    pk_padded = public_key + b"\x00" * (40 - len(public_key))
    sig_padded = signature + b"\x00" * (80 - len(signature))
    emit("    {")
    emit(f"        \"{label}\", {kind},")
    emit(f"        {c_bytes(pk_padded)}, {len(public_key)},")
    emit(f"        nmsg_{index}, {len(message)},")
    emit(f"        {c_bytes(sig_padded)}, {len(signature)}")
    emit("    },")
emit("};")
emit("")

# ---- S + L malleability (explicit acceptance-test requirement) ------
empty = positive_by_id["empty"]
sig = bytes.fromhex(empty["signature_hex"])
s_value = int.from_bytes(sig[FIELD_BYTES:], "little")
s_plus_l = s_value + L
assert s_plus_l < (1 << 304)
malleable = sig[:FIELD_BYTES] + s_plus_l.to_bytes(FIELD_BYTES, "little")
emit(f"static const unsigned char S_PLUS_L_SIGNATURE[76] = "
     f"{c_bytes(malleable)};")
emit("")

# ---- FBL-08: direct / equation-preserving policy lane ----------------
# Every declared point row gets a commitment-policy case that is decidable
# through the provider's public verify surface: for rows whose commitment
# policy accepts, an equation-preserving signature is constructed with the
# bundled reference oracle (chosen nonce k where the row's subgroup
# component has a known discrete log, otherwise the bundle's own accepting
# verification vector for that exact encoding), so acceptance of the parse
# is observable as a full verification success.  Rows whose commitment
# policy rejects use an R substitution that must fail.  The companion Rust
# unit test (src/policy_vectors_data.rs) asserts every point and scalar
# row DIRECTLY at the frozen core's public parse API.

POLICY_MESSAGE = b"v2 policy lane (test-only)"

torsion_seed = curve.decode_point(points_by_id["order-four"])
torsion_points = [curve.IDENTITY]
_point = curve.IDENTITY
for _ in range(3):
    _point = curve.point_add(_point, torsion_seed)
    torsion_points.append(_point)
assert curve.scalar_multiply(4, torsion_seed) == curve.IDENTITY


def solve_known_k(target, limit=8):
    for k in range(limit):
        k_base = curve.scalar_multiply(k, curve.G)
        for torsion in torsion_points:
            if curve.point_add(k_base, torsion) == target:
                return k
    return None


policy_seed = bytes.fromhex(positive_by_id["empty"]["seed_hex"])
policy_secret_scalar, _policy_prefix, _policy_expansion = \
    reference.expand_seed(policy_seed)
policy_public = reference.public_from_seed(policy_seed)
assert policy_public == bytes.fromhex(positive_by_id["empty"]["public_key_hex"])


def policy_challenge(commitment_encoding, public_encoding, message):
    return int.from_bytes(reference.hash_parts(
        reference.domain(), commitment_encoding, public_encoding, message), "little") % L


policy_cases = []
base_signature = bytes.fromhex(positive_by_id["empty"]["signature_hex"])
for case in EDGE["point_cases"]:
    row_id = case["id"]
    enc = bytes.fromhex(case["encoding_hex"])
    commitment_accepts = case["expected"]["commitment_policy"] == "accept"
    if not commitment_accepts:
        forged = enc + base_signature[FIELD_BYTES:]
        assert reference.verify(policy_public, POLICY_MESSAGE, forged) is False
        policy_cases.append((row_id, policy_public, POLICY_MESSAGE,
                             forged, 0))
        continue
    target = curve.decode_point(enc)
    k = solve_known_k(target)
    if k is not None:
        challenge = policy_challenge(enc, policy_public, POLICY_MESSAGE)
        s_value = (k + challenge * policy_secret_scalar) % L
        signature = enc + s_value.to_bytes(FIELD_BYTES, "little")
        assert reference.verify(
            policy_public, POLICY_MESSAGE, signature) is True, row_id
        policy_cases.append((row_id, policy_public, POLICY_MESSAGE,
                             signature, 1))
        continue
    # No small known discrete log: reuse the bundle's accepting
    # verification vector carrying exactly this commitment encoding.
    fallback = None
    for vcase in verification_cases:
        vpk, vmsg, vsig = verification_input(vcase)
        if vcase["expected"] == "accept" and vsig[:FIELD_BYTES] == enc:
            fallback = (vpk, vmsg, vsig)
            break
    if fallback is None:
        raise SystemExit(f"no equation-preserving construction for {row_id}")
    assert reference.verify(*fallback) is True, row_id
    policy_cases.append((row_id, fallback[0], fallback[1], fallback[2], 1))

emit("typedef struct policy_commitment_case_st {")
emit("    const char *id;")
emit("    unsigned char public_key[38];")
emit("    const unsigned char *message;")
emit("    size_t message_len;")
emit("    unsigned char signature[80];")
emit("    size_t signature_len;")
emit("    int expect_accept;")
emit("} POLICY_COMMITMENT_CASE;")
emit("")
for index, (_, _, message, _, _) in enumerate(policy_cases):
    emit(f"static const unsigned char pmsg_{index}"
         f"[{max(1, len(message))}] = {c_bytes(message)};")
emit("")
emit(f"static const POLICY_COMMITMENT_CASE POLICY_COMMITMENT_CASES"
     f"[{len(policy_cases)}] = {{")
for index, (row_id, public_key, message, signature, ok) in \
        enumerate(policy_cases):
    sig_padded = signature + b"\x00" * (80 - len(signature))
    emit("    {")
    emit(f"        \"{row_id}\",")
    emit(f"        {c_bytes(public_key)},")
    emit(f"        pmsg_{index}, {len(message)},")
    emit(f"        {c_bytes(sig_padded)}, {len(signature)},")
    emit(f"        {ok}")
    emit("    },")
emit("};")
emit("")

# ---- Rust direct-parse policy data (FBL-08) --------------------------
def rust_bytes(data):
    body = ", ".join(f"0x{b:02x}" for b in data)
    return f"&[{body}]"


rust_lines = [
    "// Generated by provider-tests/gen_vectors.py from frozen repository edge vectors.",
    "// Do not edit by hand; regenerate instead.  Each row carries the",
    "// declared expected policy results for direct assertion at the",
    "// frozen core's public parse API.",
    "#![allow(clippy::all)]",
    "",
    "pub const POINT_POLICY: &[(&str, &[u8], bool, bool)] = &[",
]
for case in EDGE["point_cases"]:
    enc = bytes.fromhex(case["encoding_hex"])
    pub_ok = case["expected"]["public_key_policy"] == "accept"
    com_ok = case["expected"]["commitment_policy"] == "accept"
    rust_lines.append(
        f"    (\"{case['id']}\", {rust_bytes(enc)}, "
        f"{str(pub_ok).lower()}, {str(com_ok).lower()}),")
rust_lines.append("];")
rust_lines.append("")
rust_lines.append("pub const SCALAR_POLICY: &[(&str, &[u8], bool)] = &[")
for case in EDGE["scalar_cases"]:
    enc = bytes.fromhex(case["encoding_hex"])
    ok = case["expected"] == "accept"
    rust_lines.append(
        f"    (\"{case['id']}\", {rust_bytes(enc)}, {str(ok).lower()}),")
rust_lines.append("];")
rust_lines.append("")
rust_lines.append(
    f"pub const VALID_R: &[u8] = {rust_bytes(base_signature[:FIELD_BYTES])};")
rust_lines.append(
    f"pub const VALID_S: &[u8] = {rust_bytes(base_signature[FIELD_BYTES:])};")
RUST_OUT.write_text("\n".join(rust_lines) + "\n")

# ---- historical Ed301-Sig-v1 incompatibility demonstration ----------
hist_vector = HIST["vectors"][0]
hist_public = bytes.fromhex(hist_vector["key_derivation"]["public_key_hex"])
hist_signature = bytes.fromhex(hist_vector["result"]["signature_hex"])
hist_message = bytes.fromhex(hist_vector["inputs"]["message_hex"])
hist_seed = bytes.fromhex(hist_vector["inputs"]["seed_hex"])
assert hist_seed == bytes.fromhex(empty["seed_hex"]), \
    "historical demonstration expects the shared seed"
assert hist_message == b""
emit("/* Historical Ed301-Sig-v1 'positive-empty' material (same seed as the")
emit(" * Ed301-EdDSA-v2 'empty' vector).  Used only to demonstrate that the")
emit(" * historical Ed301-Sig-v1 protocol does NOT verify as Ed301-EdDSA-v2. */")
emit(f"static const unsigned char HISTORICAL_PUBLIC_KEY[38] = "
     f"{c_bytes(hist_public)};")
emit(f"static const unsigned char HISTORICAL_SIGNATURE[76] = "
     f"{c_bytes(hist_signature)};")
emit("")
emit("#endif /* ED301V2_TEST_VECTORS_H */")

OUT.write_text("\n".join(lines) + "\n")

# OpenSSL's native EVP driver (same input grammar as the bound donor).
# Only the parameterless, empty-context whole-message surface is used here;
# context-specific and decoder cases are exercised by the C harnesses.
native = ["Title = Ed301-EdDSA v2 whole-message contract", ""]
for index, case in enumerate(POSITIVE["cases"]):
    key = f"ED301-V2-{index}"
    public_key = key + "-PUBLIC"
    native.extend([
        f"PrivateKeyRaw = {key}:Ed301-EdDSA:{case['seed_hex']}", "",
        f"PublicKeyRaw = {public_key}:Ed301-EdDSA:{case['public_key_hex']}", "",
        f"PrivPubKeyPair = {key}:{public_key}", "",
    ])
    for operation, name, message_hex, result in (
        ("Sign-Message", key, case["message_hex"], None),
        ("Verify-Message-Public", public_key, case["message_hex"], None),
        ("Verify-Message-Public", public_key, case["message_hex"] + "01", "VERIFY_ERROR"),
        ("Sign", key, case["message_hex"], "KEYOP_INIT_ERROR"),
        ("Verify", public_key, case["message_hex"], "KEYOP_INIT_ERROR"),
    ):
        native.extend([f"{operation} = Ed301-EdDSA:{name}",
                       'Input = ' + (message_hex or '\"\"'),
                       f"Output = {case['signature_hex']}"])
        if result:
            native.append(f"Result = {result}")
        native.append("")
OUT.with_name("openssl_evp_ed301.txt").write_text("\n".join(native) + "\n")
print(f"wrote {OUT} ({len(lines)} lines, "
      f"{len(negatives)} negative cases, "
      f"{len(verification_cases)} verification cases)")
