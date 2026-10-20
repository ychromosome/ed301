#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Vectors that follow libsodium and Wycheproof test patterns; stdout or exact check.

sign-kat:        libsodium test/default/sign.c (SUPERCOP layout, message length i).
eddsa-wycheproof: Wycheproof ed25519/ed448 InvalidEncoding and InvalidSignature cases.
x301-wycheproof:  Wycheproof x25519/x448 EdgeCaseMultiplication, EdgeCaseShared,
                  SpecialPublicKey and EdgeCasePrivateKey cases.
The x301 corpus needs PARI/GP (polrootsmod) for regeneration only.
"""

import argparse
from hashlib import shake_256
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import ed301_curve as c
import ed301_sig as sig
import x301 as x

P = c.P
WYCHEPROOF = "https://github.com/C2SP/wycheproof"
LIBSODIUM = "https://github.com/jedisct1/libsodium/blob/stable/test/default/sign.c"


def stream(label, index, length):
    return shake_256(label + index.to_bytes(4, "little")).digest(length)


def sign_kat():
    cases = []
    for i in range(1024):
        material = stream(b"Ed301-EdDSA-v2 libsodium sign.c pattern", i, sig.SEED_BYTES + i)
        seed, message = material[:sig.SEED_BYTES], material[sig.SEED_BYTES:]
        cases.append({"seed": seed.hex(), "pk": sig.public_from_seed(seed).hex(),
                      "sig": sig.sign(seed, message).hex(), "m": message.hex()})
    return {"schema": "Ed301-EdDSA-v2-sign-kat-1", "pattern": LIBSODIUM, "parameter_sha256": c.PARAMETER_SHA256,
            "rule": "case i: SHAKE256(label || le32(i)) gives seed (38 bytes) then message (i bytes)",
            "cases": cases}


def eddsa_wycheproof():
    seed = stream(b"Ed301-EdDSA-v2 Wycheproof pattern key", 0, sig.SEED_BYTES)
    scalar, _, _ = sig.expand_seed(seed)
    public = sig.public_from_seed(seed)
    tests = []

    def add(comment, flags, message, signature, result):
        tests.append({"tcId": len(tests) + 1, "comment": comment, "flags": flags, "msg": message.hex(),
                      "sig": signature.hex(), "result": result})

    message = b"123400"
    trace = sig.sign_trace(seed, message)
    nonce = int.from_bytes(trace["nonce_scalar"], "little")
    add("", ["Valid"], message, trace["signature"], "valid")

    def recomputed(r_encoding):
        challenge = int.from_bytes(sig.hash_parts(sig.domain(), r_encoding, public, message), "little") % c.Q
        return r_encoding + c.encode_scalar((nonce + challenge * scalar) % c.Q)

    for bit in range(8 * c.FIELD_BYTES):
        changed = bytearray(trace["commitment"])
        changed[bit >> 3] ^= 1 << (bit & 7)
        add(f"modified bit {bit} in R", ["InvalidEncoding"], message, recomputed(bytes(changed)), "invalid")
    add("all bits flipped in R", ["InvalidEncoding"], message,
        recomputed(bytes(b ^ 0xFF for b in trace["commitment"])), "invalid")

    special = b"?"
    for r in (0, 1, c.Q, P):
        for s in (0, 1, c.Q - 1, c.Q, P):
            add("special values for r and s", ["InvalidSignature"], special,
                r.to_bytes(c.FIELD_BYTES, "little") + s.to_bytes(c.SCALAR_BYTES, "little"), "invalid")
    for case in tests:
        accepted = sig.verify(public, bytes.fromhex(case["msg"]), bytes.fromhex(case["sig"]))
        if accepted != (case["result"] == "valid"):
            raise RuntimeError(f"reference disagrees with tcId {case['tcId']}")
    return {"algorithm": "Ed301-EdDSA-v2", "schema": "eddsa_verify_schema_v1.json", "pattern": WYCHEPROOF,
            "parameter_sha256": c.PARAMETER_SHA256, "numberOfTests": len(tests),
            "testGroups": [{"type": "EddsaVerify", "publicKey": {"pk": public.hex()}, "seed": seed.hex(),
                            "tests": tests}]}


# Polynomials over F_p in u, lowest coefficient first.
def padd(f, g):
    n = max(len(f), len(g))
    return [((f[i] if i < len(f) else 0) + (g[i] if i < len(g) else 0)) % P for i in range(n)]


def pneg(f):
    return [-v % P for v in f]


def pmul(f, g):
    out = [0] * (len(f) + len(g) - 1)
    for i, a in enumerate(f):
        if a:
            for j, b in enumerate(g):
                out[i + j] += a * b
    return [v % P for v in out]


def ladder_variables(scalar, x1, ops):
    """RFC 7748 ladder with Wycheproof's variable names; values at the first step per prefix."""
    add, sub, mul, const = ops
    x2, z2, x3, z3 = const(1), const(0), x1, const(1)
    swap = 0
    prefix = 0
    seen = {}
    for bit_index in range(c.LADDER_BITS - 1, -1, -1):
        bit = (scalar >> bit_index) & 1
        prefix = 2 * prefix + bit
        if swap ^ bit:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a = add(x2, z2)
        aa = mul(a, a)
        b = sub(x2, z2)
        bb = mul(b, b)
        e = sub(aa, bb)
        cc = add(x3, z3)
        d = sub(x3, z3)
        da = mul(d, a)
        cb = mul(cc, b)
        x3 = mul(add(da, cb), add(da, cb))
        z3 = mul(x1, mul(sub(da, cb), sub(da, cb)))
        x2 = mul(aa, bb)
        z2 = mul(e, add(aa, mul(const(c.A24_MINUS), e)))
        seen.setdefault(prefix, {"A": a, "AA": aa, "B": b, "BB": bb, "E": e, "C": cc, "D": d, "DA": da,
                                 "CB": cb, "DA + CB": add(da, cb), "DA - CB": sub(da, cb),
                                 # After the deferred swap, [prefix]P sits in (x_3, z_3) when bit is 1.
                                 "x_2": x3 if bit else x2, "z_2": z3 if bit else z2})
        if prefix >= 8:
            return seen
    return seen


POLY_OPS = (padd, lambda f, g: padd(f, pneg(g)), pmul, lambda v: [v % P])
INT_OPS = (lambda f, g: (f + g) % P, lambda f, g: (f - g) % P, lambda f, g: f * g % P, lambda v: v % P)
# Wycheproof x25519/x448 targets: 0, 1, -1, 2^(n-1)-1, 2^224 and 2^n mod p.
TARGETS = (("0", 0), ("1", 1), ("-1", P - 1), ("2^300-1", 2**300 - 1), ("2^224", 2**224),
           ("2^301 mod p", 2**301 % P))


def roots_mod_p(polynomials):
    script = [f"p={P};"]
    for f in polynomials:
        terms = "+".join(f"{v}*x^{i}" for i, v in enumerate(f) if v) or "0"
        script.append(f"print(apply(lift,Vec(polrootsmod({terms},p))));")
    output = subprocess.run(["gp", "-q", "-D", "parisizemax=2G"], input="\n".join(script), text=True,
                            capture_output=True, check=True).stdout.splitlines()
    if len(output) != len(polynomials):
        raise RuntimeError("unexpected PARI/GP output")
    return [sorted(json.loads(line)) for line in output]


def classify(u):
    rhs = (u ** 3 + c.A_MONTGOMERY * u * u + u) * pow(c.B_MONTGOMERY, -1, P) % P
    return pow(rhs, (P - 1) // 2, P) != 1 and rhs != 0


def clamped(secret):
    return int.from_bytes(x.clamp_secret_bytes(secret), "little")


def with_prefix(secret, k):
    """Set the top ladder bits so that the scalar prefix equals k."""
    value = int.from_bytes(secret, "little")
    width = k.bit_length()
    for offset in range(width):
        position = c.LADDER_BITS - 1 - offset
        value = value & ~(1 << position) | (((k >> (width - 1 - offset)) & 1) << position)
    return value.to_bytes(x.SECRET_BYTES, "little")


def x301_wycheproof():
    tests = []

    def add(comment, flags, secret, u):
        public = c.encode_field(u)
        if any(case["public"] == public.hex() and case["private"] == secret.hex() for case in tests):
            return
        try:
            shared, result = x.x301(secret, public).hex(), "valid"
        except x.AllZeroError:
            shared, result = "", "invalid"
            flags = flags + ["ZeroSharedSecret"]
        if classify(u):
            flags = flags + ["Twist"]
        tests.append({"tcId": len(tests) + 1, "comment": comment, "flags": flags, "public": public.hex(),
                      "private": secret.hex(), "shared": shared, "result": result})

    jobs = []
    for k in range(2, 10):
        secret = with_prefix(stream(b"X301-v2 Wycheproof multiplication", k, x.SECRET_BYTES), k)
        variables = ladder_variables(clamped(secret), [0, 1], POLY_OPS)[k]
        for name, polynomial in variables.items():
            if len(polynomial) < 2:
                continue
            for label, target in TARGETS:
                jobs.append((k, secret, name, label, target, padd(polynomial, [-target % P])))
    for (k, secret, name, label, target, _), roots in zip(jobs, roots_mod_p([job[-1] for job in jobs])):
        for u in roots[:2]:
            if ladder_variables(clamped(secret), u, INT_OPS)[k][name] != target:
                raise RuntimeError("root does not reach the target")
            add(f"special case for {name} in multiplication by {k} ({label})", ["EdgeCaseMultiplication"],
                secret, u)

    secret = stream(b"X301-v2 Wycheproof shared", 0, x.SECRET_BYTES)
    scalar = clamped(secret)
    q_twist = x.N_TWIST // 4

    def reachable(value):
        if not 0 < value < P:
            return None
        order = q_twist if classify(value) else c.Q
        if c.montgomery_ladder_u(order, value) is not None:
            return None
        return c.montgomery_ladder_u(pow(scalar, -1, order), value)

    # Wycheproof x25519: small, 2^(n-1)-i, 2^(n-5)-1, p-i, 2^(n-6), 2^(n-8).
    for base, step, count in ((1, 1, 3), (2**300 - 1, -1, 4), (2**296 - 1, -1, 1), (P - 1, -1, 4),
                              (2**295, 1, 1), (2**293, 1, 1)):
        found, offset = 0, 0
        while found < count:
            value = base + step * offset
            offset += 1
            u = reachable(value)
            if u is None:
                continue
            found += 1
            add("edge case for shared secret", ["EdgeCaseShared"], secret, u)
            if x.x301(secret, c.encode_field(u)) != c.encode_field(value):
                raise RuntimeError("edge shared secret construction failed")

    secret = stream(b"X301-v2 Wycheproof public", 0, x.SECRET_BYTES)
    # Wycheproof x25519 exponents; 285, 296, 299 and 300 stand for n-16, n-5, n-2 and n-1.
    specials = {2, 3, 4, 255, 256, 2**16, 2**16 - 1, P - 2, P - 3, P - 256}
    for e in (28, 32, 52, 56, 64, 112, 128, 192, 224, 285, 296, 299, 300):
        specials |= {2**e - 1, 2**e, P - 2**e}
    for word, width in ((2**64 - 1, 64), (2**32 - 1, 32)):
        specials.add(sum(word << (2 * width * i) for i in range(301 // (2 * width) + 1)) % 2**301 % P)
    for u in sorted(specials):
        add("edge case public key", ["SpecialPublicKey"], secret, u)

    base_u = int.from_bytes(x.BASE_U_ENCODING, "little")
    twist_u = next(u for u in range(2, 100) if classify(u))
    twist_point = c.montgomery_ladder_u(4, twist_u)
    for order, u, flag in ((c.Q, base_u, "curve"), (q_twist, twist_point, "twist")):
        for multiple in range(1, 8):
            value = multiple * order + 1
            if 2**300 <= value < 2**301 and value % 4 == 0 and value != x.N_TWIST:
                secret = value.to_bytes(x.SECRET_BYTES, "little")
                add(f"private key == 1 (mod order) on {flag}", ["EdgeCasePrivateKey"], secret, u)
    for pattern in (b"\x55", b"\xaa"):
        secret = pattern * x.SECRET_BYTES
        for u in (base_u, twist_point, 2**224):
            add("special case private key", ["EdgeCasePrivateKey"], secret, u)
    return {"algorithm": "X301-v2", "schema": "xdh_comp_schema_v1.json", "pattern": WYCHEPROOF,
            "parameter_sha256": c.PARAMETER_SHA256, "numberOfTests": len(tests),
            "testGroups": [{"type": "XdhComp", "curve": "X301", "tests": tests}]}


CORPORA = {"sign-kat": sign_kat, "eddsa-wycheproof": eddsa_wycheproof, "x301-wycheproof": x301_wycheproof}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", choices=sorted(CORPORA))
    parser.add_argument("--check", type=Path)
    args = parser.parse_args()
    output = json.dumps(CORPORA[args.corpus](), indent=1) + "\n"
    if args.check:
        if args.check.read_text() != output:
            raise SystemExit(f"FAIL: {args.corpus} regeneration differs")
        print(f"PASS: deterministic {args.corpus} regeneration")
    else:
        print(output, end="")
