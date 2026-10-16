# SPDX-License-Identifier: Apache-2.0
"""Tests for the Python Ed301 curve and signature references.

All seeds and signatures are public test fixtures.
"""

import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import ed301_curve as c
import ed301_sig as sig

CORPUS = json.loads((ROOT / "vectors/ed301-eddsa-v2.json").read_text())
V1_PATH = ROOT / "vectors/v1/ed301-eddsa-v1.json"
V1 = json.loads(V1_PATH.read_text())
HEX = bytes.fromhex


class CurveTests(unittest.TestCase):
    def test_parameter_binding_and_relations(self):
        self.assertEqual(CORPUS["parameter_sha256"], c.PARAMETER_SHA256)
        self.assertEqual(hashlib.sha256(c.PARAMETER_PATH.read_bytes()).hexdigest(), c.PARAMETER_SHA256)
        self.assertEqual(c.P, (1 << 301) - (1 << 89) + 907)
        self.assertEqual(c.A_EDWARDS, int(c.PARAMETERS["derivation"]["s"]) ** 2)
        self.assertEqual(c.D_EDWARDS, c.P - 301)
        self.assertEqual(c.N, c.H * c.Q)
        self.assertEqual(c.N + int(c.PARAMETERS["twist"]["order_decimal"]), 2 * (c.P + 1))
        self.assertEqual(c.P.bit_length(), 301)
        self.assertEqual(c.Q.bit_length(), 300)
        self.assertEqual(c.A_MONTGOMERY, 2 * (c.A_EDWARDS + c.D_EDWARDS) * pow(c.A_EDWARDS - c.D_EDWARDS, -1, c.P) % c.P)
        self.assertEqual(c.B_MONTGOMERY, 4 * pow(c.A_EDWARDS - c.D_EDWARDS, -1, c.P) % c.P)
        self.assertEqual(4 * c.A24_MINUS % c.P, (c.A_MONTGOMERY - 2) % c.P)
        self.assertEqual(pow(c.A_EDWARDS, (c.P - 1) // 2, c.P), 1)
        self.assertEqual(pow(c.D_EDWARDS, (c.P - 1) // 2, c.P), c.P - 1)

    def test_basepoint_derivation_and_order(self):
        p = c.PARAMETERS["basepoint"]
        self.assertEqual(p["first_counter"], 0)
        data = hashlib.shake_256(p["derivation_dst_ascii"].encode() + (0).to_bytes(4, "big")).digest(c.FIELD_BYTES)
        self.assertEqual(data.hex(), p["xof_output_hex"])
        y = int.from_bytes(data, "little") & ((1 << c.LADDER_BITS) - 1)
        candidate = (c.recover_x(y, 0), y)
        self.assertEqual(c.scalar_multiply(c.H, candidate), c.G)
        self.assertTrue(c.verify_basepoint())

    def test_field_canonical_boundaries(self):
        for n in (0, 1, c.P - 1):
            self.assertEqual(c.decode_field(c.encode_field(n)), n)
        for n in (c.P, c.P + 1, (1 << 301) - 1, 1 << 301, 1 << 302, 1 << 303):
            with self.subTest(n=n), self.assertRaises(ValueError):
                c.decode_field(n.to_bytes(38, "little"))
        for value in (bytes(37), bytes(39), bytearray(38), None, 0):
            with self.subTest(value=type(value)), self.assertRaises(ValueError):
                c.decode_field(value)
        for n in (-1, c.P):
            with self.assertRaises(ValueError):
                c.encode_field(n)

    def test_point_vectors(self):
        for v in CORPUS["point_decoding"]:
            with self.subTest(case=v["id"]):
                if v["accepted"]:
                    point = c.decode_point(HEX(v["encoded_hex"]))
                    self.assertEqual(point, (int(v["x"]), int(v["y"])))
                    self.assertEqual(c.encode_point(point).hex(), v["encoded_hex"])
                else:
                    with self.assertRaises(ValueError):
                        c.decode_point(HEX(v["encoded_hex"]))

    def test_scalar_vectors_and_lengths(self):
        for v in CORPUS["scalar_decoding"]:
            with self.subTest(case=v["id"]):
                if v["accepted"]:
                    value = c.decode_scalar(HEX(v["encoded_hex"]))
                    self.assertEqual(value, int(v["value"]))
                    self.assertEqual(c.encode_scalar(value).hex(), v["encoded_hex"])
                else:
                    with self.assertRaises(ValueError):
                        c.decode_scalar(HEX(v["encoded_hex"]))
        for value in (bytes(37), bytes(39), bytearray(38), None):
            with self.assertRaises(ValueError):
                c.decode_scalar(value)
        for n in (-1, c.Q):
            with self.assertRaises(ValueError):
                c.encode_scalar(n)

    def test_complete_addition_and_torsion(self):
        points = [c.IDENTITY, c.G, c.point_negate(c.G), c.ORDER_2, c.ORDER_4,
                  c.point_negate(c.ORDER_4), c.point_add(c.G, c.ORDER_4)]
        for left in points:
            self.assertEqual(c.point_add(left, c.IDENTITY), left)
            self.assertEqual(c.point_add(left, c.point_negate(left)), c.IDENTITY)
            for right in points:
                self.assertTrue(c.is_on_curve(c.point_add(left, right)))
                self.assertEqual(c.point_add(left, right), c.point_add(right, left))
                self.assertEqual(c.point_add(c.point_add(left, right), c.G),
                                 c.point_add(left, c.point_add(right, c.G)))
        self.assertEqual(c.scalar_multiply(2, c.ORDER_4), c.ORDER_2)
        self.assertEqual(c.scalar_multiply(4, c.ORDER_4), c.IDENTITY)
        self.assertEqual(c.scalar_multiply(c.N, points[-1]), c.IDENTITY)
        self.assertFalse(c.is_in_prime_subgroup(points[-1]))
        self.assertEqual(c.scalar_multiply(-7, c.G), c.point_negate(c.scalar_multiply(7, c.G)))

    def test_point_validation_rejects_invalid_internal_values(self):
        for point in ((0, 0), (c.P, 1), (-1, 1), (0, c.P + 1), (0,), None):
            self.assertFalse(c.is_on_curve(point))
            with self.assertRaises(ValueError):
                c.encode_point(point)
        with self.assertRaises(TypeError):
            c.scalar_multiply(b"1", c.G)

    def test_model_maps_and_ladder(self):
        self.assertIsNone(c.edwards_to_montgomery(c.IDENTITY))
        self.assertEqual(c.edwards_to_montgomery(c.ORDER_2), (0, 0))
        for point in (c.G, c.IDENTITY, c.ORDER_2, c.ORDER_4, c.point_negate(c.ORDER_4)):
            mont = c.edwards_to_montgomery(point)
            self.assertTrue(c.is_on_montgomery(mont))
            self.assertEqual(c.montgomery_to_edwards(mont), point)
        u = c.edwards_to_montgomery(c.G)[0]
        self.assertEqual(u, int(c.PARAMETERS["basepoint"]["G_montgomery_u_decimal"]))
        for scalar in (0, 1, 2, 3, 4, 7, c.Q - 1, c.Q, 1 << 300, (1 << 301) - 4):
            with self.subTest(scalar=scalar):
                result = c.edwards_to_montgomery(c.scalar_multiply(scalar, c.G))
                self.assertEqual(c.montgomery_ladder_u(scalar, u), None if result is None else result[0])
        for scalar, bad_u in ((-1, u), (1 << 301, u), (1, -1), (1, c.P)):
            with self.assertRaises(ValueError):
                c.montgomery_ladder_u(scalar, bad_u)


class SignatureTests(unittest.TestCase):
    def test_all_signing_intermediates_and_determinism(self):
        for v in CORPUS["signing"]:
            with self.subTest(case=v["id"]):
                seed, message, context = (HEX(v[k]) for k in ("seed_hex", "message_hex", "context_hex"))
                result = sig.sign_trace(seed, message, context)
                self.assertEqual({k: val.hex() for k, val in result.items()}, v["trace"])
                self.assertEqual(sig.public_from_seed(seed), result["public_key"])
                self.assertEqual(sig.sign(seed, message, context), result["signature"])
                self.assertTrue(sig.validate_public_key(result["public_key"]))
                self.assertTrue(sig.verify(result["public_key"], message, result["signature"], context))
                if not context:
                    self.assertEqual(sig.sign(seed, message), result["signature"])

    def test_all_verification_vectors(self):
        for v in CORPUS["verification"]:
            with self.subTest(case=v["id"]):
                self.assertEqual(sig.verify(HEX(v["public_key_hex"]), HEX(v["message_hex"]),
                                            HEX(v["signature_hex"]), HEX(v["context_hex"])), v["accepted"])

    def test_signing_errors_and_no_implicit_byte_conversion(self):
        for v in CORPUS["signing_errors"]:
            with self.subTest(case=v["id"]), self.assertRaises(ValueError):
                sig.sign(HEX(v["seed_hex"]), HEX(v["message_hex"]), HEX(v["context_hex"]))
        for args in ((None, b"", b""), (bytes(38), "message", b""),
                     (bytes(38), b"", None), (bytearray(38), b"", b"")):
            with self.assertRaises(ValueError):
                sig.sign(*args)
        v = CORPUS["signing"][0]["trace"]
        pk, signature = HEX(v["public_key"]), HEX(v["signature"])
        for args in ((None, b"", signature, b""), (pk, "message", signature, b""),
                     (pk, b"", None, b""), (pk, b"", signature, None)):
            self.assertFalse(sig.verify(*args))
        self.assertFalse(sig.validate_public_key(None))

    def test_domain_structure_and_binary_context(self):
        self.assertEqual(sig.domain(), b"SigEd301-v2\x00\x00")
        for context in (b"\x00", b"a\x00b\xff", bytes(range(255))):
            self.assertEqual(sig.domain(context), b"SigEd301-v2\x00" + bytes([len(context)]) + context)
        with self.assertRaises(ValueError):
            sig.domain(bytes(256))

    def test_pruning_extremes_and_nonidentity_proof(self):
        for digest, expected in ((bytes(76), 1 << 300), (b"\xff" * 76, (1 << 301) - 4)):
            with patch.object(sig, "hash_parts", return_value=digest):
                scalar, prefix, expanded = sig.expand_seed(bytes(38))
            self.assertEqual(scalar, expected)
            self.assertEqual(scalar % 4, 0)
            self.assertNotEqual(c.scalar_multiply(scalar, c.G), c.IDENTITY)
            self.assertEqual(prefix, digest[38:])
            self.assertEqual(expanded, digest)
        # Any multiple of odd q divisible by 4 is at least 4q, outside pruning.
        self.assertEqual(c.Q % 2, 1)
        self.assertGreaterEqual(4 * c.Q, 1 << 301)

    def test_public_key_policy_is_stricter_than_R_policy(self):
        for point in (c.IDENTITY, c.ORDER_2, c.ORDER_4, c.point_add(c.G, c.ORDER_4)):
            self.assertFalse(sig.validate_public_key(c.encode_point(point)))
        valid_torsion_R = [v for v in CORPUS["verification"] if "valid-cofactored" in v["id"]]
        self.assertEqual(len(valid_torsion_R), 8)
        self.assertTrue(all(v["accepted"] for v in valid_torsion_R))

    def test_v1_signatures_do_not_verify_under_v2(self):
        self.assertEqual(hashlib.sha256(V1_PATH.read_bytes()).hexdigest(),
                         "6dd09bd623af136be707bb1d57bf2502907cd0d2e30be71e1ef1ddbeab5b67f9")
        for v in V1["cases"] + V1["context_cases"]:
            with self.subTest(case=v["id"]):
                seed, message, context, old_pk, old_sig = (HEX(v[k]) for k in (
                    "seed_hex", "message_hex", "context_hex", "public_key_hex", "signature_hex"))
                self.assertFalse(sig.verify(old_pk, message, old_sig, context))
                new_pk = sig.public_from_seed(seed)
                self.assertNotEqual(new_pk, old_pk)
                self.assertFalse(sig.verify(new_pk, message, old_sig, context))


if __name__ == "__main__":
    unittest.main()
