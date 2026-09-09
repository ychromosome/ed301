# SPDX-License-Identifier: Apache-2.0
"""X301 strict contract tests with public synthetic secrets only."""

import hashlib
import inspect
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import ed301_curve as c
import x301 as x

CORPUS = json.loads((ROOT / "vectors/x301-v2.json").read_text())
KEYS = {v["id"]: v for v in CORPUS["keys"]}
HEX = bytes.fromhex


def weierstrass_x(scalar, u, z):
    """Independent affine model calculation, including the specified z=2 twist.

    X=z*B*u, Y²=X³+(z*A*B)X²+(z*B)²X. Uses the usual chord/tangent rule,
    no Edwards addition, Montgomery ladder or Python X301 result.
    """
    p = c.P
    scale = z * c.B_MONTGOMERY % p
    a2, a4 = c.A_MONTGOMERY * scale % p, scale * scale % p
    xx = scale * u % p
    rhs = (xx ** 3 + a2 * xx * xx + a4 * xx) % p
    yy = pow(rhs, (p + 1) // 4, p)
    if yy * yy % p != rhs:
        raise ValueError("point is not on selected Weierstrass model")

    def add(left, right):
        if left is None:
            return right
        if right is None:
            return left
        x1, y1 = left
        x2, y2 = right
        if x1 == x2 and (y1 + y2) % p == 0:
            return None
        if left == right:
            slope = (3 * x1 * x1 + 2 * a2 * x1 + a4) * pow(2 * y1, -1, p) % p
        else:
            slope = (y2 - y1) * pow(x2 - x1, -1, p) % p
        x3 = (slope * slope - a2 - x1 - x2) % p
        y3 = (slope * (x1 - x3) - y1) % p
        if (y3 * y3 - x3 ** 3 - a2 * x3 * x3 - a4 * x3) % p:
            raise ArithmeticError("Weierstrass invariant")
        return x3, y3

    result = None
    point = (xx, yy)
    for bit in bin(scalar)[2:]:
        result = add(result, result)
        if bit == "1":
            result = add(result, point)
    return None if result is None else result[0] * pow(scale, -1, p) % p


class X301Tests(unittest.TestCase):
    def test_contract_and_parameter_hashes(self):
        self.assertEqual(CORPUS["parameter_sha256"], c.PARAMETER_SHA256)
        path = ROOT / "phase-b/inputs/X301-v2_EINGABEVERTRAG_2026-09-10.md"
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), CORPUS["contract_sha256"])
        self.assertEqual(CORPUS["contract_sha256"], "b33d3fe0bf6b5b026192695902902f4b7592d4271ca98161f47920b47c6a1c2c")
        self.assertEqual(x.N_TWIST, 4 * int(c.PARAMETERS["twist"]["q_twist_decimal"]))
        self.assertEqual(x.N_TWIST_ENCODING.hex(), "84ca911e62530d13b204a5718d1a9ada9621c5ffffffffffffffffffffffffffffffffffff1f")
        self.assertEqual(int.from_bytes(x.BASE_U_ENCODING, "little"), c.edwards_to_montgomery(c.G)[0])
        self.assertLess(x.N_TWIST, 1 << 301)
        self.assertGreaterEqual(x.N_TWIST, 1 << 300)
        self.assertEqual(x.N_TWIST % 4, 0)
        qt = int(c.PARAMETERS["twist"]["q_twist_decimal"])
        self.assertEqual([n * qt for n in range(1, 6) if (1 << 300) <= n * qt < (1 << 301) and n * qt % 4 == 0], [x.N_TWIST])
        self.assertGreater(5 * qt, 1 << 301)
        self.assertGreaterEqual(4 * c.Q, 1 << 301)

    def test_keys_clamping_import_and_edwards_agreement(self):
        for v in CORPUS["keys"]:
            with self.subTest(case=v["id"]):
                raw = HEX(v["secret_hex"])
                self.assertEqual(x.clamp_secret_bytes(raw).hex(), v["clamped_hex"])
                self.assertEqual(x.import_secret(raw), raw)
                scalar = x.decode_secret_scalar(raw)
                self.assertEqual(scalar % 4, 0)
                self.assertEqual(scalar.bit_length(), 301)
                result = x.public_from_secret(raw)
                self.assertEqual(result.hex(), v["public_hex"])
                point = c.edwards_to_montgomery(c.scalar_multiply(scalar, c.G))
                self.assertEqual(c.decode_field(result), point[0])
                self.assertNotEqual(result, bytes(38))

    def test_dh_both_directions(self):
        for v in CORPUS["dh"]:
            a, b = KEYS[v["a"]], KEYS[v["b"]]
            with self.subTest(case=v["id"]):
                self.assertEqual(x.shared_secret(HEX(a["secret_hex"]), HEX(b["public_hex"])).hex(), v["shared_hex"])
                self.assertEqual(x.shared_secret(HEX(b["secret_hex"]), HEX(a["public_hex"])).hex(), v["shared_hex"])

    def test_curve_twist_vectors_against_independent_weierstrass(self):
        classes = set()
        for v in CORPUS["evaluations"]:
            with self.subTest(case=v["id"]):
                secret, encoded_u = HEX(KEYS[v["key"]]["secret_hex"]), HEX(v["u_hex"])
                u = c.decode_field(encoded_u)
                rhs = (u ** 3 + c.A_MONTGOMERY * u * u + u) * pow(c.B_MONTGOMERY, -1, c.P) % c.P
                symbol = pow(rhs, (c.P - 1) // 2, c.P)
                kind = "curve" if symbol == 1 else "twist"
                self.assertIn(symbol, (1, c.P - 1))
                self.assertEqual(kind, v["classification"])
                classes.add(kind)
                expected = weierstrass_x(x.decode_secret_scalar(secret), u, 1 if kind == "curve" else 2)
                self.assertIsNotNone(expected)
                self.assertEqual(c.encode_field(expected).hex(), v["result_hex"])
                self.assertEqual(x.x301(secret, encoded_u).hex(), v["result_hex"])
        self.assertEqual(classes, {"curve", "twist"})

    def test_malformed_inputs_fail_before_first_ladder_step(self):
        for v in CORPUS["errors"]:
            if v["stage"] == "result":
                continue
            with self.subTest(case=v["id"]), patch.object(c, "montgomery_ladder_projective") as ladder:
                sentinel = object()
                output = sentinel
                with self.assertRaises(ValueError):
                    output = x.x301(HEX(v["secret_hex"]), HEX(v["u_hex"]))
                self.assertIs(output, sentinel)
                ladder.assert_not_called()
        for secret, peer in ((None, x.BASE_U_ENCODING), (bytes(38), None),
                             (bytes(38), bytearray(38)), (bytearray(38), x.BASE_U_ENCODING)):
            with patch.object(c, "montgomery_ladder_projective") as ladder:
                with self.assertRaises(ValueError):
                    x.x301(secret, peer)
                ladder.assert_not_called()

    def test_all_zero_cases_and_no_partial_output(self):
        for v in CORPUS["errors"]:
            if v["stage"] != "result":
                continue
            with self.subTest(case=v["id"]):
                sentinel = object()
                output = sentinel
                with self.assertRaises(x.AllZeroError):
                    output = x.x301(HEX(v["secret_hex"]), HEX(v["u_hex"]))
                self.assertIs(output, sentinel)
        for projective in ((0, 1), (1, 0)):
            with patch.object(c, "montgomery_ladder_projective", return_value=projective):
                with self.assertRaises(x.AllZeroError):
                    x.x301(bytes(38), x.BASE_U_ENCODING)

    def test_small_order_points_and_twist_annihilator(self):
        self.assertEqual(pow((c.A_MONTGOMERY ** 2 - 4) % c.P, (c.P - 1) // 2, c.P), c.P - 1)
        for u in (0, 1, c.P - 1):
            rhs = (u ** 3 + c.A_MONTGOMERY * u * u + u) * pow(c.B_MONTGOMERY, -1, c.P) % c.P
            z = 1 if rhs == 0 or pow(rhs, (c.P - 1) // 2, c.P) == 1 else 2
            self.assertIsNone(weierstrass_x(4, u, z))
        twist = next(v for v in CORPUS["evaluations"] if v["classification"] == "twist")
        u = c.decode_field(HEX(twist["u_hex"]))
        self.assertIsNone(weierstrass_x(x.N_TWIST, u, 2))

    def test_library_byte_comparisons_cover_secret_and_result(self):
        with patch.object(x, "compare_digest", wraps=x.compare_digest) as compare:
            result = x.public_from_secret(bytes(38))
            self.assertEqual(compare.call_count, 2)
            self.assertEqual(compare.call_args_list[0].args, (HEX(KEYS["zeros"]["clamped_hex"]), x.N_TWIST_ENCODING))
            self.assertEqual(compare.call_args_list[1].args, (result, bytes(38)))

    def test_all_64_weak_aliases_across_entrypoints(self):
        aliases = CORPUS["weak_secrets"]
        self.assertEqual(len({v["secret_hex"] for v in aliases}), 64)
        for v in aliases:
            raw = HEX(v["secret_hex"])
            with self.subTest(case=v["id"]):
                clamped = bytearray(raw)
                clamped[0] &= 0xFC
                clamped[-1] = (clamped[-1] & 15) | 16
                self.assertEqual(bytes(clamped), x.N_TWIST_ENCODING)
                with patch.object(c, "montgomery_ladder_projective") as ladder:
                    for function, args in ((x.clamp_secret_bytes, (raw,)), (x.decode_secret_scalar, (raw,)),
                                           (x.import_secret, (raw,)), (x.public_from_secret, (raw,)),
                                           (x.shared_secret, (raw, x.BASE_U_ENCODING))):
                        with self.assertRaises(x.WeakSecretError):
                            function(*args)
                    ladder.assert_not_called()
                values = iter((raw, bytes(38)))
                draws = []
                def rng(n):
                    draws.append(n)
                    return next(values)
                secret, public = x.keygen(rng)
                self.assertEqual(draws, [38, 38])
                self.assertEqual(secret, bytes(38))
                self.assertEqual(public.hex(), KEYS["zeros"]["public_hex"])

    def test_valid_clamp_aliases_leave_public_result_unchanged(self):
        canonical = HEX(KEYS["ascending"]["clamped_hex"])
        for low in range(4):
            for high in range(16):
                alias = bytearray(canonical)
                alias[0] |= low
                alias[-1] = (alias[-1] & 15) | (high << 4)
                self.assertEqual(x.clamp_secret_bytes(bytes(alias)), canonical)
                self.assertEqual(x.public_from_secret(bytes(alias)).hex(), KEYS["ascending"]["public_hex"])

    def test_keygen_does_not_retry_other_errors(self):
        for bad in (bytes(37), bytes(39), None, "not bytes"):
            calls = []
            def rng(n):
                calls.append(n)
                return bad
            with self.assertRaises(ValueError):
                x.keygen(rng)
            self.assertEqual(calls, [38])
        error = OSError("synthetic RNG failure")
        with patch.object(x, "public_from_secret", side_effect=ValueError("internal failure")) as public:
            with self.assertRaises(ValueError):
                x.keygen(lambda n: bytes(n))
            self.assertEqual(public.call_count, 1)
        def failed_rng(n):
            raise error
        with self.assertRaises(OSError) as caught:
            x.keygen(failed_rng)
        self.assertIs(caught.exception, error)

    def test_exact_301_rounds_including_leading_zeros(self):
        function = c.montgomery_ladder_projective
        source, start = inspect.getsourcelines(function)
        bit_line = start + next(i for i, line in enumerate(source) if "bit = (scalar >> bit_index)" in line)
        for scalar in (0, 1, 1 << 300, (1 << 301) - 4):
            rounds = []
            def trace(frame, event, arg):
                if event == "line" and frame.f_code is function.__code__ and frame.f_lineno == bit_line:
                    rounds.append(frame.f_locals["bit_index"])
                return trace
            previous = sys.gettrace()
            try:
                sys.settrace(trace)
                function(scalar, int.from_bytes(x.BASE_U_ENCODING, "little"))
            finally:
                sys.settrace(previous)
            self.assertEqual(rounds, list(range(300, -1, -1)))

    def test_iteration_chain(self):
        k = u = x.BASE_U_ENCODING
        checkpoints = {v["count"]: v for v in CORPUS["iteration"]["checkpoints"]}
        self.assertEqual(list(checkpoints), [1, 10, 100, 1000])
        for n in range(1, 1001):
            k, u = x.x301(k, u), k
            if n in checkpoints:
                self.assertEqual(k.hex(), checkpoints[n]["k_hex"])
                self.assertEqual(u.hex(), checkpoints[n]["u_hex"])


if __name__ == "__main__":
    unittest.main()
