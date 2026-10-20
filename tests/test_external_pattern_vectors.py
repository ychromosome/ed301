# SPDX-License-Identifier: Apache-2.0
"""Reference replay of the libsodium- and Wycheproof-pattern corpora."""
import json
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
sys.path.insert(0, str(ROOT / "tools"))
import ed301_sig as sig
import generate_external_pattern_vectors as generator
import x301


def load(name):
    return json.loads((ROOT / "vectors" / name).read_text())


class ExternalPatternTests(unittest.TestCase):
    def test_sign_kat_inputs_and_sampled_signatures(self):
        cases = load("ed301-eddsa-v2-sign-kat.json")["cases"]
        self.assertEqual(len(cases), 1024)
        for i, case in enumerate(cases):
            material = generator.stream(b"Ed301-EdDSA-v2 libsodium sign.c pattern", i, sig.SEED_BYTES + i)
            self.assertEqual(case["seed"] + case["m"], material.hex())
            if i % 32 == 31:
                seed, message = bytes.fromhex(case["seed"]), bytes.fromhex(case["m"])
                self.assertEqual(sig.public_from_seed(seed).hex(), case["pk"])
                self.assertEqual(sig.sign(seed, message).hex(), case["sig"])
                self.assertTrue(sig.verify(bytes.fromhex(case["pk"]), message, bytes.fromhex(case["sig"])))

    def test_eddsa_wycheproof_pattern(self):
        group = load("ed301-eddsa-v2-wycheproof.json")["testGroups"][0]
        public = bytes.fromhex(group["publicKey"]["pk"])
        self.assertEqual(sig.public_from_seed(bytes.fromhex(group["seed"])), public)
        for case in group["tests"]:
            with self.subTest(tcId=case["tcId"]):
                accepted = sig.verify(public, bytes.fromhex(case["msg"]), bytes.fromhex(case["sig"]))
                self.assertEqual(accepted, case["result"] == "valid")

    def test_x301_wycheproof_pattern_targets_and_results(self):
        targets = dict(generator.TARGETS)
        tests = load("x301-v2-wycheproof.json")["testGroups"][0]["tests"]
        for case in tests:
            secret, public = bytes.fromhex(case["private"]), bytes.fromhex(case["public"])
            with self.subTest(tcId=case["tcId"]):
                match = re.fullmatch(r"special case for (.+) in multiplication by (\d) \((.+)\)", case["comment"])
                if match:
                    name, k, label = match.group(1), int(match.group(2)), match.group(3)
                    values = generator.ladder_variables(generator.clamped(secret), int.from_bytes(public, "little"),
                                                        generator.INT_OPS)
                    self.assertEqual(values[k][name], targets[label])
                    x_k, z_k = generator.c.montgomery_ladder_projective(k, int.from_bytes(public, "little"))
                    self.assertEqual(values[k]["x_2"] * z_k % generator.P, values[k]["z_2"] * x_k % generator.P)
                if case["result"] == "valid":
                    self.assertEqual(x301.x301(secret, public).hex(), case["shared"])
                else:
                    with self.assertRaises(x301.AllZeroError):
                        x301.x301(secret, public)
        self.assertEqual(sum("EdgeCaseMultiplication" in case["flags"] for case in tests),
                         sum(bool(re.match("special case for", case["comment"])) for case in tests))


if __name__ == "__main__":
    unittest.main()
