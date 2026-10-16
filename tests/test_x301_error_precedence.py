# SPDX-License-Identifier: Apache-2.0
"""Shared current-profile error ordering; historical vectors stay unchanged."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import ed301_curve as curve
import x301


class ErrorPrecedenceTests(unittest.TestCase):
    def test_shared_precedence_corpus(self):
        corpus = json.loads((ROOT / "vectors/x301-error-precedence.json").read_text())
        messages = {"InvalidSecretLength": "X301 secret must be exactly 38 bytes",
                    "WeakSecret": "X301 clamped secret equals the twist order",
                    "InvalidPublicLength": "field encoding must be exactly 38 bytes"}
        count = 0
        for secret in corpus["secrets"]:
            for peer in corpus["peers"]:
                expected = secret["error"] or peer["error"]
                if expected is None:
                    continue
                with self.subTest(secret=secret["id"], peer=peer["id"]):
                    with patch.object(curve, "montgomery_ladder_projective") as ladder:
                        with self.assertRaises(ValueError) as caught:
                            x301.shared_secret(bytes.fromhex(secret["hex"]), bytes.fromhex(peer["hex"]))
                        ladder.assert_not_called()
                    self.assertEqual(isinstance(caught.exception, x301.WeakSecretError), expected == "WeakSecret")
                    if expected in messages:
                        self.assertEqual(str(caught.exception), messages[expected])
                    else:
                        self.assertIn(str(caught.exception), (
                            "non-canonical field encoding",
                            "field encoding has a nonzero bit 301, 302, or 303"))
                    count += 1
        self.assertEqual(count, 39)


if __name__ == "__main__":
    unittest.main()
