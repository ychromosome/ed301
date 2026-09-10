#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Isolated dependency-admission controls; never hide or alter a system tool."""

from pathlib import Path
import subprocess
import tempfile
import unittest

DRIVER = Path(__file__).with_name("check_codegen.sh")


class CodegenPrerequisites(unittest.TestCase):
    def run_fixture(self, profile, available):
        with tempfile.TemporaryDirectory(prefix="ed301-gawk-preflight-") as name:
            root = Path(name)
            tool = root / "synthetic-gawk"
            if available:
                tool.write_text("#!/bin/sh\nexit 0\n")
                tool.chmod(0o700)
            # Change only the executable-presence probe in a disposable copy.
            # The probe is before input validation, so no fixture tool executes.
            original = DRIVER.read_text()
            needle = "[ ! -x /usr/bin/gawk ]"
            self.assertEqual(original.count(needle), 1)
            driver = root / "driver.sh"
            driver.write_text(original.replace(needle, f"[ ! -x {tool} ]"))
            evidence = root / "must-not-exist"
            result = subprocess.run(["/bin/sh", str(driver), profile,
                str(root / "missing-elf"), str(root / "missing-marker"), str(evidence)],
                cwd="/", env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=10)
            self.assertFalse(evidence.exists())
            self.assertNotIn("PASS", result.stdout)
            return result

    def test_missing_gawk_rejects_both_x_profiles_early(self):
        for profile in ("x-core", "x-provider"):
            with self.subTest(profile=profile):
                result = self.run_fixture(profile, False)
                self.assertEqual(result.returncode, 127)
                self.assertIn("GNU awk required for X301", result.stdout)

    def test_ed_profiles_do_not_require_gawk(self):
        for profile in ("ed-core", "ed-provider"):
            with self.subTest(profile=profile):
                result = self.run_fixture(profile, False)
                self.assertEqual(result.returncode, 2)
                self.assertIn("must be a regular non-symlink file", result.stdout)
                self.assertNotIn("GNU awk required", result.stdout)

    def test_present_gawk_advances_to_input_validation(self):
        for profile in ("x-core", "x-provider"):
            with self.subTest(profile=profile):
                result = self.run_fixture(profile, True)
                self.assertEqual(result.returncode, 2)
                self.assertIn("must be a regular non-symlink file", result.stdout)
                self.assertNotIn("GNU awk required", result.stdout)


if __name__ == "__main__":
    unittest.main()
