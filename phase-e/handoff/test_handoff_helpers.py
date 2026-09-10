#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Synthetic admission tests; no original evidence files are modified."""

from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from handoff_common import check_command_logs, check_members, digest, manifest_rows, read_json, relative_path


class HandoffControls(unittest.TestCase):
    def test_paths(self):
        self.assertEqual(relative_path("logs/pass.log"), Path("logs/pass.log"))
        for name in ("", ".", "..", "../x", "/tmp/x", "x//y", "x/./y", "x\\y"):
            with self.subTest(name=name), self.assertRaises(SystemExit):
                relative_path(name)

    def test_seals(self):
        with tempfile.TemporaryDirectory(prefix="ed301-phase-e-seal-control-") as name:
            root = Path(name)
            member = root / "member"
            member.write_text("synthetic fixture\n")
            manifest = root / "SHA256SUMS"
            line = digest(member) + "  member\n"
            manifest.write_text(line)
            expected = digest(manifest)
            self.assertEqual(check_members(root, "SHA256SUMS", expected), {"member": digest(member)})
            with self.assertRaises(SystemExit):
                check_members(root, "SHA256SUMS", "0" * 64)
            member.write_text("different synthetic bytes\n")
            with self.assertRaises(SystemExit):
                check_members(root, "SHA256SUMS", expected)
            for content in ("", line + line, line.replace("member", "../member"), "invalid\n"):
                manifest.write_text(content)
                with self.subTest(content=content), self.assertRaises(SystemExit):
                    manifest_rows(manifest)

    def test_json_duplicates(self):
        with tempfile.TemporaryDirectory(prefix="ed301-phase-e-json-control-") as name:
            path = Path(name) / "input.json"
            path.write_text('{"status":"PASS"}\n')
            self.assertEqual(read_json(path), {"status": "PASS"})
            path.write_text('{"status":"PASS","status":"FAIL"}\n')
            with self.assertRaises(SystemExit):
                read_json(path)

    def test_command_logs(self):
        with tempfile.TemporaryDirectory(prefix="ed301-phase-e-command-control-") as name:
            root = Path(name)
            path = root / "commands.json"
            rows = {"logs/run.log": "a" * 64}
            for content in ('[{"name":"run","log":"logs/run.log"}]',
                            '[{"name":"run"}]', '[{"step":"run"}]'):
                path.write_text(content)
                self.assertEqual(check_command_logs(root, rows), 1)
            for content in ('[{}]', '[{"step":"missing"}]',
                            '[{"log":"../outside"}]',
                            '[{"log":"logs/run.log","log_sha256":"wrong"}]'):
                path.write_text(content)
                with self.subTest(content=content), self.assertRaises(SystemExit):
                    check_command_logs(root, rows)


if __name__ == "__main__":
    unittest.main()
