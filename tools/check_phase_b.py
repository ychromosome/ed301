#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Read-only replay of the complete Phase-B references; Gate B remains external."""

from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
STEPS = [
    ("Phase-B source/vector hashes", ROOT,
     ["sha256sum", "--check", "phase-b/PHASE_B_SOURCE_MANIFEST.sha256"]),
    ("unchanged Gate-A package", ROOT / "provenance/phase-a/2026-09-09",
     ["sha256sum", "--check", "PHASE_A_MANIFEST.sha256"]),
    ("unchanged signed search package", ROOT / "provenance/v2-search",
     ["sha256sum", "--check", "RUN_MANIFEST.sha256"]),
    ("Python reference, edge cases and v1 controls", ROOT,
     [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-v"]),
    ("Node extended-coordinate counterimplementation", ROOT,
     ["node", "reference/node/check_vectors.mjs"]),
    ("Node X301 counterimplementation and rejection boundaries", ROOT,
     ["node", "reference/node/check_x301_vectors.mjs"]),
    ("exact deterministic Ed301 vector regeneration", ROOT,
     [sys.executable, "-B", "tools/generate_phase_b_vectors.py", "--check", "vectors/ed301-eddsa-v2.json"]),
    ("exact deterministic X301 vector regeneration", ROOT,
     [sys.executable, "-B", "tools/generate_x301_vectors.py", "--check", "vectors/x301-v2.json"]),
]


def main():
    for index, (name, cwd, command) in enumerate(STEPS, 1):
        print(f"STEP {index}/{len(STEPS)}: {name}", flush=True)
        try:
            result = subprocess.run(command, cwd=cwd, check=False)
        except OSError as error:
            print(f"FAIL: {name}: {error}", file=sys.stderr)
            return 1
        if result.returncode:
            print(f"FAIL: {name}: exit {result.returncode}", file=sys.stderr)
            return 1
        print(f"PASS: {name}", flush=True)
    print("PASS: complete Phase-B reference replay. Claude's Gate B is still required; no Phase C or production approval.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
