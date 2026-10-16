#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the Ed301 and X301 secret-taint harnesses under Valgrind.

The harnesses mark secret inputs as undefined ("tainted") for Memcheck, so any
branch or memory index that depends on a secret is reported as an error. Each
case also runs with defined inputs as a control. From the repository root:

    python3 -I rust/run_secret_taint.py [--workdir DIR] [--jobs N]

Requires valgrind and valgrind-devel. Ed301 covers public-key derivation and
signing for every signing vector; X301 covers public-key derivation, secret
import and shared-secret computation for the full vector corpus, including
error cases and the 64 excluded secrets.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("--workdir", type=Path)
parser.add_argument("--jobs", type=int, default=os.cpu_count() or 4)
args = parser.parse_args()
work = (args.workdir or Path(tempfile.mkdtemp(prefix="ed301-taint-"))).resolve()
work.mkdir(parents=True, exist_ok=True)

clean = {"PATH": "/usr/bin:/bin", "HOME": str(work), "LC_ALL": "C"}
build_env = dict(clean, CARGO_HOME=os.environ.get("CARGO_HOME", str(work / "cargo-home")),
                 CARGO_TARGET_DIR=str(work / "target"), CC="/usr/bin/gcc", AR="/usr/bin/ar",
                 ED301_HERMETIC_NATIVE_BUILD="1")
for crate in ("secret-taint", "x301-secret-taint"):
    subprocess.run(["cargo", "build", "--release", "--locked", "--manifest-path",
                    ROOT / "rust" / crate / "Cargo.toml"], env=build_env, check=True)

valgrind = ["valgrind", "--tool=memcheck", "--vgdb=no", "--enable-debuginfod=no", "--error-exitcode=99",
            "--track-origins=yes", "--undef-value-errors=yes", "--leak-check=full",
            "--errors-for-leak-kinds=definite,indirect,possible", "--quiet"]
runs = []

ed = work / "target/release/ed301-eddsa-secret-taint"
for case in json.loads((ROOT / "vectors/ed301-eddsa-v2.json").read_text())["signing"]:
    env = dict(clean, ED301_CT_SECRET_HEX=case["seed_hex"],
               ED301_CT_EXPECTED_PUBLIC_HEX=case["trace"]["public_key"],
               ED301_CT_EXPECTED_SIGNATURE_HEX=case["trace"]["signature"],
               ED301_CT_MESSAGE_HEX=case["message_hex"], ED301_CT_CONTEXT_HEX=case["context_hex"])
    for operation in ("public", "sign"):
        for mode in ("defined", "tainted"):
            runs.append((f"ed301 {case['id']} {operation} {mode}",
                         [ed, f"--case={operation}", f"--mode={mode}"], env))

x = work / "target/release/x301-core-taint"
data = json.loads((ROOT / "vectors/x301-v2.json").read_text())
base = json.loads((ROOT / "math/ed301-v2.json").read_text())["basepoint"]["G_montgomery_u_little_endian_hex"]
keys = {key["id"]: key for key in data["keys"]}
cases = []
for key in data["keys"]:
    cases += [(key["id"] + "-public", "public", key["secret_hex"], base, key["public_hex"], ""),
              (key["id"] + "-import", "import", key["secret_hex"], "", key["secret_hex"], "")]
for case in data["evaluations"]:
    cases.append((case["id"], "shared", keys[case["key"]]["secret_hex"], case["u_hex"], case["result_hex"], ""))
for case in data["errors"]:
    error = {"decode-secret": "secret-length", "result": "all-zero"}.get(case["stage"])
    if error is None:
        error = "public-length" if len(case["u_hex"]) != 76 else "noncanonical-public"
    cases.append((case["id"], "shared", case["secret_hex"], case["u_hex"], "", error))
for case in data["weak_secrets"]:
    for operation, peer in (("public", base), ("import", ""), ("shared", base)):
        cases.append((case["id"] + "-" + operation, operation, case["secret_hex"], peer, "", "weak-secret"))
for label, operation, secret, peer, expected, error in cases:
    env = dict(clean, X301_CT_SECRET=secret, X301_CT_PEER=peer, X301_CT_EXPECTED=expected, X301_CT_ERROR=error)
    for mode in ("defined", "tainted"):
        runs.append((f"x301 {label} {mode}", [x, operation, mode], env))


def execute(run):
    name, command, env = run
    result = subprocess.run(valgrind + [str(part) for part in command], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return name, result.returncode, result.stdout


failures = 0
with ThreadPoolExecutor(args.jobs) as pool:
    for name, code, output in pool.map(execute, runs):
        if code:
            failures += 1
            print(f"FAIL {name} (exit {code})\n{output[-4000:]}", flush=True)
print(f"{len(runs) - failures} of {len(runs)} Valgrind runs passed")
sys.exit(1 if failures else 0)
