#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""E8a public-import admission controls on the freshly taint-checked core ELF."""

import argparse
import json
from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "phase-d/d2/tools"))
from d2_common import ROOT, Receipt, digest

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--source-sha", required=True)
parser.add_argument("--core-taint", type=Path, required=True)
parser.add_argument("--core-taint-sha", required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
source = args.core_taint.resolve(strict=True)
if digest(source / "SHA256SUMS") != args.core_taint_sha:
    raise SystemExit("core-taint receipt digest mismatch")
for line in (source / "SHA256SUMS").read_text().splitlines():
    checksum, name = line.split("  ", 1)
    relative = Path(name)
    if relative.is_absolute() or ".." in relative.parts or digest(source / relative) != checksum:
        raise SystemExit("invalid core-taint receipt member")
summary = json.loads((source / "SUMMARY.json").read_text())
rust_manifest = "".join(f"{digest(path)}  {path.relative_to(ROOT)}\n"
                        for path in sorted((ROOT / "rust").rglob("*")) if path.is_file())
if summary.get("status") != "PASS" or (source / "SOURCE_SHA256SUMS").read_text() != rust_manifest:
    raise SystemExit("core-taint source does not match this frozen candidate")
binary = source / "target/release/ed301-eddsa-secret-taint"
if digest(binary) != summary["binary_sha256"]:
    raise SystemExit("core-taint executable digest mismatch")
receipt = Receipt(args.output, args.source_sha, "public-import-boundary-taint")
copied = receipt.output / "ed301-eddsa-secret-taint"
shutil.copy2(binary, copied)
copied.chmod(0o555)
receipt.identity.update(core_taint_receipt_sha256=args.core_taint_sha,
                        binary_sha256=summary["binary_sha256"],
                        scope="public parser admits defined bytes and rejects secret shadow bits before arithmetic; signing/key derivation call counters checked by the bound core-taint run")
receipt.write_identity()
vectors = ROOT / "vectors/ed301-eddsa-v2.json"
if digest(vectors) != "4dbbd93f5814f4e676b8007b13973037a7924872d46d328cdaeb314cd3190e82":
    raise SystemExit("approved public-vector digest mismatch")
case = json.loads(vectors.read_text())["signing"][0]
env = dict(receipt.clean, ED301_CT_EXPECTED_PUBLIC_HEX=case["trace"]["public_key"], RUST_BACKTRACE="0")
command = ["/usr/bin/valgrind", "--tool=memcheck", "--vgdb=no", "--error-exitcode=99",
           "--track-origins=yes", "--undef-value-errors=yes", "--leak-check=full",
           "--errors-for-leak-kinds=definite,indirect,possible", "--quiet", copied, "--case=import"]
for label in ("defined-before", "secret-shadow-rejected", "defined-after"):
    negative = label == "secret-shadow-rejected"
    output = receipt.run(label, command + ["--mode=" + ("tainted" if negative else "defined")],
                         env, expected=101 if negative else 0)
    expected = ("public-key import received secret-tainted input" if negative
                else "secret_taint_case=import mode=defined instrumentation=1 pass=1")
    if expected not in output:
        raise SystemExit("boundary control failed for an unexplained reason")
if digest(binary) != summary["binary_sha256"] or digest(copied) != summary["binary_sha256"]:
    raise SystemExit("executed core-taint ELF changed")
receipt.seal()
