#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Single-member integrity control in an isolated copy, never a product mutation."""

import argparse
from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from handoff_common import check_source, digest, manifest_rows, read_json

parser = argparse.ArgumentParser(description=__doc__)
for name in ("evidence", "baseline", "output"):
    parser.add_argument("--" + name, type=Path, required=True)
parser.add_argument("--source-sha", required=True)
parser.add_argument("--baseline-sha", required=True)
args = parser.parse_args()
root = args.evidence.resolve(strict=True)
baseline = args.baseline.resolve(strict=True)
check_source(root / "source", root / "SOURCE_SHA256SUMS", args.source_sha)
check_source(baseline / "source", baseline / "SOURCE_SHA256SUMS", args.baseline_sha)
sys.path.insert(0, str(root / "source/phase-d/d2/tools"))
from d2_common import Receipt, verify_source

receipt = Receipt(args.output, args.source_sha, "current-provenance-integrity-control")
out = receipt.output
controller = Path(__file__).resolve()
shutil.copy2(controller, out / "CONTROLLER.py")
fixture = out / "fixture/source"
shutil.copytree(root / "source", fixture)
name = "provenance/v2-search/search_worker_v3.gp"
original = root / "source" / name
member = fixture / name
member.chmod(0o644)
member.write_bytes(original.read_bytes() + b"\n\\\\ synthetic integrity-control comment\n")
member.chmod(0o444)
rows = manifest_rows(root / "SOURCE_SHA256SUMS")
changed = [path for path, expected in rows.items() if digest(fixture / path) != expected]
if changed != [name]:
    raise SystemExit("fixture differs beyond its sole synthetic member")
runner = fixture / "phase-e/tools/check_core_correctness.py"
output = receipt.run("current-search-member-must-fail",
    ["/usr/bin/python3", "-I", "-B", runner, "--baseline", baseline / "source"], expected=1)
if ("FAIL: current-signed-search-package" not in output
        or "search_worker_v3.gp: FAILED" not in output):
    raise SystemExit("provenance control failed outside the intended boundary")
results = list((out / "fixture").glob("ED301-v2_PHASE_E_core-check_*"))
if len(results) != 1:
    raise SystemExit("unexpected rejected-run inventory")
commands = read_json(results[0] / "commands.json")
if ([item["step"] for item in commands] != ["baseline-PHASE_C_SOURCE_MANIFEST",
        "baseline-D1_SOURCE_MANIFEST", "current-gate-a-package", "current-signed-search-package"]
        or [item["exit"] for item in commands] != [0, 0, 0, 1]):
    raise SystemExit("rejection did not occur before builds at the fourth admission step")
if [path for path, expected in rows.items() if digest(fixture / path) != expected] != [name]:
    raise SystemExit("fixture changed during its rejected run")
check_source(baseline / "source", baseline / "SOURCE_SHA256SUMS", args.baseline_sha)
if digest(controller) != digest(out / "CONTROLLER.py"):
    raise SystemExit("control changed during execution")
receipt.identity.update(baseline_source_sha256=args.baseline_sha,
    controller_sha256=digest(controller), changed_member=name,
    original_member_sha256=digest(original), synthetic_member_sha256=digest(member),
    runner_sha256=digest(runner), expected_rejection_step=4,
    scope="unchanged final runner rejects one altered signed-search member before builds; full fixture and logs retained")
# This receipt contains a complete source fixture, including the nested
# rust/vendor/SHA256SUMS. Exclude only our outer seal, not every such basename.
verify_source(args.source_sha)
receipt.identity["status"] = "PASS"
receipt.write_identity()
seal = out / "SHA256SUMS"
seal.write_text("".join(f"{digest(path)}  {path.relative_to(out).as_posix()}\n"
    for path in sorted(out.rglob("*")) if path.is_file() and not path.is_symlink() and path != seal))
receipt.sealed = True
print("PASS: current-provenance-integrity-control artifact_directory=" + str(out), flush=True)
