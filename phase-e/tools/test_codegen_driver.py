#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify that a dataflow-checker failure propagates through the shell driver."""

import argparse
from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "phase-d/d2/tools"))
from d2_common import ROOT, Receipt, digest

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--source-sha", required=True)
parser.add_argument("--elf", type=Path, required=True)
parser.add_argument("--elf-sha", required=True)
parser.add_argument("--toolchain", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
elf = args.elf.resolve(strict=True)
if digest(elf) != args.elf_sha:
    raise SystemExit("driver-control ELF hash mismatch")
receipt = Receipt(args.output, args.source_sha, "codegen-driver-failure-control")
fixture = receipt.output / "synthetic-driver-fixture"
fixture.mkdir()
for name in ("check_codegen.sh", "codegen_ed.sh", "codegen_x.sh", "codegen_transfers.awk"):
    shutil.copy2(ROOT / "phase-e/tools" / name, fixture / name)
# Only this isolated test fixture contains the rejecting stub. The original
# checker, source snapshot and inspected ELF are never modified.
(fixture / "check_codegen_dataflow.py").write_text(
    'import sys\nprint("SYNTHETIC_DATAFLOW_REJECTION", file=sys.stderr)\nraise SystemExit(47)\n')
output = receipt.run("dataflow-failure-must-propagate",
    ["/bin/sh", fixture / "check_codegen.sh", "ed-provider", elf,
     args.toolchain.resolve(strict=True), receipt.output / "codegen"], expected=47)
if "SYNTHETIC_DATAFLOW_REJECTION" not in output or "PASS phase_e_codegen" in output:
    raise SystemExit("driver swallowed the synthetic dataflow failure")
if digest(elf) != args.elf_sha:
    raise SystemExit("driver-control ELF changed")
receipt.identity.update(elf_sha256=args.elf_sha, synthetic_expected_exit=47,
                        scope="failure propagation only; this is not a codegen PASS for the ELF")
receipt.seal()
