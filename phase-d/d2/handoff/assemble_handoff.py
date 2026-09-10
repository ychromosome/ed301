#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Derive an index and optional local review bundle from completed D2 receipts."""

import argparse
import json
import os
from pathlib import Path
import shutil
import sys

CHECKOUT = Path(__file__).resolve().parents[3]
SOURCE_SHA = "0416be4902f9955e9dfac5b893e21472b3cfe0046e4894f65c5d3f508f84ed30"
VERSIONS = ("3.5.8", "4.0.2")
STAGES = ("functional", "cli", "tcp", "memory", "controls", "codegen",
          "legacy_builds", "structured", "timing", "benchmarks")
CONTROL_FIXTURES = {"wrong-digest", "tar-bytes", "prefix-extra", "prefix-missing",
                    "prefix-link", "native-evp-bytes", "empty-seal",
                    "duplicate-seal-member", "mixed-origin", "member-bytes"}

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--evidence", required=True, type=Path)
parser.add_argument("--index", required=True, type=Path)
parser.add_argument("--bundle", type=Path)
args = parser.parse_args()
root = args.evidence.resolve(strict=True)
sys.path.insert(0, str(root / "source/phase-d/d2/tools"))
from d2_common import digest, verify_receipt, verify_source

verify_source(SOURCE_SHA)
index = {"format": "ed301-v2-d2-final-index-v1", "evidence_root": str(root),
         "source_manifest_sha256": SOURCE_SHA, "source_files": 1848,
         "base_commit": "67f2910e7697cdab782cc992e44dc28843f93970",
         "architecture": "native x86_64 only", "gate_d_approval": False,
         "stages": {}, "timing": {}, "benchmarks": {}}
for version in VERSIONS:
    for stage in STAGES:
        name = stage + "-" + version
        directory = root / name
        identity = verify_receipt(directory)
        if identity["source_manifest_sha256"] != SOURCE_SHA:
            raise SystemExit("mixed source receipts")
        commands = json.loads((directory / "commands.json").read_text())
        for command in commands:
            if digest(directory / "logs" / (command["step"] + ".log")) != command["log_sha256"]:
                raise SystemExit("command log seal mismatch")
        index["stages"][name] = {
            "path": str(directory), "manifest_sha256": digest(directory / "SHA256SUMS"),
            "command_count": len(commands), "identity": identity}
    index["timing"][version] = {
        algorithm: (root / ("timing-" + version) / (algorithm + "_SUMMARY.txt")).read_text()
        for algorithm in ("ed301", "x301")}
    rows = json.loads((root / ("benchmarks-" + version) / "SUMMARY.json").read_text())
    if len(rows) != 128 or any(row["repetitions"] != 9 for row in rows):
        raise SystemExit("incomplete benchmark matrix")
    index["benchmarks"][version] = rows

# Only post-execution reports and handoff tools may be absent from the input seal.
declared = {}
for line in (root / "SOURCE_SHA256SUMS").read_text().splitlines():
    checksum, name = line.split("  ", 1)
    declared[name] = checksum
    if digest(CHECKOUT / name) != checksum:
        raise SystemExit("checkout differs from executed input: " + name)
derived = {}
for directory in ("docs", "provider", "provider-tests", "phase-d/d2"):
    for path in (CHECKOUT / directory).rglob("*"):
        if path.is_symlink():
            raise SystemExit("unexpected checkout symlink")
        if not path.is_file():
            continue
        name = path.relative_to(CHECKOUT).as_posix()
        if name in declared or path == args.index.absolute():
            continue
        if not (name.startswith("phase-d/d2/") and
                (path.suffix == ".md" or name.startswith("phase-d/d2/handoff/"))):
            raise SystemExit("unexecuted runtime/test input: " + name)
        derived[name] = digest(path)
index["post_execution_files"] = derived
args.index.write_text(json.dumps(index, indent=2) + "\n")
print("index=" + str(args.index.absolute()), flush=True)
print("index_sha256=" + digest(args.index), flush=True)
if args.bundle is None:
    raise SystemExit(0)

bundle = args.bundle.absolute()
if bundle.exists() or bundle.is_symlink() or root in bundle.parents or CHECKOUT in bundle.parents:
    raise SystemExit("bundle must be new and outside evidence/checkout")
bundle.mkdir(mode=0o700)
omitted = {}
selected = [root / "source", root / "SOURCE_SHA256SUMS", root / "SOURCE_IDENTITY.json"]
selected += [root / name for name in index["stages"]]
for top in selected:
    paths = [top] + sorted(top.rglob("*")) if top.is_dir() else [top]
    for path in paths:
        relative = path.relative_to(root)
        if "targets" in relative.parts:
            continue
        if (relative.parts[0].startswith("controls-") and len(relative.parts) > 1
                and relative.parts[1] in CONTROL_FIXTURES):
            if path.is_symlink():
                omitted[str(relative)] = {"type": "symlink", "target": os.readlink(path)}
            elif path.is_file():
                omitted[str(relative)] = {"type": "file", "sha256": digest(path)}
            continue
        target = bundle / "evidence" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            link = os.readlink(path)
            if Path(link).is_absolute() or ".." in Path(link).parts:
                raise SystemExit("unsafe runtime symlink")
            target.symlink_to(link)
        elif path.is_dir():
            target.mkdir(exist_ok=True)
        elif path.is_file():
            shutil.copy2(path, target)
        else:
            raise SystemExit("special evidence file")

(bundle / "reports").mkdir()
for name in sorted(derived):
    path = CHECKOUT / name
    target = bundle / "reports" / path.relative_to(CHECKOUT / "phase-d/d2")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, target)
shutil.copy2(args.index, bundle / "reports/D2_EVIDENCE_INDEX.json")
(bundle / "OMITTED_CONTROL_FIXTURES.json").write_text(json.dumps(omitted, indent=2) + "\n")
(bundle / "donors").mkdir()
for kind, checksum in (
    ("ED", "1e8d540bf75e09011c0ffb728cb0e6fd264ce46f1d9161f8bd6b4510dfb02ffb"),
    ("X", "179cdb066b5b8f74dd6f87b78f5d9576710fef9500e388b53747d427d73d9755"),
):
    path = CHECKOUT.parent / ("ED301-v2_D2_" + kind + "_DONOR_2026-09-10.tar.gz")
    if digest(path) != checksum:
        raise SystemExit("donor archive mismatch")
    shutil.copy2(path, bundle / "donors" / path.name)

manifest = {}
for path in sorted(bundle.rglob("*")):
    name = path.relative_to(bundle).as_posix()
    if path.is_symlink():
        manifest[name] = {"type": "symlink", "target": os.readlink(path)}
    elif path.is_dir():
        # Source read-only permissions are part of the source contract.
        path.chmod(0o555 if name == "evidence/source" or name.startswith("evidence/source/") else 0o700)
        manifest[name] = {"type": "directory", "mode": path.stat().st_mode & 0o777}
    else:
        manifest[name] = {"type": "file", "mode": path.stat().st_mode & 0o777,
                          "sha256": digest(path)}
(bundle / "BUNDLE_MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
print("bundle=" + str(bundle), flush=True)
print("bundle_manifest_sha256=" + digest(bundle / "BUNDLE_MANIFEST.json"), flush=True)
