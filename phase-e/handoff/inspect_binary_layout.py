#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Record sizes and fixed-base tables of the actual final measured core ELFs."""

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from handoff_common import check_members, check_source, digest, read_json
from handoff_inputs import SOURCE_SHA, VERSIONS

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--index", required=True, type=Path)
parser.add_argument("--output", required=True, type=Path)
args = parser.parse_args()
index = read_json(args.index)
root = Path(index["evidence_root"])
check_source(root / "source", root / "SOURCE_SHA256SUMS", SOURCE_SHA)
records = [index["stages"]["benchmarks-" + v] for v in VERSIONS]
records += [index["supplementary"][name] for name in ("core-matrix", "core-microbenchmarks", "ed-core-resources")]
for record in records:
    check_members(Path(record["path"]), "SHA256SUMS", record["manifest_sha256"])
out = args.output.absolute()
if out.exists() or out.is_symlink() or Path(__file__).resolve().parents[2] in out.parents:
    parser.error("output must be new and outside checkout")
out.mkdir(mode=0o700)
(out / "logs").mkdir(mode=0o700)
shutil.copy2(Path(__file__), out / "CONTROLLER.py")
commands, summary = [], []
binaries = []
for version in VERSIONS:
    for label in ("ed-v1", "ed-v2", "x-v1", "x-v2"):
        binaries.append((version + "/" + label, root / ("benchmarks-" + version) / "bin" / label))
for name in ("core-matrix", "core-microbenchmarks"):
    for filename, binary in index["supplementary"][name]["extra_binaries"].items():
        binaries.append((name + "/" + Path(filename).name, Path(binary["path"])))
for version in ("v1", "v2"):
    binaries.append(("ed-core-resources/" + version,
        Path(index["supplementary"]["ed-core-resources"]["path"]) / "binaries" / ("ed301-resources-" + version)))
if len(binaries) != 14:
    raise SystemExit("unexpected final binary inventory")
for number, (label, binary) in enumerate(binaries):
    checksum = digest(binary)
    outputs = {}
    for tool, argv in (("size", ["/usr/bin/size", binary]), ("nm", ["/usr/bin/nm", "-S", "-C", "--defined-only", binary]),
                       ("sections", ["/usr/bin/readelf", "-SW", binary])):
        argv = list(map(str, argv))
        result = subprocess.run(argv, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, cwd="/", text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
        log = out / "logs" / f"{number:02d}-{tool}.log"
        log.write_text(result.stdout)
        if result.returncode:
            raise SystemExit("layout command failed")
        commands.append({"step": f"{number:02d}-{tool}", "command": argv, "exit": result.returncode,
                         "log": str(log.relative_to(out)), "log_sha256": digest(log)})
        outputs[tool] = result.stdout
    size = re.search(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+\d+\s+[0-9a-f]+\s+", outputs["size"], re.M)
    if size is None or digest(binary) != checksum:
        raise SystemExit("invalid layout or changed binary")
    tables = [{"symbol": m[3], "bytes": int(m[2], 16)} for m in re.finditer(
        r"^([0-9a-f]+) ([0-9a-f]+) [A-Za-z] (.*::BASEPOINT(?:_ODD)?_TABLE)$", outputs["nm"], re.M)]
    summary.append({"label": label, "binary": str(binary), "binary_sha256": checksum,
                    "gnu_size": dict(zip(("text_including_ro", "data", "bss"), map(int, size.groups()))),
                    "fixed_base_tables": tables})
for record in records:
    check_members(Path(record["path"]), "SHA256SUMS", record["manifest_sha256"])
check_source(root / "source", root / "SOURCE_SHA256SUMS", SOURCE_SHA)
identity = {"status": "PASS", "source_manifest_sha256": SOURCE_SHA,
            "scope": "linked ELF size/section/table inventory, not runtime memory or a new codegen gate",
            "input_receipts": {record["path"]: record["manifest_sha256"] for record in records},
            "controller_sha256": digest(out / "CONTROLLER.py"), "binary_count": len(summary)}
for filename, value in (("IDENTITY.json", identity), ("SUMMARY.json", summary), ("commands.json", commands)):
    (out / filename).write_text(json.dumps(value, indent=2) + "\n")
(out / "SHA256SUMS").write_text("".join(f"{digest(path)}  {path.relative_to(out)}\n"
    for path in sorted(out.rglob("*")) if path.is_file() and path.name != "SHA256SUMS"))
print("PASS: 14 final measured ELF layouts; artifact_directory=" + str(out))
