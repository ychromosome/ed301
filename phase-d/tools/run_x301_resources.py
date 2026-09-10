#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Measure the already benchmarked X301 ELFs; no rebuild or speed inference."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--benchmarks", type=Path, default=ROOT.parent / "X301-v2_D1-benchmark_crh1w6sz")
parser.add_argument("--cpu", type=int, default=2)
args = parser.parse_args()
if args.cpu not in os.sched_getaffinity(0): parser.error("CPU not available")
WORK = Path(tempfile.mkdtemp(prefix="X301-v2_D1-resources_", dir=ROOT.parent))
for part in ("home", "logs", "massif"): (WORK / part).mkdir()
clean = {"PATH": "/usr/bin:/bin", "HOME": str(WORK / "home"), "LC_ALL": "C"}
commands = []
print(f"artifact_directory={WORK}", flush=True)


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, label, announce=False):
    command = list(map(str, command))
    if announce: print(f"STEP: {label}", flush=True)
    result = subprocess.run(command, cwd="/", env=clean, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log = WORK / "logs" / f"{len(commands):04d}-{label}.log"
    log.write_text(result.stdout)
    commands.append({"command": command, "step": label, "environment": clean,
                     "exit": result.returncode, "log": str(log.relative_to(WORK))})
    (WORK / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
    if result.returncode:
        print(result.stdout, end="", flush=True)
        raise SystemExit(f"FAIL: {label}; artifacts retained at {WORK}")
    return result.stdout


original = json.loads((args.benchmarks / "IDENTITY.json").read_text())
binaries = {v: args.benchmarks / "binaries" / ("x301-core-benchmark-" + v) for v in ("v1", "v2")}
for version, binary in binaries.items():
    if sha(binary) != original[version]["binary_sha256"]: raise SystemExit("FAIL: benchmark ELF changed")
control = ROOT.parent / "ED301-v2_resources_8s_1_ann/binaries/ed301-resources-v2"
control_hash = "2d6a262a341ff0884f332d9c16aa4c1faefce4ef8740a397202673fa7bbb08ee"
if sha(control) != control_hash: raise SystemExit("FAIL: neutral resource-control ELF changed")
identity = {"scope": "whole benchmark-process high-water including DH self-test/setup and std runtime; not per-operation stack bounds",
            "benchmark_identity_sha256": sha(args.benchmarks / "IDENTITY.json"),
            "binaries": {str(p): sha(p) for p in [*binaries.values(), control]},
            "positive_control_source": str(ROOT / "phase-c/benchmarks/core_resources.rs"),
            "positive_control_note": "reused bound neutral 256-KiB stack / 8-MiB touched-page controls; measured anew, no old measurements transferred",
            "valgrind": run(["valgrind", "--version"], "valgrind-version"),
            "time": run(["/usr/bin/time", "--version"], "time-version"),
            "cpu_affinity": args.cpu, "stack_repetitions": 3, "rss_repetitions": 9}
cases = [(v, op, [binaries[v], op]) for op in ("public", "shared", "validate-public", "canonical-public") for v in ("v1", "v2")]
cases += [("v2", op, [binaries["v2"], op]) for op in ("import-secret", "import-public", "prepared-shared", "prepared-public")]
cases += [("control", op, [control, op, 64, 0]) for op in ("empty", "stack-control", "rss-control")]
rows = []
raw = WORK / "raw.tsv"
raw.write_text("lane\trepeat\tversion\toperation\tcount\tpeak\n")
objects = set()
for lane, repetitions, count in (("stack_B", 3, 10), ("rss_KiB", 9, 100)):
    for repeat in range(repetitions):
        print(f"STEP: {lane} rotation {repeat + 1}/{repetitions}", flush=True)
        order = list(range(len(cases)))
        if repeat % 2: order.reverse()
        shift = (2 * repeat) % len(order)
        order = order[shift:] + order[:shift]
        for index in order:
            version, operation, command = cases[index]
            label = f"{lane}-{repeat + 1}-{version}-{operation}"
            if lane == "stack_B":
                out = WORK / "massif" / (label + ".out")
                text = run(["taskset", "-c", args.cpu, "valgrind", "--tool=massif", "--vgdb=no", "--enable-debuginfod=no",
                            "--heap=no", "--stacks=yes", "--time-unit=B", "--peak-inaccuracy=0.0", "--max-snapshots=1000",
                            "--massif-out-file=" + str(out), *command, count], label)
                values = re.findall(r"^mem_stacks_B=(\d+)$", out.read_text(), re.M)
                peak = max(map(int, values)) if values else 0
            else:
                text = run(["taskset", "-c", args.cpu, "/usr/bin/time", "-f", "RESOURCE_RSS_KIB=%M", *command, count], label)
                values = re.findall(r"^RESOURCE_RSS_KIB=(\d+)$", text, re.M)
                peak = int(values[0]) if len(values) == 1 else 0
            marker = "RESOURCE_DONE operation=" if version == "control" else "RESULT operation="
            if marker + operation not in text or peak <= 0: raise SystemExit("FAIL: invalid resource measurement")
            objects.update(re.findall(r"^OBJECT_BYTES .*$", text, re.M))
            row = [lane, repeat + 1, version, operation, count, peak]
            rows.append(row)
            with raw.open("a") as out: out.write("\t".join(map(str, row)) + "\n")
summary = []
for version, operation, _ in cases:
    row = {"version": version, "operation": operation}
    for lane in ("stack_B", "rss_KiB"):
        values = [r[5] for r in rows if r[0] == lane and r[2:4] == [version, operation]]
        row[lane] = {"median": statistics.median(values), "stdev": statistics.stdev(values),
                     "min": min(values), "max": max(values), "repetitions": len(values)}
    summary.append(row)
def control_value(operation, lane):
    return next(r[lane]["median"] for r in summary if r["version"] == "control" and r["operation"] == operation)
stack_delta = control_value("stack-control", "stack_B") - control_value("empty", "stack_B")
rss_delta = control_value("rss-control", "rss_KiB") - control_value("empty", "rss_KiB")
if stack_delta < 240 * 1024 or rss_delta < 4 * 1024: raise SystemExit("FAIL: resource control not observed")
identity["controls"] = {"stack_delta_B": stack_delta, "rss_delta_KiB": rss_delta, "status": "PASS"}
identity["v2_objects"] = sorted(objects)
for path, expected in identity["binaries"].items():
    if sha(Path(path)) != expected: raise SystemExit("FAIL: measured binary changed")
(WORK / "IDENTITY.json").write_text(json.dumps(identity, indent=2) + "\n")
(WORK / "SUMMARY.json").write_text(json.dumps(summary, indent=2) + "\n")
files = sorted(p for p in WORK.rglob("*") if p.is_file() and p.name != "SHA256SUMS")
(WORK / "SHA256SUMS").write_text("".join(f"{sha(p)}  {p.relative_to(WORK)}\n" for p in files))
print(f"PASS: 12 X301 resource scenarios and 3 neutral controls; artifact_directory={WORK}", flush=True)
