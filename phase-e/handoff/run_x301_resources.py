#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fresh D1-method resource measurements on the final measured X301 binaries."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import statistics
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from handoff_common import (check_members, check_source, check_source_comparison,
                            digest, read_json)
from handoff_inputs import SOURCE_SHA

parser = argparse.ArgumentParser(description=__doc__)
for name in ("evidence", "benchmarks", "ed-resources", "output"):
    parser.add_argument("--" + name, type=Path, required=True)
for name in ("benchmark-sha", "ed-resources-sha"):
    parser.add_argument("--" + name, required=True)
parser.add_argument("--cpu", type=int, default=2)
args = parser.parse_args()
root = args.evidence.resolve(strict=True)
benchmark = args.benchmarks.resolve(strict=True)
ed_resources = args.ed_resources.resolve(strict=True)
sys.path.insert(0, str(root / "source/phase-d/d2/tools"))
from d2_common import verify_receipt


def verify_inputs():
    check_source(root / "source", root / "SOURCE_SHA256SUMS", SOURCE_SHA)
    benchmark_rows = check_members(benchmark, "SHA256SUMS", args.benchmark_sha)
    identity = verify_receipt(benchmark)
    if identity["source_manifest_sha256"] != SOURCE_SHA or identity["status"] != "PASS":
        raise SystemExit("resource benchmark source/status mismatch")
    resource_rows = check_members(ed_resources, "SHA256SUMS", args.ed_resources_sha)
    check_source_comparison(ed_resources, "SOURCE_SHA256SUMS", root / "source", all_rust=True)
    resource_identity = read_json(ed_resources / "IDENTITY.json")
    if (resource_identity["stack_repetitions"] != 3 or resource_identity["rss_repetitions"] != 9
            or any(item["status"] != "PASS" for item in resource_identity["controls"])):
        raise SystemExit("resource-control input incomplete")
    if (resource_rows["binaries/ed301-resources-v2"] != resource_identity["v2"]["binary_sha256"]
            or resource_identity["harness_sha256"] != digest(root / "source/phase-c/benchmarks/core_resources.rs")):
        raise SystemExit("resource-control binary/source mismatch")
    return benchmark_rows, resource_identity


benchmark_rows, resource_identity = verify_inputs()
work = args.output.absolute()
checkout = Path(__file__).resolve().parents[2]
if (args.cpu not in os.sched_getaffinity(0) or work.exists() or work.is_symlink()
        or checkout in work.parents or (root / "source") in work.parents):
    parser.error("require available CPU and new output outside source/checkout")
work.mkdir(mode=0o700)
for part in ("home", "logs", "massif", "controllers"):
    (work / part).mkdir(mode=0o700)
controllers = [Path(__file__).resolve(), Path(__file__).with_name("handoff_common.py"),
               Path(__file__).with_name("handoff_inputs.py")]
controller_hashes = {str(path): digest(path) for path in controllers}
for path in controllers:
    shutil.copy2(path, work / "controllers" / path.name)
clean = {"PATH": "/usr/bin:/bin", "HOME": str(work / "home"), "LC_ALL": "C"}
commands = []
print("artifact_directory=" + str(work), flush=True)


def run(command, label):
    command = list(map(str, command))
    result = subprocess.run(command, cwd="/", env=clean, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
    log = work / "logs" / f"{len(commands):04d}-{label}.log"
    log.write_text(result.stdout)
    commands.append({"command": command, "step": label, "environment": clean,
                     "exit": result.returncode, "log": str(log.relative_to(work)),
                     "log_sha256": digest(log)})
    (work / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
    if result.returncode:
        raise SystemExit("resource step failed; evidence retained: " + label)
    return result.stdout


binaries = {version: benchmark / "bin" / ("x-" + version) for version in ("v1", "v2")}
control = ed_resources / "binaries/ed301-resources-v2"
identity = {
    "scope": "whole benchmark-process high-water including DH self-test/setup and std runtime; not per-operation stack bounds",
    "source_manifest_sha256": SOURCE_SHA,
    "benchmark_receipt_sha256": args.benchmark_sha,
    "benchmark_path": str(benchmark),
    "ed_resources_receipt_sha256": args.ed_resources_sha,
    "ed_resources_path": str(ed_resources),
    "binaries": {str(path): digest(path) for path in [*binaries.values(), control]},
    "controllers": controller_hashes,
    "method_source": "phase-d/tools/run_x301_resources.py",
    "method_source_sha256": digest(root / "source/phase-d/tools/run_x301_resources.py"),
    "positive_control_source": "phase-c/benchmarks/core_resources.rs",
    "positive_control_source_sha256": resource_identity["harness_sha256"],
    "positive_control_note": "freshly built bound neutral 256-KiB stack / 8-MiB touched-page controls, measured anew",
    "valgrind": run(["valgrind", "--version"], "valgrind-version"),
    "time": run(["/usr/bin/time", "--version"], "time-version"),
    "cpu_affinity": args.cpu, "stack_repetitions": 3, "rss_repetitions": 9,
    "stack_operation_count": 10, "rss_operation_count": 100,
    "status": "RUNNING", "system_installation": False,
}
(work / "IDENTITY.json").write_text(json.dumps(identity, indent=2) + "\n")
cases = [(v, op, [binaries[v], op]) for op in ("public", "shared", "validate-public", "canonical-public") for v in ("v1", "v2")]
cases += [("v2", op, [binaries["v2"], op]) for op in ("import-secret", "import-public", "prepared-shared", "prepared-public")]
cases += [("control", op, [control, op, 64, 0]) for op in ("empty", "stack-control", "rss-control")]
rows = []
raw = work / "raw.tsv"
raw.write_text("lane\trepeat\tversion\toperation\tcount\tpeak\n")
objects = set()
for lane, repetitions, count in (("stack_B", 3, 10), ("rss_KiB", 9, 100)):
    for repeat in range(repetitions):
        print(f"STEP: {lane} rotation {repeat + 1}/{repetitions}", flush=True)
        order = list(range(len(cases)))
        if repeat % 2:
            order.reverse()
        shift = (2 * repeat) % len(order)
        order = order[shift:] + order[:shift]
        for index in order:
            version, operation, command = cases[index]
            label = f"{lane}-{repeat + 1}-{version}-{operation}"
            if lane == "stack_B":
                out = work / "massif" / (label + ".out")
                output = run(["taskset", "-c", args.cpu, "valgrind", "--tool=massif", "--vgdb=no", "--enable-debuginfod=no",
                              "--heap=no", "--stacks=yes", "--time-unit=B", "--peak-inaccuracy=0.0", "--max-snapshots=1000",
                              "--massif-out-file=" + str(out), *command, count], label)
                values = re.findall(r"^mem_stacks_B=(\d+)$", out.read_text(), re.M)
                peak = max(map(int, values)) if values else 0
            else:
                output = run(["taskset", "-c", args.cpu, "/usr/bin/time", "-f", "RESOURCE_RSS_KIB=%M", *command, count], label)
                values = re.findall(r"^RESOURCE_RSS_KIB=(\d+)$", output, re.M)
                peak = int(values[0]) if len(values) == 1 else 0
            marker = "RESOURCE_DONE operation=" if version == "control" else "RESULT operation="
            if marker + operation not in output or peak <= 0:
                raise SystemExit("invalid resource measurement")
            objects.update(re.findall(r"^OBJECT_BYTES .*$", output, re.M))
            row = [lane, repeat + 1, version, operation, count, peak]
            rows.append(row)
            with raw.open("a") as stream:
                stream.write("\t".join(map(str, row)) + "\n")
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
if stack_delta < 240 * 1024 or rss_delta < 4 * 1024:
    raise SystemExit("resource control not observed")
identity["controls"] = {"stack_delta_B": stack_delta, "rss_delta_KiB": rss_delta, "status": "PASS"}
identity["v2_objects"] = sorted(objects)
verify_inputs()
for path, expected in {**identity["binaries"], **controller_hashes}.items():
    if digest(Path(path)) != expected:
        raise SystemExit("resource input or controller changed")
identity["status"] = "PASS"
(work / "IDENTITY.json").write_text(json.dumps(identity, indent=2) + "\n")
(work / "SUMMARY.json").write_text(json.dumps(summary, indent=2) + "\n")
files = sorted(path for path in work.rglob("*") if path.is_file() and path.name != "SHA256SUMS")
(work / "SHA256SUMS").write_text("".join(f"{digest(path)}  {path.relative_to(work)}\n" for path in files))
print("PASS: 12 X301 resource scenarios and 3 fresh neutral controls; artifact_directory=" + str(work), flush=True)
