#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bound whole-process Stack/Massif and native RSS/GNU-time lifecycle measurements."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import statistics
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--v1", type=Path, default=ROOT.parent / "ed301-eddsa-github")
parser.add_argument("--cpu", type=int, default=2)
parser.add_argument("--stack-repetitions", type=int, default=3)
parser.add_argument("--rss-repetitions", type=int, default=9)
args = parser.parse_args()
if args.cpu not in os.sched_getaffinity(0) or min(args.stack_repetitions, args.rss_repetitions) < 3:
    parser.error("need available CPU and >=3 repetitions in each measurement lane")
work = Path(tempfile.mkdtemp(prefix="ED301-v2_resources_", dir=ROOT.parent))
for part in ("home", "logs", "massif", "binaries"):
    (work / part).mkdir()
clean = {"PATH": "/usr/bin:/bin", "HOME": str(work / "home"), "LC_ALL": "C"}
commands = []
print(f"artifact_directory={work}", flush=True)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, name, env=None, announce=True):
    command = list(map(str, command))
    if announce:
        print(f"STEP: {name}", flush=True)
    result = subprocess.run(command, cwd="/", env=env or clean, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log = work / "logs" / f"{len(commands):04d}-{name}.log"
    log.write_text(result.stdout)
    commands.append({"command": command, "name": name, "environment": env or clean,
                     "log": str(log.relative_to(work)), "exit": result.returncode})
    (work / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
    if result.returncode:
        print(result.stdout, end="", flush=True)
        raise SystemExit(f"FAIL: {name}; evidence retained at {work}")
    return result.stdout


def baseline(label):
    commit = run(["git", "-C", args.v1, "rev-parse", "HEAD"], label + "-commit").strip()
    dirty = run(["git", "-C", args.v1, "status", "--porcelain", "--untracked-files=all"],
                label + "-status").strip()
    if commit != "5c688206a15f6ab88a50d53fe503665a302cec4d" or dirty:
        raise SystemExit("FAIL: v1 is not the bound clean baseline")
    return commit


def source_manifest():
    files = sorted(p for p in (ROOT / "rust").rglob("*") if p.is_file())
    files += [ROOT / "phase-c/benchmarks/core_resources.rs", Path(__file__)]
    return "".join(f"{digest(p)}  {p.relative_to(ROOT)}\n" for p in files)


commit = baseline("initial")
sources = source_manifest()
(work / "SOURCE_SHA256SUMS").write_text(sources)
toolchain = run(["rustc", "--version", "--verbose"], "toolchain")
identity = {"scope": "whole-process observed lifecycle high-water; not worst-case/per-call bound",
            "baseline_commit": commit, "cpu_affinity": args.cpu, "rustc": toolchain,
            "valgrind": run(["valgrind", "--version"], "valgrind-version"),
            "time": run(["/usr/bin/time", "--version"], "time-version"),
            "platform": run(["uname", "-a"], "platform"),
            "cpu": run(["lscpu"], "cpu"),
            "source_manifest_sha256": digest(work / "SOURCE_SHA256SUMS"),
            "harness_sha256": digest(ROOT / "phase-c/benchmarks/core_resources.rs"),
            "profile": "O3 ThinLTO CGU1 panic=unwind overflow-checks=on",
            "stack_repetitions": args.stack_repetitions, "rss_repetitions": args.rss_repetitions,
            "stack_operation_count": 10, "rss_operation_count": 100,
            "rss_unit": "KiB from native GNU time %M, including loader/runtime/harness",
            "stack_unit": "bytes from Massif mem_stacks_B; initial stack counted from zero",
            "frequency_policy": "governor and boost unchanged"}
binaries = {}
for version, source in (("v1", args.v1.resolve()), ("v2", ROOT / "rust")):
    out = work / version
    for part in ("src", "cargo-home", "markers", "target"):
        (out / part).mkdir(parents=True)
    shutil.copyfile(ROOT / "phase-c/benchmarks/core_resources.rs", out / "src/main.rs")
    (out / "Cargo.toml").write_text(
        '[workspace]\n[package]\nname="ed301-resources"\nversion="0.0.0"\n'
        'edition="2024"\npublish=false\n[dependencies]\ned301-eddsa={path='
        + json.dumps(str(source / "crates/ed301-eddsa")) + '}\n'
        '[profile.release]\nopt-level=3\nlto="thin"\ncodegen-units=1\n'
        'panic="unwind"\noverflow-checks=true\n')
    run(["python3", "-I", "-B", source / "scripts/write-cargo-config.py",
         out / "cargo-home/config.toml", source / "vendor"], version + "-config")
    env = dict(clean, CARGO_HOME=str(out / "cargo-home"), CARGO_TARGET_DIR=str(out / "target"),
               CARGO_NET_OFFLINE="true", CARGO_INCREMENTAL="0", CCACHE_DISABLE="1",
               ED301_PROFILE_MARKER_DIR=str(out / "markers"),
               RUSTC_WRAPPER=str(source / "scripts/rustc-profile-guard.sh"))
    (out / "markers/toolchain.txt").write_text(toolchain)
    run(["cargo", "generate-lockfile", "--manifest-path", out / "Cargo.toml", "--offline"],
        version + "-lock", env)
    run(["cargo", "build", "--manifest-path", out / "Cargo.toml", "--locked", "--offline",
         "--release"], version + "-build", env)
    run(["sh", source / "scripts/check-profile-markers.sh", out / "markers",
         "crypto_bigint=on", "ed301_eddsa=on", "ed301_resources=on"], version + "-profile")
    binary = work / "binaries" / f"ed301-resources-{version}"
    shutil.copy2(out / "target/release/ed301-resources", binary)
    binaries[version] = binary
    identity[version] = {"source": str(source), "binary_sha256": digest(binary),
                         "gnu_size": run(["size", binary], version + "-binary-size").strip()}
    if digest(out / "src/main.rs") != identity["harness_sha256"]:
        raise SystemExit("FAIL: unequal harness")

operations = ("empty", "seed-expand", "cold-sign", "prepared-sign", "public-import",
              "prepare-verifier", "prepared-verify", "import-verify")
cases = [(v, op, m, c) for m, c in ((0, 0), (64, 0), (16384, 255))
         for op in operations for v in ("v1", "v2")]
cases += [(v, op, 64, 0) for op in ("stack-control", "rss-control") for v in ("v1", "v2")]
rows = []
raw = work / "raw.tsv"
raw.write_text("lane\trepeat\tversion\toperation\tmessage_bytes\tcontext_bytes\tcount\tpeak\n")
for lane, repetitions, count in (("stack_B", args.stack_repetitions, 10),
                                  ("rss_KiB", args.rss_repetitions, 100)):
    for repeat in range(repetitions):
        print(f"STEP: {lane} rotation {repeat + 1}/{repetitions}", flush=True)
        order = list(range(len(cases)))
        if repeat % 2:
            order.reverse()
        shift = (2 * repeat) % len(order)
        order = order[shift:] + order[:shift]
        for index in order:
            version, operation, message, context = cases[index]
            label = f"{lane}-{repeat + 1}-{version}-{operation}-m{message}-c{context}"
            command = [binaries[version], operation, message, context, count]
            if lane == "stack_B":
                massif = work / "massif" / (label + ".out")
                output = run(["taskset", "-c", args.cpu, "valgrind", "--tool=massif", "--vgdb=no",
                              "--enable-debuginfod=no", "--heap=no", "--stacks=yes",
                              "--time-unit=B", "--peak-inaccuracy=0.0", "--max-snapshots=1000",
                              "--massif-out-file=" + str(massif), *command], label, announce=False)
                values = [int(x) for x in re.findall(r"^mem_stacks_B=(\d+)$", massif.read_text(), re.M)]
                if not values:
                    raise SystemExit("FAIL: missing Massif stack snapshots")
                peak = max(values)
            else:
                output = run(["taskset", "-c", args.cpu, "/usr/bin/time",
                              "-f", "RESOURCE_RSS_KIB=%M", *command], label, announce=False)
                values = re.findall(r"^RESOURCE_RSS_KIB=(\d+)$", output, re.M)
                if len(values) != 1:
                    raise SystemExit("FAIL: missing native RSS high-water")
                peak = int(values[0])
            expected = f"RESOURCE_DONE operation={operation} message_bytes={message} context_bytes={context} count={count}"
            if expected not in output or peak <= 0:
                raise SystemExit("FAIL: incomplete operation or nonpositive resource result")
            row = [lane, repeat + 1, version, operation, message, context, count, peak]
            rows.append(row)
            with raw.open("a") as out:
                out.write("\t".join(map(str, row)) + "\n")

summary = []
for version, operation, message, context in cases:
    entry = {"version": version, "operation": operation, "message_bytes": message,
             "context_bytes": context}
    for lane in ("stack_B", "rss_KiB"):
        values = [r[7] for r in rows if r[0] == lane and r[2:6] == [version, operation, message, context]]
        entry[lane] = {"repetitions": len(values), "median": statistics.median(values),
                       "stdev": statistics.stdev(values), "min": min(values), "max": max(values)}
    summary.append(entry)
controls = []
for version in ("v1", "v2"):
    def get(operation, lane):
        return next(e[lane]["median"] for e in summary if e["version"] == version
                    and e["operation"] == operation and e["message_bytes"] == 64 and e["context_bytes"] == 0)
    stack_delta = get("stack-control", "stack_B") - get("empty", "stack_B")
    rss_delta = get("rss-control", "rss_KiB") - get("empty", "rss_KiB")
    if stack_delta < 240 * 1024 or rss_delta < 4 * 1024:
        raise SystemExit("FAIL: resource positive control not observed")
    controls.append({"version": version, "stack_control_delta_B": stack_delta,
                     "rss_control_delta_KiB": rss_delta, "status": "PASS"})
identity["controls"] = controls
baseline("final")
if source_manifest() != sources:
    raise SystemExit("FAIL: source set/content changed")
(work / "IDENTITY.json").write_text(json.dumps(identity, indent=2) + "\n")
(work / "SUMMARY.json").write_text(json.dumps(summary, indent=2) + "\n")
files = sorted(p for p in work.rglob("*") if p.is_file()
               and "target" not in p.relative_to(work).parts and p.name != "SHA256SUMS")
(work / "SHA256SUMS").write_text("".join(f"{digest(p)}  {p.relative_to(work)}\n" for p in files))
print(f"PASS: {len(summary)} resource cases; artifact_directory={work}", flush=True)
