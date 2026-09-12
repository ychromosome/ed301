#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fresh paired X301 Rust benchmarks; preserve the historical v1 profile exception."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import statistics
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--v1", type=Path, default=ROOT.parent / "x301-integration")
parser.add_argument("--cpu", type=int, default=2)
parser.add_argument("--repetitions", type=int, default=9)
parser.add_argument("--target-ms", type=int, default=200)
args = parser.parse_args()
if args.cpu not in os.sched_getaffinity(0) or args.repetitions < 3 or args.target_ms < 100:
    parser.error("available CPU, >=3 repetitions and >=100 ms required")
work = Path(tempfile.mkdtemp(prefix="X301-v2_D1-benchmark_", dir=ROOT.parent))
for part in ("home", "logs", "binaries"):
    (work / part).mkdir()
clean = {"PATH": "/usr/bin:/bin", "HOME": str(work / "home"), "LC_ALL": "C"}
commands = []
print(f"artifact_directory={work}", flush=True)


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, label, env=None, announce=True):
    command = list(map(str, command))
    if announce: print(f"STEP: {label}", flush=True)
    start = time.time()
    result = subprocess.run(command, cwd="/", env=env or clean, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log = work / "logs" / f"{len(commands):04d}-{label}.log"
    log.write_text(result.stdout)
    commands.append({"command": command, "step": label, "environment": env or clean,
                     "exit": result.returncode, "log": str(log.relative_to(work)),
                     "elapsed_seconds": time.time() - start})
    (work / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
    if result.returncode:
        print(result.stdout, end="", flush=True)
        raise SystemExit(f"FAIL: {label}; artifacts retained at {work}")
    return result.stdout


def check_v1(label):
    head = run(["git", "-C", args.v1, "rev-parse", "HEAD"], label + "-head").strip()
    dirty = run(["git", "-C", args.v1, "status", "--porcelain", "--untracked-files=all"], label + "-status").strip()
    if head != "569dc4ff10e0e5e19d106cbe490d2a5aaeac935e" or dirty:
        raise SystemExit("FAIL: bound integration baseline changed")
    return head


def sources():
    files = sorted(p for p in (ROOT / "rust").rglob("*") if p.is_file())
    files += [ROOT / "phase-d/benchmarks/x301_core_bench.rs", Path(__file__)]
    return "".join(f"{sha(p)}  {p.relative_to(ROOT)}\n" for p in files)


v1_commit = check_v1("initial")
manifest = sources()
(work / "SOURCE_SHA256SUMS").write_text(manifest)
toolchain = run(["rustc", "--version", "--verbose"], "toolchain")
identity = {"v1_commit": v1_commit, "v1_scope": "historical integration core, normalization and fixed-bit optimizations retained",
            "v2_scope": "strict X301-v2; arithmetic identified by the recorded source and binary hashes",
            "profile": "O3 ThinLTO CGU1 panic=unwind; overflow on except historical v1 crypto-bigint off",
            "cpu": run(["lscpu"], "cpu"), "affinity": args.cpu, "rustc": toolchain,
            "platform": run(["uname", "-a"], "platform"), "repetitions": args.repetitions,
            "target_ms": args.target_ms, "source_manifest_sha256": sha(work / "SOURCE_SHA256SUMS"),
            "harness_sha256": sha(ROOT / "phase-d/benchmarks/x301_core_bench.rs"),
            "load_before": Path("/proc/loadavg").read_text().strip()}
binaries = {}
for version, source, package, dependency in (
    ("v1", args.v1.resolve(), "ed301-eddsa", args.v1.resolve() / "crates/ed301-eddsa"),
    ("v2", ROOT / "rust", "x301-core", ROOT / "rust/crates/x301"),
):
    out = work / version
    for part in ("src", "cargo-home", "markers", "target"):
        (out / part).mkdir(parents=True)
    shutil.copyfile(ROOT / "phase-d/benchmarks/x301_core_bench.rs", out / "src/main.rs")
    features = ',features=["x301"]' if version == "v1" else ""
    text = ('[workspace]\n[package]\nname="x301-core-benchmark"\nversion="0.0.0"\nedition="2024"\npublish=false\n'
            '[features]\nv2=[]\n[dependencies]\nx301-implementation={package=' + json.dumps(package)
            + ',path=' + json.dumps(str(dependency)) + features + '}\n'
            '[profile.release]\nopt-level=3\nlto="thin"\ncodegen-units=1\npanic="unwind"\noverflow-checks=true\n')
    if version == "v1": text += '[profile.release.package."crypto-bigint:0.7.5"]\noverflow-checks=false\n'
    (out / "Cargo.toml").write_text(text)
    run(["python3", "-I", "-B", source / "scripts/write-cargo-config.py", out / "cargo-home/config.toml", source / "vendor"], version + "-config")
    (out / "markers/toolchain.txt").write_text(toolchain)
    env = dict(clean, CARGO_HOME=str(out / "cargo-home"), CARGO_TARGET_DIR=str(out / "target"),
               CARGO_NET_OFFLINE="true", CARGO_INCREMENTAL="0", CCACHE_DISABLE="1",
               ED301_PROFILE_MARKER_DIR=str(out / "markers"), RUSTC_WRAPPER=str(source / "scripts/rustc-profile-guard.sh"))
    if version == "v1": env["ED301_PROFILE_EXCEPTIONS"] = "crypto_bigint=off"
    run(["cargo", "generate-lockfile", "--manifest-path", out / "Cargo.toml", "--offline"], version + "-lock", env)
    feature = ["--features", "v2"] if version == "v2" else []
    run(["cargo", "build", "--manifest-path", out / "Cargo.toml", "--locked", "--offline", "--release", *feature], version + "-build", env)
    required = ["crypto_bigint=off", "ed301_eddsa=on"] if version == "v1" else ["crypto_bigint=on", "x301_core=on"]
    run(["sh", source / "scripts/check-profile-markers.sh", out / "markers", *required, "x301_core_benchmark=on"], version + "-profiles")
    binary = work / "binaries" / ("x301-core-benchmark-" + version)
    shutil.copy2(out / "target/release/x301-core-benchmark", binary)
    binaries[version] = binary
    identity[version] = {"source": str(source), "binary_sha256": sha(binary),
                         "size": run(["size", binary], version + "-size")}
    if sha(out / "src/main.rs") != identity["harness_sha256"]: raise SystemExit("FAIL: unequal harness")
cases = [(v, op) for op in ("public", "shared", "validate-public", "canonical-public") for v in ("v1", "v2")]
cases += [("v2", op) for op in ("import-secret", "import-public", "prepared-shared", "prepared-public")]


def measure(case, count, label):
    version, operation = case
    output = run(["taskset", "-c", args.cpu, binaries[version], operation, count],
                 f"{label}-{version}-{operation}", announce=False)
    match = re.search(r"^RESULT .*mean_ns=([0-9.]+)$", output, re.M)
    if not match or not math.isfinite(float(match[1])) or float(match[1]) <= 0: raise SystemExit("FAIL: benchmark output")
    return float(match[1])


print("STEP: calibration", flush=True)
counts = [max(100, min(100_000_000, math.ceil(args.target_ms * 1e6 / measure(case, 100, "warmup")))) for case in cases]
rows = []
raw = work / "raw.tsv"
raw.write_text("repeat\tversion\toperation\tcount\tmean_ns\n")
for repeat in range(args.repetitions):
    print(f"STEP: rotation {repeat + 1}/{args.repetitions}", flush=True)
    order = list(range(len(cases)))
    if repeat % 2: order.reverse()
    shift = (2 * repeat) % len(order)
    order = order[shift:] + order[:shift]
    for index in order:
        row = [repeat + 1, *cases[index], counts[index], measure(cases[index], counts[index], f"repeat-{repeat + 1}")]
        rows.append(row)
        with raw.open("a") as out: out.write("\t".join(map(str, row)) + "\n")
summary = []
for version, operation in cases:
    values = [r[4] for r in rows if r[1:3] == [version, operation]]
    summary.append({"version": version, "operation": operation, "repetitions": len(values),
                    "median_ns": statistics.median(values), "stdev_ns": statistics.stdev(values),
                    "min_ns": min(values), "max_ns": max(values)})
check_v1("final")
if sources() != manifest: raise SystemExit("FAIL: source changed")
identity["load_after"] = Path("/proc/loadavg").read_text().strip()
(work / "IDENTITY.json").write_text(json.dumps(identity, indent=2) + "\n")
(work / "SUMMARY.json").write_text(json.dumps(summary, indent=2) + "\n")
files = sorted(p for p in work.rglob("*") if p.is_file() and "target" not in p.relative_to(work).parts and p.name != "SHA256SUMS")
(work / "SHA256SUMS").write_text("".join(f"{sha(p)}  {p.relative_to(work)}\n" for p in files))
print(f"PASS: {len(summary)} X301 Rust benchmark cases; artifact_directory={work}", flush=True)
