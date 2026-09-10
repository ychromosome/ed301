#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Interleaved before/after/v1 core measurements using identical bound harnesses."""
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
parser.add_argument("--before", type=Path, required=True)
parser.add_argument("--after", type=Path, required=True)
parser.add_argument("--ed-v1", type=Path, required=True)
parser.add_argument("--x-v1", type=Path, required=True)
parser.add_argument("--cpu", type=int, default=2)
parser.add_argument("--repetitions", type=int, default=9)
parser.add_argument("--target-ms", type=int, default=200)
args = parser.parse_args()
if args.cpu not in os.sched_getaffinity(0) or args.repetitions != 9 or args.target_ms < 200:
    parser.error("available CPU, exactly nine repeats and at least 200 ms required")
work = Path(tempfile.mkdtemp(prefix="ED301-v2_PHASE_E_core-bench_", dir=ROOT.parent))
for part in ("home", "logs", "binaries"):
    (work / part).mkdir()
clean = {"PATH": "/usr/bin:/bin", "HOME": str(work / "home"), "LC_ALL": "C"}
commands = []
print(f"artifact_directory={work}", flush=True)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, label, env=None, announce=True):
    command = list(map(str, command))
    if announce:
        print(f"STEP: {label}", flush=True)
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
        raise SystemExit(f"FAIL: {label}; retained at {work}")
    return result.stdout


def source_manifest(root):
    return "".join(f"{sha(p)}  {p.relative_to(root)}\n"
                   for p in sorted(root.rglob("*")) if p.is_file())


donors = (("ed", args.ed_v1.resolve(), "5c688206a15f6ab88a50d53fe503665a302cec4d"),
          ("x", args.x_v1.resolve(), "569dc4ff10e0e5e19d106cbe490d2a5aaeac935e"))


def check_donors(label):
    for name, source, expected in donors:
        head = run(["git", "-C", source, "rev-parse", "HEAD"], label + "-" + name + "-head").strip()
        dirty = run(["git", "-C", source, "status", "--porcelain", "--untracked-files=all"], label + "-" + name + "-status").strip()
        if head != expected or dirty:
            raise SystemExit("FAIL: bound v1 source changed")


check_donors("initial")
snapshots = {"before": args.before.resolve(), "after": args.after.resolve()}
sources = {label: source_manifest(path / "rust") for label, path in snapshots.items()}
for label, content in sources.items():
    (work / (label + "_RUST_SHA256SUMS")).write_text(content)
harnesses = {"ed": ROOT / "rust/performance/ed301-bench/src/main.rs",
             "x": ROOT / "phase-d/benchmarks/x301_core_bench.rs"}
harness_hashes = {label: sha(path) for label, path in harnesses.items()}
if sha(args.ed_v1 / "performance/ed301-bench/src/main.rs") != harness_hashes["ed"]:
    raise SystemExit("FAIL: historical Ed301 harness differs")
toolchain = run(["rustc", "--version", "--verbose"], "toolchain")
identity = {"scope": "core-only per-optimization comparison; provider/TLS final matrix is separate",
            "repetitions": args.repetitions, "cpu_affinity": args.cpu, "target_ms": args.target_ms,
            "rustc": toolchain, "cpu": run(["lscpu"], "cpu"), "platform": run(["uname", "-a"], "platform"),
            "frequency_policy": "no governor or boost changes", "load_before": Path("/proc/loadavg").read_text().strip(),
            "runner_sha256": sha(Path(__file__)), "harness_sha256": harness_hashes,
            "source_manifest_sha256": {key: sha(work / (key + "_RUST_SHA256SUMS")) for key in sources},
            "v1_commits": {name: commit for name, _, commit in donors},
            "profile": "O3 ThinLTO CGU1 unwind overflow on; historical X301-v1 crypto-bigint exception off",
            "binaries": {}}
binaries = {}
cases = []
for api in ("ed", "x"):
    donor = args.ed_v1.resolve() if api == "ed" else args.x_v1.resolve()
    for version, rust in [("v1", donor)] + [(label, path / "rust") for label, path in snapshots.items()]:
        label = api + "-" + version
        out = work / label
        for part in ("src", "cargo-home", "markers", "target"):
            (out / part).mkdir(parents=True)
        shutil.copyfile(harnesses[api], out / "src/main.rs")
        package = "x301-core" if api == "x" and version != "v1" else "ed301-eddsa"
        dependency = rust / "crates" / ("x301" if package == "x301-core" else "ed301-eddsa")
        features = ',features=["x301"]' if api == "x" and version == "v1" else ""
        alias = "x301-implementation" if api == "x" else "ed301-eddsa"
        text = ('[workspace]\n[package]\nname="phase-e-core-bench"\nversion="0.0.0"\nedition="2024"\npublish=false\n'
                '[features]\nv2=[]\n[dependencies]\n' + alias + '={package=' + json.dumps(package)
                + ',path=' + json.dumps(str(dependency)) + features + '}\n'
                '[profile.release]\nopt-level=3\nlto="thin"\ncodegen-units=1\npanic="unwind"\noverflow-checks=true\n')
        exception = api == "x" and version == "v1"
        if exception:
            text += '[profile.release.package."crypto-bigint:0.7.5"]\noverflow-checks=false\n'
        (out / "Cargo.toml").write_text(text)
        run(["python3", "-I", "-B", rust / "scripts/write-cargo-config.py", out / "cargo-home/config.toml", rust / "vendor"], label + "-config")
        (out / "markers/toolchain.txt").write_text(toolchain)
        env = dict(clean, CARGO_HOME=str(out / "cargo-home"), CARGO_TARGET_DIR=str(out / "target"),
                   CARGO_NET_OFFLINE="true", CARGO_INCREMENTAL="0", CCACHE_DISABLE="1",
                   ED301_PROFILE_MARKER_DIR=str(out / "markers"), RUSTC_WRAPPER=str(rust / "scripts/rustc-profile-guard.sh"))
        if exception:
            env["ED301_PROFILE_EXCEPTIONS"] = "crypto_bigint=off"
        run(["cargo", "generate-lockfile", "--manifest-path", out / "Cargo.toml", "--offline"], label + "-lock", env)
        feature = ["--features", "v2"] if api == "x" and version != "v1" else []
        run(["cargo", "build", "--manifest-path", out / "Cargo.toml", "--locked", "--offline", "--release", *feature], label + "-build", env)
        run(["sh", rust / "scripts/check-profile-markers.sh", out / "markers", "crypto_bigint=" + ("off" if exception else "on"),
             package.replace("-", "_") + "=on", "phase_e_core_bench=on"], label + "-profiles")
        binary = work / "binaries" / label
        shutil.copy2(out / "target/release/phase-e-core-bench", binary)
        binaries[(api, version)] = binary
        identity["binaries"][label] = {"sha256": sha(binary), "source": str(rust),
                                        "size": run(["size", binary], label + "-size")}
        if sha(out / "src/main.rs") != harness_hashes[api]:
            raise SystemExit("FAIL: unequal harness")
    operations = ("expand", "sign", "verify", "import") if api == "ed" else ("public", "shared", "validate-public", "canonical-public")
    cases += [(api, version, op) for op in operations for version in ("v1", "before", "after")]
    if api == "x":
        cases += [(api, version, op) for op in ("import-secret", "import-public", "prepared-shared", "prepared-public")
                  for version in ("before", "after")]


def measure(case, count, label):
    api, version, operation = case
    output = run(["taskset", "-c", args.cpu, binaries[(api, version)], operation, count],
                 label + "-" + "-".join(case), announce=False)
    match = re.search(r"^RESULT .*mean_ns=([0-9.]+)$", output, re.M)
    if not match or not math.isfinite(float(match[1])) or float(match[1]) <= 0:
        raise SystemExit("FAIL: invalid benchmark output")
    return float(match[1])


print("STEP: calibration", flush=True)
counts = [max(100, min(100_000_000, math.ceil(args.target_ms * 1e6 / measure(case, 100, "warmup")))) for case in cases]
rows = []
raw = work / "raw.tsv"
raw.write_text("repeat\tapi\tversion\toperation\tcount\tmean_ns\n")
for repeat in range(args.repetitions):
    print(f"STEP: rotation {repeat + 1}/{args.repetitions}", flush=True)
    order = list(range(len(cases)))
    if repeat % 2:
        order.reverse()
    shift = (3 * repeat) % len(order)
    for index in order[shift:] + order[:shift]:
        row = [repeat + 1, *cases[index], counts[index], measure(cases[index], counts[index], f"repeat-{repeat + 1}")]
        rows.append(row)
        with raw.open("a") as output:
            output.write("\t".join(map(str, row)) + "\n")
summary = []
for case in cases:
    values = [row[5] for row in rows if tuple(row[1:4]) == case]
    summary.append(dict(zip(("api", "version", "operation"), case), repetitions=len(values),
                        median_ns=statistics.median(values), stdev_ns=statistics.stdev(values),
                        min_ns=min(values), max_ns=max(values)))
check_donors("final")
if any(source_manifest(snapshots[key] / "rust") != value for key, value in sources.items()):
    raise SystemExit("FAIL: source changed during measurements")
if any(sha(path) != harness_hashes[key] for key, path in harnesses.items()):
    raise SystemExit("FAIL: harness changed during measurements")
identity["load_after"] = Path("/proc/loadavg").read_text().strip()
(work / "IDENTITY.json").write_text(json.dumps(identity, indent=2) + "\n")
(work / "SUMMARY.json").write_text(json.dumps(summary, indent=2) + "\n")
files = sorted(p for p in work.rglob("*") if p.is_file() and "target" not in p.relative_to(work).parts and p.name != "SHA256SUMS")
(work / "SHA256SUMS").write_text("".join(f"{sha(p)}  {p.relative_to(work)}\n" for p in files))
print(f"PASS: {len(summary)} cases; artifact_directory={work}", flush=True)
