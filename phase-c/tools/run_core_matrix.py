#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Paired public-API C1/C2 matrix; never edits the bound baseline checkout."""
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
parser.add_argument("--v1", type=Path, default=ROOT.parent / "ed301-eddsa-github")
parser.add_argument("--cpu", type=int, default=2)
parser.add_argument("--repetitions", type=int, default=9)
parser.add_argument("--target-ms", type=int, default=100)
args = parser.parse_args()
if args.cpu not in os.sched_getaffinity(0) or args.repetitions < 3 or args.target_ms < 100:
    parser.error("require available CPU, >=3 repetitions, >=100 ms")
work = Path(tempfile.mkdtemp(prefix="ED301-v2_core-matrix_", dir=ROOT.parent))
for part in ("home", "logs"):
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
    start = time.time()
    result = subprocess.run(command, cwd="/", env=env or clean, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log = work / "logs" / f"{len(commands):04d}-{name}.log"
    log.write_text(result.stdout)
    commands.append({"command": command, "name": name, "environment": env or clean,
                     "log": str(log.relative_to(work)), "exit": result.returncode,
                     "started_unix": start, "elapsed_seconds": time.time() - start})
    (work / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
    if result.returncode:
        print(result.stdout, end="", flush=True)
        raise SystemExit(f"FAIL: {name}; evidence retained at {work}")
    return result.stdout


def baseline_check(label):
    commit = run(["git", "-C", args.v1, "rev-parse", "HEAD"], label + "-commit").strip()
    dirty = run(["git", "-C", args.v1, "status", "--porcelain", "--untracked-files=all"],
                label + "-status").strip()
    if commit != "5c688206a15f6ab88a50d53fe503665a302cec4d" or dirty:
        raise SystemExit("FAIL: v1 baseline is not the bound clean commit")
    return commit


def sources():
    return "".join(f"{digest(p)}  {p.relative_to(ROOT)}\n"
                   for base in (ROOT / "rust", ROOT / "phase-c")
                   for p in sorted(base.rglob("*")) if p.is_file())


commit = baseline_check("initial")
source_manifest = sources()
(work / "V2_SOURCE_SHA256SUMS").write_text(source_manifest)
toolchain = run(["rustc", "--version", "--verbose"], "toolchain")
identity = {"baseline_commit": commit, "cpu_affinity": args.cpu,
            "repetitions": args.repetitions, "target_ms": args.target_ms,
            "rustc": toolchain, "platform": run(["uname", "-a"], "platform"),
            "cpu": run(["lscpu"], "cpu"),
            "load_before": Path("/proc/loadavg").read_text().strip(),
            "source_manifest_sha256": digest(work / "V2_SOURCE_SHA256SUMS"),
            "harness_sha256": digest(ROOT / "phase-c/benchmarks/core_matrix.rs"),
            "profile": "O3 ThinLTO CGU1 panic=unwind overflow-checks=on",
            "frequency_policy": "governor and boost unchanged"}
binaries = {}
for version, source in (("v1", args.v1), ("v2", ROOT / "rust")):
    out = work / version
    for part in ("src", "cargo-home", "markers", "target"):
        (out / part).mkdir(parents=True)
    shutil.copyfile(ROOT / "phase-c/benchmarks/core_matrix.rs", out / "src/main.rs")
    (out / "Cargo.toml").write_text(
        '[workspace]\n[package]\nname="ed301-core-matrix"\nversion="0.0.0"\n'
        'edition="2024"\npublish=false\n[dependencies]\ned301-eddsa={path='
        + json.dumps(str(source.resolve() / "crates/ed301-eddsa")) + '}\n'
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
         "crypto_bigint=on", "ed301_eddsa=on", "ed301_core_matrix=on"], version + "-profile")
    binary = out / "target/release/ed301-core-matrix"
    binaries[version] = binary
    identity[version] = {"source": str(source.resolve()), "binary_sha256": digest(binary),
                         "sizes": run([binary, "sizes"], version + "-sizes").strip(),
                         "gnu_size": run(["size", binary], version + "-binary-size").strip()}
    if digest(out / "src/main.rs") != identity["harness_sha256"]:
        raise SystemExit("FAIL: unequal harness")

cases = [(v, op, m, c) for m in (0, 64, 1024, 16384) for c in (0, 16, 255)
         for op in ("cold-sign", "prepared-sign", "prepared-verify", "import-verify")
         for v in ("v1", "v2")]
cases += [(v, "prepare-verifier", 0, 0) for v in ("v1", "v2")]


def measure(case, count, label):
    v, op, m, c = case
    output = run(["taskset", "-c", args.cpu, binaries[v], op, m, c, count],
                 f"{label}-{v}-{op}-m{m}-c{c}", announce=False)
    match = re.search(r"^RESULT .*mean_ns=([0-9.]+)$", output, re.MULTILINE)
    if not match or not math.isfinite(float(match[1])) or float(match[1]) <= 0:
        raise SystemExit("FAIL: missing/invalid benchmark result")
    return float(match[1])


print("STEP: warmup/calibration", flush=True)
counts = [max(100, min(100000, math.ceil(args.target_ms * 1e6 / measure(c, 100, "warmup"))))
          for c in cases]
rows = []
raw = work / "raw.tsv"
raw.write_text("repeat\tversion\toperation\tmessage_bytes\tcontext_bytes\tcount\tmean_ns\n")
for repeat in range(args.repetitions):
    print(f"STEP: rotation {repeat + 1}/{args.repetitions}", flush=True)
    order = list(range(len(cases)))
    if repeat % 2:
        order.reverse()
    shift = (2 * repeat) % len(order)
    order = order[shift:] + order[:shift]
    for index in order:
        row = [repeat + 1, *cases[index], counts[index],
               measure(cases[index], counts[index], f"repeat-{repeat + 1}")]
        rows.append(row)
        with raw.open("a") as out:
            out.write("\t".join(map(str, row)) + "\n")
summary = []
for case in cases:
    values = [r[6] for r in rows if r[1:5] == list(case)]
    summary.append(dict(zip(("version", "operation", "message_bytes", "context_bytes"), case),
                        repetitions=len(values), median_ns=statistics.median(values),
                        stdev_ns=statistics.stdev(values), min_ns=min(values), max_ns=max(values)))
baseline_check("final")
if sources() != source_manifest:
    raise SystemExit("FAIL: v2 source set or content changed during benchmark")
identity["load_after"] = Path("/proc/loadavg").read_text().strip()
(work / "IDENTITY.json").write_text(json.dumps(identity, indent=2) + "\n")
(work / "SUMMARY.json").write_text(json.dumps(summary, indent=2) + "\n")
files = sorted(p for p in work.rglob("*") if p.is_file()
               and "target" not in p.relative_to(work).parts and p.name != "SHA256SUMS")
(work / "SHA256SUMS").write_text("".join(f"{digest(p)}  {p.relative_to(work)}\n" for p in files))
print(f"PASS: {len(summary)} cases; artifact_directory={work}", flush=True)
