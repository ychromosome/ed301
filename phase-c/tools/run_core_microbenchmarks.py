#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Same internal-operation harness, untouched v1/v2 module sources, offline builds."""
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
    parser.error("need available CPU, >=3 repetitions and >=100 ms")
work = Path(tempfile.mkdtemp(prefix="ED301-v2_microbench_", dir=ROOT.parent))
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


def baseline(label):
    commit = run(["git", "-C", args.v1, "rev-parse", "HEAD"], label + "-commit").strip()
    dirty = run(["git", "-C", args.v1, "status", "--porcelain", "--untracked-files=all"],
                label + "-status").strip()
    if commit != "5c688206a15f6ab88a50d53fe503665a302cec4d" or dirty:
        raise SystemExit("FAIL: v1 is not the bound clean baseline")
    return commit


def source_manifest():
    # The product tree is frozen, while independent report/package work may proceed.
    files = sorted(p for p in (ROOT / "rust").rglob("*") if p.is_file())
    files += [ROOT / "phase-c/benchmarks/core_micro.rs", Path(__file__)]
    return "".join(f"{digest(p)}  {p.relative_to(ROOT)}\n" for p in files)


commit = baseline("initial")
sources = source_manifest()
(work / "SOURCE_SHA256SUMS").write_text(sources)
toolchain = run(["rustc", "--version", "--verbose"], "toolchain")
identity = {"scope": "private arithmetic microbench; not a product API or side-channel gate",
            "baseline_commit": commit, "cpu_affinity": args.cpu,
            "repetitions": args.repetitions, "target_ms": args.target_ms,
            "rustc": toolchain, "platform": run(["uname", "-a"], "platform"),
            "cpu": run(["lscpu"], "cpu"),
            "load_before": Path("/proc/loadavg").read_text().strip(),
            "source_manifest_sha256": digest(work / "SOURCE_SHA256SUMS"),
            "harness_sha256": digest(ROOT / "phase-c/benchmarks/core_micro.rs"),
            "profile": "O3 ThinLTO CGU1 panic=unwind overflow-checks=on",
            "frequency_policy": "governor and boost unchanged"}
binaries = {}
for version, source in (("v1", args.v1.resolve()), ("v2", ROOT / "rust")):
    out = work / version
    for part in ("src", "cargo-home", "markers", "target"):
        (out / part).mkdir(parents=True)
    shutil.copyfile(ROOT / "phase-c/benchmarks/core_micro.rs", out / "src/harness.rs")
    modules = ["parameters", "field", "field_5x64", "scalar", "secret"]
    if version == "v2":
        modules.insert(0, "generated_parameters")
    module_files = [source / "crates/ed301-eddsa/src" / (name + ".rs") for name in modules]
    # Modules are compiled byte-for-byte at their existing crate-private visibility.
    (out / "src/main.rs").write_text(
        '#![forbid(unsafe_code)]\n#![allow(dead_code)]\n'
        + "".join(f'#[path = {json.dumps(str(p))}]\nmod {name};\n'
                  for name, p in zip(modules, module_files))
        + 'include!("harness.rs");\n')
    (out / "Cargo.toml").write_text(
        '[workspace]\n[package]\nname="ed301-microbench"\nversion="0.0.0"\n'
        'edition="2024"\npublish=false\n[features]\nprofile-v2=[]\n'
        '[dependencies]\ncrypto-bigint={path='
        + json.dumps(str(source / "vendor/crypto-bigint"))
        + ',default-features=false,features=["zeroize"]}\n'
        'zeroize={version="=1.9.0",default-features=false}\n'
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
    feature = ["--features", "profile-v2"] if version == "v2" else []
    run(["cargo", "build", "--manifest-path", out / "Cargo.toml", "--locked", "--offline",
         "--release", *feature], version + "-build", env)
    run(["sh", source / "scripts/check-profile-markers.sh", out / "markers",
         "crypto_bigint=on", "ed301_microbench=on"], version + "-profile")
    binary = out / "target/release/ed301-microbench"
    binaries[version] = binary
    identity[version] = {"source": str(source), "binary_sha256": digest(binary),
                         "module_sha256": {str(p): digest(p) for p in module_files},
                         "generated_crate_sha256": digest(out / "src/main.rs"),
                         "gnu_size": run(["size", binary], version + "-binary-size").strip()}
    if digest(out / "src/harness.rs") != identity["harness_sha256"]:
        raise SystemExit("FAIL: unequal harness")

operations = ("control-field-copy", "field-add", "field-sub", "field-mul", "field-square",
              "field-mul-301", "field-mul-a", "field-mul-d", "field-invert", "field-sqrt-ratio",
              "lazy-mul", "lazy-square", "lazy-mul-a", "lazy-loose-mul", "scalar-add",
              "scalar-mul", "scalar-reduce-pruned", "scalar-reduce-hash", "scalar-wnaf-public")
cases = [(v, op) for op in operations for v in ("v1", "v2")]


def measure(case, count, label):
    version, op = case
    output = run(["taskset", "-c", args.cpu, binaries[version], op, count],
                 f"{label}-{version}-{op}", announce=False)
    match = re.search(r"^RESULT .*mean_ns=([0-9.]+)$", output, re.MULTILINE)
    if not match or not math.isfinite(float(match[1])) or float(match[1]) <= 0:
        raise SystemExit("FAIL: invalid benchmark result")
    return float(match[1])


print("STEP: warmup/calibration", flush=True)
counts = [max(1000, min(100000000, math.ceil(args.target_ms * 1e6 / measure(c, 1000, "warmup"))))
          for c in cases]
rows = []
raw = work / "raw.tsv"
raw.write_text("repeat\tversion\toperation\tcount\tmean_ns\n")
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
for version, operation in cases:
    values = [r[4] for r in rows if r[1:3] == [version, operation]]
    summary.append({"version": version, "operation": operation, "repetitions": len(values),
                    "median_ns": statistics.median(values), "stdev_ns": statistics.stdev(values),
                    "min_ns": min(values), "max_ns": max(values)})
baseline("final")
if source_manifest() != sources:
    raise SystemExit("FAIL: source set/content changed")
identity["load_after"] = Path("/proc/loadavg").read_text().strip()
(work / "IDENTITY.json").write_text(json.dumps(identity, indent=2) + "\n")
(work / "SUMMARY.json").write_text(json.dumps(summary, indent=2) + "\n")
files = sorted(p for p in work.rglob("*") if p.is_file()
               and "target" not in p.relative_to(work).parts and p.name != "SHA256SUMS")
(work / "SHA256SUMS").write_text("".join(f"{digest(p)}  {p.relative_to(work)}\n" for p in files))
print(f"PASS: {len(summary)} microbenchmarks; artifact_directory={work}", flush=True)
