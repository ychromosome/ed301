#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fresh, offline builds and separate API-layer benchmark receipts for Phase C."""

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
parser.add_argument("--ed301-v1", type=Path, default=ROOT.parent / "ed301-eddsa-github")
parser.add_argument("--x301-v1", type=Path, default=ROOT.parent / "x301-integration")
parser.add_argument("--cpu", type=int, default=2)
parser.add_argument("--repetitions", type=int, default=9)
parser.add_argument("--target-ms", type=int, default=200)
args = parser.parse_args()
if args.cpu not in os.sched_getaffinity(0) or args.repetitions < 3 or args.target_ms < 100:
    parser.error("need an available CPU, at least three repeats and >=100 ms calibration")
work = Path(tempfile.mkdtemp(prefix="ED301-v2_C1C2-benchmark_", dir=ROOT.parent))
(work / "home").mkdir()
(work / "logs").mkdir()
(work / "modules").mkdir()
clean = {"PATH": "/usr/bin:/bin", "HOME": str(work / "home"), "LC_ALL": "C",
         "OPENSSL_CONF": "/dev/null"}
commands = []
print(f"artifact_directory={work}", flush=True)


def run(command, name, env=None, announce=True):
    command = list(map(str, command))
    if announce:
        print(f"STEP: {name}", flush=True)
    started = time.time()
    result = subprocess.run(command, cwd="/", env=env or clean, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log = work / "logs" / f"{len(commands):04d}-{name}.log"
    log.write_text(result.stdout)
    commands.append({"command": command, "environment": env or clean, "name": name,
                     "log": str(log.relative_to(work)), "exit": result.returncode,
                     "started_unix": started, "elapsed_seconds": time.time() - started})
    (work / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
    if result.returncode:
        print(result.stdout, end="", flush=True)
        raise SystemExit(f"FAIL: {name}; artifacts retained in {work}")
    return result.stdout


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


baselines = {}
for name, source, expected in (
    ("ed301-v1", args.ed301_v1, "5c688206a15f6ab88a50d53fe503665a302cec4d"),
    ("x301-v1", args.x301_v1, "569dc4ff10e0e5e19d106cbe490d2a5aaeac935e"),
):
    head = run(["/usr/bin/git", "-C", source, "rev-parse", "HEAD"], name + "-commit").strip()
    dirty = run(["/usr/bin/git", "-C", source, "status", "--porcelain", "--untracked-files=all"],
                name + "-status").strip()
    if head != expected or dirty:
        raise SystemExit(f"FAIL: {name} is not the bound clean baseline")
    baselines[name] = {"source": str(source.resolve()), "commit": head}

source_files = sorted(p for base in (ROOT / "rust", ROOT / "phase-c")
                      for p in base.rglob("*") if p.is_file())
source_manifest = "".join(f"{digest(p)}  {p.relative_to(ROOT)}\n" for p in source_files)
(work / "V2_SOURCE_SHA256SUMS").write_text(source_manifest)
toolchain = run(["/usr/bin/rustc", "--version", "--verbose"], "rustc")
identity = {
    "scope": "Phase C C1/C2; available implementations only; separate API layers",
    "baselines": baselines, "v2_source_manifest_sha256": digest(work / "V2_SOURCE_SHA256SUMS"),
    "cpu_affinity": args.cpu, "repetitions": args.repetitions, "target_ms": args.target_ms,
    "rustc": toolchain,
    "gcc": run(["/usr/bin/gcc", "--version"], "gcc"),
    "openssl": run(["/usr/bin/openssl", "version", "-a"], "openssl"),
    "platform": run(["/usr/bin/uname", "-a"], "uname"),
    "cpu": run(["/usr/bin/lscpu"], "lscpu"),
    "load_before": Path("/proc/loadavg").read_text().strip(),
    "note": "No governor/boost changes. X301-v1 retains its historical crypto-bigint overflow-off exception.",
}
for name in ("scaling_governor", "scaling_driver"):
    p = Path(f"/sys/devices/system/cpu/cpu{args.cpu}/cpufreq/{name}")
    identity[name] = p.read_text().strip() if p.exists() else "unavailable"
p = Path("/sys/devices/system/cpu/cpufreq/boost")
identity["boost"] = p.read_text().strip() if p.exists() else "unavailable"


def build(source, manifest, name, required, exceptions="", provider=False):
    out = work / name
    for directory in ("cargo-home", "target", "markers"):
        (out / directory).mkdir(parents=True)
    run(["/usr/bin/python3", "-I", "-B", source / "scripts/write-cargo-config.py",
         out / "cargo-home/config.toml", source / "vendor"], name + "-config")
    (out / "markers/toolchain.txt").write_text(toolchain)
    env = dict(clean, CARGO_HOME=str(out / "cargo-home"), CARGO_TARGET_DIR=str(out / "target"),
               CARGO_NET_OFFLINE="true", CARGO_INCREMENTAL="0", CCACHE_DISABLE="1",
               CC="/usr/bin/gcc", AR="/usr/bin/ar", ED301_PROFILE_EXCEPTIONS=exceptions,
               ED301_PROFILE_MARKER_DIR=str(out / "markers"),
               RUSTC_WRAPPER=str(source / "scripts/rustc-profile-guard.sh"))
    if provider:
        env.update(ED301_HERMETIC_PROVIDER_BUILD="1", X301_HERMETIC_PROVIDER_BUILD="1",
                   OPENSSL_INCLUDE_DIR="/usr/include", OPENSSL_LIB_DIR="/usr/lib64")
    run(["/usr/bin/cargo", "build", "--manifest-path", source / manifest,
         "--locked", "--offline", "--release"], name + "-build", env)
    run(["/bin/sh", source / "scripts/check-profile-markers.sh", out / "markers", *required],
        name + "-profile")
    return out / "target/release"


v1core = build(args.ed301_v1, "performance/ed301-bench/Cargo.toml", "ed301-v1-core",
               ["crypto_bigint=on", "ed301_eddsa=on", "ed301_benchmark=on"])
v2core = build(ROOT / "rust", "performance/ed301-bench/Cargo.toml", "ed301-v2-core",
               ["crypto_bigint=on", "ed301_eddsa=on", "ed301_benchmark=on"])
v1provider = build(args.ed301_v1, "provider/Cargo.toml", "ed301-v1-provider",
                   ["crypto_bigint=on", "ed301_eddsa=on", "ed301_eddsa_v1=on"], provider=True)
x1provider = build(args.x301_v1, "provider/Cargo.toml", "x301-v1-provider",
                   ["crypto_bigint=off", "ed301_eddsa=on", "x301=on"],
                   exceptions="crypto_bigint=off", provider=True)
for source, name in ((v1provider / "libed301_eddsa_v1.so", "ed301_eddsa_v1.so"),
                     (x1provider / "libx301.so", "x301.so")):
    shutil.copyfile(source, work / "modules" / name)
for name in ("openssl_signature_bench", "x301_bench"):
    run(["/usr/bin/gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
         ROOT / "phase-c/benchmarks" / (name + ".c"), "-lcrypto", "-o", work / name], name + "-build")
run([work / "x301_bench", "--self-test"], "x301-bench-self-test")
identity["harness_equality"] = {
    "rust_v1_v2_identical": digest(args.ed301_v1 / "performance/ed301-bench/src/main.rs") ==
        digest(ROOT / "rust/performance/ed301-bench/src/main.rs"),
    "signature_verbatim": digest(args.ed301_v1 / "performance/openssl_signature_bench.c") ==
        digest(ROOT / "phase-c/benchmarks/openssl_signature_bench.c"),
    "xdh_verbatim": digest(args.x301_v1 / "performance/x301_bench.c") ==
        digest(ROOT / "phase-c/benchmarks/x301_bench.c"),
}
if not all(identity["harness_equality"].values()):
    raise SystemExit("FAIL: benchmark harness differs from bound source")
identity["binary_sha256"] = {str(p): digest(p) for p in (
    v1core / "ed301-benchmark", v2core / "ed301-benchmark", work / "openssl_signature_bench",
    work / "x301_bench", work / "modules/ed301_eddsa_v1.so", work / "modules/x301.so",
    Path("/usr/lib64/libcrypto.so.3").resolve(),
)}
for binary in (work / "openssl_signature_bench", work / "x301_bench",
               work / "modules/ed301_eddsa_v1.so", work / "modules/x301.so"):
    run(["/usr/bin/ldd", binary], binary.name + "-ldd")

cases = []
for operation in ("expand", "sign", "verify", "import"):
    for algorithm, binary in (("Ed301-EdDSA-v1", v1core), ("Ed301-EdDSA-v2", v2core)):
        cases.append(("Rust-core", algorithm, operation, [binary / "ed301-benchmark", operation]))
for operation in ("keygen", "sign", "verify"):
    for algorithm, props, modules, provider in (
        ("Ed25519", "provider=default", "-", "-"),
        ("Ed448", "provider=default", "-", "-"),
        ("Ed301-EdDSA-v1", "provider=ed301_eddsa_v1", work / "modules", "ed301_eddsa_v1"),
    ):
        cases.append(("EVP-signature", algorithm, operation,
                      [work / "openssl_signature_bench", operation, algorithm, props, modules, provider]))
for operation in ("keygen", "derive-setup", "derive-first", "derive-second", "derive-steady"):
    for algorithm, props, modules, size in (
        ("X25519", "provider=default", "-", 32), ("X448", "provider=default", "-", 56),
        ("X301", "provider=x301", work / "modules", 38),
    ):
        cases.append(("EVP-XDH", algorithm, operation,
                      [work / "x301_bench", operation, algorithm, props, modules, size]))


def measure(case, count, label):
    lane, algorithm, operation, command = case
    output = run(["/usr/bin/taskset", "-c", args.cpu, *command, count],
                 f"{label}-{lane}-{algorithm}-{operation}", announce=False)
    match = re.search(r"^RESULT .*mean_ns=([0-9.]+)$", output, re.MULTILINE)
    if not match or not math.isfinite(float(match[1])) or float(match[1]) <= 0:
        raise SystemExit("FAIL: benchmark result missing/invalid")
    return float(match[1])


print("STEP: single-CPU warmup and calibration", flush=True)
counts = []
for case in cases:
    mean = measure(case, 100, "warmup-calibration")
    counts.append(max(100, min(100000, math.ceil(args.target_ms * 1_000_000 / mean))))
rows = []
raw = work / "raw.tsv"
raw.write_text("repeat\tlane\talgorithm\toperation\tcount\tmean_ns\n")
for repeat in range(args.repetitions):
    print(f"STEP: measured rotation {repeat + 1}/{args.repetitions}", flush=True)
    # Alternate direction and rotate starting case: no consistently privileged first algorithm.
    order = list(range(len(cases)))
    if repeat % 2:
        order.reverse()
    shift = repeat % len(order)
    order = order[shift:] + order[:shift]
    for index in order:
        case = cases[index]
        mean = measure(case, counts[index], f"repeat-{repeat + 1}")
        row = [repeat + 1, *case[:3], counts[index], mean]
        rows.append(row)
        with raw.open("a") as out:
            out.write("\t".join(map(str, row)) + "\n")
summary = []
for lane, algorithm, operation, _ in cases:
    values = [r[5] for r in rows if r[1:4] == [lane, algorithm, operation]]
    summary.append({"lane": lane, "algorithm": algorithm, "operation": operation,
                    "repetitions": len(values), "median_ns": statistics.median(values),
                    "min_ns": min(values), "max_ns": max(values),
                    "mean_ns": statistics.mean(values), "stdev_ns": statistics.stdev(values)})
identity["load_after"] = Path("/proc/loadavg").read_text().strip()
(work / "IDENTITY.json").write_text(json.dumps(identity, indent=2) + "\n")
(work / "SUMMARY.json").write_text(json.dumps(summary, indent=2) + "\n")
current = "".join(f"{digest(p)}  {p.relative_to(ROOT)}\n" for p in source_files)
if current != source_manifest:
    raise SystemExit("FAIL: v2 source changed during benchmark")
for name, source in (("ed301-v1", args.ed301_v1), ("x301-v1", args.x301_v1)):
    if run(["/usr/bin/git", "-C", source, "status", "--porcelain", "--untracked-files=all"],
           name + "-final-status").strip():
        raise SystemExit("FAIL: baseline worktree changed")
receipt_files = sorted(p for p in work.rglob("*") if p.is_file()
                       and "target" not in p.relative_to(work).parts
                       and p.name != "SHA256SUMS")
(work / "SHA256SUMS").write_text("".join(f"{digest(p)}  {p.relative_to(work)}\n" for p in receipt_files))
for entry in summary:
    print(json.dumps(entry, sort_keys=True), flush=True)
print(f"PASS: available-stage benchmark; artifact_directory={work}", flush=True)
