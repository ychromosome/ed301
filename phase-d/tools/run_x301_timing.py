#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fresh core-only dudect build and fixed-versus-random synthetic-seed test."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
RUST = ROOT / "rust"
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--cpu", type=int, default=2)
parser.add_argument("--measurements", type=int, default=200000)
args = parser.parse_args()
if args.cpu not in os.sched_getaffinity(0) or not 200000 <= args.measurements <= 10000000:
    parser.error("invalid CPU affinity or measurement count")
work = Path(tempfile.mkdtemp(prefix="X301-v2_D1-timing_", dir=ROOT.parent))
for name in ("home", "cargo-home", "target", "markers", "logs"):
    (work / name).mkdir(mode=0o700)
clean = {"PATH": "/usr/bin:/bin", "HOME": str(work / "home"), "LC_ALL": "C"}
commands = []
print(f"artifact_directory={work}", flush=True)


def run(command, name, env=None):
    command = list(map(str, command))
    print(f"STEP: {name}", flush=True)
    result = subprocess.run(command, cwd="/", env=env or clean, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (work / "logs" / (name + ".log")).write_text(result.stdout)
    commands.append({"command": command, "environment": env or clean,
                     "step": name, "exit": result.returncode})
    (work / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
    if result.returncode:
        print(result.stdout, end="", flush=True)
        raise SystemExit(f"FAIL: {name}; artifacts retained in {work}")
    return result.stdout


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


header = ROOT / "phase-c/timing/third_party/dudect/dudect.h"
if digest(header) != "6dcf713c9e43ac1d736e21e84af738013fb2a4b05b66931dddc971bb43e899f5":
    raise SystemExit("FAIL: dudect dependency hash")
sources = sorted(p for base in (RUST, ROOT / "phase-d/timing") for p in base.rglob("*") if p.is_file())
source_manifest = "".join(f"{digest(p)}  {p.relative_to(ROOT)}\n" for p in sources)
(work / "SOURCE_SHA256SUMS").write_text(source_manifest)
run(["/usr/bin/python3", "-I", "-B", RUST / "scripts/write-cargo-config.py",
     work / "cargo-home/config.toml", RUST / "vendor"], "cargo-config")
toolchain = run(["/usr/bin/rustc", "--version", "--verbose"], "toolchain")
(work / "markers/toolchain.txt").write_text(toolchain)
build = dict(clean, CARGO_HOME=str(work / "cargo-home"), CARGO_TARGET_DIR=str(work / "target"),
             CARGO_NET_OFFLINE="true", CARGO_INCREMENTAL="0", CCACHE_DISABLE="1",
             ED301_PROFILE_MARKER_DIR=str(work / "markers"),
             RUSTC_WRAPPER=str(RUST / "scripts/rustc-profile-guard.sh"))
run(["/usr/bin/cargo", "build", "--manifest-path", ROOT / "phase-d/timing/Cargo.toml",
     "--locked", "--offline", "--release"], "build-adapter", build)
run(["/bin/sh", RUST / "scripts/check-profile-markers.sh", work / "markers",
     "crypto_bigint=on", "x301_core=on", "x301_core_timing_adapter=on"], "profile")
adapter = work / "libx301_core_timing_adapter.so"
shutil.copyfile(work / "target/release" / adapter.name, adapter)
binary = work / "x301_timing"
run(["/usr/bin/gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
     ROOT / "phase-d/timing/x301_timing.c", "-L" + str(work), "-Wl,-rpath," + str(work),
     "-lx301_core_timing_adapter", "-lm", "-o", binary], "build-harness")
run(["/usr/bin/ldd", binary], "harness-ldd")
run(["/usr/bin/valgrind", "--tool=memcheck", "--vgdb=no", "--error-exitcode=99",
     "--leak-check=full", "--errors-for-leak-kinds=definite,indirect,possible", "--quiet",
     binary, "--self-test"], "adapter-memory-self-test")
identity = {"scope": "X301 public/shared raw API; fixed/random synthetic seeds; fixed canonical base-u peer",
            "cpu": args.cpu, "requested_measurements": args.measurements,
            "source_manifest_sha256": digest(work / "SOURCE_SHA256SUMS"),
            "adapter_sha256": digest(adapter), "harness_sha256": digest(binary),
            "dudect_sha256": digest(header), "runner_sha256": digest(Path(__file__)),
            "toolchain": toolchain, "load_before": Path("/proc/loadavg").read_text().strip(),
            "threshold_abs_t": 10, "positive_control_required": True,
            "leakage_state_is_sticky_across_batches": True}
(work / "IDENTITY.json").write_text(json.dumps(identity, indent=2) + "\n")
output = run(["/usr/bin/taskset", "-c", args.cpu, binary, args.measurements], "dudect")
summary = "\n".join(line for line in output.splitlines()
                    if line.startswith(("X301_TIMING", "x301_timing"))) + "\n"
print(summary, end="", flush=True)
(work / "SUMMARY.txt").write_text(summary)
identity["load_after"] = Path("/proc/loadavg").read_text().strip()
(work / "IDENTITY.json").write_text(json.dumps(identity, indent=2) + "\n")
if source_manifest != "".join(f"{digest(p)}  {p.relative_to(ROOT)}\n" for p in sources):
    raise SystemExit("FAIL: source changed during timing test")
receipt_files = sorted(p for p in work.rglob("*") if p.is_file()
                       and "target" not in p.relative_to(work).parts and p.name != "SHA256SUMS")
(work / "SHA256SUMS").write_text("".join(f"{digest(p)}  {p.relative_to(work)}\n" for p in receipt_files))
print(f"PASS: X301 core-only timing observation; artifact_directory={work}", flush=True)
