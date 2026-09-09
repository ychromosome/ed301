#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Full offline Gate-C replay in a fresh copy; never modifies the packaged source."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--bundle", type=Path, default=Path(__file__).resolve().parent)
parser.add_argument("--work", type=Path)
args = parser.parse_args()
ROOT = args.bundle.resolve()
work = args.work.resolve() if args.work else Path(tempfile.mkdtemp(prefix="ED301-v2_gate-c-replay_", dir=ROOT.parent))
if args.work:
    work.mkdir(parents=True, exist_ok=False)
for part in ("home", "logs"):
    (work / part).mkdir()
clean = {"PATH": "/usr/bin:/bin", "HOME": str(work / "home"), "LC_ALL": "C",
         "OPENSSL_CONF": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}
commands = []
artifacts = {}
print(f"replay_directory={work}", flush=True)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, name, env=None):
    command = list(map(str, command))
    print(f"STEP: {name}", flush=True)
    record = {"command": command, "name": name, "environment": env or clean,
              "started_unix": time.time(), "status": "RUNNING"}
    commands.append(record)
    (work / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
    result = subprocess.run(command, cwd="/", env=env or clean, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log = work / "logs" / f"{len(commands):02d}-{name}.log"
    log.write_text(result.stdout)
    record.update(status="PASS" if result.returncode == 0 else "FAIL", exit=result.returncode,
                  elapsed_seconds=time.time() - record["started_unix"], log=str(log.relative_to(work)))
    (work / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
    if result.returncode:
        print(result.stdout, end="", flush=True)
        raise SystemExit(f"FAIL: {name}; evidence retained at {work}")
    print(f"PASS: {name}", flush=True)
    return result.stdout


run(["python3", "-I", "-B", ROOT / "VERIFY.py"], "package-and-provenance")
binding = json.loads((ROOT / "BINDING.json").read_text())
source = work / "ed301"
shutil.copytree(ROOT / "source/ed301", source, symlinks=True)
for snapshot in binding["snapshots"][1:]:
    destination = work / ("ed301-eddsa-github" if snapshot["id"] == "ed301-v1" else "x301-integration")
    run(["git", "-c", "protocol.allow=never", "-c", "protocol.file.allow=always", "clone",
         "--quiet", "--no-checkout", ROOT / snapshot["git_bundle"], destination], snapshot["id"] + "-clone")
    run(["git", "-C", destination, "checkout", "--quiet", "--detach", snapshot["commit"]],
        snapshot["id"] + "-checkout")
run(["rustfmt", "--edition", "2024", "--check", source / "phase-c/benchmarks/core_micro.rs",
     source / "phase-c/benchmarks/core_resources.rs"], "new-harness-format")


def execute(script, identifier):
    output = run(["python3", "-I", "-B", source / "phase-c/tools" / script], identifier)
    paths = re.findall(r"artifact_directory=([^\s;]+)", output)
    if not paths:
        raise RuntimeError("runner did not report an artifact directory")
    directory = Path(paths[0]).resolve()
    if not directory.is_relative_to(work) or not directory.is_dir():
        raise RuntimeError("runner wrote outside replay workspace")
    artifacts[identifier] = str(directory)
    return directory


execute("check_core_correctness.py", "correctness")
primary = execute("run_available_benchmarks.py", "available-benchmarks")
execute("run_core_matrix.py", "core-matrix")
execute("run_core_microbenchmarks.py", "microbenchmarks")
execute("run_core_resources.py", "resources")
execute("run_core_taint.py", "taint")
execute("run_core_timing.py", "timing")
fresh_codegen = work / "fresh-codegen"
run(["sh", source / "phase-c/tools/check_core_codegen.sh",
     primary / "ed301-v2-core/target/release/ed301-benchmark",
     primary / "ed301-v2-core/markers/toolchain.txt", fresh_codegen], "fresh-binary-codegen")
artifacts["fresh-codegen"] = str(fresh_codegen)

# Recheck the exact original ELF too, not merely a fresh binary with new paths.
index = json.loads((source / "phase-c/EVIDENCE_INDEX.json").read_text())
codegen = next(x for x in index["artifacts"] if x["id"] == "codegen")
original_name = codegen["binaries"][0]["original_path"]
original_binary = ROOT / binding["path_map"][original_name]
compiler_name = str(Path(original_name).parents[2] / "markers/toolchain.txt")
original_marker = ROOT / binding["path_map"][compiler_name]
observed_codegen = work / "observed-codegen"
run(["sh", source / "phase-c/tools/check_core_codegen.sh", original_binary,
     original_marker, observed_codegen], "original-observed-binary-codegen")
artifacts["observed-codegen"] = str(observed_codegen)

report = ["# Vollständiger Gate-C-Replay", "",
          f"Commit: {binding['source_commit']}. Keine Gate-C-Freigabe.", "",
          "Neue Arbeitskopie aus dem geprüften Paket; alle Messrunner mit ihren vollständigen",
          "Default-Wiederholungen. Diese zusätzlichen Messungen ersetzen nicht die ursprünglichen",
          "Tabellen. Werkzeug-/Last-/Binärunterschiede stehen in den jeweiligen Belegen.", ""]
for identifier in ("available-benchmarks", "core-matrix", "microbenchmarks"):
    rows = json.loads((Path(artifacts[identifier]) / "SUMMARY.json").read_text())
    keys = [k for k in ("lane", "algorithm", "version", "operation", "message_bytes", "context_bytes")
            if any(k in row for row in rows)]
    report += [f"## {identifier}", "", "Alle Zeitwerte in ns; Median, Stichproben-SD und Spannweite der Laufmittel.", "",
               "| " + " | ".join(keys + ["Median ns", "SD ns", "Min ns", "Max ns"]) + " |",
               "| " + " | ".join(["---"] * (len(keys) + 4)) + " |"]
    for row in rows:
        report.append("| " + " | ".join([str(row.get(k, "")) for k in keys] +
                      [f"{row[k]:.3f}" for k in ("median_ns", "stdev_ns", "min_ns", "max_ns")]) + " |")
    report.append("")
report += ["## Ressourcen", "", "Vollständige Prozessspitzen einschließlich Harness; keine Worst-Case-Grenzen.", "",
           "| Version | Operation | Nachricht | Context | Stack Median B | Stack Min–Max B | RSS Median KiB | RSS SD KiB | RSS Min–Max KiB |",
           "|---|---|---:|---:|---:|---:|---:|---:|---:|"]
for row in json.loads((Path(artifacts["resources"]) / "SUMMARY.json").read_text()):
    stack, rss = row["stack_B"], row["rss_KiB"]
    report.append(f"| {row['version']} | {row['operation']} | {row['message_bytes']} | {row['context_bytes']} | "
                  f"{stack['median']} | {stack['min']}–{stack['max']} | {rss['median']} | {rss['stdev']:.3f} | {rss['min']}–{rss['max']} |")
report += ["", "## Timing-Replay", "", "```text",
           (Path(artifacts["timing"]) / "SUMMARY.txt").read_text().strip(), "```", ""]
(work / "REPLAY_REPORT.md").write_text("\n".join(report))
# A PASS receipt is written only after the last immutable-input check succeeds.
run(["python3", "-I", "-B", ROOT / "VERIFY.py"], "unchanged-input-package")
result = {"status": "PASS", "source_commit": binding["source_commit"],
          "input_package_manifest_sha256": sha(ROOT / "SHA256SUMS"),
          "steps": len(commands), "replay_directory": str(work), "artifacts": artifacts,
          "gate_c_approval": False}
(work / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
files = [work / name for name in ("commands.json", "REPLAY_REPORT.md", "RESULT.json")]
files += sorted((work / "logs").glob("*.log"))
(work / "SHA256SUMS").write_text("".join(f"{sha(p)}  {p.relative_to(work)}\n" for p in files))
print(json.dumps(result, sort_keys=True), flush=True)
