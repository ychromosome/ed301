#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Assemble a commit-exact, source-complete Gate-C candidate; do not approve it."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--commit", required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
out = args.output.resolve()
if out.exists() or out.with_suffix(".tar.gz").exists():
    parser.error("output and archive must be fresh")
out.mkdir(parents=True)
commands = []


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, binary=False):
    command = list(map(str, command))
    result = subprocess.run(command, cwd="/", stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    commands.append({"command": command, "exit": result.returncode,
                     "stderr": result.stderr.decode(errors="replace")})
    if result.returncode:
        raise RuntimeError(f"command failed: {command}: {result.stderr.decode(errors='replace')}")
    return result.stdout if binary else result.stdout.decode()


def copy(path, destination, expected=None):
    if not path.is_file() or path.is_symlink():
        raise RuntimeError(f"expected regular input file: {path}")
    value = sha(path)
    if expected is not None and value != expected:
        raise RuntimeError(f"changed input: {path}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if sha(destination) != value:
            raise RuntimeError(f"conflicting destination: {destination}")
    else:
        shutil.copy2(path, destination)
    if sha(destination) != value or sha(path) != value:
        raise RuntimeError(f"copy verification failed: {path}")
    return str(destination.relative_to(out))


commit = run(["git", "-C", ROOT, "rev-parse", args.commit + "^{commit}"]).strip()
if commit != run(["git", "-C", ROOT, "rev-parse", "HEAD"]).strip():
    raise RuntimeError("bundle must bind the selected current commit")
run(["git", "-C", ROOT, "diff", "--exit-code", commit, "--", "rust", "phase-c"])
raw_index = run(["git", "-C", ROOT, "show", commit + ":phase-c/EVIDENCE_INDEX.json"], binary=True)
index = json.loads(raw_index)
if hashlib.sha256(raw_index).hexdigest() != sha(ROOT / "phase-c/EVIDENCE_INDEX.json"):
    raise RuntimeError("working evidence index differs from selected commit")
binding = {"schema": "ed301-gate-c-bundle-v1", "status": "NOT_APPROVED",
           "source_commit": commit, "snapshots": [], "supplements": [],
           "path_map": {}, "evidence_index": "source/ed301/phase-c/EVIDENCE_INDEX.json"}


def snapshot(identifier, source, revision):
    if run(["git", "-C", source, "rev-parse", "HEAD"]).strip() != revision:
        raise RuntimeError(f"baseline HEAD moved: {identifier}")
    if identifier != "ed301" and run(["git", "-C", source, "status", "--porcelain", "--untracked-files=all"]).strip():
        raise RuntimeError(f"dirty baseline: {identifier}")
    target = out / "source" / identifier
    target.mkdir(parents=True)
    archive = run(["git", "-C", source, "archive", "--format=tar", revision], binary=True)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        tar.extractall(target, filter="data")
    bundle = out / "git" / (identifier + ".bundle")
    bundle.parent.mkdir(exist_ok=True)
    run(["git", "-C", source, "bundle", "create", bundle, "HEAD"])
    run(["git", "-C", source, "bundle", "verify", bundle])
    binding["snapshots"].append({"id": identifier, "commit": revision,
                                  "directory": str(target.relative_to(out)),
                                  "git_bundle": str(bundle.relative_to(out)),
                                  "git_bundle_sha256": sha(bundle)})
    binding["path_map"][str(source)] = str(target.relative_to(out))
    print(f"SNAPSHOT: {identifier} {revision}", flush=True)


snapshot("ed301", ROOT, commit)
for baseline in index["baselines"]:
    snapshot(baseline["id"], Path(baseline["path"]), baseline["commit"])

for item in index["artifacts"]:
    original = Path(item["original_directory"])
    target = out / "evidence" / item["id"]
    receipt = original / "SHA256SUMS"
    copy(receipt, target / "SHA256SUMS", item["receipt"]["sha256"])
    binding["path_map"][str(original)] = str(target.relative_to(out))
    for line in receipt.read_text().splitlines():
        expected, name = line.split("  ", 1)
        source = original / name
        if ".." in Path(name).parts:
            raise RuntimeError("receipt traversal")
        if Path(name).is_absolute() and not source.is_relative_to(original):
            destination = target / "external-receipt-files" / (expected + "-" + source.name)
        else:
            destination = target / source.relative_to(original)
        relative = copy(source, destination, expected)
        binding["path_map"][str(source)] = relative
    for record in item.get("additional_files", []):
        source = Path(record["original_path"])
        relative = copy(source, target / source.relative_to(original), record["sha256"])
        binding["path_map"][str(source)] = relative
    for record in item["binaries"]:
        source = Path(record["original_path"])
        mapped = binding["path_map"].get(str(source))
        destination = out / mapped if mapped else target / "observed-binaries" / (record["sha256"][:12] + "-" + source.name)
        relative = copy(source, destination, record["sha256"])
        binding["path_map"][str(source)] = relative
    print(f"EVIDENCE: {item['id']}", flush=True)

# Original legacy tree and all three parent inputs, at their unchanged relative paths.
legacy = Path(index["legacy_curve"]["directory"])
legacy_target = out / "provenance/curve-source/ed301_technischer_abschluss"
copy(legacy / "SHA256SUMS", legacy_target / "SHA256SUMS", index["legacy_curve"]["receipt"]["sha256"])
for line in (legacy / "SHA256SUMS").read_text().splitlines():
    expected, name = line.split("  ", 1)
    if Path(name).is_absolute() or ".." in Path(name).parts:
        raise RuntimeError("legacy manifest traversal")
    copy(legacy / name, legacy_target / name, expected)
binding["path_map"][str(legacy)] = str(legacy_target.relative_to(out))
for record in index["legacy_parents"]:
    source = Path(record["original_path"])
    destination = legacy_target.parent / source.name
    binding["path_map"][str(source)] = copy(source, destination, record["sha256"])
    # These six links are explicitly not tracked baseline content. They repair
    # the old repositories' absent parent references without changing any blob.
    for identifier in ("ed301-v1", "x301-v1"):
        link = out / "source" / identifier / "evidence/curve-provenance/archive" / source.name
        if link.exists() or link.is_symlink():
            raise RuntimeError("unexpected pre-existing provenance supplement")
        link.symlink_to(os.path.relpath(destination, link.parent))
        binding["supplements"].append({"path": str(link.relative_to(out)),
                                        "target": os.readlink(link), "sha256": record["sha256"]})

standards = Path(index["standards"]["directory"])
copy(standards / "SHA256SUMS", out / "standards/SHA256SUMS", index["standards"]["receipt"]["sha256"])
for line in (standards / "SHA256SUMS").read_text().splitlines():
    expected, name = line.split("  ", 1)
    if Path(name).is_absolute() or ".." in Path(name).parts:
        raise RuntimeError("standards manifest traversal")
    copy(standards / name, out / "standards" / name, expected)
binding["path_map"][str(standards)] = "standards"
for collection in ("approvals", "context_inputs"):
    for record in index[collection]:
        source = Path(record["original_path"])
        binding["path_map"][str(source)] = copy(source, out / "provenance" / collection / source.name, record["sha256"])
copy(ROOT / "phase-c/tools/verify_gate_c_bundle.py", out / "VERIFY.py")
copy(ROOT / "phase-c/tools/replay_gate_c_bundle.py", out / "REPLAY.py")
(out / "BINDING.json").write_text(json.dumps(binding, indent=2) + "\n")
(out / "BUILD_COMMANDS.json").write_text(json.dumps(commands, indent=2) + "\n")
(out / "README.md").write_text(
    "# Ed301-v2 Gate-C-Prüfpaket\n\n"
    f"Testing-Commit: {commit}. Keine Gate-C- oder Produktionsfreigabe.\n\n"
    "Einstieg: [vollständiger Bericht](source/ed301/phase-c/GATE_C_REPORT_2026-09-10.md), "
    "[Quellen-/Belegindex](source/ed301/phase-c/EVIDENCE_INDEX.json), "
    "[portable Pfad- und Commitbindung](BINDING.json).\n\n"
    "Aus diesem entpackten Verzeichnis: `python3 -I -B VERIFY.py` prüft sämtliche "
    "Dateihashes, Git-Snapshots, historischen Quellbytes und Parent-Pfade. "
    "`python3 -I -B REPLAY.py` führt die Kernprüfungen, drei Gates und alle "
    "Benchmarkrunner aus einer frischen Arbeitskopie aus; Ergebnisse entstehen "
    "außerhalb dieses unveränderten Pakets. Systemwerkzeuge müssen installiert sein.\n\n"
    "Die beiden vollständigen v1-Snapshots enthalten exakt die commitgebundenen "
    "Dateien plus sechs in BINDING.json einzeln bezeichnete Provenienz-Symlinks. "
    "Die Symlinks ergänzen fehlende historische Parent-Inputs; kein getrackter "
    "Blob wurde verändert. Die ebenfalls enthaltenen Git-Bundles sind unverändert.\n\n"
    "Absolute Pfade in historischen Belegen identifizieren den ursprünglichen "
    "Messort. BINDING.json löst sie auf Paketdateien auf. Die vollständigen "
    "historischen Quellmanifeste werden gegen aktuelle Bytes oder die exakt "
    "hashgleichen Archivblobs geprüft. Standards/Errata sind unveränderte "
    "Primärquellen-Snapshots, keine Neulizenzierung oder Normkonformitätsbehauptung.\n")
files = sorted(p for p in out.rglob("*") if p.is_file() and p != out / "SHA256SUMS")
(out / "SHA256SUMS").write_text("".join(f"{sha(p)}  {p.relative_to(out)}\n" for p in files))
archive_path = out.with_suffix(".tar.gz")


def normalized(info):
    info.uid = info.gid = info.mtime = 0
    info.uname = info.gname = ""
    return info


with archive_path.open("wb") as raw:
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode="w") as tar:
            tar.add(out, arcname="ED301-v2_GATE_C", recursive=True, filter=normalized)
print(json.dumps({"status": "ASSEMBLED_NOT_YET_REPLAYED", "commit": commit,
                  "directory": str(out), "archive": str(archive_path),
                  "archive_sha256": sha(archive_path), "manifest_sha256": sha(out / "SHA256SUMS")}))
