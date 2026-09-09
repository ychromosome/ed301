#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify a Gate-C package without relying on the author's original paths/network."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--bundle", type=Path, default=Path(__file__).resolve().parent)
args = parser.parse_args()
ROOT = args.bundle.resolve()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inside(path):
    actual = path.resolve(strict=True)
    if not actual.is_relative_to(ROOT):
        raise RuntimeError(f"path escapes package: {path}")
    return path


def safe_relative(name):
    if Path(name).is_absolute() or ".." in Path(name).parts:
        raise RuntimeError(f"unsafe relative path: {name}")
    return name


def verify_file(path, expected):
    inside(path)
    if not path.is_file() or sha(path) != expected:
        raise RuntimeError(f"missing/changed package file: {path}")


def entries(path):
    rows = []
    for line in path.read_text().splitlines():
        digest, name = line.split("  ", 1)
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise RuntimeError("malformed SHA-256 manifest")
        rows.append((digest, name))
    if len({name for _, name in rows}) != len(rows):
        raise RuntimeError("duplicate manifest path")
    return rows


global_rows = entries(ROOT / "SHA256SUMS")
for digest, name in global_rows:
    verify_file(ROOT / safe_relative(name), digest)
actual_files = {str(p.relative_to(ROOT)) for p in ROOT.rglob("*")
                if p.is_file() and p != ROOT / "SHA256SUMS"}
if actual_files != {name for _, name in global_rows}:
    raise RuntimeError("global package file set differs from manifest")
binding = json.loads((ROOT / "BINDING.json").read_text())
index = json.loads((ROOT / binding["evidence_index"]).read_text())


def mapped(original):
    for prefix in sorted(binding["path_map"], key=len, reverse=True):
        if original == prefix or original.startswith(prefix + "/"):
            relative = binding["path_map"][prefix] + original[len(prefix):]
            return inside(ROOT / safe_relative(relative))
    raise RuntimeError(f"unresolved provenance path: {original}")


for supplement in binding["supplements"]:
    path = ROOT / safe_relative(supplement["path"])
    if not path.is_symlink() or os.readlink(path) != supplement["target"]:
        raise RuntimeError("changed provenance supplement")
    verify_file(path, supplement["sha256"])


def git(command):
    result = subprocess.run(list(map(str, command)), cwd="/", stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C",
                                                         "HOME": str(git_work)})
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors="replace"))
    return result.stdout


snapshots = []
with tempfile.TemporaryDirectory(prefix="ed301-gate-c-git-verify-") as work:
    git_work = Path(work)
    for snapshot in binding["snapshots"]:
        bundle = ROOT / safe_relative(snapshot["git_bundle"])
        verify_file(bundle, snapshot["git_bundle_sha256"])
        repository = git_work / (snapshot["id"] + ".git")
        git(["git", "init", "--quiet", "--bare", repository])
        git(["git", "-C", repository, "-c", "protocol.allow=never", "-c", "protocol.file.allow=always",
             "fetch", "--quiet", "--no-tags", bundle, "HEAD:refs/heads/snapshot"])
        commit = git(["git", "-C", repository, "rev-parse", "refs/heads/snapshot"]).decode().strip()
        if commit != snapshot["commit"]:
            raise RuntimeError("Git bundle selected commit mismatch")
        tree = git(["git", "-C", repository, "ls-tree", "-r", "-z", commit])
        source = ROOT / safe_relative(snapshot["directory"])
        tracked = set()
        for row in tree.split(b"\0"):
            if not row:
                continue
            metadata, name = row.split(b"\t", 1)
            mode, kind, oid = metadata.split()
            name = name.decode()
            path = inside(source / safe_relative(name))
            tracked.add(name)
            if kind != b"blob":
                raise RuntimeError("unexpanded submodule in supposedly complete source snapshot")
            if mode == b"120000":
                if not path.is_symlink():
                    raise RuntimeError("Git symlink changed type")
                data = os.readlink(path).encode()
            elif mode in (b"100644", b"100755"):
                if path.is_symlink() or not path.is_file():
                    raise RuntimeError("Git regular file changed type")
                if bool(path.stat().st_mode & 0o111) != (mode == b"100755"):
                    raise RuntimeError("Git executable mode mismatch")
                data = path.read_bytes()
            else:
                raise RuntimeError(f"unsupported Git mode: {mode}")
            actual = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
            if actual != oid.decode():
                raise RuntimeError(f"source differs from Git commit: {path}")
        additions = {str((ROOT / s["path"]).relative_to(source)) for s in binding["supplements"]
                     if (ROOT / s["path"]).is_relative_to(source)}
        files = {str(p.relative_to(source)) for p in source.rglob("*") if p.is_file() or p.is_symlink()}
        if files != tracked | additions:
            raise RuntimeError(f"incomplete/extra source snapshot: {snapshot['id']}")
        snapshots.append({"id": snapshot["id"], "commit": commit, "tracked_files": len(tracked),
                          "explicit_provenance_supplements": len(additions)})
if snapshots[0]["commit"] != binding["source_commit"]:
    raise RuntimeError("top-level source commit mismatch")

source_root = ROOT / "source/ed301"
source_total = 0
for artifact in index["artifacts"]:
    directory = ROOT / "evidence" / artifact["id"]
    verify_file(directory / "SHA256SUMS", artifact["receipt"]["sha256"])
    for digest, name in entries(directory / "SHA256SUMS"):
        path = mapped(name) if Path(name).is_absolute() else directory / safe_relative(name)
        verify_file(path, digest)
    for record in artifact["binaries"] + artifact.get("additional_files", []):
        verify_file(mapped(record["original_path"]), record["sha256"])
    if artifact["source_manifest"]:
        rows = entries(directory / artifact["source_manifest"])
        overrides = {x["source_path"]: x for x in artifact["source_overrides"]}
        for digest, name in rows:
            safe_relative(name)
            if name in overrides:
                selected = overrides[name]
                if selected["sha256"] != digest or name.startswith("rust/crates/ed301-eddsa/"):
                    raise RuntimeError("inconsistent historical override or changed product core")
                path = source_root / safe_relative(selected["available_at"])
            else:
                path = source_root / name
            verify_file(path, digest)
        if len(rows) != artifact["source_file_count"]:
            raise RuntimeError("historical source count mismatch")
        source_total += len(rows)
for record in index["legacy_parents"] + index["approvals"] + index["context_inputs"]:
    verify_file(mapped(record["original_path"]), record["sha256"])
legacy = ROOT / "provenance/curve-source/ed301_technischer_abschluss"
for manifest in ("SHA256SUMS", "SOURCE_SHA256SUMS"):
    for digest, name in entries(legacy / manifest):
        verify_file(legacy / name, digest)
for snapshot in binding["snapshots"][1:]:
    old = ROOT / snapshot["directory"] / "evidence/curve-provenance/archive/ed301_technischer_abschluss"
    for digest, name in entries(old / "SOURCE_SHA256SUMS"):
        verify_file(old / name, digest)
verify_file(ROOT / "standards/SHA256SUMS", index["standards"]["receipt"]["sha256"])
for digest, name in entries(ROOT / "standards/SHA256SUMS"):
    verify_file(ROOT / "standards" / safe_relative(name), digest)
print(json.dumps({"status": "PASS", "source_commit": binding["source_commit"],
                  "package_files": len(global_rows), "snapshots": snapshots,
                  "historical_source_entries_checked": source_total,
                  "parent_source_paths": "complete and checked in legacy and both baseline layouts",
                  "gate_c_approval": False}, indent=2))
