#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Copy tracked inputs plus the explicit additive D2 trees into a read-only snapshot."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[3]
ADDITIONS = ("docs", "phase-d/d2", "provider", "provider-tests")
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("output", type=Path)
args = parser.parse_args()
output = args.output.absolute()
if output.exists() or output.is_symlink() or ROOT in output.parents:
    parser.error("output must be new and outside the checkout")
branch = subprocess.check_output(["git", "branch", "--show-current"], cwd=ROOT, text=True).strip()
if branch != "Testing":
    raise SystemExit("D2 source preparation requires Testing")
tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
files = {Path(name) for name in tracked if name}
for directory in ADDITIONS:
    for path in (ROOT / directory).rglob("*"):
        if path.is_dir() and not path.is_symlink():
            continue
        relative = path.relative_to(ROOT)
        if any(part in {"__pycache__", "target", ".git"} for part in relative.parts):
            raise SystemExit(f"unexpected generated path in additive source tree: {relative}")
        files.add(relative)
manifest = []
for relative in sorted(files):
    source = ROOT / relative
    if source.is_symlink() or not source.is_file():
        raise SystemExit(f"source is not a regular file: {relative}")
    if any(ord(char) < 32 or char == "\\" for char in str(relative)):
        raise SystemExit(f"unsupported manifest path: {relative}")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    manifest.append(f"{digest}  {relative.as_posix()}\n")
content = "".join(manifest)
output.mkdir(mode=0o700, parents=False)
snapshot = output / "source"
snapshot.mkdir(mode=0o700)
for relative in sorted(files):
    source = ROOT / relative
    destination = snapshot / relative
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(0o555 if source.stat().st_mode & stat.S_IXUSR else 0o444)
copied = "".join(f"{hashlib.sha256((snapshot / path).read_bytes()).hexdigest()}  {path.as_posix()}\n"
                 for path in sorted(files))
if copied != content:
    raise SystemExit("source changed while copying; incomplete snapshot retained")
for path in sorted(snapshot.rglob("*"), reverse=True):
    if path.is_dir():
        path.chmod(0o555)
snapshot.chmod(0o555)
(output / "SOURCE_SHA256SUMS").write_text(content)
identity = {
    "format": "ed301-v2-d2-source-v1", "branch": branch,
    "base_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
    "source_manifest_sha256": hashlib.sha256(content.encode()).hexdigest(),
    "file_count": len(files), "additive_directories": ADDITIONS,
    "unrelated_untracked_files_included": False,
    "source_root": str(snapshot),
}
(output / "SOURCE_IDENTITY.json").write_text(json.dumps(identity, indent=2) + "\n")
print(json.dumps(identity, indent=2), flush=True)
