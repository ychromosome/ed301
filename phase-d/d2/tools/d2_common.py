# SPDX-License-Identifier: Apache-2.0
"""Source-bound local D2 evidence helpers; no network or installation actions."""

import hashlib
import atexit
import errno
import json
import os
from pathlib import Path
import re
import subprocess
import shutil
import tempfile
import time

ROOT = Path(__file__).resolve().parents[3]
TOOLS = ROOT / "phase-d/d2/tools"
OPENSSL_EVIDENCE = {
    "3.5.8": "5ea7be983ee95241b893375de349ba4dc519509b79d623c5a7f74ae1641062bd",
    "4.0.2": "942095f98a6ec8ea5fdccfb7b74f845dc07b10c212791c2ea588c1fccbebfa9f",
}


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            value.update(block)
    return value.hexdigest()


def verify_source(expected):
    manifest = ROOT.parent / "SOURCE_SHA256SUMS"
    if not re.fullmatch("[0-9a-f]{64}", expected) or digest(manifest) != expected:
        raise SystemExit("D2 source manifest does not match the caller's digest")
    declared = set()
    for line in manifest.read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\\\r\n]+)", line)
        if match is None:
            raise SystemExit("malformed source manifest")
        checksum, name = match.groups()
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts or name in declared:
            raise SystemExit("unsafe or duplicate source manifest entry")
        declared.add(name)
        path = ROOT / relative
        if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o222:
            raise SystemExit(f"source is not a read-only regular file: {name}")
        if digest(path) != checksum:
            raise SystemExit(f"source hash mismatch: {name}")
    actual = set()
    for path in ROOT.rglob("*"):
        if path.is_symlink():
            raise SystemExit(f"source symlink: {path}")
        if path.is_file():
            actual.add(path.relative_to(ROOT).as_posix())
        elif not path.is_dir():
            raise SystemExit(f"special source file: {path}")
    if actual != declared:
        raise SystemExit("source inventory differs from its complete manifest")
    return len(declared)


def canonical_build_source(receipt):
    """Give Cargo a stable source location derived only from compiled inputs.

    Rust's Cargo metadata can depend on path-package identities even after
    filename remapping. Documentation-only receipt edits must not move the
    build tree. Every byte copied here is already in the full source seal.
    """
    # Provider unit tests include the immutable vector JSON at compile time.
    selected = sorted(path for directory in (ROOT / "rust", ROOT / "provider", ROOT / "vectors")
                      for path in directory.rglob("*") if path.is_file())
    selected.append(TOOLS / "rustc_profile_guard.sh")
    selected = sorted(selected)
    manifest = "".join(f"{digest(path)}  {path.relative_to(ROOT).as_posix()}\n" for path in selected)
    checksum = hashlib.sha256(manifest.encode()).hexdigest()
    destination = Path("/tmp") / ("ed301-v2-d2-build-" + checksum)
    if not destination.exists():
        temporary = Path(tempfile.mkdtemp(prefix="ed301-v2-d2-build-preparation-", dir="/tmp"))
        try:
            for source in selected:
                target = temporary / source.relative_to(ROOT)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
                target.chmod(0o555 if source.stat().st_mode & 0o111 else 0o444)
            for directory in sorted(temporary.rglob("*"), reverse=True):
                if directory.is_dir():
                    directory.chmod(0o555)
            temporary.chmod(0o555)
            try:
                temporary.rename(destination)
            except OSError as error:
                if error.errno not in (errno.EEXIST, errno.ENOTEMPTY):
                    raise
                # A concurrent ABI lane may have installed the same tree.
        finally:
            if temporary.exists():
                for directory in [temporary] + [p for p in temporary.rglob("*") if p.is_dir()]:
                    directory.chmod(0o755)
                shutil.rmtree(temporary)
    if destination.is_symlink() or destination.stat().st_uid != os.getuid():
        raise SystemExit("unsafe canonical build source root")
    actual = []
    for path in sorted(destination.rglob("*")):
        if path.is_symlink() or path.stat().st_mode & 0o222:
            raise SystemExit("canonical build source is not read-only and regular")
        if path.is_file():
            actual.append(f"{digest(path)}  {path.relative_to(destination).as_posix()}\n")
        elif not path.is_dir():
            raise SystemExit("special file in canonical build source")
    if "".join(actual) != manifest:
        raise SystemExit("canonical build source differs from the bound compiled-input set")
    (receipt.output / "BUILD_SOURCE_SHA256SUMS").write_text(manifest)
    receipt.identity.update(build_source_sha256=checksum, canonical_build_source=str(destination))
    receipt.write_identity()
    return destination


class Receipt:
    def __init__(self, output, source_sha, stage):
        self.source_sha = source_sha
        self.source_count = verify_source(source_sha)
        self.output = Path(output).absolute()
        if self.output.exists() or self.output.is_symlink() or ROOT in self.output.parents:
            raise SystemExit("result directory must be new and outside source")
        self.output.mkdir(mode=0o700)
        for name in ("home", "logs"):
            (self.output / name).mkdir(mode=0o700)
        self.clean = {"PATH": "/usr/bin:/bin", "HOME": str(self.output / "home"), "LC_ALL": "C"}
        self.commands = []
        self.sealed = False
        self.identity = {
            "format": "ed301-v2-d2-receipt-v1", "stage": stage,
            "source_manifest_sha256": source_sha, "source_file_count": self.source_count,
            "source_root": str(ROOT), "result_root": str(self.output),
            "status": "RUNNING", "system_installation": False,
        }
        self.write_identity()
        atexit.register(self.mark_unsealed_failure)
        print(f"artifact_directory={self.output}", flush=True)

    def mark_unsealed_failure(self):
        if not self.sealed and self.identity["status"] != "FAIL":
            self.identity.update(status="FAIL", error="runner ended before its evidence seal completed")
            self.write_identity()

    def write_identity(self):
        (self.output / "IDENTITY.json").write_text(json.dumps(self.identity, indent=2) + "\n")

    def run(self, name, command, env=None, timeout=1200, expected=0):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            raise ValueError("invalid step name")
        log = self.output / "logs" / (name + ".log")
        if log.exists():
            raise ValueError(f"duplicate step: {name}")
        command = list(map(str, command))
        environment = env or self.clean
        print(f"STEP {self.output.name}: {name}", flush=True)
        started = time.monotonic()
        timed_out = False
        with log.open("w") as stream:
            try:
                result = subprocess.run(command, cwd="/", env=environment, text=True,
                                        stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
                code = result.returncode
            except subprocess.TimeoutExpired:
                code = -1
                timed_out = True
        record = {"step": name, "command": command, "environment": environment,
                  "exit": code, "timeout": timed_out, "seconds": time.monotonic() - started,
                  "log_sha256": digest(log)}
        self.commands.append(record)
        (self.output / "commands.json").write_text(json.dumps(self.commands, indent=2) + "\n")
        if timed_out or (code != expected if expected is not None else code == 0 or code < 0):
            self.identity.update(status="FAIL", failed_step=name, exit=code, timeout=timed_out)
            self.write_identity()
            print(log.read_text()[-16000:], flush=True)
            raise SystemExit(f"FAIL: {name}; evidence retained in {self.output}")
        return log.read_text()

    def seal(self):
        verify_source(self.source_sha)
        self.identity["status"] = "PASS"
        self.write_identity()
        paths = sorted(path for path in self.output.rglob("*")
                       if path.is_file() and not path.is_symlink()
                       and "targets" not in path.relative_to(self.output).parts
                       and path.name != "SHA256SUMS")
        (self.output / "SHA256SUMS").write_text("".join(
            f"{digest(path)}  {path.relative_to(self.output).as_posix()}\n" for path in paths))
        self.sealed = True
        print(f"PASS: {self.identity['stage']} artifact_directory={self.output}", flush=True)


def verify_receipt(path):
    path = Path(path).resolve(strict=True)
    identity = json.loads((path / "IDENTITY.json").read_text())
    if identity.get("status") != "PASS":
        raise SystemExit("referenced receipt did not pass")
    for line in (path / "SHA256SUMS").read_text().splitlines():
        checksum, name = line.split("  ", 1)
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise SystemExit("unsafe receipt path")
        member = path / name
        if member.is_symlink() or not member.is_file() or digest(member) != checksum:
            raise SystemExit(f"receipt hash mismatch: {name}")
    return identity
