#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify a sealed D2 bundle; optionally replay selected bound native test binaries."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify(bundle, checksum):
    seal = bundle / "BUNDLE_MANIFEST.json"
    if digest(seal) != checksum:
        raise SystemExit("bundle manifest digest mismatch")
    manifest = json.loads(seal.read_text())
    actual = {p.relative_to(bundle).as_posix() for p in bundle.rglob("*")}
    if actual != set(manifest) | {"BUNDLE_MANIFEST.json"}:
        raise SystemExit("bundle inventory mismatch")
    for name, record in manifest.items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise SystemExit("unsafe manifest path")
        path = bundle / relative
        if record["type"] == "symlink":
            link = record["target"]
            if (not path.is_symlink() or os.readlink(path) != link
                    or Path(link).is_absolute() or ".." in Path(link).parts
                    or not path.resolve().is_relative_to(bundle)):
                raise SystemExit("symlink inventory mismatch")
        else:
            if path.is_symlink() or path.stat().st_mode & 0o777 != record["mode"]:
                raise SystemExit("type/mode mismatch: " + name)
            if record["type"] == "directory":
                if not path.is_dir():
                    raise SystemExit("missing directory")
            elif record["type"] != "file" or not path.is_file() or digest(path) != record["sha256"]:
                raise SystemExit("file hash mismatch: " + name)
    index = json.loads((bundle / "reports/D2_EVIDENCE_INDEX.json").read_text())
    omissions = json.loads((bundle / "OMITTED_CONTROL_FIXTURES.json").read_text())
    expected_stages = {stage + "-" + version for stage in
                       ("functional", "cli", "tcp", "memory", "controls", "codegen",
                        "legacy_builds", "structured", "timing", "benchmarks")
                       for version in ("3.5.8", "4.0.2")}
    if set(index["stages"]) != expected_stages:
        raise SystemExit("incomplete stage inventory")
    evidence = bundle / "evidence"
    if digest(evidence / "SOURCE_SHA256SUMS") != index["source_manifest_sha256"]:
        raise SystemExit("source seal mismatch")
    for stage, record in index["stages"].items():
        path = evidence / stage
        if digest(path / "SHA256SUMS") != record["manifest_sha256"]:
            raise SystemExit("stage seal mismatch")
        if json.loads((path / "IDENTITY.json").read_text()) != record["identity"]:
            raise SystemExit("stage identity mismatch")
        if record["identity"]["status"] != "PASS":
            raise SystemExit("stage did not pass")
        for line in (path / "SHA256SUMS").read_text().splitlines():
            checksum, name = line.split("  ", 1)
            relative = Path(name)
            if relative.is_absolute() or ".." in relative.parts or relative.as_posix() != name:
                raise SystemExit("unsafe receipt member path")
            omitted = omissions.get(stage + "/" + name)
            if omitted is not None:
                if (not stage.startswith("controls-") or Path(name).parts[0] not in {
                        "wrong-digest", "tar-bytes", "prefix-extra", "prefix-missing", "prefix-link",
                        "native-evp-bytes", "empty-seal", "duplicate-seal-member", "mixed-origin", "member-bytes"}
                        or omitted != {"type": "file", "sha256": checksum}):
                    raise SystemExit("invalid explicit omission")
            elif digest(path / name) != checksum:
                raise SystemExit("receipt member mismatch")
    return index


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--bundle", required=True, type=Path)
parser.add_argument("--manifest-sha", required=True)
parser.add_argument("--replay-output", type=Path)
parser.add_argument("--tcp", action="store_true", help="also run owned 127.0.0.1:0 endpoints")
args = parser.parse_args()
bundle = args.bundle.resolve(strict=True)
index = verify(bundle, args.manifest_sha)
print("bundle_verification=PASS", flush=True)
if args.replay_output is None:
    if args.tcp:
        parser.error("--tcp requires --replay-output")
    raise SystemExit(0)
out = args.replay_output.absolute()
if out.exists() or out.is_symlink() or bundle in out.parents:
    raise SystemExit("replay output must be new and outside bundle")
out.mkdir(mode=0o700)
(out / "home").mkdir()
original = index["evidence_root"]
evidence = bundle / "evidence"
records = []
status = {"status": "RUNNING", "bundle_manifest_sha256": args.manifest_sha,
          "scope": "selected native functional replay plus optional owned TCP; no rebuild/timing replay",
          "tcp": args.tcp}
(out / "IDENTITY.json").write_text(json.dumps(status, indent=2) + "\n")
try:
    for version in ("3.5.8", "4.0.2"):
        for stage in ("functional", "tcp") if args.tcp else ("functional",):
            name = stage + "-" + version
            commands = json.loads((evidence / name / "commands.json").read_text())
            for command in commands:
                step = command["step"]
                if stage == "functional" and not (step.startswith("run-") or step.startswith("native-")
                        or step.startswith("oid-") or step.startswith("retry-") or step.startswith("unit-run-")):
                    continue
                if command["exit"] != 0 or command["timeout"]:
                    raise SystemExit("replay selection includes a non-success command")
                argv = [part.replace(original, str(evidence)) for part in command["command"]]
                if not Path(argv[0]).resolve().is_relative_to(evidence):
                    raise SystemExit("replay executable outside sealed bundle")
                env = {key: value.replace(original, str(evidence))
                       for key, value in command["environment"].items()}
                env["HOME"] = str(out / "home")
                log = out / (name + "-" + step + ".log")
                started = time.monotonic()
                with log.open("w") as stream:
                    result = subprocess.run(argv, env=env, cwd="/", stdout=stream,
                                            stderr=subprocess.STDOUT, timeout=1200)
                records.append({"stage": name, "step": step, "argv": argv, "environment": env,
                                "exit": result.returncode, "seconds": time.monotonic() - started,
                                "log_sha256": digest(log)})
                (out / "commands.json").write_text(json.dumps(records, indent=2) + "\n")
                if result.returncode != 0:
                    raise SystemExit("replay failed; retained log: " + str(log))
                print("PASS " + name + "/" + step, flush=True)
    verify(bundle, args.manifest_sha)
    status.update(status="PASS", command_count=len(records))
finally:
    if status["status"] != "PASS":
        status["status"] = "FAIL"
    (out / "IDENTITY.json").write_text(json.dumps(status, indent=2) + "\n")
    (out / "SHA256SUMS").write_text("".join(f"{digest(p)}  {p.name}\n"
        for p in sorted(out.iterdir()) if p.is_file() and p.name != "SHA256SUMS"))
print("replay=PASS", flush=True)
