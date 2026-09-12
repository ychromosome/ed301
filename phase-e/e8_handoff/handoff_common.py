# SPDX-License-Identifier: Apache-2.0
"""Small, read-only integrity checks shared by Gate-E packaging and replay."""

import hashlib
import json
from pathlib import Path
import re


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise SystemExit("duplicate JSON key: " + key)
            result[key] = value
        return result
    return json.loads(Path(path).read_text(), object_pairs_hook=unique)


def relative_path(name):
    path = Path(name)
    if (not name or path == Path(".") or path.is_absolute() or ".." in path.parts or "\\" in name
            or path.as_posix() != name):
        raise SystemExit("unsafe relative evidence path: " + name)
    return path


def manifest_rows(path):
    result = {}
    for line in Path(path).read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)", line)
        if match is None:
            raise SystemExit("malformed SHA-256 manifest: " + str(path))
        checksum, name = match.groups()
        relative_path(name)
        if name in result:
            raise SystemExit("duplicate manifest member: " + name)
        result[name] = checksum
    if not result:
        raise SystemExit("empty evidence manifest: " + str(path))
    return result


def check_members(directory, manifest, expected, omitted=None):
    directory = Path(directory)
    if digest(directory / manifest) != expected:
        raise SystemExit("manifest digest mismatch: " + str(directory / manifest))
    rows = manifest_rows(directory / manifest)
    for name, checksum in rows.items():
        if omitted is not None and name in omitted:
            if omitted[name] != {"type": "file", "sha256": checksum}:
                raise SystemExit("invalid omitted receipt member: " + name)
            continue
        member = directory / name
        if member.is_symlink() or not member.is_file() or digest(member) != checksum:
            raise SystemExit("receipt member mismatch: " + str(member))
    return rows


def check_source(source, seal, expected):
    rows = manifest_rows(seal)
    if digest(seal) != expected:
        raise SystemExit("source manifest digest mismatch")
    actual = set()
    for path in [source] + list(source.rglob("*")):
        if path.is_symlink() or path.stat().st_mode & 0o222:
            raise SystemExit("source is not read-only regular data: " + str(path))
        if path.is_file():
            actual.add(path.relative_to(source).as_posix())
        elif not path.is_dir():
            raise SystemExit("special source object")
    if actual != set(rows):
        raise SystemExit("source inventory mismatch")
    for name, checksum in rows.items():
        if digest(source / name) != checksum:
            raise SystemExit("source member mismatch: " + name)
    return rows


def check_source_comparison(receipt, manifest, source, prefix="", all_rust=False):
    rows = manifest_rows(receipt / manifest)
    names = set()
    for name, checksum in rows.items():
        mapped = (Path(prefix) / name).as_posix() if prefix else name
        relative_path(mapped)
        member = source / mapped
        if member.is_symlink() or not member.is_file() or digest(member) != checksum:
            raise SystemExit("receipt source differs from packaged source: " + mapped)
        names.add(mapped)
    if all_rust:
        rust = {p.relative_to(source).as_posix() for p in (source / "rust").rglob("*") if p.is_file()}
        if {name for name in names if name.startswith("rust/")} != rust:
            raise SystemExit("incomplete Rust source comparison")
    return len(rows)


def check_command_logs(directory, rows):
    commands_path = directory / "commands.json"
    if not commands_path.exists():
        return 0
    commands = read_json(commands_path)
    for command in commands:
        name = command.get("log")
        if name is None:
            step = command.get("step", command.get("name"))
            if not isinstance(step, str) or not step:
                raise SystemExit("command has no log or step identity")
            name = "logs/" + step + ".log"
        relative_path(name)
        if name not in rows:
            raise SystemExit("command log is not sealed: " + name)
        if "log_sha256" in command and rows[name] != command["log_sha256"]:
            raise SystemExit("command log identity mismatch: " + name)
    return len(commands)
