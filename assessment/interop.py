#!/usr/bin/env python3
"""Cross-version OpenSSL key-container tests using already bound provider DSOs."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "phase-d/d2/tools"))
from d2_common import digest, verify_receipt

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--evidence", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
out = args.output.resolve()
out.mkdir(mode=0o700)
(out / "logs").mkdir()
(out / "home").mkdir()
index = json.loads((ROOT / "docs/REVIEW_FOLLOWUP_20260912.json").read_text())
expected = {row["directory"]: row["manifest_sha256"] for row in index["receipts"]}
commands, observations = [], []
lanes = {}


def run(label, argv, env, must_pass=True):
    argv = list(map(str, argv))
    result = subprocess.run(argv, env=env, cwd=out, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=120)
    log = out / "logs" / f"{len(commands):04d}-{label}.log"
    log.write_bytes(result.stdout)
    commands.append({"label": label, "argv": argv, "exit": result.returncode,
                     "log": str(log.relative_to(out)), "sha256": digest(log)})
    (out / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
    if must_pass and result.returncode:
        raise RuntimeError(f"{label}: exit {result.returncode}; see {log}")
    return result.returncode == 0


def cli(version, label, *arguments, must_pass=True):
    lane = lanes[version]
    return run(version + "-" + label, [lane["openssl"], *arguments], lane["env"], must_pass)


def write(path, content):
    path.write_bytes(content)
    path.chmod(0o600)


def tlv(tag, content):
    length = len(content)
    encoded = bytes([length]) if length < 128 else bytes([0x81, length])
    return bytes([tag]) + encoded + content


for version in ("3.5.8", "4.0.2"):
    folder = (args.evidence / ("functional-" + version)).resolve()
    if digest(folder / "SHA256SUMS") != expected[folder.name]:
        raise RuntimeError("functional receipt seal differs")
    identity = verify_receipt(folder)
    # Bind reused executable inputs to the active source, not just a version label.
    for line in (folder / "BUILD_SOURCE_SHA256SUMS").read_text().splitlines():
        checksum, name = line.split("  ", 1)
        if digest(ROOT / name) != checksum:
            raise RuntimeError("compiled source differs: " + name)
    prefix = folder / "openssl/inst" / version
    directory = out / version
    directory.mkdir()
    config = directory / "openssl.cnf"
    config.write_text("config_diagnostics = 1\nopenssl_conf = init\nextensions = empty\n"
        "[init]\nproviders = providers\n[providers]\ndefault = builtin\n"
        "ed301_eddsa_v2_tls = ed\nx301_v2_tls = x\n[builtin]\nactivate = 1\n"
        "[ed]\nactivate = 1\n[x]\nactivate = 1\n[empty]\n")
    env = {"PATH": "/usr/bin:/bin", "HOME": str(out / "home"), "LC_ALL": "C",
           "OPENSSL_CONF": str(config), "OPENSSL_MODULES": str(folder / "modules"),
           "LD_LIBRARY_PATH": str(prefix / "lib"), "ED301V2_EXPECT_OPENSSL_PREFIX": str(prefix)}
    lanes[version] = {"openssl": prefix / "bin/openssl", "env": env, "dir": directory,
                      "modules": folder / "modules", "receipt": expected[folder.name]}
    cli(version, "identity", "version", "-a")
    for tag, algorithm in (("ed", "Ed301-EdDSA"), ("x", "X301")):
        binary = directory / (tag + "-filecheck")
        options = ["-DX301_CODEC_TEST"] if tag == "x" else []
        run(version + "-build-" + tag + "-filecheck", ["gcc", "-std=c11", "-D_GNU_SOURCE", "-O2",
            "-Wall", "-Wextra", "-Werror", "-I" + str(prefix / "include"),
            "-I" + str(ROOT / "provider-tests"), *options,
            ROOT / "provider-tests/provider_keyfile_check.c", "-o", binary,
            "-L" + str(prefix / "lib"), "-Wl,-rpath," + str(prefix / "lib"),
            "-lcrypto", "-ldl", "-pthread"], env)
        stem = directory / tag
        cli(version, tag + "-generate", "genpkey", "-algorithm", algorithm, "-out", str(stem) + ".pem")
        for public in (False, True):
            for fmt in ("PEM", "DER"):
                name = str(stem) + ("-public" if public else "-private") + "." + fmt.lower()
                cli(version, tag + "-export", "pkey", "-in", str(stem) + ".pem",
                    *(["-pubout"] if public else []), "-outform", fmt, "-out", name)
        for fmt in ("PEM", "DER"):
            cli(version, tag + "-encrypt", "pkcs8", "-topk8", "-in", str(stem) + ".pem",
                "-v2", "aes-256-cbc", "-iter", "10000", "-passout", "pass:interop-test",
                "-outform", fmt, "-out", str(stem) + "-encrypted." + fmt.lower())
        write(Path(str(stem) + "-crlf.pem"), Path(str(stem) + ".pem").read_bytes().replace(b"\n", b"\r\n"))
    cli(version, "ca", "req", "-new", "-x509", "-key", directory / "ed.pem",
        "-subj", "/CN=ED301 container test", "-days", "1", "-out", directory / "ed.crt")
    cli(version, "x-cert", "x509", "-new", "-force_pubkey", directory / "x-public.pem",
        "-CA", directory / "ed.crt", "-CAkey", directory / "ed.pem", "-set_serial", "2",
        "-subj", "/CN=X301 container test", "-days", "1", "-out", directory / "x.crt")
    for tag in ("ed", "x"):
        cli(version, tag + "-p12", "pkcs12", "-export", "-inkey", directory / (tag + ".pem"),
            "-in", directory / (tag + ".crt"), "-passout", "pass:interop-test",
            "-out", directory / (tag + ".p12"))


for producer in lanes:
    directory = lanes[producer]["dir"]
    for tag in ("ed", "x"):
        canonical = (directory / (tag + "-private.der")).read_bytes()
        public_der = (directory / (tag + "-public.der")).read_bytes()
        if len(canonical) != 62 or len(public_der) != 58:
            raise RuntimeError("producer changed canonical profile size")
        version_part, algorithm_part, private_part = canonical[2:5], canonical[5:20], canonical[20:]
        attribute = tlv(0xa0, tlv(0x30, bytes.fromhex("06092a864886f70d010914")
            + tlv(0x31, tlv(0x1e, "test key".encode("utf-16-be")))))
        variants = {
            "attributes": tlv(0x30, version_part + algorithm_part + private_part + attribute),
            "one-asymmetric-key": tlv(0x30, b"\x02\x01\x01" + algorithm_part + private_part
                                      + tlv(0x81, b"\0" + public_der[-38:])),
            "null-parameters": tlv(0x30, version_part + tlv(0x30, algorithm_part[2:] + b"\x05\x00") + private_part),
            "trailing-byte": canonical + b"\0",
            "two-der-objects": canonical + canonical,
        }
        pem = (directory / (tag + ".pem")).read_bytes()
        pem_variants = {"leading-blank": b"\n" + pem, "trailing-space": pem + b" \n",
                        "two-pem-objects": pem + pem}
        for name, data in variants.items():
            path = directory / (tag + "-" + name + ".der")
            write(path, data)
            if name in {"attributes", "one-asymmetric-key", "null-parameters"}:
                cli(producer, "asn1-" + name, "asn1parse", "-inform", "DER", "-in", path)
        for name, data in pem_variants.items():
            write(directory / (tag + "-" + name + ".pem"), data)
        cases = [("private.pem", "PEM", False, True), ("private.der", "DER", False, True),
                 ("public.pem", "PEM", True, True), ("public.der", "DER", True, True),
                 ("encrypted.pem", "PEM", False, True), ("encrypted.der", "DER", False, True),
                 ("crlf.pem", "PEM", False, True)]
        cases += [(name + ".der", "DER", False, False) for name in variants]
        cases += [(name + ".pem", "PEM", False, False) for name in pem_variants]
        for consumer, lane in lanes.items():
            private_env = dict(lane["env"], OPENSSL_CONF="/dev/null")
            for name, fmt, public, supported in cases:
                path = directory / (tag + "-" + name)
                recovered = out / "recovered-public.der"
                recovered.unlink(missing_ok=True)
                accepted = cli(consumer, "read-" + name, "pkey", "-inform", fmt,
                    *( ["-pubin"] if public else []), "-in", path,
                    "-passin", "pass:interop-test", "-pubout", "-outform", "DER", "-out", recovered,
                    must_pass=supported)
                if accepted and recovered.read_bytes() != public_der:
                    raise RuntimeError("cross-version import changed key identity")
                if accepted and not public:
                    private_copy = out / "recovered-private.der"
                    cli(consumer, "private-roundtrip-" + name, "pkey", "-inform", fmt,
                        "-in", path, "-passin", "pass:interop-test", "-outform", "DER", "-out", private_copy)
                    if private_copy.read_bytes() != canonical:
                        raise RuntimeError("cross-version import changed original private bytes")
                strict = run(consumer + "-strict-" + name,
                    [lane["dir"] / (tag + "-filecheck"), fmt, "public" if public else "private",
                     path, "interop-test"], private_env, must_pass=False)
                if strict != supported:
                    raise RuntimeError("complete-file contract mismatch: " + str(path))
                observations.append({"producer": producer, "consumer": consumer, "algorithm": tag,
                    "format": name, "supported_profile": supported,
                    "stock_cli_accepts": accepted, "complete_file_accepts": strict})
            for suffix, fmt in (("encrypted.pem", "PEM"), ("encrypted.der", "DER")):
                path = directory / (tag + "-" + suffix)
                if cli(consumer, "wrong-password", "pkey", "-in", path, "-inform", fmt,
                       "-passin", "pass:wrong", "-noout", must_pass=False):
                    raise RuntimeError("wrong password accepted")
            dump = out / "p12-keydump.pem"
            normal = out / "p12-normalized.pem"
            cli(consumer, "p12-import", "pkcs12", "-in", directory / (tag + ".p12"),
                "-passin", "pass:interop-test", "-nocerts", "-noenc", "-out", dump)
            cli(consumer, "p12-normalize", "pkey", "-in", dump, "-out", normal)
            cli(consumer, "p12-identity", "pkey", "-in", normal, "-pubout", "-outform", "DER", "-out", recovered)
            if recovered.read_bytes() != public_der:
                raise RuntimeError("PKCS12 changed key identity")
            private_copy = out / "p12-private.der"
            cli(consumer, "p12-private-roundtrip", "pkey", "-in", normal,
                "-outform", "DER", "-out", private_copy)
            if private_copy.read_bytes() != canonical:
                raise RuntimeError("PKCS12 changed original private bytes")
            raw_strict = run(consumer + "-p12-raw-filecheck",
                [lane["dir"] / (tag + "-filecheck"), "PEM", "private", dump], private_env, must_pass=False)
            run(consumer + "-p12-normalized-filecheck",
                [lane["dir"] / (tag + "-filecheck"), "PEM", "private", normal], private_env)
            if cli(consumer, "p12-wrong-password", "pkcs12", "-in", directory / (tag + ".p12"),
                   "-passin", "pass:wrong", "-noout", must_pass=False):
                raise RuntimeError("wrong PKCS12 password accepted")
            observations.append({"producer": producer, "consumer": consumer, "algorithm": tag,
                "format": "pkcs12", "supported_profile": True, "stock_cli_accepts": True,
                "raw_keydump_complete_file_accepts": raw_strict, "normalized_complete_file_accepts": True})

result = {"status": "PASS", "scope": "OpenSSL 3.5.8/4.0.2 container exchange, no host activation",
          "commands": len(commands), "observations": observations,
          "functional_receipts": {v: lane["receipt"] for v, lane in lanes.items()},
          "runner_sha256": digest(Path(__file__))}
(out / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
print(f"INTEROP=PASS observations={len(observations)} commands={len(commands)}")
