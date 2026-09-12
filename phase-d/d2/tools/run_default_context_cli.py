#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""N2 stock CLI in isolated process-default contexts; never edit host policy."""

import argparse
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from d2_common import ROOT, Receipt, digest, verify_receipt

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--source-sha", required=True)
parser.add_argument("--functional", required=True, type=Path)
parser.add_argument("--functional-sha", required=True)
parser.add_argument("--output", required=True, type=Path)
args = parser.parse_args()
functional = args.functional.resolve(strict=True)
if digest(functional / "SHA256SUMS") != args.functional_sha:
    raise SystemExit("functional receipt hash mismatch")
identity = verify_receipt(functional)
if identity["source_manifest_sha256"] != args.source_sha:
    raise SystemExit("default-context CLI and functional source must match")
receipt = Receipt(args.output, args.source_sha, "stock-default-context-cli")
out = receipt.output
version = identity["openssl_version"]
prefix = functional / "openssl/inst" / version
modules = functional / "modules"
for path in (out, prefix, modules):
    if re.fullmatch(r"[/A-Za-z0-9_.-]+", str(path)) is None:
        raise SystemExit("run-local configuration paths must not contain expansion or delimiter characters")
expected_modules = ("ed301_eddsa_v2_tls", "x301_v2_tls")
for module in expected_modules:
    if digest(modules / (module + ".so")) != identity["module_sha256"][module]:
        raise SystemExit("renamed module is not bound to the functional receipt")
for old in ("ed301_eddsa_v2_tls_test", "x301_v2_tls_test"):
    if (modules / (old + ".so")).exists():
        raise SystemExit("obsolete TLS module remains in the new build inventory")

active = out / "process-default.cnf"
inactive = out / "builtin-only.cnf"
# OpenSSL 4 x509 also reads extensions from the default configuration.
# Keep that namespace separate from provider initialization. The explicitly
# requested CSR extensions are still copied and verified below.
common = "config_diagnostics = 1\nopenssl_conf = init\nextensions = n2_extensions\n[init]\nproviders = providers\n[providers]\ndefault = builtin\n"
inactive.write_text(common + "[builtin]\nactivate = 1\n[n2_extensions]\n")
active.write_text(common + "ed301_eddsa_v2_tls = ed\nx301_v2_tls = x\n"
    "[builtin]\nactivate = 1\n"
    f"[ed]\nmodule = {modules / 'ed301_eddsa_v2_tls.so'}\nactivate = 1\n"
    f"[x]\nmodule = {modules / 'x301_v2_tls.so'}\nactivate = 1\n[n2_extensions]\n")
runtime = dict(receipt.clean, OPENSSL_CONF=str(active), OPENSSL_MODULES=str(modules),
    LD_LIBRARY_PATH=str(prefix / "lib"), ED301V2_EXPECT_OPENSSL_PREFIX=str(prefix))
assert "OPENSSL_TEST_LIBCTX" not in runtime
receipt.identity.update(openssl_version=version, functional_receipt_sha256=args.functional_sha,
    process_default_libctx="default plus two renamed v2 TLS providers, only inside child test processes",
    host_configuration_changed=False, explicit_provider_cli_options=False,
    private_frontends_used=False, network_used=False, rpm_or_installation=False,
    test_keys="fresh local fixtures, never committed or used in production")
receipt.write_identity()
(out / "bin").mkdir(mode=0o700)
probe = out / "bin/provider_default_context"
receipt.run("compile-context-observer", ["/usr/bin/gcc", "-std=c11", "-D_GNU_SOURCE", "-O2",
    "-Wall", "-Wextra", "-Werror", "-I" + str(prefix / "include"), "-I" + str(ROOT / "provider-tests"),
    ROOT / "provider-tests/provider_default_context.c", "-o", probe, "-L" + str(prefix / "lib"),
    "-Wl,-rpath," + str(prefix / "lib"), "-lcrypto", "-ldl", "-pthread"])
missing = receipt.run("inactive-context-control", [probe], dict(runtime, OPENSSL_CONF=str(inactive)), expected=1)
if "DEFAULT_CONTEXT_PROVIDERS_MISSING_OR_UNEXPECTED" not in missing:
    raise SystemExit("inactive context control failed outside the expected boundary")
output = receipt.run("active-default-context", [probe], runtime)
if "DEFAULT_CONTEXT_V2=PASS" not in output:
    raise SystemExit("default context was not observed")


def cli(step, command, *options, expected=0, env=None):
    # No -provider, OPENSSL_TEST_LIBCTX or application frontend is permitted.
    if any(str(value) in ("-provider", "-provider-path") for value in options):
        raise SystemExit("N2 must exercise configuration-based provider discovery")
    return receipt.run(step, [prefix / "bin/openssl", command, *options], env or runtime, expected=expected)


listing = cli("configured-providers", "list", "-providers", "-verbose")
if any(name not in listing for name in expected_modules) or "_tls_test" in listing:
    raise SystemExit("configured provider names mismatch")
cli("openssl-identity", "version", "-a")
for name, algorithm in (("ed", "Ed301-EdDSA"), ("x", "X301")):
    cli(name + "-keygen", "genpkey", "-algorithm", algorithm, "-out", out / (name + ".key"))
    cli(name + "-key-check", "pkey", "-in", out / (name + ".key"), "-check", "-noout")
    cli(name + "-public", "pkey", "-in", out / (name + ".key"), "-pubout", "-out", out / (name + ".pub"))
    cli(name + "-public-check", "pkey", "-pubin", "-in", out / (name + ".pub"), "-pubcheck", "-noout")
    cli(name + "-encrypted", "pkcs8", "-topk8", "-in", out / (name + ".key"),
        "-v2", "aes-256-cbc", "-passout", "pass:n2-test-password", "-out", out / (name + "-encrypted.key"))
    cli(name + "-decrypted", "pkey", "-in", out / (name + "-encrypted.key"),
        "-passin", "pass:n2-test-password", "-out", out / (name + "-decrypted.key"))
    if (out / (name + ".key")).read_bytes() != (out / (name + "-decrypted.key")).read_bytes():
        raise SystemExit("PKCS8 roundtrip changed a private key")
    bad = cli(name + "-wrong-password", "pkey", "-in", out / (name + "-encrypted.key"),
        "-passin", "pass:wrong", "-check", "-noout", expected=None)
    if "bad decrypt" not in bad:
        raise SystemExit("PKCS8 password control failed unexpectedly")

ca, leaf, csr = out / "ca.crt", out / "leaf.crt", out / "leaf.csr"
cli("ca-key", "genpkey", "-algorithm", "Ed301-EdDSA", "-out", out / "ca.key")
cli("ca-certificate", "req", "-new", "-x509", "-key", out / "ca.key", "-subj", "/CN=N2 ephemeral CA",
    "-days", "1", "-addext", "basicConstraints=critical,CA:TRUE,pathlen:1",
    "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", ca)
verify = ["-no-CApath", "-no-CAstore", "-CAfile", ca]
cli("ca-self-signature", "verify", *verify, "-check_ss_sig", ca)
cli("leaf-csr", "req", "-new", "-key", out / "ed.key", "-subj", "/CN=n2.test.example",
    "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "keyUsage=critical,digitalSignature",
    "-addext", "extendedKeyUsage=serverAuth", "-addext", "subjectAltName=DNS:n2.test.example", "-out", csr)
verified = cli("stock-req-verify", "req", "-in", csr, "-verify", "-noout")
if "self-signature verify OK" not in verified:
    raise SystemExit("stock req did not attest CSR verification")
issued = cli("stock-x509-req", "x509", "-req", "-in", csr, "-CA", ca, "-CAkey", out / "ca.key",
    "-set_serial", "2", "-days", "1", "-copy_extensions", "copy", "-out", leaf)
if "request self-signature ok" not in issued:
    raise SystemExit("stock x509 did not attest the CSR self-signature")
cli("stock-chain-verify", "verify", *verify, "-purpose", "sslserver", "-verify_hostname", "n2.test.example", leaf)
bad = cli("wrong-hostname", "verify", *verify, "-verify_hostname", "wrong.test.example", leaf, expected=None)
if "hostname mismatch" not in bad:
    raise SystemExit("hostname control failed unexpectedly")
cli("csr-to-der", "req", "-in", csr, "-outform", "DER", "-out", out / "csr.der")
damaged = bytearray((out / "csr.der").read_bytes())
damaged[-1] ^= 1
(out / "bad-csr.der").write_bytes(damaged)
bad = cli("bad-csr-verify", "req", "-inform", "DER", "-in", out / "bad-csr.der", "-verify", "-noout", expected=None)
if "self-signature verify failure" not in bad:
    raise SystemExit("damaged CSR control failed outside signature verification")
bad = cli("bad-csr-issue", "x509", "-req", "-inform", "DER", "-in", out / "bad-csr.der",
    "-CA", ca, "-CAkey", out / "ca.key", "-set_serial", "3", "-days", "1", "-out", out / "bad.crt", expected=None)
if "self-signature did not match" not in bad or ((out / "bad.crt").exists() and (out / "bad.crt").stat().st_size):
    raise SystemExit("invalid CSR was issued or rejected for an unrelated reason")

# X301 cannot sign a CSR. Give its public key a certificate signed by the
# ephemeral Ed301 CA, then exercise the same stock PKCS12 private-key path.
cli("x-certificate", "x509", "-new", "-force_pubkey", out / "x.pub", "-subj", "/CN=N2 X301 key",
    "-CA", ca, "-CAkey", out / "ca.key", "-set_serial", "4", "-days", "1", "-out", out / "x.crt")
cli("x-certificate-verify", "verify", *verify, out / "x.crt")
for name, cert in (("ed", leaf), ("x", out / "x.crt")):
    cli(name + "-pkcs12-export", "pkcs12", "-export", "-inkey", out / (name + ".key"),
        "-in", cert, "-certfile", ca, "-passout", "pass:n2-test-password", "-out", out / (name + ".p12"))
    cli(name + "-stock-pkcs12-keydump", "pkcs12", "-in", out / (name + ".p12"),
        "-passin", "pass:n2-test-password", "-nocerts", "-noenc", "-out", out / (name + "-extracted.key"))
    cli(name + "-extracted-key-check", "pkey", "-in", out / (name + "-extracted.key"), "-check", "-noout")
    cli(name + "-extracted-public", "pkey", "-in", out / (name + "-extracted.key"),
        "-pubout", "-out", out / (name + "-extracted.pub"))
    if (out / (name + ".pub")).read_bytes() != (out / (name + "-extracted.pub")).read_bytes():
        raise SystemExit("stock PKCS12 extraction changed a key")
    bad = cli(name + "-pkcs12-wrong-password", "pkcs12", "-in", out / (name + ".p12"),
        "-passin", "pass:wrong", "-noout", expected=None)
    if "Mac verify error" not in bad:
        raise SystemExit("PKCS12 password control failed unexpectedly")

cli("x-peer-key", "genpkey", "-algorithm", "X301", "-out", out / "peer.key")
cli("x-peer-public", "pkey", "-in", out / "peer.key", "-pubout", "-out", out / "peer.pub")
cli("x-derive-forward", "pkeyutl", "-derive", "-inkey", out / "x.key", "-peerkey", out / "peer.pub", "-out", out / "shared-a.bin")
cli("x-derive-reverse", "pkeyutl", "-derive", "-inkey", out / "peer.key", "-peerkey", out / "x.pub", "-out", out / "shared-b.bin")
shared = (out / "shared-a.bin").read_bytes()
if len(shared) != 38 or not any(shared) or shared != (out / "shared-b.bin").read_bytes():
    raise SystemExit("stock X301 derivation mismatch")
receipt.run("active-context-after-cli", [probe], runtime)
receipt.run("inactive-context-after-cli", [probe], dict(runtime, OPENSSL_CONF=str(inactive)), expected=1)
verify_receipt(functional)
receipt.identity.update(stock_req_verify="PASS", stock_x509_req="PASS",
    stock_pkcs12_keydump={"Ed301-EdDSA": "PASS", "X301": "PASS"},
    x301_bidirectional_derive="PASS", wrong_password_and_invalid_csr_controls="PASS")
receipt.seal()
