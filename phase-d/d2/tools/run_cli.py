#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Private-libctx CLI interoperability and strict standalone-key file checks."""

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from d2_common import ROOT, Receipt, digest, verify_receipt

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--source-sha", required=True)
parser.add_argument("--functional", type=Path, required=True)
parser.add_argument("--functional-sha", required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
functional = args.functional.resolve(strict=True)
if digest(functional / "SHA256SUMS") != args.functional_sha:
    raise SystemExit("functional receipt differs from its caller-supplied digest")
identity = verify_receipt(functional)
if identity["source_manifest_sha256"] != args.source_sha:
    raise SystemExit("CLI and functional stages must use one immutable source snapshot")
receipt = Receipt(args.output, args.source_sha, "private-libctx-cli")
out = receipt.output
version = identity["openssl_version"]
prefix = functional / "openssl/inst" / version
modules = functional / "modules"
builtin_config = out / "builtin-default-only.cnf"
builtin_config.write_text("openssl_conf = init\n[init]\nproviders = providers\n"
                          "[providers]\ndefault = builtins\n[builtins]\nactivate = 1\n")
# Stock apps/pkcs8.c in both pinned releases calls legacy PBES2 helpers in
# the process default context. Only the built-in default provider is enabled
# there; OPENSSL_TEST_LIBCTX keeps every explicit v2 -provider load private.
runtime = dict(receipt.clean, OPENSSL_CONF=str(builtin_config), OPENSSL_TEST_LIBCTX="1",
               OPENSSL_MODULES=str(modules), LD_LIBRARY_PATH=str(prefix / "lib"),
               ED301V2_EXPECT_OPENSSL_PREFIX=str(prefix))
receipt.identity.update(openssl_version=version, functional_receipt_sha256=args.functional_sha,
                        process_default_libctx="built-in default only; no v2 module",
                        test_keys="fresh per run, retained only in uncommitted local test evidence",
                        cli_pki_verify="OpenSSL interoperability; strict X509 object precheck is a separate application contract")
receipt.write_identity()
(out / "bin").mkdir(mode=0o700)
csr_frontend = out / "bin/provider_csr_cli"
p12_frontend = out / "bin/provider_pkcs12_cli"
receipt.run("compile-csr-frontend", ["/usr/bin/gcc", "-std=c11", "-D_GNU_SOURCE", "-O2", "-Wall", "-Wextra", "-Werror",
            "-I" + str(prefix / "include"), "-I" + str(ROOT / "provider-tests"),
            ROOT / "provider-tests/provider_csr_cli.c", "-o", csr_frontend,
            "-L" + str(prefix / "lib"), "-Wl,-rpath," + str(prefix / "lib"), "-lcrypto", "-ldl", "-pthread"])
receipt.run("compile-pkcs12-frontend", ["/usr/bin/gcc", "-std=c11", "-D_GNU_SOURCE", "-O2", "-Wall", "-Wextra", "-Werror",
            "-I" + str(prefix / "include"), "-I" + str(ROOT / "provider-tests"),
            ROOT / "provider-tests/provider_pkcs12_cli.c", "-o", p12_frontend,
            "-L" + str(prefix / "lib"), "-Wl,-rpath," + str(prefix / "lib"), "-lcrypto", "-ldl", "-pthread"])


def cli(step, module, command, *options, expected=0):
    return receipt.run(step, [prefix / "bin/openssl", command, "-provider-path", modules,
                       "-provider", "default", "-provider", module] + list(options), runtime, expected=expected)


for name, algorithm, ordinary, pki, tls in (
    ("ed301", "Ed301-EdDSA", "ed301_eddsa_v2", "ed301_eddsa_v2_pki_test", "ed301_eddsa_v2_tls"),
    ("x301", "X301", "x301_v2", "x301_v2_pki_test", "x301_v2_tls"),
):
    directory = out / name
    directory.mkdir(mode=0o700)
    checker = out / "bin" / (name + "_keyfile_check")
    command = ["/usr/bin/gcc", "-std=c11", "-D_GNU_SOURCE", "-O2", "-Wall", "-Wextra", "-Werror",
               "-I" + str(prefix / "include"), "-I" + str(ROOT / "provider-tests")]
    if name == "x301":
        command.append("-DX301_CODEC_TEST")
    command += [ROOT / "provider-tests/provider_keyfile_check.c", "-o", checker,
                "-L" + str(prefix / "lib"), "-Wl,-rpath," + str(prefix / "lib"), "-lcrypto", "-ldl", "-pthread"]
    receipt.run(name + "-build-checker", command)
    cli(name + "-list", ordinary, "list", "-key-managers", "-verbose")
    cli(name + "-keygen", pki, "genpkey", "-algorithm", algorithm, "-out", directory / "private.pem")
    cli(name + "-private-check", tls, "pkey", "-in", directory / "private.pem", "-check", "-noout")
    cli(name + "-private-text", tls, "pkey", "-in", directory / "private.pem", "-text", "-noout",
        "-out", directory / "private-text.txt")
    text = (directory / "private-text.txt").read_text()
    if algorithm + " Private-Key:" not in text or "priv:" not in text or "pub:" not in text:
        raise SystemExit("private text encoder output is incomplete")
    cli(name + "-public-pem", tls, "pkey", "-in", directory / "private.pem", "-pubout", "-out", directory / "public.pem")
    cli(name + "-public-check", tls, "pkey", "-pubin", "-in", directory / "public.pem", "-pubcheck", "-noout")
    cli(name + "-public-text", tls, "pkey", "-pubin", "-in", directory / "public.pem", "-text_pub", "-noout",
        "-out", directory / "public-text.txt")
    text = (directory / "public-text.txt").read_text()
    if algorithm + " Public-Key:" not in text or "pub:" not in text or "priv:" in text:
        raise SystemExit("public text output is not public-only")
    cli(name + "-private-der", tls, "pkey", "-in", directory / "private.pem", "-outform", "DER",
        "-out", directory / "private.der")
    cli(name + "-public-der", tls, "pkey", "-pubin", "-in", directory / "public.pem", "-outform", "DER",
        "-pubout", "-out", directory / "public.der")
    cli(name + "-der-roundtrip", tls, "pkey", "-inform", "DER", "-in", directory / "private.der",
        "-out", directory / "roundtrip.pem")
    if (directory / "roundtrip.pem").read_bytes() != (directory / "private.pem").read_bytes():
        raise SystemExit("private DER/PEM roundtrip changed the original secret")
    cli(name + "-direct-encryption", tls, "pkey", "-in", directory / "private.pem", "-aes-256-cbc",
        "-passout", "pass:d2-test-password", "-out", directory / "encrypted.pem")
    cli(name + "-generic-encryption", tls, "pkcs8", "-topk8", "-in", directory / "private.pem",
        "-v2", "aes-256-cbc", "-passout", "pass:d2-test-password", "-outform", "DER",
        "-out", directory / "encrypted.der")
    for form in ("DER", "PEM"):
        cli(name + "-decrypt-" + form, tls, "pkey", "-inform", form,
            "-in", directory / ("encrypted." + form.lower()), "-passin", "pass:d2-test-password",
            "-out", directory / ("decrypted-" + form + ".pem"))
        if (directory / ("decrypted-" + form + ".pem")).read_bytes() != (directory / "private.pem").read_bytes():
            raise SystemExit("encrypted PKCS#8 roundtrip changed the original secret")
        negative = cli(name + "-wrong-password-" + form, tls, "pkey", "-inform", form,
                       "-in", directory / ("encrypted." + form.lower()), "-passin", "pass:wrong",
                       "-check", "-noout", expected=None)
        if "bad decrypt" not in negative:
            raise SystemExit("wrong-password control failed for an unexpected reason")
    for filename, form, selection, password in (
        ("private.pem", "PEM", "private", None), ("private.der", "DER", "private", None),
        ("public.pem", "PEM", "public", None), ("public.der", "DER", "public", None),
        ("encrypted.pem", "PEM", "private", "d2-test-password"),
        ("encrypted.der", "DER", "private", "d2-test-password"),
    ):
        path = directory / filename
        extra = [] if password is None else [password]
        receipt.run(name + "-complete-" + filename, [checker, form, selection, path] + extra, runtime)
        tail = directory / (filename + ".tail")
        tail.write_bytes(path.read_bytes() + b"\x00")
        negative = receipt.run(name + "-tail-" + filename, [checker, form, selection, tail] + extra,
                               runtime, expected=1)
        if "keyfile_complete=REJECT" not in negative:
            raise SystemExit("complete-file negative control had no rejection marker")

ed = out / "ed301"
tls = "ed301_eddsa_v2_tls"
ca = ed / "ca.crt"
leaf = ed / "leaf.crt"
leaf_key = ed / "leaf-key.pem"
cli("ed-ca", tls, "req", "-new", "-x509", "-key", ed / "private.pem", "-subj", "/CN=D2 ephemeral CA",
    "-days", "1", "-addext", "basicConstraints=critical,CA:TRUE,pathlen:1",
    "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", ca)
cli("ed-ca-self-signature", tls, "verify", "-check_ss_sig", "-no-CApath", "-no-CAstore", "-CAfile", ca, ca)
cli("ed-leaf-key", "ed301_eddsa_v2_pki_test", "genpkey", "-algorithm", "Ed301-EdDSA", "-out", leaf_key)
cli("ed-csr", tls, "req", "-new", "-key", leaf_key, "-subj", "/CN=server.v2.test.example",
    "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "keyUsage=critical,digitalSignature",
    "-addext", "extendedKeyUsage=serverAuth", "-addext", "subjectAltName=DNS:server.v2.test.example",
    "-out", ed / "leaf.csr")
negative = cli("stock-csr-private-context-limit", tls, "req", "-in", ed / "leaf.csr", "-verify", "-noout", expected=None)
if "X509_PUBKEY_get0" not in negative or "decode error" not in negative:
    raise SystemExit("stock CSR context limitation changed; review the pinned app behavior")
receipt.identity["stock_csr_verification"] = "unsupported with private app libctx; public-API frontend used, no global v2 fallback"
receipt.run("ed-csr-verify", [csr_frontend, "verify", ed / "leaf.csr"], runtime)
cli("ed-csr-der", tls, "req", "-in", ed / "leaf.csr", "-outform", "DER", "-out", ed / "leaf-csr.der")
damaged = bytearray((ed / "leaf-csr.der").read_bytes())
damaged[-1] ^= 1  # The CSR signature BIT STRING is the final field.
(ed / "bad-csr.der").write_bytes(damaged)
cli("ed-csr-bad-pem", tls, "req", "-inform", "DER", "-in", ed / "bad-csr.der", "-outform", "PEM", "-out", ed / "bad.csr")
receipt.run("ed-csr-signature-negative", [csr_frontend, "verify", ed / "bad.csr"], runtime, expected=1)
receipt.run("ed-sign-leaf", [csr_frontend, "issue", ed / "leaf.csr", ca, ed / "private.pem", "2", leaf], runtime)
csr_asan = out / "bin/provider_csr_cli_asan"
receipt.run("compile-csr-asan", ["/usr/bin/gcc", "-std=c11", "-D_GNU_SOURCE", "-O2", "-g", "-Wall", "-Wextra", "-Werror",
            "-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-omit-frame-pointer",
            "-I" + str(prefix / "include"), "-I" + str(ROOT / "provider-tests"),
            ROOT / "provider-tests/provider_csr_cli.c", "-o", csr_asan,
            "-L" + str(prefix / "lib"), "-Wl,-rpath," + str(prefix / "lib"), "-lcrypto", "-ldl", "-pthread"])
receipt.run("csr-asan", [csr_asan, "issue", ed / "leaf.csr", ca, ed / "private.pem", "3", ed / "leaf-asan.crt"],
            dict(runtime, ASAN_OPTIONS="detect_leaks=0:halt_on_error=1", UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"))
receipt.run("csr-valgrind", ["/usr/bin/valgrind", "--error-exitcode=99", "--leak-check=full", "--vgdb=no",
            "--errors-for-leak-kinds=definite,indirect,possible", "--quiet", csr_frontend,
            "issue", ed / "leaf.csr", ca, ed / "private.pem", "4", ed / "leaf-valgrind.crt"], runtime)
verify_options = ["-no-CApath", "-no-CAstore", "-CAfile", ca, "-purpose", "sslserver"]
cli("ed-chain", tls, "verify", *verify_options, "-verify_hostname", "server.v2.test.example", leaf)
negative = cli("ed-wrong-hostname", tls, "verify", *verify_options, "-verify_hostname", "wrong.v2.test.example", leaf, expected=None)
if "hostname mismatch" not in negative:
    raise SystemExit("hostname negative control failed for an unexpected reason")
cli("ed-pkcs12-export", tls, "pkcs12", "-export", "-inkey", leaf_key, "-in", leaf, "-certfile", ca,
    "-passout", "pass:d2-test-password", "-out", ed / "leaf.p12")
negative = cli("stock-pkcs12-private-context-limit", tls, "pkcs12", "-in", ed / "leaf.p12", "-passin", "pass:d2-test-password",
               "-nocerts", "-noenc", "-out", ed / "bag-key.pem", expected=None)
if "unsupported private key algorithm" not in negative:
    raise SystemExit("stock PKCS12 context limitation changed; review the pinned app behavior")
receipt.identity["stock_pkcs12_key_extraction"] = "uses legacy default-context EVP_PKCS82PKEY; context-bound PKCS12_parse frontend used"
receipt.run("ed-pkcs12-key", [p12_frontend, ed / "leaf.p12", "d2-test-password", ed / "p12-key.pem", ed / "p12-native-cert.pem"], runtime)
receipt.run("ed-pkcs12-native-wrong-password", [p12_frontend, ed / "leaf.p12", "wrong", ed / "wrong-key.pem", ed / "wrong-cert.pem"], runtime, expected=1)
receipt.run("ed-pkcs12-valgrind", ["/usr/bin/valgrind", "--error-exitcode=99", "--leak-check=full", "--vgdb=no",
            "--errors-for-leak-kinds=definite,indirect,possible", "--quiet", p12_frontend, ed / "leaf.p12", "d2-test-password",
            ed / "p12-valgrind-key.pem", ed / "p12-valgrind-cert.pem"], runtime)
receipt.run("ed-p12-complete-key", [out / "bin/ed301_keyfile_check", "PEM", "private", ed / "p12-key.pem"], runtime)
for tag, key in (("original", leaf_key), ("p12", ed / "p12-key.pem")):
    cli("ed-p12-public-" + tag, tls, "pkey", "-in", key, "-pubout", "-out", ed / (tag + "-leaf-public.pem"))
if (ed / "original-leaf-public.pem").read_bytes() != (ed / "p12-leaf-public.pem").read_bytes():
    raise SystemExit("PKCS#12 extraction changed the leaf key")
cli("ed-pkcs12-cert", tls, "pkcs12", "-in", ed / "leaf.p12", "-passin", "pass:d2-test-password",
    "-nokeys", "-out", ed / "p12-cert.pem")
cli("ed-pkcs12-cert-verify", tls, "verify", *verify_options, ed / "p12-cert.pem")
negative = cli("ed-pkcs12-wrong-password", tls, "pkcs12", "-in", ed / "leaf.p12", "-passin", "pass:wrong", "-noout", expected=None)
if "Mac verify error" not in negative:
    raise SystemExit("PKCS#12 wrong-password control failed unexpectedly")

# The CA database and configuration are entirely run-local, not host policy.
(ed / "newcerts").mkdir(mode=0o700)
(ed / "index.txt").write_text("")
(ed / "serial").write_text("03\n")
(ed / "crlnumber").write_text("01\n")
config = ed / "ca-test.cnf"
config.write_text(f"""[ca]
default_ca = test
[test]
database = {ed / 'index.txt'}
new_certs_dir = {ed / 'newcerts'}
certificate = {ca}
private_key = {ed / 'private.pem'}
serial = {ed / 'serial'}
crlnumber = {ed / 'crlnumber'}
default_days = 1
default_crl_days = 1
default_md = default
policy = names
[names]
commonName = supplied
""")
cli("ed-empty-crl", tls, "ca", "-config", config, "-batch", "-gencrl", "-out", ed / "empty.crl")
cli("ed-empty-crl-verify", tls, "crl", "-in", ed / "empty.crl", "-verify", "-CAfile", ca, "-noout")
cli("ed-nonrevoked", tls, "verify", *verify_options, "-crl_check", "-CRLfile", ed / "empty.crl", leaf)
cli("ed-revoke", tls, "ca", "-config", config, "-batch", "-revoke", leaf, "-crl_reason", "keyCompromise")
cli("ed-revoked-crl", tls, "ca", "-config", config, "-batch", "-gencrl", "-out", ed / "revoked.crl")
cli("ed-revoked-crl-verify", tls, "crl", "-in", ed / "revoked.crl", "-verify", "-CAfile", ca, "-noout")
negative = cli("ed-revoked", tls, "verify", *verify_options, "-crl_check", "-CRLfile", ed / "revoked.crl", leaf, expected=None)
if "certificate revoked" not in negative:
    raise SystemExit("revocation control failed for an unexpected reason")
verify_receipt(functional)
receipt.seal()
