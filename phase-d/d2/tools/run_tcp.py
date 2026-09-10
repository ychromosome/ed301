#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run only the bound owned-loopback TCP harness from a passed functional build."""

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from d2_common import Receipt, digest, verify_receipt

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--source-sha", required=True)
parser.add_argument("--functional", type=Path, required=True)
parser.add_argument("--functional-sha", required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
functional = args.functional.resolve(strict=True)
if digest(functional / "SHA256SUMS") != args.functional_sha:
    raise SystemExit("functional receipt digest mismatch")
identity = verify_receipt(functional)
if identity["source_manifest_sha256"] != args.source_sha:
    raise SystemExit("TCP and functional stages must use one source snapshot")
receipt = Receipt(args.output, args.source_sha, "owned-loopback-tcp")
prefix = functional / "openssl/inst" / identity["openssl_version"]
runtime = dict(receipt.clean, OPENSSL_CONF="/dev/null", OPENSSL_MODULES=str(functional / "modules"),
               LD_LIBRARY_PATH=str(prefix / "lib"), ED301V2_EXPECT_OPENSSL_PREFIX=str(prefix))
receipt.identity.update(openssl_version=identity["openssl_version"],
                        functional_receipt_sha256=args.functional_sha,
                        endpoints="127.0.0.1:0 listeners owned by this test process",
                        foreign_connections=False)
receipt.write_identity()
log = receipt.run("tcp", [functional / "bin/provider_tls_tcp"], runtime)
print(log, end="", flush=True)
verify_receipt(functional)
receipt.seal()
