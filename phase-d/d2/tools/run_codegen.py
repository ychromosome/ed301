#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Apply the explicit x86-64 codegen policy to the linked ordinary/TLS DSOs."""

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from d2_common import ROOT, TOOLS, Receipt, digest, verify_receipt

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
    raise SystemExit("codegen and functional stages must use one source snapshot")
receipt = Receipt(args.output, args.source_sha, "provider-codegen-x86-64")
receipt.identity.update(openssl_version=identity["openssl_version"],
                        functional_receipt_sha256=args.functional_sha,
                        scope="classified critical arithmetic and zeroization symbols in linked DSOs; not a universal CT proof")
receipt.write_identity()
for profile, variant, module in (
    ("ed", "ed-normal", "ed301_eddsa_v2"), ("ed", "ed-tls", "ed301_eddsa_v2_tls_test"),
    ("x", "x-normal", "x301_v2"), ("x", "x-tls", "x301_v2_tls_test"),
):
    receipt.run(module, ["/bin/sh", TOOLS / "check_provider_codegen.sh", profile,
                         functional / "modules" / (module + ".so"),
                         functional / "markers" / variant / "toolchain.txt", receipt.output / module])
verify_receipt(functional)
receipt.seal()
