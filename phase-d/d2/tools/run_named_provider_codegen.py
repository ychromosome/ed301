#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""N4 codegen on the fresh ordinary/TLS DSOs; no performance or core replay claim."""

import argparse
from pathlib import Path
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
    raise SystemExit("codegen source differs from the fresh functional build")
receipt = Receipt(args.output, args.source_sha, "named-provider-codegen")
receipt.identity.update(openssl_version=identity["openssl_version"],
    functional_receipt_sha256=args.functional_sha,
    scope="fresh ordinary/TLS DSOs under the unchanged LLVM-21 arithmetic policies; no new core benchmark")
receipt.write_identity()
for profile, variant, module in (
    ("ed", "ed-normal", "ed301_eddsa_v2"), ("ed", "ed-tls", "ed301_eddsa_v2_tls"),
    ("x", "x-normal", "x301_v2"), ("x", "x-tls", "x301_v2_tls"),
):
    binary = functional / "modules" / (module + ".so")
    if digest(binary) != identity["module_sha256"][module]:
        raise SystemExit("DSO differs from its functional receipt")
    receipt.run(module, ["/bin/sh", ROOT / "phase-e/tools/check_codegen.sh",
        profile + "-provider", binary, functional / "markers" / variant / "toolchain.txt",
        receipt.output / module])
verify_receipt(functional)
receipt.seal()
