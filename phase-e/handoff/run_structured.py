#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Replay the existing structured-contract tests on sealed Phase-E DSOs."""

import argparse
from pathlib import Path
import shutil
import sys

SOURCE_SHA = "16e13fc68b35812c553b6659f3101b4e956b57d6f980ce9819216205536deb8a"

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--evidence", type=Path, required=True)
parser.add_argument("--functional", type=Path, required=True)
parser.add_argument("--functional-sha", required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
root = args.evidence.resolve(strict=True)
sys.path.insert(0, str(root / "source/phase-d/d2/tools"))
from d2_common import Receipt, digest, verify_receipt

functional = args.functional.resolve(strict=True)
if digest(functional / "SHA256SUMS") != args.functional_sha:
    raise SystemExit("functional receipt digest mismatch")
identity = verify_receipt(functional)
if identity["source_manifest_sha256"] != SOURCE_SHA:
    raise SystemExit("structured and functional stages must use one source snapshot")
receipt = Receipt(args.output, SOURCE_SHA, "structured-contract-replay")
controller_sha = digest(Path(__file__).resolve())
shutil.copy2(Path(__file__).resolve(), receipt.output / "CONTROLLER.py")
version = identity["openssl_version"]
prefix = functional / "openssl/inst" / version
runtime = dict(receipt.clean, OPENSSL_CONF="/dev/null",
               OPENSSL_MODULES=str(functional / "modules"),
               LD_LIBRARY_PATH=str(prefix / "lib"),
               ED301V2_EXPECT_OPENSSL_PREFIX=str(prefix),
               X301_STRUCTURED_SWEEP="1")
receipt.identity.update(
    openssl_version=version, functional_receipt_sha256=args.functional_sha,
    controller_sha256=controller_sha,
    controller_scope="post-build orchestration of unchanged sealed native tests",
    inputs="existing deterministic local contract-test inputs only",
    network=False)
receipt.write_identity()
receipt.run("raw", [functional / "bin/provider_x301_contract", functional / "modules"], runtime)
receipt.run("hybrid", [functional / "bin/provider_x301_hybrid_contract", functional / "modules"],
            dict(runtime, X301_HYBRID_ALLOC_SWEEP="1"))
verify_receipt(functional)
if digest(Path(__file__).resolve()) != controller_sha:
    raise SystemExit("controller changed during execution")
receipt.seal()
