#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Freeze explicitly listed primary references; replay never downloads anything."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

SOURCES = {
    "rfc8032.txt": "https://www.rfc-editor.org/rfc/rfc8032.txt",
    "rfc7748.txt": "https://www.rfc-editor.org/rfc/rfc7748.txt",
    "rfc8446.txt": "https://www.rfc-editor.org/rfc/rfc8446.txt",
    "rfc8032-errata.html": "https://www.rfc-editor.org/errata/rfc8032",
    "rfc7748-errata.html": "https://www.rfc-editor.org/errata/rfc7748",
    "rfc8446-errata.html": "https://www.rfc-editor.org/errata/rfc8446",
    "NIST.FIPS.202.pdf": "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf",
    "fips202-publication-and-notes.html": "https://csrc.nist.gov/pubs/fips/202/final",
    "efd-twisted-extended.html": "https://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended.html",
    "safecurves.html": "https://safecurves.cr.yp.to/",
    "safecurves-complete.html": "https://safecurves.cr.yp.to/complete.html",
    "safecurves-twist.html": "https://safecurves.cr.yp.to/twist.html",
    "safecurves-ladder.html": "https://safecurves.cr.yp.to/ladder.html",
    "massif-manual.html": "https://valgrind.org/docs/manual/ms-manual.html",
    "gnu-time-manual.html": "https://www.gnu.org/software/time/manual/time.html",
}
HOSTS = {urlparse(url).hostname for url in SOURCES.values()} | {"errata.rfc-editor.org"}
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("output", type=Path)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=False)


def download(item):
    name, url = item
    request = Request(url, headers={"User-Agent": "ED301-private-review-source-freeze/1.0"})
    with urlopen(request, timeout=45) as response:
        final = response.geturl()
        if urlparse(final).scheme != "https" or urlparse(final).hostname not in HOSTS:
            raise RuntimeError("unexpected reference redirect")
        data = response.read(10 * 1024 * 1024 + 1)
        if not 1000 <= len(data) <= 10 * 1024 * 1024:
            raise RuntimeError(f"unexpected reference length: {name}")
        if name.endswith(".pdf") and not data.startswith(b"%PDF-"):
            raise RuntimeError("FIPS download is not a PDF")
        if name.endswith(".txt") and name[3:7].encode() not in data:
            raise RuntimeError("RFC download lacks RFC number")
        record = {"file": name, "requested_url": url, "final_url": final,
                  "retrieved_utc": datetime.now(timezone.utc).isoformat(),
                  "http_status": response.status, "headers": dict(response.headers.items()),
                  "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    (args.output / name).write_bytes(data)
    print(f"FROZEN: {name} {record['sha256']}", flush=True)
    return record


with ThreadPoolExecutor(max_workers=4) as executor:
    records = list(executor.map(download, SOURCES.items()))
(args.output / "SOURCES.json").write_text(json.dumps(records, indent=2) + "\n")
(args.output / "NOTICE.txt").write_text(
    "Unmodified primary-source snapshots for private offline technical review.\n"
    "Original notices and terms remain in effect; the project Apache-2.0 license\n"
    "does not relicense these standards, errata, formula pages or manuals.\n"
    "RFC errata include all returned statuses, not only Verified records.\n"
    "Remote site navigation/assets are not mirrored; authoritative text is retained.\n"
    "A frozen reference is not a claim that Ed301 is a named standardized algorithm.\n")
files = sorted(p for p in args.output.iterdir() if p.is_file())
(args.output / "SHA256SUMS").write_text("".join(
    f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in files))
print(f"PASS: {len(records)} primary reference snapshots at {args.output}", flush=True)
