#!/usr/bin/env python3
"""Gap-free parallel driver for search_worker_v3.gp (ED301-v2 confirmation run).
All outputs (raw chunk files and the JSONL chunk log) go under --out, so --out fully isolates a run.
A chunk counts as completed only if the worker exited 0, printed no PARI error and wrote its raw file.
Any failure stops assignment, is reported in SUMMARY as fatal and makes the driver exit 1."""
import argparse, concurrent.futures, json, os, re, subprocess, sys, time
from pathlib import Path
HERE = Path(__file__).resolve().parent
HIT_RE = re.compile(r"^HIT=(\[.*\])$", re.M)
def run_chunk(d, wid, start, end, out):
    env = dict(os.environ, ED301_D=str(d), ED301_COUNTER_START=str(start), ED301_COUNTER_END=str(end), ED301_WORKER_ID=str(wid), ED301_OUT=str(out))
    t = time.monotonic()
    pr = subprocess.run(["gp", "-q", "-f", str(HERE / "search_worker_v3.gp")], env=env, capture_output=True, text=True)
    text = pr.stdout + pr.stderr
    raw = out / f"search_v3_d{d}_{start}_{end}_worker_{wid}.txt"
    err = [l for l in text.splitlines() if "***" in l and "Warning" not in l]
    ok = pr.returncode == 0 and not err and raw.is_file()
    return {"wid": wid, "start": start, "end": end, "sec": round(time.monotonic() - t, 1), "rc": pr.returncode, "ok": ok, "raw": raw.name, "hits": HIT_RE.findall(text), "err": err}
def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--d", type=int, required=True); ap.add_argument("--workers", type=int, default=10); ap.add_argument("--chunk", type=int, default=64); ap.add_argument("--start", type=int, default=0); ap.add_argument("--maximum", type=int, default=1_000_000); ap.add_argument("--out", default="raw_v3")
    a = ap.parse_args(); out = HERE / a.out; out.mkdir(exist_ok=True)
    log = open(out / f"search_v3_d{a.d}_from{a.start}.jsonl", "w"); nxt = a.start; completed = []; failed = []; hits = []; stop = False
    def job():
        nonlocal nxt
        if nxt > a.maximum or stop: return None
        s, e = nxt, min(nxt + a.chunk - 1, a.maximum); nxt = e + 1; return (s, e)
    with concurrent.futures.ThreadPoolExecutor(a.workers) as pool:
        pend = {}
        for w in range(a.workers):
            j = job()
            if j: pend[pool.submit(run_chunk, a.d, w, *j, out)] = w
        while pend:
            dn, _ = concurrent.futures.wait(pend, return_when=concurrent.futures.FIRST_COMPLETED)
            for f in dn:
                w = pend.pop(f); r = f.result(); log.write(json.dumps(r) + "\n"); log.flush()
                if r["ok"]:
                    completed.append((r["start"], r["end"]))
                else:
                    failed.append((r["start"], r["end"])); stop = True; print("FATAL chunk %d-%d rc=%s err=%s" % (r["start"], r["end"], r["rc"], r["err"][:3]), flush=True)
                for h in r["hits"]:
                    if r["ok"]: hits.append((r["start"], h)); stop = True; print("HIT d=%d c-range=%d-%d %s" % (a.d, r["start"], r["end"], h[:120]), flush=True)
                print("CHUNK d=%d w=%d %d-%d %.0fs ok=%s hits=%d" % (a.d, w, r["start"], r["end"], r["sec"], r["ok"], len(r["hits"])), flush=True)
                j = job()
                if j: pend[pool.submit(run_chunk, a.d, w, *j, out)] = w
    completed.sort(); contig = a.start - 1
    for s, e in completed:
        if s != contig + 1: break
        contig = e
    hits.sort()
    status = "FATAL" if failed else "OK"
    print("SUMMARY d=%d status=%s contiguous_through=%d completed_chunks=%d failed_chunks=%s hits=%s" % (a.d, status, contig, len(completed), json.dumps(failed), json.dumps(hits)), flush=True)
    sys.exit(1 if failed else 0)
if __name__ == "__main__": main()
