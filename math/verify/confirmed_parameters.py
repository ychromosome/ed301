"""Load the confirmation-search result (math/selection/search_result.json) for the proof tools."""

import json
from pathlib import Path


def load_candidate(path):
    record = json.loads(Path(path).read_text())
    if record.get("status") != "PASS":
        raise ValueError("search result has not passed record verification")
    candidate = record["candidate"]
    names = {"p", "p_hex", "d", "c", "s", "a", "A", "B", "N", "q", "Nt", "qt", "t", "DK"}
    if set(candidate) != names:
        raise ValueError("unexpected candidate fields")
    values = {key: int(value) for key, value in candidate.items() if key != "p_hex"}
    p, d = values["p"], values["d"]
    if p != 2**301 - 2**89 + 907 or candidate["p_hex"] != hex(p) or d != p - 301:
        raise ValueError("candidate field or family differs from the selected v2 rule")
    if values["c"] < 0 or values["s"] != 907 + values["c"]:
        raise ValueError("candidate counter derivation failed")
    if values["a"] != values["s"] ** 2 % p or not 0 < values["a"] < p:
        raise ValueError("candidate Edwards coefficient derivation failed")
    q, qt = values["q"], values["qt"]
    if q <= 0 or qt <= 0 or q.bit_length() != 300 or qt.bit_length() < 299:
        raise ValueError("candidate subgroup bit bounds failed")
    if values["N"] != 4*q or values["Nt"] != 4*qt or values["N"] < 2**301:
        raise ValueError("candidate order/cofactor/pruning relation failed")
    if values["N"] % 8 != 4 or values["Nt"] % 8 != 4:
        raise ValueError("candidate parity conditions failed")
    if values["N"] + values["Nt"] != 2*p + 2 or values["t"] != p + 1 - values["N"]:
        raise ValueError("candidate twist/trace relation failed")
    if values["t"] ** 2 > 4*p:
        raise ValueError("candidate Hasse bound failed")
    inverse = pow(values["a"] - d, -1, p)
    if values["A"] != 2*(values["a"] + d)*inverse % p or values["B"] != 4*inverse % p:
        raise ValueError("candidate Montgomery model relation failed")
    return values
