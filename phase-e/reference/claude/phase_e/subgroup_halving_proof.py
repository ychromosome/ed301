#!/usr/bin/env python3
"""Claude, 2026-09-10: subgroup membership for ED301-v2 via one halving instead of [q]A.

Uses Claude's own affine Edwards arithmetic (gate_b_independent_check.py header), not any
reference module. Ground truth: P in 4E  <=>  [q]P = O  (E(F_p) cyclic of order 4q).

Criteria (derived in the accompanying note):
  P in 2E  <=>  P = T  or  chi(B * (1 - y^2)) = +1          (chi = Legendre symbol; B nonsquare)
  P in 4E  <=>  P in 2E  and  Q in 2E for a halving Q of P, where y_Q^2 = t is the root of
               d(Y+1) t^2 - 2(dY+a) t + a(Y+1) = 0  that reproduces Y under doubling,
               and Q in 2E  <=>  chi(B * (1 - t)) = +1.
"""
import json, random, sys
from pathlib import Path
own = (Path(__file__).resolve().parent.parent.parent / "gate_b_independent_check.py").read_text().splitlines()
src = "\n".join(own[:57]).replace("R='/tmp/claude-1000/-home-martin-Projekte-Claude-OpenSSL-Fork/6f22a499-c749-43d5-95c3-537696cbf897/scratchpad/ed301pub'", f"R={sys.argv[1]!r}")
ns = {}; exec(src, ns)
p, a, d, q, A, B, G, eadd, emul, on, inv, pt_enc = (ns[k] for k in ("p", "a", "d", "q", "A", "B", "G", "eadd", "emul", "on", "inv", "pt_enc"))
O = (0, 1); T = (0, p - 1); s = 907 + 246492; P4 = (inv(s), 0); assert on(P4) and emul(2, P4) == T and emul(4, P4) == O
def chi(z):
    z %= p
    if z == 0: return 0
    return 1 if pow(z, (p - 1) // 2, p) == 1 else -1
def sqrt(z):
    r = pow(z % p, (p + 1) // 4, p); return r if r * r % p == z % p else None
print("chi(B) =", chi(B), "(criterion needs -1)"); assert chi(B) == -1
print("chi(a-d) =", chi(a - d), " chi(d) =", chi(d), " chi(a) =", chi(a))
def in2E_truth(P): return emul(2 * q, P) == O
def in4E_truth(P): return emul(q, P) == O
def in2E(P):
    x, y = P
    if P == O: return True
    if P == T: return True
    return chi(B * (1 - y * y)) == 1
def halving_t(P):
    """Both roots t of d(Y+1)t^2 - 2(dY+a)t + a(Y+1) = 0. Exactly one is y_Q^2 of a rational
    halving; the other belongs to a point over F_{p^2}. No selection is needed because
    (1-t1)(1-t2) = (a-d)(Y-1)/(d(Y+1)) and chi of that is chi(d(a-d)) = +1 for P in 2E."""
    _, Y = P
    delta = (a - d) * (a - d * Y * Y) % p
    sd = sqrt(delta)
    if sd is None: return None
    den = inv(d * (Y + 1) % p)
    roots = [((d * Y + a) + sg * sd) * den % p for sg in (1, -1)]
    for t in roots: assert (Y * (d * t * t - 2 * d * t + a) + (d * t * t - 2 * a * t + a)) % p == 0
    return {"delta": delta, "sqrt_delta": sd, "roots": roots}
assert chi(d * (a - d)) == 1, "curve property needed for selection-free test"
def in4E(P):
    if P == O: return True
    if P == T: return False
    if not in2E(P): return False
    info = halving_t(P)
    assert info is not None, "P in 2E must be halvable"
    t1, t2 = info["roots"]
    c1, c2 = chi(B * (1 - t1)), chi(B * (1 - t2))
    assert c1 == c2 and c1 != 0, ("roots must agree", c1, c2)
    # rational halving exists for exactly one root: y_Q^2 square and x_Q^2 square
    rat = [chi(t) == 1 and chi((1 - t) * (a - d * t)) == 1 for t in (t1, t2)]
    assert rat.count(True) == 1, ("exactly one rational halving root", rat)
    # sqrt-free reformulation of the same symbol: chi(B * d * (Y+1) * ((d-a) - s))
    _, Y = P; s_ = info["sqrt_delta"]
    assert chi(B * d * (Y + 1) * ((d - a) - s_)) == c1
    return c1 == 1
rng = random.Random(301)
n = 0; classes = {}
samples = [(k, tor) for k in [1, 2, 3, 4, q - 1, q - 2, q - 3, q - 4, 12345] for tor in (O, T, P4, emul(3, P4))]
for _ in range(120):
    samples.append((rng.randrange(1, q), rng.choice([O, T, P4, emul(3, P4)])))
for k, tor in samples:
    P = eadd(emul(k, G), tor)
    if P == O: continue
    t2, t4 = in2E_truth(P), in4E_truth(P)
    assert in2E(P) == t2, ("2E criterion failed", k, tor)
    assert in4E(P) == t4, ("4E criterion failed", k, tor)
    classes[(t2, t4)] = classes.get((t2, t4), 0) + 1; n += 1
print("points checked:", n, "classes (in2E,in4E):", classes)
# torsion points explicitly
for name, P, e2, e4 in (("T", T, True, False), ("P4", P4, False, False), ("-P4", emul(3, P4), False, False)):
    assert in2E(P) == e2 and in4E(P) == e4, name
print("torsion points: T in 2E not 4E; P4, -P4 in neither: OK")
# vectors for Emmy: 24 points with intermediates
vec = []
for k, tor, label in [(rng.randrange(1, q), tor, lab) for tor, lab in ((O, "prime-order"), (T, "plus-T"), (P4, "plus-P4"), (emul(3, P4), "plus-3P4")) for _ in range(5)] + [(1, O, "G"), (q - 1, O, "-G"), (2, P4, "2G+P4")]:
    P = eadd(emul(k, G), tor); x, y = P
    w = B * (1 - y * y) % p; e2 = in2E(P)
    rec = {"label": label, "encoded_hex": pt_enc(P).hex(), "y_decimal": str(y), "w_decimal": str(w), "chi_w": chi(w), "in_2E": e2, "in_4E": in4E(P), "in_4E_truth": in4E_truth(P)}
    if e2 and P != T:
        info = halving_t(P); rec.update({"delta_decimal": str(info["delta"]), "sqrt_delta_decimal": str(info["sqrt_delta"]), "roots_decimal": [str(r) for r in info["roots"]], "chi_B_1_minus_t_both_roots": [chi(B * (1 - t)) for t in info["roots"]]})
    vec.append(rec)
for name, P, lab in (("T", T, "T"), ("P4", P4, "P4")):
    vec.append({"label": lab, "encoded_hex": pt_enc(P).hex(), "y_decimal": str(P[1]), "in_2E": in2E(P), "in_4E": in4E(P), "in_4E_truth": in4E_truth(P)})
out = {"schema": "ED301-v2-subgroup-halving-vectors-claude-v1", "curve": "ED301-v2 (Gate-A parameters)", "B_decimal": str(B), "chi_B": chi(B), "d_decimal": str(d), "criterion_2E": "P==T or chi(B*(1-y^2))==1", "criterion_4E": "in_2E and chi(B*(1-t))==1 for either root t of d(Y+1)t^2-2(dY+a)t+a(Y+1)=0 (delta=(a-d)(a-dY^2), both roots give the same symbol because chi(d(a-d))=+1); equivalently chi(B*d*(Y+1)*((d-a)-sqrt(delta)))==1", "chi_d_times_a_minus_d": chi(d * (a - d)), "vectors": vec}
Path(sys.argv[2]).write_text(json.dumps(out, indent=1) + "\n")
print("vectors written:", len(vec), "->", sys.argv[2])
print("PASS: halving criterion equals [q]P = O on every sample")
