\\ ED301-v2 search worker, final form for the confirmation run.
\\ Inputs (environment): ED301_D, ED301_COUNTER_START, ED301_COUNTER_END, ED301_WORKER_ID, ED301_OUT.
\\ Rule: p = 2^301 - 2^89 + 907, s = 907 + c, a = s^2 mod p; the criteria below are checked in
\\ exactly the order of REGELDATEI_ED301-v2 section 3.
default(parisize, 268435456);
default(parisizemax, 2147483648);
default(recover, 0);

p = 2^301 - 2^89 + 907;
d = eval(getenv("ED301_D"));
counter_start = eval(getenv("ED301_COUNTER_START"));
counter_end = eval(getenv("ED301_COUNTER_END"));
worker_id = eval(getenv("ED301_WORKER_ID"));
out_dir = getenv("ED301_OUT");
if (counter_start < 0 || counter_end < counter_start, error("invalid counter range"));
if (kronecker(d, p) != -1, error("d is not a quadratic nonresidue"));

mov_small_pass(base, subgroup_order) = {
  my(v = Mod(1, subgroup_order), multiplier = Mod(base, subgroup_order));
  for (k = 1, 100, v *= multiplier; if (v == 1, return(0)));
  return(1);
};

test_candidate(c) = {
  my(s = 907 + c, a, A, B, a2, a4, E, N, N_twist, q, q_twist, t, D_K);
  a = lift(Mod(s, p)^2);
  \\ (1) Edwards completeness conditions
  if (a == 0 || a == lift(Mod(d, p)), return(0));
  if (kronecker(a, p) != 1, return(0));
  \\ (2) Montgomery model, twist-secure ladder
  A = lift(Mod(2 * (a + d), p) / Mod(a - d, p));
  B = lift(Mod(4, p) / Mod(a - d, p));
  if (A == 2 || A == p - 2 || B == 0, return(0));
  if (kronecker(A^2 - 4, p) != -1, return(0));
  \\ (3) j-invariant
  a2 = lift(Mod(A * B, p));
  a4 = lift(Mod(B^2, p));
  E = ellinit([0, Mod(a2, p), 0, Mod(a4, p), 0]);
  if (E.j == Mod(0, p) || E.j == Mod(1728, p), return(0));
  \\ (4) exact orders; tors=-2 aborts early on small odd divisors of either order
  N = ellsea(E, -2);
  if (N == 0, return(0));
  N_twist = 2*p + 2 - N;
  if (N % 8 != 4 || N_twist % 8 != 4, return(0));
  q = N / 4;
  q_twist = N_twist / 4;
  \\ (5) subgroup bit lengths: main subgroup exactly 300 bits (4q >= 2^301), twist >= 299
  if (logint(q, 2) + 1 != 300, return(0));
  if (logint(q_twist, 2) + 1 < 299, return(0));
  \\ (6) primality of both subgroup orders (proven: isprime is APR-CL / ECPP)
  if (!ispseudoprime(q) || !ispseudoprime(q_twist), return(0));
  if (!isprime(q) || !isprime(q_twist), return(0));
  \\ (7) no small embedding degree k <= 100
  if (!mov_small_pass(p, q) || !mov_small_pass(p, q_twist), return(0));
  \\ (8) Hasse, not anomalous
  t = p + 1 - N;
  if (t^2 > 4*p || N == p || N_twist == p, return(0));
  \\ (9) large fundamental CM discriminant
  D_K = coredisc(t^2 - 4*p);
  if (abs(D_K) <= 2^100, return(0));
  return([c, s, a, A, B, N, q, N_twist, q_twist, t, D_K]);
};

hits = List();
t0 = getwalltime();
for (c = counter_start, counter_end, candidate = test_candidate(c); if (candidate != 0, listput(hits, candidate); print("HIT=", candidate)));
elapsed_ms = getwalltime() - t0;
fd = fileopen(Str(out_dir, "/search_v3_d", d, "_", counter_start, "_", counter_end, "_worker_", worker_id, ".txt"), "w");
filewrite(fd, Str("rule=REGELDATEI_ED301-v2 section 3, worker search_worker_v3.gp"));
filewrite(fd, Str("d=", d));
filewrite(fd, Str("counter_start=", counter_start));
filewrite(fd, Str("counter_end=", counter_end));
filewrite(fd, Str("tested=", counter_end-counter_start+1));
filewrite(fd, Str("elapsed_ms=", elapsed_ms));
filewrite(fd, Str("hits=", Vec(hits)));
fileclose(fd);
print("worker_id=", worker_id, " range=", counter_start, "-", counter_end, " elapsed_ms=", elapsed_ms, " hits=", #hits);
quit;
