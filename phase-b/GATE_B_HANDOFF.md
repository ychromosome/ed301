# Gate B handoff: references and byte vectors

Review scope: Phase B of Martin's implementation assignment. Gate A approved
the curve at commit `23c8feef7fd89bf0a2db0910df778f393aaf4614`; none of its
hash-bound artifacts or the signed pre-search package have been changed.
The selected Phase-B commit/archive hashes accompany the delivery separately,
avoiding a self-referential commit or manifest hash in this source file.

## Replay

From the root of a fresh checkout or extracted Git archive:

```sh
python3 -B tools/check_phase_b.py
```

Prerequisites: Python 3.10+, Node with SHAKE256, GNU sha256sum. No dependencies
are downloaded, no provider is loaded, and no external service is contacted.
The eight steps verify manifests, run 29 Python test methods and both Node
counterimplementations, and regenerate both JSON vector files byte exactly.
All secrets are public deterministic test material. The mathematical and
pre-search archives are present so their original manifest checks work too.

## Requested independent checks

1. Recalculate selected Ed301 signing cases from the approved parameters and
   SigEd301-v2 domain, including both hash transcripts, empty context and
   binary/255-byte contexts. There are 9 cases and 108 intermediate values.
2. Check the Ed301 negative corpus against the point/scalar and public-key
   rules. In particular, distinguish invalid torsion-R manipulations from
   valid cofactored equations; R has no subgroup restriction. The missing-
   nonce-domain control is deliberately a valid but nonnormative signer
   output. All 7 unchanged v1 fixture pairs are positive controls for their
   own oracle and negative cross-profile controls in both directions.
3. Recalculate selected X301 public/DH outputs and at least one twist case.
   X301's input authority is revision 2 of the byte-identical contract in
   `phase-b/inputs/`, hash-bound in the vector corpus and source manifest.
4. Check rejection before ladder entry for wrong lengths, all high-bit
   combinations, p, p+1, p+2 and 2^301-1. In particular p+2 and a high-bit
   alias of the basepoint distinguish strict decoding from reduction/masking
   that would otherwise produce an accepted nonzero result.
5. Recompute N_t, its unchanged clamp, its 64 raw aliases and the probability
   2^-298. Verify exclusion at Import/Public/Shared, resampling only for this
   error at KeyGen, and no ladder entry for excluded inputs.
6. Verify mandatory failure without return bytes for u=0,1,p-1 and for
   injected projective infinity/affine zero. Confirm 301 rounds and the
   iteration recurrence through checkpoints 1,10,100,1000.
7. Inspect the independent-language implementation boundaries. Python uses
   affine Edwards/reference Montgomery arithmetic; the Ed301 Node oracle
   uses extended Edwards coordinates and the X301 Node oracle uses a distinct
   ladder schedule. A separate Python Weierstrass/twist calculation checks
   all 24 positive X301 u evaluations. None is an independent author review.

## Scope limits

No approval is requested here for Rust, providers, codecs, constant-time
binaries, performance, OIDs, TLS codepoints or completed handshakes. Node and
Python references are variable-time and do not zeroize runtime copies.
The fixed-length library comparisons do not change that limitation.

Strict input decoding follows the RFC-8032 canonicalization principle, not
an asserted RFC-8032 DH algorithm or a claim that tolerant X448 is insecure.
Encoding uniqueness is not a general DH/TLS nonmalleability theorem.

The historical normalization tests are catalogued separately and not silently
rewritten. The hybrid/provider/TLS baseline remains for Phase D with the new
decoder contract. Raw-TLS versus Hybrid-only is still a Phase-D decision.

Expected review outcome: a report tied to the delivered commit, source
manifest and archive, with independently checked samples, weighted findings
and an explicit Gate-B approval or return. Phase C must not start before
that approval.
