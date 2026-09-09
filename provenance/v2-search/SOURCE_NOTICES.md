# Source notices and preparation changes

Copyright 2026 Martin Wolf and ED301 contributors.

Project-authored material is supplied under the repository's Apache-2.0 license,
subject to existing notices. Mathematical facts and parameter values are not
claimed as copyrightable. PARI/GP, Python, Git, GNU tar, gzip, Bitcoin Core and
OpenTimestamps are external tools; their distributions and licenses are not
incorporated into this grant. No third-party software distribution is vendored
in this package.

The v3 tools and exploratory data were supplied by Martin through Claude's
ED301-v2 handoff. Codex prepared this publication package. The three executable
tool sources are byte-identical to the handoff versions:

| File | Supplied SHA-256 |
|---|---|
| `search_worker_v3.gp` | `b4ef9d0477dc45aff88d016d93a43fd6d1dadf40580c0990c68bdad56aab4ee6` |
| `search_v3.py` | `f75793113085511019615a17173475e1c1e4761a0a8b1e03b387d87521ee9368` |
| `audit_v3_template.gp` | `2b51c97369f6dff6c5fac05acb27161f652d1db37728a751292d77fd72c34ceb` |

The supplied rule draft has SHA-256
`461f7ea8c2e0a69dab3557905d8a25d0fda1089086fa4162656033988a5890a6`
and is preserved inside `exploration.tar.gz`. The publication copy was renamed
to `REGELDATEI_ED301-v2.md`. Its entire section 3, including all nine acceptance
criteria, is unchanged. Preparation changes outside that section bind the
publication/signing gate, fixed execution parameters, included archive/reference
paths, and the already specified v2 basepoint procedure. They do not change the
candidate acceptance predicate or choose a new candidate.

The original `ED301-v2_candidate_values.json` has SHA-256
`0fc28268c7b766fcef43efa2022220fb5f05e65cef883690698ac8d0603d07ea`
and is preserved byte-for-byte inside the archive. `EXPECTED_CANDIDATE.json`
contains the same JSON values with a terminal newline; its distinct file hash
is recorded in the publication manifest.

## Unchanged v1 reference documents

These copies come from Martin's ED301 technical completion archive. They retain
the old parameters and describe v1, not the v2 implementation:

| Included reference | Original source-tree file | SHA-256 |
|---|---|---|
| `reference/ED301-v1.md` | `spezifikation/ED301-v1.md` | `7ec87dfb0dc6689467e2f1ae5d832302412d1a3e161827b1885e89c681d41d68` |
| `reference/KURVENBERICHT_ED301-v1.md` | `berichte/KURVENBERICHT_ED301.md` | `6abf8c137d22bf506d3857cd1622aedd9204acea7fcc432d672f698cdd584b7f` |
| `reference/LICENSE_SCOPE.md` | `LICENSE_SCOPE.md` | `a0949691ab46500448f03a18091f8af7fbd1ff115a0c7142bd53912716298406` |
| `reference/LICENSE` | `LICENSE` | `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30` |

The original Apache-2.0 license and scope statement are retained. References
inside those historical documents to other old scripts or results describe
their original source tree; this is not a repackaging of the entire v1 review
bundle. The v2 rule's acceptance criteria are self-contained. Its inherited
point-decoding/basepoint recipe is supplied in the included v1 specification,
with the v2 substitutions stated explicitly in section 5 of the v2 rule.

Internal identifiers are versioned. Public project-name continuity does not
reassign historical OIDs or make historical keys and signatures v2-compatible.
