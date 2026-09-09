# ED301-v2: pre-run publication package

This is a review-ready **precommitment package**, not a completed confirmation
run, not an implementation, and not a product release. The selected candidate is
`d = -301`, `c = 246492`, `a = 247399^2 = 61206265201` over
`p = 2^301 - 2^89 + 907`.

An exploratory search already found that candidate. The upcoming computation is
a public, reproducible **confirmation run after disclosed exploratory work**;
it is not an unseen first selection or a retroactive pre-search commitment.

## Contents and binding

- `REGELDATEI_ED301-v2.md`: the nine acceptance criteria and deterministic order.
- `search_worker_v3.gp`, `search_v3.py`, `audit_v3_template.gp`: exact reviewed
  tools, copied without code changes from Claude's handoff.
- `RUN_PARAMETERS.json`: fixed invocation and confirmation-success requirements.
- `TOOL_VERSIONS.txt`: the prepared reference environment; actual run evidence
  must confirm these versions or obtain a separately reviewed manifest.
- `EXPECTED_CANDIDATE.json`: the disclosed exploratory prediction, not a source
  of replacement results if the confirmation run disagrees.
- `EXPLORATION.md`, `exploration.tar.gz`: historical searches, controls, audits,
  and their limits. No exploratory result is counted as a new run result.
- `reference/`: unchanged v1 specification and report needed to interpret the
  inherited rules; historical v1 parameter values do not define the v2 curve.
- `SOURCE_NOTICES.md`: source digests and attribution.
- `RUN_MANIFEST.sha256`: hashes of this fixed publication package, including
  parameters and version information. It intentionally does not hash itself.

From this directory, verify the package with:

```sh
sha256sum --check RUN_MANIFEST.sha256
```

Paths in this package are repository-relative. The repository's initial license
commit is retained. `Testing` is the development branch, `Review` is the review
snapshot, and `main` remains reserved for the finished product. The provenance
tag may point to the approved `Review` commit; it need not point to `main`.

## A1: publication and signing, before any confirmation search

1. Claude reviews the exact package and manifest. Record the approved commit and
   manifest SHA-256; subsequent changes require a new review and new hashes.
2. Martin personally creates and verifies an annotated GPG-signed tag on that
   exact commit, then pushes the tag. A suggested tag prefix is
   `v2-search-rule-`; its date must be the actual publication date.
3. Publish a GitHub **prerelease** explicitly described as a search-rule
   precommitment, not a released cryptographic implementation. Use immutable
   releases/tag protection where available. Record the release ID, URL,
   `published_at`, signed tag object, target commit, and manifest hash.
   GitHub's `created_at` is not a reliable publication-time field.
4. Timestamp the unchanged manifest with OpenTimestamps. Save the initial `.ots`
   receipt immediately. Upgrade and verify its Bitcoin attestation before A2
   when using it as the second pre-run timestamp. A pending calendar submission
   alone is not a completed Bitcoin timestamp proof.
5. Archive the complete receipt and verification evidence in a later commit or
   separate evidence artifact. Never move the original tag or modify the
   originally timestamped manifest to add the receipt to itself.
6. Martin gives an explicit go-ahead for A2 only after the publication and
   timestamp evidence has been checked. No command in this package overrides
   that gate. Signing is Martin's action, not an assistant action.

Timestamp references: [GitHub release API](https://docs.github.com/en/rest/releases/releases#get-the-latest-release),
[immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases),
[OpenTimestamps client](https://github.com/opentimestamps/opentimestamps-client#usage).
The Python OTS client's independent verification requires Bitcoin Core; record
the actual verifier and trust assumptions rather than substituting a calendar
acknowledgement for verification.

## A2 and A3: instructions only, not executed by this publication

After A1 and Martin's go-ahead, verify the exact tagged package. Create a new,
empty execution directory outside this checkout. Copy only the rule file and
the three reviewed tools into it, verify their manifest hashes against the
approved package, and confirm the tool versions. Do not copy exploratory output.

Run the command specified in `RUN_PARAMETERS.json` there, capturing stdout,
stderr, start/end times and the process exit status separately. All block files
and the JSONL log belong under that run's fresh `raw_v3/` directory. Do not reuse
a result directory or rerun over its files.

`status=OK` only means no worker failure was reported. Confirmation additionally
requires checked raw metadata, gap-free coverage from zero through the winning
block, and the numerically smallest valid counter. Parse candidate integers;
do not infer numeric order from textual sorting. A no-hit run, an incomplete
range, or any mismatch with the disclosed prediction is not a successful
confirmation. Preserve and investigate discrepancies rather than replacing
the computed result with the prediction.

For A3, derive `ED301_D`, `ED301_C`, `ED301_Q`, and `ED301_QT` from the verified
confirmation result, and set `ED301_OUT` to a new audit-output directory. Run
the bound audit template, retain its exit status and log, and check every
required criterion as well as the unique final pass marker. In particular,
the template reports the `j` exclusions; the search worker enforces them.

Phase A is complete only after the additional certificates, independent order
witnesses, deterministic v2 basepoint, specification and report pass Gate A.
OID numbers, TLS codepoints and the final X301 integration baseline are not
assigned by this package.
