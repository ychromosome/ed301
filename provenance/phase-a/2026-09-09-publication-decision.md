# ED301 v2 search rule: pre-run publication

This prerelease publishes the reviewed rule package before the formal
confirmation search. It is not a cryptographic implementation release and does
not report a completed confirmation run.

Bound artifacts:

- Signed tag: `v2-search-rule-2026-09-09`
- Annotated tag object: `6d48ac5f584263c7fde3afd347c9b93debe3b224`
- Reviewed commit: `0bf9b5936737fc920d701815cf55cfd35c54d288`
- Package: `provenance/v2-search/`
- SHA-256 of `RUN_MANIFEST.sha256`:
  `a9c210823af851675678117d401415b54c2ad0cad8bb4ab47ce94f669acae313`
- SHA-256 of `REGELDATEI_ED301-v2.md`:
  `b5e9c6d49641f2181c3d5635b7827814c799d924ffcfbc7cdbeb9bbb61cdab7a`

## Author's publication-gate amendment, 9 September 2026

Martin explicitly waived the OpenTimestamps/Bitcoin requirement and authorized
creating this GitHub prerelease, checking its server-side publication time, and
then starting A2. This decision supersedes only the OTS prerequisite in the
signed package's publication instructions. No Bitcoin attestation or second
independent timestamp is claimed.

The signed tag, reviewed commit, mathematical acceptance criteria, tools,
execution parameters and manifest remain unchanged. The pre-run publication
evidence is this public GitHub release and its `published_at` value, archived
together with the signed tag identity before A2 begins. It is not the client-set
commit/tag date or GitHub's `created_at` field.

The selected prediction remains d=-301, c=246492, a=247399^2. The prior exploration
is disclosed in the signed package. The new run must independently reproduce
the first valid counter from zero; later mathematical, implementation and
review gates remain in force.
