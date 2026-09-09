# Repository workflow

This repository uses case-sensitive branch names:

- `Testing`: active development and preparation work.
- `Review`: an explicitly selected, review-ready snapshot from `Testing`.
- `main`: the completed product only, promoted after the applicable review gates
  and Martin's explicit release approval.

Do not develop on, push unfinished work to, reset, or force-push `main`.
Do not replace the development role of `Testing` with `Review`. Keep review
findings and subsequent corrections traceable; do not rewrite published review
snapshots or signed provenance tags.

Before a commit or push, check the current branch, worktree, and destination.
Preserve unrelated user changes. A review-ready snapshot is not a product release.

Public project names remain Ed301-EdDSA and X301. Internal v2 profile identifiers
and new OIDs remain distinct from all historical v1 identities.

For v2 Phase A, the formal confirmation search must not start before the agreed
signed publication and external timestamp checks, followed by Martin's go-ahead.
Martin creates his own GPG-signed tag; do not use his signing key on his behalf.
Public push permission is not permission to sign, publish a product release,
change the mathematical selection rule, or begin a later gated phase.
