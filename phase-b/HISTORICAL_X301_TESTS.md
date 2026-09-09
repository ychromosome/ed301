# Historical X301 input-normalization expectations

Martin's revision-2 contract selects strict canonical external u decoding.
The following v1 integration tests are **historical and not normative for
X301-v2**. Their source checkout and fixtures are preserved unchanged; no
historical expected result has been rewritten to appear v2-compatible.

Source checkout: `/home/martin/Dokumente/ED301/x301-integration`, clean at
commit `569dc4ff10e0e5e19d106cbe490d2a5aaeac935e` when inspected.
File: `/home/martin/Dokumente/ED301/x301-integration/provider-tests/x301/provider_x301_contract.c`,
SHA-256 `808a232945293521a76acc70662273d28a50e5f81b55c8cf71d83a3f6028906d`.
The affected function is `alias_inputs_canonicalize_before_keymgmt_and_derive`
(lines 932-1048 in this snapshot), invoked under the D2 normalization label
at lines 1958-1963. Its helper `canonicalize_public_oracle` begins at line 160.

| Historical expectation | X301-v2 expectation and Phase-B control |
|---|---|
| Accept high-bit aliases and mask bits 301..303 | Reject before the first ladder step; all seven bit combinations are covered on both zero and nonzero peers |
| Import p and p+1 as 0 and 1, then fail during DH | Reject the original bytes during decoding; tests check that no ladder call occurs |
| Reduce p+2 and derive as u=2 | Reject p+2; included because reducing it could otherwise yield a nonzero accepted result |
| Reduce 2^301-1 | Reject as noncanonical before ladder entry |
| KEYMGMT import/export, equality, duplicate/set-encoded-public and paired import normalize aliases | Historical acceptance expectations are not copied; the corresponding v2 provider negative tests belong to Phase D |

The source's valid DH, lifetime, provider and hybrid-handshake test intentions
remain relevant. Marking the normalization tests historical does not discard
those surfaces. Raw-TLS-group versus Hybrid-only selection, OIDs and codepoints
remain separate Phase-D decisions. This Phase-B reference does not claim to
have changed or retested the old provider.
