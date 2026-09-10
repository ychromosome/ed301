# D1 implementation boundary

The normative X301-v2 input contract is already decided. The strict local
X301-v1 core supplies API/ladder test intents; the bound integration checkout
supplies later provider/hybrid surfaces and secret-owner patterns. Neither
donor's former result or build profile is a v2 acceptance result.

D1 is a separate x301-core crate with its own workspace/lockfile. It compiles
the hash-bound Phase-C field, Montgomery-oracle and generated-field modules as
shared source modules. No arithmetic file or public Ed301 API is edited, and
there is no source copy that could silently drift. The dependency on those
adjacent modules is explicit in the manifest/provenance and review bundle;
standalone crate publication is not claimed. A later shared-crate extraction
would be a separate structural change with new gates.

The first ladder uses canonical field values and the complete 301-round
A24-minus schedule. The existing zeroize DefaultIsZeroes implementation is
used for the shared canonical field representation; raw/clamped keys, ladder
state, projective output and shared output have named zeroizing owners.
Arithmetic temporaries and compiler-made copies have no forensic erasure claim.
No new byte comparison, random generator, Big-Integer implementation or inverse
is introduced. KeyGen receives a fallible caller-provided random fill function.

Secret length and excluded-clamp validation precede public-input decoding.
Only the specified validity/error predicates and derived public-key bytes are
declassified for taint instrumentation. A successful DH result stays secret.
The public input parser validates canonical encoding, not curve membership;
low-order canonical inputs reach the full ladder and then fail without output.

The approved Phase-B Python module is not rewritten to change error precedence.
D1 tests explicitly cover the requested Secret-before-u order, in addition to
the unchanged vector corpus. All baseline and approval snapshots remain intact.

OID/codepoint allocation, Raw TLS versus Hybrid selection, persistent X301
formats and activation/deployment authority remain separately visible choices.
No provider module or TLS surface is introduced by D1.
