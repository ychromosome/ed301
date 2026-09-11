# D2 integration contract

This describes the local test integration, not system deployment or a release.
The original Stage-1 checks use private library contexts. The separately
authorized N2 checks below use process-default contexts only in isolated
child test processes with run-local configuration.
The authoritative decision is
/home/martin/Dokumente/ED301/ed301/phase-d/d2/inputs/D1_BEWERTUNG_UND_D2_ENTSCHEIDUNGEN_2026-09-10.md.
The source/build/test receipts and the final D2 report determine which paths
have actually been executed. A declared capability alone is not evidence of
a successful handshake.

## Modules and public operations

The Rust provider workspace is
/home/martin/Dokumente/ED301/ed301/provider/Cargo.toml.
Each feature variant is built into its own module file; the ordinary module
does not acquire the diagnostic surfaces of a test artifact.

| Module basename | Operations beyond the shared raw key operations |
| --- | --- |
| `ed301_eddsa_v2` | KEYMGMT and pure, whole-message SIGNATURE |
| `ed301_eddsa_v2_pki_test` | Ed301 PKCS#8/SPKI encoders |
| `ed301_eddsa_v2_tls` | Ed301 codecs, text output and TLS-SIGALG |
| `ed301_eddsa_v2_tls_collider` | Separate same-generation collision fixture; no private decoder |
| `ed301_eddsa_v2_failpoint` | Explicitly injected allocation/panic failures; no TLS |
| `x301_v2` | KEYMGMT and KEYEXCH |
| `x301_v2_pki_test` | X301 PKCS#8/SPKI encoders |
| `x301_v2_tls` | X301 codecs/text plus hybrid KEYMGMT/KEM and two TLS groups |
| `x301_v2_failpoint` | Explicitly injected allocation/panic failures |

The N4 naming follow-up removes the `_test` suffix only from the two TLS
module names. Their former basenames are not compatibility aliases. The
TLS-SIGALG selection/display name is now `ed301_eddsa_v2`; its numeric
SignatureScheme remains `0xFE85`. OIDs, algorithm names and NamedGroups are
unchanged. PKI experiment, collision and failpoint artifacts remain distinct;
the new names do not by themselves authorize installing or activating them.

Public algorithm names are `Ed301-EdDSA`, `X301` and `X301MLKEM1024`.
The old alias `MLKEM1024X301` is not offered. The Ed301 generation path uses
`EVP_PKEY_CTX_new_from_name`, `EVP_PKEY_keygen_init` and `EVP_PKEY_generate`;
the inherited Ed301 adapter does not advertise generation parameters, so
OpenSSL's `EVP_PKEY_Q_keygen` convenience path is not part of this profile.

The arithmetic is the subsequently optimized and reviewed E8 implementation,
with the original Ed301 and X301 encoding and protocol contracts retained.
The v1 adapters provide the C dispatch/lifetime patterns, not v2 constants
or expected cryptographic outputs. The shared allocation, random-generator
and codec adapters are under /home/martin/Dokumente/ED301/ed301/provider/common.
They contain no replacement hash, big-integer, ML-KEM or encryption primitive.

## Context ownership and discovery order

Create a private `OSSL_LIB_CTX`, set its verified build-module directory,
load the required providers, and only then call `SSL_CTX_new_ex` with that
same context. Configure the TLS version, signature and groups explicitly.
An already-created `SSL_CTX` does not acquire the missing provider capability
caches retroactively; it must be replaced by a fresh context.

The checked loader in
/home/martin/Dokumente/ED301/ed301/provider-tests/v2_generation_policy.h
accepts a closed list of standard and v2 test modules. The application owns
and serializes all context configuration. It rejects legacy names and
unknown preloaded modules before a v2 load. Its contract requires the names
to refer to the hash-verified module files. It is not an interposer on
`OSSL_PROVIDER_load`: unrelated application code can bypass it, and a v2 DSO
cannot change the behavior of an unchanged v1 DSO loaded later by such code.
No supported integration co-loads both generations in one context.

OpenSSL's OID/SIGID registry is process-global, despite private library
contexts. The Ed301 test integration checks the exact numeric OID, names and
digestless SIGID before/after registration and rejects conflicting mappings.
The generation-isolation tests use the exact bound v1 donors in separate
contexts; this does not authorize arbitrary third-party provider mixtures.

## TLS selection and wire values

The integration default in
/home/martin/Dokumente/ED301/ed301/provider-tests/v2_tls_policy.h
is the explicit `SSL_CTX_set1_groups_list(ctx, "X301MLKEM1024")` policy.
Stock OpenSSL `DEFAULT` is unchanged and includes neither custom group.
The provider cannot silently amend that built-in list.

| Component | v2 wire value | Meaning |
| --- | --- | --- |
| CertificateVerify | `0xFE85` | Ed301-EdDSA-v2, TLS 1.3 only |
| Hybrid NamedGroup | `0xFE2F` | X301MLKEM1024; recommended integration choice |
| Raw NamedGroup | `0xFE30` | X301; explicit experimental test/measurement path only |

Raw X301 has no ML-KEM protection and is never in the integration default.
Without explicit raw selection, a raw-only peer must fail or a mutually
configured non-raw group must be selected. Both client and server roles are
tested. These are private-use allocations, not IANA registrations.

When both groups are explicitly enabled, the tested OpenSSL lanes follow the
client's key-share order: a raw-first client can negotiate Raw X301 even if
the server lists Hybrid first. To enforce Hybrid, the server must enable only
Hybrid and omit Raw; server preference alone does not enforce that policy.

The hybrid delegates ML-KEM-1024 to OpenSSL in the provider child context:

| Value | Layout |
| --- | --- |
| Client key share | ML-KEM public key 1568 bytes, then X301 public 38 bytes |
| Server key share | ML-KEM ciphertext 1568 bytes, then X301 public 38 bytes |
| Shared key material | ML-KEM shared 32 bytes, then X301 shared 38 bytes |

There is no additional hybrid KDF or persistent hybrid-key format. TLS owns
the subsequent key schedule. Invalid X301 encodings and all-zero results
fail without a partial caller output. ML-KEM implicit rejection remains
OpenSSL-owned and is tested separately from hard X301 rejection.

## File and PKI boundaries

The identifiers are recorded in
/home/martin/Dokumente/ED301/ed301/docs/OID_REGISTRY.md.
Both v2 AlgorithmIdentifiers are parameterless: Ed301 uses `.301.5`, X301
uses `.301.6`. SPKI is exactly 58 DER bytes with 38 public bytes. PrivateKeyInfo
is exactly 62 DER bytes, version INTEGER 0, with a nested OCTET STRING of the
38 original private bytes. X301 does not export its clamped working copy.
Attributes, version 1, alternate OIDs, noncanonical profile DER and trailing
bytes are outside the profile.

A low-level decoder consumes one object from a BIO chain. It does not own
the entire original file, including the bytes inside an encrypted wrapper.
The complete-file boundary therefore lives in
/home/martin/Dokumente/ED301/ed301/provider-tests/v2_file_boundary.h.
It checks the complete plain/decrypted profile object and the outer buffer,
using OpenSSL ASN.1/PEM/PBE APIs, before running the real generic decoder
chain. This test integration deliberately decrypts twice. The key-file
utility /home/martin/Dokumente/ED301/ed301/provider-tests/provider_keyfile_check.c
also bounds test files to 8 KiB. It is not a general-purpose container parser.
The surrounding PBE algorithm policy remains OpenSSL's, not a new X301
cryptosystem. Canonical low-order X301 public values can be imported; using
them for DH is where the specified all-zero rejection occurs.

Generic X.509/CSR verification does not pass all AlgorithmIdentifier details
to the signature provider. The strict object prechecks in
/home/martin/Dokumente/ED301/ed301/provider-tests/strict_pki.h
are therefore mandatory for the all-Ed301 test PKI profile. The TCP harness
checks every certificate through its verification callback. Generic
cross-algorithm chains and ordinary CLI `verify` are interoperability tests,
not a claim that libssl or the provider alone enforces this extra profile.

Raw 38-byte seeds are not self-describing. Feeding the same seed bytes to
v1 and v2 intentionally derives different profile keys; a raw byte string
cannot identify its historical owner. The OIDs, serialized objects, public
keys/signatures and TLS codepoints provide the tested version boundaries.

## CLI isolation and permitted effects

The historical Stage-1 CLI invocations that load v2 set `OPENSSL_TEST_LIBCTX=1`.
The pinned 3.5.8/4.0.2 app sources create a private context and apply explicit
`-provider` arguments to it. This is a test-only facility, not a promise about
unverified future OpenSSL releases.

The stock `pkcs8` application still calls legacy PBES2 helpers using the
process default context. The CLI receipt supplies a run-local configuration
that enables only OpenSSL's built-in `default` provider there. It contains
no v2 module entry. The v2 provider loads remain in the private app context.
Other acceptance runners use `OPENSSL_CONF=/dev/null`.

Loaded CSRs are another distinct stock-app boundary: their nested
`X509_PUBKEY` can retain the process default context. The run-local frontend
/home/martin/Dokumente/ED301/ed301/provider-tests/provider_csr_cli.c
reads the profile-checked embedded public bytes through OpenSSL's ASN.1
accessors, imports them explicitly in the private context, and verifies the
unchanged signed request. It does not rewrite the CSR before verification.
The stock `req -verify` limitation is recorded, not represented as provider
success or worked around by enabling v2 globally.

Likewise, the stock PKCS#12 application's key-dumping code calls the legacy
default-context `EVP_PKCS82PKEY`. The frontend
/home/martin/Dokumente/ED301/ed301/provider-tests/provider_pkcs12_cli.c
instead initializes a context-bound `PKCS12` object and calls OpenSSL's own
`PKCS12_parse`, including MAC verification, key/leaf matching and ordinary
encoder output. It implements no bag parser or cryptographic primitive.

The authorized N2 runner is
/home/martin/Dokumente/ED301/ed301/phase-d/d2/tools/run_default_context_cli.py.
It omits OPENSSL_TEST_LIBCTX and all explicit -provider options, and selects
a newly generated OPENSSL_CONF solely in each child process. That private
configuration activates default and the two bound TLS modules in that
process's default library context. It never edits host configuration or
installs modules. The stock req -verify, x509 -req, and Ed301/X301 PKCS12
private-key extraction paths are checked directly, without the private
frontends. A small observer verifies context/provider identity only; it does
not parse or repair any key, request or container for the stock applications.
The new receipt, not this description, establishes whether N2 passed.

All sockets bind project-owned `127.0.0.1:0` listeners. Keys and certificates
for connections/CLI runs are generated afresh and are not committed. No
system installation, system configuration edit, remote connection, push,
publication or RPM/policy activation is part of Stage 1. Existing v1
repositories and packages are not taken offline by this work. Stage 2 still
requires Gate D and Martin's separate approval.
