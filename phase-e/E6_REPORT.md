# E6: DER-encoding overhead is encoder discovery, not seed expansion

Result: the proposed seed-re-expansion cause is **disproved for the measured
same-provider DER path** on both OpenSSL 3.5.8 and 4.0.2. No runtime change is
made. In particular, explicit key validation is not weakened, algorithm
aliases/OIDs are not removed, and the benchmark boundary is not shortened.
E6's conditional instruction to fix redundant expansion therefore does not
apply. This report diagnoses the original Gate-D N3 result using its actual
sealed binaries; the final Phase-E provider matrix must be measured anew.

## Evidence and method

The new source-bound profiler runs the unchanged, sealed Gate-D codec
benchmark under Callgrind, with one and ten loop iterations, separately for
v1 and v2. It checks all three input receipts before and after execution and
records binary/library/source/runner hashes, commands, raw call graphs and
complete annotations. Only fresh generated test keys in private libctx are
used. No key bytes are printed. Valgrind elapsed time is **not** a benchmark.

Every run has one setup encode/decode/equality check outside its timer.
Both generations and ABIs give exactly:

| Call | One loop iteration | Ten loop iterations |
| --- | ---: | ---: |
| Encoder context construction | 2 | 11 |
| Encoder output / provider encoding / private-byte getter, each | 2 | 11 |
| Rust key import, from the initial decode | 1 | 1 |
| Key validation | 0 | 0 |
| Encoder cross-provider import | 0 | 0 |

Increasing the encoding work by nine operations adds no key import or key
validation. The provider encoder calls the private-byte getter, which copies
the already stored seed. OpenSSL passes the existing provider key object
directly when the keymgmt and encoder providers match. Its import callback
is for cross-provider object conversion, not this path.

## Where the additional work occurs

For each new encoder context, OpenSSL collects all keymgmt names and scans
available encoders, including the default provider's encoders. The v1 TLS
provider advertises its versioned name and OID (two aliases). v2 advertises
the public project name, versioned name and OID (three aliases). The second
provider scan therefore performs 723 versus 482 name tests per operation;
three additional encoder-chain tests in each give totals 726 versus 485.
The callback counts prove the 3:2 alias inventory in both ABI lanes.

Subtracting the one-iteration run from the ten-iteration run removes the
one-time initialization contribution. Dividing by nine gives the following
warm-path instruction estimates (not nanoseconds):

| ABI | Context construction v1 | Context construction v2 | DER output v1 = v2 |
| --- | ---: | ---: | ---: |
| 3.5.8 | 483932 | 656979 | 5074 |
| 4.0.2 | 372038 | 524041 | 4219 |

Context instructions increase by about 35.8% / 40.9%. About 99.6% of that
extra context work lies in `collect_encoder`, where the additional alias
causes additional name lookup. This explains the mechanism behind N3; it
does not assert that every observed wall-clock percentage equals an
instruction-count percentage. The DER output itself has identical counts.

The lookup loop and same-provider object shortcut were checked in the exact
official source archives carried by the input receipts. The encoder source
SHA-256 is `c58a280b14ec56acb719591136abdfba399cea2c28315ff30151ff652c1d16cc`
for 3.5.8 and `fc57d60e5315a82a565a6492b46f9a2316c3a94b0ddb8e1552a9f33aab9c1bab`
for 4.0.2. The two versions differ there only in an allocation helper and
the new context-frozen flag, not in the relevant discovery/import loops.

Reusing an encoder context would measure a different lifecycle; removing an
alias would alter discovery/API contracts. Neither is done to improve the
score. There is no E6 runtime before/after speedup to report because the
runtime inputs are unchanged. The original v1/v2 paired wall-clock result
is retained, and the complete final matrix will report the optimized cores.

## Receipts

3.5.8:
`/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e6_d2-profile-3.5.8_02_2026-09-10`

Summary SHA-256: `f4795e67295e1cdafc92a36bd1becaf34ca7a1b31c1b9bda9f201e80e9622e60`.
Receipt SHA-256: `42132d66b6d4dfb7753e6f81f3b41e867dd676793c7663f2ba2cc90774ad532a`.

4.0.2:
`/home/martin/Dokumente/ED301/ED301-v2_PHASE_E_e6_d2-profile-4.0.2_2026-09-10`

Summary SHA-256: `79c9726d46664ea15452611b9ffac6c704f6573856e22961571d714fc466c1e4`.
Receipt SHA-256: `023241a0e8bddc609199706ddddc065b092f9458cb3aa78c576e6c74dcaf72e7`.
Profiler SHA-256: `c1094004a0b33b2fd8fa0de4a93ff9081a37f8c28cc60aef326f49b84ad67e47`.

The first profiler attempt expected the v2 C symbol prefix in v1 and stopped
at its call-inventory assertion. The parser now matches the common exact
function suffix; the failed preparation output is retained separately and
is not a passing receipt. An earlier GDB probe could not attach under the
local ptrace restriction; the completed evidence uses Callgrind instead.
