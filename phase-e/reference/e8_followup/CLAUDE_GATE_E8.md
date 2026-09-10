# Gate E, Nachtrag für E8a–E8e: Freigabe

Prüfer: Claude (Fable 5.1). Datum: 11. September 2026.
Ergebnis: **Gate E ist mit E8 vollständig erteilt.** Korrektheit, Sicherheit, Nachweise und das Leistungsziel sind erfüllt: keine Kern-Lane liegt mehr messbar über v1, Import ist um die Hälfte schneller, EVP-Keygen laut Emmys Messung fast halbiert. Stufe 2 (RPMs, Installation, Aktivierung) braucht weiterhin Martins gesondertes Go.

## 1. Bindung (nachgerechnet)

| Objekt | Wert |
|---|---|
| Testing-Commit E8 | `a81eeb526579c6e8066183919a7e488bb56eeba7` (Tree `a712ea4f…`, Vorgänger `74d30ba`) |
| Archiv `ED301-v2_GATE_E_E8_2026-09-11.tar.zst` | `e6d637af6b869d02e866e6190876dbd3ef801cb21d50a63d5f8aa6bc2e08085c` |
| `BUNDLE_MANIFEST.json` | `480bf5f9991b569c593b3469e9b65f0c9408bf492983bb36b8ed5d811a7e415a` |
| `phase-e/E8_FINAL_HANDOFF_SOURCE_MANIFEST.sha256` | im Checkout mit `sha256sum --check` bestätigt (1945 Einträge) |

## 2. Eigene Prüfungen (Belege `gate_c/e/gate_e8/`, Testvektoren wie bei Gate C, D1 und E)

1. **Differentialtests gegen meine Implementierungen** auf dem E8-Baum: EdDSA 1301/1301, X301 296/296, Untergruppenprüfung 400/400 (Punkte mit und ohne Torsionsanteil). Crate-Tests 65/65 und 57/57.
2. **E8a, Jacobi:** `is_nonzero_square` nutzt jetzt das unveränderte crypto-bigint `jacobi_symbol`; die Euler-Fassung bleibt als Testorakel (100 003 Vergleiche). Konstante `LEGENDRE_WORDS` = (p−1)/2 per Compile-Zeit-Assertion gegen den Modulus geprüft. **Aufrufgraph:** Der Prüfpfad (`ValidatedPublicKey::from_bytes` → `is_prime_subgroup_decoded` → `halving_terms`/`is_nonzero_square`) wird nur beim Import externer öffentlicher Schlüssel aufgerufen (Provider `sig_ffi.rs` Zeilen 349, 374, 428). Signieren, Expansion und der eigene Public Key des Providers laufen über `scalar_mul_base(_pruned)` und `validated_public_key()` ohne diese Prüfung. Zusätzlich sichert `audit_public_import` unter Taint-Instrumentierung, dass die Importbytes keine undefinierten V-Bits tragen. Codegen-Policy (Abschnitt "E3/E8a: public-only import boundary") und Spezifikation ("Public-key import processes only public data; its running time may depend on the key") sind entsprechend ergänzt.
3. **E8b, Rundenumordnung:** Code entspricht meinem Patch R1; 301 Runden, Swap und Fehlerpfade unverändert.
4. **E8c, Verifikationstabelle:** neue Typen `ValidatedPublicKey` (ohne Tabelle) und `VerifyingKey` (mit Tabelle, `prepare()`); im Provider `PublicKeyMaterial` mit einmaliger, fehlbarer Materialisierung hinter einem Mutex. Externe Schlüssel bleiben streng geprüft.
5. **E8d, Zeroisierung:** `commitment_point`, `public_point` in `secret(...)`, Inverse der Kodierung in einem eigenen Besitzer `EncodingInverse`; Tests zählen die Löschungen auf normalem Rückweg und bei Unwind (2 beim Expand, 4 nach Sign; Inverse in allen drei Fällen).
6. **E8e, Parameter:** unbekannte `OSSL_PARAM`-Schlüssel werden ignoriert; bekannte, nicht unterstützte Modi (Digest, Instance, Prehash, Nonce-Typ, KEM-Operation/IKME, ECDH-Cofactor/KDF-Parameter, Gruppen-/Bitparameter beim Keygen) weiterhin abgewiesen. Entspricht OSSL_PARAM(3).
7. **Eigener Disassembly-Scan:** Geheimer Pfad unverändert (`ladder301` ein Rückwärtssprung, 60 cmov; `double`, `add_affine`, `conditional_select`, `negate` sprungfrei; Expansion und Festbasis nur feste Schleifen). Öffentlicher Importpfad enthält jetzt Sprünge und Divisionen aus dem Jacobi-Algorithmus, wie in der Policy als öffentlicher Pfad deklariert.
8. **Eigene Messung** (gleiche CPU, verschränkt, Host mit VM und zweitem Codex belastet), v1 gegen E8: X301 shared 57,6 / 58,6 µs, public 27,6 / 27,8; Ed301 expand 27,9 / 28,1, sign 29,1 / 29,3, verify 87,5 / 84,1, import 98,3 / 51,0. Die Differenzen bei shared, public, expand und sign liegen unter 2 % und innerhalb der Laufstreuung; verify −4 %, import −48 %. Emmys ABI-Läufe: shared +1,0 / +2,0 %, sonst gleich oder besser.

## 3. Zweites Bein

Emmys Paketprüfer aus der frischen Extraktion mit nativem Replay und TCP: `bundle_verification=PASS`, **92/92**.

## 4. Befunde

Keine hohen oder mittleren. Niedrig: Die Zahl 92/92 ist dieselbe wie bei E7, obwohl Tests hinzukamen; das ist die Zählung der Replay-Schritte, nicht der Testfälle. Für die nächste Übergabe die Testfallzahlen der Crates (65/57) mit nennen, damit das nicht als "keine neuen Tests" gelesen wird.

## 5. Entscheidung und nächste Schritte

Gate E erteilt. Das Leistungsziel gilt als erreicht: keine Lane messbar langsamer als v1, zwei deutlich schneller. Offen für Stufe 2: N2 (Stock-CLI im Standard-Libctx nach Aktivierung), N4 (Benennung `_test`), N5 (Vertragssatz zur Gruppenwahl) aus Gate D, RPMs wie v1, Ablösung der v1-Pakete, Veröffentlichung der Gate-Archive als Release-Assets. Das zweite externe Review läuft auf diesem Stand.
