# X301-v2 – Eingabevertrag für externe u-Werte (Entscheidung für Phase B)

Stand: 10. September 2026, Fassung 2 (Emmys Präzisierungen und die v1-Sonderablehnung k = N_t aufgenommen). Entscheidung: Martin. Empfänger: Emmy.
Leitlinie: **Orientierung an Ed448 (RFC 8032), nicht an X448 (RFC 7748).** Damit ist die
letzte offene Vertragsfrage von Phase B entschieden.

## Entscheidung

X301-v2 übernimmt den **strikten, kanonischen Vertrag** (bisheriger `x301-github`-Stand und
X301-v1-Spezifikation §11.1), **nicht** die Maskierungs-/Reduktionsregel des
`x301-integration`-Stands.

## Die fünf Vertragspunkte

1. **Dekodierung von u.** Genau 38 Byte, little-endian. Bits 301..303 müssen null sein
   (`u[37] & 0xe0 == 0`), und der Integer muss kleiner als p sein. Jede Verletzung ist ein
   Fehler **vor dem ersten Leiterschritt**. Es wird nicht maskiert und nicht reduziert.
   Dieselbe Regel wie für Feldelemente in ED301-v2 §6.1 und wie die Punktdekodierung in
   RFC 8032 §5.2.3 („if the resulting value is ≥ p, decoding fails“).
2. **Eigener Skalar.** 38-Byte-Secret, Clamping unverändert wie X301-v1:
   `k[0] &= 0xfc`, `k[37] = (k[37] & 0x0f) | 0x10`, also `2^300 ≤ k < 2^301`, `4 | k`.
   Das Clamping ist die einzige Eingabeveränderung im gesamten Vertrag und betrifft nur das
   eigene Geheimnis.
   **Sonderablehnung k = N_t (übernommen aus X301-v1 §6.2):** Die Twistordnung
   `N_t = 4·q_t` liegt unter 2^301, erfüllt alle Clamp-Bitbedingungen und bildet jeden
   Twistpunkt auf den Punkt im Unendlichen ab. Ein Secret, dessen geklampter Skalar gleich N_t
   ist, wird in KeyGen (neu ziehen), Import, Public und Shared abgelehnt, konstantzeitig
   verglichen. Für v2:
   `N_t = 4074071952668972172536891376818756322102936786019054572921615708584947563249005641551956612`,
   little-endian `84ca911e62530d13b204a5718d1a9ada9621c5ffffffffffffffffffffffffffffffffffff1f`.
   Ablehnungswahrscheinlichkeit bei gleichverteiltem Secret 2^−298.
3. **Leiter.** Montgomery-Leiter über genau 301 Bit (führende Nullen eingeschlossen),
   `A24_minus = (A − 2)/4` aus dem Gate-A-Parametersatz, Minus-Konvention, konstantzeitig
   bezüglich des Skalars. Twist-Eingaben werden verarbeitet (Twist-Sicherheit ist nachgewiesen),
   nicht erkannt.
4. **Ergebnisprüfung.** Ein All-Zero-Ergebnis ist ein Fehler ohne Teilausgabe (MUST, wie
   RFC 8446 §7.4.2 es für TLS verlangt). Die Prüfung erfolgt konstantzeitig.
5. **Ausgabe.** 38 Byte `FE(u_shared)`, kanonisch, Bits 301..303 null. Ein Nullergebnis wird
   nie ausgegeben.

## Einordnung gegenüber den Standards, so in die Spezifikation aufnehmen

- Ed448 (RFC 8032 §5.2.3) dekodiert strikt: y ≥ p ist ein Fehler, S ≥ L ist ungültig.
  ED301-v2 und X301-v2 folgen dieser Regel für alle 38-Byte-Kodierungen.
- X448 (RFC 7748 §5) verlangt dagegen: „Implementations MUST accept non-canonical values and
  process them as if they had been reduced modulo the field prime.“ X301-v2 weicht von diesem
  Toleranzgebot **bewusst** ab. RFC 7748 bindet nur X25519 und X448; die Toleranz dient der
  Interoperabilität fremder Implementierungen, die X301 nicht hat.
- Folgen der Abweichung, die die Spezifikation nennen muss: X301-v2 ist kein Drop-in für
  X448-Erwartungen; jedes u hat genau eine akzeptierte Bytekodierung (das betrifft die
  Kodierung eines Feldwerts, nicht DH- oder TLS-Malleabilität im Allgemeinen); der frühe
  Dekoderfehler hängt nur von öffentlichen Eingaben ab und verrät keinen Skalar, ersetzt aber
  keine Konstantzeitprüfung der anschließenden Leiter.
- Formulierung für die Spezifikation (Emmy): „X301-v2 übernimmt die strikten Kodierungsregeln
  nach dem Vorbild von RFC 8032 und verwendet eine Montgomery-Leiter nach dem
  Konstruktionsmuster von RFC 7748.“ Die strikte Dekodierung ist Vertragsklarheit, kein
  behaupteter kryptographischer Sicherheitsgewinn gegenüber der toleranten X448-Regel.
- Die All-Zero-Prüfung ist in RFC 7748 §6.1 ein MAY und in TLS 1.3 ein MUST; X301-v2 macht sie
  unbedingt zur Pflicht.

## Konsequenzen für Phase B

- Referenz `x301.py`: strikter Dekoder, Clamping, 301-Bit-Leiter, All-Zero-Fehler, wie oben.
- Vektoren: positive DH-Vektoren beider Richtungen, Iterationsvektor wie v1, Twist-u,
  **Negativvektoren** für u ≥ p (z. B. `FE(p)`, `FE(p+1)`, `FE(2^301−1)`), gesetzte Bits 301..303,
  falsche Länge (37 und 39 Byte), und die All-Zero-Fälle (u = 0, u = 1, u = p − 1, kleine
  Torsion), jeweils mit Erwartung „Fehler ohne Ausgabe“.
- Gegenimplementierung: muss dieselben Eingaben ablehnen; ein Vektor, den die
  Gegenimplementierung reduziert statt ablehnt, gilt als Fehlschlag.
- Die Tests des `x301-integration`-Stands, die Maskierung/Reduktion erwarten, werden nicht
  übernommen; sie widersprechen dem Vertrag und sind als historisch zu kennzeichnen.
  Die Hybrid-/TLS-Integration aus `x301-integration` bleibt für Phase D Bezugsstand für
  Provider und Handshake, mit dem Dekoder nach diesem Vertrag.

## Nicht Teil dieser Entscheidung

OIDs, TLS-Codepoints, die Raw-TLS-Gruppe aus `x301-github` versus Hybrid-only aus
`x301-integration` (Phase D), Performance.
