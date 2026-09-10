# Antwort zu E8a (Jacobi-Symbol im Import) – Claude, 10. September 2026

Emmys Beobachtung ist korrekt: crypto-bigints `jacobi_symbol` rechnet mit festem Iterationsplan, die abschließende Umwandlung in den Enum-Wert enthält eine ergebnisabhängige Verzweigung. Die Schlussfolgerung, deshalb Euler zu behalten oder den Vendor-Fork zu ändern, ist nicht nötig.

## Begründung

Die Eingabe des Imports ist ein öffentlicher Schlüssel. Das Legendre-Symbol davon ist selbst öffentlich; jeder kann es aus dem Schlüssel nachrechnen. Eine Verzweigung auf dieser Größe ist kein Seitenkanal. Die Regel "sprungfrei" gilt dem geheimen Pfad (Signieren, Skalarmultiplikation mit geheimem Skalar, X301-Leiter). Für den öffentlichen Pfad lässt das Projekt variable Laufzeit bereits ausdrücklich zu: die Verifikation nutzt wNAF als "variablen öffentlichen Pfad". Der Public-Key-Import gehört in dieselbe Klasse, unabhängig davon, ob er Euler oder Jacobi verwendet.

## Empfehlung (Option c)

1. Unverändertes `U320::jacobi_symbol` aus dem gebundenen crypto-bigint verwenden; kein Eingriff in den Vendor-Fork.
2. Im Codegen-Prüfer die Import-Symbole (`VerifyingKey::from_bytes`, `is_prime_subgroup_decoded`, `halving_terms`, die Jacobi-Aufrufe) als öffentlichen Pfad führen, wie die wNAF-Verifikation, nicht in der sprungfreien Liste.
3. In `specifications/Ed301-EdDSA-v2.md` ergänzen: "Der Import öffentlicher Schlüssel verarbeitet ausschließlich öffentliche Daten; seine Laufzeit darf vom Schlüssel abhängen. Er wird nie mit geheimem Material aufgerufen."
4. Test, der festhält, dass der Signierpfad (`sign_expanded`, `key_from_seed`) den Import-Prüfpfad nicht aufruft; Taint-Lauf bestätigt, dass kein geheimes Byte den Import erreicht.
5. Euler-Fassung als `cfg(test)`-Orakel behalten (existiert bereits mit 100 003 Vergleichswerten).

Erwartung: Import ≈ 51 µs wie im vorläufigen Vergleich gemessen.

## Verworfen

- Option a (Euler behalten): 11 µs pro Import ohne Sicherheitsgewinn.
- Option b (Vendor-Korrektur der Enum-Umwandlung): Aufwand und neue Fork-Nachweise für eine Eigenschaft, die an dieser Stelle nichts schützt.

Entscheidung: Martin.
