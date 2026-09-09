# Historische Quellbytes für Belegmanifeste

Die fünf SHA-256-benannten Dateien sind unveränderte historische Quellstände,
die ältere Messmanifeste referenzieren. Ihr Dateiname ist ihr Inhalts-Hash.
Sie werden nicht als aktive Programme, aktuelle Tests oder neue Gate-Pässe benutzt.

Der Paketprüfer löst einen historischen Quellmanifest-Eintrag zuerst gegen den
passenden aktuellen Quellhash auf, sonst gegen den gleichnamigen Archivblob.
Jeder einzelne Eintrag muss exakt passen. Die vollständigen historischen
Quellstände sind damit offline rekonstruierbar, ohne mehrfach identische
Vendor-Bäume beizulegen. Die unabhängigen v1-Importrepositories sind zusätzlich
als vollständige commitgenaue Snapshots und Git-Bundles enthalten.

Betroffen sind der frühere Benchmarkvertrag, ein früher Vier-Fall-Taint-Runner,
der unveränderte v1-Taint-Harness, der erste noch unformatierte Timing-Adapter
und der Zwischenbericht vor Aufnahme der erweiterten Matrix. Die aktuelle
Produktarithmetik wird durch diese Archivkopien nicht ersetzt.
