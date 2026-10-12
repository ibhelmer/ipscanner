# Ændringslog

## 1.1.0 — 12. oktober 2026

### Windows-netkort

Netkortlisten samler nu Scapys interfaces, Windows-adapteroplysninger fra Scapys Windows API og det lokale resultat fra `Get-NetAdapter -IncludeHidden`/`Get-NetIPAddress`. PowerShell-output læses som JSON; kommandoerne er faste, read-only og kører uden ændring af Execution Policy.

Netkort uden IPv4, med ugyldig/manglende MAC, inaktive kort og kort, som ikke er tilgængelige gennem Npcap, skjules ikke længere. De vises med status og begrundelse. Et negativt `is_valid()`-flag alene bruges ikke længere til at skjule et interface. Genkendelige Windows-blokeringer, manglende pakkedriver, loopback/tunnel og manglende gyldig kildeadresse forhindrer scanning.

GUID og interface-index kobler kilder sammen. Delte MAC-adresser bruges ikke til at sammenlægge netkort, da fysiske og virtuelle kort kan dele MAC. Ingen Npcap-interfaceidentifikator opfindes for kort, som kun Windows viser. Netkort med flere IPv4-adresser får separate valg. Windows-netmasker bruges, når de er tilgængelige; netmasken gættes ikke.

Nye funktioner: **Netkort / diagnostik**, gembar rapport, `--list-adapters`, `--diagnostics FIL` og `diagnostic_windows.cmd`. Netkortvalg og mål bevares ved opdatering, når det valgte interface/IP stadig findes. Windows-listen kan stadig vises, selv om Scapy ikke kan importeres, hvis Windows' egen forespørgsel lykkes.

### CSV og licens

Ny **CSV-format**-knap med forklaring, separatorer, tegnsæt, aliaser, anførselstegn, fejl og forskellen på tildelingsfil og eksport. Eksempler kan gemmes fra programmet. Den samme beskrivelse findes i `CSV_FORMAT.md` og README. Blanke overskrifter og flere alias-kolonner for samme logiske felt afvises nu tydeligt.

Tilføjet `Copyright 2026 Ib Helmer Nielsen`, Apache 2.0-kildeheader, `LICENSE`, `NOTICE` og `THIRD_PARTY_NOTICES.md`. Om-dialogen viser ophav og licens og er gjort scrollbar.

## 1.0.0 — 12. oktober 2026

Første version: Tkinter-GUI, ARP-scanning med Scapy, ICMP-verifikation, tildelingskontrol via CSV, producentopslag, eksport og syntetisk demotilstand.
