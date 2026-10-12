# Testresultater — IP Scanner 1.1.0

**Dato: 12. oktober 2026**

## Resultat

**107 testmetoder fundet: 100 bestået, 7 eksplicit sprunget over, 0 fejl.**

Sluttesten er kørt efter de sidste ændringer i programkoden:

```bash
python -m py_compile ipscanner.py tests/*.py
xvfb-run -a python -m unittest discover -s tests -v
```

Miljø: Python 3.13.5, Linux og Tkinter med Xvfb-display. Den komplette testlog findes i `testlog.txt`.

## Nye regressionstests

**Windows-inventar og sammenlægning:** syntetiske Scapy-interfaceobjekter, Windows-API-data og PowerShell-JSON med nul, ét og flere netkort/IP-adresser. GUID-matching, index-fallback, flere kort med samme MAC uden sammenlægning, native Windows-only-kort, inaktive kort, kort uden IPv4, IPv6-only, Npcap fraværende, manglende MAC/IP, flere kilde-IP'er med forskellige præfikser, fejl ved route-opdatering, negativt Scapy-validitetsflag, loopback/tunnel, duplicate/tentative IP-status, importfejl og delvist fejlede OS-forespørgsler. Kommando, timeout og fravær af `shell=True` er kontrolleret med mocks.

**CSV:** nye tests af blanke overskrifter, tvetydige aliaser for samme kolonne, dokumenterede anførselstegns-/semikolon-eksempler, afvisning af subnet/interval/IPv6/værtsnavn i tildelingsfilen, ombyttede/ekstra kolonner og afvisning af UTF-16.

**GUI:** copyright og licens i Om-vinduet, CSV-hjælp, gemning af gyldig eksempel-CSV, synlige men blokerede netkort, deaktiveret scanningsknap for uegnede kort, bevarelse af netkortvalg og mål ved opdatering, diagnostiktekst og scrollbare hjælpevinduers oprettelse/lukning.

## Eksisterende funktioner

De tidligere tests af IPv4-input, intervalgrænser, CSV-import/-eksport, dubletter, fejlbeskeder, formelbeskyttelse, numerisk sortering, scanmotor, genforsøg, stop, delresultater, ICMP-status, alarmer og GUI-responsivitet består fortsat.

Demoen og de nye hjælpevinduer er åbnet, og brugerfladen er visuelt kontrolleret ved **1240 × 810** og **1040 × 720** pixel. Resultattabellen har scrollbar ved den mindre størrelse. `gui_demo.png` og `gui_csv_help.png` er skærmbilleder af det faktiske program med syntetiske data, ikke dokumentation for Windows- eller netværksfunktion.

CLI-demo er også kontrolleret med `--demo --list-adapters` og `--version`.

## Ikke verificeret

**Windows, PowerShell-cmdlets og Npcap er ikke live-testet.** Windows-opslag er testet med syntetiske API-/JSON-svar. Mocks dokumenterer programlogikken, ikke den faktiske opførsel på brugerens Windows-maskine eller med konkrete netkort/driverbindinger. Windows-startfilerne er ikke eksekveret på Windows.

**De 7 Scapy-pakkeintegrationstests er ikke kørt**, fordi Scapy ikke kunne installeres i dette miljø. Testene ligger i `tests/test_scapy_packets.py` og bruger rigtige Scapy-pakkeobjekter, men mocker `srp()`, så de ikke sender trafik. De aktiveres, når Scapy er installeret.

Ingen fysisk ARP-/ICMP-scanning er udført. Status **Kan forsøges** er kun en forudsætningskontrol, ikke bevis for en fungerende pakkedriver eller et svarende netværk.

## Lokal validering på Windows

Kør `diagnostic_windows.cmd` og sammenlign navn/index med `Get-NetAdapter -IncludeHidden`. Kontrollér særligt fysiske Ethernet-/Wi-Fi-kort, virtuelle interfaces, et deaktiveret kort og et kort uden IPv4. Gennemgå `Netkort / diagnostik` for eventuelle kildefejl.

Vælg derefter et aktivt Ethernet-/Wi-Fi-interface med gyldig IPv4/MAC og Scapy/Npcap-adgang. Scan et kendt, autoriseret lokalt subnet, sammenhold med kendte enheder, og afprøv CSV-alarm og stop. Følg README for installation, øvrige tests og fejlretning.
