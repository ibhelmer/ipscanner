# Tredjepartsafhængigheder og licensafgrænsning

**IP Scanner 1.1.0 · 12. oktober 2026**

`Copyright 2026 Ib Helmer Nielsen` og **Apache License 2.0** gælder projektets egen kode, tests, startfiler og dokumentation. Den uændrede licenstekst findes i `LICENSE`; ophavsangivelsen findes også i `NOTICE` og øverst i kildefilerne. Ingen tredjeparts kildekode eller binære biblioteker er medpakket.

## Scapy

Scapy installeres separat via `pip` og bruges til at opbygge, sende og modtage Ethernet-, ARP- og ICMP-pakker. Scapys egen kildekode er markeret **GPL-2.0-only**, og projektet har sin egen GPL version 2-licens. Apache-licensen i denne mappe ændrer ikke Scapys vilkår.

Kilder: [Scapy LICENSE](https://github.com/secdev/scapy/blob/master/LICENSE) og [Scapys Windows-modul med SPDX-angivelse](https://github.com/secdev/scapy/blob/master/scapy/arch/windows/__init__.py).

**Vigtigt ved videre distribution:** Apache 2.0 er ikke kompatibel med GPL version 2-only for et samlet afledt værk. Derfor må en samlet distribution, der inkluderer eller integrerer Scapy, ikke uden videre beskrives som udelukkende Apache-licenseret. En separat installation af afhængigheden er ikke i sig selv en juridisk afklaring af, om det samlede program er et afledt værk. Før offentlig distribution af en samlet pakke, Docker-container eller en eksekverbar fil med Scapy skal licensforhold og eventuelt alternativ licensering af egen kode afklares. Denne leverance tilføjer ikke en anden licens til din kode uden dit valg.

Se [Apache: GPL compatibility](https://www.apache.org/licenses/GPL-compatibility.html).

## Npcap

Npcap er Windows-pakkedriveren. Den installeres separat af brugeren og er ikke med i projektet. Npcap har egne licens- og distributionsvilkår; den er ikke dækket af projektets Apache-licens. Kontrollér vilkårene for den konkrete Npcap-udgave, især ved distribution eller installation på flere computere.

Kilde: [Npcap license](https://npcap.com/#license).

## Python og Tcl/Tk

Python og Tcl/Tk leveres ikke med projektet. De beholder deres egne licenser. Tkinter er Python-grænsefladen til Tcl/Tk og installeres ikke med `pip install tkinter`.

Kilder: [Python license](https://docs.python.org/3/license.html) og [Tcl/Tk license](https://www.tcl-lang.org/software/tcltk/license.html).
