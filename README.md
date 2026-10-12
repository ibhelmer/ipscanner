# IP Scanner — Python, Tkinter og Scapy

**Version 1.1.0 · 12. oktober 2026 · Python 3.10 eller nyere**

**Copyright 2026 Ib Helmer Nielsen · Apache License 2.0 for egen projektkode.** Se [LICENSE](LICENSE), [NOTICE](NOTICE) og [tredjepartslicenser](THIRD_PARTY_NOTICES.md).

GUI-baseret løsning til opgaven i **IPscanner(1).docx**. Programmet finder IPv4-adresser, der besvarer ARP-forespørgsler på det valgte netkort. Det viser IP- og MAC-adresse, tilbyder lokal producentidentifikation og ICMP-verifikation og kan sammenholde fund med en CSV-fil over tildelte adresser.

Programmet foretager en scanning pr. tryk på **Start scanning**. Resultaterne er et øjebliksbillede, ikke en kontinuerligt opdateret overvågningstjeneste.

**Kildekodeudgave på GitHub:** Program, tests, dokumentation, licenser og Windows-startfiler er med. De to dokumentationsskærmbilleder fra ZIP-udgaven er ikke inkluderet her. Brugerfladen kan afprøves med `python ipscanner.py --demo`.

## 1. Filer i pakken

| Fil | Indhold |
|---|---|
| `ipscanner.py` | Hele programmet: validering, CSV, Scapy-backend, scanmotor og GUI. |
| `requirements.txt` | Python-afhængigheden `scapy>=2.6.1,<3.0`. |
| `tildelte_ip_eksempel.csv` | Eksempel på tildelte IP-adresser; tilpas til dit eget net. |
| `install_windows.cmd` | Opretter `.venv` og installerer Python-afhængigheden. |
| `start_windows.cmd` | Starter programmet med Python fra `.venv`. |
| `demo_windows.cmd` | Starter syntetisk demo; kræver hverken Scapy eller Npcap. |
| `tests/` | Automatiske tests af input, CSV, scanning, GUI og Scapy-pakker. |
| `docs/TESTRESULTATER.md` | Hvad der er testet, og hvad der ikke er verificeret. |
| `CSV_FORMAT.md` | Detaljeret formatbeskrivelse af tildelingsfil og resultateksport. |
| `diagnostic_windows.cmd` | Gemmer og åbner netkortdiagnostik uden scanning. |
| `LICENSE`, `NOTICE` | Apache 2.0 og copyright til Ib Helmer Nielsen. |
| `THIRD_PARTY_NOTICES.md` | Afhængighedernes egne licenser og distributionsforbehold. |
| `CHANGELOG.md` | Versionshistorik. |

## 2. Installation på Windows

### Forudsætninger

Installér **Python 3.10 eller nyere** med **Tcl/Tk / Tkinter**. Ved en almindelig Python-installation til Windows kan Tcl/Tk vælges i installationsprogrammet. Tkinter installeres ikke med `pip install tkinter`.

Installér derefter **Npcap** fra [Npcaps officielle side](https://npcap.com/#download). Npcap er pakkedriveren, Scapy bruger til Ethernet/ARP på Windows; den følger ikke med ZIP-filen. Scapys aktuelle installationsvejledning anbefaler, at **WinPcap compatibility mode er slået fra**. Almindelig scanning på et tilsluttet Wi-Fi-net kræver ikke monitor mode. Se [Scapy: Windows-installation](https://scapy.readthedocs.io/en/stable/installation.html#windows).

### Installation med de medfølgende startfiler

Udpak hele ZIP-filen til en almindelig mappe. Kør `install_windows.cmd`. Scriptet opretter et virtuelt miljø i `.venv` og installerer Scapy; det installerer ikke Npcap.

Start derefter `start_windows.cmd`. Til faktisk pakkescanning anbefales **Kør som administrator**, som i [Scapys startvejledning](https://scapy.readthedocs.io/en/stable/usage.html#starting-scapy). Kravet om forhøjede rettigheder afhænger også af Npcaps adgangsindstillinger. Der foretages ingen automatisk rettighedsforhøjelse i programmet.

### Manuel installation i PowerShell

Åbn PowerShell i den udpakkede projektmappe:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Start en PowerShell som administrator, gå til samme projektmappe, og kør:

```powershell
.\.venv\Scripts\python.exe ipscanner.py
```

Det er ikke nødvendigt at aktivere miljøet med `Activate.ps1`: kommandoerne bruger direkte miljøets Python. Der skal derfor ikke ændres i PowerShell Execution Policy.

Kontrollér Tkinter med:

```powershell
.\.venv\Scripts\python.exe -m tkinter
```

Det skal åbne et lille Tk-testvindue. Se også [Pythons Tkinter-dokumentation](https://docs.python.org/3/library/tkinter.html) og [venv-dokumentationen](https://docs.python.org/3/library/venv.html).

## 3. Installation på Debian/Ubuntu

Kør fra et grafisk skrivebord; en ren SSH-terminal uden grafisk videresendelse kan ikke vise Tkinter-vinduet.

```bash
sudo apt update
sudo apt install python3 python3-venv python3-tk libpcap-dev
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Demo, uden forhøjede rettigheder:

```bash
.venv/bin/python ipscanner.py --demo
```

Faktisk scanning kræver rettigheder til pakkesockets. I en grafisk session, som tillader det, kan programmet startes med:

```bash
sudo .venv/bin/python ipscanner.py
```

GUI-adgang under `sudo` kan være begrænset af desktop-/Wayland-/X11-opsætningen. Ændr ikke generelt adgangskontrollen til skrivebordet eller rettighederne for en system-Python for at omgå dette. Brug en passende administreret grafisk session. Windows og Linux er ikke live-netværkstestet i denne leverance; se testresultaterne.

## 4. Brug

### Netkort på Windows

Version 1.1.0 viser **alle netkort, som de tilgængelige datakilder rapporterer**, også deaktiverede netkort, kort uden IPv4 og kort, som ikke kan bruges til ARP. Windows-inventaret indhentes fra Scapys Windows API og en fast, lokal PowerShell-forespørgsel med `Get-NetAdapter -IncludeHidden` og `Get-NetIPAddress`, og sammenholdes med Scapys faktiske pakkeinterfaces. [Microsofts dokumentation](https://learn.microsoft.com/en-us/powershell/module/netadapter/get-netadapter) beskriver `-IncludeHidden`; uden den indstilling viser kommandoen som udgangspunkt kun synlige adaptere.

Et netkort i Windows-listen er ikke nødvendigvis tilgængeligt gennem Npcap. Scanning kræver en gyldig IPv4-adresse, en Ethernet-MAC og adgang til netkortet gennem Scapy/pakkedriveren. Der bruges ikke længere `is_valid()` som et filter, der skjuler hele interfacet; usikre statusflag fremgår i stedet af diagnostikken. Der opfindes ikke en Npcap-identifikator for et kort, som pakkedriveren ikke har registreret.

| Visning | Betydning |
|---|---|
| **Kan forsøges** | De kontrollerede forudsætninger er til stede. Det er ikke en live-test af pakker eller driver. |
| **Ikke klar** | En kendt blokering forhindrer scanning. Begrundelsen vises under netkortvalget og i diagnostik. |

**Netkort / diagnostik** viser navn, beskrivelse, interface-index, GUID, Scapy-identifikator, IPv4, MAC, subnet, eventuelle IPv6-adresser, Windows-status, datakilder og fejl. Rapporten kan gemmes. Ingen oplysninger uploades. Den indeholder lokale netværksoplysninger, så gennemgå den før deling.

**Opdater netkort** genindlæser alle kilder. Det valgte interface/IP og målinterval bevares, hvis kombinationen stadig findes. Windows-forespørgslen ændrer ikke netkort, IP-adresser, driverbindinger eller Execution Policy. Hvis PowerShell/API-adgang fejler, bruges de øvrige kilder, og diagnostikken viser en advarsel om manglende/ufuldstændige data.

Vælg det Ethernet- eller Wi-Fi-netkort, som er tilsluttet målnettet. Netkort med flere IPv4-adresser vises som separate netkort/IP-kombinationer. Knappen **Brug netkortets subnet** bruger Windows’ præfikslængde eller et direkte tilsluttet net fra Scapys routingtabel; programmet gætter ikke en `/24`-netmaske.

Indtast et mål i et af disse formater:

| Format | Eksempel |
|---|---|
| IPv4-subnet i CIDR-format | `192.168.1.0/24` |
| Enkelt IP-adresse | `192.168.1.10` |
| Inklusivt interval med to fulde adresser | `192.168.1.10-192.168.1.50` |
| Kort interval i samme /24-adresserum | `192.168.1.10-50` |

`192.168.1.17/24` normaliseres til `192.168.1.0/24`. For CIDR-net fra `/0` til `/30` udelades netværks- og broadcastadressen. Et `/31` har to mål, og et `/32` har ét. Det er værtsadresserne, der scannes; et `/24` giver normalt 254 mål.

Der er en fast øvre grænse på **65.536 måladresser**, kontrolleret før allokering. Et `/16` med 65.534 værtsadresser accepteres, men kan tage lang tid. Over 4.096 adresser skal bekræftes særskilt. Grænsen er en implementeringsbeslutning, ikke et krav fra opgaven.

**Svartid** er lytteperioden for en pakkegruppe, ikke den samlede scantid. Standard er 1,5 sekunder. Der sendes højst 64 mål i hver gruppe med cirka 10 ms mellem forespørgslerne. **Ekstra ARP-forsøg** kan være 0, 1 eller 2; kun adresser uden ARP-svar forsøges igen.

Aktivér eventuelt **Ping fundne enheder (ICMP)**, og tryk **Start scanning**. Tabellen opdateres efter hver pakkegruppe. GUI'en kører på hovedtråden; netværksarbejdet foregår i en workertråd. Fremdriften viser den aktuelle fase, så den kan starte forfra ved et ekstra ARP-gennemløb eller ved ICMP-verifikation.

**Stop** afslutter den igangværende pakkegruppe og bevarer delresultater. Knappen er ikke en øjeblikkelig afbrydelse af en åben Scapy-socket. Ventetiden afhænger af svartid, gruppestørrelse og driveren.

Kolonneoverskrifter kan bruges til sortering; IP-adresser sorteres numerisk. Dobbeltklik viser detaljer og CSV-kommentar. **Kopiér valgte IP'er** eller Ctrl+C kopierer de markerede adresser. **Vis log** viser eller skjuler hændelsesloggen. **Om / hjælp** forklarer programmet og viser versionen.

## 5. Tildelingsfil og alarm

Se **CSV-format** i programmet eller den selvstændige [CSV_FORMAT.md](CSV_FORMAT.md). Hjælpevinduet kan også gemme et eksempel til dig.

Indlæs en CSV-fil med **Indlæs CSV**. Kolonnen `ip` er obligatorisk; `bruger` og `kommentar` er valgfrie:

```csv
ip;bruger;kommentar
192.168.1.1;Netværksudstyr;Gateway
192.168.1.10;Studerende A;Laboratoriecomputer
192.168.1.20;Studerende B;Virtuel maskine
```

Tilpas adresserne til dit eget netværk. Hver række skal indeholde én IPv4-adresse, ikke et subnet eller interval. Komma, semikolon eller tabulator accepteres; UTF-8 med eller uden BOM og Windows-1252 understøttes. Der kræves en overskriftsrække. Engelske kolonnenavne som `ip_address`, `owner` og `note` accepteres også. Brug kun ét alias for hvert logisk felt i samme fil; blanke og tvetydige overskrifter afvises. Se formatbeskrivelsen for anførselstegn og øvrige regler.

Den **samlede fil valideres**, før den indlæses. En forkert fil erstatter ikke en tidligere gyldig liste. Identiske dubletter samles; modstridende tildelinger af samme IP giver en fejl med linjenummer.

| Status | Betydning |
|---|---|
| **Tildelt** | IP-adressen findes i den indlæste liste. |
| **UKENDT IP** | IP-adressen har svaret på ARP, men findes ikke i listen. |
| **Ikke kontrolleret** | Der er ikke indlæst nogen tildelingsliste. |
| **/ flere MAC** | Samme IP er observeret med flere MAC-adresser i den aktuelle scanning. |

En ukendt IP giver rød markering, alarmtekst og en samlet dialog efter scanningens afslutning. En lyd forsøges via operativsystemets standardklokke; om lyden kan høres, afhænger af systemindstillingerne. Ved indlæsning af en ny CSV kontrolleres allerede viste resultater igen.

Tildelingskontrollen er **udelukkende et opslag på IP-adressen**. Den beviser ikke, at den korrekte bruger eller enhed anvender adressen, og en afvigelse er ikke i sig selv bevis for et angreb. Programmet udfører ikke MAC-binding, autentifikation eller kontrol mod en DHCP-server.

## 6. Producent, ping og fortolkning

**Producent/OUI:** Scapys lokale producentdatabase benyttes. Der sendes ingen opslag til en webtjeneste. Ikke alle MAC-adresser kan identificeres, og databaseindholdet er ikke nødvendigvis aktuelt. Lokalt administrerede MAC-adresser vises som **Lokalt administreret MAC** frem for at tilskrive dem en sikker producentidentitet.

**ICMP:** Kun fundne ARP-enheder pinges. Programmet sender `Ether / IP / ICMP` med `srp()` på det valgte interface. Et ping er kun vellykket ved et passende Echo Reply med korrekt IP-adresse, identifier, sequence og payload. En ICMP-fejl eller timeout tælles ikke som et Echo Reply. RTT beregnes fra pakkernes faktiske send-/modtagetidsstempler, når de findes.

**Et manglende ICMP-svar fjerner ikke et ARP-fund.** En enhed kan besvare ARP uden at besvare ICMP. Der udføres ikke portscanning, DNS-opslag eller IPv6 Neighbor Discovery.

ARP-scanning er afgrænset til det lokale lag-2-net og går ikke gennem en router. Ved kendte netmasker afviser GUI'en mål uden for netkortets direkte tilsluttede net. Hvis netmasken ikke kan fastslås, kræves en særskilt bekræftelse. VLAN-adskillelse og Wi-Fi-klientisolation kan påvirke synligheden. Proxy ARP kan give svar på vegne af andre adresser; et ARP-fund er ikke en kryptografisk verificering af en bestemt fysisk enhed.

Scanningsmaskinens egen IP er ikke nødvendigvis med i resultaterne: en maskine besvarer ikke nødvendigvis sine egne ARP-requests på samme måde som en fjernvært. Programmet tilføjer derfor ikke egen IP som et kunstigt ARP-fund.

**Intet svar er ikke dokumentation for, at en IP-adresse er ledig.** Brug ikke scanningen alene til at afgøre, hvilke adresser der må tildeles.

## 7. Eksport

**Gem resultater som CSV** eksporterer samtlige aktuelle fund, uanset markering eller sortering i tabellen. Filen indeholder IP, MAC, producent, bruger, kommentar, tildelingsstatus, ICMP-status, RTT, tidspunkt for ARP-observation, scanningens start, mål, netkort, datakilde og afslutningsstatus.

UTF-8 med BOM og semikolon bruges til eksport; RTT skrives med decimalkomma. Tekstfelter beskyttes mod utilsigtet fortolkning som regnearksformler. Filen skrives først til en midlertidig fil og erstattes derefter atomisk. Luk en eksisterende resultatfil i Excel, før den overskrives.

Afbrudte eller fejlede scanninger markeres som **delresultater** i eksporten. Syntetiske resultater markeres med **DEMO** både i det foreslåede filnavn og i datakolonnen. Eksporten indeholder tidspunktet for den seneste gennemførte observation i den aktuelle scanning, ikke løbende historik.

## 8. Demotilstand

```powershell
py -3 ipscanner.py --demo
```

Alternativt: kør `demo_windows.cmd`.

Demo kræver kun Python og Tkinter. Den sender **ingen netværkspakker**, importerer ikke Scapy og behøver hverken Npcap eller administratorrettigheder. Brug intervallet `192.168.1.0/24` for at se fire syntetiske enheder. Tre er forhåndstildelt, og `192.168.1.42` udløser en ukendt-IP-alarm. `192.168.1.20` demonstrerer ARP-svar uden ICMP-svar.

Demo er en kontrol af brugerflade og programlogik, **ikke** en test af pakkedriver, netkort eller et fysisk netværk.

## 9. Tests og lokal validering

Fra projektmappen efter installation:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Scapy-pakketests mocker kun `srp()`; de sender ingen trafik. GUI-tests kræver et grafisk display og bruger syntetiske resultater. Uden Scapy eller et grafisk display markeres de relevante tests eksplicit som **skipped**. Se `docs/TESTRESULTATER.md` for resultatet i leverancemiljøet og testbegrænsningerne.

Afprøv derefter faktisk scanning på et netværk, du har tilladelse til at undersøge:

1. Scan en kendt, aktiv nabovært i det valgte lokalnet, eksempelvis gatewayen. Kontrollér ARP og eventuelt ICMP med Wireshark-filteret `arp or icmp`.
2. Scan et mindre interval og derefter det lokale subnet. Sammenhold med kendte enheder; en værtsadresse uden svar må ikke uden videre kaldes ledig.
3. Indlæs en liste, som mangler én kendt, svarende IP, og kontrollér alarmen. Tilføj derefter adressen, og kontrollér, at den markeres som tildelt.
4. Afprøv forkert input, Stop, eksport af delresultater og forskellige netkort, især hvis computeren også har VPN-, Hyper-V- eller VMware-adaptere.

Denne lokale netværksvalidering er en del af opgavens testkrav og er **ikke udført i dit netværk som del af leverancen**.

## 10. Sammenhæng med opgavens krav

| Krav/udvidelse i IPscanner(1).docx | Implementering |
|---|---|
| Python og Scapy | `ScapyBackend` i `ipscanner.py`. |
| ARP-forespørgsler til subnettets værtsadresser | `Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(...)`, udsendt med `srp()`. |
| Modtage ARP-svar og vise aktive IP-adresser | Matchning af ARP-replies og resultattabel med IP/MAC. |
| Brugerinput til netværk/IP-range | `parse_targets()` og GUI-felt. |
| Venlig fejlhåndtering | Inputvalidering, CSV-linjenumre, driver-/rettighedsbeskeder og log. |
| Gemme resultater, valgfri udvidelse | `export_results()` og eksportknap. |
| Producentidentifikation, valgfri udvidelse | Lokalt opslag i `conf.manufdb`, med tydeligt ukendt/lokalt administreret resultat. |
| GUI, nævnt som udvidelse og krævet i bestillingen | Tkinter/ttk i `ScannerGUI`. |
| Ping af fundne enheder, valgfri udvidelse | Scapy-baseret ICMP-verifikation i `ping_batch()`. |
| CSV med tildelte adresser og alarm | `load_assignments()`, præcist IP-opslag, rød markering og alarmdialog. |
| Test med lokalt net og forskellige ranges | Automatiske logik-/GUI-tests medfølger; fysisk netværkstest skal stadig udføres lokalt. |

Netkortvalg, begrænset pakkehastighed, stopfunktion, trådet GUI, numerisk sortering, genkendelse af flere MAC-adresser og demotilstand er supplerende implementeringsvalg.

## 11. Centrale kilder

Opgavekravene er fra **IPscanner(1).docx**, side 1–3. Den tekniske implementering anvender dokumentationen nedenfor som supplement til opgavegrundlaget:

- [Scapy: installation og platformskrav](https://scapy.readthedocs.io/en/stable/installation.html).
- [Scapy: ARP Ping og ICMP Ping](https://scapy.readthedocs.io/en/stable/usage.html#arp-ping).
- [Scapy: netkort-API](https://scapy.readthedocs.io/en/stable/api/scapy.interfaces.html).
- [Scapy: producentdatabasen og lookup i kildekoden](https://github.com/secdev/scapy/blob/v2.6.1/scapy/data.py).
- [Npcap: officiel distribution](https://npcap.com/).
- [Python: Tkinter](https://docs.python.org/3/library/tkinter.html) og [virtuelle miljøer](https://docs.python.org/3/library/venv.html).

Brug kun programmet på netværk, du har tilladelse til at undersøge.


## 12. Når Windows stadig ikke viser det ønskede netkort

Start med **Opdater netkort** og åbn **Netkort / diagnostik**. Se først, om kortet er registreret med **Ikke klar**, og læs årsagen. Et netkort uden lokal IPv4 eller uden tilgængelighed gennem Scapy/Npcap kan godt vises, men kan ikke ARP-scannes med denne løsning.

Kør diagnostik uden GUI fra den udpakkede projektmappe:

```powershell
.\.venv\Scripts\python.exe ipscanner.py --list-adapters
.\.venv\Scripts\python.exe ipscanner.py --diagnostics netkort_diagnostik.txt
```

Alternativt: `diagnostic_windows.cmd`. Diagnostikken scanner ikke netværket. Sammenlign efter behov med Windows’ egen liste og Scapys rå visning:

```powershell
Get-NetAdapter -IncludeHidden | Format-Table ifIndex, Name, InterfaceDescription, Status, MacAddress -AutoSize
Get-NetIPAddress -AddressFamily IPv4 | Format-Table InterfaceIndex, InterfaceAlias, IPAddress, PrefixLength -AutoSize
.\.venv\Scripts\python.exe -c "from scapy.all import conf; conf.ifaces.reload(); conf.ifaces.show(hidden=True)"
```

Scapys `show(hidden=True)` viser også interfaces, der er markeret ugyldige; se [Scapys interface-API](https://scapy.readthedocs.io/en/stable/api/scapy.interfaces.html). At Windows og Scapy viser forskellige lister kan pege på Npcap-tilgængelighed, status, driverbinding eller manglende OS-oplysninger — ikke nødvendigvis at netkortet mangler i Windows.

Kontrollér Npcap-installation og administratorrettigheder ved en driver-/adgangsfejl. En installation/opdatering af Scapy erstatter ikke installationen af Npcap. Programmet installerer eller ændrer ikke pakkedriveren automatisk. Se [Scapys officielle Windows-installation](https://scapy.readthedocs.io/en/stable/installation.html#windows).

**Windows/Npcap er ikke live-testet i udviklingsmiljøet.** Windows-opslag og sammenlægning er testet med syntetiske API-/JSON-svar. Den konkrete Windows-maskine skal bruges til endelig kontrol af dens netkort og faktisk ARP-trafik.

## 13. Licens og copyright

```text
Copyright 2026 Ib Helmer Nielsen
SPDX-License-Identifier: Apache-2.0
```

Apache-licensen er indsat i egen programkode, tests og startfiler. Ophav og version vises også under **Om / hjælp**. Den fulde Apache 2.0-tekst ligger i `LICENSE`.

**Scapy og Npcap er ikke omlicenseret.** Scapy er GPL-2.0-only; Apache 2.0 og GPL-2.0-only er ikke generelt kompatible for et samlet afledt værk. Licensforhold skal derfor afklares før videre distribution af en samlet løsning med Scapy. Scapy/Npcap medfølger ikke som kildekode eller binære filer. Se [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) og [Apaches redegørelse](https://www.apache.org/licenses/GPL-compatibility.html).
