# CSV-format — tildelte IP-adresser

**IP Scanner 1.1.0 · Copyright 2026 Ib Helmer Nielsen · Apache-2.0**

## Formålet med filen

Tildelingsfilen er en liste over de IPv4-adresser, som er tildelt brugere eller udstyr. Den indlæses med **Indlæs CSV**. Hvis en adresse besvarer ARP, men mangler i listen, viser programmet **UKENDT IP**, markerer rækken rødt og giver en samlet alarm efter scanningen.

Kontrollen sammenligner kun IP-adresser. Den bekræfter ikke brugerens identitet, MAC-adressen eller en DHCP-tildeling. En ukendt adresse er en afvigelse fra listen, ikke i sig selv bevis for et angreb.

Den samme hjælp findes i programmet under **CSV-format**, hvor **Gem eksempel-CSV …** gemmer en fil, der kan tilpasses.

## Anbefalet format

Brug en almindelig tekstfil med filendelsen `.csv`, **UTF-8** (gerne med BOM) og **semikolon** som separator:

```csv
ip;bruger;kommentar
192.168.1.1;Netværksudstyr;Gateway
192.168.1.10;Studerende A;Laboratoriecomputer
192.168.1.20;Studerende B;Virtuel maskine
```

Adresser og navne er eksempler. Tilpas dem til dit eget netværk. Første linje er overskrifter; hver efterfølgende datarække repræsenterer én tildelt adresse.

| Kolonne | Krav | Indhold |
|---|---|---|
| `ip` | Obligatorisk | En enkelt gyldig unicast-IPv4-adresse, fx `192.168.1.10`. |
| `bruger` | Valgfri | Bruger, gruppe, afdeling eller udstyr, som adressen er tildelt. |
| `kommentar` | Valgfri | Supplerende beskrivelse, fx placering eller formål. |

Valgfri felter kan være tomme. Kolonnerne kan stå i en anden rækkefølge; yderligere kolonner ignoreres. Der kræves mindst én gyldig adresse i filen.

Det mindste gyldige eksempel er:

```csv
ip
192.168.1.10
192.168.1.20
```

## Hvad må stå i `ip`?

En celle skal indeholde én IPv4-adresse. Følgende er **ikke** gyldige tildelinger:

| Eksempel | Hvorfor afvises det? |
|---|---|
| `192.168.1.0/24` | Et subnet er ikke en enkelt IP-adresse. |
| `192.168.1.10-50` | Et interval er ikke en enkelt IP-adresse. |
| `pc01.local` | Værtsnavne slås ikke op. |
| `fe80::1` | Programmet ARP-scanner IPv4, ikke IPv6. |
| `00:11:22:33:44:55` | En MAC-adresse er ikke en IPv4-adresse. |
| `127.0.0.1` | Loopback er ikke et lokalt Ethernet-ARP-mål. |
| `0.0.0.0` eller `255.255.255.255` | Uspecificeret/broadcast accepteres ikke. |

CSV-formatet indeholder ingen subnetmaske og kan derfor ikke i sig selv afgøre, om en almindelig adresse er netværks- eller broadcastadressen i netop dit subnet. Tildel kun værtsadresser, der faktisk må bruges i dit net.

## Separatorer, tegnsæt og overskrifter

Parseren accepterer **semikolon**, **komma** eller **tabulator**. Brug samme separator gennem hele filen. Den accepterer UTF-8 med eller uden BOM samt Windows-1252. UTF-16 og Excel-filer i `.xlsx`-format understøttes ikke.

Overskrifter matches uden forskel på store/små bogstaver. Mellemrum, bindestreg og underscore fjernes ved sammenligning. Derfor accepteres fx `IP Address`, `ip_address` og `IP-ADDRESS` som det samme felt.

| Logisk felt | Accepterede navne |
|---|---|
| IP | `ip`, `ipadresse`, `ipaddress` samt varianter med mellemrum, `-` og `_`. |
| Bruger | `bruger`, `user`, `navn`, `name`, `ejer`, `owner`. |
| Kommentar | `kommentar`, `comment`, `note`, `beskrivelse`, `description`. |

Brug **kun én kolonne for hvert logisk felt**. En fil med både `ip` og `ip_address` afvises, så programmet ikke stiltiende vælger den ene. Tomme og gentagne kolonneoverskrifter afvises også.

## Tekst med separatorer eller anførselstegn

Omslut et felt med dobbelte anførselstegn, når teksten indeholder separatoren. Et dobbelt anførselstegn i selve teksten skrives to gange:

```csv
ip;bruger;kommentar
192.168.1.30;"Gruppe A; Gruppe B";"PC kaldet ""Lab 1"""
```

Programmet læser brugeren som `Gruppe A; Gruppe B` og kommentaren som `PC kaldet "Lab 1"`.

Et kommasepareret eksempel er også gyldigt:

```csv
ip,user,note
192.168.1.40,"Nielsen, Ib Helmer",Laboratoriecomputer
```

## Validering og typiske fejl

Hele filen valideres, før den erstatter den aktuelt indlæste liste. En forkert fil ødelægger derfor ikke en tidligere gyldig tildelingsliste.

Tomme linjer springes over. Identiske dubletter af samme IP, bruger og kommentar samles. Samme IP med forskellige brugere eller kommentarer afvises som en modstridende tildeling. IP-fejl og modstridende tildelinger vises med linjenummer.

Filen må højst fylde **2 MiB**. Rækker med flere felter end overskrifterne afvises. Kommentarlinjer som `# kommentar` og en indledende Excel-linje som `sep=;` understøttes ikke. Første linje skal være de faktiske kolonneoverskrifter.

## Oprettelse i Excel

Opret kolonnerne `ip`, `bruger` og `kommentar`, udfyld tildelingerne og gem som **CSV UTF-8**. Både komma- og semikolonseparerede filer kan indlæses. En `.xlsx`-fil bliver ikke til CSV ved blot at få et andet filnavn. Kontrollér eventuelt den gemte fil i en teksteditor før indlæsning.

## Tildelingsfil og resultateksport er ikke det samme

Tildelingsfilen er det godkendte grundlag for kontrollen. **Gem resultater som CSV** opretter derimod en observationsrapport med disse kolonner:

```text
ip;mac;producent;bruger;kommentar;status;ping;rtt_ms;arp_sidst_set;scan_start;scan_status;scan_maal;netkort;datakilde
```

Eksporten bruger UTF-8 med BOM og semikolon. RTT skrives med decimalkomma. Scanstatus angiver, om resultaterne er fuldstændige eller delresultater; `datakilde` skelner mellem Scapy og syntetisk demo. Tekstfelter, der kan ligne regnearksformler, beskyttes med en foranstillet apostrof.

**Genindlæs ikke ukritisk resultatfilen som tildelingsliste.** Den kan indeholde de ukendte adresser, du netop ønskede at opdage. Ved at genindlæse den godkender du i praksis også disse adresser. Gennemgå og godkend tildelinger separat.
