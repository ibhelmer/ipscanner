#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2026 Ib Helmer Nielsen
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This notice covers this project's own code, not Scapy, Npcap or Python.
# See THIRD_PARTY_NOTICES.md before distributing a combined application.
# Modified 2026-10-12: v1.1.0, Windows adapter inventory and CSV documentation.
"""IP Scanner 1.1.0 — dansk Tkinter-GUI og ARP-scanning med Scapy.

Opgavegrundlag: IPscanner(1).docx. Python 3.10 eller nyere.
Start: python ipscanner.py          Demo: python ipscanner.py --demo

Programmet er opdelt i input/CSV, Scapy-backend, scanning og brugerflade.
Scapy importeres først ved normal opstart. Demo og logiktests kræver ikke Scapy.
Brug kun scanneren på netværk, du har tilladelse til at undersøge.
"""
from __future__ import annotations

import argparse
import base64
import json
import platform
import subprocess
import csv
import importlib
import io
import math
import os
import queue
import re
import secrets
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, replace
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from pathlib import Path
from typing import Any, Callable, Protocol, Sequence

VERSION = "1.1.0"
COPYRIGHT = "Copyright 2026 Ib Helmer Nielsen"
LICENSE_ID = "Apache-2.0"
MAX_TARGETS = 65_536
BATCH_SIZE = 64
PACKET_INTERVAL = 0.01  # Højst ca. 100 udsendte forespørgsler/sekund.
MAX_CSV_BYTES = 2 * 1024 * 1024

CSV_EXAMPLE = """ip;bruger;kommentar
192.168.1.1;Netværksudstyr;Gateway
192.168.1.10;Studerende A;Laboratoriecomputer
192.168.1.20;Studerende B;Virtuel maskine
"""

CSV_HELP_TEXT = '''CSV-FORMAT: TILDELTE IP-ADRESSER

CSV-filen er en liste over adresser, som må være i brug. Indlæs den med
'Indlæs CSV'. Adresser, der besvarer ARP, men mangler i listen, markeres
med UKENDT IP. Det er et opslag på IP — ikke kontrol af brugeridentitet.

ANBEFALET FORMAT
UTF-8, gerne med BOM, og semikolon mellem kolonnerne.
Første linje er kolonneoverskrifter. Én IPv4-adresse pr. datarække.

''' + CSV_EXAMPLE + '''
KOLONNER
ip         Obligatorisk. En enkelt IPv4-adresse, fx 192.168.1.10.
bruger     Valgfri. Navn på bruger, gruppe eller udstyr.
kommentar  Valgfri. En beskrivelse af tildelingen.

Den mindste gyldige fil er:
ip
192.168.1.10
192.168.1.20

REGLER
• Ikke CIDR-subnet, intervaller, værtsnavne, IPv6 eller MAC-adresser i ip.
• Kolonnerne må stå i en anden rækkefølge; ukendte ekstra kolonner ignoreres.
• Store/små bogstaver, mellemrum, '-' og '_' i overskrifter ignoreres.
• IP-aliaser: ip, ip-adresse, ip_address, IP Address.
• Brugeraliaser: bruger, user, navn, name, ejer, owner.
• Kommentaraliaser: kommentar, comment, note, beskrivelse, description.
• Semikolon, komma og tabulator accepteres. Brug samme separator i hele filen.
• UTF-8 med/uden BOM og Windows-1252 accepteres. Ikke UTF-16.
• Tomme linjer springes over; der skal være mindst én tildelt adresse.
• Identiske dubletter samles. Samme IP med forskellig bruger/kommentar afvises.
• Gentagne/blanke overskrifter eller flere felter end overskrifter afvises.
• Højst 2 MiB. Hele filen valideres før den erstatter den indlæste liste.
• Brug kun ét af aliaserne for hver kolonne i samme fil.
• Kommentarrækker med # og Excel-linjen sep=; understøttes ikke.

SEPARATORER OG ANFØRSELSTEGN I TEKST
Sæt tekst i dobbelte anførselstegn, hvis den indeholder separatoren.
Et anførselstegn inde i teksten skrives som to anførselstegn:

ip;bruger;kommentar
192.168.1.30;"Gruppe A; Gruppe B";"PC kaldet ""Lab 1"""

EXCEL
Opret kolonnerne ip, bruger og kommentar og gem som CSV UTF-8.
Både komma- og semikolonsepareret CSV kan bruges. En .xlsx-fil er ikke CSV.
Tilpas altid eksempeladresserne til dit netværk før indlæsning.

TILDELINGSFIL ELLER RESULTATEKSPORT?
Tildelingsfilen er grundlaget for kontrollen. Resultateksporten indeholder
også MAC, producent, ICMP og scanmetadata. Genindlæs ikke resultatfilen som
ny tildelingsliste uden at gennemgå den: ellers godkendes også ukendte IP'er.

STATUSER
Tildelt            IP-adressen findes i den indlæste liste.
UKENDT IP          IP-adressen har svaret, men findes ikke i listen.
Ikke kontrolleret  Der er ikke indlæst en liste.

Knappen 'Gem eksempel-CSV' gemmer et syntetisk eksempel, som skal tilpasses.
'''




# ---------------------------------------------------------------------------
# 1. Datamodeller, inputkontrol og CSV — ingen netværksadgang i disse funktioner.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Targets:
    label: str
    ips: tuple[str, ...]


def checked_ipv4(text: str) -> IPv4Address:
    """Accepter kun en almindelig unicast-IPv4-adresse, aldrig et værtsnavn."""
    try:
        address = ip_address(text.strip())
    except ValueError as exc:
        raise ValueError(f"'{text}' er ikke en gyldig IP-adresse.") from exc
    if not isinstance(address, IPv4Address):
        raise ValueError("ARP-scanneren understøtter kun IPv4, ikke IPv6.")
    if (address.is_loopback or address.is_multicast or address.is_unspecified
            or address.is_reserved):
        raise ValueError(f"{address} er ikke en understøttet lokal unicast-adresse.")
    return address


def parse_targets(text: str) -> Targets:
    """Læs CIDR, en enkelt IPv4 eller et inklusivt interval.

    CIDR normaliseres, så 192.168.1.17/24 betyder 192.168.1.0/24.
    Netværks- og broadcastadressen udelades for /0–/30; /31 og /32 følger
    ipaddress.hosts(). Grænsen kontrolleres FØR adresserne oprettes i hukommelsen.
    """
    text = text.strip()
    if not text:
        raise ValueError("Indtast et subnet, fx 192.168.1.0/24, eller et IP-interval.")
    if "/" in text:
        try:
            net = ip_network(text, strict=False)
        except ValueError as exc:
            raise ValueError("Ugyldigt subnet. Eksempel: 192.168.1.0/24.") from exc
        if not isinstance(net, IPv4Network):
            raise ValueError("ARP-scanneren understøtter kun IPv4, ikke IPv6.")
        count = net.num_addresses if net.prefixlen >= 31 else net.num_addresses - 2
        if count > MAX_TARGETS:
            raise ValueError(f"Subnettet er for stort. Maksimum er {MAX_TARGETS:,} adresser.")
        addresses = tuple(str(checked_ipv4(str(ip))) for ip in net.hosts())
        return Targets(str(net), addresses)
    if "-" in text:
        if text.count("-") != 1:
            raise ValueError("Brug fx 192.168.1.10-192.168.1.50.")
        left, right = (part.strip() for part in text.split("-"))
        first = checked_ipv4(left)
        # Det korte format 192.168.1.10-50 understøttes også.
        if right.isdecimal() and len(right) <= 3:
            right = str(first).rsplit(".", 1)[0] + "." + right
        last = checked_ipv4(right)
        count = int(last) - int(first) + 1
        if count < 1:
            raise ValueError("Startadressen skal være mindre end eller lig med slutadressen.")
        if count > MAX_TARGETS:
            raise ValueError(f"Intervallet er for stort. Maksimum er {MAX_TARGETS:,} adresser.")
        addresses = tuple(str(checked_ipv4(str(IPv4Address(n))))
                          for n in range(int(first), int(last) + 1))
        return Targets(f"{first}-{last}", addresses)
    address = str(checked_ipv4(text))
    return Targets(address, (address,))


def normalise_mac(text: str) -> str:
    text = str(text).strip().lower().replace("-", ":")
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", text):
        raise ValueError("Ugyldig MAC-adresse.")
    if text == "00:00:00:00:00:00" or int(text[:2], 16) & 1:
        raise ValueError("Der kræves en unicast-MAC-adresse.")
    return text


@dataclass(frozen=True)
class Assignment:
    user: str = ""
    note: str = ""


def _header(text: str) -> str:
    return re.sub(r"[\s_-]", "", text.strip().casefold())


def load_assignments(path: str | Path) -> dict[str, Assignment]:
    """Valider HELE CSV-filen før den erstatter den nuværende tildelingsliste.

    Obligatorisk overskrift: ip (også ip-adresse eller ip_address).
    Valgfri kolonner: bruger og kommentar. Komma, semikolon og tabulator støttes.
    """
    path = Path(path)
    if path.stat().st_size > MAX_CSV_BYTES:
        raise ValueError("CSV-filen er for stor. Maksimum er 2 MiB.")
    raw = path.read_bytes()
    if len(raw) > MAX_CSV_BYTES:
        raise ValueError("CSV-filen er for stor. Maksimum er 2 MiB.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("cp1252")
    if not text.strip():
        raise ValueError("CSV-filen er tom.")
    sample = text[:8192]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=";,\t")
        reader = csv.DictReader(io.StringIO(text, newline=""), dialect=dialect, strict=True)
    except csv.Error:
        # En fil med kun kolonnen 'ip' har ikke nogen separator at genkende.
        first_line = text.splitlines()[0]
        separator = ";" if ";" in first_line else "\t" if "\t" in first_line else ","
        reader = csv.DictReader(io.StringIO(text, newline=""), delimiter=separator, strict=True)
    fields = reader.fieldnames or []
    if not fields or any(not _header(h) for h in fields) or len({_header(h) for h in fields}) != len(fields):
        raise ValueError("CSV-filen har manglende eller gentagne kolonneoverskrifter.")
    headers = {_header(field): field for field in fields}

    def column(*names: str) -> str | None:
        matches = [headers[name] for name in names if name in headers]
        if len(matches) > 1:
            raise ValueError("CSV-filen har flere kolonner med samme betydning: " + ", ".join(matches))
        return matches[0] if matches else None

    ip_col = column("ip", "ipadresse", "ipaddress")
    user_col = column("bruger", "user", "navn", "name", "ejer", "owner")
    note_col = column("kommentar", "comment", "note", "beskrivelse", "description")
    if ip_col is None:
        raise ValueError("CSV-filen skal have en overskrift med kolonnen 'ip'.")
    assignments: dict[str, Assignment] = {}
    for row in reader:
        if not any(str(value or "").strip() for value in row.values()):
            continue
        if None in row:
            raise ValueError(f"CSV-linje {reader.line_num}: for mange felter. Kontrollér separatoren.")
        try:
            address = str(checked_ipv4(row.get(ip_col) or ""))
        except ValueError as exc:
            raise ValueError(f"CSV-linje {reader.line_num}: {exc}") from exc
        item = Assignment((row.get(user_col) or "").strip() if user_col else "",
                          (row.get(note_col) or "").strip() if note_col else "")
        if address in assignments and assignments[address] != item:
            raise ValueError(f"CSV-linje {reader.line_num}: {address} har modstridende tildelinger.")
        assignments[address] = item
    if not assignments:
        raise ValueError("CSV-filen indeholder ingen tildelte IP-adresser.")
    return assignments


@dataclass(frozen=True)
class Adapter:
    interface: str
    name: str
    ip: str
    mac: str
    networks: tuple[IPv4Network, ...]
    default: bool = False
    description: str = ""
    index: int | None = None
    guid: str = ""
    os_status: str = ""
    capture_available: bool = True
    blocked_reason: str = ""
    sources: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    ipv6: tuple[str, ...] = ()

    @property
    def can_scan(self) -> bool:
        # A visible adapter is not necessarily an Ethernet/IPv4 scan candidate.
        if self.blocked_reason or not self.capture_available:
            return False
        try:
            checked_ipv4(self.ip)
            normalise_mac(self.mac)
        except ValueError:
            return False
        return True

    @property
    def state(self) -> str:
        return "Kan forsøges" if self.can_scan else "Ikke klar"

    @property
    def label(self) -> str:
        subnet = str(self.networks[0]) if self.networks else "subnet ukendt"
        index = f" [#{self.index}]" if self.index is not None else ""
        return f"{self.name}{index}  |  {self.ip or 'ingen IPv4'}  |  {subnet}  |  {self.state}"

    @property
    def details(self) -> str:
        return "\n".join([
            f"Navn: {self.name}", f"Beskrivelse: {self.description or '—'}",
            f"Status: {self.state}", f"Årsag: {self.blocked_reason or 'Ingen kendt blokering'}",
            f"Windows-status: {self.os_status or 'Ikke oplyst'}",
            f"Interface-index: {self.index if self.index is not None else '—'}",
            f"GUID: {self.guid or '—'}", f"Scapy-interface: {self.interface or 'Ikke fundet'}",
            f"Tilgængelig for pakkescanning: {'Ja' if self.capture_available else 'Nej'}",
            f"IPv4: {self.ip or 'Ingen'}", f"MAC: {self.mac or 'Ikke oplyst'}",
            "Direkte net: " + (", ".join(map(str, self.networks)) or "Ikke oplyst"),
            "IPv6 (ikke scannet): " + (", ".join(self.ipv6) or "Ingen oplyst"),
            "Datakilder: " + (", ".join(self.sources) or "Backend"),
            "Bemærkninger: " + ("; ".join(self.warnings) or "Ingen"),
        ])



def outside_adapter(targets: Targets, adapter: Adapter) -> tuple[str, ...]:
    """Adresser uden for netkortets kendte, direkte tilsluttede IPv4-net."""
    return tuple(ip for ip in targets.ips
                 if not any(IPv4Address(ip) in net for net in adapter.networks))


@dataclass(frozen=True)
class Device:
    ip: str
    mac: str
    vendor: str = "Ukendt producent"
    last_seen: str = ""
    ping: str = "Ikke testet"
    rtt_ms: float | None = None

    @property
    def key(self) -> str:
        return f"{self.ip}|{self.mac}"


@dataclass(frozen=True)
class ScanSettings:
    targets: Targets
    adapter: Adapter
    timeout: float = 1.5
    retries: int = 1
    ping: bool = False

    def validate(self) -> None:
        if not self.adapter.can_scan:
            raise ValueError("Netkortet kan ikke bruges til ARP-scanning: " +
                             (self.adapter.blocked_reason or "IPv4, MAC eller pakkedriver mangler."))
        if not self.targets.ips or len(self.targets.ips) > MAX_TARGETS:
            raise ValueError("Antallet af adresser er ugyldigt.")
        if not math.isfinite(self.timeout) or not 0.2 <= self.timeout <= 5:
            raise ValueError("Svartid skal være mellem 0,2 og 5 sekunder.")
        if type(self.retries) is not int or self.retries not in (0, 1, 2):
            raise ValueError("Ekstra forsøg skal være 0, 1 eller 2.")


@dataclass(frozen=True)
class ExportContext:
    start: str = ""
    target: str = ""
    interface: str = ""
    state: str = "Ikke startet"
    source: str = "Scapy / ARP"


def device_status(device: Device, assignments: dict[str, Assignment] | None,
                  conflict: bool = False) -> str:
    status = ("Ikke kontrolleret" if assignments is None else
              "Tildelt" if device.ip in assignments else "UKENDT IP")
    return status + (" / flere MAC" if conflict else "")


def safe_csv_cell(value: Any) -> str:
    """Beskyt CSV-tekst mod utilsigtet formeludførelse ved åbning i regneark."""
    text = str(value)
    if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")):
        return "'" + text
    return text


def export_results(path: str | Path, devices: Sequence[Device],
                   assignments: dict[str, Assignment] | None,
                   context: ExportContext) -> None:
    """Skriv atomisk CSV med UTF-8-BOM og semikolon, egnet til dansk Excel."""
    path = Path(path)
    by_ip: dict[str, set[str]] = {}
    for device in devices:
        by_ip.setdefault(device.ip, set()).add(device.mac)
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8-sig", newline="",
                                         dir=path.parent, delete=False, suffix=".tmp") as file:
            temporary = file.name
            writer = csv.writer(file, delimiter=";")
            writer.writerow(["ip", "mac", "producent", "bruger", "kommentar", "status",
                             "ping", "rtt_ms", "arp_sidst_set", "scan_start", "scan_status",
                             "scan_maal", "netkort", "datakilde"])
            for device in sorted(devices, key=lambda d: (IPv4Address(d.ip), d.mac)):
                owner = (assignments or {}).get(device.ip, Assignment())
                writer.writerow([safe_csv_cell(value) for value in [
                    device.ip, device.mac, device.vendor, owner.user, owner.note,
                    device_status(device, assignments, len(by_ip[device.ip]) > 1),
                    device.ping,
                    "" if device.rtt_ms is None else f"{device.rtt_ms:.2f}".replace(".", ","),
                    device.last_seen, context.start, context.state, context.target,
                    context.interface, context.source]])
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


# ---------------------------------------------------------------------------
# 2. Scapy-backend — al faktisk pakkekommunikation er samlet her.
# ---------------------------------------------------------------------------
class Backend(Protocol):
    def adapters(self) -> list[Adapter]: ...
    def scan_batch(self, ips: Sequence[str], adapter: Adapter, timeout: float) -> list[Device]: ...
    def ping_batch(self, devices: Sequence[Device], adapter: Adapter,
                   timeout: float) -> dict[str, tuple[str, float | None]]: ...


# Windows inventory is read-only. Scapy remains the only packet-sending backend.
# The fixed PowerShell command has no user input, uses JSON (not formatted tables),
# and never changes adapters, IP addresses, driver bindings or execution policy.
WINDOWS_INVENTORY_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$issues = @()
$adapters = @()
$addresses = @()
try {
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | ForEach-Object {
        [PSCustomObject]@{
            name = [string]$_.Name
            description = [string]$_.InterfaceDescription
            index = $_.ifIndex
            guid = [string]$_.InterfaceGuid
            mac = [string]$_.MacAddress
            status = [string]$_.Status
            type = $_.InterfaceType
        }
    })
} catch { $issues += ('Get-NetAdapter: ' + $_.Exception.Message) }
try {
    $addresses = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
        Select-Object InterfaceIndex, InterfaceAlias, IPAddress, PrefixLength, AddressState)
} catch { $issues += ('Get-NetIPAddress: ' + $_.Exception.Message) }
[PSCustomObject]@{ adapters = $adapters; addresses = $addresses; warnings = $issues } |
    ConvertTo-Json -Depth 6 -Compress
"""


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _guid_key(value: Any) -> str:
    match = re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                      str(value or ""), re.IGNORECASE)
    return match.group(0).casefold() if match else ""


def _same_interface(left: dict[str, Any], right: dict[str, Any]) -> bool:
    """GUID first; never merge physical/Hyper-V adapters merely by shared MAC."""
    left_guid = _guid_key(left.get("guid") or left.get("interface"))
    right_guid = _guid_key(right.get("guid") or right.get("interface"))
    if left_guid and right_guid:
        return left_guid == right_guid
    a, b = _int_or_none(left.get("index")), _int_or_none(right.get("index"))
    if a is not None and b is not None and a > 0 and b > 0:
        return a == b
    # Names are only a fallback when neither side has a reliable GUID/index.
    return (not left_guid and not right_guid and a in (None, 0) and b in (None, 0)
            and bool(left.get("name")) and
            str(left["name"]).casefold() == str(right.get("name", "")).casefold())


def merge_interface_records(records: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge inventory sources without losing Windows-only or IPv6-only adapters."""
    result: list[dict[str, Any]] = []
    for record in records:
        existing = next((item for item in result if _same_interface(item, record)), None)
        if existing is None:
            existing = {"ips": [], "sources": [], "prefixes": {}, "warnings": []}
            result.append(existing)
        for name, value in record.items():
            if name in ("ips", "sources", "warnings"):
                for item in _as_list(value):
                    if item not in existing[name]:
                        existing[name].append(item)
            elif name == "prefixes":
                existing["prefixes"].update(value or {})
            elif name == "mac":
                try:
                    existing[name] = normalise_mac(str(value or ""))
                except ValueError:
                    if not existing.get(name):
                        existing[name] = str(value or "")
            elif name == "interface":
                # Only Scapy supplies a socket identifier. Never construct a fake NPF name.
                if value:
                    existing[name] = value
            elif value not in (None, "", [], {}):
                existing[name] = value
    return result


def parse_windows_inventory(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Parse fixed PowerShell JSON; accepts zero, one or many adapters/addresses."""
    payload = json.loads(text.lstrip("\ufeff"))
    if not isinstance(payload, dict):
        raise ValueError("Windows returnerede ikke et JSON-objekt.")
    records: list[dict[str, Any]] = []
    warnings = [str(item) for item in _as_list(payload.get("warnings"))]
    for item in _as_list(payload.get("adapters")):
        if not isinstance(item, dict):
            continue
        records.append({
            "name": str(item.get("name") or "Windows-netkort"),
            "description": str(item.get("description") or ""),
            "index": _int_or_none(item.get("index")), "guid": str(item.get("guid") or ""),
            "mac": str(item.get("mac") or ""), "status": str(item.get("status") or ""),
            "type": _int_or_none(item.get("type")), "ips": [], "prefixes": {},
            "sources": ["Windows / Get-NetAdapter -IncludeHidden"], "warnings": [],
        })
    for address in _as_list(payload.get("addresses")):
        if not isinstance(address, dict):
            continue
        index = _int_or_none(address.get("InterfaceIndex"))
        item = next((record for record in records if index is not None and record["index"] == index), None)
        if item is None:
            item = {"name": str(address.get("InterfaceAlias") or "Windows-IP-interface"),
                    "index": index, "ips": [], "prefixes": {}, "sources": [], "warnings": []}
            records.append(item)
        if "Windows / Get-NetIPAddress" not in item["sources"]:
            item["sources"].append("Windows / Get-NetIPAddress")
        ip = str(address.get("IPAddress") or "")
        try:
            IPv4Address(ip)
        except ValueError:
            continue
        if ip not in item["ips"]:
            item["ips"].append(ip)
        prefix = _int_or_none(address.get("PrefixLength"))
        if prefix is not None and 0 <= prefix <= 32:
            item["prefixes"][ip] = prefix
        state = str(address.get("AddressState") or "")
        # Do not mistake DHCP-tentative or duplicate addresses for stable source IPs.
        if state.casefold() in ("invalid", "tentative", "duplicate", "0", "1", "2"):
            item.setdefault("bad_addresses", {})[ip] = state
    return records, warnings


def read_windows_inventory() -> tuple[list[dict[str, Any]], list[str]]:
    """Read Windows' full adapter list, independently of Npcap. No network traffic."""
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    powershell = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    encoded = base64.b64encode(WINDOWS_INVENTORY_SCRIPT.encode("utf-16-le")).decode("ascii")
    try:
        result = subprocess.run(
            [str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            capture_output=True, timeout=20, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode:
            detail = result.stderr.decode("utf-8", errors="replace").strip()[:1200]
            raise RuntimeError(f"PowerShell fejlede (kode {result.returncode}): {detail}")
        return parse_windows_inventory(result.stdout.decode("utf-8-sig"))
    except (OSError, subprocess.TimeoutExpired, ValueError, RuntimeError) as exc:
        return [], [f"Windows-inventar kunne ikke læses: {exc}. Listen kan være ufuldstændig."]


def adapter_inventory_report(adapters: Sequence[Adapter], messages: Sequence[str] = ()) -> str:
    interfaces = len({adapter.interface or adapter.guid or str(adapter.index) + adapter.name
                      for adapter in adapters})
    lines = [f"IP Scanner {VERSION} — netkortdiagnostik", COPYRIGHT,
             f"Tidspunkt: {datetime.now().astimezone().isoformat(timespec='seconds')}",
             f"Platform: {platform.platform()}", f"Python: {sys.version.split()[0]}",
             f"Netkort: {interfaces}; netkort/IP-valg: {len(adapters)}; "
             f"mulige scanningsvalg: {sum(adapter.can_scan for adapter in adapters)}", "",
             "Rapporten indeholder lokale IP-/MAC-adresser og netkortnavne.",
             "Kontrollér indholdet før deling. Intet sendes til en webtjeneste.", "",
             "'Kan forsøges' er en forudsætningskontrol, ikke en test af driver eller pakker.",
             "Visning af et netkort betyder ikke, at det understøtter Ethernet/ARP.", ""]
    lines.extend(f"BEMÆRK: {message}" for message in messages)
    for number, adapter in enumerate(adapters, 1):
        lines.extend(["", f"--- Netkort/IP-valg {number} ---", adapter.details])
    return "\n".join(lines) + "\n"


class ScapyBackend:
    def __init__(self) -> None:
        self.messages: list[str] = []
        self.s: Any = None
        self.interface_api: Any = None
        self.import_error = ""
        try:
            self.s = importlib.import_module("scapy.all")
            self.interface_api = importlib.import_module("scapy.interfaces")
        except Exception as exc:
            self.import_error = ("Scapy kunne ikke indlæses. Kør python -m pip install -r requirements.txt. "
                                 "På Windows skal Npcap også være installeret. "
                                 f"Detalje: {type(exc).__name__}: {exc}")
            # Windows' own inventory still works when Scapy or Npcap cannot load.
            if sys.platform != "win32":
                raise RuntimeError(self.import_error) from exc

    def _iface_key(self, value: Any) -> str:
        key = getattr(value, "network_name", None)
        if key:
            return str(key)
        if self.interface_api is not None:
            try:
                return str(self.interface_api.network_name(value))
            except Exception:
                pass
        return str(value or "")

    def adapters(self) -> list[Adapter]:
        """Union of Scapy, Windows API and Get-NetAdapter -IncludeHidden.

        Keep every discovered interface visible. Availability is determined separately.
        Windows GUID/index links OS metadata to an actual Scapy socket identifier.
        """
        self.messages = [self.import_error] if self.import_error else []
        s = self.s
        is_windows = sys.platform == "win32"
        records: list[dict[str, Any]] = []
        routes: list[Any] = []
        default = ""
        if s is not None:
            for label, operation in (("Scapy-netkort", s.conf.ifaces.reload),
                                     ("Scapy-ruter", s.conf.route.resync)):
                try:
                    operation()
                except Exception as exc:
                    self.messages.append(f"{label} kunne ikke opdateres: {exc}. Data kan være ufuldstændige.")
            default = self._iface_key(s.conf.iface)
            routes = list(s.conf.route.routes)
            cache = {str(key).casefold() for key in getattr(s.conf, "cache_pcapiflist", {})}
            for iface in s.conf.ifaces.values():
                try:
                    key = self._iface_key(iface)
                    raw_ips = getattr(iface, "ips", {})
                    ips = ([ip for values in raw_ips.values() for ip in _as_list(values)]
                           if isinstance(raw_ips, dict) else _as_list(raw_ips))
                    if getattr(iface, "ip", None):
                        ips.append(iface.ip)
                    valid = None
                    try:
                        valid = bool(iface.is_valid())
                    except Exception:
                        pass
                    captured = (bool(getattr(s.conf, "use_pcap", False)) and key.casefold() in cache
                                if is_windows else True)
                    records.append({
                        "interface": key, "name": str(getattr(iface, "name", "") or key),
                        "description": str(getattr(iface, "description", "") or ""),
                        "index": _int_or_none(getattr(iface, "index", None)),
                        "guid": str(getattr(iface, "guid", "") or ""),
                        "mac": str(getattr(iface, "mac", "") or ""), "ips": ips,
                        "capture": captured, "valid": valid, "sources": ["Scapy"],
                    })
                except Exception as exc:
                    self.messages.append(f"Et Scapy-netkort kunne ikke læses: {exc}.")
            if is_windows:
                self.messages.append(f"Scapy {getattr(s.conf, 'version', 'version ikke oplyst')}: "
                                     f"use_pcap={getattr(s.conf, 'use_pcap', False)}, "
                                     f"use_npcap={getattr(s.conf, 'use_npcap', False)}; "
                                     f"{len(cache)} interfaces i pakkedriverens liste.")
                try:
                    win_api = importlib.import_module("scapy.arch.windows")
                    for item in win_api.get_windows_if_list():
                        records.append({**item, "sources": ["Windows API / Scapy"],
                                        "ips": list(item.get("ips") or [])})
                except Exception as exc:
                    self.messages.append(f"Windows API via Scapy kunne ikke læses: {exc}.")
        if is_windows:
            windows_records, messages = read_windows_inventory()
            records.extend(windows_records)
            self.messages.extend(messages)
        merged = merge_interface_records(records)
        result: list[Adapter] = []
        for item in merged:
            key = str(item.get("interface") or "")
            captured = bool(item.get("capture", False))
            status = str(item.get("status") or "")
            common_reasons: list[str] = []
            notes = list(item.get("warnings", []))
            if not captured:
                common_reasons.append("Ikke tilgængeligt gennem Scapy/Npcap" if is_windows
                                      else "Ikke tilgængeligt gennem Scapy")
            normal_status = re.sub(r"[\s_-]", "", status).casefold()
            if normal_status in {"disabled", "disconnected", "down", "notpresent", "lowerlayerdown",
                                 "dormant", "testing", "deaktiveret", "afbrudt"}:
                common_reasons.append(f"Windows-status: {status}")
            if is_windows and _int_or_none(item.get("type")) in (23, 24, 131):
                common_reasons.append("PPP, loopback eller tunnel: ikke Ethernet/ARP")
            if item.get("valid") is False:
                notes.append("Scapy markerer interfacet som inaktivt/usikkert; statusflag alene skjuler det ikke")
            try:
                mac = normalise_mac(str(item.get("mac") or ""))
            except ValueError:
                mac = str(item.get("mac") or "")
                common_reasons.append("Ingen gyldig Ethernet-MAC")
            v4: set[str] = set()
            v6: set[str] = set()
            for value in item.get("ips", []):
                try:
                    address = ip_address(str(value))
                    (v4 if isinstance(address, IPv4Address) else v6).add(str(address))
                except ValueError:
                    continue
            for address in sorted(v4, key=IPv4Address) or [""]:
                reasons = common_reasons.copy()
                if address:
                    try:
                        checked_ipv4(address)
                    except ValueError:
                        reasons.append("IPv4-adressen er ikke egnet til lokal ARP-scanning")
                else:
                    reasons.append("Ingen IPv4-adresse (evt. kun IPv6)")
                if address in item.get("bad_addresses", {}):
                    reasons.append("Windows markerer kildeadressen som " + str(item["bad_addresses"][address]))
                nets: set[IPv4Network] = set()
                prefix = item.get("prefixes", {}).get(address)
                if address and prefix is not None and 0 < prefix <= 32:
                    nets.add(IPv4Network(f"{address}/{prefix}", strict=False))
                # Keep networks specific to this source IP, not other IPs on the NIC.
                for route in routes:
                    if (not address or not key or len(route) < 5 or
                            self._iface_key(route[3]).casefold() != key.casefold() or str(route[2]) != "0.0.0.0"):
                        continue
                    try:
                        net = IPv4Network(f"{IPv4Address(route[0])}/{IPv4Address(route[1])}", strict=False)
                        if 0 < net.prefixlen < 32 and IPv4Address(address) in net:
                            nets.add(net)
                    except (TypeError, ValueError):
                        continue
                result.append(Adapter(
                    interface=key, name=str(item.get("name") or item.get("description") or key or "Netkort"),
                    ip=address, mac=mac,
                    networks=tuple(sorted(nets, key=lambda net: (-net.prefixlen, int(net.network_address)))),
                    default=bool(key and key.casefold() == default.casefold()),
                    description=str(item.get("description") or ""), index=_int_or_none(item.get("index")),
                    guid=str(item.get("guid") or ""), os_status=status, capture_available=captured,
                    blocked_reason="; ".join(dict.fromkeys(reasons)), sources=tuple(item.get("sources", [])),
                    warnings=tuple(notes), ipv6=tuple(sorted(v6)),
                ))
        return sorted(result, key=lambda adapter: (
            not adapter.can_scan, not adapter.default, adapter.name.casefold(),
            adapter.index if adapter.index is not None else -1,
            int(IPv4Address(adapter.ip)) if adapter.ip else -1))

    def _require_scapy(self, adapter: Adapter) -> Any:
        if self.s is None:
            raise RuntimeError(self.import_error or "Scapy mangler.")
        if not adapter.can_scan:
            raise ValueError(adapter.blocked_reason or "Netkortet er ikke klar til ARP.")
        return self.s

    def _vendor(self, mac: str) -> str:
        if int(mac[:2], 16) & 2:
            return "Lokalt administreret MAC"
        try:
            # Scapys lokale OUI-database; der foretages ikke webopslag.
            name = str(self.s.conf.manufdb.lookup(mac)[1])
            return name if name and name.casefold() != mac.casefold() else "Ukendt producent"
        except (AttributeError, KeyError, IndexError, TypeError):
            return "Ukendt producent"

    def scan_batch(self, ips: Sequence[str], adapter: Adapter, timeout: float) -> list[Device]:
        s = self._require_scapy(adapter)
        # Ether er broadcast; ARP spørger efter én mål-IP pr. Ethernet-frame.
        packets = [s.Ether(src=adapter.mac, dst="ff:ff:ff:ff:ff:ff") /
                   s.ARP(op=1, hwsrc=adapter.mac, psrc=adapter.ip,
                         hwdst="00:00:00:00:00:00", pdst=ip) for ip in ips]
        answered, _ = s.srp(packets, iface=adapter.interface, timeout=timeout,
                            inter=PACKET_INTERVAL, retry=0, multi=True, verbose=False)
        allowed = set(ips)
        found: dict[str, Device] = {}
        for sent, received in answered:
            if not received.haslayer(s.ARP) or not sent.haslayer(s.ARP):
                continue
            arp = received[s.ARP]
            if int(arp.op) != 2 or str(arp.psrc) not in allowed:
                continue
            # Ignorér fremmede/gratuitous ARP-svar, der ikke matcher vores request.
            if str(arp.psrc) != str(sent[s.ARP].pdst) or str(arp.pdst) != adapter.ip:
                continue
            try:
                mac = normalise_mac(str(arp.hwsrc))
            except ValueError:
                continue
            device = Device(str(arp.psrc), mac, self._vendor(mac),
                            datetime.now().astimezone().isoformat(timespec="seconds"))
            found[device.key] = device
        return list(found.values())

    def ping_batch(self, devices: Sequence[Device], adapter: Adapter,
                   timeout: float) -> dict[str, tuple[str, float | None]]:
        s = self._require_scapy(adapter)
        identifier = secrets.randbelow(65_536)
        token = f"IPScanner/{VERSION}/".encode("ascii") + secrets.token_bytes(12)
        # Også ICMP sendes på lag 2 med srp(), så det VALGTE netkort bruges.
        # sr1(IP()/ICMP(), iface=...) kan ellers blive styret af lag-3-routing.
        packets = [s.Ether(src=adapter.mac, dst=device.mac) /
                   s.IP(src=adapter.ip, dst=device.ip) /
                   s.ICMP(type=8, code=0, id=identifier, seq=index) / s.Raw(load=token)
                   for index, device in enumerate(devices)]
        answered, _ = s.srp(packets, iface=adapter.interface, timeout=timeout,
                            inter=PACKET_INTERVAL, retry=0, verbose=False)
        results: dict[str, tuple[str, float | None]] = {
            device.key: ("Intet ICMP-svar", None) for device in devices}
        for sent, received in answered:
            key = f"{sent[s.IP].dst}|{str(sent[s.Ether].dst).lower()}"
            if key not in results or not received.haslayer(s.IP):
                continue
            outer_ip = received[s.IP]
            icmp = outer_ip.payload
            if not isinstance(icmp, s.ICMP):
                continue
            if int(icmp.type) != 0:
                results[key] = (f"ICMP-fejl {int(icmp.type)}/{int(icmp.code)}", None)
                continue
            if (int(icmp.code) != 0 or str(outer_ip.src) != str(sent[s.IP].dst)
                    or str(outer_ip.dst) != adapter.ip
                    or int(icmp.id) != identifier or int(icmp.seq) != int(sent[s.ICMP].seq)
                    or bytes(icmp.payload) != token):
                continue
            # Brug pakkernes send/modtag-tidsstempler, ikke tiden for hele batchen.
            rtt = None
            try:
                delta = (float(received.time) - float(sent.sent_time)) * 1000
                if math.isfinite(delta) and delta >= 0:
                    rtt = delta
            except (TypeError, ValueError, AttributeError):
                pass
            results[key] = ("Echo-svar", rtt)
        return results


class DemoBackend:
    """Rent syntetiske resultater. Denne klasse åbner ingen netværkssockets."""
    DEMO_MACS = {"192.168.1.1": "02:00:00:00:00:01", "192.168.1.10": "02:00:00:00:00:10",
                 "192.168.1.20": "02:00:00:00:00:20", "192.168.1.42": "02:00:00:00:00:42"}

    def adapters(self) -> list[Adapter]:
        return [Adapter("demo", "DEMO — virtuelt netkort", "192.168.1.200", "02:00:00:00:00:fe",
                        (IPv4Network("192.168.1.0/24"),), True)]

    def scan_batch(self, ips: Sequence[str], adapter: Adapter, timeout: float) -> list[Device]:
        time.sleep(0.12)
        return [Device(ip, mac, "Demoenhed (syntetisk)",
                       datetime.now().astimezone().isoformat(timespec="seconds"))
                for ip, mac in self.DEMO_MACS.items() if ip in ips]

    def ping_batch(self, devices: Sequence[Device], adapter: Adapter,
                   timeout: float) -> dict[str, tuple[str, float | None]]:
        time.sleep(0.12)
        return {device.key: (("Intet ICMP-svar", None) if device.ip.endswith(".20")
                            else ("Echo-svar", 0.8)) for device in devices}


# ---------------------------------------------------------------------------
# 3. Scanmotor — kører i en workertråd, men kalder ALDRIG Tkinter direkte.
# ---------------------------------------------------------------------------
EventSink = Callable[[str, Any], None]


def run_scan(backend: Backend, settings: ScanSettings, stop: threading.Event,
             emit: EventSink) -> dict[str, Device]:
    settings.validate()
    devices: dict[str, Device] = {}
    pending = list(settings.targets.ips)
    for attempt in range(settings.retries + 1):
        if stop.is_set() or not pending:
            break
        phase = f"ARP — gennemløb {attempt + 1}/{settings.retries + 1}"
        emit("progress", (phase, 0, len(pending)))
        answered_ips: set[str] = set()
        for offset in range(0, len(pending), BATCH_SIZE):
            if stop.is_set():
                break
            batch = pending[offset:offset + BATCH_SIZE]
            for device in backend.scan_batch(batch, settings.adapter, settings.timeout):
                if device.ip not in batch:
                    continue
                # En IP kan svare med flere MAC-adresser; overskriv ikke den første.
                devices[device.key] = device
                answered_ips.add(device.ip)
                emit("device", device)
            emit("progress", (phase, min(offset + len(batch), len(pending)), len(pending)))
        pending = [ip for ip in pending if ip not in answered_ips]
    if settings.ping and not stop.is_set() and devices:
        ordered = sorted(devices.values(), key=lambda d: (IPv4Address(d.ip), d.mac))
        emit("progress", ("ICMP-verifikation", 0, len(ordered)))
        for offset in range(0, len(ordered), BATCH_SIZE):
            if stop.is_set():
                break
            batch = ordered[offset:offset + BATCH_SIZE]
            responses = backend.ping_batch(batch, settings.adapter, settings.timeout)
            for device in batch:
                status, rtt = responses.get(device.key, ("Intet ICMP-svar", None))
                updated = replace(device, ping=status, rtt_ms=rtt)
                devices[updated.key] = updated
                emit("device", updated)
            emit("progress", ("ICMP-verifikation", min(offset + len(batch), len(ordered)), len(ordered)))
    return devices


def friendly_error(exc: Exception) -> str:
    detail = f"{type(exc).__name__}: {exc}"
    lowered = detail.casefold()
    if isinstance(exc, PermissionError) or any(word in lowered for word in (
            "permission", "access is denied", "operation not permitted", "winerror 5")):
        return ("Adgang til netkortet blev afvist.\nWindows: start programmet som administrator.\n"
                "Linux/macOS: kontrollér rettigheder til raw sockets/BPF.\n\n" + detail)
    if any(word in lowered for word in ("npcap", "winpcap", "layer 2", "libpcap", "pcap")):
        return ("Pakkedriveren kunne ikke bruges.\nWindows: installér Npcap, genstart programmet, "
                "og vælg et aktivt Ethernet- eller Wi-Fi-netkort.\n\n" + detail)
    return "Scanningen kunne ikke gennemføres. Kontrollér netkort, forbindelse og rettigheder.\n\n" + detail


# ---------------------------------------------------------------------------
# 4. Tkinter-GUI — hovedtråden modtager events fra workertråden via en kø.
# ---------------------------------------------------------------------------
class ScannerGUI:
    def __init__(self, root: Any, demo: bool = False) -> None:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
        from tkinter.scrolledtext import ScrolledText
        self.tk, self.ttk = tk, ttk
        self.dialog, self.files = messagebox, filedialog
        self.root, self.demo = root, demo
        self.backend: Backend | None = None
        self.adapters_list: list[Adapter] = []
        self.devices: dict[str, Device] = {}
        self.by_ip: dict[str, set[str]] = {}
        self.assignments: dict[str, Assignment] | None = None
        self.context = ExportContext(source="DEMO — syntetiske data" if demo else "Scapy / ARP")
        self.events: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.stop = threading.Event()
        self.worker: threading.Thread | None = None
        self.busy = False
        self.loading = False
        self.closing = False
        self.closed = False
        self.sort_reverse: dict[str, bool] = {}
        self.locked_widgets: list[tuple[Any, str]] = []
        self.target = tk.StringVar(value="")
        self.timeout = tk.StringVar(value="1.5")
        self.retries = tk.StringVar(value="1")
        self.ping_enabled = tk.BooleanVar(value=False)
        self.log_visible = tk.BooleanVar(value=False)
        self.adapter_choice = tk.StringVar()
        self.adapter_hint = tk.StringVar(value="Alle registrerede netkort vises, også netkort som ikke kan scannes.")
        self._previous_adapter: Adapter | None = None
        self.csv_label = tk.StringVar(value="Ingen CSV indlæst — adresserne kontrolleres ikke mod en tildelingsliste.")
        self.stats = tk.StringVar(value="Fundne IP-adresser: 0   |   MAC-adresser: 0   |   Ukendte IP'er: —")
        self.status = tk.StringVar(value="Indlæser netkort …")
        self.alarm = tk.StringVar(value="")

        root.title(f"IP Scanner {VERSION}" + (" — DEMO" if demo else ""))
        root.geometry("1240x810")
        root.minsize(1040, 720)
        root.protocol("WM_DELETE_WINDOW", self.close)
        style = ttk.Style(root)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure(".", font=("Segoe UI", 10))
        style.configure("TFrame", background="#f4f7fb")
        style.configure("TLabel", background="#f4f7fb", foreground="#263e50")
        style.configure("TLabelframe", background="#f4f7fb")
        style.configure("TLabelframe.Label", background="#f4f7fb", foreground="#263e50")
        style.configure("TCheckbutton", background="#f4f7fb", foreground="#263e50")
        style.configure("TButton", padding=(8, 3), background="#ffffff", foreground="#263e50")
        style.configure("Treeview", rowheight=27, font=("Segoe UI", 10))
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
        style.configure("Title.TLabel", font=("Segoe UI", 11, "bold"))
        style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"))
        root.columnconfigure(0, weight=1)
        root.rowconfigure(1, weight=1)

        header = tk.Frame(root, bg="#132a3e", padx=22, pady=12)
        header.grid(row=0, column=0, sticky="ew")
        tk.Label(header, text="IP SCANNER", font=("Segoe UI", 22, "bold"),
                 fg="white", bg="#132a3e").pack(side="left")
        tk.Label(header, text="SCAPY  /  IPv4  /  ARP", font=("Segoe UI", 10),
                 fg="#bdd6e6", bg="#132a3e", padx=22).pack(side="left")
        ttk.Button(header, text="Om / hjælp", command=self.show_about).pack(side="right")
        body = ttk.Frame(root, padding=(18, 12))
        body.grid(row=1, column=0, sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.rowconfigure(4, weight=1)

        scanning = ttk.LabelFrame(body, text="Scanning", padding=10)
        scanning.grid(row=0, column=0, sticky="ew")
        scanning.columnconfigure(1, weight=1)
        ttk.Label(scanning, text="Netkort").grid(row=0, column=0, sticky="w", padx=(0, 12))
        self.combo = ttk.Combobox(scanning, textvariable=self.adapter_choice, state="readonly", width=65, height=20)
        self.combo.grid(row=0, column=1, sticky="ew", padx=(0, 10))
        self.combo.bind("<<ComboboxSelected>>", lambda _: self.use_subnet())
        self.locked_widgets.append((self.combo, "readonly"))
        self.refresh_button = ttk.Button(scanning, text="Opdater netkort", command=self.refresh_adapters)
        self.refresh_button.grid(row=0, column=2, sticky="ew")
        self.locked_widgets.append((self.refresh_button, "normal"))
        ttk.Label(scanning, text="Subnet / IP-range").grid(row=1, column=0, sticky="w", pady=(10, 0))
        self.entry = ttk.Entry(scanning, textvariable=self.target)
        self.entry.grid(row=1, column=1, sticky="ew", padx=(0, 10), pady=(10, 0))
        self.entry.bind("<Return>", lambda _: self.start_scan())
        self.locked_widgets.append((self.entry, "normal"))
        subnet_button = ttk.Button(scanning, text="Brug netkortets subnet", command=self.use_subnet)
        subnet_button.grid(row=1, column=2, pady=(10, 0), sticky="ew")
        self.locked_widgets.append((subnet_button, "normal"))
        ttk.Label(scanning, text="Eksempler: 192.168.1.0/24   ·   192.168.1.10-50   ·   192.168.1.10",
                  foreground="#536778").grid(row=2, column=1, sticky="w", pady=(4, 5))
        options = ttk.Frame(scanning)
        options.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(4, 0))
        ttk.Label(options, text="Svartid pr. pakkegruppe (sek.)").pack(side="left")
        timeout_spin = ttk.Spinbox(options, textvariable=self.timeout, from_=0.2, to=5, increment=0.1, width=5)
        timeout_spin.pack(side="left", padx=(6, 15))
        self.locked_widgets.append((timeout_spin, "normal"))
        ttk.Label(options, text="Ekstra ARP-forsøg").pack(side="left")
        retry_spin = ttk.Spinbox(options, textvariable=self.retries, from_=0, to=2, width=3)
        retry_spin.pack(side="left", padx=(6, 15))
        self.locked_widgets.append((retry_spin, "normal"))
        ping_check = ttk.Checkbutton(options, text="Ping fundne enheder (ICMP)", variable=self.ping_enabled)
        ping_check.pack(side="left")
        self.locked_widgets.append((ping_check, "normal"))
        self.stop_button = ttk.Button(options, text="Stop", command=self.request_stop, state="disabled")
        self.stop_button.pack(side="right")
        self.start_button = ttk.Button(options, text="Start scanning", style="Accent.TButton",
                                       command=self.start_scan, state="disabled")
        self.start_button.pack(side="right", padx=(10, 8))

        adapter_info = ttk.Frame(scanning)
        adapter_info.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(8, 0))
        adapter_info.columnconfigure(0, weight=1)
        hint_label = ttk.Label(adapter_info, textvariable=self.adapter_hint, wraplength=800,
                               foreground="#536778")
        hint_label.grid(row=0, column=0, sticky="w", padx=(0, 10))
        adapter_info.bind("<Configure>", lambda event: hint_label.configure(wraplength=max(200, event.width - 210)))
        self.details_button = ttk.Button(adapter_info, text="Netkort / diagnostik", command=self.show_adapters)
        self.details_button.grid(row=0, column=1, sticky="e")

        csv_frame = ttk.LabelFrame(body, text="Tildelte IP-adresser / CSV-kontrol", padding=(12, 8))
        csv_frame.grid(row=1, column=0, sticky="ew", pady=(9, 0))
        csv_frame.columnconfigure(0, weight=1)
        csv_label = ttk.Label(csv_frame, textvariable=self.csv_label, wraplength=620)
        csv_label.grid(row=0, column=0, sticky="w")
        csv_frame.bind("<Configure>", lambda event: csv_label.configure(wraplength=max(180, event.width - 380)))
        ttk.Button(csv_frame, text="CSV-format", command=self.show_csv_help).grid(row=0, column=3, padx=(8, 0))
        for col, label, command in [(1, "Indlæs CSV", self.import_csv), (2, "Fjern CSV", self.remove_csv)]:
            button = ttk.Button(csv_frame, text=label, command=command)
            button.grid(row=0, column=col, padx=(8, 0))
            self.locked_widgets.append((button, "normal"))
        self.banner = tk.Label(body, textvariable=self.alarm, anchor="w", padx=10, pady=7,
                               font=("Segoe UI", 10, "bold"), bg="#e9f0f5", fg="#29495e")
        self.banner.grid(row=2, column=0, sticky="ew", pady=(9, 7))
        ttk.Label(body, textvariable=self.stats, style="Title.TLabel").grid(row=3, column=0, sticky="w", pady=(0, 7))

        table_frame = ttk.Frame(body)
        table_frame.grid(row=4, column=0, sticky="nsew")
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)
        columns = ("ip", "mac", "vendor", "user", "status", "ping", "rtt", "seen")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="extended", height=9)
        self.tree.grid(row=0, column=0, sticky="nsew")
        headings = [("ip", "IP-adresse", 125), ("mac", "MAC-adresse", 145),
                    ("vendor", "Producent / OUI", 190), ("user", "Tildelt til", 125),
                    ("status", "CSV-status", 145), ("ping", "ICMP", 140),
                    ("rtt", "RTT (ms)", 78), ("seen", "ARP set kl.", 90)]
        for name, title, width in headings:
            self.tree.heading(name, text=title, command=lambda c=name: self.sort_table(c))
            self.tree.column(name, width=width, minwidth=65, stretch=name in ("vendor", "user"),
                             anchor="e" if name == "rtt" else "w")
        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        hscroll = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        hscroll.grid(row=1, column=0, sticky="ew")
        self.tree.configure(yscrollcommand=scroll.set, xscrollcommand=hscroll.set)
        self.tree.tag_configure("unknown", background="#fde7e5", foreground="#8d241d")
        self.tree.tag_configure("known", background="#eff8f2", foreground="#20533d")
        self.tree.tag_configure("conflict", background="#fff0d5", foreground="#6e4710")
        self.tree.bind("<Control-c>", lambda _: self.copy_ips())
        self.tree.bind("<Double-1>", self.show_device)

        actions = ttk.Frame(body)
        actions.grid(row=5, column=0, sticky="ew", pady=(7, 0))
        self.export_button = ttk.Button(actions, text="Gem resultater som CSV", command=self.save_csv)
        self.export_button.pack(side="left")
        ttk.Button(actions, text="Kopiér valgte IP'er", command=self.copy_ips).pack(side="left", padx=8)
        clear_button = ttk.Button(actions, text="Ryd resultater", command=self.clear_results)
        clear_button.pack(side="left")
        self.locked_widgets.extend([(self.export_button, "normal"), (clear_button, "normal")])
        ttk.Checkbutton(actions, text="Vis log", variable=self.log_visible,
                        command=self.toggle_log).pack(side="right")
        ttk.Label(actions, text="Dobbeltklik: detaljer", foreground="#536778").pack(side="right", padx=10)
        self.progress = ttk.Progressbar(body, mode="determinate", maximum=100)
        self.progress.grid(row=6, column=0, sticky="ew", pady=(9, 3))
        ttk.Label(body, textvariable=self.status).grid(row=7, column=0, sticky="w")
        self.log_widget = ScrolledText(body, height=4, wrap="word", state="disabled", font=("Consolas", 9))
        self.log_widget.grid(row=8, column=0, sticky="ew", pady=(8, 5))
        self.log_widget.grid_remove()
        ttk.Label(body, text="ARP virker på det lokale lag-2-net. Intet svar er ikke bevis for, at en IP er ledig.",
                  foreground="#536778").grid(row=9, column=0, sticky="w")

        if demo:
            self.assignments = {"192.168.1.1": Assignment("Demo-router"),
                                "192.168.1.10": Assignment("Studerende A"),
                                "192.168.1.20": Assignment("Studerende B")}
            self.csv_label.set("DEMO: 3 syntetiske tildelinger indlæst. 192.168.1.42 er ikke tildelt.")
            self.ping_enabled.set(True)
        self.update_summary()
        self.log("Demotilstand: ingen pakker sendes." if demo else
                 "Klar til lokal ARP-scanning. Brug kun netværk, du har tilladelse til at undersøge.")
        self._poll_id = self.root.after(100, self.poll_events)
        self.refresh_adapters()

    def emit(self, kind: str, data: Any = None) -> None:
        self.events.put((kind, data))

    def log(self, text: str) -> None:
        self.log_widget.configure(state="normal")
        self.log_widget.insert("end", f"{datetime.now():%H:%M:%S}  {text}\n")
        line_count = int(self.log_widget.index("end-1c").split(".")[0])
        if line_count > 700:
            self.log_widget.delete("1.0", f"{line_count - 700}.0")
        self.log_widget.see("end")
        self.log_widget.configure(state="disabled")

    def toggle_log(self) -> None:
        if self.log_visible.get():
            self.log_widget.grid()
        else:
            self.log_widget.grid_remove()

    def set_controls(self) -> None:
        locked = self.busy or self.loading or self.closing
        for widget, idle_state in self.locked_widgets:
            widget.configure(state="disabled" if locked else idle_state)
        adapter = self.selected_adapter()
        self.start_button.configure(state="normal" if not locked and adapter is not None and adapter.can_scan else "disabled")
        self.stop_button.configure(state="normal" if self.busy and not self.stop.is_set() else "disabled")

    def refresh_adapters(self) -> None:
        if self.busy or self.loading or self.closing:
            return
        self._previous_adapter = self.selected_adapter()
        self.loading = True
        self.status.set("Indlæser netkort …")
        self.set_controls()

        # Workertråden får kun almindelige Python-data, aldrig en Tk/GUI-reference.
        demo, output = self.demo, self.events

        def load() -> None:
            try:
                backend = DemoBackend() if demo else ScapyBackend()
                adapters = backend.adapters()
                if not adapters:
                    raise RuntimeError("Ingen netkort fundet i de tilgængelige datakilder.\n"
                                       "Kontrollér forbindelse, IPv4-adresse og (på Windows) Npcap.")
                output.put(("ready", (backend, adapters)))
            except Exception as exc:
                output.put(("init_error", str(exc)))
        self.worker = threading.Thread(target=load, daemon=True, name="ipscanner-init")
        self.worker.start()

    def selected_adapter(self) -> Adapter | None:
        index = self.combo.current()
        return self.adapters_list[index] if 0 <= index < len(self.adapters_list) else None

    def use_subnet(self) -> None:
        if self.busy or self.closing:
            return
        adapter = self.selected_adapter()
        if adapter:
            if adapter.can_scan:
                self.target.set(str(adapter.networks[0]) if adapter.networks else f"{adapter.ip}/32")
            else:
                self.target.set("")
        self.update_adapter_hint()
        self.set_controls()

    def update_adapter_hint(self) -> None:
        adapter = self.selected_adapter()
        if adapter is None:
            self.adapter_hint.set("Intet netkort valgt. Se Netkort / diagnostik ved problemer.")
        elif adapter.can_scan:
            state = f"Windows: {adapter.os_status}. " if adapter.os_status else ""
            warning = " Bemærkning i netkortdiagnostik." if adapter.warnings else ""
            self.adapter_hint.set(state + "IPv4 og pakkescanning tilgængelig; faktisk trafik er ikke testet." + warning)
        else:
            self.adapter_hint.set("Kan ikke scannes: " + (adapter.blocked_reason or "IPv4/MAC eller pakkedriver mangler."))

    def start_scan(self) -> None:
        if self.busy or self.loading or self.closing or self.backend is None:
            return
        adapter = self.selected_adapter()
        if adapter is None:
            self.dialog.showerror("Vælg netkort", "Vælg et aktivt Ethernet- eller Wi-Fi-netkort.", parent=self.root)
            return
        if not adapter.can_scan:
            self.dialog.showerror("Netkortet er ikke klar", adapter.details, parent=self.root)
            return
        try:
            settings = ScanSettings(parse_targets(self.target.get()), adapter,
                                    float(self.timeout.get().replace(",", ".")),
                                    int(self.retries.get()), self.ping_enabled.get())
            settings.validate()
        except ValueError as exc:
            self.dialog.showerror("Kontrollér input", str(exc), parent=self.root)
            return
        if adapter.networks and outside_adapter(settings.targets, adapter):
            self.dialog.showerror("Målet ligger uden for netkortets subnet",
                "ARP kan ikke scanne gennem en router. Vælg et netkort i målnettet eller begræns intervallet.\n\n"
                "Direkte tilsluttede net: " + ", ".join(map(str, adapter.networks)), parent=self.root)
            return
        if not adapter.networks and not self.dialog.askyesno("Subnet ukendt",
                "Netkortets subnet kunne ikke fastslås. Fortsæt kun, hvis mål-IP'erne ligger på samme "
                "lokale lag-2-net. Fortsæt?", default="no", parent=self.root):
            return
        if len(settings.targets.ips) > 4096 and not self.dialog.askyesno("Stort interval",
                f"Du har valgt {len(settings.targets.ips):,} adresser. Det giver mange ARP-forespørgsler. "
                "Start scanningen?", default="no", parent=self.root):
            return
        self.clear_results()
        self.context = replace(self.context, start=datetime.now().astimezone().isoformat(timespec="seconds"),
                               target=settings.targets.label, interface=adapter.label, state="I gang")
        self.target.set(settings.targets.label)
        self.stop.clear()
        self.busy = True
        self.set_controls()
        self.status.set("Starter ARP-scanning …")
        self.log(f"Start: {settings.targets.label}, {len(settings.targets.ips)} adresser på {adapter.name}.")
        self.log("Ekstra forsøg gensender kun forespørgsler til adresser uden svar.")
        backend, stop_event, output = self.backend, self.stop, self.events

        def post(kind: str, data: Any) -> None:
            output.put((kind, data))

        def work() -> None:
            state = "Gennemført"
            try:
                run_scan(backend, settings, stop_event, post)
                if stop_event.is_set():
                    state = "Afbrudt — delresultater"
            except Exception as exc:
                state = "Fejl — delresultater"
                post("scan_error", friendly_error(exc))
            finally:
                post("done", state)
        self.worker = threading.Thread(target=work, daemon=True, name="ipscanner-scan")
        self.worker.start()

    def request_stop(self) -> None:
        if self.busy:
            self.stop.set()
            self.status.set("Stop bestilt — afslutter igangværende pakkegruppe; delresultater bevares.")
            self.log("Stop bestilt.")
            self.set_controls()

    def poll_events(self) -> None:
        self._poll_id = None
        if self.closed:
            return
        changed = False
        for _ in range(150):
            try:
                kind, data = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == "ready":
                self.backend, self.adapters_list = data
                self.combo.configure(values=[adapter.label for adapter in self.adapters_list])
                previous = self._previous_adapter
                selected_index = next((index for index, adapter in enumerate(self.adapters_list)
                    if previous is not None and adapter.ip == previous.ip and
                    ((adapter.interface and adapter.interface == previous.interface) or
                     (adapter.guid and adapter.guid == previous.guid))), None)
                self.combo.current(selected_index if selected_index is not None else 0)
                self.loading = False
                if selected_index is None:
                    self.use_subnet()
                else:
                    self.update_adapter_hint()
                ready = sum(adapter.can_scan for adapter in self.adapters_list)
                self.status.set(f"{len(self.adapters_list)} netkort/IP-valg fundet; {ready} kan forsøges scannet.")
                self.log(self.status.get())
                for message in getattr(self.backend, "messages", []):
                    self.log(message)
                if not ready:
                    self.log("Ingen netkort er klar. Se Netkort / diagnostik for årsagen til hvert netkort.")
                self.set_controls()
            elif kind == "init_error":
                self.loading = False
                self.backend = None
                self.adapters_list = []
                self.combo.configure(values=[])
                self.adapter_choice.set("")
                self.update_adapter_hint()
                self.status.set("Netkort kunne ikke indlæses. Se fejlen i loggen.")
                self.log(data)
                self.set_controls()
                if not self.closing:
                    self.dialog.showerror("Opstart", data, parent=self.root)
            elif kind == "device":
                self.upsert_device(data)
                changed = True
            elif kind == "progress":
                phase, done, total = data
                self.progress["value"] = 100 * done / max(total, 1)
                if not self.stop.is_set():
                    self.status.set(f"{phase}: {done}/{total} adresser behandlet.")
            elif kind == "scan_error":
                self.log(data)
                if not self.closing:
                    self.dialog.showerror("Netværksfejl", data, parent=self.root)
            elif kind == "done":
                self.busy = False
                self.context = replace(self.context, state=data)
                if data == "Gennemført":
                    self.progress["value"] = 100
                self.status.set(f"{data}. {len(self.by_ip)} IP-adresser svarede på ARP.")
                self.log(self.status.get())
                if not self.devices and data == "Gennemført":
                    self.log("Ingen svar: kontrollér netkort, subnet, VLAN/Wi-Fi-isolation og svartid. "
                             "Manglende svar betyder ikke nødvendigvis, at adresserne er ledige.")
                self.set_controls()
                self.sort_table("ip", reverse=False)
                self.update_summary()
                unknown = self.unknown_ips()
                if unknown:
                    addresses = ", ".join(unknown[:15]) + (" …" if len(unknown) > 15 else "")
                    self.log(f"ALARM: {len(unknown)} IP-adresser findes ikke i tildelingslisten: {addresses}")
                    if not self.closing:
                        self.root.bell()
                        self.dialog.showwarning("Ukendte IP-adresser",
                            f"{len(unknown)} svarende IP-adresser findes ikke i den indlæste tildelingsliste:\n\n"
                            f"{addresses}\n\nDet er en afvigelse fra listen, ikke bevis for et angreb.", parent=self.root)
            if self.closing and not self.busy and not self.loading:
                self.destroy_window()
                return
        if changed:
            self.update_summary()
        self._poll_id = self.root.after(100, self.poll_events)

    def upsert_device(self, device: Device) -> None:
        new = device.key not in self.devices
        self.devices[device.key] = device
        self.by_ip.setdefault(device.ip, set()).add(device.key)
        for key in self.by_ip[device.ip]:
            self.render_device(self.devices[key])
        if new:
            status = device_status(device, self.assignments)
            self.log(f"ARP-svar: {device.ip}  {device.mac}  [{status}]")

    def render_device(self, device: Device) -> None:
        owner = (self.assignments or {}).get(device.ip, Assignment())
        conflict = len(self.by_ip.get(device.ip, set())) > 1
        unknown = self.assignments is not None and device.ip not in self.assignments
        tag = "unknown" if unknown else "conflict" if conflict else "known" if self.assignments is not None else ""
        seen = device.last_seen[11:19] if device.last_seen else ""
        values = (device.ip, device.mac, device.vendor, owner.user,
                  device_status(device, self.assignments, conflict), device.ping,
                  "" if device.rtt_ms is None else f"{device.rtt_ms:.2f}", seen)
        if self.tree.exists(device.key):
            self.tree.item(device.key, values=values, tags=(tag,))
        else:
            self.tree.insert("", "end", iid=device.key, values=values, tags=(tag,))

    def unknown_ips(self) -> list[str]:
        if self.assignments is None:
            return []
        return sorted((ip for ip in self.by_ip if ip not in self.assignments), key=IPv4Address)

    def update_summary(self) -> None:
        unknown = self.unknown_ips()
        count = str(len(unknown)) if self.assignments is not None else "—"
        self.stats.set(f"Fundne IP-adresser: {len(self.by_ip)}   |   MAC-adresser: {len(self.devices)}   |   Ukendte IP'er: {count}")
        prefix = "DEMO · Syntetiske data · Ingen netværkspakker.  " if self.demo else ""
        conflicts = sum(len(keys) > 1 for keys in self.by_ip.values())
        if unknown:
            self.alarm.set(prefix + f"ALARM: {len(unknown)} aktive IP-adresser mangler i tildelingslisten.")
            self.banner.configure(bg="#fde7e5", fg="#8d241d")
        elif conflicts:
            self.alarm.set(prefix + f"BEMÆRK: {conflicts} IP-adresser har svaret med flere MAC-adresser.")
            self.banner.configure(bg="#fff0d5", fg="#6e4710")
        else:
            text = ("CSV-kontrol aktiv. Ukendte adresser markeres og udløser en alarm."
                    if self.assignments is not None else "Indlæs en CSV-fil for at kontrollere, om adresserne er tildelt.")
            self.alarm.set(prefix + text)
            self.banner.configure(bg="#e9f0f5", fg="#29495e")

    def import_csv(self) -> None:
        if self.busy or self.loading or self.closing:
            return
        path = self.files.askopenfilename(parent=self.root, title="Indlæs tildelte IP-adresser",
                                         filetypes=[("CSV-filer", "*.csv"), ("Alle filer", "*.*")])
        if not path:
            return
        try:
            assignments = load_assignments(path)
        except (OSError, ValueError, UnicodeError, csv.Error) as exc:
            self.dialog.showerror("CSV kunne ikke indlæses", str(exc), parent=self.root)
            return
        self.assignments = assignments
        self.csv_label.set(f"{Path(path).name} — {len(assignments)} tildelte IP-adresser.")
        for device in self.devices.values():
            self.render_device(device)
        self.update_summary()
        self.log(f"Indlæst {len(assignments)} tildelte IP-adresser fra {Path(path).name}.")
        if self.unknown_ips():
            self.root.bell()
            self.dialog.showwarning("Ukendte IP-adresser",
                f"{len(self.unknown_ips())} af de allerede fundne IP-adresser mangler i den nye liste.", parent=self.root)

    def remove_csv(self) -> None:
        if self.busy or self.loading or self.closing:
            return
        self.assignments = None
        self.csv_label.set("Ingen CSV indlæst — adresserne kontrolleres ikke mod en tildelingsliste.")
        for device in self.devices.values():
            self.render_device(device)
        self.update_summary()
        self.log("Tildelingslisten er fjernet. CSV-kontrol er slået fra.")

    def clear_results(self) -> None:
        if self.busy or self.closing:
            return
        self.devices.clear()
        self.by_ip.clear()
        children = self.tree.get_children()
        if children:
            self.tree.delete(*children)
        self.progress["value"] = 0
        self.context = replace(self.context, state="Ikke startet", start="", target="", interface="")
        self.status.set("Resultater ryddet. Klar til scanning.")
        self.update_summary()

    def sort_table(self, column: str, reverse: bool | None = None) -> None:
        if reverse is None:
            reverse = not self.sort_reverse.get(column, True)
        self.sort_reverse[column] = reverse

        def key(iid: str) -> Any:
            value = self.tree.set(iid, column)
            if column == "ip":
                return int(IPv4Address(value))
            if column == "rtt":
                return float(value) if value else float("inf")
            return value.casefold()

        for index, iid in enumerate(sorted(self.tree.get_children(""), key=key, reverse=reverse)):
            self.tree.move(iid, "", index)

    def save_csv(self) -> None:
        if self.busy or self.loading or self.closing:
            return
        if not self.devices:
            self.dialog.showinfo("Ingen resultater", "Der er ingen fundne enheder at gemme.", parent=self.root)
            return
        prefix = "DEMO_" if self.demo else ""
        path = self.files.asksaveasfilename(parent=self.root, title="Gem scanresultater",
            defaultextension=".csv", initialfile=f"{prefix}ipscan_{datetime.now():%Y%m%d_%H%M%S}.csv",
            filetypes=[("CSV-filer", "*.csv")])
        if path:
            try:
                export_results(path, list(self.devices.values()), self.assignments, self.context)
            except OSError as exc:
                self.dialog.showerror("Filen kunne ikke gemmes",
                                      "Kontrollér skriverettigheder, og luk filen i Excel.\n\n" + str(exc), parent=self.root)
                return
            self.log(f"Gemt {len(self.devices)} rækker i {path}.")
            self.status.set(f"Resultater gemt i {Path(path).name}.")

    def copy_ips(self) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        ips = sorted({self.devices[key].ip for key in selection}, key=IPv4Address)
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(ips))
        self.status.set(f"{len(ips)} IP-adresser kopieret til udklipsholderen.")

    def show_device(self, event: Any) -> None:
        iid = self.tree.identify_row(event.y)
        if not iid or iid not in self.devices:
            return
        device = self.devices[iid]
        owner = (self.assignments or {}).get(device.ip, Assignment())
        self.dialog.showinfo("Enhedsoplysninger", "\n".join([
            f"IP: {device.ip}", f"MAC: {device.mac}", f"Producent: {device.vendor}",
            f"Tildelt til: {owner.user or 'Ikke angivet'}", f"Kommentar: {owner.note or 'Ingen'}",
            f"CSV-status: {device_status(device, self.assignments, len(self.by_ip[device.ip]) > 1)}",
            f"ARP-svar modtaget: {device.last_seen}", f"ICMP: {device.ping}",
            f"Datakilde: {self.context.source}"]), parent=self.root)

    def _text_window(self, title: str, text: str, action_label: str = "",
                     action: Callable[[], None] | None = None) -> Any:
        """Scrollable help/diagnostics window; usable on smaller screens as well."""
        from tkinter.scrolledtext import ScrolledText
        window = self.tk.Toplevel(self.root)
        window.title(title)
        width = min(900, max(520, self.root.winfo_screenwidth() - 100))
        height = min(680, max(400, self.root.winfo_screenheight() - 120))
        window.geometry(f"{width}x{height}")
        window.minsize(520, 400)
        window.transient(self.root)
        window.columnconfigure(0, weight=1)
        window.rowconfigure(0, weight=1)
        content = ScrolledText(window, wrap="word", font=("Consolas", 10), padx=14, pady=12)
        content.grid(row=0, column=0, sticky="nsew")
        content.insert("1.0", text)
        content.configure(state="disabled")
        buttons = self.ttk.Frame(window, padding=10)
        buttons.grid(row=1, column=0, sticky="ew")
        if action is not None:
            self.ttk.Button(buttons, text=action_label, command=action).pack(side="left")
        self.ttk.Button(buttons, text="Luk", command=window.destroy).pack(side="right")
        window.bind("<Escape>", lambda _: window.destroy())
        return window

    def show_csv_help(self) -> None:
        self._text_window("CSV-format — tildelte IP-adresser", CSV_HELP_TEXT,
                          "Gem eksempel-CSV …", self.save_assignment_example)

    def save_assignment_example(self) -> None:
        path = self.files.asksaveasfilename(parent=self.root, title="Gem eksempel på tildelingsfil",
                 defaultextension=".csv", initialfile="tildelte_ip_eksempel.csv", filetypes=[("CSV-filer", "*.csv")])
        if path:
            try:
                Path(path).write_text(CSV_EXAMPLE, encoding="utf-8-sig")
            except OSError as exc:
                self.dialog.showerror("Eksemplet kunne ikke gemmes", str(exc), parent=self.root)
                return
            self.status.set(f"Eksempel gemt i {Path(path).name}. Tilpas adresserne til dit eget net.")

    def show_adapters(self) -> None:
        selected = self.selected_adapter()
        report = adapter_inventory_report(self.adapters_list, getattr(self.backend, "messages", []))
        if self.loading:
            report = "NETKORT OPDATERES — nedenstående er seneste afsluttede inventar.\n\n" + report
        if selected is not None:
            report = "VALGT NETKORT\n" + selected.details + "\n\n" + report

        def save() -> None:
            path = self.files.asksaveasfilename(parent=self.root, title="Gem netkortdiagnostik",
                defaultextension=".txt", initialfile="netkort_diagnostik.txt", filetypes=[("Tekstfiler", "*.txt")])
            if path:
                try:
                    Path(path).write_text(report, encoding="utf-8-sig")
                except OSError as exc:
                    self.dialog.showerror("Rapporten kunne ikke gemmes", str(exc), parent=self.root)
        self._text_window("Netkort / diagnostik", report, "Gem rapport …", save)

    def show_about(self) -> None:
        self._text_window("Om IP Scanner", f"IP Scanner {VERSION}\nPython · Tkinter · Scapy\n"
            f"{COPYRIGHT}\nApache License 2.0 (egen projektkode).\n\n"
            "Indtast et IPv4-subnet eller interval, vælg netkort, og tryk Start scanning. "
            "Der udsendes Ethernet-broadcasts med ARP-requests. Kun adresser, som besvarer "
            "ARP, vises som fundet.\n\n"
            "Knappen Netkort / diagnostik viser alle fundne kort og deres tilgængelighed. "
            "Windows-only-, IPv6- og inaktive kort skjules ikke.\n\n"
            "CSV: ip er obligatorisk; bruger og kommentar er valgfrie. Se knappen CSV-format. "
            "Adresser uden for listen markeres med UKENDT IP. "
            "Det er ikke identitetskontrol eller bevis for et angreb.\n\n"
            "Ping er valgfri. En enhed kan svare på ARP uden at svare på ICMP. "
            "Producentopslag sker lokalt via Scapys OUI-database.\n\n"
            "ARP videresendes ikke af routere. Proxy ARP kan give svar på andres vegne. "
            "Egen computer bliver ikke nødvendigvis fundet af dens egne ARP-requests. "
            "Et manglende svar beviser ikke, at en IP er ledig.\n\n"
            "Stop afslutter den igangværende pakkegruppe før scanningen afsluttes. "
            "Scan kun netværk, du har tilladelse til at undersøge.\n\n"
            "Demo: start med python ipscanner.py --demo. Se README.md for installation og test.\n\n"
            "Scapy og Npcap har egne licenser. Apache 2.0 gælder ikke disse afhængigheder. "
            "Se LICENSE, NOTICE og THIRD_PARTY_NOTICES.md.")

    def close(self) -> None:
        if self.closing:
            return
        if self.busy or self.loading:
            if not self.dialog.askyesno("Afslut programmet", "Stop igangværende arbejde og luk programmet?", parent=self.root):
                return
            self.closing = True
            self.stop.set()
            self.status.set("Lukker efter igangværende pakkegruppe …")
            self.set_controls()
            return
        self.destroy_window()

    def destroy_window(self) -> None:
        """Afmeld Tk-timeren, så der ikke køres callbacks efter root.destroy()."""
        self.closed = True
        if self._poll_id is not None:
            try:
                self.root.after_cancel(self._poll_id)
            except self.tk.TclError:
                pass
            self._poll_id = None
        self.root.destroy()


def main() -> int:
    parser = argparse.ArgumentParser(description="GUI-baseret IPv4/ARP-scanner med Scapy.")
    parser.add_argument("--demo", action="store_true", help="syntetiske data; ingen netværkspakker eller Scapy-krav")
    parser.add_argument("--list-adapters", action="store_true", help="vis netkortdiagnostik uden at åbne GUI")
    parser.add_argument("--diagnostics", metavar="FIL", help="gem netkortdiagnostik i en tekstfil uden GUI eller scanning")
    parser.add_argument("--version", action="version", version=f"IP Scanner {VERSION}")
    args = parser.parse_args()
    if sys.version_info < (3, 10):
        print("Programmet kræver Python 3.10 eller nyere.", file=sys.stderr)
        return 1
    if args.list_adapters or args.diagnostics:
        try:
            backend = DemoBackend() if args.demo else ScapyBackend()
            adapters = backend.adapters()
            report = adapter_inventory_report(adapters, getattr(backend, "messages", []))
            if args.diagnostics:
                Path(args.diagnostics).write_text(report, encoding="utf-8-sig")
                print(f"Netkortrapport gemt i {args.diagnostics}")
            else:
                if hasattr(sys.stdout, "reconfigure"):
                    sys.stdout.reconfigure(errors="replace")
                print(report)
            return 0 if adapters else 1
        except Exception as exc:
            print(f"Netkortdiagnostik fejlede: {exc}", file=sys.stderr)
            return 1
    try:
        import tkinter as tk
    except ImportError:
        print("Tkinter mangler. På Debian/Ubuntu: sudo apt install python3-tk\n"
              "På Windows: tilføj Tcl/Tk via Python-installationsprogrammet.", file=sys.stderr)
        return 1
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print(f"GUI kunne ikke åbnes. Start fra et grafisk skrivebord.\n{exc}", file=sys.stderr)
        return 1
    ScannerGUI(root, demo=args.demo)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
