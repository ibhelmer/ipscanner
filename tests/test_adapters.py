# Copyright 2026 Ib Helmer Nielsen
# SPDX-License-Identifier: Apache-2.0

"""Windows discovery regression tests. All OS/Npcap inputs are synthetic."""
import json
import subprocess
import unittest
from dataclasses import replace
from ipaddress import IPv4Network
from types import SimpleNamespace
from unittest.mock import Mock, patch

import ipscanner as app

GUID1 = "{11111111-1111-1111-1111-111111111111}"
GUID2 = "{22222222-2222-2222-2222-222222222222}"
GUID3 = "{33333333-3333-3333-3333-333333333333}"
KEY1 = "\\Device\\NPF_" + GUID1
KEY2 = "\\Device\\NPF_" + GUID2


def iface(key=KEY1, guid=GUID1, index=12, name="Ethernet", ips=None, mac="00:11:22:33:44:55", valid=True):
    ips = ["192.168.1.200"] if ips is None else ips
    return SimpleNamespace(network_name=key, guid=guid, index=index, name=name, description="Test adapter",
                           ips={4: [ip for ip in ips if ":" not in ip], 6: [ip for ip in ips if ":" in ip]},
                           ip=next((ip for ip in ips if ":" not in ip), ""), mac=mac,
                           is_valid=lambda: valid)


def os_record(guid=GUID1, index=12, name="Ethernet", ips=None, mac="00-11-22-33-44-55", status="Up"):
    return dict(guid=guid, index=index, name=name, ips=["192.168.1.200"] if ips is None else ips,
                mac=mac, status=status, sources=["Windows test"], prefixes={"192.168.1.200": 24})


class InventoryParsingTests(unittest.TestCase):
    def test_powershell_one_adapter_one_address(self):
        payload = {"adapters": dict(name="Ethernet æøå", index=12, guid=GUID1, mac="00-11-22-33-44-55", status="Up"),
                   "addresses": dict(InterfaceIndex=12, IPAddress="192.168.1.200", PrefixLength=25), "warnings": []}
        records, messages = app.parse_windows_inventory("\ufeff" + json.dumps(payload))
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["ips"], ["192.168.1.200"])
        self.assertEqual(records[0]["prefixes"]["192.168.1.200"], 25)
        self.assertEqual(messages, [])

    def test_no_adapters_is_valid_json(self):
        records, warnings = app.parse_windows_inventory('{"adapters":[],"addresses":[],"warnings":[]}')
        self.assertEqual((records, warnings), ([], []))

    def test_ip_only_interface_remains_visible(self):
        records, _ = app.parse_windows_inventory(json.dumps({"addresses": [
            {"InterfaceIndex": 88, "InterfaceAlias": "Loopback", "IPAddress": "127.0.0.1", "PrefixLength": 8}]}))
        self.assertEqual(records[0]["name"], "Loopback")
        self.assertEqual(records[0]["index"], 88)

    def test_invalid_address_is_ignored_not_whole_adapter(self):
        records, _ = app.parse_windows_inventory(json.dumps({"adapters": {"name": "Test", "index": 12},
            "addresses": {"InterfaceIndex": 12, "IPAddress": "invalid", "PrefixLength": 24}}))
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["ips"], [])

    def test_duplicate_address_state_retained(self):
        records, _ = app.parse_windows_inventory(json.dumps({"addresses": {
            "InterfaceIndex": 12, "IPAddress": "192.168.1.200", "PrefixLength": 24, "AddressState": 2}}))
        self.assertEqual(records[0]["bad_addresses"], {"192.168.1.200": "2"})

    def test_partial_windows_error_is_explicit(self):
        records, warnings = app.parse_windows_inventory('{"adapters":[],"warnings":"Get-NetAdapter denied"}')
        self.assertEqual(warnings, ["Get-NetAdapter denied"])

    def test_invalid_json_shape(self):
        with self.assertRaises(ValueError):
            app.parse_windows_inventory('[]')

    def test_powershell_uses_timeout_and_no_shell(self):
        response = SimpleNamespace(returncode=0, stdout=b'{"adapters":[],"warnings":[]}', stderr=b'')
        with patch("ipscanner.subprocess.run", return_value=response) as run:
            self.assertEqual(app.read_windows_inventory(), ([], []))
        kwargs = run.call_args.kwargs
        self.assertEqual(kwargs["timeout"], 20)
        self.assertNotIn("shell", kwargs)
        self.assertIn("-NoProfile", run.call_args.args[0])
        self.assertNotIn("-ExecutionPolicy", run.call_args.args[0])

    def test_powershell_timeout_is_not_empty_success(self):
        with patch("ipscanner.subprocess.run", side_effect=subprocess.TimeoutExpired("powershell", 20)):
            records, warnings = app.read_windows_inventory()
        self.assertEqual(records, [])
        self.assertIn("ufuldstændig", warnings[0])

    def test_powershell_denied_is_explicit(self):
        response = SimpleNamespace(returncode=1, stdout=b'', stderr=b'Access denied')
        with patch("ipscanner.subprocess.run", return_value=response):
            records, warnings = app.read_windows_inventory()
        self.assertIn("Access denied", warnings[0])

    def test_non_utf8_output_warns(self):
        response = SimpleNamespace(returncode=0, stdout=b'\xff\xfeinvalid', stderr=b'')
        with patch("ipscanner.subprocess.run", return_value=response):
            records, warnings = app.read_windows_inventory()
        self.assertTrue(warnings)


class InventoryMergeTests(unittest.TestCase):
    def test_guid_case_and_npf_path_match(self):
        records = app.merge_interface_records([
            {"interface": KEY1, "name": "NPF", "ips": ["192.168.1.200"], "capture": True, "sources": ["Scapy"]},
            {"guid": GUID1.lower(), "name": "Ethernet", "ips": ["10.0.0.1"], "sources": ["Windows"]}])
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["interface"], KEY1)
        self.assertEqual(records[0]["name"], "Ethernet")
        self.assertEqual(len(records[0]["ips"]), 2)

    def test_same_mac_different_guid_not_merged(self):
        records = app.merge_interface_records([os_record(), os_record(guid=GUID2, index=20, name="vEthernet")])
        self.assertEqual(len(records), 2)

    def test_conflicting_guid_never_merged_by_index(self):
        self.assertEqual(len(app.merge_interface_records([os_record(), os_record(guid=GUID2)])), 2)

    def test_interface_index_fallback(self):
        records = app.merge_interface_records([{"index": 12, "name": "Scapy"}, os_record()])
        self.assertEqual(len(records), 1)

    def test_no_synthetic_capture_identifier(self):
        records = app.merge_interface_records([os_record()])
        self.assertNotIn("interface", records[0])

    def test_duplicate_addresses_deduplicated(self):
        records = app.merge_interface_records([os_record(), os_record()])
        self.assertEqual(records[0]["ips"], ["192.168.1.200"])


    def test_placeholder_mac_does_not_replace_valid_mac(self):
        records = app.merge_interface_records([os_record(), {"guid": GUID1, "mac": "00:00:00:00:00:00"}])
        self.assertEqual(records[0]["mac"], "00:11:22:33:44:55")


class WindowsBackendTests(unittest.TestCase):
    def discover(self, interfaces=None, native=None, windows=None, pcap=True, cache=None, route_error=False):
        interfaces = [iface()] if interfaces is None else interfaces
        interface_dict = {item.network_name: item for item in interfaces}
        default_cache = {key: None for key in interface_dict}
        ifaces = SimpleNamespace(values=lambda: interface_dict.values(), reload=Mock())
        route = SimpleNamespace(routes=[], resync=Mock(side_effect=OSError("route denied") if route_error else None))
        config = SimpleNamespace(ifaces=ifaces, route=route, iface=KEY1, use_pcap=pcap,
                                 use_npcap=pcap, cache_pcapiflist=default_cache if cache is None else cache)
        backend = app.ScapyBackend.__new__(app.ScapyBackend)
        backend.s = SimpleNamespace(conf=config)
        backend.interface_api = SimpleNamespace(network_name=lambda value: getattr(value, "network_name", value))
        backend.import_error = ""
        native_api = SimpleNamespace(get_windows_if_list=lambda: native or [])
        with patch.object(app.sys, "platform", "win32"), \
             patch.object(app.importlib, "import_module", return_value=native_api), \
             patch.object(app, "read_windows_inventory", return_value=(windows or [], [])):
            adapters = backend.adapters()
        return adapters, backend

    def test_windows_name_and_prefix_enrich_scapy(self):
        found, _ = self.discover(windows=[os_record(name="Ethernet 2")])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].name, "Ethernet 2")
        self.assertEqual(found[0].networks, (IPv4Network("192.168.1.0/24"),))
        self.assertTrue(found[0].can_scan)
        self.assertEqual(found[0].interface, KEY1)

    def test_inactive_and_no_ipv4_not_hidden(self):
        found, _ = self.discover(interfaces=[iface(ips=[], valid=False)], windows=[os_record(ips=[], status="Disabled")])
        self.assertEqual(len(found), 1)
        self.assertFalse(found[0].can_scan)
        self.assertIn("Disabled", found[0].blocked_reason)
        self.assertIn("Ingen IPv4", found[0].blocked_reason)

    def test_windows_only_adapter_is_listed_but_not_scannable(self):
        found, _ = self.discover(windows=[os_record(), os_record(guid=GUID2, index=20, name="VPN")])
        self.assertEqual(len(found), 2)
        vpn = next(item for item in found if item.name == "VPN")
        self.assertFalse(vpn.can_scan)
        self.assertEqual(vpn.interface, "")
        self.assertIn("Scapy/Npcap", vpn.blocked_reason)

    def test_missing_npcap_keeps_os_inventory_visible(self):
        found, _ = self.discover(pcap=False, windows=[os_record()])
        self.assertEqual(len(found), 1)
        self.assertFalse(found[0].capture_available)
        self.assertFalse(found[0].can_scan)

    def test_ipv6_only_interface_is_not_lost(self):
        found, _ = self.discover(interfaces=[iface(ips=["fe80::1234"])])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].ipv6, ("fe80::1234",))
        self.assertFalse(found[0].can_scan)

    def test_windows_api_recovers_missing_mac_and_ip(self):
        found, _ = self.discover(interfaces=[iface(ips=[], mac="")], native=[os_record()])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].mac, "00:11:22:33:44:55")
        self.assertTrue(found[0].can_scan)

    def test_multi_ip_uses_separate_prefixes(self):
        windows = os_record(ips=["192.168.1.200", "10.1.0.20"])
        windows["prefixes"] = {"192.168.1.200": 24, "10.1.0.20": 16}
        found, _ = self.discover(windows=[windows])
        self.assertEqual(len(found), 2)
        by_ip = {item.ip: item for item in found}
        self.assertEqual(by_ip["10.1.0.20"].networks, (IPv4Network("10.1.0.0/16"),))
        self.assertEqual(by_ip["192.168.1.200"].networks, (IPv4Network("192.168.1.0/24"),))

    def test_route_failure_does_not_hide_adapters(self):
        found, backend = self.discover(windows=[os_record()], route_error=True)
        self.assertEqual(len(found), 1)
        self.assertIn("route denied", backend.messages[0])

    def test_scapy_valid_false_is_warning_not_visibility_filter(self):
        found, _ = self.discover(interfaces=[iface(valid=False)], windows=[os_record(status="Up")])
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0].can_scan)
        self.assertTrue(found[0].warnings)

    def test_loopback_visible_but_arp_blocked(self):
        windows = os_record(ips=["127.0.0.1"])
        windows["type"] = 24
        found, _ = self.discover(interfaces=[iface(ips=["127.0.0.1"])], windows=[windows])
        self.assertEqual(len(found), 1)
        self.assertFalse(found[0].can_scan)
        self.assertIn("loopback", found[0].blocked_reason)

    def test_duplicate_source_ip_blocks_scan(self):
        windows = os_record()
        windows["bad_addresses"] = {"192.168.1.200": "Duplicate"}
        found, _ = self.discover(windows=[windows])
        self.assertFalse(found[0].can_scan)
        self.assertIn("Duplicate", found[0].blocked_reason)

    def test_native_windows_only_not_silently_dropped(self):
        found, _ = self.discover(interfaces=[], native=[os_record()])
        self.assertEqual(len(found), 1)
        self.assertFalse(found[0].can_scan)

    def test_import_failure_still_reads_windows(self):
        with patch.object(app.sys, "platform", "win32"), \
             patch.object(app.importlib, "import_module", side_effect=ImportError("no scapy")), \
             patch.object(app, "read_windows_inventory", return_value=([os_record()], [])):
            backend = app.ScapyBackend()
            found = backend.adapters()
        self.assertEqual(len(found), 1)
        self.assertFalse(found[0].can_scan)
        self.assertIn("Scapy kunne ikke", backend.messages[0])

    def test_report_explains_unavailable_and_does_not_send(self):
        found, backend = self.discover(windows=[os_record()])
        report = app.adapter_inventory_report(found, backend.messages)
        self.assertIn("Copyright 2026 Ib Helmer Nielsen", report)
        self.assertIn("Scapy-interface", report)
        self.assertIn("Kontrollér indholdet før deling", report)

    def test_engine_rejects_unavailable_adapter(self):
        found, _ = self.discover(pcap=False)
        settings = app.ScanSettings(app.parse_targets("192.168.1.10"), found[0])
        with self.assertRaises(ValueError):
            settings.validate()


if __name__ == "__main__":
    unittest.main()
