# Copyright 2026 Ib Helmer Nielsen
# SPDX-License-Identifier: Apache-2.0

"""Logiktests uden netværkstrafik og uden krav om Scapy eller et grafisk display."""
import csv
import io
import tempfile
import threading
import unittest
from dataclasses import replace
from ipaddress import IPv4Network
from pathlib import Path
from unittest.mock import patch

import ipscanner as app

ADAPTER = app.Adapter("test-interface", "Testnetkort", "192.168.1.200", "02:00:00:00:00:fe",
                      (IPv4Network("192.168.1.0/24"),))


def device(ip="192.168.1.10", mac="02:00:00:00:00:10"):
    return app.Device(ip, mac, "Testproducent", "2026-10-12T12:00:00+02:00")


class TargetTests(unittest.TestCase):
    def test_cidr_normalisation_and_host_exclusion(self):
        targets = app.parse_targets(" 192.168.1.17/24 ")
        self.assertEqual(targets.label, "192.168.1.0/24")
        self.assertEqual(len(targets.ips), 254)
        self.assertEqual(targets.ips[0], "192.168.1.1")
        self.assertEqual(targets.ips[-1], "192.168.1.254")

    def test_single_address(self):
        self.assertEqual(app.parse_targets("192.168.1.10").ips, ("192.168.1.10",))

    def test_full_range(self):
        self.assertEqual(app.parse_targets("192.168.1.10-192.168.1.12").ips,
                         ("192.168.1.10", "192.168.1.11", "192.168.1.12"))

    def test_short_range(self):
        self.assertEqual(app.parse_targets("192.168.1.10-12").ips,
                         app.parse_targets("192.168.1.10-192.168.1.12").ips)

    def test_range_can_cross_octet_boundary(self):
        self.assertEqual(len(app.parse_targets("192.168.1.254-192.168.2.1").ips), 4)

    def test_slash_31(self):
        self.assertEqual(app.parse_targets("192.168.1.0/31").ips, ("192.168.1.0", "192.168.1.1"))

    def test_slash_32(self):
        self.assertEqual(app.parse_targets("192.168.1.10/32").ips, ("192.168.1.10",))

    def test_slash_16_allowed(self):
        self.assertEqual(len(app.parse_targets("10.1.0.0/16").ips), 65534)

    def test_invalid_inputs(self):
        for value in ("", "hello", "192.168.1.999", "192.168.1.0/33", "::1", "fd00::/64",
                      "127.0.0.1", "224.0.0.1", "0.0.0.0", "255.255.255.255",
                      "192.168.1.50-10", "192.168.1.1-300", "1.2.3.4-5-6"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                app.parse_targets(value)

    def test_oversized_targets_rejected(self):
        for value in ("0.0.0.0/0", "10.0.0.0/8", "10.0.0.1-10.2.0.1"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                app.parse_targets(value)

    def test_link_check(self):
        self.assertEqual(app.outside_adapter(app.parse_targets("192.168.1.0/24"), ADAPTER), ())
        self.assertEqual(app.outside_adapter(app.parse_targets("192.168.2.10"), ADAPTER), ("192.168.2.10",))

    def test_source_adapter_multiple_networks(self):
        adapter = replace(ADAPTER, networks=ADAPTER.networks + (IPv4Network("192.168.2.0/24"),))
        self.assertFalse(app.outside_adapter(app.parse_targets("192.168.1.254-192.168.2.1"), adapter))

    def test_mac_validation(self):
        self.assertEqual(app.normalise_mac("00-AA-BB-CC-DD-EE"), "00:aa:bb:cc:dd:ee")
        for value in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01", "abcdef"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                app.normalise_mac(value)

    def test_invalid_numeric_scan_settings(self):
        base = app.ScanSettings(app.parse_targets("192.168.1.10"), ADAPTER)
        for value in (0, -1, 5.1, float("nan"), float("inf")):
            with self.subTest(timeout=value), self.assertRaises(ValueError):
                replace(base, timeout=value).validate()
        for value in (-1, 3, True, 1.5):
            with self.subTest(retries=value), self.assertRaises(ValueError):
                replace(base, retries=value).validate()


class CSVTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "test.csv"

    def tearDown(self):
        self.directory.cleanup()

    def load(self, text, encoding="utf-8-sig"):
        self.path.write_bytes(text.encode(encoding))
        return app.load_assignments(self.path)

    def test_semicolon_and_danish_text(self):
        items = self.load("ip;bruger;kommentar\n192.168.1.10;Søren;Bærbar\n")
        self.assertEqual(items["192.168.1.10"], app.Assignment("Søren", "Bærbar"))

    def test_comma_quoted_value(self):
        items = self.load('ip,user,note\n192.168.1.10,"Jensen, Ib",Test\n')
        self.assertEqual(items["192.168.1.10"].user, "Jensen, Ib")

    def test_tab_separated(self):
        self.assertIn("192.168.1.10", self.load("ip\tbruger\n192.168.1.10\tIb\n"))

    def test_cp1252(self):
        self.assertEqual(self.load("ip;bruger\n192.168.1.10;Søren\n", "cp1252")["192.168.1.10"].user, "Søren")

    def test_only_ip_column(self):
        self.assertEqual(len(self.load("ip\n192.168.1.10\n192.168.1.20\n")), 2)

    def test_case_and_header_aliases(self):
        self.assertIn("192.168.1.10", self.load("IP_ADDRESS; OWNER \n192.168.1.10;Ib\n"))

    def test_duplicate_identical_is_deduplicated(self):
        self.assertEqual(len(self.load("ip;bruger\n192.168.1.10;Ib\n192.168.1.10;Ib\n")), 1)

    def test_duplicate_conflict_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "modstridende"):
            self.load("ip;bruger\n192.168.1.10;Ib\n192.168.1.10;Anden\n")

    def test_invalid_csv(self):
        for text in ("", "ip;bruger\n", "adresse;bruger\n192.168.1.10;Ib\n",
                     "ip;bruger\nnot-an-ip;Ib\n", "ip;bruger\nfd00::1;Ib\n",
                     "ip;ip\n192.168.1.10;192.168.1.10\n", "ip;bruger\n;Ib\n",
                     "ip;bruger\n192.168.1.10;Ib;for mange\n"):
            with self.subTest(text=text), self.assertRaises((ValueError, csv.Error)):
                self.load(text)

    def test_invalid_row_reports_line(self):
        with self.assertRaisesRegex(ValueError, "CSV-linje 3"):
            self.load("ip;bruger\n192.168.1.10;Ib\nfejl;Anden\n")

    def test_too_large_file(self):
        self.path.write_bytes(b"a" * (app.MAX_CSV_BYTES + 1))
        with self.assertRaises(ValueError):
            app.load_assignments(self.path)

    def test_export_is_sorted_and_contains_metadata(self):
        devices = [device("192.168.1.20"), device("192.168.1.2", "02:00:00:00:00:02")]
        context = app.ExportContext("2026-10-12T12:00:00+02:00", "192.168.1.0/24", "Testnetkort",
                                    "Afbrudt — delresultater", "DEMO — syntetiske data")
        app.export_results(self.path, devices, {"192.168.1.20": app.Assignment("Ib")}, context)
        self.assertTrue(self.path.read_bytes().startswith(b"\xef\xbb\xbf"))
        rows = list(csv.DictReader(io.StringIO(self.path.read_text(encoding="utf-8-sig")), delimiter=";"))
        self.assertEqual(rows[0]["ip"], "192.168.1.2")
        self.assertEqual(rows[0]["status"], "UKENDT IP")
        self.assertEqual(rows[1]["status"], "Tildelt")
        self.assertEqual(rows[0]["scan_status"], "Afbrudt — delresultater")
        self.assertEqual(rows[0]["datakilde"], "DEMO — syntetiske data")

    def test_export_formula_protection(self):
        app.export_results(self.path, [device()], {"192.168.1.10": app.Assignment("=1+1", "@SUM(1)")},
                           app.ExportContext())
        rows = list(csv.DictReader(io.StringIO(self.path.read_text(encoding="utf-8-sig")), delimiter=";"))
        self.assertEqual(rows[0]["bruger"], "'=1+1")
        self.assertEqual(rows[0]["kommentar"], "'@SUM(1)")

    def test_safe_csv_cells(self):
        for text in ("=1+1", " +1", "-SUM(1)", "@SUM(1)", "\ttext", "\ntext"):
            self.assertEqual(app.safe_csv_cell(text), "'" + text)
        self.assertEqual(app.safe_csv_cell("Søren"), "Søren")

    def test_atomic_export_keeps_old_file_if_replace_fails(self):
        self.path.write_text("original", encoding="utf-8")
        with patch("ipscanner.os.replace", side_effect=PermissionError("locked")):
            with self.assertRaises(PermissionError):
                app.export_results(self.path, [device()], None, app.ExportContext())
        self.assertEqual(self.path.read_text(), "original")
        self.assertEqual(list(self.path.parent.glob("*.tmp")), [])

    def test_duplicate_ip_is_reported_in_export(self):
        app.export_results(self.path, [device(), device(mac="02:00:00:00:00:11")], None, app.ExportContext())
        self.assertIn("flere MAC", self.path.read_text(encoding="utf-8-sig"))

    def test_decimal_comma_for_danish_excel(self):
        app.export_results(self.path, [replace(device(), ping="Echo-svar", rtt_ms=1.25)], None, app.ExportContext())
        self.assertIn("1,25", self.path.read_text(encoding="utf-8-sig"))


    def test_blank_header_is_rejected(self):
        with self.assertRaises(ValueError):
            self.load("ip;;kommentar\n192.168.1.10;Ib;Test\n")

    def test_multiple_aliases_for_same_column_are_rejected(self):
        for text in ("ip;ip_address\n192.168.1.10;192.168.1.20\n",
                     "ip;bruger;owner\n192.168.1.10;Ib;Anden\n"):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, "samme betydning"):
                self.load(text)

    def test_documented_semicolon_and_quotes_example(self):
        items = self.load('ip;bruger;kommentar\n192.168.1.30;"Gruppe A; Gruppe B";"PC kaldet ""Lab 1"""\n')
        self.assertEqual(items["192.168.1.30"], app.Assignment("Gruppe A; Gruppe B", 'PC kaldet "Lab 1"'))

    def test_csv_rejects_subnets_ranges_and_ipv6(self):
        for value in ("192.168.1.0/24", "192.168.1.10-20", "fe80::1", "pc01.local"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.load("ip\n" + value + "\n")

    def test_unknown_columns_and_reordered_headers(self):
        items = self.load("kommentar;extra;IP Address;bruger\nTest;ignored;192.168.1.10;Ib\n")
        self.assertEqual(items["192.168.1.10"], app.Assignment("Ib", "Test"))

    def test_utf16_not_supported(self):
        with self.assertRaises((ValueError, UnicodeError, csv.Error)):
            self.load("ip;bruger\n192.168.1.10;Ib\n", "utf-16")


class FakeBackend:
    def __init__(self, observations=None, stop=None):
        self.observations = observations or []
        self.calls = []
        self.ping_calls = []
        self.stop = stop

    def scan_batch(self, ips, adapter, timeout):
        self.calls.append(tuple(ips))
        if self.stop is not None:
            self.stop.set()
        return [item for item in self.observations if item.ip in ips]

    def ping_batch(self, devices, adapter, timeout):
        self.ping_calls.append(tuple(devices))
        return {item.key: ("Intet ICMP-svar", None) for item in devices}


class ScanEngineTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.stop = threading.Event()

    def scan(self, backend, text="192.168.1.1-3", retries=1, ping=False):
        settings = app.ScanSettings(app.parse_targets(text), ADAPTER, 0.2, retries, ping)
        return app.run_scan(backend, settings, self.stop, lambda *event: self.events.append(event))

    def test_retry_only_unanswered_addresses(self):
        backend = FakeBackend([device("192.168.1.1")])
        self.scan(backend)
        self.assertEqual(backend.calls, [("192.168.1.1", "192.168.1.2", "192.168.1.3"),
                                         ("192.168.1.2", "192.168.1.3")])

    def test_multiple_macs_are_preserved(self):
        backend = FakeBackend([device("192.168.1.1"), device("192.168.1.1", "02:00:00:00:00:11")])
        self.assertEqual(len(self.scan(backend)), 2)

    def test_repeated_identical_observation_is_deduplicated(self):
        observation = device("192.168.1.1")
        self.assertEqual(len(self.scan(FakeBackend([observation, observation]))), 1)

    def test_cancel_before_start_sends_nothing(self):
        backend = FakeBackend()
        self.stop.set()
        self.assertEqual(self.scan(backend), {})
        self.assertEqual(backend.calls, [])

    def test_cancel_between_batches_preserves_partial_results(self):
        backend = FakeBackend([device("192.168.1.1")], stop=self.stop)
        found = self.scan(backend, "192.168.1.0/24", ping=True)
        self.assertEqual(len(backend.calls), 1)
        self.assertEqual(len(found), 1)
        self.assertEqual(backend.ping_calls, [])

    def test_ping_timeout_keeps_arp_device(self):
        found = self.scan(FakeBackend([device("192.168.1.1")]), ping=True)
        self.assertEqual(len(found), 1)
        self.assertEqual(next(iter(found.values())).ping, "Intet ICMP-svar")

    def test_ping_optional(self):
        backend = FakeBackend([device("192.168.1.1")])
        self.scan(backend, ping=False)
        self.assertEqual(backend.ping_calls, [])

    def test_empty_scan_does_not_ping(self):
        backend = FakeBackend()
        self.assertEqual(self.scan(backend, ping=True), {})
        self.assertEqual(backend.ping_calls, [])

    def test_batch_size_is_bounded(self):
        backend = FakeBackend()
        self.scan(backend, "192.168.1.0/24", retries=0)
        self.assertEqual(len(backend.calls), 4)
        self.assertLessEqual(max(map(len, backend.calls)), app.BATCH_SIZE)
        self.assertEqual(sum(map(len, backend.calls)), 254)

    def test_progress_completes(self):
        self.scan(FakeBackend(), retries=0)
        self.assertEqual(self.events[-1], ("progress", ("ARP — gennemløb 1/1", 3, 3)))

    def test_unknown_status_is_not_enabled_without_csv(self):
        self.assertEqual(app.device_status(device(), None), "Ikke kontrolleret")
        self.assertEqual(app.device_status(device(), {}), "UKENDT IP")
        self.assertEqual(app.device_status(device(), {"192.168.1.10": app.Assignment()}), "Tildelt")

    def test_permission_error_is_user_friendly(self):
        self.assertIn("administrator", app.friendly_error(PermissionError("denied")))

    def test_driver_error_is_user_friendly(self):
        self.assertIn("installér Npcap", app.friendly_error(RuntimeError("Npcap failed")))

    def test_demo_uses_only_synthetic_addresses(self):
        backend = app.DemoBackend()
        with patch("ipscanner.time.sleep"):
            result = self.scan(backend, "192.168.1.0/24", ping=True)
        self.assertEqual({d.ip for d in result.values()}, set(backend.DEMO_MACS))
        self.assertTrue(all("syntetisk" in d.vendor for d in result.values()))


if __name__ == "__main__":
    unittest.main()
