# Copyright 2026 Ib Helmer Nielsen
# SPDX-License-Identifier: Apache-2.0

"""Pakkeintegration med rigtig Scapy, men mock af srp: ingen netværkspakker.

Disse tests springes eksplicit over, hvis Scapy ikke er installeret.
"""
import importlib.util
import unittest
from ipaddress import IPv4Network
from unittest.mock import patch

import ipscanner as app

HAS_SCAPY = importlib.util.find_spec("scapy") is not None
ADAPTER = app.Adapter("test-interface", "Testnetkort", "192.168.1.200", "02:00:00:00:00:fe",
                      (IPv4Network("192.168.1.0/24"),))


@unittest.skipUnless(HAS_SCAPY, "Scapy er ikke installeret: pakkeintegration er ikke kørt.")
class ScapyPacketTests(unittest.TestCase):
    def setUp(self):
        self.backend = app.ScapyBackend()
        self.s = self.backend.s
        self.target = app.Device("192.168.1.10", "00:00:0c:00:00:10")

    def reply_arp(self, request, mac=None, ip=None, op=2):
        s = self.s
        return s.Ether(src=mac or self.target.mac, dst=ADAPTER.mac) / s.ARP(
            op=op, psrc=ip or self.target.ip, pdst=ADAPTER.ip,
            hwsrc=mac or self.target.mac, hwdst=ADAPTER.mac)

    def test_broadcast_request_and_selected_interface(self):
        def fake_srp(packets, **kwargs):
            self.assertEqual(kwargs["iface"], ADAPTER.interface)
            self.assertTrue(kwargs["multi"])
            self.assertEqual(packets[0][self.s.Ether].dst, "ff:ff:ff:ff:ff:ff")
            self.assertEqual(packets[0][self.s.ARP].op, 1)
            self.assertEqual(packets[0][self.s.ARP].psrc, ADAPTER.ip)
            return [(packets[0], self.reply_arp(packets[0]))], []
        with patch.object(self.s, "srp", side_effect=fake_srp):
            result = self.backend.scan_batch([self.target.ip], ADAPTER, 0.2)
        self.assertEqual((result[0].ip, result[0].mac), (self.target.ip, self.target.mac))

    def test_unsolicited_and_wrong_arp_packets_are_ignored(self):
        def fake_srp(packets, **kwargs):
            req = packets[0]
            return [(req, self.reply_arp(req, ip="192.168.1.11")),
                    (req, self.reply_arp(req, op=1))], []
        with patch.object(self.s, "srp", side_effect=fake_srp):
            self.assertEqual(self.backend.scan_batch([self.target.ip], ADAPTER, 0.2), [])

    def test_two_macs_for_one_ip_are_preserved(self):
        def fake_srp(packets, **kwargs):
            req = packets[0]
            return [(req, self.reply_arp(req)), (req, self.reply_arp(req, mac="00:00:0c:00:00:11"))], []
        with patch.object(self.s, "srp", side_effect=fake_srp):
            self.assertEqual(len(self.backend.scan_batch([self.target.ip], ADAPTER, 0.2)), 2)

    def echo_reply(self, request, **override):
        s = self.s
        fields = dict(type=0, code=0, id=request[s.ICMP].id, seq=request[s.ICMP].seq)
        fields.update(override)
        return s.Ether(src=self.target.mac, dst=ADAPTER.mac) / s.IP(src=self.target.ip, dst=ADAPTER.ip) / \
            s.ICMP(**fields) / s.Raw(load=bytes(request[s.ICMP].payload))

    def test_echo_reply_and_real_packet_timestamps(self):
        def fake_srp(packets, **kwargs):
            self.assertEqual(kwargs["iface"], ADAPTER.interface)
            request = packets[0]
            self.assertEqual(request[self.s.Ether].dst, self.target.mac)
            self.assertEqual(request[self.s.IP].src, ADAPTER.ip)
            request.sent_time = 100.0
            reply = self.echo_reply(request)
            reply.time = 100.020
            return [(request, reply)], []
        with patch.object(self.s, "srp", side_effect=fake_srp):
            result = self.backend.ping_batch([self.target], ADAPTER, 0.2)
        self.assertEqual(result[self.target.key][0], "Echo-svar")
        self.assertAlmostEqual(result[self.target.key][1], 20, places=4)

    def test_wrong_echo_sequence_is_not_a_ping_success(self):
        def fake_srp(packets, **kwargs):
            return [(packets[0], self.echo_reply(packets[0], seq=999))], []
        with patch.object(self.s, "srp", side_effect=fake_srp):
            result = self.backend.ping_batch([self.target], ADAPTER, 0.2)
        self.assertEqual(result[self.target.key], ("Intet ICMP-svar", None))

    def test_icmp_error_is_not_a_ping_success(self):
        def fake_srp(packets, **kwargs):
            return [(packets[0], self.echo_reply(packets[0], type=3, code=1))], []
        with patch.object(self.s, "srp", side_effect=fake_srp):
            result = self.backend.ping_batch([self.target], ADAPTER, 0.2)
        self.assertEqual(result[self.target.key], ("ICMP-fejl 3/1", None))

    def test_vendor_lookup_is_local(self):
        self.assertEqual(self.backend._vendor("02:00:00:00:00:01"), "Lokalt administreret MAC")
        self.assertNotEqual(self.backend._vendor("00:00:0c:00:00:01"), "Ukendt producent")


if __name__ == "__main__":
    unittest.main()
