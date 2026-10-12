# Copyright 2026 Ib Helmer Nielsen
# SPDX-License-Identifier: Apache-2.0

"""GUI-tests med syntetisk backend. Kræver et grafisk display, ikke Scapy/Npcap."""
import gc
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import ipscanner

try:
    import tkinter as tk
    DISPLAY_AVAILABLE = bool(os.environ.get("DISPLAY")) or sys.platform in ("win32", "darwin")
except ImportError:
    DISPLAY_AVAILABLE = False


@unittest.skipUnless(DISPLAY_AVAILABLE, "GUI-test kræver Tkinter og et grafisk display.")
class GUITests(unittest.TestCase):
    def setUp(self):
        self.warning = patch("tkinter.messagebox.showwarning").start()
        self.error = patch("tkinter.messagebox.showerror").start()
        self.info = patch("tkinter.messagebox.showinfo").start()
        self.question = patch("tkinter.messagebox.askyesno", return_value=True).start()
        self.addCleanup(patch.stopall)
        self.root = tk.Tk()
        self.root.withdraw()
        self.gui = ipscanner.ScannerGUI(self.root, demo=True)
        self.wait_for(lambda: not self.gui.loading)

    def tearDown(self):
        if not self.gui.closed:
            if self.gui.busy:
                self.gui.request_stop()
                self.wait_for(lambda: not self.gui.busy)
            self.gui.close()
        if self.gui.worker is not None:
            self.gui.worker.join(timeout=2)
        # Flere Tk-interpretere oprettes i tests. Frigiv dem på hovedtråden,
        # ikke ved en senere garbage collection i en netværks-worker.
        for mock in (self.warning, self.error, self.info, self.question):
            mock.reset_mock()
        self.gui = None
        self.root = None
        gc.collect()

    def wait_for(self, condition, timeout=7):
        end = time.monotonic() + timeout
        while not condition():
            if time.monotonic() >= end:
                self.fail("GUI-betingelsen blev ikke opfyldt.")
            self.root.update()
            time.sleep(0.01)
        if not self.gui.closed:
            self.root.update()

    def complete_demo(self):
        self.gui.start_scan()
        self.wait_for(lambda: not self.gui.busy)

    def test_demo_scan_and_alarm(self):
        self.complete_demo()
        self.assertEqual(len(self.gui.tree.get_children()), 4)
        self.assertEqual(self.gui.unknown_ips(), ["192.168.1.42"])
        self.assertIn("DEMO", self.gui.alarm.get())
        self.assertEqual(self.gui.context.state, "Gennemført")
        self.warning.assert_called_once()
        self.error.assert_not_called()

    def test_invalid_input_does_not_delete_results(self):
        self.complete_demo()
        self.gui.target.set("forkert")
        self.gui.start_scan()
        self.assertEqual(len(self.gui.devices), 4)
        self.error.assert_called_once()

    def test_off_link_target_is_rejected(self):
        self.gui.target.set("192.168.2.0/24")
        self.gui.start_scan()
        self.assertFalse(self.gui.busy)
        self.error.assert_called_once()

    def test_remove_csv_disables_alarm(self):
        self.complete_demo()
        self.gui.remove_csv()
        self.assertEqual(self.gui.unknown_ips(), [])
        self.assertTrue(all("Ikke kontrolleret" in self.gui.tree.set(key, "status") for key in self.gui.devices))

    def test_stop_keeps_gui_responsive(self):
        tick = []
        self.gui.start_scan()
        self.root.after(10, lambda: tick.append(True))
        self.root.after(40, self.gui.request_stop)
        self.wait_for(lambda: not self.gui.busy)
        self.assertTrue(tick)
        self.assertEqual(self.gui.context.state, "Afbrudt — delresultater")
        self.assertEqual(str(self.gui.start_button.cget("state")), "normal")

    def test_bad_csv_preserves_original_list(self):
        old = dict(self.gui.assignments)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.csv"
            path.write_text("ip;bruger\ninvalid;Ib\n", encoding="utf-8")
            with patch("tkinter.filedialog.askopenfilename", return_value=str(path)):
                self.gui.import_csv()
        self.assertEqual(self.gui.assignments, old)
        self.error.assert_called_once()

    def test_numeric_ip_sorting(self):
        for ip in ("192.168.1.10", "192.168.1.2", "192.168.1.1"):
            self.gui.upsert_device(ipscanner.Device(ip, "02:00:00:00:00:10"))
        self.gui.sort_table("ip", reverse=False)
        result = [self.gui.tree.set(key, "ip") for key in self.gui.tree.get_children()]
        self.assertEqual(result, ["192.168.1.1", "192.168.1.2", "192.168.1.10"])

    def test_close_while_scanning(self):
        self.gui.start_scan()
        self.gui.close()
        self.wait_for(lambda: self.gui.closed)
        self.assertFalse(self.gui.busy)

    def test_clear_results(self):
        self.complete_demo()
        self.gui.clear_results()
        self.assertEqual(self.gui.devices, {})
        self.assertEqual(self.gui.tree.get_children(), ())
        self.assertEqual(self.gui.context.state, "Ikke startet")


    def test_about_contains_copyright_and_license(self):
        with patch.object(self.gui, "_text_window") as window:
            self.gui.show_about()
        text = window.call_args.args[1]
        self.assertIn("Copyright 2026 Ib Helmer Nielsen", text)
        self.assertIn("Apache License 2.0", text)

    def test_csv_help_button_has_format_rules(self):
        with patch.object(self.gui, "_text_window") as window:
            self.gui.show_csv_help()
        text = window.call_args.args[1]
        self.assertIn("ip;bruger;kommentar", text)
        self.assertIn("Windows-1252", text)
        self.assertIn("Genindlæs ikke", text)

    def test_save_example_creates_readable_assignment_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example.csv"
            with patch("tkinter.filedialog.asksaveasfilename", return_value=str(path)):
                self.gui.save_assignment_example()
            items = ipscanner.load_assignments(path)
            self.assertEqual(len(items), 3)
            self.assertTrue(path.read_bytes().startswith(b"\xef\xbb\xbf"))

    def test_blocked_adapter_visible_but_start_disabled(self):
        available = self.gui.adapters_list[0]
        blocked = ipscanner.Adapter("", "Windows-only VPN", "", "", (),
                    capture_available=False, blocked_reason="Ingen IPv4; Npcap mangler")
        self.gui.emit("ready", (self.gui.backend, [available, blocked]))
        self.wait_for(lambda: len(self.gui.adapters_list) == 2)
        self.assertIn("Windows-only VPN", self.gui.combo.cget("values")[1])
        self.gui.combo.current(1)
        self.gui.use_subnet()
        self.assertEqual(str(self.gui.start_button.cget("state")), "disabled")
        self.assertIn("Ingen IPv4", self.gui.adapter_hint.get())
        self.assertEqual(self.gui.target.get(), "")
        self.gui.start_scan()
        self.assertFalse(self.gui.busy)
        self.error.assert_called_once()

    def test_refresh_preserves_selected_ip_and_manual_target(self):
        self.gui.target.set("192.168.1.10-20")
        before = self.gui.selected_adapter()
        self.gui.refresh_adapters()
        self.wait_for(lambda: not self.gui.loading)
        self.assertEqual(self.gui.selected_adapter(), before)
        self.assertEqual(self.gui.target.get(), "192.168.1.10-20")

    def test_diagnostics_shows_interface_and_sources(self):
        with patch.object(self.gui, "_text_window") as window:
            self.gui.show_adapters()
        text = window.call_args.args[1]
        self.assertIn("VALGT NETKORT", text)
        self.assertIn("Scapy-interface: demo", text)
        self.assertIn("Datakilder", text)

    def test_help_window_is_scrollable_and_closes(self):
        window = self.gui._text_window("Test", "Linje\n" * 120)
        self.root.update()
        self.assertTrue(window.winfo_exists())
        window.destroy()


if __name__ == "__main__":
    unittest.main()
