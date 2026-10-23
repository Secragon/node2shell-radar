import os
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QStyle, QStyleOptionButton
from shiboken6 import delete

from radar.gui import MainWindow
from radar.widgets import CopyToast, StyledCheckBox


class GuiOptionsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.window = MainWindow(Path(self.temp.name) / "sessions.sqlite")
        self.window.targets.setPlainText("example.test")

    def tearDown(self):
        self.window.close()
        delete(self.window)
        self.temp.cleanup()

    def test_discovery_controls_reach_engine_options(self):
        self.window.extra_ports.setChecked(True)
        self.window.ports.setText("3000, 8443")
        self.window.words = ["api", "staging"]
        self.window.recursive_dns.setChecked(True)
        self.window.tls_names.setChecked(False)
        self.window.crawl.setChecked(True)
        self.window.all_addresses.setChecked(True)
        self.window.workers.setValue(4)
        options = self.window._options()
        self.assertEqual(options.ports, [80, 443, 3000, 8443])
        self.assertEqual(options.words, ["api", "staging"])
        self.assertTrue(options.recursive_dns)
        self.assertFalse(options.tls_names)
        self.assertTrue(options.crawl)
        self.assertTrue(options.all_addresses)
        self.assertEqual(options.concurrency, 4)

    def test_invalid_extra_port_is_rejected(self):
        self.window.extra_ports.setChecked(True)
        self.window.ports.setText("70000")
        with self.assertRaises(ValueError):
            self.window._options()

    def test_active_probe_is_not_presented_as_available(self):
        self.assertFalse(self.window.active_check.isEnabled())
        self.assertFalse(self.window.active_check.isChecked())

    def test_possible_node_site_is_shown_as_candidate(self):
        asset = {"id": "https://candidate.example.test/", "url": "https://candidate.example.test/",
                 "http_status": 200, "node": "POSSIBLE", "version": None,
                 "technologies": ["Next.js"], "technology_versions": {"Next.js": "16.3.3"},
                 "verdict": "Unconfirmed"}
        self.window.assets[asset["id"]] = asset
        self.window.refresh_results()
        self.assertEqual(self.window.table.rowCount(), 1)
        self.assertEqual(self.window.table.item(0, 2).text(), "Possible")
        self.assertEqual(self.window.table.item(0, 3).text(), "Next.js 16.3.3")
        for col in range(self.window.table.columnCount()):
            self.assertEqual(self.window.table.item(0, col).textAlignment(),
                             self.window.table.horizontalHeaderItem(col).textAlignment())

    def test_equivalent_site_addresses_expand_below_one_candidate(self):
        for key, url in (("root", "https://example.test/"),
                         ("www", "https://www.example.test/")):
            self.window.assets[key] = {"id": key, "url": url, "final_url": url,
                                       "http_status": 200, "node": "LIKELY",
                                       "version": None, "verdict": "Unconfirmed",
                                       "content_sha256": "same"}
        self.window.refresh_results()
        self.assertEqual(self.window.table.rowCount(), 1)
        self.assertTrue(self.window.table.item(0, 0).text().startswith("▸ "))
        self.window.copy_site(0, 0)
        self.assertEqual(self.window.table.rowCount(), 2)
        self.assertIn("https://www.example.test/", self.window.table.item(1, 0).text())
        self.window.copy_site(1, 0)
        self.assertEqual(QApplication.clipboard().text(), "https://www.example.test/")
        self.assertEqual(self.window.visible_result_rows()[1]["Address"],
                         "https://www.example.test/")

    def test_different_apex_and_www_are_separate_results(self):
        for key, url, digest in (("root", "https://example.test/", "one"),
                                 ("www", "https://www.example.test/", "two")):
            self.window.assets[key] = {"id": key, "url": url, "final_url": url,
                                       "http_status": 200, "node": "LIKELY",
                                       "version": None, "verdict": "Unconfirmed",
                                       "content_sha256": digest}
        self.window.refresh_results()
        self.assertEqual(self.window.table.rowCount(), 2)
        self.assertTrue(all(not self.window.table.item(row, 0).text().startswith("▸")
                            for row in range(2)))

    def test_window_icon_has_small_sizes_and_no_inventory_control(self):
        sizes = {size.width() for size in self.window.windowIcon().availableSizes()}
        self.assertTrue({16, 32, 256}.issubset(sizes))
        self.assertFalse(hasattr(self.window, "inventory_path"))

    def test_checkboxes_and_feedback_fit_in_the_layout(self):
        window = self.window
        window.resize(1280, 780)
        window.show()
        self.app.processEvents()
        for box in (window.passive_dns, window.active_check, window.show_other):
            self.assertIsInstance(box, StyledCheckBox)
            option = QStyleOptionButton()
            box.initStyleOption(option)
            indicator = box.style().subElementRect(QStyle.SE_CheckBoxIndicator, option, box)
            self.assertGreaterEqual(indicator.left(), 0)
            self.assertLess(indicator.right(), box.width())
        self.assertIsInstance(window.copy_toast, CopyToast)
        self.assertIs(window.copy_toast.parent(), window.table.viewport())
        self.assertGreater(window.progress.width(), window.table.width() // 2)

    def test_progress_copy_and_export_visible_results(self):
        window = self.window
        window.on_event({"type": "started", "id": "gui-export", "options": {}})
        window.on_event({"type": "stage", "stage": "HTTP and Node.js signals", "total": 3})
        self.assertEqual(window.progress.maximum(), 3)
        window.on_event({"type": "progress", "completed": 1, "total": 3,
                         "current": "https://node.example.test/"})
        self.assertEqual(window.progress.value(), 1)
        asset = {"id": "https://node.example.test/", "url": "https://node.example.test/",
                 "http_status": 200, "node": "DETECTED", "version": "20.0.0",
                 "verdict": "Unconfirmed"}
        window.on_event({"type": "asset", "asset": asset})
        window.on_event({"type": "finished", "status": "COMPLETED", "completed": 1})
        window.refresh_results()
        self.assertEqual(window.progress.value(), 100)
        self.assertTrue(window.export_button.isEnabled())
        window.show()
        self.app.processEvents()
        address = window.table.item(0, 0)
        QTest.mouseClick(window.table.viewport(), Qt.LeftButton,
                         pos=window.table.visualItemRect(address).center())
        self.assertEqual(QApplication.clipboard().text(), asset["url"])
        self.assertTrue(window.copy_toast.isVisible())
        self.assertEqual(window.copy_toast.text(), "Copied")

        path = Path(self.temp.name) / "results"
        with patch("radar.gui.QFileDialog.getSaveFileName",
                   return_value=(str(path), "JSON results (*.json)")):
            window.export_button.click()
        exported = json.loads(path.with_suffix(".json").read_text(encoding="utf-8"))
        self.assertEqual(exported["results"][0]["Address"], asset["url"])
        window.search.setText("absent")
        self.assertEqual(window.visible_result_rows(), [])

if __name__ == "__main__":
    unittest.main()
