"""Desktop UI for Node2Shell Radar."""

import asyncio
from html import escape
from pathlib import Path
import re
import sys

from PySide6.QtCore import QStandardPaths, Qt, QThread, QTimer, Signal
from PySide6.QtGui import QColor, QIcon
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QDialog, QDialogButtonBox, QDoubleSpinBox,
    QFileDialog, QFormLayout, QGridLayout, QGroupBox, QHBoxLayout,
    QHeaderView, QInputDialog, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QPlainTextEdit, QProgressBar, QPushButton, QSpinBox, QSplitter,
    QTableWidget, QTableWidgetItem, QToolButton, QVBoxLayout,
    QWidget,
)

from radar.engine import Control, run_scan
from radar.models import ScanOptions, WEB_PORTS, default_words, parse_targets
from radar.storage import Store, export_visible_results, grouped_websites
from radar.widgets import CopyToast, StyledCheckBox


STYLE = """
QWidget { background: #f7fafb; color: #263b43; font-family: 'Segoe UI'; font-size: 13px; }
QMainWindow { background: #f7fafb; }
QLabel#title { font-size: 24px; font-weight: 700; color: #173f4d; }
QLabel#metric { color: #3f6975; font-size: 15px; font-weight: 550; }
QLabel#subtitle { color: #667d87; font-size: 12px; }
QGroupBox { background: #ffffff; border: 1px solid #dbe9e9; border-radius: 12px;
            margin-top: 12px; padding: 15px 12px 10px; font-weight: 650; }
QGroupBox::title { subcontrol-origin: margin; left: 11px; padding: 0 6px; color: #315865; }
QPlainTextEdit, QLineEdit, QTextBrowser, QSpinBox, QDoubleSpinBox { background: #ffffff; border: 1px solid #d5e3e6;
             border-radius: 7px; padding: 6px; selection-background-color: #d8eeed; }
QPlainTextEdit:focus, QLineEdit:focus { border-color: #77b9b8; }
QPushButton { background: #e9f3f2; color: #285b62; border: 1px solid #d1e8e5;
              border-radius: 7px; padding: 7px 12px; font-weight: 600; }
QPushButton:hover { background: #d9ece9; }
QPushButton:disabled { color: #a2adb3; background: #edf1f2; border-color: #dce6e7; }
QPushButton#primary { background: #267f84; color: #ffffff; border: none; font-weight: 700; }
QPushButton#primary:hover { background: #1d6c72; }
QPushButton#advancedButton { background: #e4f1f1; color: #315e66; border-color: #c9e1e1; }
QCheckBox { spacing: 7px; }
QCheckBox::indicator { width: 16px; height: 16px; }
QWidget#optionRow { background: transparent; }
QTableWidget { background: #ffffff; alternate-background-color: #f8fbfb;
               border: 1px solid #dce8e9; gridline-color: #ecf1f1;
               selection-background-color: #e2f2f0; selection-color: #173f4d; }
QHeaderView::section { background: #edf6f5; color: #4c6e76; padding: 8px;
                       border: none; font-weight: 650; }
QProgressBar { background: #e7efef; border: none; border-radius: 3px;
               min-height: 6px; max-height: 6px; text-align: center; }
QProgressBar::chunk { background: #267f84; border-radius: 3px; }
QToolButton#help { background: #e8f3f8; color: #527c93; border: 1px solid #cce4ef;
                   border-radius: 10px; font-weight: 800; }
QToolButton#help:hover { background: #d7ebf4; }
QSplitter::handle { background: #e2eeee; height: 5px; }
"""


class ScanThread(QThread):
    event = Signal(dict)

    def __init__(self, options, parent=None):
        super().__init__(parent)
        self.options = options
        self.control = Control()

    def run(self):
        try:
            asyncio.run(run_scan(self.options, self.control, self.event.emit))
        except Exception as exc:
            self.event.emit({"type": "finished", "status": "FAILED", "error": str(exc)})


def help_button(title, description, impact):
    button = QToolButton()
    button.setObjectName("help")
    button.setText("?")
    button.setFixedSize(21, 21)
    body = f"{description}\n\nImpact: {impact}"
    button.setToolTip(f"<div style='width:340px;white-space:normal'>{escape(body).replace(chr(10), '<br>')}</div>")
    button.clicked.connect(lambda: QMessageBox.information(button, title, body))
    return button


class MainWindow(QMainWindow):
    NODE_ROWS = {"DETECTED", "LIKELY", "POSSIBLE"}
    VERDICT_COLORS = {
        "Fixed version": ("#e4f5e9", "#1f7140"),
        "Fixed version reported": ("#e4f5e9", "#1f7140"),
        "At risk": ("#fde8e6", "#a53e3a"),
        "Unconfirmed": ("#fff4d8", "#896a1e"),
    }

    def __init__(self, store_path=None):
        super().__init__()
        self.setWindowTitle("Node2Shell Radar")
        self.setMinimumSize(780, 560)
        screen = QApplication.primaryScreen().availableGeometry()
        self.resize(min(1280, screen.width() - 40), min(780, screen.height() - 40))
        self.assets = {}
        self.display_rows = []
        self.expanded_sites = set()
        self.run_document = {}
        self.thread = None
        self.finished = False
        self._close_when_done = False
        self.words = default_words()
        data_path = Path(store_path) if store_path else Path(
            QStandardPaths.writableLocation(QStandardPaths.AppDataLocation)) / "sessions.sqlite"
        self.store = Store(data_path)
        icon_path = Path(__file__).parent / "data" / "app-icon.ico"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))
        self._build_ui()
        self.refresh_timer = QTimer(self)
        self.refresh_timer.setSingleShot(True)
        self.refresh_timer.timeout.connect(self.refresh_results)

    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)

        heading = QHBoxLayout()
        title = QLabel("Node2Shell Radar")
        title.setObjectName("title")
        heading.addWidget(title, 1)
        advanced = QPushButton("More options  ↗")
        advanced.setObjectName("advancedButton")
        advanced.clicked.connect(self.open_advanced)
        heading.addWidget(advanced)
        self.history_button = QPushButton("History")
        self.history_button.clicked.connect(self.open_history)
        heading.addWidget(self.history_button)
        layout.addLayout(heading)

        config = QWidget()
        config.setMaximumHeight(210)
        config_grid = QGridLayout(config)
        config_grid.setContentsMargins(0, 0, 0, 0)
        config_grid.setHorizontalSpacing(10)
        target_box = QGroupBox("Domains and URLs")
        target_layout = QVBoxLayout(target_box)
        self.targets = QPlainTextEdit()
        self.targets.setPlaceholderText("One domain or URL per line\nexample.com\nhttps://app.example.com/")
        self.targets.setMinimumHeight(100)
        target_layout.addWidget(self.targets)
        load = QPushButton("Load list…")
        load.clicked.connect(self.import_targets)
        target_layout.addWidget(load)
        config_grid.addWidget(target_box, 0, 0, Qt.AlignTop)

        options_box = QGroupBox("Discovery")
        options_layout = QVBoxLayout(options_box)
        self.passive_dns = self._option(options_layout, "Find public subdomains", True,
            "Find subdomain names in public certificate and DNS-related sources.",
            "Read-only requests to public services; each candidate is checked before it counts as a website.")
        self.active_dns = self._option(options_layout, "Check common subdomains", True,
            "Try the bundled top-100 generic names against the domain's DNS.",
            "Up to about 100 DNS lookups per domain, plus checks for names that resolve.")
        self.extra_ports = self._option(options_layout, "Check other web ports", False,
            "Check common additional web ports such as 3000, 8080 and 8443.",
            "Makes more connections to each discovered host; may reach development services.")
        self.port_row = QWidget()
        port_layout = QVBoxLayout(self.port_row)
        port_layout.setContentsMargins(0, 2, 0, 0)
        port_layout.addWidget(QLabel("Additional ports"))
        self.ports = QLineEdit(", ".join(map(str, WEB_PORTS[2:])))
        self.ports.setToolTip("Edit the extra ports. Ports 80 and 443 are always checked.")
        port_layout.addWidget(self.ports)
        self.port_row.setVisible(False)
        self.extra_ports.toggled.connect(self.port_row.setVisible)
        options_layout.addWidget(self.port_row)
        config_grid.addWidget(options_box, 0, 1, Qt.AlignTop)

        detection_box = QGroupBox("Node.js detection")
        detection_layout = QVBoxLayout(detection_box)
        self.passive_check = self._option(detection_layout, "Read public Node.js clues", True,
            "Read the normal HTTP response for Node.js runtime, framework and version indicators.",
            "This is the standard passive detection and is always part of a scan.")
        self.passive_check.setEnabled(False)
        self.active_check = self._option(detection_layout, "Active check if unclear", False,
            "A Node.js-specific Brotli decoder probe requires separate validation before it can assess a remote process.",
            "This check is not available yet. Selecting it will not send a probe or change the verdict.")
        self.active_check.setEnabled(False)
        config_grid.addWidget(detection_box, 0, 2, Qt.AlignTop)
        for column in range(3):
            config_grid.setColumnStretch(column, 1)

        self.advanced_dialog = QDialog(self)
        self.advanced_dialog.setWindowTitle("More options")
        dialog_layout = QVBoxLayout(self.advanced_dialog)
        dialog_columns = QHBoxLayout()
        discovery_extras = QGroupBox("Discovery extras")
        discovery_extras_layout = QVBoxLayout(discovery_extras)
        edit_words = QPushButton("Edit DNS names…")
        edit_words.clicked.connect(self.edit_words)
        discovery_extras_layout.addWidget(edit_words)
        self.recursive_dns = self._option(discovery_extras_layout, "Check deeper subdomains", False,
            "Try common names one level below up to 20 resolved subdomains.",
            "Can add up to 1,000 DNS candidates per root domain.")
        self.tls_names = self._option(discovery_extras_layout, "Read names from TLS certificates", True,
            "Read same-domain names in the site's TLS certificate.",
            "Adds a certificate connection and checks the names it yields.")
        self.crawl = self._option(discovery_extras_layout, "Check pages within each site", False,
            "Follow same-site links, robots.txt and sitemap.xml for Node.js clues.",
            "Up to 12 additional GET requests per reached website.")
        self.all_addresses = self._option(discovery_extras_layout, "Check every IP address", False,
            "Check the site on each resolved address.",
            "Can multiply web requests for names with several addresses.")
        discovery_extras_layout.addStretch()
        dialog_columns.addWidget(discovery_extras, 1)

        scan_settings = QGroupBox("Scan behavior")
        scan_settings_layout = QVBoxLayout(scan_settings)
        self.verify_tls = self._option(scan_settings_layout, "Verify TLS certificates", True,
            "Require HTTPS certificates to be trusted and match the website name.",
            "Turning this off permits inspection of sites with invalid certificates.")
        settings_form = QFormLayout()
        self.workers = QSpinBox()
        self.workers.setRange(1, 32)
        self.workers.setValue(8)
        settings_form.addRow("Concurrent checks", self.workers)
        self.timeout = QDoubleSpinBox()
        self.timeout.setRange(1, 60)
        self.timeout.setValue(7)
        self.timeout.setSuffix(" s")
        settings_form.addRow("Timeout", self.timeout)
        self.interval = QDoubleSpinBox()
        self.interval.setRange(0.1, 10)
        self.interval.setValue(0.35)
        self.interval.setSingleStep(0.1)
        self.interval.setSuffix(" s")
        settings_form.addRow("Request interval", self.interval)
        scan_settings_layout.addLayout(settings_form)
        scan_settings_layout.addStretch()
        dialog_columns.addWidget(scan_settings, 1)
        dialog_layout.addLayout(dialog_columns)
        done = QDialogButtonBox(QDialogButtonBox.Close)
        done.rejected.connect(self.advanced_dialog.reject)
        dialog_layout.addWidget(done)
        self.advanced_dialog.resize(980, 480)

        outer_splitter = QSplitter(Qt.Vertical)
        outer_splitter.addWidget(config)

        actions = QHBoxLayout()
        actions.setContentsMargins(0, 5, 0, 0)
        self.start_button = QPushButton("Scan")
        self.start_button.setObjectName("primary")
        self.start_button.clicked.connect(self.start_scan)
        actions.addWidget(self.start_button)
        self.pause_button = QPushButton("Pause")
        self.pause_button.setEnabled(False)
        self.pause_button.clicked.connect(self.pause_scan)
        actions.addWidget(self.pause_button)
        self.stop_button = QPushButton("Stop")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_scan)
        actions.addWidget(self.stop_button)
        actions.addStretch()
        self.metric_label = QLabel("Node.js candidates 0/0")
        self.metric_label.setObjectName("metric")
        actions.addWidget(self.metric_label)
        self.show_other = StyledCheckBox("Show other sites")
        self.show_other.setEnabled(False)
        self.show_other.toggled.connect(self.refresh_results)
        actions.addWidget(self.show_other)

        self.splitter = QSplitter(Qt.Horizontal)
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.addLayout(actions)
        search_row = QHBoxLayout()
        search_row.addWidget(QLabel("Node.js candidates"))
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search Node.js sites…")
        self.search.textChanged.connect(self.refresh_results)
        search_row.addWidget(self.search, 1)
        left_layout.addLayout(search_row)
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Address", "HTTP", "Node.js", "Version", "Active check", "Result"])
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(36)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        samples = {1: ("HTTP", "503"), 2: ("Node.js", "Detected"),
                   3: ("Version", "Next.js 16.3.3", "Node.js 24.22.0"),
                   4: ("Active check",), 5: ("Result", "Unconfirmed")}
        item_metrics = self.table.fontMetrics()
        header_metrics = self.table.horizontalHeader().fontMetrics()
        for col, labels in samples.items():
            self.table.horizontalHeader().setSectionResizeMode(col, QHeaderView.Interactive)
            width = max(max(item_metrics.horizontalAdvance(label) for label in labels),
                        header_metrics.horizontalAdvance(labels[0])) + 28
            self.table.setColumnWidth(col, width)
        for col in range(self.table.columnCount()):
            alignment = Qt.AlignVCenter | (Qt.AlignLeft if col == 0 else Qt.AlignHCenter)
            self.table.horizontalHeaderItem(col).setTextAlignment(alignment)
        self.table.cellClicked.connect(self.copy_site)
        self.table.cellDoubleClicked.connect(self.show_details)
        self.copy_toast = CopyToast(self.table.viewport())
        self.copy_toast.hide()
        left_layout.addWidget(self.table, 1)
        self.splitter.addWidget(left)

        self.journal_panel = QWidget()
        journal_layout = QVBoxLayout(self.journal_panel)
        journal_layout.setContentsMargins(8, 0, 0, 0)
        journal_layout.addWidget(QLabel("Journal"))
        self.journal = QPlainTextEdit()
        self.journal.setReadOnly(True)
        self.journal.setLineWrapMode(QPlainTextEdit.NoWrap)
        journal_layout.addWidget(self.journal)
        self.splitter.addWidget(self.journal_panel)
        self.journal_panel.hide()
        outer_splitter.addWidget(self.splitter)
        outer_splitter.setStretchFactor(1, 1)
        layout.addWidget(outer_splitter, 1)

        bottom = QHBoxLayout()
        self.status = QLabel("Ready")
        self.status.setObjectName("subtitle")
        bottom.addWidget(self.status, 1)
        self.export_button = QPushButton("Export results")
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self.export)
        bottom.addWidget(self.export_button)
        self.journal_button = QPushButton("Journal  ›")
        self.journal_button.clicked.connect(self.toggle_journal)
        bottom.addWidget(self.journal_button)
        layout.addLayout(bottom)
        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        layout.addWidget(self.progress)

    def _option(self, parent_layout, label, checked, description, impact):
        row = QWidget()
        row.setObjectName("optionRow")
        cell = QHBoxLayout(row)
        cell.setContentsMargins(8, 0, 0, 0)
        checkbox = StyledCheckBox(label)
        checkbox.setChecked(checked)
        checkbox.setToolTip(f"<div style='width:340px'>{escape(description)}<br><br>Impact: {escape(impact)}</div>")
        cell.addWidget(checkbox)
        cell.addStretch()
        cell.addWidget(help_button(label, description, impact))
        parent_layout.addWidget(row)
        return checkbox

    def open_advanced(self):
        self.advanced_dialog.exec()

    def import_targets(self):
        path, _ = QFileDialog.getOpenFileName(self, "Load domains or URLs", "", "Text lists (*.txt *.csv);;All files (*)")
        if path:
            try:
                self.targets.setPlainText(Path(path).read_text(encoding="utf-8-sig"))
            except OSError as exc:
                QMessageBox.warning(self, "Load failed", str(exc))

    def edit_words(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Edit DNS names")
        dialog.resize(480, 540)
        layout = QVBoxLayout(dialog)
        layout.addWidget(QLabel("One DNS name per line. These names are tried for every entered domain."))
        editor = QPlainTextEdit("\n".join(self.words))
        layout.addWidget(editor)
        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        if dialog.exec() == QDialog.Accepted:
            words = list(dict.fromkeys(editor.toPlainText().lower().split()))
            if not words or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", word)
                                or ".." in word for word in words):
                QMessageBox.warning(self, "Invalid DNS names", "Enter valid, nonempty DNS names.")
                return
            self.words = words
            self.active_dns.setText(f"Check {len(words)} subdomains")

    def _options(self):
        ports = list(WEB_PORTS)
        if self.extra_ports.isChecked():
            values = [value for value in re.split(r"[,\s]+", self.ports.text().strip()) if value]
            if not values or any(not value.isdecimal() or not 1 <= int(value) <= 65535 for value in values):
                raise ValueError("Additional ports must be numbers between 1 and 65535.")
            ports = list(dict.fromkeys([80, 443] + [int(value) for value in values]))
        return ScanOptions(
            targets=parse_targets(self.targets.toPlainText()),
            passive_dns=self.passive_dns.isChecked(), active_dns=self.active_dns.isChecked(),
            tls_names=self.tls_names.isChecked(), extra_ports=self.extra_ports.isChecked(),
            ports=ports, words=self.words.copy(), recursive_dns=self.recursive_dns.isChecked(),
            crawl=self.crawl.isChecked(), all_addresses=self.all_addresses.isChecked(),
            verify_tls=self.verify_tls.isChecked(), concurrency=self.workers.value(),
            timeout=self.timeout.value(), interval=self.interval.value(),
        )

    def start_scan(self):
        if self.thread and self.thread.isRunning():
            return
        try:
            options = self._options()
        except (ValueError, OSError) as exc:
            QMessageBox.warning(self, "Check inputs", str(exc))
            return
        self.assets.clear()
        self.expanded_sites.clear()
        self.run_document.clear()
        self.finished = False
        self.show_other.setChecked(False)
        self.show_other.setEnabled(False)
        self.export_button.setEnabled(False)
        self.history_button.setEnabled(False)
        self.table.setRowCount(0)
        self.journal.clear()
        self.metric_label.setText("Node.js candidates 0/0")
        self.progress.setValue(0)
        self.start_button.setEnabled(False)
        self.pause_button.setEnabled(True)
        self.stop_button.setEnabled(True)
        self.status.setText("Starting discovery…")
        self.thread = ScanThread(options, self)
        self.thread.event.connect(self.on_event)
        self.thread.finished.connect(self.thread_done)
        self.thread.start()

    def pause_scan(self):
        if not self.thread:
            return
        if self.thread.control.paused.is_set():
            self.thread.control.paused.clear()
            self.pause_button.setText("Pause")
            self.status.setText("Resuming…")
        else:
            self.thread.control.paused.set()
            self.pause_button.setText("Resume")
            self.status.setText("Pausing after the current request…")

    def stop_scan(self):
        if self.thread and self.thread.isRunning():
            self.thread.control.stopped.set()
            self.thread.control.paused.clear()
            self.stop_button.setEnabled(False)
            self.status.setText("Stopping after the current request…")

    def thread_done(self):
        self.start_button.setEnabled(True)
        self.pause_button.setEnabled(False)
        self.pause_button.setText("Pause")
        self.stop_button.setEnabled(False)
        self.history_button.setEnabled(True)
        if self._close_when_done:
            QTimer.singleShot(0, self.close)

    def on_event(self, event):
        kind = event["type"]
        if kind == "started":
            self.run_document.update(event)
            self.store.save_run(self.run_document)
        elif kind == "log":
            self.journal.appendPlainText(event["message"])
        elif kind == "stage":
            self.status.setText(event["stage"])
            self.journal.appendPlainText(event["stage"])
            self.progress.setMaximum(max(1, event.get("total", 1)))
            self.progress.setValue(0)
        elif kind == "asset":
            asset = event["asset"]
            self.assets[asset["id"]] = asset
            if self.run_document.get("id"):
                self.store.save_asset(self.run_document["id"], asset)
            self.refresh_timer.start(120)
        elif kind == "progress":
            total = max(1, event["total"])
            self.progress.setMaximum(total)
            self.progress.setValue(event["completed"])
            self.status.setText(f"Checking {event['completed']}/{event['total']}: {event['current']}")
            self.journal.appendPlainText(f"{event['completed']}/{event['total']}  {event['current']}")
        elif kind == "finished":
            self.run_document.update(event)
            if self.run_document.get("id"):
                self.store.save_run(self.run_document)
            self.finished = event["status"] == "COMPLETED"
            self.show_other.setEnabled(self.finished)
            self.export_button.setEnabled(bool(self.assets))
            if event["status"] == "COMPLETED":
                self.progress.setMaximum(100)
                self.progress.setValue(100)
            self.status.setText(f"Scan {event['status'].lower()}. {event.get('completed', 0)} addresses checked.")
            if event.get("error"):
                self.journal.appendPlainText(event["error"])
            self.refresh_results()

    def toggle_journal(self):
        opened = self.journal_panel.isVisible()
        self.journal_panel.setVisible(not opened)
        self.journal_button.setText("Journal  ›" if opened else "Journal  ‹")
        if not opened:
            self.splitter.setSizes([max(640, self.splitter.width() - 430), 430])

    def refresh_results(self):
        rows = grouped_websites(self.assets.values())
        node_rows = [item for item in rows if item.get("node") in self.NODE_ROWS]
        other_rows = [item for item in rows if item.get("node") not in self.NODE_ROWS]
        self.metric_label.setText(f"Node.js candidates {len(node_rows)}/{len(rows)}")
        groups = node_rows + (other_rows if self.show_other.isChecked() and self.finished else [])
        query = self.search.text().strip().lower()
        if query:
            groups = [item for item in groups if any(
                query in url.lower() for url in
                [item.get("site_url") or item["url"], *item.get("checked_urls", ())])]
        display = []
        for group in groups:
            display.append(group)
            site_url = group.get("site_url") or group["url"]
            variants = [url for url in group.get("site_variants", ()) if url != site_url]
            reveal = site_url in self.expanded_sites or (
                query and any(query in url.lower() for url in variants))
            if reveal:
                for variant in variants:
                    if query and site_url not in self.expanded_sites and query not in variant.lower():
                        continue
                    child = dict(group)
                    child["id"] = f"{group['id']} [variant {variant}]"
                    child["site_url"] = variant
                    child["_child"] = True
                    display.append(child)
        self.display_rows = display
        selected = self.table.currentItem().data(Qt.UserRole) if self.table.currentItem() else None
        self.table.blockSignals(True)
        self.table.clearSelection()
        self.table.setRowCount(len(display))
        for index, asset in enumerate(display):
            found = asset.get("node") in self.NODE_ROWS
            site_url = asset.get("site_url") or asset["url"]
            expandable = not asset.get("_child") and len(asset.get("site_variants", ())) > 1
            prefix = ("    ↳ " if asset.get("_child") else
                      "▾ " if expandable and site_url in self.expanded_sites else
                      "▸ " if expandable else "")
            node_version = asset.get("version")
            next_version = (asset.get("technology_versions") or {}).get("Next.js")
            version_label = (f"Node.js {node_version}" if node_version else
                             f"Next.js {next_version}" if next_version else "—")
            values = [prefix + site_url,
                      asset.get("http_status") or "—",
                      asset.get("node", "Unknown").replace("_", " ").title() if found else "",
                      version_label,
                      "Off",
                      asset.get("verdict", "Unconfirmed") if found else ""]
            for col, value in enumerate(values):
                cell = QTableWidgetItem(str(value))
                cell.setData(Qt.UserRole, asset["id"])
                cell.setTextAlignment(self.table.horizontalHeaderItem(col).textAlignment())
                if col == 0 and expandable:
                    cell.setToolTip("Click to expand matching site addresses")
                elif col == 3 and next_version and not node_version:
                    cell.setToolTip("Next.js version; Node.js runtime version is not known")
                if col == 5 and found:
                    background, foreground = self.VERDICT_COLORS.get(value, ("#fff4d8", "#896a1e"))
                    cell.setBackground(QColor(background))
                    cell.setForeground(QColor(foreground))
                self.table.setItem(index, col, cell)
            if selected == asset["id"]:
                self.table.selectRow(index)
        self.table.blockSignals(False)

    def copy_site(self, row, column):
        if not 0 <= row < len(self.display_rows):
            return
        asset = self.display_rows[row]
        site_url = asset.get("site_url") or asset["url"]
        QApplication.clipboard().setText(site_url)
        if column == 0 and not asset.get("_child") and len(asset.get("site_variants", ())) > 1:
            if site_url in self.expanded_sites:
                self.expanded_sites.remove(site_url)
            else:
                self.expanded_sites.add(site_url)
            self.refresh_results()
        self.copy_toast.adjustSize()
        viewport = self.table.viewport()
        self.copy_toast.move((viewport.width() - self.copy_toast.width()) // 2,
                             max(0, viewport.height() - self.copy_toast.height() - 20))
        self.copy_toast.show()
        self.copy_toast.raise_()
        QTimer.singleShot(1800, self.copy_toast.hide)

    def visible_result_rows(self):
        results = []
        for row, asset in enumerate(self.display_rows):
            result = {self.table.horizontalHeaderItem(col).text(): self.table.item(row, col).text()
                      for col in range(self.table.columnCount())}
            result["Address"] = asset.get("site_url") or asset["url"]
            results.append(result)
        return results

    def show_details(self, *_):
        row = self.table.currentRow()
        if row < 0:
            return
        cell = self.table.item(row, 0)
        if cell is None:
            return
        if row >= len(self.display_rows):
            return
        asset = self.display_rows[row]
        checked_urls = asset.get("checked_urls", [asset["url"]])
        evidence = asset.get("evidence") or []
        evidence_lines = "<br>".join(
            f"• {escape(item['value'])} ({escape(item['source'])})"
            for item in evidence[:12]
        ) or "No Node.js runtime indicator was found."
        urls = "<br>".join(escape(url) for url in checked_urls)
        reason = escape(asset.get("verdict_reason", ""))
        dialog = QMessageBox(self)
        dialog.setWindowTitle("Node.js site details")
        dialog.setTextFormat(Qt.RichText)
        dialog.setText(f"<b>{escape(asset.get('site_url') or asset['url'])}</b><br>"
                       f"{reason}<br><br><b>Evidence</b><br>{evidence_lines}"
                       f"<br><br><b>Checked addresses</b><br>{urls}")
        dialog.exec()

    def export(self):
        if not self.run_document or not self.assets:
            return
        path, selected_filter = QFileDialog.getSaveFileName(self, "Export results", "node2shell-results.json",
                                              "JSON results (*.json);;CSV results (*.csv)")
        if not path:
            return
        if not Path(path).suffix:
            path += ".csv" if selected_filter.startswith("CSV") else ".json"
        try:
            export_visible_results(path, self.visible_result_rows())
        except OSError as exc:
            QMessageBox.warning(self, "Export failed", str(exc))
            return
        self.status.setText(f"Exported to {path}")

    def open_history(self):
        runs = self.store.runs()
        if not runs:
            QMessageBox.information(self, "History", "No previous scans are saved yet.")
            return
        labels = [f"{run.get('started_at', '')} — {run.get('status', 'IN PROGRESS')} — {run['id'][:8]}"
                  for run in runs]
        choice, accepted = QInputDialog.getItem(self, "Previous scans", "Choose a scan", labels, 0, False)
        if not accepted:
            return
        run = runs[labels.index(choice)]
        self.run_document = run
        self.assets = {asset["id"]: asset for asset in self.store.assets(run["id"])}
        self.expanded_sites.clear()
        self.finished = True
        self.show_other.setEnabled(True)
        self.show_other.setChecked(False)
        self.export_button.setEnabled(bool(self.assets))
        self.status.setText(f"Loaded scan from {run.get('started_at', 'unknown time')}")
        self.refresh_results()

    def closeEvent(self, event):
        if self.thread and self.thread.isRunning():
            self._close_when_done = True
            self.stop_scan()
            event.ignore()
            return
        self.store.close()
        event.accept()


_APP = None
_WINDOW = None


def main():
    global _APP, _WINDOW
    _APP = QApplication(sys.argv)
    _APP.setApplicationName("Node2Shell Radar")
    _APP.setStyleSheet(STYLE)
    _WINDOW = MainWindow()
    _WINDOW.show()
    return _APP.exec()
