"""Exercise a real Qt window lifecycle and result filtering."""

from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from radar.gui import MainWindow


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as temp:
        app = QApplication([])
        window = MainWindow(Path(temp) / "sessions.sqlite")
        window.targets.setPlainText("example.test")
        assert window._options().targets[0].host == "example.test"
        node = {"id": "https://node.example.test/", "url": "https://node.example.test/",
                "final_url": "https://node.example.test/", "http_status": 200,
                "node": "LIKELY", "verdict": "Unconfirmed", "evidence": [],
                "content_sha256": "node"}
        other = {"id": "https://other.example.test/", "url": "https://other.example.test/",
                 "final_url": "https://other.example.test/", "http_status": 200,
                 "node": "NOT_ESTABLISHED", "verdict": "Unconfirmed", "evidence": [],
                 "content_sha256": "other"}
        window.assets = {node["id"]: node, other["id"]: other}
        window.refresh_results()
        assert window.table.rowCount() == 1
        assert window.metric_label.text() == "Node.js sites 1/2"
        window.finished = True
        window.show_other.setEnabled(True)
        window.show_other.setChecked(True)
        assert window.table.rowCount() == 2
        window.show()
        QTimer.singleShot(150, window.close)
        QTimer.singleShot(300, app.quit)
        result = app.exec()
    raise SystemExit(result)
