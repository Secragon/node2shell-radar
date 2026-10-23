"""Render the app's vector mark to a PNG and multi-size Windows ICO."""

import os
from pathlib import Path
import struct

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, Qt
from PySide6.QtGui import QGuiApplication, QImage, QPainter
from PySide6.QtSvg import QSvgRenderer


def render_png(renderer, size):
    image = QImage(size, size, QImage.Format.Format_ARGB32)
    image.fill(Qt.GlobalColor.transparent)
    painter = QPainter(image)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    renderer.render(painter)
    painter.end()
    output = QByteArray()
    buffer = QBuffer(output)
    buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    if not image.save(buffer, "PNG"):
        raise RuntimeError(f"Could not render {size}px icon")
    return bytes(output)


def main():
    root = Path(__file__).resolve().parents[1]
    assets = root / "radar" / "data"
    app = QGuiApplication.instance() or QGuiApplication([])
    renderer = QSvgRenderer(str(assets / "app-icon.svg"))
    if not renderer.isValid():
        raise RuntimeError("Invalid app icon SVG")

    sizes = (16, 24, 32, 48, 64, 128, 256)
    images = [(size, render_png(renderer, size)) for size in sizes]
    (assets / "app-icon.png").write_bytes(render_png(renderer, 512))

    offset = 6 + 16 * len(images)
    directory = bytearray(struct.pack("<HHH", 0, 1, len(images)))
    payload = bytearray()
    for size, png in images:
        directory.extend(struct.pack("<BBBBHHII", size if size < 256 else 0,
                                     size if size < 256 else 0, 0, 0, 1, 32,
                                     len(png), offset))
        payload.extend(png)
        offset += len(png)
    (assets / "app-icon.ico").write_bytes(directory + payload)
    app.quit()
    print(assets / "app-icon.ico")


if __name__ == "__main__":
    main()
