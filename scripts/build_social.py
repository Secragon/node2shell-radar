"""Render the 1280x640 social preview from the product icon."""

import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import (QColor, QFont, QGuiApplication, QImage, QLinearGradient,
                           QFontDatabase, QPainter, QPen, QRadialGradient)
from PySide6.QtSvg import QSvgRenderer


def main():
    root = Path(__file__).resolve().parents[1]
    output = root / "assets" / "social-preview.png"
    output.parent.mkdir(exist_ok=True)
    app = QGuiApplication.instance() or QGuiApplication([])
    for name in ("segoeui.ttf", "segoeuib.ttf"):
        font_path = Path("C:/Windows/Fonts") / name
        if font_path.is_file():
            QFontDatabase.addApplicationFont(str(font_path))
    icon = QSvgRenderer(str(root / "radar" / "data" / "app-icon.svg"))
    if not icon.isValid():
        raise RuntimeError("Invalid product icon SVG")

    canvas = QImage(1280, 640, QImage.Format.Format_ARGB32_Premultiplied)
    painter = QPainter(canvas)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)

    background = QLinearGradient(0, 0, 1280, 640)
    background.setColorAt(0, QColor("#f8fdfa"))
    background.setColorAt(0.57, QColor("#eef9f4"))
    background.setColorAt(1, QColor("#e8f3fa"))
    painter.fillRect(canvas.rect(), background)

    for x, y, radius, color in (
        (75, 610, 330, QColor(100, 210, 189, 37)),
        (1160, 55, 390, QColor(120, 188, 214, 32)),
    ):
        glow = QRadialGradient(x, y, radius)
        glow.setColorAt(0, color)
        glow.setColorAt(1, QColor(color.red(), color.green(), color.blue(), 0))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(glow)
        painter.drawEllipse(QRectF(x - radius, y - radius, radius * 2, radius * 2))

    painter.setBrush(Qt.BrushStyle.NoBrush)
    for radius, alpha in ((180, 35), (260, 30), (340, 24), (420, 18)):
        painter.setPen(QPen(QColor(45, 128, 122, alpha), 3))
        painter.drawEllipse(QRectF(1150 - radius, 320 - radius, radius * 2, radius * 2))

    for offset, alpha in ((14, 10), (9, 16), (5, 22)):
        painter.setBrush(QColor(22, 55, 64, alpha))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRoundedRect(QRectF(104 + offset, 169 + offset, 300, 300), 70, 70)
    icon.render(painter, QRectF(104, 169, 300, 300))

    painter.setPen(QColor("#173947"))
    title = QFont("Segoe UI")
    title.setWeight(QFont.Weight.Bold)
    title.setPixelSize(76)
    painter.setFont(title)
    painter.drawText(QRectF(455, 188, 750, 105),
                     Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                     "Node2Shell")
    title.setPixelSize(100)
    painter.setFont(title)
    painter.drawText(QRectF(451, 278, 700, 125),
                     Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                     "Radar")

    painter.setPen(QColor("#54717b"))
    subtitle = QFont("Segoe UI")
    subtitle.setPixelSize(30)
    painter.setFont(subtitle)
    painter.drawText(QRectF(460, 411, 720, 66),
                     Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                     "Find Node.js sites. Prioritize exposure.")
    painter.setBrush(QColor("#6bcdbb"))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawRoundedRect(QRectF(460, 507, 124, 8), 4, 4)
    painter.setBrush(QColor("#f18d79"))
    painter.drawEllipse(QRectF(598, 503, 16, 16))
    painter.end()

    if not canvas.save(str(output), "PNG"):
        raise RuntimeError("Could not save social preview")
    app.quit()
    print(output)


if __name__ == "__main__":
    main()
