"""Small controls that paint consistently at Windows display scales."""

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QCheckBox, QLabel, QStyle, QStyleOptionButton, QStylePainter


class StyledCheckBox(QCheckBox):
    def __init__(self, text="", parent=None, accent="#267f84"):
        super().__init__(text, parent)
        self.accent = QColor(accent)

    def paintEvent(self, event):
        option = QStyleOptionButton()
        self.initStyleOption(option)
        indicator = self.style().subElementRect(QStyle.SE_CheckBoxIndicator, option, self)
        label_rect = self.style().subElementRect(QStyle.SE_CheckBoxContents, option, self)
        painter = QStylePainter(self)
        option.rect = label_rect
        painter.drawControl(QStyle.CE_CheckBoxLabel, option)

        box = indicator.adjusted(1, 1, -1, -1)
        enabled, checked = self.isEnabled(), self.isChecked()
        painter.setRenderHint(QPainter.Antialiasing)
        border = self.accent if checked and enabled else QColor("#b7c6ca" if enabled else "#cbd5d8")
        fill = self.accent if checked and enabled else QColor(
            "#dce7e9" if checked else "#ffffff" if enabled else "#f1f5f5")
        painter.setPen(QPen(border, 1.3))
        painter.setBrush(fill)
        painter.drawRoundedRect(box, 3, 3)
        if checked:
            mark = QPainterPath()
            mark.moveTo(box.left() + 3, box.top() + 7)
            mark.lineTo(box.left() + 6, box.top() + 10)
            mark.lineTo(box.right() - 3, box.top() + 4)
            painter.setPen(QPen(QColor("#ffffff" if enabled else "#789397"),
                                2, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
            painter.setBrush(Qt.NoBrush)
            painter.drawPath(mark)


class CopyToast(QLabel):
    """A compact confirmation shown over the result table after a copy."""

    def __init__(self, parent=None):
        super().__init__("Copied", parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.setAttribute(Qt.WA_TranslucentBackground)
        font = self.font()
        font.setPixelSize(13)
        font.setWeight(QFont.DemiBold)
        self.setFont(font)

    def sizeHint(self):
        return QSize(self.fontMetrics().horizontalAdvance(self.text()) + 56, 34)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = self.rect().adjusted(1, 1, -1, -1)
        painter.setPen(QPen(QColor(83, 102, 112, 90), 1))
        painter.setBrush(QColor(38, 59, 67, 150))
        painter.drawRoundedRect(rect, 9, 9)
        painter.setPen(QPen(QColor("#ffffff"), 2, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
        mark = QPainterPath()
        mark.moveTo(16, 17)
        mark.lineTo(20, 21)
        mark.lineTo(27, 13)
        painter.drawPath(mark)
        painter.setPen(QColor("#ffffff"))
        painter.drawText(self.rect().adjusted(36, 0, -12, 0), Qt.AlignVCenter, self.text())
