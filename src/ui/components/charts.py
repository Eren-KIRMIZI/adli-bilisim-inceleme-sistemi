"""Custom QPainter forensic telemetry widgets: circular progress ring gauges and smooth spline area charts."""

from typing import List, Optional, Tuple
from PySide6.QtWidgets import QWidget
from PySide6.QtCore import Qt, QRectF, QPointF
from PySide6.QtGui import (
    QPainter, QColor, QPen, QFont, QPainterPath, QLinearGradient
)

from src.ui.styles.tokens import get_theme


class CircularGaugeWidget(QWidget):
    """Anti-aliased radial progress ring gauge inspired by modern SOC/DFIR consoles."""

    def __init__(
        self,
        value: int = 0,
        accent_color: str = "#4ADE80",
        size: int = 58,
        theme_name: str = "dark",
        parent=None,
    ):
        super().__init__(parent)
        self._value = max(0, min(100, int(value)))
        self._accent = accent_color
        self._theme_name = theme_name
        self._center_text: Optional[str] = None
        self.setFixedSize(size, size)

    def set_value(self, value: int, accent_color: Optional[str] = None, center_text: Optional[str] = None) -> None:
        self._value = max(0, min(100, int(value)))
        if accent_color:
            self._accent = accent_color
        self._center_text = center_text
        self.update()

    def set_theme(self, theme_name: str) -> None:
        self._theme_name = theme_name
        self.update()

    def paintEvent(self, event) -> None:
        t = get_theme(self._theme_name)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        stroke = 5.5
        pad = stroke + 2.0
        rect = QRectF(pad, pad, self.width() - 2 * pad, self.height() - 2 * pad)

        # Background track ring
        track_color = QColor("#253041") if self._theme_name == "dark" else QColor(t["border_light"])
        track_pen = QPen(track_color, stroke, Qt.SolidLine, Qt.RoundCap)
        painter.setPen(track_pen)
        painter.drawArc(rect, 0, 360 * 16)

        # Progress arc (12 o'clock = 90 deg, clockwise = negative span)
        if self._value > 0:
            accent_q = QColor(self._accent)
            # Subtle outer halo in dark mode
            if self._theme_name == "dark":
                glow_col = QColor(accent_q)
                glow_col.setAlpha(45)
                painter.setPen(QPen(glow_col, stroke + 3.5, Qt.SolidLine, Qt.RoundCap))
                span = int(-360 * 16 * (self._value / 100.0))
                painter.drawArc(rect, 90 * 16, span)

            arc_pen = QPen(accent_q, stroke, Qt.SolidLine, Qt.RoundCap)
            painter.setPen(arc_pen)
            span = int(-360 * 16 * (self._value / 100.0))
            painter.drawArc(rect, 90 * 16, span)

        # Centered percentage or custom metric text
        label = self._center_text if self._center_text is not None else f"{self._value}%"
        painter.setPen(QColor(t["text"]))
        f = QFont("Segoe UI", 9, QFont.Bold)
        painter.setFont(f)
        painter.drawText(self.rect(), Qt.AlignCenter, label)


class SplineAreaChart(QWidget):
    """Smooth cubic Bezier spline + gradient area telemetry chart with subtle gridlines."""

    def __init__(self, height: int = 128, theme_name: str = "dark", parent=None):
        super().__init__(parent)
        self.setFixedHeight(height)
        self._buckets: List[Tuple[str, int]] = []
        self._theme_name = theme_name
        self._accent = "#38BDF8"
        self._empty_text = "Zaman yoğunluğu verisi yok"

    def set_theme(self, theme_name: str) -> None:
        self._theme_name = theme_name
        self.update()

    def set_series(
        self,
        buckets: List[Tuple[str, int]],
        accent_color: Optional[str] = None,
        empty_text: Optional[str] = None,
    ) -> None:
        self._buckets = list(buckets)
        if accent_color:
            self._accent = accent_color
        if empty_text:
            self._empty_text = empty_text
        self.update()

    def paintEvent(self, event) -> None:
        t = get_theme(self._theme_name)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        rect = self.rect()
        bg_col = QColor(t["surface"])
        painter.fillRect(rect, bg_col)

        if not self._buckets:
            painter.setPen(QColor(t["text_muted"]))
            painter.setFont(QFont("Segoe UI", 10))
            painter.drawText(rect, Qt.AlignCenter, self._empty_text)
            return

        pad_l, pad_r, pad_top, pad_bot = 36, 18, 18, 26
        plot_w = max(1.0, float(rect.width() - pad_l - pad_r))
        plot_h = max(1.0, float(rect.height() - pad_top - pad_bot))
        base_y = pad_top + plot_h

        max_c = max(c for _, c in self._buckets) or 1

        # Horizontal dashed gridlines & Y-axis labels
        grid_col = QColor("#242E3F") if self._theme_name == "dark" else QColor(t["border_light"])
        grid_pen = QPen(grid_col, 1, Qt.DashLine)
        label_font = QFont("Consolas", 8)
        painter.setFont(label_font)

        for frac in (0.0, 0.5, 1.0):
            gy = base_y - frac * plot_h
            painter.setPen(grid_pen)
            painter.drawLine(QPointF(pad_l, gy), QPointF(pad_l + plot_w, gy))
            y_val = int(round(frac * max_c))
            painter.setPen(QColor(t["text_muted"]))
            painter.drawText(QRectF(2, gy - 8, pad_l - 8, 16), Qt.AlignRight | Qt.AlignVCenter, str(y_val))

        # Compute plot points
        n = len(self._buckets)
        points: List[QPointF] = []
        for idx, (_, cnt) in enumerate(self._buckets):
            if n == 1:
                px = pad_l + plot_w / 2.0
            else:
                px = pad_l + (idx / (n - 1)) * plot_w
            py = base_y - (cnt / max_c) * (plot_h - 4)
            points.append(QPointF(px, py))

        # Build smooth cubic spline path
        line_path = QPainterPath()
        line_path.moveTo(points[0])
        if n == 2:
            line_path.lineTo(points[1])
        elif n > 2:
            for i in range(n - 1):
                p0 = points[i]
                p1 = points[i + 1]
                cx = (p0.x() + p1.x()) / 2.0
                line_path.cubicTo(QPointF(cx, p0.y()), QPointF(cx, p1.y()), p1)

        # Gradient fill under curve
        area_path = QPainterPath(line_path)
        area_path.lineTo(QPointF(points[-1].x(), base_y))
        area_path.lineTo(QPointF(points[0].x(), base_y))
        area_path.closeSubpath()

        accent_q = QColor(self._accent)
        grad = QLinearGradient(0, pad_top, 0, base_y)
        top_fill = QColor(accent_q)
        top_fill.setAlpha(95)
        bot_fill = QColor(accent_q)
        bot_fill.setAlpha(6)
        grad.setColorAt(0.0, top_fill)
        grad.setColorAt(1.0, bot_fill)
        painter.fillPath(area_path, grad)

        # Outer glow + crisp curve stroke
        glow_col = QColor(accent_q)
        glow_col.setAlpha(55)
        painter.setPen(QPen(glow_col, 5.5, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
        painter.drawPath(line_path)

        painter.setPen(QPen(accent_q, 2.2, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
        painter.drawPath(line_path)

        # Data nodes & sparse X-axis labels
        step = max(1, n // 8)
        for idx, (pt, (lbl, cnt)) in enumerate(zip(points, self._buckets)):
            painter.setPen(QPen(accent_q, 2.0))
            painter.setBrush(bg_col)
            painter.drawEllipse(pt, 3.3, 3.3)

            if idx == 0 or idx == n - 1 or idx % step == 0:
                painter.setPen(QColor(t["text_muted"]))
                short_lbl = lbl[-5:] if len(lbl) > 5 else lbl
                painter.drawText(
                    QRectF(pt.x() - 26, base_y + 4, 52, 16),
                    Qt.AlignCenter,
                    short_lbl,
                )
