"""Interactive Evidence Relations Graph Page with strict separation of proven vs unverified links."""

from typing import Any, Dict, List, Optional
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QCheckBox, QSplitter, QTextEdit, QGraphicsView, QGraphicsScene,
    QGraphicsEllipseItem, QGraphicsLineItem, QGraphicsTextItem
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QPen, QBrush, QColor, QFont, QPainter

from src.correlation_engine.correlation_service import CorrelationService
from src.ui.styles.tokens import get_theme
from src.ui.components.breadcrumb import Breadcrumb
from src.ui.components.status_indicator import StatusBadge


class InteractiveNodeItem(QGraphicsEllipseItem):
    """Clickable forensic graph node."""

    def __init__(self, node_meta: Dict[str, Any], cx: float, cy: float, on_click):
        r = 26
        super().__init__(cx - r, cy - r, r * 2, r * 2)
        self.node_meta = node_meta
        self.on_click = on_click
        self.setFlag(QGraphicsEllipseItem.ItemIsSelectable, True)
        self.setCursor(Qt.PointingHandCursor)

        kind = node_meta.get("kind", "")
        if "Şüpheli" in kind:
            fill, border = "#FEE4E2", "#C34C4C"
        elif kind == "Vaka":
            fill, border = "#E9F1F8", "#315C85"
        elif kind == "Delil":
            fill, border = "#EDF7F2", "#26845B"
        elif kind == "Kullanıcı":
            fill, border = "#FEF7E6", "#B9822D"
        else:
            fill, border = "#F2F4F7", "#475467"

        self.setBrush(QBrush(QColor(fill)))
        self.setPen(QPen(QColor(border), 2.2))

    def mousePressEvent(self, event):
        super().mousePressEvent(event)
        if self.on_click:
            self.on_click(self.node_meta)


class RelationsPage(QWidget):
    """Interactive entity-relation workbench distinguishing verified evidence from hypotheses."""

    def __init__(self, db_path: str = "data/forensics.db", parent=None):
        super().__init__(parent)
        self.svc = CorrelationService(db_path=db_path)
        self._graph_data: Dict[str, Any] = {"nodes": [], "edges": []}
        self._theme_name = "light"

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 18, 24, 18)
        main_layout.setSpacing(12)

        # Header
        header_bar = QHBoxLayout()
        self.breadcrumb = Breadcrumb(["Adli Bilişim", "Bulgu İlişkilendirme (Evidence Relations)"])
        header_bar.addWidget(self.breadcrumb)
        header_bar.addStretch()
        self.stats_badge = StatusBadge("0 Düğüm / 0 İlişki", "info")
        header_bar.addWidget(self.stats_badge)
        main_layout.addLayout(header_bar)

        # Toolbar
        toolbar = QHBoxLayout()
        self.hyp_checkbox = QCheckBox("Kanıtlanmamış Zamansal İlişkileri Göster (Kesik Çizgi)")
        self.hyp_checkbox.setChecked(True)
        self.hyp_checkbox.toggled.connect(self.refresh_records)
        toolbar.addWidget(self.hyp_checkbox)

        toolbar.addStretch()
        zoom_in = QPushButton("➕ Yakınlaştır")
        zoom_in.clicked.connect(lambda: self.view.scale(1.15, 1.15))
        toolbar.addWidget(zoom_in)

        zoom_out = QPushButton("➖ Uzaklaştır")
        zoom_out.clicked.connect(lambda: self.view.scale(0.87, 0.87))
        toolbar.addWidget(zoom_out)

        refresh_btn = QPushButton("🔄 Grafiği Yenile")
        refresh_btn.setObjectName("primaryBtn")
        refresh_btn.clicked.connect(self.refresh_records)
        toolbar.addWidget(refresh_btn)
        main_layout.addLayout(toolbar)

        # Splitter: Interactive Canvas + Right Evidence Basis Inspector
        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)

        graph_card = QFrame()
        graph_card.setObjectName("surfaceCard")
        g_lay = QVBoxLayout(graph_card)
        g_lay.setContentsMargins(8, 8, 8, 8)

        legend = QLabel(
            "Gösterim:  ━━ Doğrulanabilir Kanıtlı Bağlantı (Registry/Seri/SID)   |   "
            "- - - Kanıtlanmamış Zamansal Yakınlık (Hipotez)"
        )
        legend.setObjectName("mutedLabel")
        g_lay.addWidget(legend)

        self.scene = QGraphicsScene(self)
        self.view = QGraphicsView(self.scene)
        self.view.setRenderHint(QPainter.Antialiasing)
        self.view.setDragMode(QGraphicsView.ScrollHandDrag)
        g_lay.addWidget(self.view)
        splitter.addWidget(graph_card)

        right = QFrame()
        right.setObjectName("surfaceCard")
        right.setFixedWidth(360)
        r_lay = QVBoxLayout(right)
        r_lay.setContentsMargins(12, 12, 12, 12)
        r_lay.addWidget(QLabel("Seçili Düğüm & İlişki Dayanağı"))
        self.detail_view = QTextEdit()
        self.detail_view.setReadOnly(True)
        self.detail_view.setStyleSheet("font-family: Consolas; font-size: 11px;")
        r_lay.addWidget(self.detail_view)
        splitter.addWidget(right)

        splitter.setStretchFactor(0, 7)
        splitter.setStretchFactor(1, 3)
        main_layout.addWidget(splitter, 1)

        self.refresh_records()

    def set_theme(self, theme_name: str):
        self._theme_name = theme_name
        self.refresh_records()

    def refresh_records(self):
        t = get_theme(self._theme_name)
        self._graph_data = self.svc.build_case_graph(include_hypotheses=self.hyp_checkbox.isChecked())
        self.scene.clear()
        self.scene.setBackgroundBrush(QBrush(QColor(t["surface"])))

        nodes = self._graph_data["nodes"]
        edges = self._graph_data["edges"]
        self.stats_badge.set_status(f"{len(nodes)} Düğüm / {len(edges)} İlişki", "info")

        coord_map: Dict[str, tuple] = {}
        scale = 260.0
        for n in nodes:
            coord_map[n["id"]] = (n["x"] * scale, n["y"] * scale)

        # Draw edges first
        for e in edges:
            if e["source"] not in coord_map or e["target"] not in coord_map:
                continue
            x1, y1 = coord_map[e["source"]]
            x2, y2 = coord_map[e["target"]]
            line = QGraphicsLineItem(x1, y1, x2, y2)
            if e["verified"]:
                pen = QPen(QColor(t["verified"]), 2.0, Qt.SolidLine)
            else:
                pen = QPen(QColor(t["warning"]), 1.8, Qt.DashLine)
            line.setPen(pen)
            line.setToolTip(f"{e['relation']}\nDayanak: {e['basis']}")
            self.scene.addItem(line)

        # Draw nodes on top
        label_font = QFont("Segoe UI", 8, QFont.Bold)
        label_color = QColor(t["text"])
        for n in nodes:
            cx, cy = coord_map[n["id"]]
            node_item = InteractiveNodeItem(n, cx, cy, self._on_node_clicked)
            self.scene.addItem(node_item)

            txt = QGraphicsTextItem(f"{n['label']}")
            txt.setFont(label_font)
            txt.setDefaultTextColor(label_color)
            txt.setPos(cx - txt.boundingRect().width() / 2, cy + 28)
            self.scene.addItem(txt)

        if nodes:
            self._on_node_clicked(nodes[0])

    def _on_node_clicked(self, node_meta: Dict[str, Any]):
        nid = node_meta["id"]
        connected = [
            e for e in self._graph_data["edges"]
            if e["source"] == nid or e["target"] == nid
        ]
        rel_lines = []
        for e in connected:
            tag = "[DOĞRULANMIŞ KANIT]" if e["verified"] else "[KANITLANMAMIŞ HİPOTEZ]"
            other = e["target"] if e["source"] == nid else e["source"]
            rel_lines.append(f"• {tag} {e['relation']} -> {other}\n  Dayanak: {e['basis']}")

        self.detail_view.setPlainText(
            f"DÜĞÜM TÜRÜ:    {node_meta['kind']}\n"
            f"ETİKET:        {node_meta['label']}\n"
            f"DELİL KAYNAĞI: {node_meta['evidence_source']}\n\n"
            f"AYRINTILAR:\n{node_meta['details']}\n\n"
            f"BAĞLANTILI İLİŞKİLER ({len(connected)}):\n" +
            ("\n".join(rel_lines) if rel_lines else "(Bağlantı yok)")
        )
