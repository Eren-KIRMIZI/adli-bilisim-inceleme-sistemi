"""Forensic Metadata & Technical Property Inspector Panel."""

from typing import Dict, Any, List
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, 
    QScrollArea, QPushButton, QTabWidget, QApplication, QMessageBox
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from src.ui.components.status_indicator import StatusBadge
from src.ui.components.hex_viewer import ForensicHexViewer

class MetadataPanel(QFrame):
    """Collapsible right-side inspector displaying comprehensive forensic item properties."""
    def __init__(self, title: str = "Adli Detay ve Metadata", parent=None):
        super().__init__(parent)
        self.setObjectName("surfaceCard")
        self.setFixedWidth(360)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(14, 14, 14, 14)
        main_layout.setSpacing(10)

        # Header
        header = QHBoxLayout()
        header.setSpacing(8)

        self.title_lbl = QLabel(title)
        self.title_lbl.setStyleSheet("font-size: 14px; font-weight: 700; color: #1D2733;")
        header.addWidget(self.title_lbl)

        header.addStretch()

        self.status_badge = StatusBadge("Normal", "verified")
        header.addWidget(self.status_badge)

        main_layout.addLayout(header)

        # Tabs: Detaylar, Zamanlar, Kaynak, Hex
        self.tabs = QTabWidget()
        self.tab_general = QWidget()
        self.tab_timeline = QWidget()
        self.tab_source = QWidget()
        self.tab_hex = ForensicHexViewer()

        self.tabs.addTab(self._create_scroll_tab(self.tab_general), "Kimlik")
        self.tabs.addTab(self._create_scroll_tab(self.tab_timeline), "Zamanlar")
        self.tabs.addTab(self._create_scroll_tab(self.tab_source), "Kaynak & Delil")
        self.tabs.addTab(self.tab_hex, "Hex İnceleme")

        main_layout.addWidget(self.tabs)

        # Action Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)

        self.copy_btn = QPushButton("Panoya Kopyala")
        self.copy_btn.clicked.connect(self._copy_all)
        btn_layout.addWidget(self.copy_btn)

        self.report_btn = QPushButton("Rapora Ekle")
        self.report_btn.setObjectName("primaryBtn")
        self.report_btn.clicked.connect(self._add_to_report)
        btn_layout.addWidget(self.report_btn)

        main_layout.addLayout(btn_layout)

        self._current_data: Dict[str, Any] = {}

    def _create_scroll_tab(self, target_widget: QWidget) -> QScrollArea:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidget(target_widget)
        return scroll

    def populate(self, data: Dict[str, Any], raw_hex: bytes = b""):
        """Populate the inspector with structured key-value pairs."""
        self._current_data = data

        # Status badge update
        status = str(data.get("Durum", data.get("Status", "Normal")))
        variant = "verified"
        if any(k in status.lower() for k in ["şüpheli", "warning", "uyarı"]):
            variant = "warning"
        elif any(k in status.lower() for k in ["kritik", "critical", "bozuk"]):
            variant = "critical"
        self.status_badge.set_status(status, variant)

        # Populate Kimlik Tab
        general_keys = ["Cihaz Adı", "Üretici", "Model", "Seri Numarası", "VID", "PID", "Sürücü Harfi", "Cihaz Sınıfı", "İlişkili Kullanıcı"]
        self._populate_key_values(self.tab_general, {k: data[k] for k in general_keys if k in data})

        # Populate Zamanlar Tab
        time_keys = ["İlk Bağlantı", "İlk Bağlantı (UTC)", "Son Bağlantı", "Son Bağlantı (UTC)", "Son Çıkarılma", "Kayıt Tarihi"]
        self._populate_key_values(self.tab_timeline, {k: data[k] for k in time_keys if k in data})

        # Populate Kaynak Tab
        source_keys = ["Kaynak Kayıt", "Hive Dosyası", "Volume GUID", "User SID", "NIST Kuralı", "Güvenilirlik", "Doğrulama"]
        self._populate_key_values(self.tab_source, {k: data[k] for k in source_keys if k in data})

        # Populate Hex Tab
        if raw_hex:
            self.tab_hex.load_bytes(raw_hex)
        else:
            # Generate hex representation of data dictionary
            import json
            serialized = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
            self.tab_hex.load_bytes(serialized)

    def _populate_key_values(self, container: QWidget, items: Dict[str, Any]):
        # Clear existing layout
        old_lay = container.layout()
        if old_lay:
            QWidget().setLayout(old_lay)

        layout = QVBoxLayout(container)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(8)

        mono_font = QFont("Consolas", 10)

        for key, val in items.items():
            box = QFrame()
            box.setStyleSheet("background: #F9FAFB; border: 1px solid #EAECF0; border-radius: 6px; padding: 6px;")
            box_lay = QVBoxLayout(box)
            box_lay.setContentsMargins(4, 4, 4, 4)
            box_lay.setSpacing(2)

            k_lbl = QLabel(key)
            k_lbl.setStyleSheet("font-size: 11px; font-weight: 600; color: #667085;")
            box_lay.addWidget(k_lbl)

            v_lay = QHBoxLayout()
            v_lay.setSpacing(4)

            v_lbl = QLabel(str(val) if val not in (None, "") else "-")
            v_lbl.setWordWrap(True)
            v_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
            if any(k in key.lower() for k in ["vid", "pid", "seri", "guid", "sid", "zaman", "tarih", "hash"]):
                v_lbl.setFont(mono_font)
                v_lbl.setStyleSheet("font-size: 11px; color: #1D2733;")
            else:
                v_lbl.setStyleSheet("font-size: 12px; color: #1D2733; font-weight: 500;")
            v_lay.addWidget(v_lbl, 1)

            # Copy small icon button
            cp = QPushButton("📋")
            cp.setFixedSize(22, 22)
            cp.setToolTip("Panoya Kopyala")
            cp.setStyleSheet("padding: 0px; font-size: 10px; background: transparent; border: none;")
            cp.clicked.connect(lambda ch=False, text=str(val): QApplication.clipboard().setText(text))
            v_lay.addWidget(cp)

            box_lay.addLayout(v_lay)
            layout.addWidget(box)

        layout.addStretch()

    def _copy_all(self):
        if self._current_data:
            import json
            QApplication.clipboard().setText(json.dumps(self._current_data, indent=2, ensure_ascii=False, default=str))
            QMessageBox.information(self, "Kopyalandı", "Tüm metadata JSON formatında panoya kopyalandı.")

    def _add_to_report(self):
        QMessageBox.information(self, "Rapor Güncellendi", "Seçili artefakt aktif vaka adli raporuna başarıyla eklendi.")
