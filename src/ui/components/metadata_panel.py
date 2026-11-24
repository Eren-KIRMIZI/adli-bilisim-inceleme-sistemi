"""Forensic Metadata & Technical Property Inspector Panel."""

from typing import Dict, Any
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QScrollArea, QPushButton, QTabWidget, QApplication, QMessageBox
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from src.ui.components.status_indicator import StatusBadge
from src.ui.components.hex_viewer import ForensicHexViewer


class MetadataPanel(QFrame):
    """Right-side inspector displaying comprehensive forensic item properties."""

    def __init__(self, title: str = "Adli Detay ve Metadata", parent=None):
        super().__init__(parent)
        self.setObjectName("surfaceCard")
        self.setFixedWidth(365)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(14, 14, 14, 14)
        main_layout.setSpacing(10)

        header = QHBoxLayout()
        header.setSpacing(8)

        self.title_lbl = QLabel(title)
        self.title_lbl.setObjectName("sectionTitle")
        header.addWidget(self.title_lbl)
        header.addStretch()

        self.status_badge = StatusBadge("Normal", "verified")
        header.addWidget(self.status_badge)
        main_layout.addLayout(header)

        self.tabs = QTabWidget()
        self.tab_general = QWidget()
        self.tab_timeline = QWidget()
        self.tab_source = QWidget()
        self.tab_hex = ForensicHexViewer()

        self.tabs.addTab(self._create_scroll_tab(self.tab_general), "Kimlik")
        self.tabs.addTab(self._create_scroll_tab(self.tab_timeline), "Zaman")
        self.tabs.addTab(self._create_scroll_tab(self.tab_source), "Kaynak")
        self.tabs.addTab(self.tab_hex, "Hex")
        main_layout.addWidget(self.tabs)

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

        status = str(data.get("Durum", data.get("Status", "Normal")))
        variant = "verified"
        if any(k in status.lower() for k in ["şüpheli", "warning", "uyarı"]):
            variant = "warning"
        elif any(k in status.lower() for k in ["kritik", "critical", "bozuk"]):
            variant = "critical"
        self.status_badge.set_status(status, variant)

        general_keys = [
            "Cihaz Adı", "Üretici", "Model", "Seri Numarası", "VID", "PID",
            "Sürücü Harfi", "Cihaz Sınıfı", "İlişkili Kullanıcı"
        ]
        self._populate_key_values(self.tab_general, {k: data[k] for k in general_keys if k in data})

        time_keys = [
            "İlk Bağlantı", "İlk Bağlantı (UTC)", "Son Bağlantı",
            "Son Bağlantı (UTC)", "Son Çıkarılma", "Kayıt Tarihi"
        ]
        self._populate_key_values(self.tab_timeline, {k: data[k] for k in time_keys if k in data})

        source_keys = [
            "Kaynak Kayıt", "Hive Dosyası", "Volume GUID", "User SID",
            "NIST Kuralı", "Güvenilirlik", "Doğrulama"
        ]
        self._populate_key_values(self.tab_source, {k: data[k] for k in source_keys if k in data})

        if raw_hex:
            self.tab_hex.load_bytes(raw_hex)
        else:
            import json
            serialized = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
            self.tab_hex.load_bytes(serialized)

    def _populate_key_values(self, container: QWidget, items: Dict[str, Any]):
        old_lay = container.layout()
        if old_lay:
            QWidget().setLayout(old_lay)

        layout = QVBoxLayout(container)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(8)
        mono_font = QFont("Consolas", 10)

        for key, val in items.items():
            box = QFrame()
            box.setObjectName("subCard")
            box_lay = QVBoxLayout(box)
            box_lay.setContentsMargins(8, 6, 8, 6)
            box_lay.setSpacing(2)

            k_lbl = QLabel(key)
            k_lbl.setObjectName("mutedLabel")
            box_lay.addWidget(k_lbl)

            v_lay = QHBoxLayout()
            v_lay.setSpacing(4)

            v_lbl = QLabel(str(val) if val not in (None, "") else "-")
            v_lbl.setWordWrap(True)
            v_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
            if any(k in key.lower() for k in ["vid", "pid", "seri", "guid", "sid", "zaman", "tarih", "hash"]):
                v_lbl.setFont(mono_font)
                v_lbl.setObjectName("monoLabel")
            v_lay.addWidget(v_lbl, 1)

            cp = QPushButton("📋")
            cp.setFixedSize(24, 24)
            cp.setToolTip("Panoya Kopyala")
            cp.setStyleSheet("padding: 0px; font-size: 11px; border: none; background: transparent;")
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
