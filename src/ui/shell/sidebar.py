"""Forensic suite navigation sidebar with crisp SVG vector icons, collapse toggle, and status indicator."""

from typing import List, Tuple
from PySide6.QtWidgets import QFrame, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QScrollArea, QWidget
from PySide6.QtCore import Signal, QSize
from src.ui.styles.icons import render_svg_icon

# Escape '&' as '&&' in Qt QPushButton labels so mnemonics do not strip '&'
NAV_ITEMS: List[Tuple[str, str]] = [
    ("dashboard", "Genel Bakış (Dashboard)"),
    ("cases", "Vaka Yönetimi (Cases)"),
    ("evidence", "Delil Yönetimi (Evidence)"),
    ("integrity", "Bütünlük && Hash"),
    ("disk", "Disk Forensics"),
    ("windows", "Windows Forensics"),
    ("usb", "USB Cihaz Analizi"),
    ("browser", "Tarayıcı Analizi"),
    ("memory", "RAM Bellek Analizi"),
    ("file", "Dosya && Hex İnceleme"),
    ("timeline", "Olay Zaman Çizelgesi"),
    ("relations", "Bulgu İlişkilendirme"),
    ("report", "Adli Rapor Oluşturucu"),
    ("acquisition", "Saha İmaj Edinim"),
    ("settings", "Ayarlar && Lisanslar"),
]


class Sidebar(QFrame):
    pageChanged = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("sidebarFrame")
        self.setFixedWidth(235)
        self._collapsed = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 14, 10, 12)
        layout.setSpacing(4)

        head_row = QHBoxLayout()
        self.lbl_head = QLabel("ADLİ İNCELEME")
        self.lbl_head.setObjectName("sidebarHeader")
        head_row.addWidget(self.lbl_head)
        head_row.addStretch()

        self.collapse_btn = QPushButton("☰")
        self.collapse_btn.setToolTip("Kenar Çubuğunu Daralt / Genişlet")
        self.collapse_btn.setFixedSize(28, 24)
        self.collapse_btn.setStyleSheet("background: transparent; color: #9CA3AF; border: none; font-size: 14px;")
        self.collapse_btn.clicked.connect(self.toggle_collapse)
        head_row.addWidget(self.collapse_btn)
        layout.addLayout(head_row)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        container = QWidget()
        container.setObjectName("sidebarContainer")
        c_layout = QVBoxLayout(container)
        c_layout.setContentsMargins(0, 4, 0, 4)
        c_layout.setSpacing(3)

        self.buttons: List[QPushButton] = []
        for idx, (icon_key, label) in enumerate(NAV_ITEMS):
            btn = QPushButton(f"  {label}")
            btn.setObjectName("navBtn")
            btn.setIcon(render_svg_icon(icon_key, "#CBD5E1", 17))
            btn.setIconSize(QSize(17, 17))
            btn.setToolTip(label.replace("&&", "&"))
            btn.setCheckable(True)
            btn.setProperty("active", "false")
            btn.clicked.connect(lambda checked=False, i=idx: self.select_page(i))
            c_layout.addWidget(btn)
            self.buttons.append(btn)

        c_layout.addStretch()
        scroll.setWidget(container)
        layout.addWidget(scroll)

        # Bottom System Info (styled transparently via QSS #sidebarFooter)
        self.footer = QFrame()
        self.footer.setObjectName("sidebarFooter")
        f_lay = QVBoxLayout(self.footer)
        f_lay.setContentsMargins(6, 6, 6, 0)
        f_lay.setSpacing(2)

        sys_lbl = QLabel("🔒 Güvenli Adli Ortam")
        sys_lbl.setObjectName("sidebarFooterSafe")
        f_lay.addWidget(sys_lbl)

        ver_lbl = QLabel("v1.0.0 Pro • Windows x64")
        ver_lbl.setObjectName("sidebarFooterVer")
        f_lay.addWidget(ver_lbl)

        layout.addWidget(self.footer)

        if self.buttons:
            self.select_page(0)

    def toggle_collapse(self):
        self._collapsed = not self._collapsed
        self.setFixedWidth(64 if self._collapsed else 235)
        self.lbl_head.setVisible(not self._collapsed)
        self.footer.setVisible(not self._collapsed)
        for idx, (_, label) in enumerate(NAV_ITEMS):
            self.buttons[idx].setText("" if self._collapsed else f"  {label}")

    def select_page(self, index: int):
        for i, btn in enumerate(self.buttons):
            is_active = (i == index)
            btn.setChecked(is_active)
            btn.setProperty("active", "true" if is_active else "false")
            btn.style().unpolish(btn)
            btn.style().polish(btn)
        self.pageChanged.emit(index)
