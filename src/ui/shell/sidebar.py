"""Forensic suite navigation sidebar with categories and status indicator."""

from typing import List, Tuple
from PySide6.QtWidgets import QFrame, QVBoxLayout, QPushButton, QLabel, QScrollArea, QWidget
from PySide6.QtCore import Signal

# Escape '&' as '&&' in Qt QPushButton labels so mnemonics do not strip '&'
NAV_ITEMS: List[Tuple[str, str]] = [
    ("📊", "Genel Bakış (Dashboard)"),
    ("📁", "Vaka Yönetimi (Cases)"),
    ("💾", "Delil Yönetimi (Evidence)"),
    ("🔐", "Bütünlük && Hash"),
    ("💽", "Disk Forensics"),
    ("🪟", "Windows Forensics"),
    ("🔌", "USB Cihaz Analizi"),
    ("🌐", "Tarayıcı Analizi"),
    ("🧠", "RAM Bellek Analizi"),
    ("📄", "Dosya && Hex İnceleme"),
    ("⏱️", "Olay Zaman Çizelgesi"),
    ("🔗", "Bulgu İlişkilendirme"),
    ("📑", "Adli Rapor Oluşturucu"),
    ("⚙️", "Ayarlar && Lisanslar"),
]


class Sidebar(QFrame):
    pageChanged = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("sidebarFrame")
        self.setFixedWidth(235)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 16, 10, 12)
        layout.setSpacing(4)

        lbl_head = QLabel("ADLİ İNCELEME")
        lbl_head.setObjectName("sidebarHeader")
        layout.addWidget(lbl_head)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        container = QWidget()
        container.setObjectName("sidebarContainer")
        c_layout = QVBoxLayout(container)
        c_layout.setContentsMargins(0, 4, 0, 4)
        c_layout.setSpacing(3)

        self.buttons: List[QPushButton] = []
        for idx, (icon, label) in enumerate(NAV_ITEMS):
            btn = QPushButton(f"{icon}  {label}")
            btn.setObjectName("navBtn")
            btn.setCheckable(True)
            btn.setProperty("active", "false")
            btn.clicked.connect(lambda checked=False, i=idx: self.select_page(i))
            c_layout.addWidget(btn)
            self.buttons.append(btn)

        c_layout.addStretch()
        scroll.setWidget(container)
        layout.addWidget(scroll)

        # Bottom System Info (styled transparently via QSS #sidebarFooter)
        footer = QFrame()
        footer.setObjectName("sidebarFooter")
        f_lay = QVBoxLayout(footer)
        f_lay.setContentsMargins(6, 6, 6, 0)
        f_lay.setSpacing(2)

        sys_lbl = QLabel("🔒 Güvenli Adli Ortam")
        sys_lbl.setObjectName("sidebarFooterSafe")
        f_lay.addWidget(sys_lbl)

        ver_lbl = QLabel("v1.0.0 Pro • Windows x64")
        ver_lbl.setObjectName("sidebarFooterVer")
        f_lay.addWidget(ver_lbl)

        layout.addWidget(footer)

        if self.buttons:
            self.select_page(0)

    def select_page(self, index: int):
        for i, btn in enumerate(self.buttons):
            is_active = (i == index)
            btn.setChecked(is_active)
            btn.setProperty("active", "true" if is_active else "false")
            btn.style().unpolish(btn)
            btn.style().polish(btn)
        self.pageChanged.emit(index)
