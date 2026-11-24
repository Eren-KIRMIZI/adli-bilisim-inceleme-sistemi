"""Forensic suite navigation sidebar with categories and status indicator."""

from typing import List, Tuple
from PySide6.QtWidgets import QFrame, QVBoxLayout, QPushButton, QLabel, QScrollArea, QWidget
from PySide6.QtCore import Qt, Signal

NAV_ITEMS: List[Tuple[str, str]] = [
    ("📊", "Genel Bakış (Dashboard)"),
    ("📁", "Vaka Yönetimi (Cases)"),
    ("💾", "Delil Yönetimi (Evidence)"),
    ("🔐", "Bütünlük & Hash"),
    ("💽", "Disk Forensics"),
    ("🪟", "Windows Forensics"),
    ("🔌", "USB Cihaz Analizi"),
    ("🌐", "Tarayıcı Analizi"),
    ("🧠", "RAM Bellek Analizi"),
    ("📄", "Dosya & Hex İnceleme"),
    ("⏱️", "Olay Zaman Çizelgesi"),
    ("🔗", "Bulgu İlişkilendirme"),
    ("📑", "Adli Rapor Oluşturucu"),
    ("⚙️", "Ayarlar & Lisanslar")
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

        # Header Title
        lbl_head = QLabel("ADLİ İNCELEME")
        lbl_head.setStyleSheet("color: #8A99AC; font-size: 11px; font-weight: 700; letter-spacing: 1px; padding: 4px 8px;")
        layout.addWidget(lbl_head)

        # Scroll Area for Nav Buttons
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("background: transparent;")

        container = QWidget()
        container.setStyleSheet("background: transparent;")
        c_layout = QVBoxLayout(container)
        c_layout.setContentsMargins(0, 4, 0, 4)
        c_layout.setSpacing(3)

        self.buttons: List[QPushButton] = []
        for idx, (icon, label) in enumerate(NAV_ITEMS):
            btn = QPushButton(f"{icon}  {label}")
            btn.setObjectName("navBtn")
            btn.setCheckable(True)
            btn.setProperty("active", "false")
            btn.setStyleSheet("""
                QPushButton {
                    background-color: transparent;
                    color: #D1D5DB;
                    border: none;
                    border-radius: 6px;
                    padding: 8px 12px;
                    text-align: left;
                    font-size: 13px;
                    font-weight: 500;
                }
                QPushButton:hover {
                    background-color: #283747;
                    color: #FFFFFF;
                }
                QPushButton:checked {
                    background-color: #315C85;
                    color: #FFFFFF;
                    font-weight: 600;
                }
            """)
            btn.clicked.connect(lambda checked=False, i=idx: self.select_page(i))
            c_layout.addWidget(btn)
            self.buttons.append(btn)

        c_layout.addStretch()
        scroll.setWidget(container)
        layout.addWidget(scroll)

        # Bottom System Info
        footer = QFrame()
        footer.setStyleSheet("border-top: 1px solid #283747; padding-top: 8px;")
        f_lay = QVBoxLayout(footer)
        f_lay.setContentsMargins(4, 4, 4, 0)
        f_lay.setSpacing(2)

        sys_lbl = QLabel("🔒 Güvenli Adli Ortam")
        sys_lbl.setStyleSheet("color: #26845B; font-size: 11px; font-weight: 600;")
        f_lay.addWidget(sys_lbl)

        ver_lbl = QLabel("v1.0.0 Pro • Windows x64")
        ver_lbl.setStyleSheet("color: #8A99AC; font-size: 10px;")
        f_lay.addWidget(ver_lbl)

        layout.addWidget(footer)

        # Set default active page
        if self.buttons:
            self.select_page(0)

    def select_page(self, index: int):
        for i, btn in enumerate(self.buttons):
            is_active = (i == index)
            btn.setChecked(is_active)
            btn.setProperty("active", "true" if is_active else "false")
        self.pageChanged.emit(index)
