"""Top bar for global forensic case status, write blocker indicators, and profile."""

from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QWidget
from PySide6.QtCore import Qt, Signal

class Topbar(QFrame):
    themeToggled = Signal(str)
    caseSwitchRequested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("topbarFrame")
        self.setFixedHeight(58)
        self._current_theme = "light"

        layout = QHBoxLayout(self)
        layout.setContentsMargins(18, 0, 18, 0)
        layout.setSpacing(14)

        # Brand Logo and Title
        title_box = QHBoxLayout()
        title_box.setSpacing(8)

        logo_lbl = QLabel("🛡️")
        logo_lbl.setStyleSheet("font-size: 20px; background: transparent;")
        title_box.addWidget(logo_lbl)

        title_lbl = QLabel("ADLİ BİLİŞİM İNCELEME SİSTEMİ")
        title_lbl.setStyleSheet("font-size: 14px; font-weight: 700; color: #1D2733; letter-spacing: 0.5px;")
        title_box.addWidget(title_lbl)

        suite_badge = QLabel("DFIR SUITE • V1.0")
        suite_badge.setStyleSheet("""
            background-color: #E9F1F8;
            color: #315C85;
            font-size: 10px;
            font-weight: 700;
            padding: 2px 6px;
            border-radius: 4px;
        """)
        title_box.addWidget(suite_badge)
        layout.addLayout(title_box)

        layout.addStretch()

        # Active Case Pill Button
        self.case_btn = QPushButton("📁 Vaka: VAK-2026-001 (Şirket İncelemesi)")
        self.case_btn.setStyleSheet("""
            QPushButton {
                background-color: #F2F4F7;
                color: #1D2733;
                border: 1px solid #D0D5DD;
                border-radius: 6px;
                padding: 5px 12px;
                font-size: 12px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #EAECF0;
                border-color: #315C85;
            }
        """)
        self.case_btn.clicked.connect(self.caseSwitchRequested.emit)
        layout.addWidget(self.case_btn)

        # Active Evidence Pill
        self.evidence_pill = QLabel("💾 Delil: EVD-01 (Kingston DT)")
        self.evidence_pill.setStyleSheet("""
            background-color: #F8FAFC;
            color: #475467;
            border: 1px solid #E2E8F0;
            border-radius: 6px;
            padding: 5px 10px;
            font-size: 12px;
            font-weight: 500;
        """)
        layout.addWidget(self.evidence_pill)

        # Write-Blocker / Salt Okunur Güvenlik Rozeti
        wb_badge = QLabel("🔒 Salt Okunur / Write-Blocked")
        wb_badge.setStyleSheet("""
            background-color: #EDF7F2;
            color: #26845B;
            border: 1px solid #A3D9C1;
            border-radius: 6px;
            padding: 5px 10px;
            font-size: 11px;
            font-weight: 700;
        """)
        wb_badge.setToolTip("Delil dosyası bütünlüğü kilitli: Tüm analiz işlemleri salt okunur çalışma kopyası üzerinde yürütülmektedir.")
        layout.addWidget(wb_badge)

        # Theme Toggle Button
        self.theme_btn = QPushButton("🌙 Koyu Tema")
        self.theme_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                border: 1px solid #D0D5DD;
                border-radius: 6px;
                padding: 5px 10px;
                font-size: 12px;
                color: #475467;
            }
            QPushButton:hover {
                background-color: #F2F4F7;
            }
        """)
        self.theme_btn.clicked.connect(self._toggle_theme)
        layout.addWidget(self.theme_btn)

        # User/Investigator Profile
        profile_lbl = QLabel("👤 Adli Uzman")
        profile_lbl.setStyleSheet("""
            background-color: #1D2733;
            color: #F5F5F7;
            border-radius: 6px;
            padding: 5px 10px;
            font-size: 12px;
            font-weight: 600;
        """)
        layout.addWidget(profile_lbl)

    def set_active_case(self, case_number: str, title: str):
        self.case_btn.setText(f"📁 Vaka: {case_number} ({title[:20]}...)")

    def set_active_evidence(self, evidence_name: str):
        self.evidence_pill.setText(f"💾 Delil: {evidence_name}")

    def _toggle_theme(self):
        if self._current_theme == "light":
            self._current_theme = "dark"
            self.theme_btn.setText("☀️ Açık Tema")
        else:
            self._current_theme = "light"
            self.theme_btn.setText("🌙 Koyu Tema")
        self.themeToggled.emit(self._current_theme)
