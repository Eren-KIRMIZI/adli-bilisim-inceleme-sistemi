"""Top bar for global forensic case status, write blocker indicators, and profile."""

from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton
from PySide6.QtCore import Signal
from src.ui.styles.icons import get_brand_pixmap


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
        layout.setSpacing(12)

        # Brand Logo and Title
        title_box = QHBoxLayout()
        title_box.setSpacing(8)

        logo_lbl = QLabel()
        pix = get_brand_pixmap(32)
        if not pix.isNull():
            logo_lbl.setPixmap(pix)
        else:
            logo_lbl.setText("🛡️")
        logo_lbl.setFixedSize(34, 34)
        title_box.addWidget(logo_lbl)

        title_lbl = QLabel("ADLİ BİLİŞİM İNCELEME SİSTEMİ")
        title_lbl.setObjectName("topbarTitle")
        title_box.addWidget(title_lbl)

        suite_badge = QLabel("DFIR SUITE • V1.0")
        suite_badge.setObjectName("topbarBadge")
        title_box.addWidget(suite_badge)
        layout.addLayout(title_box)

        layout.addStretch()

        # Active Case Pill Button
        self.case_btn = QPushButton("📁 Vaka: VAK-2026-084")
        self.case_btn.setObjectName("topbarCaseBtn")
        self.case_btn.clicked.connect(self.caseSwitchRequested.emit)
        layout.addWidget(self.case_btn)

        # Active Evidence Pill
        self.evidence_pill = QLabel("💾 Delil: Seçilmedi")
        self.evidence_pill.setObjectName("topbarEvidencePill")
        layout.addWidget(self.evidence_pill)

        # Write-Blocker / Salt Okunur Güvenlik Rozeti
        wb_badge = QLabel("🔒 Salt Okunur / Write-Blocked")
        wb_badge.setObjectName("topbarWriteBlockPill")
        wb_badge.setToolTip(
            "Delil dosyası bütünlüğü kilitli: Tüm analiz işlemleri salt okunur çalışma kopyası üzerinde yürütülmektedir."
        )
        layout.addWidget(wb_badge)

        # Theme Toggle Button
        self.theme_btn = QPushButton("🌙 Koyu Tema")
        self.theme_btn.clicked.connect(self._toggle_theme)
        layout.addWidget(self.theme_btn)

        # User/Investigator Profile
        profile_lbl = QLabel("👤 Adli Uzman")
        profile_lbl.setObjectName("topbarProfilePill")
        layout.addWidget(profile_lbl)

    def set_active_case(self, case_number: str, title: str):
        short_title = (title[:22] + "...") if len(title) > 22 else title
        self.case_btn.setText(f"📁 Vaka: {case_number} ({short_title})")

    def set_active_evidence(self, evidence_name: str):
        self.evidence_pill.setText(f"💾 Delil: {evidence_name}")

    def set_theme_state(self, theme_name: str):
        self._current_theme = theme_name
        if theme_name == "dark":
            self.theme_btn.setText("☀️ Açık Tema")
        else:
            self.theme_btn.setText("🌙 Koyu Tema")

    def _toggle_theme(self):
        new_theme = "dark" if self._current_theme == "light" else "light"
        self.set_theme_state(new_theme)
        self.themeToggled.emit(new_theme)
