"""Status bar for bottom system metrics and custody verification status."""

from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel
from PySide6.QtCore import Qt

class Statusbar(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("statusbarFrame")
        self.setFixedHeight(28)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 0, 14, 0)
        layout.setSpacing(16)

        # Left: Active case summary
        self.case_status = QLabel("Aktif Vaka: VAK-2026-001 • Delil Sayısı: 4")
        self.case_status.setStyleSheet("font-size: 11px; color: #8A99AC;")
        layout.addWidget(self.case_status)

        layout.addStretch()

        # Center: Custody status
        self.custody_status = QLabel("🛡️ ISO/IEC 27037 & NIST SP 800-86 Uyumlu İnceleme")
        self.custody_status.setStyleSheet("font-size: 11px; color: #8A99AC;")
        layout.addWidget(self.custody_status)

        layout.addStretch()

        # Right: DB status & Version
        self.db_status = QLabel("● SQLite Bağlantısı: Aktif")
        self.db_status.setStyleSheet("font-size: 11px; color: #26845B; font-weight: 600;")
        layout.addWidget(self.db_status)

        self.version_lbl = QLabel("v1.0.0-dfir")
        self.version_lbl.setStyleSheet("font-size: 11px; color: #8A99AC;")
        layout.addWidget(self.version_lbl)

    def set_case_info(self, text: str):
        self.case_status.setText(text)

    def set_db_status(self, connected: bool):
        if connected:
            self.db_status.setText("● SQLite Bağlantısı: Aktif")
            self.db_status.setStyleSheet("font-size: 11px; color: #26845B; font-weight: 600;")
        else:
            self.db_status.setText("○ SQLite Bağlantısı: Kesildi")
            self.db_status.setStyleSheet("font-size: 11px; color: #C34C4C; font-weight: 600;")
