"""Status bar for bottom system metrics, crash-recovery info, and custody verification status."""

from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel


class Statusbar(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("statusbarFrame")
        self.setFixedHeight(30)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 0, 14, 0)
        layout.setSpacing(16)

        self.case_status = QLabel("Aktif Vaka: - • Delil Sayısı: 0")
        self.case_status.setObjectName("statusBarText")
        layout.addWidget(self.case_status)

        layout.addStretch()

        self.custody_status = QLabel("🛡️ ISO/IEC 27037 • NIST SP 800-86 • WAL Koruması Aktif")
        self.custody_status.setObjectName("statusBarText")
        layout.addWidget(self.custody_status)

        layout.addStretch()

        self.db_status = QLabel("● SQLite WAL Bağlı")
        self.db_status.setObjectName("statusBarDbOk")
        layout.addWidget(self.db_status)

        self.version_lbl = QLabel("v1.0.0-dfir")
        self.version_lbl.setObjectName("statusBarText")
        layout.addWidget(self.version_lbl)

    def set_case_info(self, text: str):
        self.case_status.setText(text)

    def set_recovery_notice(self, text: str):
        self.custody_status.setText(text)

    def set_db_status(self, connected: bool):
        if connected:
            self.db_status.setText("● SQLite WAL Bağlı")
            self.db_status.setObjectName("statusBarDbOk")
        else:
            self.db_status.setText("○ SQLite Bağlantısı Kesildi")
            self.db_status.setStyleSheet("font-size: 11px; color: #C34C4C; font-weight: 600;")
