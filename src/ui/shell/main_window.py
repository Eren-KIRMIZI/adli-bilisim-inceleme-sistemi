"""Main application shell window coordinating topbar, sidebar, pages, statusbar, and crash recovery."""

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QStackedWidget, QApplication
)
from PySide6.QtCore import QTimer
from PySide6.QtGui import QIcon

from src.ui.shell.topbar import Topbar
from src.ui.shell.sidebar import Sidebar
from src.ui.shell.statusbar import Statusbar
from src.ui.styles.tokens import build_qss, build_palette
from src.ui.styles.icons import get_app_icon
from src.case_engine.case_service import CaseService
from src.evidence_engine.evidence_service import EvidenceService
from src.core.recovery import RecoveryManager


class MainWindow(QMainWindow):
    def __init__(self, db_path: str = "data/forensics.db", data_dir: str = "data"):
        super().__init__()
        self.setWindowTitle("Adli Bilişim İnceleme Sistemi (Digital Forensics Suite)")
        self.setWindowIcon(get_app_icon())
        self.resize(1400, 880)
        self.setMinimumSize(1100, 700)

        self.db_path = db_path
        self.active_case_id = None
        self.active_evidence_id = None
        self._current_theme = "dark"

        # Power-loss & crash recovery manager
        self.recovery = RecoveryManager(data_dir=data_dir)
        recovered = self.recovery.begin_session()

        # Central Container
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        root_layout = QVBoxLayout(central_widget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # Topbar
        self.topbar = Topbar(self)
        self.topbar.caseSwitchRequested.connect(self._on_case_switch_clicked)
        root_layout.addWidget(self.topbar)

        # Main Body: Sidebar + Page Stack
        body_widget = QWidget()
        body_layout = QHBoxLayout(body_widget)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)

        self.sidebar = Sidebar(self)
        body_layout.addWidget(self.sidebar)

        self.stack = QStackedWidget()
        self.stack.setObjectName("pageStack")
        body_layout.addWidget(self.stack, 1)

        root_layout.addWidget(body_widget, 1)

        # Statusbar
        self.statusbar = Statusbar(self)
        root_layout.addWidget(self.statusbar)

        # Initialize and connect pages
        self._init_pages()
        self.sidebar.pageChanged.connect(self._on_page_changed)
        self._sync_initial_context(recovered)

        # Enforce flagship Dark Forensic theme unconditionally
        self.set_theme("dark")

        if self.recovery.unclean_shutdown_detected:
            self.statusbar.set_recovery_notice(
                "⚡ Önceki oturum beklenmedik kesintiden kurtarıldı (WAL + Atomik Yedek)"
            )

        # Periodic autosave checkpoint every 30 seconds
        self._autosave_timer = QTimer(self)
        self._autosave_timer.setInterval(30_000)
        self._autosave_timer.timeout.connect(self._save_checkpoint)
        self._autosave_timer.start()

    def _init_pages(self):
        from src.ui.pages.dashboard.dashboard_page import DashboardPage
        from src.ui.pages.cases_page import CasesPage
        from src.ui.pages.evidence_page import EvidencePage
        from src.ui.pages.integrity_page import IntegrityPage
        from src.ui.pages.disk_forensics.disk_forensics_page import DiskForensicsPage
        from src.ui.pages.windows_forensics.windows_forensics_page import WindowsForensicsPage
        from src.ui.pages.usb_analysis.usb_analysis_page import UsbAnalysisPage
        from src.ui.pages.browser_forensics.browser_forensics_page import BrowserAnalysisPage
        from src.ui.pages.memory_forensics.memory_forensics_page import MemoryAnalysisPage
        from src.ui.pages.file_analysis_page import FileAnalysisPage
        from src.ui.pages.timeline_page import TimelinePage
        from src.ui.pages.relations.relations_page import RelationsPage
        from src.ui.pages.reports_page import ReportsPage
        from src.ui.pages.settings_page import SettingsPage

        self.dashboard_page = DashboardPage()
        self.cases_page = CasesPage(db_path=self.db_path)
        self.evidence_page = EvidencePage(db_path=self.db_path)
        self.integrity_page = IntegrityPage(db_path=self.db_path)
        self.disk_page = DiskForensicsPage()
        self.windows_page = WindowsForensicsPage()
        self.usb_page = UsbAnalysisPage()
        self.browser_page = BrowserAnalysisPage()
        self.memory_page = MemoryAnalysisPage()
        self.file_page = FileAnalysisPage()
        self.timeline_page = TimelinePage(db_path=self.db_path)
        self.relations_page = RelationsPage(db_path=self.db_path)
        self.reports_page = ReportsPage(db_path=self.db_path)
        self.settings_page = SettingsPage()

        # Global case & evidence synchronization signals
        self.cases_page.activeCaseSelected.connect(self._on_active_case_changed)
        self.evidence_page.activeEvidenceSelected.connect(self._on_active_evidence_changed)

        pages = [
            self.dashboard_page,
            self.cases_page,
            self.evidence_page,
            self.integrity_page,
            self.disk_page,
            self.windows_page,
            self.usb_page,
            self.browser_page,
            self.memory_page,
            self.file_page,
            self.timeline_page,
            self.relations_page,
            self.reports_page,
            self.settings_page,
        ]

        for p in pages:
            self.stack.addWidget(p)

    def _sync_initial_context(self, recovered: dict):
        cases = CaseService(db_path=self.db_path).list_cases()
        target_case = None
        rec_cid = recovered.get("active_case_id")
        if rec_cid:
            target_case = next((c for c in cases if c.id == rec_cid), None)
        if not target_case and cases:
            target_case = cases[0]

        if target_case:
            self._on_active_case_changed(target_case.id, target_case.case_number, target_case.title)
            evds = EvidenceService(db_path=self.db_path).list_evidence(case_id=target_case.id)
            rec_eid = recovered.get("active_evidence_id")
            target_evd = next((e for e in evds if e.id == rec_eid), None) if rec_eid else None
            if not target_evd and evds:
                target_evd = evds[0]
            if target_evd:
                self._on_active_evidence_changed(target_evd.id, f"{target_evd.evidence_number} ({target_evd.brand} {target_evd.model})")

        # Restore draft notes if present
        draft = recovered.get("report_draft") or {}
        if draft.get("expert_notes"):
            self.reports_page.notes_edit.setPlainText(draft["expert_notes"])
        if draft.get("limitations"):
            self.reports_page.limits_edit.setPlainText(draft["limitations"])

        # Restore page index if cleanly saved
        rec_page = recovered.get("page_index")
        if isinstance(rec_page, int) and 0 <= rec_page < self.stack.count():
            self.sidebar.select_page(rec_page)

    def _on_active_case_changed(self, case_id: int, case_number: str, title: str):
        self.active_case_id = case_id
        self.topbar.set_active_case(case_number, title)
        evd_count = len(EvidenceService(db_path=self.db_path).list_evidence(case_id=case_id))
        self.statusbar.set_case_info(f"Aktif Vaka: {case_number} • Delil Sayısı: {evd_count}")
        self.dashboard_page.set_active_case(case_id)
        self.evidence_page.set_case_context(case_id)
        self._save_checkpoint()

    def _on_active_evidence_changed(self, evidence_id: int, label: str):
        self.active_evidence_id = evidence_id
        self.topbar.set_active_evidence(label)
        self._save_checkpoint()

    def _on_page_changed(self, index: int):
        self.stack.setCurrentIndex(index)
        page = self.stack.widget(index)
        if hasattr(page, "refresh_data"):
            page.refresh_data()
        elif hasattr(page, "refresh_records"):
            page.refresh_records()
        self._save_checkpoint()

    def set_theme(self, theme_name: str = "dark"):
        # Application runs strictly in flagship dark mode
        self._current_theme = "dark"
        qss_code = build_qss("dark")
        app = QApplication.instance()
        if app:
            app.setPalette(build_palette("dark"))
            app.setStyleSheet(qss_code)
        if hasattr(self.dashboard_page, "set_theme"):
            self.dashboard_page.set_theme("dark")
        if hasattr(self.timeline_page, "set_theme"):
            self.timeline_page.set_theme("dark")
        if hasattr(self.relations_page, "set_theme"):
            self.relations_page.set_theme("dark")
        self._save_checkpoint()

    def _save_checkpoint(self):
        draft = {
            "expert_notes": self.reports_page.notes_edit.toPlainText(),
            "limitations": self.reports_page.limits_edit.toPlainText(),
        }
        self.recovery.save_checkpoint(
            active_case_id=self.active_case_id,
            active_evidence_id=self.active_evidence_id,
            page_index=self.stack.currentIndex(),
            theme=self._current_theme,
            report_draft=draft,
        )

    def closeEvent(self, event):
        if hasattr(self, "_autosave_timer"):
            self._autosave_timer.stop()
        self._save_checkpoint()
        self.recovery.create_verified_db_backup(self.db_path)
        self.recovery.end_session_cleanly()
        super().closeEvent(event)

    def _on_case_switch_clicked(self):
        self.sidebar.select_page(1)
