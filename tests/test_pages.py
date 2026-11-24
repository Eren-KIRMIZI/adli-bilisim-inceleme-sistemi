"""Tests for Dashboard, USB Analysis, Cases, Evidence, Integrity pages, and MainWindow."""

import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"

import pytest
from PySide6.QtWidgets import QApplication
from src.ui.pages.dashboard.dashboard_page import DashboardPage
from src.ui.pages.usb_analysis.usb_analysis_page import UsbAnalysisPage
from src.ui.pages.cases_page import CasesPage
from src.ui.pages.evidence_page import EvidencePage
from src.ui.pages.integrity_page import IntegrityPage
from src.ui.shell.main_window import MainWindow


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance()
    if not app:
        app = QApplication([])
    return app


def test_dashboard_page(qapp):
    page = DashboardPage()
    assert page.card_cases is not None
    assert page.table_audit.rowCount() >= 4


def test_usb_analysis_page(qapp):
    page = UsbAnalysisPage()
    assert page.table.rowCount() >= 4
    assert page.meta_panel is not None

    page.search_field.input.setText("SanDisk")
    page.search_field._emit_search()
    assert page.table.rowCount() == 1

    page.search_field.clear()
    page.search_field._emit_search()
    assert page.table.rowCount() >= 4


def test_cases_page(qapp, tmp_path):
    db_file = str(tmp_path / "ui_cases.db")
    page = CasesPage(db_path=db_file)
    assert page.table.rowCount() >= 1
    assert page.ins_title.text() != "Vaka Seçilmedi"


def test_evidence_page(qapp, tmp_path):
    db_file = str(tmp_path / "ui_evd.db")
    page = EvidencePage(db_path=db_file)
    assert page.table.rowCount() >= 3
    assert page.txt_sha256.text() != ""


def test_integrity_page(qapp, tmp_path):
    db_file = str(tmp_path / "ui_int.db")
    page = IntegrityPage(db_path=db_file)
    assert page.custody_table.rowCount() >= 4


def test_main_window_integration(qapp):
    win = MainWindow()
    assert win.stack.count() == 14
    assert "VAK-" in win.topbar.case_btn.text()
