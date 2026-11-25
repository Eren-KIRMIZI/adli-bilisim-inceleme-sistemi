"""Tests for Dashboard, USB Analysis, Cases, Evidence, Integrity pages, and MainWindow."""

import os
import pytest
from src.ui.pages.dashboard.dashboard_page import DashboardPage
from src.ui.pages.usb_analysis.usb_analysis_page import UsbAnalysisPage
from src.ui.pages.cases_page import CasesPage
from src.ui.pages.evidence_page import EvidencePage
from src.ui.pages.integrity_page import IntegrityPage
from src.ui.pages.disk_forensics.disk_forensics_page import DiskForensicsPage
from src.ui.pages.windows_forensics.windows_forensics_page import WindowsForensicsPage
from src.ui.pages.file_analysis_page import FileAnalysisPage
from src.ui.pages.browser_forensics.browser_forensics_page import BrowserAnalysisPage
from src.ui.pages.memory_forensics.memory_forensics_page import MemoryAnalysisPage
from src.ui.pages.timeline_page import TimelinePage
from src.ui.pages.relations.relations_page import RelationsPage
from src.ui.pages.reports_page import ReportsPage
from src.ui.pages.settings_page import SettingsPage
from src.ui.shell.main_window import MainWindow


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


def test_disk_forensics_page(qapp, tmp_path):
    from src.ntfs_engine.ntfs_service import create_synthetic_ntfs_image
    img_path = str(tmp_path / "ui_disk.dd")
    create_synthetic_ntfs_image(img_path)

    page = DiskForensicsPage()
    page.load_image(img_path)
    assert page.table.rowCount() >= 6
    page._run_carving()
    assert page.table.rowCount() >= 3


def test_windows_forensics_page(qapp, tmp_path):
    from src.registry_engine.hive_parser import create_synthetic_registry_hive
    from src.eventlog_engine.evtx_service import create_synthetic_evtx_file
    from src.registry_engine.windows_artifacts import create_synthetic_windows_artifacts

    hive_path = str(tmp_path / "ui_hive.hiv")
    evtx_path = str(tmp_path / "ui_sec.evtx")
    create_synthetic_registry_hive(hive_path)
    create_synthetic_evtx_file(evtx_path)
    art_paths = create_synthetic_windows_artifacts(str(tmp_path / "arts"))

    page = WindowsForensicsPage()
    page.load_hive(hive_path)
    assert page.reg_tree.topLevelItemCount() == 1

    page.load_evtx(evtx_path)
    assert page.evtx_table.rowCount() == 5

    for p in art_paths.values():
        page.load_artifact_file(p)
    assert page.art_table.rowCount() >= 4


def test_file_browser_memory_pages(qapp, tmp_path):
    from src.file_engine.file_service import create_synthetic_exif_jpeg
    from src.browser_engine.browser_service import create_synthetic_browser_databases
    from src.memory_engine.memory_service import create_synthetic_memory_dump

    jpg = str(tmp_path / "ui_exif.jpg")
    create_synthetic_exif_jpeg(jpg)
    fpage = FileAnalysisPage()
    fpage.analyze_file(jpg)
    assert "Canon EOS R5" in fpage.meta_view.toPlainText()

    bpaths = create_synthetic_browser_databases(str(tmp_path / "ui_br"))
    bpage = BrowserAnalysisPage()
    bpage.load_artifact(bpaths["history"], browser_hint="Google Chrome")
    assert bpage.tbl_history.rowCount() == 3

    dmp = str(tmp_path / "ui_mem.dmp")
    create_synthetic_memory_dump(dmp)
    mpage = MemoryAnalysisPage()
    mpage.load_dump(dmp)
    assert mpage.tbl_pes.rowCount() == 1
    assert mpage.tbl_iocs.rowCount() >= 2
    assert mpage.tbl_eprocs.rowCount() >= 1


def test_timeline_relations_reports_settings_pages(qapp, tmp_path):
    db_file = str(tmp_path / "ui_final.db")

    tl = TimelinePage(db_path=db_file)
    assert tl.table.rowCount() >= 10

    rel = RelationsPage(db_path=db_file)
    assert len(rel._graph_data["nodes"]) >= 6

    rep = ReportsPage(db_path=db_file, cert_dir=str(tmp_path / "certs"))
    assert "VAK-2026-084" in rep.preview.toHtml()

    st = SettingsPage(db_path=db_file, cert_dir=str(tmp_path / "certs"))
    assert st.lic_table.rowCount() >= 10
    assert st.rbac_table.rowCount() >= 4


def test_main_window_integration(qapp, tmp_path):
    qapp.setStyle("Fusion")
    win = MainWindow(db_path=str(tmp_path / "main.db"), data_dir=str(tmp_path))
    assert win.stack.count() == 15
    assert "VAK-" in win.topbar.case_btn.text()
    assert isinstance(win.settings_page, SettingsPage)
    assert win.acquisition_page.targets_table.rowCount() >= 1
    # Verify escaped ampersand in sidebar labels
    assert "&&" in win.sidebar.buttons[3].text()
    # Verify flagship dark-only theme enforcement
    assert win._current_theme == "dark"
    win.set_theme("light")
    assert win._current_theme == "dark"
    win.close()
