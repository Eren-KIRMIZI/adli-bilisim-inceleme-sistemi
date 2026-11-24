"""Tests for Dashboard and USB Analysis pages."""

import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"

import pytest
from PySide6.QtWidgets import QApplication
from src.ui.pages.dashboard.dashboard_page import DashboardPage
from src.ui.pages.usb_analysis.usb_analysis_page import UsbAnalysisPage

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
    
    # Test search filter with explicit emit
    page.search_field.input.setText("SanDisk")
    page.search_field._emit_search()
    assert page.table.rowCount() == 1
    
    # Reset
    page.search_field.clear()
    page.search_field._emit_search()
    assert page.table.rowCount() >= 4
