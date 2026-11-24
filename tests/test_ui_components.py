"""GUI component tests in headless mode."""

import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"

import pytest
from PySide6.QtWidgets import QApplication
from src.ui.components.status_indicator import StatusBadge
from src.ui.components.search_field import ForensicSearchField
from src.ui.components.breadcrumb import Breadcrumb
from src.ui.components.data_table import ForensicDataTable
from src.ui.components.hex_viewer import ForensicHexViewer
from src.ui.components.metadata_panel import MetadataPanel

@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance()
    if not app:
        app = QApplication([])
    return app

def test_status_badge(qapp):
    badge = StatusBadge("Doğrulandı", "verified")
    assert "Doğrulandı" in badge.text()

def test_search_field(qapp):
    sf = ForensicSearchField("Ara...")
    assert sf.text() == ""
    sf.input.setText("SanDisk")
    assert sf.text() == "SanDisk"

def test_breadcrumb(qapp):
    bc = Breadcrumb(["Adli Bilişim", "USB Analiz"])
    assert bc.layout.count() >= 2

def test_data_table(qapp):
    headers = ["Durum", "Cihaz", "Seri"]
    table = ForensicDataTable(headers)
    table.set_records([
        {"Durum": "Doğrulandı", "Cihaz": "SanDisk", "Seri": "12345"},
        {"Durum": "Şüpheli", "Cihaz": "BadUSB", "Seri": "99999"}
    ])
    assert table.rowCount() == 2
    
    table.filter_records("BadUSB")
    assert len(table._visible_records) == 1

def test_hex_viewer(qapp):
    hv = ForensicHexViewer()
    hv.load_bytes(b"HELLO_FORENSICS")
    text = hv.text_edit.toPlainText()
    assert "OFFSET" in text
    assert "HELLO_FORENSICS" in text

def test_metadata_panel(qapp):
    mp = MetadataPanel()
    mp.populate({
        "Cihaz Adı": "SanDisk Cruzer",
        "Üretici": "SanDisk",
        "VID": "0781",
        "Durum": "Normal"
    })
    assert mp.status_badge.text() != ""
