"""GUI component tests in headless mode."""

import os
import pytest
from src.ui.components.status_indicator import StatusBadge
from src.ui.components.search_field import ForensicSearchField
from src.ui.components.breadcrumb import Breadcrumb
from src.ui.components.data_table import ForensicDataTable
from src.ui.components.hex_viewer import ForensicHexViewer
from src.ui.components.metadata_panel import MetadataPanel


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


def test_brand_assets_svg_icons_and_collapsible_sidebar(qapp):
    """Verify Gemini Banana assets, multi-res .ico app icon, SVG navigation icons, and collapsible sidebar toggle."""
    from src.ui.styles.icons import get_app_icon, get_brand_pixmap, get_banner_pixmap, render_svg_icon
    from src.ui.shell.sidebar import Sidebar

    app_ico = get_app_icon()
    assert not app_ico.isNull()
    assert len(app_ico.availableSizes()) >= 5
    assert not get_brand_pixmap(32).isNull()
    assert not get_banner_pixmap("light").isNull()
    assert not get_banner_pixmap("dark").isNull()
    assert not render_svg_icon("disk").isNull()

    sb = Sidebar()
    assert sb.width() == 235
    sb.toggle_collapse()
    assert sb.width() == 64
    sb.toggle_collapse()
    assert sb.width() == 235
