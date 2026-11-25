"""Asset loaders and crisp inline SVG vector icons for the DFIR PySide6 desktop shell."""

import os
from PySide6.QtCore import QByteArray, QSize, Qt
from PySide6.QtGui import QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer

ASSETS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "assets"))


def get_asset_path(filename: str) -> str:
    return os.path.join(ASSETS_DIR, filename)


def get_app_icon() -> QIcon:
    """Return multi-resolution Windows .ico (falling back to app_icon.png / brand_shield.png)."""
    for fname in ("app_icon.ico", "app_icon.png", "brand_shield.png"):
        p = get_asset_path(fname)
        if os.path.isfile(p):
            ic = QIcon(p)
            if not ic.isNull():
                return ic
    return QIcon()


def get_brand_pixmap(size: int = 28) -> QPixmap:
    for fname in ("app_icon.png", "brand_shield.png"):
        p = get_asset_path(fname)
        if os.path.isfile(p):
            pix = QPixmap(p)
            if not pix.isNull():
                return pix.scaled(size, size, Qt.KeepAspectRatio, Qt.SmoothTransformation)
    return QPixmap()


def get_banner_pixmap(theme_name: str = "light") -> QPixmap:
    fname = "lab_banner_dark.png" if theme_name == "dark" else "lab_banner_light.png"
    p = get_asset_path(fname)
    if os.path.isfile(p):
        pix = QPixmap(p)
        if not pix.isNull():
            return pix
    return QPixmap()


_SVG_PATHS = {
    "dashboard": '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
    "cases": '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
    "evidence": '<rect x="4" y="3" width="16" height="18" rx="2"/><circle cx="12" cy="11" r="4"/><line x1="8" y1="18" x2="16" y2="18"/>',
    "integrity": '<path d="M12 2l7 4v6c0 5-3.5 9-7 10-3.5-1-7-5-7-10V6l7-4z"/><polyline points="9 12 11 14 15 10"/>',
    "disk": '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="2.5"/><line x1="12" y1="14.5" x2="17" y2="19"/>',
    "windows": '<rect x="3" y="4" width="8" height="7"/><rect x="13" y="4" width="8" height="7"/><rect x="3" y="13" width="8" height="7"/><rect x="13" y="13" width="8" height="7"/>',
    "usb": '<path d="M12 2v14m0-14l-3 3m3-3l3 3"/><circle cx="7" cy="11" r="1.5"/><circle cx="17" cy="11" r="1.5"/><path d="M7 12.5V15l5 2 5-2v-2.5"/><circle cx="12" cy="20" r="2"/>',
    "browser": '<circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><line x1="3" y1="12" x2="21" y2="12"/>',
    "memory": '<rect x="5" y="5" width="14" height="14" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"/>',
    "file": '<path d="M6 2h8l5 5v15a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V3a1 1 0 0 1 1-1z"/><polyline points="14 2 14 8 19 8"/><line x1="9" y1="13" x2="15" y2="13"/><line x1="9" y1="17" x2="13" y2="17"/>',
    "timeline": '<circle cx="12" cy="12" r="9"/><polyline points="12 7 12 12 16 14"/>',
    "relations": '<circle cx="6" cy="12" r="2.5"/><circle cx="18" cy="6" r="2.5"/><circle cx="18" cy="18" r="2.5"/><line x1="8.2" y1="10.8" x2="15.8" y2="7.2"/><line x1="8.2" y1="13.2" x2="15.8" y2="16.8"/>',
    "report": '<path d="M6 2h9l4 4v16H6z"/><polyline points="14 2 14 7 19 7"/><line x1="9" y1="12" x2="15" y2="12"/><line x1="9" y1="16" x2="15" y2="16"/>',
    "acquisition": '<rect x="3" y="4" width="18" height="12" rx="2"/><line x1="7" y1="20" x2="17" y2="20"/><line x1="12" y1="16" x2="12" y2="20"/><path d="M12 7v5m-2-2l2 2 2-2"/>',
    "hunt": '<circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.65" y2="16.65"/><path d="M11 8v6M8 11h6"/>',
    "settings": '<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M2 12h3M19 12h3M4.9 19.1L7 17M17 7l2.1-2.1"/>',
}


def render_svg_icon(key: str, color: str = "#E5E7EB", size: int = 18) -> QIcon:
    inner = _SVG_PATHS.get(key, _SVG_PATHS["dashboard"])
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" '
        f'viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="1.9" '
        f'stroke-linecap="round" stroke-linejoin="round">{inner}</svg>'
    )
    renderer = QSvgRenderer(QByteArray(svg.encode("utf-8")))
    pix = QPixmap(QSize(size, size))
    pix.fill(Qt.transparent)
    painter = QPainter(pix)
    renderer.render(painter)
    painter.end()
    return QIcon(pix)
