"""Browser Forensics Page for Chrome, Edge, and Firefox SQLite & Bookmarks artifacts."""

import os
from typing import Dict, Any, List
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QComboBox, QSplitter, QTabWidget, QTextEdit, QFileDialog, QMessageBox
)
from PySide6.QtCore import Qt

from src.browser_engine.browser_service import BrowserForensicsEngine, create_synthetic_browser_databases
from src.ui.components.breadcrumb import Breadcrumb
from src.ui.components.search_field import ForensicSearchField
from src.ui.components.data_table import ForensicDataTable
from src.ui.components.status_indicator import StatusBadge


class BrowserAnalysisPage(QWidget):
    """Browser artifact inspection workbench (History, Downloads, Bookmarks, Masked Cookies)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.engine = BrowserForensicsEngine()
        self._history: List[Dict[str, Any]] = []
        self._downloads: List[Dict[str, Any]] = []
        self._searches: List[Dict[str, Any]] = []
        self._bookmarks: List[Dict[str, Any]] = []
        self._cookies: List[Dict[str, Any]] = []

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 18, 24, 18)
        main_layout.setSpacing(12)

        # Header
        header_bar = QHBoxLayout()
        self.breadcrumb = Breadcrumb(["Adli Bilişim", "Tarayıcı Analizi (Chrome / Edge / Firefox)"])
        header_bar.addWidget(self.breadcrumb)
        header_bar.addStretch()

        self.privacy_badge = StatusBadge("Hassas Parolalar Maskeli", "verified")
        header_bar.addWidget(self.privacy_badge)
        self.count_badge = StatusBadge("0 Kayıt", "info")
        header_bar.addWidget(self.count_badge)
        main_layout.addLayout(header_bar)

        # Toolbar
        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)

        self.search_field = ForensicSearchField("URL, başlık, indirme dosyası veya arama terimi ara...")
        self.search_field.searchChanged.connect(self._apply_filters)
        toolbar.addWidget(self.search_field, 2)

        self.browser_filter = QComboBox()
        self.browser_filter.addItems(["Tüm Tarayıcılar", "Google Chrome", "Microsoft Edge", "Mozilla Firefox"])
        self.browser_filter.setFixedWidth(160)
        self.browser_filter.currentIndexChanged.connect(self._apply_filters)
        toolbar.addWidget(self.browser_filter)

        open_btn = QPushButton("📁 SQLite / Bookmarks Aç")
        open_btn.setObjectName("primaryBtn")
        open_btn.clicked.connect(self._open_file_dialog)
        toolbar.addWidget(open_btn)

        local_btn = QPushButton("🔍 Yerel Profilleri Tara")
        local_btn.clicked.connect(self._scan_local_profiles)
        toolbar.addWidget(local_btn)

        sample_btn = QPushButton("🧪 Örnek Tarayıcı Verisi İncele")
        sample_btn.clicked.connect(self._load_synthetic_data)
        toolbar.addWidget(sample_btn)

        main_layout.addLayout(toolbar)

        # Splitter: Tabs + Right Detail Inspector
        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)

        self.tabs = QTabWidget()
        self.tbl_history = ForensicDataTable(["Tarayıcı", "Profil", "Zaman (UTC)", "Başlık", "URL", "Ziyaret"], self)
        self.tbl_downloads = ForensicDataTable(["Tarayıcı", "Zaman (UTC)", "Hedef Dosya", "Boyut", "Kaynak URL"], self)
        self.tbl_searches = ForensicDataTable(["Tarayıcı", "Zaman (UTC)", "Arama Terimi", "Kaynak", "URL"], self)
        self.tbl_bookmarks = ForensicDataTable(["Tarayıcı", "Zaman (UTC)", "Yer İmi Başlığı", "URL"], self)
        self.tbl_cookies = ForensicDataTable(["Tarayıcı", "Alan Adı (Host)", "Çerez Adı", "Değer Durumu", "Oluşturulma (UTC)"], self)

        for tbl in (self.tbl_history, self.tbl_downloads, self.tbl_searches, self.tbl_bookmarks, self.tbl_cookies):
            tbl.rowSelected.connect(self._on_row_selected)

        self.tabs.addTab(self.tbl_history, "🌐 Ziyaret Geçmişi")
        self.tabs.addTab(self.tbl_downloads, "⬇️ İndirmeler")
        self.tabs.addTab(self.tbl_searches, "🔎 Arama Geçmişi")
        self.tabs.addTab(self.tbl_bookmarks, "⭐ Yer İmleri")
        self.tabs.addTab(self.tbl_cookies, "🍪 Çerez Metadata")
        splitter.addWidget(self.tabs)

        right = QFrame()
        right.setObjectName("surfaceCard")
        right.setFixedWidth(340)
        r_lay = QVBoxLayout(right)
        r_lay.setContentsMargins(12, 12, 12, 12)
        r_lay.addWidget(QLabel("Seçili Tarayıcı Artefaktı Kaynağı"))
        self.detail_view = QTextEdit()
        self.detail_view.setReadOnly(True)
        self.detail_view.setStyleSheet("font-family: Consolas; font-size: 11px;")
        r_lay.addWidget(self.detail_view)
        splitter.addWidget(right)

        splitter.setStretchFactor(0, 7)
        splitter.setStretchFactor(1, 3)
        main_layout.addWidget(splitter, 1)

    def _open_file_dialog(self):
        fp, _ = QFileDialog.getOpenFileName(
            self,
            "Tarayıcı SQLite veya Bookmarks Dosyası Seç (Salt Okunur)",
            "",
            "Tarayıcı Dosyaları (History places.sqlite cookies.sqlite Cookies Bookmarks *.sqlite *.db *.json);;Tüm Dosyalar (*.*)",
        )
        if fp:
            self.load_artifact(fp)

    def _load_synthetic_data(self):
        paths = create_synthetic_browser_databases(os.path.join("data", "sample_browser"))
        self._clear_all()
        self.load_artifact(paths["history"], browser_hint="Google Chrome", append=True)
        self.load_artifact(paths["bookmarks"], browser_hint="Google Chrome", append=True)

    def _scan_local_profiles(self):
        profiles = self.engine.discover_local_profiles()
        if not profiles:
            QMessageBox.information(self, "Profil Bulunamadı", "Yerel Chrome/Edge/Firefox profili tespit edilemedi.")
            return
        self._clear_all()
        loaded = 0
        for p in profiles:
            for key in ("history", "cookies"):
                if p.get(key):
                    try:
                        self.load_artifact(p[key], browser_hint=p["browser"], profile=p["profile"], append=True)
                        loaded += 1
                    except Exception:
                        continue
            if p.get("bookmarks") and p["bookmarks"].endswith("Bookmarks"):
                try:
                    self.load_artifact(p["bookmarks"], browser_hint=p["browser"], profile=p["profile"], append=True)
                except Exception:
                    pass
        if loaded == 0:
            QMessageBox.information(self, "Kilitli Dosya", "Yerel tarayıcı veritabanları tarayıcı açık olduğu için kilitli olabilir; çalışma kopyası üzerinden açın.")

    def _clear_all(self):
        self._history.clear()
        self._downloads.clear()
        self._searches.clear()
        self._bookmarks.clear()
        self._cookies.clear()

    def load_artifact(self, path: str, browser_hint: str = "Otomatik", profile: str = "Default", append: bool = False):
        if not append:
            self._clear_all()
        try:
            if path.lower().endswith(".json") or os.path.basename(path) == "Bookmarks":
                bmarks = self.engine.parse_chromium_bookmarks_json(path, browser_name="Google Chrome" if browser_hint == "Otomatik" else browser_hint, profile=profile)
                for b in bmarks:
                    self._bookmarks.append({
                        "Tarayıcı": b["browser"],
                        "Zaman (UTC)": b["timestamp_utc"].strftime("%Y-%m-%d %H:%M:%S") if b["timestamp_utc"] else "-",
                        "Yer İmi Başlığı": b["title"],
                        "URL": b["url"],
                        "_source": b["source"],
                        "_profile": b["profile"],
                    })
            else:
                res = self.engine.parse_sqlite_artifact(path, browser_hint=browser_hint, profile_name=profile)
                for h in res["history"]:
                    self._history.append({
                        "Tarayıcı": h["browser"],
                        "Profil": h["profile"],
                        "Zaman (UTC)": h["timestamp_utc"].strftime("%Y-%m-%d %H:%M:%S") if h["timestamp_utc"] else "-",
                        "Başlık": h["title"],
                        "URL": h["url"],
                        "Ziyaret": h["visit_count"],
                        "_source": h["source"],
                    })
                for d in res["downloads"]:
                    self._downloads.append({
                        "Tarayıcı": d["browser"],
                        "Zaman (UTC)": d["timestamp_utc"].strftime("%Y-%m-%d %H:%M:%S") if d["timestamp_utc"] else "-",
                        "Hedef Dosya": d["target_path"],
                        "Boyut": f"{d['total_bytes']:,} B",
                        "Kaynak URL": d["source_url"],
                        "_source": d["source"],
                    })
                for s in res["searches"]:
                    self._searches.append({
                        "Tarayıcı": s["browser"],
                        "Zaman (UTC)": s["timestamp_utc"].strftime("%Y-%m-%d %H:%M:%S") if s["timestamp_utc"] else "-",
                        "Arama Terimi": s["term"],
                        "Kaynak": s["source"],
                        "URL": s["url"],
                        "_source": s["source"],
                    })
                for b in res["bookmarks"]:
                    self._bookmarks.append({
                        "Tarayıcı": b["browser"],
                        "Zaman (UTC)": b["timestamp_utc"].strftime("%Y-%m-%d %H:%M:%S") if b["timestamp_utc"] else "-",
                        "Yer İmi Başlığı": b["title"],
                        "URL": b["url"],
                        "_source": b["source"],
                    })
                for c in res["cookies"]:
                    self._cookies.append({
                        "Tarayıcı": c["browser"],
                        "Alan Adı (Host)": c["host"],
                        "Çerez Adı": c["cookie_name"],
                        "Değer Durumu": c["value_status"],
                        "Oluşturulma (UTC)": c["created_utc"].strftime("%Y-%m-%d %H:%M:%S") if c["created_utc"] else "-",
                        "_source": c["source"],
                    })
                if res.get("warnings"):
                    self.detail_view.setPlainText("⚠️ UYARILAR:\n" + "\n".join(res["warnings"]))
                    self.count_badge.set_status("Kayıt Sınırı Uyarısı", "warning")
            self._apply_filters()
        except Exception as e:
            QMessageBox.critical(self, "Tarayıcı Analiz Hatası", str(e))

    def _apply_filters(self):
        bflt = self.browser_filter.currentText()
        q = self.search_field.text().lower()

        def filt(rows):
            out = rows
            if bflt != "Tüm Tarayıcılar":
                out = [r for r in out if bflt.lower() in r["Tarayıcı"].lower()]
            if q:
                out = [r for r in out if any(q in str(v).lower() for k, v in r.items() if not k.startswith("_"))]
            return out

        h_rows = filt(self._history)
        d_rows = filt(self._downloads)
        s_rows = filt(self._searches)
        b_rows = filt(self._bookmarks)
        c_rows = filt(self._cookies)

        self.tbl_history.set_records(h_rows)
        self.tbl_downloads.set_records(d_rows)
        self.tbl_searches.set_records(s_rows)
        self.tbl_bookmarks.set_records(b_rows)
        self.tbl_cookies.set_records(c_rows)

        total = len(h_rows) + len(d_rows) + len(s_rows) + len(b_rows) + len(c_rows)
        self.count_badge.set_status(f"{total} Artefakt", "info")

    def _on_row_selected(self, row: Dict[str, Any]):
        lines = [f"{k}: {v}" for k, v in row.items() if not k.startswith("_")]
        lines.append(f"\nKaynak Veritabanı: {row.get('_source', '-')}")
        self.detail_view.setPlainText("\n".join(lines))
