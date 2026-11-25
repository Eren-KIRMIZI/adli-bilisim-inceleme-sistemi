"""Mobile (ALEAPP/iLEAPP), Cloud Sync (M365/OneDrive), SQLite FTS5 Search, Bookmarks & CFReDS/STIX Hub."""

import os
from typing import Any, Dict, List
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QTabWidget, QLineEdit, QComboBox, QTextEdit, QSplitter, QFileDialog, QMessageBox
)
from PySide6.QtCore import Qt

from src.mobile_cloud_engine.mobile_cloud_service import (
    MobileCloudForensicsService,
    create_synthetic_mobile_cloud_bundle,
)
from src.core.fts_index import ForensicFtsIndex
from src.core.bookmark_service import BookmarkService
from src.core.benchmark_service import BenchmarkService
from src.core.triage_collector import TriageCollector
from src.core.orchestrator import AnalysisOrchestrator
from src.ui.components.breadcrumb import Breadcrumb
from src.ui.components.data_table import ForensicDataTable
from src.ui.components.status_indicator import StatusBadge


class MobileCloudHuntPage(QWidget):
    """Unified Mobile/Cloud Forensics, SQLite FTS5 Full-Text Search, Analyst Bookmarks & CFReDS/STIX Hub."""

    def __init__(self, db_path: str = "data/forensics.db", fts_db_path: str = "data/fts_index.db", parent=None):
        super().__init__(parent)
        self.db_path = db_path
        self.fts = ForensicFtsIndex(db_path=fts_db_path)
        self.bookmarks = BookmarkService(db_path=db_path)
        self._active_case_id = 1
        self._active_user = "Adli Bilişim Uzmanı"

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 18, 24, 18)
        main_layout.setSpacing(12)

        header = QHBoxLayout()
        self.breadcrumb = Breadcrumb(["Adli Bilişim", "Mobil, Bulut & Tehdit Avı Merkezi"])
        header.addWidget(self.breadcrumb)
        header.addStretch()
        self.status_badge = StatusBadge("ALEAPP/iLEAPP + FTS5 + STIX 2.1", "verified")
        header.addWidget(self.status_badge)
        main_layout.addLayout(header)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_mobile_cloud_tab(), "📱 Mobil && Bulut Artefaktları")
        self.tabs.addTab(self._build_fts_bookmark_tab(), "🔎 Tam Metin Arama (FTS5) && Etiketler")
        self.tabs.addTab(self._build_benchmark_triage_tab(), "🛡️ CFReDS Doğrulama, Uzak Triyaj && STIX")
        main_layout.addWidget(self.tabs, 1)

        self.refresh_bookmarks()

    def set_case_context(self, case_id: int, operator_name: str = "") -> None:
        self._active_case_id = case_id
        if operator_name:
            self._active_user = operator_name
        self.refresh_bookmarks()

    # ------------------------------------------------------------------
    # TAB 1: Mobile (WhatsApp / SMS / iOS) & Cloud (M365 / OneDrive)
    # ------------------------------------------------------------------
    def _build_mobile_cloud_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(10)

        top = QHBoxLayout()
        btn_mob = QPushButton("📱 Mobil SQLite / Plist Aç (msgstore / mmssms / Manifest)")
        btn_mob.setObjectName("primaryBtn")
        btn_mob.clicked.connect(self._open_mobile_dialog)
        top.addWidget(btn_mob)

        btn_cloud = QPushButton("☁️ Bulut Audit / Sync Aç (M365 JSON/CSV, OneDrive)")
        btn_cloud.clicked.connect(self._open_cloud_dialog)
        top.addWidget(btn_cloud)

        btn_demo = QPushButton("🧪 Örnek Mobil && Bulut Paketi Yükle")
        btn_demo.clicked.connect(self.load_synthetic_bundle)
        top.addWidget(btn_demo)
        top.addStretch()
        lay.addLayout(top)

        self.mc_table = ForensicDataTable(
            ["Platform", "Kategori", "Aktör / Yön", "Karşı Taraf / Hedef", "İçerik", "Zaman (UTC)"],
            self,
        )
        lay.addWidget(self.mc_table, 1)
        return w

    def _open_mobile_dialog(self):
        fp, _ = QFileDialog.getOpenFileName(
            self, "Mobil Adli Artefakt Seç", "", "Mobil DB & Plist (*.db *.sqlite *.plist);;Tüm Dosyalar (*.*)"
        )
        if fp:
            self.load_mobile_file(fp)

    def _open_cloud_dialog(self):
        fp, _ = QFileDialog.getOpenFileName(
            self, "Bulut Denetim / Senkronizasyon Dosyası Seç", "", "Bulut Logları (*.json *.csv *.log *.txt);;Tüm Dosyalar (*.*)"
        )
        if fp:
            self.load_cloud_file(fp)

    def load_mobile_file(self, path: str, append: bool = False):
        if path.lower().endswith(".plist"):
            res = MobileCloudForensicsService.parse_ios_plist(path)
        else:
            res = MobileCloudForensicsService.parse_mobile_sqlite(path)
        rows = self._normalize_mc_rows(res["records"])
        if append:
            existing = list(getattr(self.mc_table, "_raw_records", []))
            self.mc_table.set_records(existing + rows)
        else:
            self.mc_table.set_records(rows)

    def load_cloud_file(self, path: str, append: bool = True):
        res = MobileCloudForensicsService.parse_cloud_audit_or_sync(path)
        rows = self._normalize_mc_rows(res["records"])
        if append:
            existing = list(getattr(self.mc_table, "_raw_records", []))
            self.mc_table.set_records(existing + rows)
        else:
            self.mc_table.set_records(rows)

    @staticmethod
    def _normalize_mc_rows(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [
            {
                "Platform": r.get("platform", "-"),
                "Kategori": r.get("category", "-"),
                "Aktör / Yön": r.get("actor", "-"),
                "Karşı Taraf / Hedef": r.get("peer", "-"),
                "İçerik": r.get("content", "-"),
                "Zaman (UTC)": r.get("timestamp") or "-",
            }
            for r in records
        ]

    def load_synthetic_bundle(self):
        out_dir = os.path.join("data", "sample_mobile_cloud")
        paths = create_synthetic_mobile_cloud_bundle(out_dir)
        self.load_mobile_file(paths["whatsapp_db"], append=False)
        self.load_mobile_file(paths["ios_plist"], append=True)
        self.load_cloud_file(paths["m365_audit"], append=True)

    # ------------------------------------------------------------------
    # TAB 2: SQLite FTS5 Full-Text Search & Analyst Bookmarks
    # ------------------------------------------------------------------
    def _build_fts_bookmark_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(10)

        # FTS5 Bar
        fts_bar = QHBoxLayout()
        self.fts_dir_input = QLineEdit("examples/suspect_pc_case")
        fts_bar.addWidget(self.fts_dir_input, 2)

        idx_btn = QPushButton("📚 Klasörü FTS5 İndeksle")
        idx_btn.clicked.connect(self._index_folder)
        fts_bar.addWidget(idx_btn)

        self.fts_query_input = QLineEdit()
        self.fts_query_input.setPlaceholderText("Tam metin ara (örn: rclone, exfil, invoice, powershell)...")
        self.fts_query_input.returnPressed.connect(self.run_fts_search)
        fts_bar.addWidget(self.fts_query_input, 2)

        search_btn = QPushButton("🔎 FTS5 Ara")
        search_btn.setObjectName("primaryBtn")
        search_btn.clicked.connect(self.run_fts_search)
        fts_bar.addWidget(search_btn)
        lay.addLayout(fts_bar)

        splitter = QSplitter(Qt.Vertical)
        splitter.setChildrenCollapsible(False)

        self.fts_table = ForensicDataTable(["Dosya", "Tür", "BM25 Skor", "Eşleşen Kesit (Snippet)", "Tam Yol"], self)
        splitter.addWidget(self.fts_table)

        # Bookmark Section
        bm_card = QFrame()
        bm_card.setObjectName("surfaceCard")
        bm_lay = QVBoxLayout(bm_card)
        bm_lay.setContentsMargins(10, 10, 10, 10)
        bm_lay.setSpacing(6)

        bm_form = QHBoxLayout()
        self.bm_tag = QComboBox()
        self.bm_tag.addItems(list(BookmarkService.VALID_TAGS))
        self.bm_tag.setFixedWidth(150)
        bm_form.addWidget(self.bm_tag)

        self.bm_label = QLineEdit()
        self.bm_label.setPlaceholderText("Etiketlenecek bulgu adı (örn: tatil_fatura_ek.jpg -> PE Exfil)...")
        bm_form.addWidget(self.bm_label, 2)

        self.bm_note = QLineEdit()
        self.bm_note.setPlaceholderText("Analist inceleme notu...")
        bm_form.addWidget(self.bm_note, 2)

        bm_add = QPushButton("🏷️ Bulguyu Etiketle (Rapora Ekle)")
        bm_add.setObjectName("primaryBtn")
        bm_add.clicked.connect(self._add_bookmark)
        bm_form.addWidget(bm_add)
        bm_lay.addLayout(bm_form)

        self.bm_table = ForensicDataTable(["Etiket", "Modül", "Bulgu", "Analist Notu", "Uzman", "Zaman"], self)
        bm_lay.addWidget(self.bm_table, 1)
        splitter.addWidget(bm_card)

        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 5)
        lay.addWidget(splitter, 1)
        return w

    def _index_folder(self):
        dp = self.fts_dir_input.text().strip()
        if not os.path.isdir(dp):
            dp = QFileDialog.getExistingDirectory(self, "FTS5 İndekslenecek Klasörü Seç")
            if not dp:
                return
            self.fts_dir_input.setText(dp)
        cnt = self.fts.index_directory(dp)
        self.status_badge.set_status(f"FTS5: {cnt} belge indekslendi", "verified")
        if self.fts_query_input.text().strip():
            self.run_fts_search()

    def index_and_search_demo(self, folder: str, query: str = "rclone"):
        if os.path.isdir(folder):
            self.fts_dir_input.setText(folder)
            self.fts.index_directory(folder)
            self.fts_query_input.setText(query)
            self.run_fts_search()

    def run_fts_search(self):
        q = self.fts_query_input.text().strip()
        if not q:
            return
        hits = self.fts.search(q)
        self.fts_table.set_records([
            {
                "Dosya": h["title"],
                "Tür": h["source_type"],
                "BM25 Skor": h["score"],
                "Eşleşen Kesit (Snippet)": h["snippet"],
                "Tam Yol": h["path"],
            }
            for h in hits
        ])

    def _add_bookmark(self):
        lbl = self.bm_label.text().strip()
        if not lbl:
            QMessageBox.warning(self, "Eksik Bilgi", "Etiketlenecek bulgu adını girin.")
            return
        self.bookmarks.add_bookmark(
            case_id=self._active_case_id,
            tag=self.bm_tag.currentText(),
            source_module="Analist İnceleme",
            item_label=lbl,
            analyst_note=self.bm_note.text().strip(),
            analyst_name=self._active_user,
        )
        self.bm_label.clear()
        self.bm_note.clear()
        self.refresh_bookmarks()

    def refresh_bookmarks(self):
        rows = [
            {
                "Etiket": b.tag,
                "Modül": b.source_module,
                "Bulgu": b.item_label,
                "Analist Notu": b.analyst_note or "-",
                "Uzman": b.analyst_name,
                "Zaman": b.created_at.strftime("%Y-%m-%d %H:%M") if b.created_at else "-",
            }
            for b in self.bookmarks.list_bookmarks(self._active_case_id)
        ]
        self.bm_table.set_records(rows)

    # ------------------------------------------------------------------
    # TAB 3: CFReDS Benchmark, Remote Triage PS1 & STIX 2.1 Bundle
    # ------------------------------------------------------------------
    def _build_benchmark_triage_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(10)

        row = QHBoxLayout()
        run_cf = QPushButton("🎯 CFReDS Referans Doğrulama Paketini Çalıştır")
        run_cf.setObjectName("primaryBtn")
        run_cf.clicked.connect(self.run_cfreds_benchmark)
        row.addWidget(run_cf)

        ps1_btn = QPushButton("📜 Uzak Triyaj Betiği Üret (.ps1)")
        ps1_btn.clicked.connect(self._export_remote_ps1)
        row.addWidget(ps1_btn)

        stix_btn = QPushButton("🕸️ STIX 2.1 IOC Paketi Dışa Aktar")
        stix_btn.clicked.connect(self._export_stix)
        row.addWidget(stix_btn)
        row.addStretch()
        lay.addLayout(row)

        self.cf_summary = QLabel("Hazır")
        self.cf_summary.setObjectName("mutedLabel")
        self.cf_summary.setWordWrap(True)
        lay.addWidget(self.cf_summary)

        self.cf_table = ForensicDataTable(["Modül", "Beklenen Kriter", "Gözlenen Sonuç", "Durum"], self)
        lay.addWidget(self.cf_table, 1)
        return w

    def run_cfreds_benchmark(self):
        res = BenchmarkService.run_cfreds_reference_suite()
        self.cf_summary.setText(
            f"{res['suite_name']}: {res['passed_checks']}/{res['total_checks']} Başarılı (Doğruluk: %{res['accuracy_pct']})"
        )
        self.cf_table.set_records([
            {
                "Modül": c["module"],
                "Beklenen Kriter": c["expected"],
                "Gözlenen Sonuç": c["observed"],
                "Durum": "Doğrulandı" if c["passed"] else "Uyuşmazlık",
            }
            for c in res["checks"]
        ])

    def _export_remote_ps1(self):
        fp, _ = QFileDialog.getSaveFileName(self, "Uzak Triyaj PowerShell Betiği Kaydet", "outputs/dfir_remote_triage.ps1", "PowerShell (*.ps1)")
        if not fp:
            return
        TriageCollector.export_remote_triage_script(fp)
        QMessageBox.information(self, "Betik Üretildi", f"Velociraptor/KAPE-tarzı salt-okunur toplama betiği kaydedildi:\n{fp}")

    def _export_stix(self):
        fp, _ = QFileDialog.getSaveFileName(self, "STIX 2.1 IOC Paketi Kaydet", "outputs/vak_stix2.json", "STIX JSON (*.json)")
        if not fp:
            return
        AnalysisOrchestrator(db_path=self.db_path).export_stix2_bundle(self._active_case_id, fp)
        QMessageBox.information(self, "STIX 2.1 Hazır", f"STIX 2.1 tehdit istihbaratı paketi kaydedildi:\n{fp}")
