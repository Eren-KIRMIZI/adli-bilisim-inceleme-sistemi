"""Memory Forensics Page: RAM dump header/PE/IOC inspection and live volatile process snapshot."""

import os
from typing import Dict, Any, List
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QSplitter, QTabWidget, QTextEdit, QFileDialog, QMessageBox
)
from PySide6.QtCore import Qt

from src.memory_engine.memory_service import MemoryForensicsEngine, create_synthetic_memory_dump
from src.ui.components.breadcrumb import Breadcrumb
from src.ui.components.search_field import ForensicSearchField
from src.ui.components.data_table import ForensicDataTable
from src.ui.components.hex_viewer import ForensicHexViewer
from src.ui.components.status_indicator import StatusBadge


class MemoryAnalysisPage(QWidget):
    """RAM image and live volatile process forensic analyzer."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.engine = MemoryForensicsEngine()
        self._pe_rows: List[Dict[str, Any]] = []
        self._ioc_rows: List[Dict[str, Any]] = []
        self._proc_rows: List[Dict[str, Any]] = []

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 18, 24, 18)
        main_layout.setSpacing(12)

        header_bar = QHBoxLayout()
        self.breadcrumb = Breadcrumb(["Adli Bilişim", "RAM Bellek Analizi (Memory Forensics)"])
        header_bar.addWidget(self.breadcrumb)
        header_bar.addStretch()
        self.format_badge = StatusBadge("RAM İmajı Bekleniyor", "neutral")
        header_bar.addWidget(self.format_badge)
        main_layout.addLayout(header_bar)

        # Toolbar
        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)
        self.search_field = ForensicSearchField("Süreç adı, PID, IP, URL veya PE offset ara...")
        self.search_field.searchChanged.connect(self._apply_filters)
        toolbar.addWidget(self.search_field, 2)

        open_btn = QPushButton("📁 RAM İmajı Aç (.dmp / .raw / .mem)")
        open_btn.setObjectName("primaryBtn")
        open_btn.clicked.connect(self._open_dump_dialog)
        toolbar.addWidget(open_btn)

        sample_btn = QPushButton("🧪 Sentetik Crash Dump İncele")
        sample_btn.clicked.connect(self._load_synthetic_dump)
        toolbar.addWidget(sample_btn)

        live_btn = QPushButton("⚡ Canlı Süreç Anlık Görüntüsü")
        live_btn.clicked.connect(self._capture_live_processes)
        toolbar.addWidget(live_btn)
        main_layout.addLayout(toolbar)

        # Warning / Honesty Banner
        info_frame = QFrame()
        info_frame.setObjectName("infoBanner")
        if_lay = QHBoxLayout(info_frame)
        if_lay.setContentsMargins(12, 8, 12, 8)
        self.warning_lbl = QLabel(
            "ℹ️ Adli Bütünlük İlkesi: Desteklenmeyen veya sembolsüz RAM formatlarında uydurma süreç ağacı üretilmez; "
            "yalnızca ham dökümde doğrulanabilen başlıklar, PE modülleri ve ağ/IOC kalıntıları raporlanır."
        )
        self.warning_lbl.setWordWrap(True)
        self.warning_lbl.setObjectName("infoBannerText")
        if_lay.addWidget(self.warning_lbl)
        main_layout.addWidget(info_frame)

        # Main Splitter
        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)

        self.tabs = QTabWidget()
        self.tbl_procs = ForensicDataTable(["PID", "PPID", "Süreç Adı", "Thread", "Öncelik"], self)
        self.tbl_pes = ForensicDataTable(["Offset", "Tür", "Mimari"], self)
        self.tbl_iocs = ForensicDataTable(["Tür", "Offset", "Değer"], self)

        self.tbl_pes.rowSelected.connect(self._on_pe_selected)
        self.tbl_iocs.rowSelected.connect(self._on_ioc_selected)
        self.tbl_procs.rowSelected.connect(self._on_proc_selected)

        self.tabs.addTab(self.tbl_procs, "⚙️ Canlı Süreçler (PID/PPID)")
        self.tabs.addTab(self.tbl_pes, "🧩 Bellek PE Modülleri (MZ/PE)")
        self.tabs.addTab(self.tbl_iocs, "🌐 Bellek Ağ & IOC Kalıntıları")
        splitter.addWidget(self.tabs)

        right = QFrame()
        right.setObjectName("surfaceCard")
        right.setFixedWidth(380)
        r_lay = QVBoxLayout(right)
        r_lay.setContentsMargins(10, 10, 10, 10)
        self.summary_view = QTextEdit()
        self.summary_view.setReadOnly(True)
        self.summary_view.setFixedHeight(190)
        self.summary_view.setStyleSheet("font-family: Consolas; font-size: 11px;")
        r_lay.addWidget(self.summary_view)
        self.hex_viewer = ForensicHexViewer(self)
        r_lay.addWidget(self.hex_viewer)
        splitter.addWidget(right)

        splitter.setStretchFactor(0, 6)
        splitter.setStretchFactor(1, 4)
        main_layout.addWidget(splitter, 1)

    def _open_dump_dialog(self):
        fp, _ = QFileDialog.getOpenFileName(self, "RAM Bellek İmajı Seç", "", "RAM İmajları (*.dmp *.raw *.mem *.bin *.vmem);;Tüm Dosyalar (*.*)")
        if fp:
            self.load_dump(fp)

    def _load_synthetic_dump(self):
        p = os.path.join("data", "sample_memory.dmp")
        create_synthetic_memory_dump(p)
        self.load_dump(p)

    def load_dump(self, path: str):
        try:
            res = self.engine.inspect_memory_dump(path)
            is_known = "Bilinmeyen" not in res["format"]
            self.format_badge.set_status(res["format"], "verified" if is_known else "warning")
            if res["warnings"]:
                self.warning_lbl.setText("⚠️ " + " ".join(res["warnings"]))

            self._pe_rows = [
                {"Offset": m["offset_hex"], "Tür": m["type"], "Mimari": m["arch"], "_preview": m["preview"]}
                for m in res["pe_modules"]
            ]
            self._ioc_rows = [
                {"Tür": i["kind"], "Offset": i["offset_hex"], "Değer": i["value"]}
                for i in res["iocs"]
            ]
            self._apply_filters()

            kdbg = ", ".join(res["kdbg_offsets"]) if res["kdbg_offsets"] else "Bulunamadı"
            self.summary_view.setPlainText(
                f"DOSYA:      {res['filename']}\n"
                f"BOYUT:      {res['size_bytes']:,} bayt\n"
                f"FORMAT:     {res['format']}\n"
                f"MİMARİ:     {res['architecture']}\n"
                f"KDBG İZİ:   {kdbg}\n"
                f"PE MODÜLÜ:  {len(self._pe_rows)} adet\n"
                f"IOC İZİ:    {len(self._ioc_rows)} adet\n"
            )
            self.hex_viewer.load_bytes(res["header_bytes"])
            self.tabs.setCurrentIndex(1)
        except Exception as e:
            QMessageBox.critical(self, "Bellek Analiz Hatası", str(e))

    def _capture_live_processes(self):
        res = self.engine.capture_live_windows_processes()
        if not res.get("supported"):
            QMessageBox.information(self, "Platform Bilgisi", res.get("reason", "Desteklenmiyor."))
            return
        self._proc_rows = [
            {
                "PID": p["pid"],
                "PPID": p["ppid"],
                "Süreç Adı": p["name"],
                "Thread": p["threads"],
                "Öncelik": p["priority"],
            }
            for p in res["processes"]
        ]
        self.format_badge.set_status(f"Canlı Sistem ({len(self._proc_rows)} Süreç)", "verified")
        self._apply_filters()
        self.tabs.setCurrentIndex(0)

    def _apply_filters(self):
        q = self.search_field.text().lower()

        def filt(rows):
            if not q:
                return rows
            return [r for r in rows if any(q in str(v).lower() for k, v in r.items() if not k.startswith("_"))]

        self.tbl_procs.set_records(filt(self._proc_rows))
        self.tbl_pes.set_records(filt(self._pe_rows))
        self.tbl_iocs.set_records(filt(self._ioc_rows))

    def _on_pe_selected(self, row: Dict[str, Any]):
        self.summary_view.setPlainText(f"PE MODÜLÜ\nOffset: {row['Offset']}\nMimari: {row['Mimari']}\nTür:    {row['Tür']}")
        self.hex_viewer.load_bytes(row.get("_preview", b""))

    def _on_ioc_selected(self, row: Dict[str, Any]):
        self.summary_view.setPlainText(f"BELLEK IOC BULGUSU\nTür:    {row['Tür']}\nOffset: {row['Offset']}\nDeğer:  {row['Değer']}")

    def _on_proc_selected(self, row: Dict[str, Any]):
        self.summary_view.setPlainText(
            f"CANLI SÜREÇ ANLIK GÖRÜNTÜSÜ\n"
            f"Süreç:  {row['Süreç Adı']}\n"
            f"PID:    {row['PID']}\n"
            f"PPID:   {row['PPID']}\n"
            f"Thread: {row['Thread']}"
        )
