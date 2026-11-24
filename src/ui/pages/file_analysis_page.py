"""File Analysis Page: Signature & Spoofing Check, EXIF Metadata, Hex View, Diff & Duplicates."""

import os
from typing import Dict, Any, List
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QTabWidget, QTextEdit, QLineEdit, QSplitter, QFileDialog, QMessageBox
)
from PySide6.QtCore import Qt

from src.file_engine.file_service import FileAnalysisService, create_synthetic_exif_jpeg
from src.file_engine.threat_scanner import YaraStyleScanner, HashSetService
from src.ui.components.breadcrumb import Breadcrumb
from src.ui.components.data_table import ForensicDataTable
from src.ui.components.hex_viewer import ForensicHexViewer
from src.ui.components.status_indicator import StatusBadge


class FileAnalysisPage(QWidget):
    """Comprehensive File Forensic Analysis workbench."""

    def __init__(self, parent=None, hashset_db_path: str = "data/hashsets.db"):
        super().__init__(parent)
        self.yara_scanner = YaraStyleScanner()
        self.hashset_service = HashSetService(db_path=hashset_db_path)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 18, 24, 18)
        main_layout.setSpacing(12)

        header_bar = QHBoxLayout()
        self.breadcrumb = Breadcrumb(["Adli Bilişim", "Dosya & Hex İnceleme"])
        header_bar.addWidget(self.breadcrumb)
        header_bar.addStretch()
        self.sig_badge = StatusBadge("Hazır", "neutral")
        header_bar.addWidget(self.sig_badge)
        main_layout.addLayout(header_bar)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_single_tab(), "🔍 Tekil Dosya & EXIF / İmza")
        self.tabs.addTab(self._build_diff_tab(), "⚖️ Dosya Karşılaştırma (Diff)")
        self.tabs.addTab(self._build_dup_tab(), "📂 Yinelenen Dosya & Uzantı Taraması")
        main_layout.addWidget(self.tabs, 1)

    def _build_single_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(10)

        row = QHBoxLayout()
        self.single_path = QLineEdit()
        self.single_path.setPlaceholderText("İncelenecek dosya yolunu seçin...")
        row.addWidget(self.single_path, 1)

        pick_btn = QPushButton("📁 Dosya Seç")
        pick_btn.clicked.connect(self._pick_single)
        row.addWidget(pick_btn)

        run_btn = QPushButton("⚡ Analiz Et")
        run_btn.setObjectName("primaryBtn")
        run_btn.clicked.connect(lambda: self.analyze_file(self.single_path.text()))
        row.addWidget(run_btn)

        sample_btn = QPushButton("🧪 Örnek EXIF JPEG İncele")
        sample_btn.clicked.connect(self._load_sample_exif)
        row.addWidget(sample_btn)
        lay.addLayout(row)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)

        left = QFrame()
        left.setObjectName("surfaceCard")
        l_lay = QVBoxLayout(left)
        l_lay.setContentsMargins(12, 12, 12, 12)
        l_lay.addWidget(QLabel("Dosya Kimliği, Hash, Entropi & EXIF Metadata"))
        self.meta_view = QTextEdit()
        self.meta_view.setReadOnly(True)
        self.meta_view.setStyleSheet("font-family: Consolas; font-size: 11px;")
        l_lay.addWidget(self.meta_view)
        splitter.addWidget(left)

        right = QFrame()
        right.setObjectName("surfaceCard")
        r_lay = QVBoxLayout(right)
        r_lay.setContentsMargins(12, 12, 12, 12)
        self.hex_viewer = ForensicHexViewer(self)
        r_lay.addWidget(self.hex_viewer)
        splitter.addWidget(right)

        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 6)
        lay.addWidget(splitter, 1)
        return w

    def _build_diff_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(10)

        r1 = QHBoxLayout()
        self.path_a = QLineEdit()
        self.path_a.setPlaceholderText("Dosya A (Referans)...")
        r1.addWidget(self.path_a, 1)
        b1 = QPushButton("Dosya A Seç")
        b1.clicked.connect(lambda: self._pick_into(self.path_a))
        r1.addWidget(b1)
        lay.addLayout(r1)

        r2 = QHBoxLayout()
        self.path_b = QLineEdit()
        self.path_b.setPlaceholderText("Dosya B (Karşılaştırılacak)...")
        r2.addWidget(self.path_b, 1)
        b2 = QPushButton("Dosya B Seç")
        b2.clicked.connect(lambda: self._pick_into(self.path_b))
        r2.addWidget(b2)

        cmp_btn = QPushButton("⚖️ Karşılaştır")
        cmp_btn.setObjectName("primaryBtn")
        cmp_btn.clicked.connect(self._run_compare)
        r2.addWidget(cmp_btn)
        lay.addLayout(r2)

        self.diff_out = QTextEdit()
        self.diff_out.setReadOnly(True)
        self.diff_out.setStyleSheet("font-family: Consolas; font-size: 12px;")
        lay.addWidget(self.diff_out, 1)
        return w

    def _build_dup_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(10)

        row = QHBoxLayout()
        self.dir_input = QLineEdit()
        self.dir_input.setPlaceholderText("Yinelenen dosya ve imza uyumsuzluğu taranacak klasör...")
        row.addWidget(self.dir_input, 1)
        pick_d = QPushButton("📁 Klasör Seç")
        pick_d.clicked.connect(self._pick_dir)
        row.addWidget(pick_d)

        scan_d = QPushButton("🔎 Klasörü Tara")
        scan_d.setObjectName("primaryBtn")
        scan_d.clicked.connect(lambda: self.scan_folder(self.dir_input.text()))
        row.addWidget(scan_d)
        lay.addLayout(row)

        self.dup_summary = QLabel("Durum: Bekleniyor")
        self.dup_summary.setObjectName("mutedLabel")
        lay.addWidget(self.dup_summary)

        self.dup_table = ForensicDataTable(
            ["Durum", "Dosya Adı", "Boyut", "İmza", "SHA-256", "Tam Yol"],
            self
        )
        lay.addWidget(self.dup_table, 1)
        return w

    def _pick_single(self):
        fp, _ = QFileDialog.getOpenFileName(self, "Analiz Edilecek Dosya")
        if fp:
            self.single_path.setText(fp)
            self.analyze_file(fp)

    def _pick_into(self, target: QLineEdit):
        fp, _ = QFileDialog.getOpenFileName(self, "Dosya Seç")
        if fp:
            target.setText(fp)

    def _pick_dir(self):
        dp = QFileDialog.getExistingDirectory(self, "Klasör Seç")
        if dp:
            self.dir_input.setText(dp)
            self.scan_folder(dp)

    def _load_sample_exif(self):
        p = os.path.join("data", "sample_exif_evidence.jpg")
        create_synthetic_exif_jpeg(p)
        self.single_path.setText(p)
        self.analyze_file(p)

    def analyze_file(self, path: str):
        path = path.strip()
        if not path or not os.path.isfile(path):
            QMessageBox.warning(self, "Dosya Bulunamadı", "Lütfen geçerli bir dosya yolu seçin.")
            return
        res = FileAnalysisService.analyze(path)
        yara_hits = self.yara_scanner.scan_file(path)
        hs_hit = self.hashset_service.lookup(res["sha256"])

        if yara_hits or (hs_hit and hs_hit["category"] == "known_bad"):
            self.sig_badge.set_status("⚠️ YARA / Kötücül Hash Uyarısı!", "critical")
        elif res["extension_mismatch"]:
            self.sig_badge.set_status("⚠️ Uzantı/İmza Uyuşmazlığı!", "critical")
        else:
            self.sig_badge.set_status(f"İmza: {res['signature_type']}", "verified")

        if hs_hit:
            hs_text = f"EŞLEŞTİ [{hs_hit['category']}] — {hs_hit['label']} ({hs_hit['source']})"
        else:
            hs_text = "Yerel NSRL / IOC hash setinde eşleşme yok."

        if yara_hits:
            yara_lines = "\n".join(
                f"  • [{h['severity']}] {h['rule']} @ {h['offset_hex']}: {h['match_preview']}"
                for h in yara_hits
            )
        else:
            yara_lines = "  Temiz (Yerleşik YARA-stili kurallarla eşleşme yok)"

        exif_lines = "\n".join(f"  {k}: {v}" for k, v in res["exif"].items()) if res["exif"] else "  (EXIF verisi yok)"
        txt = (
            f"DOSYA ADI:     {res['name']}\n"
            f"TAM YOL:       {res['path']}\n"
            f"BOYUT:         {res['size']:,} bayt\n"
            f"UZANTI / MIME: {res['extension']} | {res['mime']}\n"
            f"DOSYA İMZASI:  {res['signature_type']} (Kesinlik: {res['signature_confidence']})\n"
            f"UZANTI RİSKİ:  {'UYUŞMAZLIK TESPİT EDİLDİ' if res['extension_mismatch'] else 'Tutarlı'}\n"
            f"ENTROPİ:       {res['entropy']} bit/bayt ({res['entropy_note']})\n\n"
            f"HASH SET (NSRL / IOC):\n  {hs_text}\n\n"
            f"YARA-STİLİ KURAL TARAMASI:\n{yara_lines}\n\n"
            f"ZAMAN DAMGALARI (UTC):\n"
            f"  Oluşturulma:  {res['created_utc']}\n"
            f"  Değiştirilme: {res['modified_utc']}\n"
            f"  Erişim:       {res['accessed_utc']}\n\n"
            f"KRİPTOGRAFİK ÖZETLER:\n"
            f"  SHA-256: {res['sha256']}\n"
            f"  SHA-512: {res['sha512']}\n"
            f"  MD5:     {res['md5']}\n\n"
            f"EXIF METADATA:\n{exif_lines}\n"
        )
        self.meta_view.setPlainText(txt)
        self.hex_viewer.load_bytes(res["preview_bytes"])

    def _run_compare(self):
        pa, pb = self.path_a.text().strip(), self.path_b.text().strip()
        if not os.path.isfile(pa) or not os.path.isfile(pb):
            QMessageBox.warning(self, "Eksik Dosya", "Her iki dosya yolunun da geçerli olması gerekir.")
            return
        res = FileAnalysisService.compare_files(pa, pb)
        fa, fb = res["file_a"], res["file_b"]
        diff_hex = f"0x{res['first_diff_offset']:08X} ({res['first_diff_offset']} bayt)" if res["first_diff_offset"] is not None else "Yok (Birebir Aynı)"
        self.diff_out.setPlainText(
            f"KARŞILAŞTIRMA SONUCU: {'BİREBİR EŞLEŞME (ÖZDEŞ)' if res['identical'] else 'FARKLI DOSYALAR'}\n"
            f"İlk Farklı Bayt Offseti: {diff_hex}\n"
            f"Boyut Farkı:             {res['size_diff']:+,} bayt\n\n"
            f"--- DOSYA A ---\nAd: {fa['name']} | Boyut: {fa['size']:,} B | İmza: {fa['signature_type']}\nSHA-256: {fa['sha256']}\n\n"
            f"--- DOSYA B ---\nAd: {fb['name']} | Boyut: {fb['size']:,} B | İmza: {fb['signature_type']}\nSHA-256: {fb['sha256']}\n"
        )

    def scan_folder(self, folder: str):
        folder = folder.strip()
        if not os.path.isdir(folder):
            QMessageBox.warning(self, "Klasör Bulunamadı", "Lütfen geçerli bir klasör seçin.")
            return
        res = FileAnalysisService.scan_directory_duplicates(folder)
        self.dup_summary.setText(
            f"Taranan: {res['total_scanned']} dosya | Yinelenen Hash Grubu: {res['duplicate_groups']}"
        )
        rows = []
        for r in res["records"]:
            if r["mismatch"]:
                st = "Kritik (Uzantı Sahte)"
            elif r["is_duplicate"]:
                st = "Uyarı (Yinelenen)"
            else:
                st = "Normal"
            rows.append({
                "Durum": st,
                "Dosya Adı": r["name"],
                "Boyut": f"{r['size']:,} B",
                "İmza": r["signature"],
                "SHA-256": r["sha256"],
                "Tam Yol": r["path"],
            })
        self.dup_table.set_records(rows)
