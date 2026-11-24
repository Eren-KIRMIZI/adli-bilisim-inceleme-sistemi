"""Disk Forensics Page with 3-column Explorer layout (Tree | File List | Metadata) + bottom Hex Viewer."""

import os
from typing import Dict, Any, List, Optional
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QComboBox, QSplitter, QTreeWidget, QTreeWidgetItem, QTextEdit,
    QFileDialog, QMessageBox
)
from PySide6.QtCore import Qt

from src.ntfs_engine.ntfs_service import DiskForensicsEngine, create_synthetic_ntfs_image
from src.ui.components.breadcrumb import Breadcrumb
from src.ui.components.search_field import ForensicSearchField
from src.ui.components.data_table import ForensicDataTable
from src.ui.components.hex_viewer import ForensicHexViewer
from src.ui.components.status_indicator import StatusBadge


class DiskForensicsPage(QWidget):
    """3-column Disk, Partition (MBR/GPT), NTFS/MFT & File Carving workbench."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.engine = DiskForensicsEngine()
        self._current_image_path: Optional[str] = None
        self._inspection: Dict[str, Any] = {}
        self._all_file_rows: List[Dict[str, Any]] = []
        self._carved_rows: List[Dict[str, Any]] = []
        self._view_mode = "mft"  # "mft" or "carving"

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 18, 24, 18)
        main_layout.setSpacing(12)

        # 1. Breadcrumb & Format Badge
        header_bar = QHBoxLayout()
        self.breadcrumb = Breadcrumb(["Adli Bilişim", "Disk Forensics", "Bölüm & Dosya Sistemi"])
        header_bar.addWidget(self.breadcrumb)
        header_bar.addStretch()

        self.format_badge = StatusBadge("İmaj Yüklenmedi", "neutral")
        header_bar.addWidget(self.format_badge)
        self.records_badge = StatusBadge("0 Kayıt", "info")
        header_bar.addWidget(self.records_badge)
        main_layout.addLayout(header_bar)

        # 2. Toolbar
        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)

        self.search_field = ForensicSearchField("Dosya adı, MFT #, imza veya offset ara...")
        self.search_field.searchChanged.connect(self._apply_filters)
        toolbar.addWidget(self.search_field, 2)

        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["Tüm Dosyalar", "Yalnızca Aktif", "Silinmiş Kayıtlar (Unallocated)"])
        self.filter_combo.setFixedWidth(210)
        self.filter_combo.currentIndexChanged.connect(self._apply_filters)
        toolbar.addWidget(self.filter_combo)

        open_btn = QPushButton("📁 İmaj / $MFT Aç")
        open_btn.setObjectName("primaryBtn")
        open_btn.clicked.connect(self._open_image_dialog)
        toolbar.addWidget(open_btn)

        sample_btn = QPushButton("🧪 Sentetik NTFS İmajı İncele")
        sample_btn.clicked.connect(self._load_synthetic_image)
        toolbar.addWidget(sample_btn)

        carve_btn = QPushButton("🔎 File Carving Tara")
        carve_btn.clicked.connect(self._run_carving)
        toolbar.addWidget(carve_btn)

        main_layout.addLayout(toolbar)

        # 3. Vertical Splitter: Top 3-column workspace + Bottom Hex Viewer
        v_splitter = QSplitter(Qt.Vertical)
        v_splitter.setChildrenCollapsible(False)

        h_splitter = QSplitter(Qt.Horizontal)
        h_splitter.setChildrenCollapsible(False)

        # Column 1: Disk & Partition Tree
        tree_card = QFrame()
        tree_card.setObjectName("surfaceCard")
        tree_card.setMinimumWidth(220)
        tree_lay = QVBoxLayout(tree_card)
        tree_lay.setContentsMargins(10, 10, 10, 10)
        tree_lay.setSpacing(6)
        tree_lbl = QLabel("Disk ve Bölüm Ağacı")
        tree_lbl.setObjectName("sectionTitle")
        tree_lay.addWidget(tree_lbl)

        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.itemClicked.connect(self._on_tree_item_clicked)
        tree_lay.addWidget(self.tree)
        h_splitter.addWidget(tree_card)

        # Column 2: File & MFT / Carving List
        table_card = QFrame()
        table_card.setObjectName("surfaceCard")
        tbl_lay = QVBoxLayout(table_card)
        tbl_lay.setContentsMargins(10, 10, 10, 10)
        tbl_lay.setSpacing(6)

        self.table_title = QLabel("Dosya Sistemi & MFT Kayıtları")
        self.table_title.setObjectName("sectionTitle")
        tbl_lay.addWidget(self.table_title)

        self.mft_headers = [
            "Durum", "Dosya Adı", "MFT #", "Boyut", "İmza / Tür",
            "Oluşturulma (UTC)", "Değiştirilme (UTC)"
        ]
        self.table = ForensicDataTable(self.mft_headers, self)
        self.table.rowSelected.connect(self._on_row_selected)
        tbl_lay.addWidget(self.table)
        h_splitter.addWidget(table_card)

        # Column 3: Metadata Panel
        meta_card = QFrame()
        meta_card.setObjectName("surfaceCard")
        meta_card.setMinimumWidth(280)
        meta_lay = QVBoxLayout(meta_card)
        meta_card.setContentsMargins(0, 0, 0, 0)
        meta_lay.setContentsMargins(10, 10, 10, 10)
        meta_lay.setSpacing(6)

        meta_lbl = QLabel("Seçili Öğe Metadata & Zamanlar")
        meta_lbl.setObjectName("sectionTitle")
        meta_lay.addWidget(meta_lbl)

        self.meta_text = QTextEdit()
        self.meta_text.setReadOnly(True)
        self.meta_text.setStyleSheet("font-family: Consolas; font-size: 11px;")
        meta_lay.addWidget(self.meta_text)
        h_splitter.addWidget(meta_card)

        h_splitter.setStretchFactor(0, 2)
        h_splitter.setStretchFactor(1, 5)
        h_splitter.setStretchFactor(2, 3)
        v_splitter.addWidget(h_splitter)

        # Bottom Hex Viewer Area
        hex_card = QFrame()
        hex_card.setObjectName("surfaceCard")
        hex_lay = QVBoxLayout(hex_card)
        hex_lay.setContentsMargins(10, 8, 10, 8)
        hex_lay.setSpacing(4)

        self.hex_viewer = ForensicHexViewer(self)
        hex_lay.addWidget(self.hex_viewer)
        v_splitter.addWidget(hex_card)

        v_splitter.setStretchFactor(0, 6)
        v_splitter.setStretchFactor(1, 4)
        main_layout.addWidget(v_splitter, 1)

        # Auto-load synthetic image if present or on demand
        sample_path = os.path.join("data", "sample_ntfs_disk.dd")
        if os.path.isfile(sample_path):
            self.load_image(sample_path)

    def _open_image_dialog(self):
        fp, _ = QFileDialog.getOpenFileName(
            self,
            "Disk İmajı veya $MFT Dosyası Seç (Salt Okunur)",
            "",
            "Adli İmajlar (*.dd *.raw *.img *.e01 $MFT);;Tüm Dosyalar (*.*)",
        )
        if fp:
            self.load_image(fp)

    def _load_synthetic_image(self):
        sample_path = os.path.join("data", "sample_ntfs_disk.dd")
        create_synthetic_ntfs_image(sample_path)
        self.load_image(sample_path)

    def load_image(self, path: str):
        try:
            self._current_image_path = path
            self._inspection = self.engine.inspect_image(path)
            self._view_mode = "mft"
            self._carved_rows = []
            self._populate_tree_and_table()
        except Exception as e:
            QMessageBox.critical(self, "Disk Analiz Hatası", str(e))

    def _populate_tree_and_table(self):
        self.tree.clear()
        ins = self._inspection
        fmt = ins.get("format", "RAW")
        self.format_badge.set_status(fmt, "warning" if ins.get("warnings") else "verified")

        root = QTreeWidgetItem(self.tree, [f"💽 {ins.get('image_name', 'Disk')} ({ins.get('image_size', 0):,} B)"])
        root.setData(0, Qt.UserRole, {"kind": "image"})

        parts = ins.get("partitions", [])
        for p in parts:
            label = f"📦 Bölüm {p['index']}: {p.get('filesystem', p.get('type_name'))} (LBA {p['start_lba']})"
            p_item = QTreeWidgetItem(root, [label])
            p_item.setData(0, Qt.UserRole, {"kind": "partition", "partition": p})

            all_node = QTreeWidgetItem(p_item, ["📂 Tüm Dosya Kayıtları ($MFT)"])
            all_node.setData(0, Qt.UserRole, {"kind": "filter", "mode": "all", "part": p["index"]})

            del_node = QTreeWidgetItem(p_item, ["🗑️ Silinmiş Dosya Kayıtları"])
            del_node.setData(0, Qt.UserRole, {"kind": "filter", "mode": "deleted", "part": p["index"]})

        carve_node = QTreeWidgetItem(root, ["🧩 File Carving (Ham İmza Taraması)"])
        carve_node.setData(0, Qt.UserRole, {"kind": "carving"})
        self.tree.expandAll()

        # Build MFT row records
        self._all_file_rows = []
        for rec in ins.get("mft_records", []):
            status_str = "Şüpheli / Silinmiş" if rec["is_deleted"] else "Normal (Aktif)"
            self._all_file_rows.append({
                "Durum": status_str,
                "Dosya Adı": rec["filename"],
                "MFT #": rec["record_index"],
                "Boyut": f"{rec['size']:,} B",
                "İmza / Tür": rec["signature_type"],
                "Oluşturulma (UTC)": rec["created"].strftime("%Y-%m-%d %H:%M:%S") if rec["created"] else "-",
                "Değiştirilme (UTC)": rec["modified"].strftime("%Y-%m-%d %H:%M:%S") if rec["modified"] else "-",
                "_raw": rec,
            })

        self.records_badge.set_status(f"{len(self._all_file_rows)} MFT Kaydı", "info")
        self._apply_filters()

        if ins.get("header_bytes"):
            self.hex_viewer.load_bytes(ins["header_bytes"], base_offset=0)
        if ins.get("warnings"):
            self.meta_text.setPlainText("UYARILAR:\n" + "\n".join(f"- {w}" for w in ins["warnings"]))
        elif self._all_file_rows:
            self._on_row_selected(self._all_file_rows[0])

    def _apply_filters(self):
        if self._view_mode == "carving":
            rows = list(self._carved_rows)
        else:
            rows = list(self._all_file_rows)
            flt = self.filter_combo.currentText()
            if flt == "Yalnızca Aktif":
                rows = [r for r in rows if not r["_raw"]["is_deleted"]]
            elif "Silinmiş" in flt:
                rows = [r for r in rows if r["_raw"]["is_deleted"]]

        q = self.search_field.text().lower()
        if q:
            rows = [r for r in rows if any(q in str(v).lower() for k, v in r.items() if k != "_raw")]

        self.table.set_records(rows)

    def _on_tree_item_clicked(self, item: QTreeWidgetItem, col: int):
        meta = item.data(0, Qt.UserRole) or {}
        kind = meta.get("kind")
        if kind == "image":
            self._view_mode = "mft"
            self.filter_combo.setCurrentIndex(0)
            self._apply_filters()
            if self._inspection.get("header_bytes"):
                self.hex_viewer.load_bytes(self._inspection["header_bytes"], 0)
        elif kind == "partition":
            p = meta["partition"]
            vbr = p.get("vbr_info", {})
            txt = (
                f"BÖLÜM BİLGİSİ ({p.get('scheme')})\n"
                f"Tür:             {p.get('type_name')}\n"
                f"Dosya Sistemi:   {p.get('filesystem')}\n"
                f"Başlangıç LBA:   {p.get('start_lba')}\n"
                f"Offset:          0x{p.get('start_offset', 0):X}\n"
                f"Sektör Sayısı:   {p.get('sector_count')}\n"
                f"Boyut:           {p.get('size_bytes', 0):,} B\n"
            )
            if vbr:
                txt += (
                    f"\nNTFS VBR ($Boot):\n"
                    f"Seri No:         {vbr.get('volume_serial', '-')}\n"
                    f"Cluster Boyutu:  {vbr.get('bytes_per_cluster', '-')} B\n"
                    f"$MFT Cluster:    {vbr.get('mft_cluster', '-')}\n"
                    f"$MFT Offset:     0x{vbr.get('mft_offset', 0):X}\n"
                    f"MFT Kayıt Boyutu:{vbr.get('mft_record_size', '-')} B\n"
                )
            self.meta_text.setPlainText(txt)
            if self._current_image_path and os.path.isfile(self._current_image_path):
                with open(self._current_image_path, "rb") as f:
                    f.seek(p.get("start_offset", 0))
                    self.hex_viewer.load_bytes(f.read(512), base_offset=p.get("start_offset", 0))
        elif kind == "filter":
            self._view_mode = "mft"
            self.table_title.setText("Dosya Sistemi & MFT Kayıtları")
            self.filter_combo.setCurrentIndex(2 if meta.get("mode") == "deleted" else 0)
            self._apply_filters()
        elif kind == "carving":
            self._run_carving()

    def _run_carving(self):
        if not self._current_image_path or not os.path.isfile(self._current_image_path):
            QMessageBox.information(self, "İmaj Gerekli", "Önce bir disk imajı açın veya sentetik NTFS imajını yükleyin.")
            return
        carved = self.engine.carve_signatures(self._current_image_path)
        self._carved_rows = []
        for idx, c in enumerate(carved, 1):
            self._carved_rows.append({
                "Durum": "Doğrulandı" if c["confidence"] == "Yüksek" else "İnceleniyor",
                "Dosya Adı": f"carved_{idx:03d} ({c['type']})",
                "MFT #": c["offset_hex"],
                "Boyut": f"{c['estimated_size']:,} B",
                "İmza / Tür": f"{c['type']} ({c['confidence']})",
                "Oluşturulma (UTC)": "-",
                "Değiştirilme (UTC)": "-",
                "_carved": c,
            })
        self._view_mode = "carving"
        self.table_title.setText(f"File Carving Sonuçları ({len(self._carved_rows)} İmza)")
        self.records_badge.set_status(f"{len(self._carved_rows)} Carved", "verified")
        self._apply_filters()
        if self._carved_rows:
            self._on_row_selected(self._carved_rows[0])

    def _on_row_selected(self, row: Dict[str, Any]):
        if "_carved" in row:
            c = row["_carved"]
            txt = (
                f"FILE CARVING BULGUSU\n"
                f"Tür:           {c['type']} ({c['mime']})\n"
                f"Başlangıç:     {c['offset_hex']} ({c['offset']} bayt)\n"
                f"Tahmini Boyut: {c['estimated_size']:,} B\n"
                f"Kesinlik:      {c['confidence']}\n"
                f"Yöntem:        {c['method']}\n"
                f"SHA-256:       {c['sha256_head']}\n"
            )
            self.meta_text.setPlainText(txt)
            self.hex_viewer.load_bytes(c["preview_bytes"], base_offset=c["offset"])
            return

        rec = row.get("_raw")
        if not rec:
            return
        created = rec["created"].strftime("%Y-%m-%d %H:%M:%S UTC") if rec["created"] else "Eksik"
        modified = rec["modified"].strftime("%Y-%m-%d %H:%M:%S UTC") if rec["modified"] else "Eksik"
        mft_mod = rec["mft_modified"].strftime("%Y-%m-%d %H:%M:%S UTC") if rec["mft_modified"] else "Eksik"
        accessed = rec["accessed"].strftime("%Y-%m-%d %H:%M:%S UTC") if rec["accessed"] else "Eksik"

        txt = (
            f"MFT KAYIT DETAYI\n"
            f"Dosya Adı:       {rec['filename']}\n"
            f"MFT Kayıt No:    {rec['record_index']} (Offset 0x{rec['image_offset']:X})\n"
            f"Durum:           {'SİLİNMİŞ (Unallocated)' if rec['is_deleted'] else 'Aktif (In-Use)'}\n"
            f"Tip:             {'Dizin' if rec['is_dir'] else 'Dosya'}\n"
            f"Ebeveyn MFT Ref: {rec['parent_mft_ref']}\n"
            f"USA Fixup:       {'Geçerli' if rec['fixup_ok'] else 'Uyarı (Bozuk)'}\n"
            f"Boyut:           {rec['size']:,} bayt ({'Resident' if rec['is_resident'] else 'Non-Resident'})\n"
            f"İmza Analizi:    {rec['signature_type']} (Kesinlik: {rec['signature_confidence']})\n"
            f"Öznitelikler:    {', '.join(rec['attributes'])}\n\n"
            f"MACB ZAMAN DAMGALARI ($STANDARD_INFORMATION):\n"
            f"Oluşturulma (C): {created}\n"
            f"Değiştirilme(M): {modified}\n"
            f"MFT Değişim (B): {mft_mod}\n"
            f"Erişim (A):      {accessed}\n\n"
            f"SHA-256 ($DATA): {rec['sha256']}\n"
        )
        self.meta_text.setPlainText(txt)
        preview = rec["resident_data"] if rec["resident_data"] else rec["raw_bytes"]
        self.hex_viewer.load_bytes(preview, base_offset=rec["image_offset"])
