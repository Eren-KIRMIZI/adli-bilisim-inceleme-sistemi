"""Forensic Data Table with smart column sizing, filtering, badges, sorting, and context actions."""

import csv
from typing import List, Dict, Any, Optional
from PySide6.QtWidgets import (
    QTableWidget, QTableWidgetItem, QHeaderView, QMenu,
    QApplication, QFileDialog, QMessageBox, QWidget, QHBoxLayout, QAbstractItemView
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QAction
from src.ui.components.status_indicator import StatusBadge


class ForensicDataTable(QTableWidget):
    """High performance, forensic-standard data table widget."""
    rowSelected = Signal(dict)
    rowDoubleClicked = Signal(dict)

    def __init__(self, headers: List[str], parent=None):
        super().__init__(0, len(headers), parent)
        self.headers = headers
        self.setHorizontalHeaderLabels(headers)
        self._raw_records: List[Dict[str, Any]] = []
        self._visible_records: List[Dict[str, Any]] = []

        # Appearance & Behavior
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setSelectionMode(QTableWidget.SingleSelection)
        self.setShowGrid(True)
        self.setWordWrap(False)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(40)
        self.setSortingEnabled(True)

        header = self.horizontalHeader()
        header.setStretchLastSection(True)
        header.setHighlightSections(False)
        header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        header.setMinimumSectionSize(72)

        # Context Menu
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_context_menu)
        self.itemSelectionChanged.connect(self._on_selection_changed)
        self.cellDoubleClicked.connect(self._on_double_click)

    def set_records(self, records: List[Dict[str, Any]]):
        """Populate the table with records. Each record dict maps header name to value."""
        self.setSortingEnabled(False)
        self._raw_records = records
        self._visible_records = list(records)
        self._render_rows(self._visible_records)
        self._autosize_columns()
        self.setSortingEnabled(True)

    def _render_rows(self, records: List[Dict[str, Any]]):
        self.setRowCount(len(records))
        mono_font = QFont("Consolas", 10)

        for row_idx, rec in enumerate(records):
            for col_idx, col_name in enumerate(self.headers):
                val = rec.get(col_name, "")

                if col_name.lower() in ("durum", "status", "bütünlük", "doğrulama"):
                    variant = "neutral"
                    sval = str(val).lower()
                    if any(k in sval for k in ["doğrulandı", "normal", "verified", "ok"]):
                        variant = "verified"
                    elif any(k in sval for k in ["şüpheli", "warning", "uyarı", "anomali", "silinmiş", "yinelenen"]):
                        variant = "warning"
                    elif any(k in sval for k in ["kritik", "bozuk", "critical", "zararlı", "uyuşmazlık", "sahte"]):
                        variant = "critical"
                    elif any(k in sval for k in ["inceleniyor", "bilgi", "info"]):
                        variant = "info"

                    badge = StatusBadge(str(val), variant)
                    container = QWidget()
                    container.setStyleSheet("background: transparent;")
                    lay = QHBoxLayout(container)
                    lay.setContentsMargins(6, 4, 6, 4)
                    lay.addWidget(badge)
                    lay.addStretch()
                    self.setCellWidget(row_idx, col_idx, container)

                    item = QTableWidgetItem(str(val))
                    item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                    # Keep underlying text hidden behind badge widget cleanly
                    item.setData(Qt.DisplayRole, "")
                    self.setItem(row_idx, col_idx, item)
                else:
                    text = str(val) if val is not None else "-"
                    item = QTableWidgetItem(text)
                    item.setToolTip(text)
                    if any(k in col_name.lower() for k in ["vid", "pid", "seri", "hash", "zaman", "guid", "tarih", "offset"]):
                        item.setFont(mono_font)
                    item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                    self.setItem(row_idx, col_idx, item)

    def _autosize_columns(self):
        """Ensure badges, timestamps, and headers are never clipped."""
        self.resizeColumnsToContents()
        header = self.horizontalHeader()
        for col_idx, col_name in enumerate(self.headers):
            current_w = header.sectionSize(col_idx)
            min_header_w = max(84, len(col_name) * 8 + 26)
            if col_name.lower() in ("durum", "status", "bütünlük", "doğrulama"):
                # Calculate max badge width in this column
                badge_max = min_header_w
                for row_idx in range(min(self.rowCount(), 50)):
                    w = self.cellWidget(row_idx, col_idx)
                    if w:
                        badge_max = max(badge_max, w.sizeHint().width() + 8)
                header.resizeSection(col_idx, min(220, badge_max))
            elif any(k in col_name.lower() for k in ["açıklama", "başlığı", "cihaz adı", "hedef", "kullanım", "tam yol", "url", "ayrıntılar"]):
                header.resizeSection(col_idx, max(min_header_w, min(320, current_w + 18)))
            else:
                header.resizeSection(col_idx, max(min_header_w, min(240, current_w + 18)))

    def filter_records(self, query: str):
        """Filter rows across all columns case-insensitively."""
        if not query:
            self._visible_records = list(self._raw_records)
        else:
            q = query.lower()
            self._visible_records = [
                r for r in self._raw_records
                if any(q in str(v).lower() for v in r.values())
            ]
        self.setSortingEnabled(False)
        self._render_rows(self._visible_records)
        self._autosize_columns()
        self.setSortingEnabled(True)

    def get_selected_record(self) -> Optional[Dict[str, Any]]:
        rows = self.selectionModel().selectedRows()
        if not rows:
            return None
        selected_idx = rows[0].row()
        if 0 <= selected_idx < len(self._visible_records):
            return self._visible_records[selected_idx]
        return None

    def _on_selection_changed(self):
        rec = self.get_selected_record()
        if rec:
            self.rowSelected.emit(rec)

    def _on_double_click(self, row: int, col: int):
        if 0 <= row < len(self._visible_records):
            self.rowDoubleClicked.emit(self._visible_records[row])

    def _show_context_menu(self, pos):
        item = self.itemAt(pos)
        menu = QMenu(self)

        copy_cell_act = QAction("Hücre Değerini Kopyala", self)
        copy_cell_act.triggered.connect(lambda: self._copy_cell(item))
        menu.addAction(copy_cell_act)

        copy_row_act = QAction("Tüm Satırı Kopyala (JSON)", self)
        copy_row_act.triggered.connect(self._copy_row)
        menu.addAction(copy_row_act)

        menu.addSeparator()

        export_csv_act = QAction("Tabloyu CSV Olarak Dışa Aktar...", self)
        export_csv_act.triggered.connect(self.export_to_csv)
        menu.addAction(export_csv_act)

        menu.exec(self.viewport().mapToGlobal(pos))

    def _copy_cell(self, item):
        if item:
            QApplication.clipboard().setText(item.text())

    def _copy_row(self):
        rec = self.get_selected_record()
        if rec:
            import json
            QApplication.clipboard().setText(json.dumps(rec, indent=2, ensure_ascii=False, default=str))

    def export_to_csv(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "CSV Olarak Kaydet", "adli_tablo_cikti.csv", "CSV Dosyası (*.csv)")
        if not file_path:
            return
        try:
            with open(file_path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                writer.writerow(self.headers)
                for rec in self._visible_records:
                    writer.writerow([rec.get(h, "") for h in self.headers])
            QMessageBox.information(self, "Başarılı", f"Veriler başarıyla aktarıldı:\n{file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Dışa aktarma başarısız: {e}")
