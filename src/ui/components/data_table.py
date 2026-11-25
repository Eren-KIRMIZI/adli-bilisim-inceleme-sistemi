"""Forensic Data Table with smart column sizing, filtering, badges, sorting, and context actions."""

import csv
import math
from typing import List, Dict, Any, Optional
from PySide6.QtWidgets import (
    QTableWidget, QTableWidgetItem, QHeaderView, QMenu,
    QApplication, QFileDialog, QMessageBox, QWidget, QHBoxLayout,
    QAbstractItemView, QPushButton, QLabel
)
from PySide6.QtCore import Qt, Signal, QAbstractTableModel, QModelIndex
from PySide6.QtGui import QFont, QAction
from src.ui.components.status_indicator import StatusBadge


class ForensicTableModel(QAbstractTableModel):
    """Virtual Model-View table model for large (100k+) forensic datasets with near-zero widget overhead."""

    def __init__(self, headers: List[str], records: Optional[List[Dict[str, Any]]] = None, parent=None):
        super().__init__(parent)
        self.headers = headers
        self._records: List[Dict[str, Any]] = records or []

    def set_records(self, records: List[Dict[str, Any]]):
        self.beginResetModel()
        self._records = records
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._records)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.headers)

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        rec = self._records[index.row()]
        col = self.headers[index.column()]
        if role in (Qt.DisplayRole, Qt.ToolTipRole):
            val = rec.get(col, "")
            return str(val) if val is not None else "-"
        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal and 0 <= section < len(self.headers):
            return self.headers[section]
        return None


class ForensicDataTable(QTableWidget):
    """High performance paginated forensic-standard data table widget (caps live QWidgets at page_size)."""
    rowSelected = Signal(dict)
    rowDoubleClicked = Signal(dict)

    def __init__(self, headers: List[str], parent=None, page_size: int = 250):
        super().__init__(0, len(headers), parent)
        self.headers = headers
        self.setHorizontalHeaderLabels(headers)
        self._raw_records: List[Dict[str, Any]] = []
        self._visible_records: List[Dict[str, Any]] = []
        self._page_size = max(25, page_size)
        self._current_page = 0
        self._page_lbl: Optional[QLabel] = None
        self._prev_btn: Optional[QPushButton] = None
        self._next_btn: Optional[QPushButton] = None

        # Appearance & Behavior
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setSelectionMode(QTableWidget.SingleSelection)
        self.setShowGrid(False)
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
        """Populate the table with records using fast windowed pagination (renders page_size rows)."""
        self.setSortingEnabled(False)
        self._raw_records = records
        self._visible_records = list(records)
        self._current_page = 0
        self._render_current_page()
        self._autosize_columns()
        self.setSortingEnabled(True)

    def total_record_count(self) -> int:
        return len(self._visible_records)

    def page_count(self) -> int:
        return max(1, math.ceil(len(self._visible_records) / self._page_size))

    def current_page(self) -> int:
        return self._current_page

    def set_page(self, page_idx: int):
        total_p = self.page_count()
        self._current_page = max(0, min(page_idx, total_p - 1))
        self.setSortingEnabled(False)
        self._render_current_page()
        self.setSortingEnabled(True)

    def next_page(self):
        self.set_page(self._current_page + 1)

    def prev_page(self):
        self.set_page(self._current_page - 1)

    def build_pagination_bar(self, parent=None) -> QWidget:
        """Create an optional compact pagination control bar linked to this table."""
        bar = QWidget(parent or self)
        self._pagination_bar = bar
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(0, 2, 0, 2)
        lay.setSpacing(8)
        self._prev_btn = QPushButton("◀ Önceki", bar)
        self._prev_btn.clicked.connect(self.prev_page)
        self._page_lbl = QLabel(bar)
        self._page_lbl.setObjectName("mutedLabel")
        self._next_btn = QPushButton("Sonraki ▶", bar)
        self._next_btn.clicked.connect(self.next_page)
        lay.addWidget(self._prev_btn)
        lay.addWidget(self._page_lbl)
        lay.addWidget(self._next_btn)
        lay.addStretch()
        self._update_pagination_bar()
        return bar

    def _update_pagination_bar(self):
        total_p = self.page_count()
        try:
            if self._page_lbl is not None:
                self._page_lbl.setText(
                    f"Sayfa {self._current_page + 1} / {total_p}  (Toplam {len(self._visible_records):,} kayıt)"
                )
            if self._prev_btn is not None:
                self._prev_btn.setEnabled(self._current_page > 0)
            if self._next_btn is not None:
                self._next_btn.setEnabled(self._current_page + 1 < total_p)
        except RuntimeError:
            # Widget tree already torn down cleanly
            self._page_lbl = None
            self._prev_btn = None
            self._next_btn = None

    def _render_current_page(self):
        start = self._current_page * self._page_size
        end = start + self._page_size
        self._render_rows(self._visible_records[start:end])
        self._update_pagination_bar()

    def _render_rows(self, records: List[Dict[str, Any]]):
        self.setRowCount(len(records))
        mono_font = QFont("Consolas", 10)

        for row_idx, rec in enumerate(records):
            for col_idx, col_name in enumerate(self.headers):
                val = rec.get(col_name, "")

                if col_name.lower() in ("durum", "status", "bütünlük", "doğrulama"):
                    variant = "neutral"
                    sval = str(val).strip().lower()
                    # Check negative/critical/warning phrases BEFORE positive tokens (prevents 'hash yok', 'normal dışı', 'çok şüpheli' -> green)
                    if any(k in sval for k in ["kritik", "bozuk", "critical", "zararlı", "uyuşmazlık", "mismatch", "sahte", "kötücül"]):
                        variant = "critical"
                    elif any(k in sval for k in ["şüpheli", "warning", "uyarı", "anomali", "silinmiş", "yinelenen", "normal dışı", "doğrulanmadı", "hash yok", "yok"]):
                        variant = "warning"
                    elif any(k in sval for k in ["inceleniyor", "bilgi", "info", "bekliyor", "received", "kısmi"]):
                        variant = "info"
                    elif sval in ("ok", "normal", "doğrulandı", "verified") or any(k in sval for k in ["doğrulandı", "verified", "tutarlı", "clean", "temiz"]):
                        variant = "verified"

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
                # Calculate max badge width in this column with extra padding for pill borders
                badge_max = max(min_header_w, 126)
                for row_idx in range(min(self.rowCount(), 50)):
                    w = self.cellWidget(row_idx, col_idx)
                    if w:
                        badge_max = max(badge_max, w.sizeHint().width() + 20)
                header.resizeSection(col_idx, min(240, badge_max))
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
        self._current_page = 0
        self._render_current_page()
        self._autosize_columns()
        self.setSortingEnabled(True)

    def get_selected_record(self) -> Optional[Dict[str, Any]]:
        rows = self.selectionModel().selectedRows()
        if not rows:
            return None
        global_idx = self._current_page * self._page_size + rows[0].row()
        if 0 <= global_idx < len(self._visible_records):
            return self._visible_records[global_idx]
        return None

    def _on_selection_changed(self):
        rec = self.get_selected_record()
        if rec:
            self.rowSelected.emit(rec)

    def _on_double_click(self, row: int, col: int):
        global_idx = self._current_page * self._page_size + row
        if 0 <= global_idx < len(self._visible_records):
            self.rowDoubleClicked.emit(self._visible_records[global_idx])

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
