"""Case Management Page adhering to the forensic desktop design system."""

from typing import List, Dict, Any, Optional
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QComboBox, QSplitter, QTabWidget, QTextEdit, QLineEdit, QDialog,
    QFormLayout, QMessageBox, QScrollArea
)
from PySide6.QtCore import Qt, Signal

from src.case_engine.case_service import CaseService
from src.ui.components.breadcrumb import Breadcrumb
from src.ui.components.search_field import ForensicSearchField
from src.ui.components.data_table import ForensicDataTable
from src.ui.components.status_indicator import StatusBadge


class CasesPage(QWidget):
    """Forensic Case Management workspace with detailed inspector and audit trail."""

    activeCaseSelected = Signal(int, str, str)  # case_id, case_number, title

    STATUS_MAP = {
        "open": "Açık",
        "in_progress": "İncelemede",
        "closed": "Kapandı",
        "archived": "Arşivlendi",
    }

    REVERSE_STATUS_MAP = {v: k for k, v in STATUS_MAP.items()}

    def __init__(self, db_path: str = "data/forensics.db", parent=None):
        super().__init__(parent)
        self.svc = CaseService(db_path=db_path)
        self._all_records: List[Dict[str, Any]] = []
        self._selected_case_id: Optional[int] = None

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 20, 24, 20)
        main_layout.setSpacing(14)

        # 1. Breadcrumb & Summary Header
        header_bar = QHBoxLayout()
        self.breadcrumb = Breadcrumb(["Adli Bilişim", "Vaka Yönetimi (Cases)"])
        header_bar.addWidget(self.breadcrumb)
        header_bar.addStretch()

        self.count_badge = StatusBadge("0 Vaka", "info")
        header_bar.addWidget(self.count_badge)
        main_layout.addLayout(header_bar)

        # 2. Toolbar: Search, Status Filter, Actions
        toolbar = QHBoxLayout()
        toolbar.setSpacing(10)

        self.search_field = ForensicSearchField("Vaka No, Başlık, Sorumlu veya Birim Ara...")
        self.search_field.searchChanged.connect(self._apply_filters)
        toolbar.addWidget(self.search_field, 2)

        self.status_filter = QComboBox()
        self.status_filter.addItems(["Tüm Durumlar", "Açık", "İncelemede", "Kapandı", "Arşivlendi"])
        self.status_filter.setFixedWidth(160)
        self.status_filter.currentIndexChanged.connect(self._apply_filters)
        toolbar.addWidget(self.status_filter)

        self.set_active_btn = QPushButton("✓ Aktif Vaka Yap")
        self.set_active_btn.clicked.connect(self._activate_selected_case)
        toolbar.addWidget(self.set_active_btn)

        new_btn = QPushButton("➕ Yeni Vaka Oluştur")
        new_btn.setObjectName("primaryBtn")
        new_btn.clicked.connect(self._open_create_dialog)
        toolbar.addWidget(new_btn)

        main_layout.addLayout(toolbar)

        # 3. Main Splitter: Case Table + Case Inspector
        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)

        # Left Table Container
        table_card = QFrame()
        table_card.setObjectName("surfaceCard")
        t_lay = QVBoxLayout(table_card)
        t_lay.setContentsMargins(12, 12, 12, 12)
        t_lay.setSpacing(8)

        t_head = QHBoxLayout()
        t_title = QLabel("Kayıtlı Adli Soruşturma Vakaları")
        t_title.setStyleSheet("font-size: 13px; font-weight: 700; color: #1D2733;")
        t_head.addWidget(t_title)
        t_head.addStretch()
        t_lay.addLayout(t_head)

        headers = ["Durum", "Vaka No", "Soruşturma Başlığı", "İnceleme Sorumlusu", "Birim / Kurum", "Açılış Tarihi (UTC)", "Delil"]
        self.table = ForensicDataTable(headers, self)
        self.table.rowSelected.connect(self._on_case_selected)
        t_lay.addWidget(self.table)
        splitter.addWidget(table_card)

        # Right Detail Inspector
        self.inspector = QFrame()
        self.inspector.setObjectName("surfaceCard")
        self.inspector.setFixedWidth(380)
        ins_lay = QVBoxLayout(self.inspector)
        ins_lay.setContentsMargins(14, 14, 14, 14)
        ins_lay.setSpacing(10)

        ins_head = QHBoxLayout()
        self.ins_title = QLabel("Vaka Seçilmedi")
        self.ins_title.setStyleSheet("font-size: 14px; font-weight: 700; color: #1D2733;")
        ins_head.addWidget(self.ins_title)
        ins_head.addStretch()
        self.ins_badge = StatusBadge("-", "neutral")
        ins_head.addWidget(self.ins_badge)
        ins_lay.addLayout(ins_head)

        self.tabs = QTabWidget()

        # Tab 1: Genel Bilgiler & Düzenleme
        tab_info = QWidget()
        ti_lay = QVBoxLayout(tab_info)
        ti_lay.setContentsMargins(8, 10, 8, 8)
        ti_lay.setSpacing(8)

        self.lbl_dates = QLabel("Açılış: - | Kapanış: -")
        self.lbl_dates.setStyleSheet("font-family: Consolas; font-size: 11px; color: #667085;")
        ti_lay.addWidget(self.lbl_dates)

        form = QFormLayout()
        form.setSpacing(6)
        self.ed_title = QLineEdit()
        self.ed_investigator = QLineEdit()
        self.ed_org = QLineEdit()
        self.cb_status = QComboBox()
        self.cb_status.addItems(["Açık", "İncelemede", "Kapandı", "Arşivlendi"])
        self.ed_desc = QTextEdit()
        self.ed_desc.setFixedHeight(90)

        form.addRow("Başlık:", self.ed_title)
        form.addRow("Sorumlu:", self.ed_investigator)
        form.addRow("Kurum/Birim:", self.ed_org)
        form.addRow("Durum:", self.cb_status)
        form.addRow("Açıklama:", self.ed_desc)
        ti_lay.addLayout(form)

        save_btn = QPushButton("Değişiklikleri Kaydet")
        save_btn.setObjectName("primaryBtn")
        save_btn.clicked.connect(self._save_case_changes)
        ti_lay.addWidget(save_btn)
        ti_lay.addStretch()

        self.tabs.addTab(tab_info, "Vaka Detayı")

        # Tab 2: Bağlı Deliller
        self.evd_table = ForensicDataTable(["Delil No", "Tür", "Marka / Model", "Durum"], self)
        self.tabs.addTab(self.evd_table, "Deliller")

        # Tab 3: Vaka Analiz Geçmişi
        self.audit_table = ForensicDataTable(["Zaman (UTC)", "İşlem", "Uzman"], self)
        self.tabs.addTab(self.audit_table, "Analiz Geçmişi")

        ins_lay.addWidget(self.tabs)
        splitter.addWidget(self.inspector)

        splitter.setStretchFactor(0, 7)
        splitter.setStretchFactor(1, 3)
        main_layout.addWidget(splitter, 1)

        self.refresh_records()

    def refresh_records(self):
        cases = self.svc.list_cases()
        self._all_records = []
        for c in cases:
            summary = self.svc.get_case_summary(c.id)
            status_tr = self.STATUS_MAP.get(c.status, c.status)
            # Map status to badge keywords recognized by ForensicDataTable
            display_status = "Doğrulandı" if c.status == "closed" else ("İnceleniyor" if c.status == "in_progress" else status_tr)
            if c.status == "open":
                display_status = "Normal (Açık)"

            self._all_records.append({
                "id": c.id,
                "raw_status": c.status,
                "Durum": display_status,
                "status_tr": status_tr,
                "Vaka No": c.case_number,
                "Soruşturma Başlığı": c.title,
                "İnceleme Sorumlusu": c.investigator or "-",
                "Birim / Kurum": c.organization or "-",
                "Açılış Tarihi (UTC)": c.opened_at.strftime("%Y-%m-%d %H:%M") if c.opened_at else "-",
                "Kapanış Tarihi (UTC)": c.closed_at.strftime("%Y-%m-%d %H:%M") if c.closed_at else "Devam Ediyor",
                "Delil": f"{summary.get('evidence_count', 0)} Adet",
                "description": c.description or "",
            })

        self.count_badge.set_status(f"{len(self._all_records)} Vaka", "info")
        self._apply_filters()

        if self._all_records:
            self._load_inspector(self._all_records[0]["id"])

    def _apply_filters(self):
        records = list(self._all_records)
        st = self.status_filter.currentText()
        if st != "Tüm Durumlar":
            records = [r for r in records if r["status_tr"] == st]

        q = self.search_field.text().lower()
        if q:
            records = [r for r in records if any(q in str(v).lower() for v in r.values())]

        self.table.set_records(records)

    def _on_case_selected(self, record: Dict[str, Any]):
        self._load_inspector(record["id"])

    def _load_inspector(self, case_id: int):
        summary = self.svc.get_case_summary(case_id)
        c = summary.get("case")
        if not c:
            return
        self._selected_case_id = c.id

        self.ins_title.setText(c.case_number)
        st_tr = self.STATUS_MAP.get(c.status, c.status)
        variant = "verified" if c.status in ("closed", "open") else ("info" if c.status == "in_progress" else "neutral")
        self.ins_badge.set_status(st_tr, variant)

        opened = c.opened_at.strftime("%Y-%m-%d %H:%M") if c.opened_at else "-"
        closed = c.closed_at.strftime("%Y-%m-%d %H:%M") if c.closed_at else "Açık"
        self.lbl_dates.setText(f"Açılış: {opened} | Kapanış: {closed}")

        self.ed_title.setText(c.title)
        self.ed_investigator.setText(c.investigator or "")
        self.ed_org.setText(c.organization or "")
        idx = self.cb_status.findText(st_tr)
        if idx >= 0:
            self.cb_status.setCurrentIndex(idx)
        self.ed_desc.setPlainText(c.description or "")

        # Populate Evidences tab
        evd_rows = []
        for e in summary.get("evidences", []):
            evd_rows.append({
                "Delil No": e.evidence_number,
                "Tür": e.device_type or "-",
                "Marka / Model": f"{e.brand or ''} {e.model or ''}".strip() or "-",
                "Durum": "Doğrulandı" if e.status == "verified" else e.status,
            })
        self.evd_table.set_records(evd_rows)

        # Populate Audit tab
        audit_rows = []
        for a in summary.get("audit_logs", []):
            audit_rows.append({
                "Zaman (UTC)": a.timestamp.strftime("%Y-%m-%d %H:%M") if a.timestamp else "-",
                "İşlem": a.action,
                "Uzman": a.investigator or "-",
            })
        self.audit_table.set_records(audit_rows)

    def _save_case_changes(self):
        if not self._selected_case_id:
            return
        new_status = self.REVERSE_STATUS_MAP.get(self.cb_status.currentText(), "open")
        self.svc.update_case(
            self._selected_case_id,
            title=self.ed_title.text(),
            investigator=self.ed_investigator.text(),
            organization=self.ed_org.text(),
            description=self.ed_desc.toPlainText(),
            status=new_status,
        )
        self.refresh_records()
        QMessageBox.information(self, "Vaka Güncellendi", "Vaka bilgileri ve denetim kaydı kaydedildi.")

    def _activate_selected_case(self):
        rec = self.table.get_selected_record()
        if not rec and self._selected_case_id:
            c = self.svc.get_case(self._selected_case_id)
            if c:
                self.activeCaseSelected.emit(c.id, c.case_number, c.title)
                QMessageBox.information(self, "Aktif Vaka Değiştirildi", f"Aktif çalışma vakası: {c.case_number}")
                return
        if rec:
            self.activeCaseSelected.emit(rec["id"], rec["Vaka No"], rec["Soruşturma Başlığı"])
            QMessageBox.information(self, "Aktif Vaka Değiştirildi", f"Aktif çalışma vakası: {rec['Vaka No']}")

    def _open_create_dialog(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("Yeni Adli Bilişim Vakası Oluştur")
        dlg.setMinimumWidth(460)
        lay = QVBoxLayout(dlg)
        lay.setSpacing(10)

        form = QFormLayout()
        num = QLineEdit()
        num.setPlaceholderText("Örn: VAK-2026-085")
        title = QLineEdit()
        title.setPlaceholderText("Örn: Şüpheli Sunucu Disk İncelemesi")
        inv = QLineEdit()
        inv.setPlaceholderText("Adli Bilişim Uzmanı")
        org = QLineEdit()
        org.setPlaceholderText("Siber Olay Müdahale Ekibi")
        desc = QTextEdit()
        desc.setFixedHeight(90)

        form.addRow("Vaka Numarası *:", num)
        form.addRow("Vaka Başlığı *:", title)
        form.addRow("İnceleme Sorumlusu:", inv)
        form.addRow("Kurum / Birim:", org)
        form.addRow("Soruşturma Özeti:", desc)
        lay.addLayout(form)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        cancel_btn = QPushButton("İptal")
        cancel_btn.clicked.connect(dlg.reject)
        create_btn = QPushButton("Vaka Oluştur")
        create_btn.setObjectName("primaryBtn")
        btn_row.addWidget(cancel_btn)
        btn_row.addWidget(create_btn)
        lay.addLayout(btn_row)

        def submit():
            try:
                c = self.svc.create_case(
                    num.text(),
                    title.text(),
                    inv.text(),
                    desc.toPlainText(),
                    organization=org.text(),
                )
                dlg.accept()
                self.refresh_records()
                self.activeCaseSelected.emit(c.id, c.case_number, c.title)
            except ValueError as e:
                QMessageBox.warning(dlg, "Doğrulama Hatası", str(e))

        create_btn.clicked.connect(submit)
        dlg.exec()
