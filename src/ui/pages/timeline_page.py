"""Timeline Analysis Page with UTC standardization, density chart, and delta calculator."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QComboBox, QSplitter, QTextEdit, QLineEdit, QMessageBox, QFileDialog
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QPainter, QColor, QFont

from src.timeline_engine.timeline_service import TimelineService
from src.core.orchestrator import AnalysisOrchestrator
from src.ui.styles.tokens import get_theme
from src.ui.components.breadcrumb import Breadcrumb
from src.ui.components.search_field import ForensicSearchField
from src.ui.components.data_table import ForensicDataTable
from src.ui.components.status_indicator import StatusBadge


class TimelineDensityChart(QWidget):
    """Lightweight native Qt bar chart showing chronological event density by day."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(96)
        self._buckets: List[tuple] = []  # (label, count)
        self._theme_name = "light"

    def set_theme(self, theme_name: str):
        self._theme_name = theme_name
        self.update()

    def set_events(self, events: List[Dict[str, Any]]):
        counts: Dict[str, int] = {}
        for ev in events:
            ts = ev.get("timestamp_utc")
            if isinstance(ts, datetime):
                key = ts.strftime("%m-%d %H:00")
                counts[key] = counts.get(key, 0) + 1
        self._buckets = sorted(counts.items())[-16:]
        self.update()

    def paintEvent(self, event):
        t = get_theme(self._theme_name)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = self.rect()
        painter.fillRect(rect, QColor(t["surface"]))

        if not self._buckets:
            painter.setPen(QColor(t["text_muted"]))
            painter.drawText(rect, Qt.AlignCenter, "Zaman yoğunluğu verisi yok")
            return

        max_c = max(c for _, c in self._buckets) or 1
        pad_x, pad_top, pad_bot = 16, 16, 22
        avail_w = max(1, rect.width() - 2 * pad_x)
        avail_h = max(1, rect.height() - pad_top - pad_bot)
        bar_w = max(12, int(avail_w / len(self._buckets)) - 6)

        font = QFont("Consolas", 8)
        painter.setFont(font)

        for idx, (lbl, cnt) in enumerate(self._buckets):
            x = pad_x + idx * (avail_w / len(self._buckets))
            h = max(4, int((cnt / max_c) * avail_h))
            y = pad_top + (avail_h - h)

            painter.fillRect(int(x), int(y), int(bar_w), int(h), QColor(t["accent"]))
            painter.setPen(QColor(t["text"]))
            painter.drawText(int(x), int(y) - 3, str(cnt))
            painter.setPen(QColor(t["text_muted"]))
            painter.drawText(int(x), rect.height() - 6, lbl[-5:])


class TimelinePage(QWidget):
    """Unified forensic timeline page with filtering, delta computation, and event inspector."""

    def __init__(self, db_path: str = "data/forensics.db", parent=None):
        super().__init__(parent)
        self.svc = TimelineService(db_path=db_path)
        self._all_events: List[Dict[str, Any]] = []
        self._anchor_dt: Optional[datetime] = None
        self._selected_dt: Optional[datetime] = None

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 18, 24, 18)
        main_layout.setSpacing(12)

        # 1. Header
        header_bar = QHBoxLayout()
        self.breadcrumb = Breadcrumb(["Adli Bilişim", "Olay Zaman Çizelgesi (UTC)"])
        header_bar.addWidget(self.breadcrumb)
        header_bar.addStretch()

        self.delta_badge = StatusBadge("Referans Noktası Seçilmedi", "neutral")
        header_bar.addWidget(self.delta_badge)
        self.count_badge = StatusBadge("0 Olay", "info")
        header_bar.addWidget(self.count_badge)
        main_layout.addLayout(header_bar)

        # 2. Filters Toolbar
        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)

        self.search_field = ForensicSearchField("Olay türü, kullanıcı, cihaz veya açıklama ara...")
        self.search_field.searchChanged.connect(self._apply_filters)
        toolbar.addWidget(self.search_field, 2)

        self.source_filter = QComboBox()
        self.source_filter.addItems([
            "Tüm Kaynaklar", "USB", "Muhafaza", "Denetim",
            "MFT", "EVTX", "Prefetch", "Tarayıcı", "E-posta", "Artefakt"
        ])
        self.source_filter.setFixedWidth(150)
        self.source_filter.currentIndexChanged.connect(self._apply_filters)
        toolbar.addWidget(self.source_filter)

        self.user_filter = QComboBox()
        self.user_filter.setFixedWidth(180)
        self.user_filter.currentIndexChanged.connect(self._apply_filters)
        toolbar.addWidget(self.user_filter)

        ingest_btn = QPushButton("🔀 Artefakt Ekle (Super-Timeline)")
        ingest_btn.setToolTip("EVTX, Prefetch (.pf), veya E-posta (.eml) dosyasını zaman çizelgesine ekler.")
        ingest_btn.clicked.connect(self._ingest_artifact_dialog)
        toolbar.addWidget(ingest_btn)

        anchor_btn = QPushButton("⏱️ Referans Noktası Yap (Δt)")
        anchor_btn.setToolTip("Seçili olayı zaman farkı hesabı için referans noktası olarak işaretler.")
        anchor_btn.clicked.connect(self._set_anchor_event)
        toolbar.addWidget(anchor_btn)

        export_btn = QPushButton("CSV Dışa Aktar")
        export_btn.clicked.connect(lambda: self.table.export_to_csv())
        toolbar.addWidget(export_btn)

        jsonl_btn = QPushButton("JSONL / BodyFile")
        jsonl_btn.setToolTip("Timesketch (JSONL) veya Sleuth Kit (BodyFile) formatında dışa aktarır.")
        jsonl_btn.clicked.connect(self._export_interchange)
        toolbar.addWidget(jsonl_btn)
        main_layout.addLayout(toolbar)

        # 3. Timeline Density Chart Card
        chart_card = QFrame()
        chart_card.setObjectName("surfaceCard")
        ch_lay = QVBoxLayout(chart_card)
        ch_lay.setContentsMargins(10, 6, 10, 6)
        ch_lay.setSpacing(2)
        ch_lbl = QLabel("Saatlik Olay Yoğunluğu (UTC)")
        ch_lbl.setObjectName("mutedLabel")
        ch_lay.addWidget(ch_lbl)
        self.chart = TimelineDensityChart(self)
        ch_lay.addWidget(self.chart)
        main_layout.addWidget(chart_card)

        # 4. Splitter: Timeline Table + Event Detail
        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)

        headers = ["Zaman (UTC)", "Olay Türü", "Kullanıcı", "Açıklama", "Güvenilirlik", "Kaynak"]
        self.table = ForensicDataTable(headers, self)
        self.table.rowSelected.connect(self._on_event_selected)

        left_box = QWidget()
        lb_lay = QVBoxLayout(left_box)
        lb_lay.setContentsMargins(0, 0, 0, 0)
        lb_lay.addWidget(self.table)
        lb_lay.addWidget(self.table.build_pagination_bar(left_box))
        splitter.addWidget(left_box)

        right = QFrame()
        right.setObjectName("surfaceCard")
        right.setFixedWidth(340)
        r_lay = QVBoxLayout(right)
        r_lay.setContentsMargins(12, 12, 12, 12)
        r_lay.addWidget(QLabel("Seçili Olay & Zaman Güvenilirliği"))
        self.detail_view = QTextEdit()
        self.detail_view.setReadOnly(True)
        self.detail_view.setStyleSheet("font-family: Consolas; font-size: 11px;")
        r_lay.addWidget(self.detail_view)
        splitter.addWidget(right)

        splitter.setStretchFactor(0, 7)
        splitter.setStretchFactor(1, 3)
        main_layout.addWidget(splitter, 1)

        self.refresh_records()

    def set_theme(self, theme_name: str):
        self.chart.set_theme(theme_name)

    def refresh_records(self):
        self._all_events = self.svc.collect_case_timeline()

        users = sorted({e.get("user", "-") for e in self._all_events if e.get("user")})
        self.user_filter.blockSignals(True)
        self.user_filter.clear()
        self.user_filter.addItem("Tüm Kullanıcılar")
        for u in users:
            self.user_filter.addItem(u)
        self.user_filter.blockSignals(False)

        self._apply_filters()

    def _apply_filters(self):
        src = self.source_filter.currentText()
        usr = self.user_filter.currentText()
        q = self.search_field.text().lower()

        filtered = []
        for e in self._all_events:
            if src != "Tüm Kaynaklar" and src.lower() not in e["event_type"].lower():
                continue
            if usr != "Tüm Kullanıcılar" and e.get("user") != usr:
                continue
            row = {
                "Zaman (UTC)": e["timestamp"],
                "Olay Türü": e["event_type"],
                "Kullanıcı": e.get("user", "-"),
                "Açıklama": e["details"],
                "Güvenilirlik": e["reliability"],
                "Kaynak": e["source"],
                "_raw": e,
            }
            if q and not any(q in str(v).lower() for k, v in row.items() if k != "_raw"):
                continue
            filtered.append(row)

        self.table.set_records(filtered)
        self.chart.set_events([r["_raw"] for r in filtered])
        self.count_badge.set_status(f"{len(filtered)} Olay", "info")
        if filtered:
            self._on_event_selected(filtered[0])

    def _on_event_selected(self, row: Dict[str, Any]):
        ev = row.get("_raw")
        if not ev:
            return
        self._selected_dt = ev.get("timestamp_utc")

        delta_txt = "-"
        if self._anchor_dt and self._selected_dt:
            delta_txt = TimelineService.compute_time_delta(self._anchor_dt, self._selected_dt)
            self.delta_badge.set_status(f"Δt: {delta_txt}", "info")

        self.detail_view.setPlainText(
            f"OLAY TÜRÜ:       {ev['event_type']}\n"
            f"UTC ZAMANI:      {ev['timestamp']}\n"
            f"ORİJİNAL DAMGA:  {ev['original_timestamp']}\n"
            f"SAAT DİLİMİ:     {ev['timezone_info']}\n"
            f"KULLANICI:       {ev['user']}\n"
            f"GÜVENİLİRLİK:    {ev['reliability']}\n"
            f"REFERANS Δt:     {delta_txt}\n\n"
            f"KAYNAK ARTEFAKT:\n{ev['source']}\n\n"
            f"AÇIKLAMA:\n{ev['details']}"
        )

    def _ingest_artifact_dialog(self):
        fp, _ = QFileDialog.getOpenFileName(
            self,
            "Zaman Çizelgesine Artefakt Ekle",
            "",
            "Adli Artefaktlar (*.evtx *.pf *.eml);;Tüm Dosyalar (*.*)"
        )
        if not fp:
            return
        added = 0
        low = fp.lower()
        try:
            if low.endswith(".evtx"):
                from src.eventlog_engine.evtx_service import EventLogService
                res = EventLogService().parse_evtx_file(fp)
                added = self.svc.ingest_evtx_events(res.get("events", []), source_label=fp)
            elif low.endswith(".pf"):
                from src.registry_engine.windows_artifacts import WindowsArtifactParsers
                added = self.svc.ingest_prefetch(WindowsArtifactParsers.parse_prefetch(fp))
            elif low.endswith(".eml"):
                from src.email_network_engine import EmailForensicsService
                added = self.svc.ingest_eml(EmailForensicsService.parse_eml(fp))
            self.refresh_records()
            QMessageBox.information(self, "Super-Timeline Güncellendi", f"{added} olay UTC zaman çizelgesine eklendi.")
        except Exception as e:
            QMessageBox.critical(self, "Zaman Çizelgesi İçe Aktarma Hatası", str(e))

    def _export_interchange(self):
        fp, filt = QFileDialog.getSaveFileName(
            self,
            "Zaman Çizelgesi Dışa Aktar",
            "super_timeline.jsonl",
            "Timesketch JSONL (*.jsonl);;Sleuth Kit BodyFile (*.body)"
        )
        if not fp:
            return
        if fp.lower().endswith(".body") or "BodyFile" in filt:
            AnalysisOrchestrator.export_timeline_bodyfile(self._all_events, fp)
        else:
            AnalysisOrchestrator.export_timeline_jsonl(self._all_events, fp)
        QMessageBox.information(self, "Dışa Aktarıldı", f"Zaman çizelgesi kaydedildi:\n{fp}")

    def _set_anchor_event(self):
        if self._selected_dt:
            self._anchor_dt = self._selected_dt
            self.delta_badge.set_status(f"Referans: {self._anchor_dt.strftime('%H:%M:%S')}", "verified")
            QMessageBox.information(
                self,
                "Referans Zaman Ayarlandı",
                f"Referans UTC zamanı: {self._anchor_dt.strftime('%Y-%m-%d %H:%M:%S')}\n"
                "Tablodan başka bir olaya tıklayarak aradaki zaman farkını (Δt) görebilirsiniz.",
            )
