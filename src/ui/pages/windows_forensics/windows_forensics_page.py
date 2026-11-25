"""Windows Forensics Page: Registry Hive Tree, EVTX Event Logs, Prefetch/LNK/$I & Live Triage."""

import os
from typing import Any, Dict, List, Optional
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QComboBox, QSplitter, QTabWidget, QTreeWidget, QTreeWidgetItem,
    QTextEdit, QFileDialog, QMessageBox
)
from PySide6.QtCore import Qt

from src.registry_engine.hive_parser import RegistryHiveParser, create_synthetic_registry_hive
from src.registry_engine.windows_artifacts import WindowsArtifactParsers, create_synthetic_windows_artifacts
from src.eventlog_engine.evtx_service import EventLogService, create_synthetic_evtx_file
from src.core.triage_collector import TriageCollector
from src.email_network_engine import NetworkForensicsService, create_synthetic_pcap_file
from src.ui.components.breadcrumb import Breadcrumb
from src.ui.components.search_field import ForensicSearchField
from src.ui.components.data_table import ForensicDataTable
from src.ui.components.hex_viewer import ForensicHexViewer
from src.ui.components.status_indicator import StatusBadge


class WindowsForensicsPage(QWidget):
    """Multi-tab Windows forensic analysis workbench."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.hive_parser = RegistryHiveParser()
        self.evtx_service = EventLogService()
        self._evtx_events: List[Dict[str, Any]] = []
        self._artifact_rows: List[Dict[str, Any]] = []

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 18, 24, 18)
        main_layout.setSpacing(12)

        # 1. Breadcrumb Header
        header_bar = QHBoxLayout()
        self.breadcrumb = Breadcrumb(["Adli Bilişim", "Windows Forensics", "Registry, EVTX & Çalıştırma İzleri"])
        header_bar.addWidget(self.breadcrumb)
        header_bar.addStretch()

        self.mode_badge = StatusBadge("Salt Okunur Ayrıştırıcı", "verified")
        header_bar.addWidget(self.mode_badge)
        main_layout.addLayout(header_bar)

        # 2. Tabs
        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_registry_tab(), "🗂️ Registry Hive Gezgini")
        self.tabs.addTab(self._build_evtx_tab(), "📜 Windows Event Logs (.evtx)")
        self.tabs.addTab(self._build_artifacts_tab(), "⚡ Çalıştırma & Dosya İzleri (.pf / .lnk / $I)")
        self.tabs.addTab(self._build_network_tab(), "🌐 Ağ / PCAP & Hosts İzleri")
        main_layout.addWidget(self.tabs, 1)

    # ------------------------------------------------------------------
    # TAB 1: Registry Hive Explorer (3-Column Layout)
    # ------------------------------------------------------------------
    def _build_registry_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(10)

        toolbar = QHBoxLayout()
        open_hive_btn = QPushButton("📁 Hive Dosyası Aç (SYSTEM / SOFTWARE / NTUSER.DAT)")
        open_hive_btn.setObjectName("primaryBtn")
        open_hive_btn.clicked.connect(self._open_hive_dialog)
        toolbar.addWidget(open_hive_btn)

        sample_hive_btn = QPushButton("🧪 Örnek Registry Hive Oluştur & Aç")
        sample_hive_btn.clicked.connect(self._load_synthetic_hive)
        toolbar.addWidget(sample_hive_btn)

        self.hive_info_lbl = QLabel("Kovan: Yüklenmedi")
        self.hive_info_lbl.setObjectName("monoLabel")
        toolbar.addWidget(self.hive_info_lbl)
        toolbar.addStretch()
        lay.addLayout(toolbar)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)

        # Left: Registry Tree
        self.reg_tree = QTreeWidget()
        self.reg_tree.setHeaderHidden(True)
        self.reg_tree.setMinimumWidth(240)
        self.reg_tree.itemClicked.connect(self._on_reg_node_clicked)
        splitter.addWidget(self.reg_tree)

        # Center: Values Table
        self.reg_table = ForensicDataTable(["Değer Adı", "Tür", "Veri", "Son Yazma (UTC)"], self)
        self.reg_table.rowSelected.connect(self._on_reg_val_selected)
        splitter.addWidget(self.reg_table)

        # Right: Value Details + Hex
        right_panel = QFrame()
        right_panel.setObjectName("surfaceCard")
        right_panel.setMinimumWidth(290)
        rp_lay = QVBoxLayout(right_panel)
        rp_lay.setContentsMargins(10, 10, 10, 10)
        rp_lay.setSpacing(6)

        self.reg_detail = QTextEdit()
        self.reg_detail.setReadOnly(True)
        self.reg_detail.setFixedHeight(160)
        self.reg_detail.setStyleSheet("font-family: Consolas; font-size: 11px;")
        rp_lay.addWidget(self.reg_detail)

        self.reg_hex = ForensicHexViewer(self)
        rp_lay.addWidget(self.reg_hex)
        splitter.addWidget(right_panel)

        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 4)
        splitter.setStretchFactor(2, 4)
        lay.addWidget(splitter, 1)
        return w

    def _open_hive_dialog(self):
        fp, _ = QFileDialog.getOpenFileName(self, "Windows Registry Hive Seç", "", "Registry Hive (*; *.dat; *.hiv);;Tüm Dosyalar (*.*)")
        if fp:
            self.load_hive(fp)

    def _load_synthetic_hive(self):
        path = os.path.join("data", "sample_system_hive.hiv")
        create_synthetic_registry_hive(path)
        self.load_hive(path)

    def load_hive(self, path: str):
        try:
            parsed = self.hive_parser.parse_hive_file(path)
            self.hive_info_lbl.setText(f"Kovan: {parsed['hive_name']} | Toplam Anahtar: {parsed['total_keys_parsed']}")
            self.reg_tree.clear()
            root_data = parsed.get("root")
            if root_data:
                root_item = self._add_reg_tree_node(None, root_data)
                self.reg_tree.expandAll()
                # Prefer selecting the first child node that contains registry values so inspector is populated
                chosen_item = root_item
                for i in range(root_item.childCount()):
                    ch = root_item.child(i)
                    ch_data = ch.data(0, Qt.UserRole) or {}
                    if ch_data.get("values"):
                        chosen_item = ch
                        break
                    for j in range(ch.childCount()):
                        gch = ch.child(j)
                        if (gch.data(0, Qt.UserRole) or {}).get("values"):
                            chosen_item = gch
                            break
                    if chosen_item is not root_item:
                        break
                self.reg_tree.setCurrentItem(chosen_item)
                self._on_reg_node_clicked(chosen_item, 0)
            hive_arts = self.hive_parser.extract_hive_forensics_artifacts(parsed)
            if hive_arts:
                for ha in hive_arts:
                    self._artifact_rows.insert(0, {
                        "Durum": ha["Durum"],
                        "Artefakt Türü": ha["Kategori"],
                        "Ad / Dosya": ha["Ad"],
                        "Hedef / Değer / Yol": ha["Değer / Yol"],
                        "Zaman / Sayaç": ha["Zaman / Sayaç"],
                        "Kaynak": ha["Kaynak"],
                        "_raw": ha.get("_raw", b""),
                    })
                self._apply_artifact_filters()
        except Exception as e:
            QMessageBox.critical(self, "Registry Ayrıştırma Hatası", str(e))

    def _add_reg_tree_node(self, parent_item, node: Dict[str, Any]) -> QTreeWidgetItem:
        label = f"🔑 {node['name']} ({len(node['values'])})"
        item = QTreeWidgetItem(self.reg_tree, [label]) if parent_item is None else QTreeWidgetItem(parent_item, [label])
        item.setData(0, Qt.UserRole, node)
        for ch in node.get("children", []):
            self._add_reg_tree_node(item, ch)
        return item

    def _on_reg_node_clicked(self, item: QTreeWidgetItem, col: int):
        node = item.data(0, Qt.UserRole)
        if not node:
            return
        ts = node["last_written"].strftime("%Y-%m-%d %H:%M:%S") if node.get("last_written") else "-"
        rows = []
        for v in node.get("values", []):
            rows.append({
                "Değer Adı": v["name"],
                "Tür": v["type"],
                "Veri": v["value"],
                "Son Yazma (UTC)": ts,
                "_raw": v["raw_bytes"],
                "_path": node["path"],
            })
        self.reg_table.set_records(rows)
        self.reg_detail.setPlainText(f"ANAHTAR YOLU:\n{node['path']}\n\nSON YAZMA (UTC): {ts}\nALT ANAHTAR: {len(node['children'])}\nDEĞER SAYISI: {len(rows)}")
        if rows:
            self._on_reg_val_selected(rows[0])

    def _on_reg_val_selected(self, row: Dict[str, Any]):
        self.reg_detail.setPlainText(
            f"ANAHTAR YOLU:\n{row.get('_path', '-')}\n\n"
            f"DEĞER ADI: {row['Değer Adı']}\n"
            f"TÜR:       {row['Tür']}\n"
            f"ZAMAN:     {row['Son Yazma (UTC)']}\n\n"
            f"VERİ:\n{row['Veri']}"
        )
        self.reg_hex.load_bytes(row.get("_raw", b""))

    # ------------------------------------------------------------------
    # TAB 2: Windows Event Logs (.evtx)
    # ------------------------------------------------------------------
    def _build_evtx_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(10)

        toolbar = QHBoxLayout()
        self.evtx_search = ForensicSearchField("Event ID, kullanıcı veya olay içeriği ara...")
        self.evtx_search.searchChanged.connect(self._apply_evtx_filters)
        toolbar.addWidget(self.evtx_search, 2)

        self.evtx_filter = QComboBox()
        self.evtx_filter.addItems(["Tüm Olaylar", "Kritik / Uyarı Olayları", "4624/4625 Oturum", "4688 Süreç", "7045 Servis"])
        self.evtx_filter.setFixedWidth(180)
        self.evtx_filter.currentIndexChanged.connect(self._apply_evtx_filters)
        toolbar.addWidget(self.evtx_filter)

        open_evtx_btn = QPushButton("📁 EVTX Dosyası Aç")
        open_evtx_btn.setObjectName("primaryBtn")
        open_evtx_btn.clicked.connect(self._open_evtx_dialog)
        toolbar.addWidget(open_evtx_btn)

        sample_evtx_btn = QPushButton("🧪 Sentetik Security EVTX İncele")
        sample_evtx_btn.clicked.connect(self._load_synthetic_evtx)
        toolbar.addWidget(sample_evtx_btn)
        lay.addLayout(toolbar)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)

        self.evtx_table = ForensicDataTable(
            ["Durum", "Kayıt #", "Event ID", "Zaman (UTC)", "Olay Açıklaması", "Ayrıntılar"],
            self
        )
        self.evtx_table.rowSelected.connect(self._on_evtx_selected)
        splitter.addWidget(self.evtx_table)

        right = QFrame()
        right.setObjectName("surfaceCard")
        right.setFixedWidth(360)
        r_lay = QVBoxLayout(right)
        r_lay.setContentsMargins(10, 10, 10, 10)
        self.evtx_detail = QTextEdit()
        self.evtx_detail.setReadOnly(True)
        self.evtx_detail.setFixedHeight(190)
        self.evtx_detail.setStyleSheet("font-family: Consolas; font-size: 11px;")
        r_lay.addWidget(self.evtx_detail)
        self.evtx_hex = ForensicHexViewer(self)
        r_lay.addWidget(self.evtx_hex)
        splitter.addWidget(right)

        splitter.setStretchFactor(0, 7)
        splitter.setStretchFactor(1, 3)
        lay.addWidget(splitter, 1)
        return w

    def _open_evtx_dialog(self):
        fp, _ = QFileDialog.getOpenFileName(self, "Windows EVTX Dosyası Seç", "", "Event Log (*.evtx);;Tüm Dosyalar (*.*)")
        if fp:
            self.load_evtx(fp)

    def _load_synthetic_evtx(self):
        path = os.path.join("data", "sample_security.evtx")
        create_synthetic_evtx_file(path)
        self.load_evtx(path)

    def load_evtx(self, path: str):
        try:
            res = self.evtx_service.parse_evtx_file(path)
            self._evtx_events = []
            for ev in res["events"]:
                sev = ev["severity"]
                status_badge = "Kritik" if sev == "Kritik" else ("Uyarı" if sev == "Uyarı" else ("İnceleniyor" if sev == "İnceleniyor" else "Normal"))
                self._evtx_events.append({
                    "Durum": status_badge,
                    "Kayıt #": ev["record_id"],
                    "Event ID": ev["event_id"] if ev["event_id"] is not None else "Bilinmiyor",
                    "Zaman (UTC)": ev["timestamp"].strftime("%Y-%m-%d %H:%M:%S") if ev["timestamp"] else "-",
                    "Olay Açıklaması": ev["description"],
                    "Ayrıntılar": ev["details"],
                    "_raw": ev["raw_bytes"],
                    "_offset": ev["source_offset"],
                })
            self._apply_evtx_filters()
            if self._evtx_events:
                self._on_evtx_selected(self._evtx_events[0])
        except Exception as e:
            QMessageBox.critical(self, "EVTX Ayrıştırma Hatası", str(e))

    def _apply_evtx_filters(self):
        rows = list(self._evtx_events)
        flt = self.evtx_filter.currentText()
        if flt == "Kritik / Uyarı Olayları":
            rows = [r for r in rows if r["Durum"] in ("Kritik", "Uyarı")]
        elif flt == "4624/4625 Oturum":
            rows = [r for r in rows if str(r["Event ID"]) in ("4624", "4625")]
        elif flt == "4688 Süreç":
            rows = [r for r in rows if str(r["Event ID"]) == "4688"]
        elif flt == "7045 Servis":
            rows = [r for r in rows if str(r["Event ID"]) == "7045"]

        q = self.evtx_search.text().lower()
        if q:
            rows = [r for r in rows if any(q in str(v).lower() for k, v in r.items() if k not in ("_raw", "_offset"))]
        self.evtx_table.set_records(rows)

    def _on_evtx_selected(self, row: Dict[str, Any]):
        self.evtx_detail.setPlainText(
            f"KAYIT ID:  {row['Kayıt #']} (Offset {row.get('_offset', '-')})\n"
            f"EVENT ID:  {row['Event ID']}\n"
            f"ZAMAN:     {row['Zaman (UTC)']}\n"
            f"ÖNEM:      {row['Durum']}\n"
            f"AÇIKLAMA:  {row['Olay Açıklaması']}\n\n"
            f"AYRINTILAR (BinXML Tokenları):\n{row['Ayrıntılar']}"
        )
        self.evtx_hex.load_bytes(row.get("_raw", b""))

    # ------------------------------------------------------------------
    # TAB 3: Execution & User Artifacts (Prefetch, LNK, $I, Live Triage)
    # ------------------------------------------------------------------
    def _build_artifacts_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(10)

        toolbar = QHBoxLayout()
        self.art_search = ForensicSearchField("Program, yol, servis veya SID ara...")
        self.art_search.searchChanged.connect(self._apply_artifact_filters)
        toolbar.addWidget(self.art_search, 2)

        self.art_filter = QComboBox()
        self.art_filter.addItems([
            "Tüm Artefaktlar", "Başlangıç (Autorun)", "Servis", "Kullanıcı Hesabı",
            "UserAssist", "ShimCache", "ShellBags", "Amcache",
            "Prefetch (.pf)", "LNK Kısayolu", "Jump List", "Geri Dönüşüm Kutusu ($I)"
        ])
        self.art_filter.setFixedWidth(190)
        self.art_filter.currentIndexChanged.connect(self._apply_artifact_filters)
        toolbar.addWidget(self.art_filter)

        triage_btn = QPushButton("⚡ Canlı Sistem Triage Tara")
        triage_btn.setObjectName("primaryBtn")
        triage_btn.clicked.connect(self._scan_live_triage)
        toolbar.addWidget(triage_btn)

        pack_btn = QPushButton("📦 KAPE Triage Paketi")
        pack_btn.clicked.connect(self._collect_kape_triage)
        toolbar.addWidget(pack_btn)

        open_art_btn = QPushButton("📁 .pf / .lnk / JumpList Aç")
        open_art_btn.clicked.connect(self._open_artifact_file)
        toolbar.addWidget(open_art_btn)

        sample_art_btn = QPushButton("🧪 Örnek Artefaktları Yükle")
        sample_art_btn.clicked.connect(self._load_synthetic_artifacts)
        toolbar.addWidget(sample_art_btn)
        lay.addLayout(toolbar)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)

        self.art_table = ForensicDataTable(
            ["Durum", "Artefakt Türü", "Ad / Dosya", "Hedef / Değer / Yol", "Zaman / Sayaç", "Kaynak"],
            self
        )
        self.art_table.rowSelected.connect(self._on_artifact_selected)
        splitter.addWidget(self.art_table)

        right = QFrame()
        right.setObjectName("surfaceCard")
        right.setFixedWidth(360)
        r_lay = QVBoxLayout(right)
        r_lay.setContentsMargins(10, 10, 10, 10)
        self.art_detail = QTextEdit()
        self.art_detail.setReadOnly(True)
        self.art_detail.setFixedHeight(190)
        self.art_detail.setStyleSheet("font-family: Consolas; font-size: 11px;")
        r_lay.addWidget(self.art_detail)
        self.art_hex = ForensicHexViewer(self)
        r_lay.addWidget(self.art_hex)
        splitter.addWidget(right)

        splitter.setStretchFactor(0, 7)
        splitter.setStretchFactor(1, 3)
        lay.addWidget(splitter, 1)
        return w

    def _scan_live_triage(self):
        res = self.hive_parser.read_live_windows_triage()
        if not res.get("supported"):
            QMessageBox.information(self, "Platform Bilgisi", res.get("reason", "Desteklenmiyor."))
            return

        new_rows: List[Dict[str, Any]] = []
        for cat_items in res["categories"].values():
            for it in cat_items:
                new_rows.append({
                    "Durum": it["Durum"],
                    "Artefakt Türü": it["Kategori"],
                    "Ad / Dosya": it["Ad"],
                    "Hedef / Değer / Yol": it["Değer / Yol"],
                    "Zaman / Sayaç": "Canlı Kayıt",
                    "Kaynak": it["Kaynak"],
                    "_raw": it["Değer / Yol"].encode("utf-8", "replace"),
                })
        self._artifact_rows = new_rows + [r for r in self._artifact_rows if r.get("Zaman / Sayaç") != "Canlı Kayıt"]
        self._apply_artifact_filters()

    def _open_artifact_file(self):
        fp, _ = QFileDialog.getOpenFileName(
            self,
            "Windows Artefakt Dosyası Seç",
            "",
            "Artefaktlar (*.pf *.lnk *.automaticDestinations-ms $I*);;Tüm Dosyalar (*.*)"
        )
        if fp:
            self.load_artifact_file(fp)

    def _collect_kape_triage(self):
        out_dir = QFileDialog.getExistingDirectory(
            self, "KAPE-Stili Triage Çalışma Kopyası Hedef Klasörü Seç", os.path.join("data", "triage_packages")
        )
        if not out_dir:
            return
        res = TriageCollector.collect_live_system_triage(out_dir, max_per_target=25)
        summary_lines = [
            f"{k}: {v['collected']} dosya kopyalandı ({v['skipped']} atlandı)"
            for k, v in res.get("targets", {}).items()
        ]
        msg = "\n".join(summary_lines) if summary_lines else "Erişilebilir canlı triage hedefi bulunamadı."
        QMessageBox.information(
            self,
            "KAPE-Stili Triage Tamamlandı",
            f"Oturum Klasörü:\n{res['session_dir']}\n\n{msg}\n\nHer hedef için SHA-256 triage_manifest.json üretildi."
        )

    def _load_synthetic_artifacts(self):
        paths = create_synthetic_windows_artifacts(os.path.join("data", "sample_win_artifacts"))
        for p in paths.values():
            self.load_artifact_file(p)

    def load_artifact_file(self, path: str):
        base = os.path.basename(path)
        lower_base = base.lower()
        try:
            if lower_base.endswith(".lnk"):
                p = WindowsArtifactParsers.parse_lnk(path)
                ts = p["target_modified"].strftime("%Y-%m-%d %H:%M") if p["target_modified"] else "-"
                self._artifact_rows.insert(0, {
                    "Durum": "Doğrulandı",
                    "Artefakt Türü": p["artifact_type"],
                    "Ad / Dosya": p["filename"],
                    "Hedef / Değer / Yol": p["target_path"],
                    "Zaman / Sayaç": ts,
                    "Kaynak": f"Boyut: {p['target_file_size']:,} B | Dizin: {p['working_dir']}",
                    "_raw": p["raw_bytes"],
                })
            elif lower_base.endswith(".pf"):
                p = WindowsArtifactParsers.parse_prefetch(path)
                ts = p["last_run"].strftime("%Y-%m-%d %H:%M") if p["last_run"] else "-"
                runs_fmt = ", ".join(t.strftime("%Y-%m-%d %H:%M:%S") for t in p.get("last_run_times", [])) or "-"
                loaded_fmt = "\n  • ".join(p.get("loaded_files", [])[:25]) or "(Yok)"
                self._artifact_rows.insert(0, {
                    "Durum": "Uyarı" if p["warnings"] else "Doğrulandı",
                    "Artefakt Türü": p["artifact_type"],
                    "Ad / Dosya": p["executable"],
                    "Hedef / Değer / Yol": f"Hash: {p.get('prefetch_hash', '-')} | Sürüm: {p['version']}",
                    "Zaman / Sayaç": f"{ts} (Çalışma: {p['run_count'] if p['run_count'] is not None else '?'})",
                    "Kaynak": f"{base} | {len(p.get('loaded_files', []))} modül",
                    "_extra_detail": f"SON ÇALIŞTIRMA ZAMANLARI (8 Slot):\n{runs_fmt}\n\nYÜKLENEN DOSYALAR:\n  • {loaded_fmt}",
                    "_raw": p["raw_bytes"],
                })
            elif lower_base.endswith(".automaticdestinations-ms"):
                jl_entries = WindowsArtifactParsers.parse_jump_list(path)
                if not jl_entries:
                    QMessageBox.information(self, "Jump List Boş", f"'{base}' içinde çözümlenebilir LNK akışı bulunamadı.")
                    return
                for jl in jl_entries:
                    ts = jl["target_modified"].strftime("%Y-%m-%d %H:%M") if jl["target_modified"] else "-"
                    self._artifact_rows.insert(0, {
                        "Durum": "Doğrulandı",
                        "Artefakt Türü": jl["artifact_type"],
                        "Ad / Dosya": jl["filename"],
                        "Hedef / Değer / Yol": jl["target_path"],
                        "Zaman / Sayaç": ts,
                        "Kaynak": f"Akış: {jl.get('stream_name', '-')} | Dizin: {jl['working_dir']}",
                        "_raw": jl["raw_bytes"],
                    })
            elif base.startswith("$I"):
                p = WindowsArtifactParsers.parse_recycle_bin_i(path)
                ts = p["deleted_at"].strftime("%Y-%m-%d %H:%M") if p["deleted_at"] else "-"
                self._artifact_rows.insert(0, {
                    "Durum": "İnceleniyor",
                    "Artefakt Türü": p["artifact_type"],
                    "Ad / Dosya": p["filename"],
                    "Hedef / Değer / Yol": p["original_path"],
                    "Zaman / Sayaç": f"Silindi: {ts}",
                    "Kaynak": f"Orijinal Boyut: {p['original_size']:,} B",
                    "_raw": p["raw_bytes"],
                })
            else:
                QMessageBox.warning(self, "Desteklenmeyen Tür", f"'{base}' desteklenen .pf, .lnk, .automaticDestinations-ms veya $I formatında değil.")
                return

            self._apply_artifact_filters()
            if self._artifact_rows:
                self._on_artifact_selected(self._artifact_rows[0])
        except Exception as e:
            QMessageBox.critical(self, "Artefakt Hatası", str(e))

    def _apply_artifact_filters(self):
        rows = list(self._artifact_rows)
        flt = self.art_filter.currentText()
        if flt != "Tüm Artefaktlar":
            rows = [r for r in rows if flt.split(" ")[0].lower() in r["Artefakt Türü"].lower()]
        q = self.art_search.text().lower()
        if q:
            rows = [r for r in rows if any(q in str(v).lower() for k, v in r.items() if k != "_raw")]
        self.art_table.set_records(rows)

    def _on_artifact_selected(self, row: Dict[str, Any]):
        extra = f"\n\n{row['_extra_detail']}" if row.get("_extra_detail") else ""
        self.art_detail.setPlainText(
            f"ARTEFAKT TÜRÜ: {row['Artefakt Türü']}\n"
            f"AD / DOSYA:    {row['Ad / Dosya']}\n"
            f"DURUM:         {row['Durum']}\n"
            f"ZAMAN / SAYAÇ: {row['Zaman / Sayaç']}\n"
            f"KAYNAK:        {row['Kaynak']}\n\n"
            f"HEDEF / DEĞER:\n{row['Hedef / Değer / Yol']}{extra}"
        )
        self.art_hex.load_bytes(row.get("_raw", b""))

    # ------------------------------------------------------------------
    # TAB 4: Network Forensics (.pcap, Hosts & Live Sockets)
    # ------------------------------------------------------------------
    def _build_network_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(10)

        top = QHBoxLayout()
        open_pcap = QPushButton("📦 PCAP Dosyası Aç (.pcap)")
        open_pcap.setObjectName("primaryBtn")
        open_pcap.clicked.connect(self._open_pcap_dialog)
        top.addWidget(open_pcap)

        sample_pcap = QPushButton("🧪 Sentetik DNS/HTTP .pcap Yükle")
        sample_pcap.clicked.connect(self._load_synthetic_pcap)
        top.addWidget(sample_pcap)

        live_net = QPushButton("⚡ Canlı Hosts & Soket Anlık Görüntüsü")
        live_net.clicked.connect(self._scan_live_network)
        top.addWidget(live_net)
        top.addStretch()
        lay.addLayout(top)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)

        self.net_table = ForensicDataTable(
            ["Tür", "Zaman / Satır", "Kaynak", "Hedef / Alan Adı", "Bilgi / PID"], self
        )
        self.net_table.rowSelected.connect(self._on_net_selected)
        splitter.addWidget(self.net_table)

        right = QFrame()
        right.setObjectName("surfaceCard")
        right.setFixedWidth(360)
        r_lay = QVBoxLayout(right)
        r_lay.setContentsMargins(10, 10, 10, 10)
        self.net_detail = QTextEdit()
        self.net_detail.setReadOnly(True)
        self.net_detail.setFixedHeight(190)
        self.net_detail.setStyleSheet("font-family: Consolas; font-size: 11px;")
        r_lay.addWidget(self.net_detail)
        self.net_hex = ForensicHexViewer(self)
        r_lay.addWidget(self.net_hex)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 7)
        splitter.setStretchFactor(1, 3)
        lay.addWidget(splitter, 1)
        return w

    def _open_pcap_dialog(self):
        fp, _ = QFileDialog.getOpenFileName(self, "PCAP Yakalama Dosyası Seç", "", "PCAP (*.pcap);;Tüm Dosyalar (*.*)")
        if fp:
            self.load_pcap(fp)

    def _load_synthetic_pcap(self):
        p = os.path.join("data", "sample_capture.pcap")
        create_synthetic_pcap_file(p)
        self.load_pcap(p)

    def load_pcap(self, path: str):
        try:
            res = NetworkForensicsService.parse_pcap(path)
            rows: List[Dict[str, Any]] = []
            for d in res["dns_queries"]:
                rows.append({
                    "Tür": "DNS Sorgusu",
                    "Zaman / Satır": d["timestamp"],
                    "Kaynak": d["src_ip"],
                    "Hedef / Alan Adı": d["domain"],
                    "Bilgi / PID": f"DNS Sunucu: {d['dst_ip']}",
                    "_raw": d["domain"].encode("utf-8", "replace"),
                })
            for h in res["http_iocs"]:
                rows.append({
                    "Tür": "HTTP IOC",
                    "Zaman / Satır": h["timestamp"],
                    "Kaynak": h["src_ip"],
                    "Hedef / Alan Adı": h["ioc"],
                    "Bilgi / PID": f"Hedef IP: {h['dst_ip']}",
                    "_raw": h["ioc"].encode("utf-8", "replace"),
                })
            for p in res["packets"]:
                rows.append({
                    "Tür": p["protocol"],
                    "Zaman / Satır": p["timestamp"],
                    "Kaynak": p["src"],
                    "Hedef / Alan Adı": p["dst"],
                    "Bilgi / PID": f"Paket #{p['index']} ({p['length']} B)",
                    "_raw": p["_raw"],
                })
            self.net_table.set_records(rows)
            if rows:
                self._on_net_selected(rows[0])
        except Exception as e:
            QMessageBox.critical(self, "PCAP Ayrıştırma Hatası", str(e))

    def _scan_live_network(self):
        rows: List[Dict[str, Any]] = []
        for h in NetworkForensicsService.read_hosts_file():
            rows.append({
                "Tür": "Hosts Kaydı",
                "Zaman / Satır": f"Satır {h['line']}",
                "Kaynak": h["ip"],
                "Hedef / Alan Adı": h["domain"],
                "Bilgi / PID": h["source"],
                "_raw": f"{h['ip']} {h['domain']}".encode("utf-8"),
            })
        for c in NetworkForensicsService.capture_live_connections():
            rows.append({
                "Tür": f"Canlı {c['protocol']}",
                "Zaman / Satır": c["state"],
                "Kaynak": c["local"],
                "Hedef / Alan Adı": c["remote"],
                "Bilgi / PID": f"PID: {c['pid']}",
                "_raw": f"{c['local']} -> {c['remote']}".encode("utf-8"),
            })
        self.net_table.set_records(rows)
        if rows:
            self._on_net_selected(rows[0])

    def _on_net_selected(self, row: Dict[str, Any]):
        self.net_detail.setPlainText(
            f"TÜR:           {row['Tür']}\n"
            f"ZAMAN / SATIR: {row['Zaman / Satır']}\n"
            f"KAYNAK:        {row['Kaynak']}\n"
            f"HEDEF / ALAN:  {row['Hedef / Alan Adı']}\n"
            f"BİLGİ / PID:   {row['Bilgi / PID']}"
        )
        self.net_hex.load_bytes(row.get("_raw", b""))
