"""Timeline Analysis Engine: Aggregates multi-source artifacts into standardized UTC timeline."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.database.models import init_db, UsbDeviceRecord, ChainOfCustodyEntry, AuditLog, ForensicArtifact
from src.database.seed import seed_database_if_empty


class TimelineService:
    """Unified chronological timeline aggregator with UTC normalization and source reliability."""

    def __init__(self, db_path: str = "data/forensics.db"):
        self.db_path = db_path
        self.Session = init_db(db_path)
        seed_database_if_empty(db_path)
        self.manual_events: List[Dict[str, Any]] = []

    def add(self, event_type: str, timestamp: Any, source: str, details: str = "", user: str = "-", reliability: str = "Orta"):
        """Add a custom or externally imported event to the timeline."""
        ts_dt = self._parse_ts(timestamp)
        self.manual_events.append({
            "event_type": event_type,
            "timestamp_utc": ts_dt,
            "timestamp": ts_dt.strftime("%Y-%m-%d %H:%M:%S") if ts_dt else str(timestamp),
            "original_timestamp": str(timestamp),
            "timezone_info": "UTC",
            "source": source,
            "user": user,
            "details": details,
            "reliability": reliability,
        })

    def collect_case_timeline(self, case_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """Aggregate chronological UTC events from USB, Custody, Audit Logs, and Artifacts."""
        events: List[Dict[str, Any]] = list(self.manual_events)

        with self.Session() as s:
            # 1. USB Device Events
            usb_q = s.query(UsbDeviceRecord)
            if case_id:
                usb_q = usb_q.filter(UsbDeviceRecord.case_id == case_id)
            for u in usb_q.all():
                if u.first_connected:
                    events.append({
                        "event_type": "USB İlk Bağlantı",
                        "timestamp_utc": u.first_connected,
                        "timestamp": u.first_connected.strftime("%Y-%m-%d %H:%M:%S"),
                        "original_timestamp": u.first_connected.isoformat() + "Z",
                        "timezone_info": "Windows Registry -> UTC",
                        "source": u.registry_source_key or "USBSTOR",
                        "user": u.user_account or "SYSTEM",
                        "details": f"{u.device_name} (VID_{u.vid}&PID_{u.pid} | Seri: {u.serial_number})",
                        "reliability": "Yüksek (Registry + DeviceClasses)",
                    })
                if u.last_connected:
                    events.append({
                        "event_type": "USB Son Bağlantı",
                        "timestamp_utc": u.last_connected,
                        "timestamp": u.last_connected.strftime("%Y-%m-%d %H:%M:%S"),
                        "original_timestamp": u.last_connected.isoformat() + "Z",
                        "timezone_info": "Windows Registry -> UTC",
                        "source": u.registry_source_key or "USBSTOR",
                        "user": u.user_account or "SYSTEM",
                        "details": f"{u.device_name} | Sürücü: {u.drive_letter or '-'}",
                        "reliability": "Yüksek (Registry)",
                    })
                if u.last_removed:
                    events.append({
                        "event_type": "USB Çıkarılma",
                        "timestamp_utc": u.last_removed,
                        "timestamp": u.last_removed.strftime("%Y-%m-%d %H:%M:%S"),
                        "original_timestamp": u.last_removed.isoformat() + "Z",
                        "timezone_info": "Windows Event/Registry -> UTC",
                        "source": u.registry_source_key or "USB",
                        "user": u.user_account or "SYSTEM",
                        "details": f"{u.device_name} bağlantısı kesildi.",
                        "reliability": "Orta (Sistem Durumu)",
                    })

            # 2. Chain of Custody Events
            cust_q = s.query(ChainOfCustodyEntry)
            if case_id:
                cust_q = cust_q.filter(ChainOfCustodyEntry.case_id == case_id)
            for c in cust_q.all():
                if c.timestamp:
                    events.append({
                        "event_type": f"Muhafaza: {c.action_type}",
                        "timestamp_utc": c.timestamp,
                        "timestamp": c.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                        "original_timestamp": c.timestamp.isoformat() + "Z",
                        "timezone_info": "UTC",
                        "source": c.location or "Adli Laboratuvar",
                        "user": c.received_by or "-",
                        "details": f"{c.delivered_by} -> {c.received_by} | Yöntem: {c.acquire_method or '-'}",
                        "reliability": "Yüksek (Doğrulanmış Zincir)",
                    })

            # 3. Audit Log Events
            log_q = s.query(AuditLog)
            if case_id:
                log_q = log_q.filter(AuditLog.case_id == case_id)
            for l in log_q.all():
                if l.timestamp:
                    events.append({
                        "event_type": f"Denetim: {l.action}",
                        "timestamp_utc": l.timestamp,
                        "timestamp": l.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                        "original_timestamp": l.timestamp.isoformat() + "Z",
                        "timezone_info": "UTC",
                        "source": "Adli Uygulama Günlüğü",
                        "user": l.investigator or "-",
                        "details": l.details or "-",
                        "reliability": "Yüksek (Uygulama Kaydı)",
                    })

            # 4. Multi-module ForensicArtifact DB entries
            art_q = s.query(ForensicArtifact)
            if case_id:
                art_q = art_q.filter(ForensicArtifact.case_id == case_id)
            for a in art_q.all():
                if a.normalized_timestamp:
                    events.append({
                        "event_type": f"Artefakt: {a.artifact_type}",
                        "timestamp_utc": a.normalized_timestamp,
                        "timestamp": a.normalized_timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                        "original_timestamp": a.original_timestamp or (a.normalized_timestamp.isoformat() + "Z"),
                        "timezone_info": "UTC",
                        "source": a.source_location or a.source_path or a.parser_name,
                        "user": "-",
                        "details": (a.extracted_data or "")[:200],
                        "reliability": f"%{a.confidence} ({a.parser_name})",
                    })

        events.sort(key=lambda e: e["timestamp_utc"] or datetime.min)
        return events

    def ingest_mft_records(self, mft_records: List[Dict[str, Any]], source_label: str = "$MFT") -> int:
        """Ingest NTFS $MFT $STANDARD_INFORMATION MACB timestamps into the Super-Timeline."""
        added = 0
        for rec in mft_records:
            fpath = rec.get("full_path") or rec.get("filename") or "-"
            for ts_key, ev_label in [
                ("si_created", "MFT Oluşturulma (SI)"),
                ("si_modified", "MFT Değiştirilme (SI)"),
                ("si_mft_modified", "MFT Kayıt Değişimi (SI)"),
            ]:
                dt = rec.get(ts_key)
                if dt:
                    self.add(ev_label, dt, source_label, f"{fpath} (Rec #{rec.get('record_index', '?')})", reliability="Yüksek (NTFS $SI)")
                    added += 1
        return added

    def ingest_evtx_events(self, evtx_events: List[Dict[str, Any]], source_label: str = "EVTX") -> int:
        """Ingest parsed Windows Event Log records into the Super-Timeline."""
        added = 0
        for ev in evtx_events:
            dt = ev.get("timestamp")
            if dt:
                eid = ev.get("event_id", "?")
                desc = ev.get("description", "")
                self.add(f"EVTX Event {eid}", dt, source_label, f"{desc} | {ev.get('details', '')}", reliability="Yüksek (ElfFile EVTX)")
                added += 1
        return added

    def ingest_prefetch(self, pf_dict: Dict[str, Any], source_label: str = "Prefetch") -> int:
        """Ingest all available execution timestamps from a parsed Prefetch (.pf) record."""
        added = 0
        exe = pf_dict.get("executable", "-")
        for idx, dt in enumerate(pf_dict.get("last_run_times", [])):
            self.add(
                "Prefetch Çalıştırma",
                dt,
                pf_dict.get("filename", source_label),
                f"{exe} (Slot #{idx + 1}, Toplam Çalışma: {pf_dict.get('run_count', '?')})",
                reliability="Yüksek (Windows Prefetch)",
            )
            added += 1
        return added

    def ingest_browser_visits(self, visits: List[Dict[str, Any]], browser: str = "Tarayıcı") -> int:
        """Ingest parsed browser URL visits into the Super-Timeline."""
        added = 0
        for v in visits:
            dt = v.get("timestamp")
            if dt:
                self.add(
                    f"Tarayıcı ({browser})",
                    dt,
                    v.get("browser", browser),
                    f"{v.get('title', '')} — {v.get('url', '')}",
                    reliability="Yüksek (SQLite UTC)",
                )
                added += 1
        return added

    def ingest_eml(self, eml_dict: Dict[str, Any]) -> int:
        """Ingest parsed RFC 5322 Email (.eml) timestamp into the Super-Timeline."""
        dt = eml_dict.get("date_utc")
        if dt:
            self.add(
                "E-posta (.eml)",
                dt,
                eml_dict.get("filename", "EML"),
                f"Kimden: {eml_dict.get('from', '-')} -> Kime: {eml_dict.get('to', '-')} | Konu: {eml_dict.get('subject', '-')}",
                reliability="Orta-Yüksek (E-posta Başlığı)",
            )
            return 1
        return 0

    def list(self, start: Optional[datetime] = None, end: Optional[datetime] = None, case_id: Optional[int] = None) -> List[Dict[str, Any]]:
        out = self.collect_case_timeline(case_id=case_id)
        if start:
            out = [e for e in out if e["timestamp_utc"] and e["timestamp_utc"] >= start]
        if end:
            out = [e for e in out if e["timestamp_utc"] and e["timestamp_utc"] <= end]
        return out

    @staticmethod
    def compute_time_delta(dt_a: datetime, dt_b: datetime) -> str:
        """Return human-readable delta between two UTC timestamps."""
        diff = abs((dt_b - dt_a).total_seconds())
        days = int(diff // 86400)
        rem = diff % 86400
        hours = int(rem // 3600)
        rem %= 3600
        minutes = int(rem // 60)
        seconds = int(rem % 60)
        parts = []
        if days:
            parts.append(f"{days} gün")
        if hours:
            parts.append(f"{hours} saat")
        if minutes:
            parts.append(f"{minutes} dk")
        parts.append(f"{seconds} sn")
        return " ".join(parts)

    @staticmethod
    def _parse_ts(val: Any) -> Optional[datetime]:
        if isinstance(val, datetime):
            return val
        if isinstance(val, str):
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
                try:
                    return datetime.strptime(val.strip().rstrip("Z"), fmt)
                except ValueError:
                    continue
        return None
