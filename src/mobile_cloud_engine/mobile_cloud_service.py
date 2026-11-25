"""ALEAPP/iLEAPP-Style Mobile (Android/iOS), Messaging (WhatsApp/SMS/CallLog) & Cloud Sync (OneDrive/Google Drive/M365) Parsers."""

from datetime import datetime, timedelta, timezone
import csv
import json
import os
import plistlib
import shutil
import sqlite3
import tempfile
from typing import Any, Dict, List, Optional


APPLE_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)


def _unix_ms_or_sec_to_iso(val: Optional[int]) -> Optional[str]:
    if not val or val <= 0:
        return None
    try:
        sec = val / 1000.0 if val > 10_000_000_000 else float(val)
        return datetime.fromtimestamp(sec, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OSError, OverflowError, ValueError):
        return None


def _apple_cocoa_to_iso(val: Optional[float]) -> Optional[str]:
    if not val:
        return None
    try:
        dt = APPLE_EPOCH + timedelta(seconds=float(val))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except OverflowError:
        return None


class MobileCloudForensicsService:
    """Read-only parsers for Android/iOS mobile backups, messaging DBs, and Cloud Sync artifacts."""

    @staticmethod
    def _copy_ro(db_path: str, tmp_dir: str) -> sqlite3.Connection:
        dst = os.path.join(tmp_dir, os.path.basename(db_path))
        shutil.copy2(db_path, dst)
        for ext in ("-wal", "-shm"):
            if os.path.isfile(db_path + ext):
                shutil.copy2(db_path + ext, dst + ext)
        return sqlite3.connect(f"file:{dst}?mode=ro", uri=True)

    @classmethod
    def parse_mobile_sqlite(cls, db_path: str, limit: int = 1000) -> Dict[str, Any]:
        """Auto-detect and parse WhatsApp msgstore.db, Android mmssms.db, contacts2.db, calls, or iOS Manifest.db."""
        if not os.path.isfile(db_path):
            raise FileNotFoundError(db_path)

        records: List[Dict[str, Any]] = []
        platform = "Mobil SQLite"
        with tempfile.TemporaryDirectory() as td:
            con = cls._copy_ro(db_path, td)
            try:
                tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}

                # 1. WhatsApp msgstore.db (message / messages)
                if "messages" in tables:
                    platform = "Android WhatsApp (msgstore.db)"
                    cols = {r[1] for r in con.execute("PRAGMA table_info(messages)").fetchall()}
                    ts_col = "timestamp" if "timestamp" in cols else ("received_timestamp" if "received_timestamp" in cols else None)
                    txt_col = "data" if "data" in cols else ("text_data" if "text_data" in cols else None)
                    jid_col = "key_remote_jid" if "key_remote_jid" in cols else ("remote_resource" if "remote_resource" in cols else None)
                    if txt_col and jid_col:
                        q = f"SELECT {jid_col}, {txt_col}, {ts_col or '0'}, key_from_me FROM messages ORDER BY {ts_col or 'rowid'} DESC LIMIT ?"
                        for jid, body, ts, from_me in con.execute(q, (limit,)).fetchall():
                            records.append({
                                "platform": platform,
                                "category": "WhatsApp Mesajı",
                                "actor": f"{'Gönderen (Cihaz)' if from_me else jid}",
                                "peer": str(jid or "-"),
                                "content": str(body or "(Medya/Boş)"),
                                "timestamp": _unix_ms_or_sec_to_iso(ts),
                            })
                elif "message" in tables and "chat" in tables:
                    platform = "Android WhatsApp v2 (msgstore.db)"
                    for row in con.execute(
                        "SELECT COALESCE(text_data, ''), from_me, timestamp, _id FROM message ORDER BY timestamp DESC LIMIT ?",
                        (limit,),
                    ).fetchall():
                        records.append({
                            "platform": platform,
                            "category": "WhatsApp Mesajı",
                            "actor": "Gönderen (Cihaz)" if row[1] else "Karşı Taraf",
                            "peer": f"Msg#{row[3]}",
                            "content": str(row[0] or "(Medya)"),
                            "timestamp": _unix_ms_or_sec_to_iso(row[2]),
                        })

                # 2. Android SMS (mmssms.db -> sms)
                if "sms" in tables:
                    platform = "Android SMS (mmssms.db)"
                    for addr, body, dt_val, typ in con.execute(
                        "SELECT address, body, date, type FROM sms ORDER BY date DESC LIMIT ?", (limit,)
                    ).fetchall():
                        records.append({
                            "platform": platform,
                            "category": "SMS İletisi",
                            "actor": "Gelen" if typ == 1 else "Giden",
                            "peer": str(addr or "-"),
                            "content": str(body or ""),
                            "timestamp": _unix_ms_or_sec_to_iso(dt_val),
                        })

                # 3. Call Log (calls)
                if "calls" in tables:
                    platform = "Android Arama Kaydı (CallLog)"
                    for num, dur, dt_val, typ in con.execute(
                        "SELECT number, duration, date, type FROM calls ORDER BY date DESC LIMIT ?", (limit,)
                    ).fetchall():
                        records.append({
                            "platform": platform,
                            "category": "Arama Kaydı",
                            "actor": {1: "Gelen", 2: "Giden", 3: "Cevapsız"}.get(typ, str(typ)),
                            "peer": str(num or "-"),
                            "content": f"Süre: {dur} sn",
                            "timestamp": _unix_ms_or_sec_to_iso(dt_val),
                        })

                # 4. iOS Backup Manifest.db (Files)
                if "Files" in tables and "Properties" in tables:
                    platform = "iOS Yedek (Manifest.db)"
                    for fid, dom, relp, flags in con.execute(
                        "SELECT fileID, domain, relativePath, flags FROM Files LIMIT ?", (limit,)
                    ).fetchall():
                        records.append({
                            "platform": platform,
                            "category": f"iOS Yedek Öğesi ({dom})",
                            "actor": str(fid)[:16],
                            "peer": str(dom),
                            "content": str(relp),
                            "timestamp": None,
                        })

                # 5. iOS SMS / iMessage (sms.db -> message + handle)
                if "handle" in tables and "message" in tables:
                    platform = "iOS iMessage/SMS (sms.db)"
                    for txt, is_from_me, dt_val, h_id in con.execute(
                        "SELECT m.text, m.is_from_me, m.date, COALESCE(h.id, '-') "
                        "FROM message m LEFT JOIN handle h ON m.handle_id = h.ROWID ORDER BY m.date DESC LIMIT ?",
                        (limit,),
                    ).fetchall():
                        sec = dt_val / 1_000_000_000 if dt_val and dt_val > 1_000_000_000_000 else dt_val
                        records.append({
                            "platform": platform,
                            "category": "iMessage / SMS",
                            "actor": "Gönderen (Cihaz)" if is_from_me else str(h_id),
                            "peer": str(h_id),
                            "content": str(txt or ""),
                            "timestamp": _apple_cocoa_to_iso(sec),
                        })
            finally:
                con.close()

        return {
            "artifact_type": platform,
            "filename": os.path.basename(db_path),
            "record_count": len(records),
            "records": records,
        }

    @staticmethod
    def parse_ios_plist(plist_path: str) -> Dict[str, Any]:
        """Parse binary or XML Apple .plist (Info.plist / Manifest.plist) read-only."""
        if not os.path.isfile(plist_path):
            raise FileNotFoundError(plist_path)
        with open(plist_path, "rb") as f:
            data = plistlib.load(f)
        flat: List[Dict[str, Any]] = []
        if isinstance(data, dict):
            for k, v in list(data.items())[:200]:
                flat.append({
                    "platform": "iOS / macOS Plist",
                    "category": "Plist Anahtarı",
                    "actor": str(k),
                    "peer": os.path.basename(plist_path),
                    "content": str(v)[:240],
                    "timestamp": v.strftime("%Y-%m-%d %H:%M:%S UTC") if isinstance(v, datetime) else None,
                })
        return {"artifact_type": "Apple Plist", "filename": os.path.basename(plist_path), "record_count": len(flat), "records": flat}

    @staticmethod
    def parse_cloud_audit_or_sync(path: str, limit: int = 1000) -> Dict[str, Any]:
        """Parse OneDrive/Google Drive sync logs or Microsoft 365 / Entra ID JSON/CSV Audit Logs."""
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        ext = os.path.splitext(path)[1].lower()
        records: List[Dict[str, Any]] = []
        kind = "Bulut Artefaktı"

        if ext == ".json":
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                doc = json.load(f)
            items = doc if isinstance(doc, list) else doc.get("value", doc.get("records", [doc]))
            kind = "M365 / Entra ID JSON Audit"
            for it in items[:limit]:
                if not isinstance(it, dict):
                    continue
                records.append({
                    "platform": kind,
                    "category": str(it.get("Operation") or it.get("Workload") or it.get("activityDisplayName") or "CloudEvent"),
                    "actor": str(it.get("UserId") or it.get("ClientIP") or it.get("userPrincipalName") or "-"),
                    "peer": str(it.get("ClientIP") or it.get("ObjectId") or "-"),
                    "content": str(it.get("ObjectId") or it.get("SourceFileName") or json.dumps(it, ensure_ascii=False)[:180]),
                    "timestamp": str(it.get("CreationTime") or it.get("activityDateTime") or "-"),
                })
        elif ext == ".csv":
            kind = "M365 / Bulut CSV Denetim Günlüğü"
            with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
                reader = csv.DictReader(f)
                for idx, row in enumerate(reader):
                    if idx >= limit:
                        break
                    records.append({
                        "platform": kind,
                        "category": str(row.get("Operation") or row.get("Operations") or "CloudCSV"),
                        "actor": str(row.get("UserIds") or row.get("UserId") or "-"),
                        "peer": str(row.get("ClientIP") or row.get("IPAddress") or "-"),
                        "content": str(row.get("AuditData") or row.get("ObjectId") or str(row)[:180]),
                        "timestamp": str(row.get("CreationDate") or row.get("CreationTime") or "-"),
                    })
        else:
            # OneDrive / Google Drive plain-text sync logs
            kind = "OneDrive / Google Drive Sync Log"
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    s = line.strip()
                    if not s:
                        continue
                    if any(k in s.lower() for k in ("upload", "download", "sync", "delete", "cid=", "drive", "share")):
                        records.append({
                            "platform": kind,
                            "category": "Bulut Senkronizasyon İz",
                            "actor": "SyncClient",
                            "peer": os.path.basename(path),
                            "content": s[:240],
                            "timestamp": None,
                        })
                        if len(records) >= limit:
                            break

        return {"artifact_type": kind, "filename": os.path.basename(path), "record_count": len(records), "records": records}


def create_synthetic_mobile_cloud_bundle(output_dir: str) -> Dict[str, str]:
    """Create synthetic WhatsApp msgstore.db, iOS Info.plist, and M365 Audit JSON for offline demos/tests."""
    os.makedirs(output_dir, exist_ok=True)

    wa_db = os.path.join(output_dir, "msgstore.db")
    if os.path.exists(wa_db):
        os.remove(wa_db)
    con = sqlite3.connect(wa_db)
    con.execute("CREATE TABLE messages (_id INTEGER PRIMARY KEY, key_remote_jid TEXT, key_from_me INTEGER, data TEXT, timestamp INTEGER)")
    con.executemany(
        "INSERT INTO messages VALUES (?, ?, ?, ?, ?)",
        [
            (1, "905551234567@s.whatsapp.net", 1, "rclone ile bulut klasorune yukledim, arsiv hazir.", 1773570200000),
            (2, "905551234567@s.whatsapp.net", 0, "Tamamdir, USB bellegi temizlemeyi unutma.", 1773570350000),
        ],
    )
    con.commit()
    con.close()

    plist_path = os.path.join(output_dir, "Info.plist")
    with open(plist_path, "wb") as f:
        plistlib.dump({
            "Device Name": "Ahmet iPhone 15 Pro",
            "Product Type": "iPhone16,1",
            "Product Version": "18.1",
            "Serial Number": "F2LX99DFIR01",
            "Last Backup Date": datetime(2026, 3, 15, 11, 0, 0),
        }, f, fmt=plistlib.FMT_BINARY)

    m365_json = os.path.join(output_dir, "m365_audit.json")
    with open(m365_json, "w", encoding="utf-8") as f:
        json.dump([
            {
                "CreationTime": "2026-03-15T10:18:00Z",
                "Operation": "FileDownloaded",
                "UserId": "ahmet.k@sirket.example",
                "ClientIP": "185.220.101.42",
                "SourceFileName": "gizli_maas_tablosu.xlsx",
            },
            {
                "CreationTime": "2026-03-15T10:25:00Z",
                "Operation": "AnonymousLinkCreated",
                "UserId": "ahmet.k@sirket.example",
                "ClientIP": "185.220.101.42",
                "ObjectId": "https://sirket-my.sharepoint.com/:x:/g/personal/ahmet_k/ExfilLink",
            },
        ], f, indent=2, ensure_ascii=False)

    return {"whatsapp_db": wa_db, "ios_plist": plist_path, "m365_audit": m365_json}
