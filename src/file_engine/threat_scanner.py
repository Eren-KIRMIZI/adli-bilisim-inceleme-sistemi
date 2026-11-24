"""Local Hash Sets (Known-Good NSRL / Known-Bad Malicious) & Pure-Python YARA-Style Rule Scanner."""

import os
import re
import sqlite3
from typing import Any, Dict, List, Optional


DEFAULT_YARA_RULES: List[Dict[str, Any]] = [
    {
        "name": "PowerShell_EncodedCommand",
        "severity": "Yüksek",
        "description": "Gizlenmiş / Base64 kodlu PowerShell çalıştırma parametresi tespit edildi.",
        "patterns": [rb"(?i)powershell(?:\.exe)?\s+.*-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{12,}"],
    },
    {
        "name": "Mimikatz_Credential_Dumping",
        "severity": "Kritik",
        "description": "Mimikatz veya bellek içi kimlik bilgisi dökümü (sekurlsa/lsadump) izi tespit edildi.",
        "patterns": [rb"(?i)(?:sekurlsa::logonpasswords|lsadump::sam|gentilkiwi|mimikatz)"],
    },
    {
        "name": "Suspicious_Exfil_Tools",
        "severity": "Orta",
        "description": "Veri sızdırma amaçlı sık kullanılan araç veya komut izi (rclone / Invoke-WebRequest).",
        "patterns": [rb"(?i)(?:rclone(?:\.exe)?|Invoke-WebRequest\s+-Uri)"],
    },
    {
        "name": "WebShell_Exec_Pattern",
        "severity": "Kritik",
        "description": "WebShell veya uzaktan komut çalıştırma deseni tespit edildi.",
        "patterns": [rb"(?i)(?:eval\s*\(\s*\$_(?:POST|GET|REQUEST)|cmd\.exe\s+/c\s+)"],
    },
]


class YaraStyleScanner:
    """Pure-Python multi-pattern hex/regex scanner compatible with DFIR YARA-style rule sets."""

    def __init__(self, extra_rules: Optional[List[Dict[str, Any]]] = None):
        self.rules = list(DEFAULT_YARA_RULES)
        if extra_rules:
            self.rules.extend(extra_rules)

    def scan_bytes(self, data: bytes) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        for rule in self.rules:
            for pat in rule["patterns"]:
                rx = re.compile(pat)
                m = rx.search(data)
                if m:
                    hits.append({
                        "rule": rule["name"],
                        "severity": rule["severity"],
                        "description": rule["description"],
                        "offset": m.start(),
                        "offset_hex": f"0x{m.start():08X}",
                        "match_preview": m.group(0)[:120].decode("ascii", "replace"),
                    })
                    break
        return hits

    def scan_file(self, path: str, max_bytes: int = 16 * 1024 * 1024) -> List[Dict[str, Any]]:
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        with open(path, "rb") as f:
            data = f.read(max_bytes)
        return self.scan_bytes(data)


class HashSetService:
    """SQLite-indexed SHA-256 hash set database for Known-Good (NSRL) & Known-Bad IOC matching."""

    def __init__(self, db_path: str = "data/hashsets.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self._init_table()

    def _init_table(self) -> None:
        con = sqlite3.connect(self.db_path)
        try:
            con.execute(
                "CREATE TABLE IF NOT EXISTS hash_sets ("
                "sha256 TEXT PRIMARY KEY, "
                "category TEXT NOT NULL, "
                "label TEXT, "
                "source TEXT)"
            )
            con.commit()
        finally:
            con.close()

    def add_hashes(self, entries: List[Dict[str, str]]) -> int:
        """Bulk-insert hashes. Each dict: {'sha256', 'category' ('known_good'|'known_bad'), 'label', 'source'}."""
        con = sqlite3.connect(self.db_path)
        try:
            rows = [
                (e["sha256"].strip().lower(), e["category"], e.get("label", ""), e.get("source", "Manual"))
                for e in entries if e.get("sha256")
            ]
            con.executemany(
                "INSERT OR REPLACE INTO hash_sets (sha256, category, label, source) VALUES (?, ?, ?, ?)",
                rows,
            )
            con.commit()
            return len(rows)
        finally:
            con.close()

    def lookup(self, sha256: str) -> Optional[Dict[str, str]]:
        if not sha256:
            return None
        con = sqlite3.connect(self.db_path)
        try:
            row = con.execute(
                "SELECT sha256, category, label, source FROM hash_sets WHERE sha256 = ?",
                (sha256.strip().lower(),),
            ).fetchone()
            if not row:
                return None
            return {"sha256": row[0], "category": row[1], "label": row[2], "source": row[3]}
        finally:
            con.close()
