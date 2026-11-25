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

    def scan_directory(self, folder: str, max_files: int = 300) -> List[Dict[str, Any]]:
        """Batch-scan a directory with built-in/custom YARA-style rules."""
        if not os.path.isdir(folder):
            raise NotADirectoryError(folder)
        findings: List[Dict[str, Any]] = []
        scanned = 0
        for root, _, files in os.walk(folder):
            for fname in files:
                if scanned >= max_files:
                    return findings
                fp = os.path.join(root, fname)
                scanned += 1
                try:
                    for h in self.scan_file(fp):
                        h["file"] = fname
                        h["path"] = fp
                        findings.append(h)
                except Exception:
                    continue
        return findings


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

    def import_hash_file(self, file_path: str, category: str = "known_bad", source: str = "ImportedList") -> int:
        """Import SHA-256 hashes from .txt/.csv (supports 'sha256' or 'sha256,label' lines)."""
        if not os.path.isfile(file_path):
            raise FileNotFoundError(file_path)
        entries: List[Dict[str, str]] = []
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                raw = line.strip()
                if not raw or raw.startswith("#"):
                    continue
                parts = [p.strip().strip('"') for p in raw.split(",")]
                h = parts[0].lower()
                if len(h) == 64 and all(c in "0123456789abcdef" for c in h):
                    entries.append({
                        "sha256": h,
                        "category": category,
                        "label": parts[1] if len(parts) > 1 else os.path.basename(file_path),
                        "source": source,
                    })
        return self.add_hashes(entries)

    def stats(self) -> Dict[str, int]:
        """Return counts of known_good (NSRL) and known_bad (IOC) hashes."""
        con = sqlite3.connect(self.db_path)
        try:
            good = con.execute("SELECT COUNT(*) FROM hash_sets WHERE category = 'known_good'").fetchone()[0]
            bad = con.execute("SELECT COUNT(*) FROM hash_sets WHERE category = 'known_bad'").fetchone()[0]
            total = con.execute("SELECT COUNT(*) FROM hash_sets").fetchone()[0]
            return {"total": total, "known_good": good, "known_bad": bad}
        finally:
            con.close()
