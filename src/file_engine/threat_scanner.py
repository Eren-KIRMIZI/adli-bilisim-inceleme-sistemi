"""Local Hash Sets (Known-Good NSRL / Known-Bad Malicious), Pure-Python YARA-Style Scanner & yara-python Bridge."""

import os
import re
import sqlite3
from typing import Any, Dict, List, Optional

try:
    import yara  # type: ignore
    HAS_YARA_PYTHON = True
except ImportError:
    HAS_YARA_PYTHON = False


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

BUILTIN_REAL_YARA_SOURCE = """
rule PowerShell_EncodedCommand {
    meta:
        severity = "Yüksek"
        description = "Gizlenmiş / Base64 kodlu PowerShell çalıştırma parametresi"
    strings:
        $ps = /powershell(\\.exe)?\\s+.*-(e|enc|encodedcommand)\\s+[A-Za-z0-9+\\/=]{12,}/ nocase
    condition:
        $ps
}

rule Mimikatz_Credential_Dumping {
    meta:
        severity = "Kritik"
        description = "Mimikatz / sekurlsa kimlik bilgisi dökümü izi"
    strings:
        $a = "sekurlsa::logonpasswords" nocase
        $b = "lsadump::sam" nocase
        $c = "mimikatz" nocase
    condition:
        any of them
}

rule Suspicious_Exfil_Tools {
    meta:
        severity = "Orta"
        description = "Veri sızdırma amaçlı rclone veya Invoke-WebRequest izi"
    strings:
        $r = "rclone" nocase
        $w = "Invoke-WebRequest -Uri" nocase
    condition:
        any of them
}
"""


class YaraStyleScanner:
    """Dual-mode YARA scanner: uses native yara-python (.yar/.yara) when available, with pure-Python fallback."""

    def __init__(self, extra_rules: Optional[List[Dict[str, Any]]] = None, yar_file: Optional[str] = None):
        self.rules = list(DEFAULT_YARA_RULES)
        if extra_rules:
            self.rules.extend(extra_rules)
        self._compiled_yara = None
        self.engine_backend = "Pure-Python YARA-Stili Motor"
        if HAS_YARA_PYTHON:
            try:
                if yar_file and os.path.isfile(yar_file):
                    self._compiled_yara = yara.compile(filepath=yar_file)
                    self.engine_backend = f"yara-python ({os.path.basename(yar_file)})"
                else:
                    self._compiled_yara = yara.compile(source=BUILTIN_REAL_YARA_SOURCE)
                    self.engine_backend = "yara-python (Yerleşik .yar)"
            except Exception:
                self._compiled_yara = None

    def load_yar_file(self, yar_path: str) -> str:
        """Compile an external .yar / .yara rule file using yara-python."""
        if not HAS_YARA_PYTHON:
            raise RuntimeError("Gerçek .yar dosyası derleme için yara-python paketi gereklidir.")
        if not os.path.isfile(yar_path):
            raise FileNotFoundError(yar_path)
        self._compiled_yara = yara.compile(filepath=yar_path)
        self.engine_backend = f"yara-python ({os.path.basename(yar_path)})"
        return self.engine_backend

    def scan_bytes(self, data: bytes) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        seen_rules = set()
        if self._compiled_yara is not None:
            try:
                for m in self._compiled_yara.match(data=data):
                    off = 0
                    preview = ""
                    if m.strings:
                        first = m.strings[0]
                        if hasattr(first, "instances") and first.instances:
                            off = first.instances[0].offset
                            preview = first.instances[0].matched_data[:120].decode("ascii", "replace")
                    hits.append({
                        "rule": m.rule,
                        "severity": m.meta.get("severity", "Yüksek"),
                        "description": m.meta.get("description", "YARA kural eşleşmesi"),
                        "offset": off,
                        "offset_hex": f"0x{off:08X}",
                        "match_preview": preview or m.rule,
                        "engine": self.engine_backend,
                    })
                    seen_rules.add(m.rule)
            except Exception:
                pass

        for rule in self.rules:
            if any(rule["name"] in sr or sr.endswith(rule["name"]) for sr in seen_rules):
                continue
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
                        "engine": "Pure-Python Fallback",
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
        """Batch-scan a directory with built-in/custom YARA rules."""
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
        con = sqlite3.connect(self.db_path)
        try:
            good = con.execute("SELECT COUNT(*) FROM hash_sets WHERE category='known_good'").fetchone()[0]
            bad = con.execute("SELECT COUNT(*) FROM hash_sets WHERE category='known_bad'").fetchone()[0]
            return {"known_good": good, "known_bad": bad, "total": good + bad}
        finally:
            con.close()
