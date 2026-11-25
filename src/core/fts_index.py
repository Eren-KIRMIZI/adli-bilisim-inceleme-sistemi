"""SQLite FTS5 Full-Text Indexing & Keyword Search Engine for Forensic Files & Artifacts."""

import os
import re
import sqlite3
import zipfile
from typing import Any, Dict, List


TEXT_EXTENSIONS = (
    ".txt", ".log", ".csv", ".json", ".jsonl", ".xml", ".ps1", ".bat", ".cmd",
    ".py", ".js", ".html", ".htm", ".eml", ".mbox", ".ini", ".cfg", ".yml", ".yaml",
)


class ForensicFtsIndex:
    """SQLite FTS5 full-text search index over case directories, documents (DOCX/XML/PDF strings), and artifacts."""

    def __init__(self, db_path: str = "data/fts_index.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self._init_fts()

    def _init_fts(self) -> None:
        con = sqlite3.connect(self.db_path)
        try:
            con.execute(
                "CREATE VIRTUAL TABLE IF NOT EXISTS forensic_docs "
                "USING fts5(path, title, source_type, content, tokenize='unicode61')"
            )
            con.commit()
        finally:
            con.close()

    @staticmethod
    def extract_searchable_text(path: str, max_bytes: int = 2 * 1024 * 1024) -> str:
        ext = os.path.splitext(path)[1].lower()
        if ext == ".docx" and zipfile.is_zipfile(path):
            try:
                with zipfile.ZipFile(path, "r") as zf:
                    if "word/document.xml" in zf.namelist():
                        xml_raw = zf.read("word/document.xml").decode("utf-8", "replace")
                        return re.sub(r"<[^>]+>", " ", xml_raw)[:max_bytes]
            except Exception:
                pass
        with open(path, "rb") as f:
            raw = f.read(max_bytes)
        if ext in TEXT_EXTENSIONS:
            return raw.decode("utf-8", "replace")
        # Extract printable ASCII & UTF-16LE strings from PDF/binary files
        ascii_runs = [m.decode("ascii", "replace") for m in re.findall(rb"[ -~]{5,180}", raw)]
        return "\n".join(ascii_runs[:5000])

    def index_document(self, path: str, title: str, source_type: str, content: str) -> None:
        con = sqlite3.connect(self.db_path)
        try:
            con.execute("DELETE FROM forensic_docs WHERE path = ?", (path,))
            con.execute(
                "INSERT INTO forensic_docs (path, title, source_type, content) VALUES (?, ?, ?, ?)",
                (path, title, source_type, content),
            )
            con.commit()
        finally:
            con.close()

    def index_directory(self, folder: str, max_files: int = 500) -> int:
        if not os.path.isdir(folder):
            raise NotADirectoryError(folder)
        indexed = 0
        con = sqlite3.connect(self.db_path)
        try:
            for root, _, files in os.walk(folder):
                for fn in files:
                    if indexed >= max_files:
                        con.commit()
                        return indexed
                    fp = os.path.join(root, fn)
                    try:
                        txt = self.extract_searchable_text(fp)
                        if txt.strip():
                            con.execute("DELETE FROM forensic_docs WHERE path = ?", (fp,))
                            con.execute(
                                "INSERT INTO forensic_docs (path, title, source_type, content) VALUES (?, ?, ?, ?)",
                                (fp, fn, os.path.splitext(fn)[1].lower() or "file", txt),
                            )
                            indexed += 1
                    except Exception:
                        continue
            con.commit()
            return indexed
        finally:
            con.close()

    def search(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        q = (query or "").strip()
        if not q:
            return []
        con = sqlite3.connect(self.db_path)
        try:
            rows = con.execute(
                "SELECT path, title, source_type, snippet(forensic_docs, 3, '[', ']', '...', 18), bm25(forensic_docs) "
                "FROM forensic_docs WHERE forensic_docs MATCH ? ORDER BY bm25(forensic_docs) LIMIT ?",
                (q, limit),
            ).fetchall()
            return [
                {
                    "path": r[0],
                    "title": r[1],
                    "source_type": r[2],
                    "snippet": r[3],
                    "score": round(abs(float(r[4])), 3),
                }
                for r in rows
            ]
        except sqlite3.OperationalError:
            # Safe quoted phrase fallback for queries with special FTS5 punctuation (e.g. URLs/IPs)
            safe_q = '"' + q.replace('"', '""') + '"'
            rows = con.execute(
                "SELECT path, title, source_type, snippet(forensic_docs, 3, '[', ']', '...', 18), bm25(forensic_docs) "
                "FROM forensic_docs WHERE forensic_docs MATCH ? ORDER BY bm25(forensic_docs) LIMIT ?",
                (safe_q, limit),
            ).fetchall()
            return [
                {"path": r[0], "title": r[1], "source_type": r[2], "snippet": r[3], "score": round(abs(float(r[4])), 3)}
                for r in rows
            ]
        finally:
            con.close()

    def stats(self) -> Dict[str, int]:
        con = sqlite3.connect(self.db_path)
        try:
            cnt = con.execute("SELECT COUNT(*) FROM forensic_docs").fetchone()[0]
            return {"indexed_documents": cnt}
        finally:
            con.close()
