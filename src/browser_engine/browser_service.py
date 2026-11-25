"""Browser Forensics Engine for Chrome, Microsoft Edge, and Mozilla Firefox.

Reads SQLite databases strictly in read-only URI mode (?mode=ro) and redacts
sensitive session/credential secrets by default per forensic privacy policy.
"""

import json
import os
import shutil
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs

WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def webkit_to_utc(microseconds: Optional[int]) -> Optional[datetime]:
    """Convert Chromium WebKit timestamp (microseconds since 1601-01-01) to UTC."""
    if not microseconds or microseconds <= 0:
        return None
    try:
        return (WEBKIT_EPOCH + timedelta(microseconds=int(microseconds))).replace(tzinfo=None)
    except Exception:
        return None


def prtime_to_utc(microseconds: Optional[int]) -> Optional[datetime]:
    """Convert Firefox PRTime (microseconds since 1970-01-01) to UTC."""
    if not microseconds or microseconds <= 0:
        return None
    try:
        return datetime.fromtimestamp(int(microseconds) / 1_000_000, tz=timezone.utc).replace(tzinfo=None)
    except Exception:
        return None


class BrowserForensicsEngine:
    """Read-only parser for Chromium (Chrome/Edge) and Gecko (Firefox) artifacts."""

    PARSER_NAME = "AdliBilisim-Original-Browser-Engine"
    PARSER_VERSION = "1.0.0"

    def discover_local_profiles(self) -> List[Dict[str, str]]:
        """Discover local Windows browser History/Bookmarks/Cookies paths (read-only)."""
        profiles: List[Dict[str, str]] = []
        local_app = os.environ.get("LOCALAPPDATA", "")
        roaming_app = os.environ.get("APPDATA", "")

        roots = [
            ("Google Chrome", os.path.join(local_app, "Google", "Chrome", "User Data")),
            ("Microsoft Edge", os.path.join(local_app, "Microsoft", "Edge", "User Data")),
        ]
        for bname, root_dir in roots:
            if not root_dir or not os.path.isdir(root_dir):
                continue
            for entry in sorted(os.listdir(root_dir)):
                if entry != "Default" and not entry.startswith("Profile "):
                    continue
                pdir = os.path.join(root_dir, entry)
                if not os.path.isdir(pdir):
                    continue
                hist = os.path.join(pdir, "History")
                bmarks = os.path.join(pdir, "Bookmarks")
                cookies = os.path.join(pdir, "Network", "Cookies")
                if not os.path.isfile(cookies):
                    cookies = os.path.join(pdir, "Cookies")
                if os.path.isfile(hist) or os.path.isfile(bmarks):
                    profiles.append({
                        "browser": bname,
                        "profile": entry,
                        "path": pdir,
                        "history": hist if os.path.isfile(hist) else "",
                        "bookmarks": bmarks if os.path.isfile(bmarks) else "",
                        "cookies": cookies if os.path.isfile(cookies) else "",
                    })

        ff_root = os.path.join(roaming_app, "Mozilla", "Firefox", "Profiles")
        if roaming_app and os.path.isdir(ff_root):
            for entry in os.listdir(ff_root):
                pdir = os.path.join(ff_root, entry)
                places = os.path.join(pdir, "places.sqlite")
                cookies = os.path.join(pdir, "cookies.sqlite")
                if os.path.isfile(places):
                    profiles.append({
                        "browser": "Mozilla Firefox",
                        "profile": entry,
                        "path": pdir,
                        "history": places,
                        "bookmarks": places,
                        "cookies": cookies if os.path.isfile(cookies) else "",
                    })
        return profiles

    def parse_sqlite_artifact(
        self,
        db_path: str,
        browser_hint: str = "Otomatik",
        profile_name: str = "Default",
        max_rows: int = 5000,
    ) -> Dict[str, Any]:
        """Parse Chrome/Edge/Firefox SQLite safely using a read-only WAL/SHM-aware working copy and truncation warnings."""
        if not os.path.isfile(db_path):
            raise FileNotFoundError(f"Veritabanı bulunamadı: {db_path}")

        # Copy DB + optional -wal/-shm sidecars to isolated temp dir so uncheckpointed WAL frames are read cleanly
        tmp_dir_ctx = tempfile.TemporaryDirectory(prefix="dfir_br_")
        tmp_db = os.path.join(tmp_dir_ctx.name, os.path.basename(db_path))
        shutil.copy2(db_path, tmp_db)
        for suffix in ("-wal", "-shm"):
            sidecar = db_path + suffix
            if os.path.isfile(sidecar):
                try:
                    shutil.copy2(sidecar, tmp_db + suffix)
                except Exception:
                    pass

        uri = f"file:{os.path.abspath(tmp_db)}?mode=ro"
        con = sqlite3.connect(uri, uri=True)
        cur = con.cursor()
        warnings: List[str] = []
        try:
            tables = {r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            history: List[Dict[str, Any]] = []
            downloads: List[Dict[str, Any]] = []
            searches: List[Dict[str, Any]] = []
            bookmarks: List[Dict[str, Any]] = []
            cookies: List[Dict[str, Any]] = []
            detected_browser = browser_hint

            # Chromium History DB (prefer per-visit join urls + visits; fallback to urls if visits empty)
            if "urls" in tables and "visits" in tables:
                if detected_browser == "Otomatik":
                    detected_browser = "Google Chrome / Edge (Chromium)"
                visit_rows = cur.execute(
                    f"SELECT u.url, u.title, u.visit_count, v.visit_time FROM visits v "
                    f"JOIN urls u ON v.url = u.id ORDER BY v.visit_time DESC LIMIT {max_rows + 1}"
                ).fetchall()
                if len(visit_rows) > max_rows:
                    warnings.append(f"⚠️ Ziyaret geçmişi {max_rows:,} kayıt sınırına ulaştı; devamı kesildi.")
                    visit_rows = visit_rows[:max_rows]
                if not visit_rows:
                    visit_rows = cur.execute(
                        f"SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT {max_rows}"
                    ).fetchall()

                for url, title, vcount, last_vt in visit_rows:
                    ts = webkit_to_utc(last_vt)
                    history.append({
                        "browser": detected_browser,
                        "profile": profile_name,
                        "url": url,
                        "title": title or "-",
                        "visit_count": vcount,
                        "timestamp_utc": ts,
                        "source": f"{os.path.basename(db_path)}::visits+urls",
                    })
                    q_term = self._extract_search_query(url)
                    if q_term:
                        searches.append({
                            "browser": detected_browser,
                            "profile": profile_name,
                            "term": q_term,
                            "url": url,
                            "timestamp_utc": ts,
                            "source": "URL Parametresi",
                        })

            if "keyword_search_terms" in tables and "urls" in tables:
                k_rows = cur.execute(
                    f"SELECT k.term, u.url, u.last_visit_time FROM keyword_search_terms k "
                    f"JOIN urls u ON k.url_id = u.id ORDER BY u.last_visit_time DESC LIMIT {max_rows + 1}"
                ).fetchall()
                if len(k_rows) > max_rows:
                    warnings.append(f"⚠️ Arama terimleri {max_rows:,} kayıt sınırına ulaştı.")
                    k_rows = k_rows[:max_rows]
                for term, url, last_vt in k_rows:
                    searches.append({
                        "browser": detected_browser,
                        "profile": profile_name,
                        "term": term,
                        "url": url,
                        "timestamp_utc": webkit_to_utc(last_vt),
                        "source": "keyword_search_terms",
                    })

            if "downloads" in tables:
                cols = {r[1] for r in cur.execute("PRAGMA table_info(downloads)").fetchall()}
                path_col = "target_path" if "target_path" in cols else ("current_path" if "current_path" in cols else "''")
                url_col = "tab_url" if "tab_url" in cols else "''"
                d_rows = cur.execute(
                    f"SELECT {path_col}, total_bytes, start_time, {url_col} FROM downloads ORDER BY start_time DESC LIMIT {max_rows + 1}"
                ).fetchall()
                if len(d_rows) > max_rows:
                    warnings.append(f"⚠️ İndirmeler {max_rows:,} kayıt sınırına ulaştı.")
                    d_rows = d_rows[:max_rows]
                for tpath, total_b, start_t, turl in d_rows:
                    downloads.append({
                        "browser": detected_browser,
                        "profile": profile_name,
                        "target_path": tpath or "-",
                        "source_url": turl or "-",
                        "total_bytes": total_b or 0,
                        "timestamp_utc": webkit_to_utc(start_t),
                        "source": f"{os.path.basename(db_path)}::downloads",
                    })

            # Firefox places.sqlite
            if "moz_places" in tables:
                detected_browser = "Mozilla Firefox"
                ff_rows = cur.execute(
                    f"SELECT url, title, visit_count, last_visit_date FROM moz_places ORDER BY last_visit_date DESC LIMIT {max_rows + 1}"
                ).fetchall()
                if len(ff_rows) > max_rows:
                    warnings.append(f"⚠️ Firefox geçmişi {max_rows:,} kayıt sınırına ulaştı.")
                    ff_rows = ff_rows[:max_rows]
                for url, title, vcount, last_vt in ff_rows:
                    ts = prtime_to_utc(last_vt)
                    history.append({
                        "browser": detected_browser,
                        "profile": profile_name,
                        "url": url,
                        "title": title or "-",
                        "visit_count": vcount or 0,
                        "timestamp_utc": ts,
                        "source": "places.sqlite::moz_places",
                    })
                    q_term = self._extract_search_query(url)
                    if q_term:
                        searches.append({
                            "browser": detected_browser,
                            "profile": profile_name,
                            "term": q_term,
                            "url": url,
                            "timestamp_utc": ts,
                            "source": "URL Parametresi",
                        })

            if "moz_bookmarks" in tables and "moz_places" in tables:
                for btitle, url, added in cur.execute(
                    f"SELECT b.title, p.url, b.dateAdded FROM moz_bookmarks b "
                    f"JOIN moz_places p ON b.fk = p.id WHERE b.type = 1 LIMIT {max_rows}"
                ):
                    bookmarks.append({
                        "browser": detected_browser,
                        "profile": profile_name,
                        "title": btitle or "-",
                        "url": url,
                        "timestamp_utc": prtime_to_utc(added),
                        "source": "places.sqlite::moz_bookmarks",
                    })

            # Cookie Metadata ONLY (never extract secret token values)
            if "cookies" in tables:
                if detected_browser == "Otomatik":
                    detected_browser = "Chromium (Cookies)"
                for host, name, created_utc, expires_utc in cur.execute(
                    f"SELECT host_key, name, creation_utc, expires_utc FROM cookies ORDER BY creation_utc DESC LIMIT {max_rows}"
                ):
                    cookies.append({
                        "browser": detected_browser,
                        "profile": profile_name,
                        "host": host,
                        "cookie_name": name,
                        "value_status": "[GİZLİ — Güvenlik İlkesi Gereği Çıkarılmadı]",
                        "created_utc": webkit_to_utc(created_utc),
                        "expires_utc": webkit_to_utc(expires_utc),
                        "source": "Cookies::cookies",
                    })
            elif "moz_cookies" in tables:
                detected_browser = "Mozilla Firefox"
                for host, name, ctime, expiry in cur.execute(
                    f"SELECT host, name, creationTime, expiry FROM moz_cookies ORDER BY creationTime DESC LIMIT {max_rows}"
                ):
                    cookies.append({
                        "browser": detected_browser,
                        "profile": profile_name,
                        "host": host,
                        "cookie_name": name,
                        "value_status": "[GİZLİ — Güvenlik İlkesi Gereği Çıkarılmadı]",
                        "created_utc": prtime_to_utc(ctime),
                        "expires_utc": datetime.fromtimestamp(expiry, tz=timezone.utc).replace(tzinfo=None) if expiry else None,
                        "source": "cookies.sqlite::moz_cookies",
                    })

            return {
                "browser": detected_browser,
                "tables": sorted(tables),
                "history": history,
                "downloads": downloads,
                "searches": searches,
                "bookmarks": bookmarks,
                "cookies": cookies,
                "warnings": warnings,
            }
        finally:
            con.close()
            tmp_dir_ctx.cleanup()

    def parse_chromium_bookmarks_json(self, json_path: str, browser_name: str = "Google Chrome", profile: str = "Default") -> List[Dict[str, Any]]:
        """Parse Chromium Bookmarks JSON file read-only."""
        with open(json_path, "r", encoding="utf-8") as f:
            doc = json.load(f)
        out: List[Dict[str, Any]] = []

        def walk(node: Dict[str, Any]):
            if node.get("type") == "url":
                added = node.get("date_added")
                ts = webkit_to_utc(int(added)) if added and str(added).isdigit() else None
                out.append({
                    "browser": browser_name,
                    "profile": profile,
                    "title": node.get("name", "-"),
                    "url": node.get("url", "-"),
                    "timestamp_utc": ts,
                    "source": os.path.basename(json_path),
                })
            for ch in node.get("children", []):
                walk(ch)

        for root in doc.get("roots", {}).values():
            if isinstance(root, dict):
                walk(root)
        return out

    def _extract_search_query(self, url: str) -> Optional[str]:
        try:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            for key in ("q", "query", "search", "p"):
                if key in qs and qs[key]:
                    return qs[key][0]
        except Exception:
            pass
        return None


def create_synthetic_browser_databases(output_dir: str) -> Dict[str, str]:
    """Create realistic synthetic Chrome History SQLite & Bookmarks JSON for offline testing."""
    os.makedirs(output_dir, exist_ok=True)
    hist_path = os.path.join(output_dir, "Chrome_History.sqlite")
    bmark_path = os.path.join(output_dir, "Chrome_Bookmarks.json")

    if os.path.exists(hist_path):
        os.remove(hist_path)

    def to_wk(dt: datetime) -> int:
        return int((dt.replace(tzinfo=timezone.utc) - WEBKIT_EPOCH).total_seconds() * 1_000_000)

    con = sqlite3.connect(hist_path)
    cur = con.cursor()
    cur.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER)")
    cur.execute("CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)")
    cur.execute("CREATE TABLE keyword_search_terms (keyword_id INTEGER, url_id INTEGER, term TEXT)")
    cur.execute("CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT, total_bytes INTEGER, start_time INTEGER, tab_url TEXT)")

    t1 = to_wk(datetime(2026, 11, 20, 18, 12, 5))
    t2 = to_wk(datetime(2026, 11, 20, 19, 30, 44))
    t3 = to_wk(datetime(2026, 11, 20, 19, 35, 10))

    cur.execute("INSERT INTO urls VALUES (1, 'https://www.google.com/search?q=usb+data+exfiltration+powershell', 'usb data exfiltration - Google Search', 2, ?)", (t1,))
    cur.execute("INSERT INTO urls VALUES (2, 'https://transfer.example-cloud.test/upload', 'AnonFile Upload Portal', 4, ?)", (t2,))
    cur.execute("INSERT INTO urls VALUES (3, 'https://intranet.corp.local/hr/maas_2026.xlsx', 'İK Maaş Raporu', 1, ?)", (t3,))
    cur.execute("INSERT INTO visits VALUES (1, 1, ?), (2, 2, ?), (3, 3, ?)", (t1, t2, t3))
    cur.execute("INSERT INTO keyword_search_terms VALUES (1, 1, 'usb data exfiltration powershell')")
    cur.execute("INSERT INTO downloads VALUES (1, 'C:\\Users\\AhmetK\\Downloads\\rclone-v1.68-windows-amd64.zip', 18450210, ?, 'https://downloads.rclone.org/rclone.zip')", (t2,))
    con.commit()
    con.close()

    with open(bmark_path, "w", encoding="utf-8") as f:
        json.dump({
            "roots": {
                "bookmark_bar": {
                    "type": "folder",
                    "children": [
                        {"type": "url", "name": "Kurumsal Portal", "url": "https://intranet.corp.local", "date_added": str(t1)},
                        {"type": "url", "name": "Harici Depolama", "url": "https://transfer.example-cloud.test", "date_added": str(t2)},
                    ],
                }
            }
        }, f, indent=2)

    return {"history": hist_path, "bookmarks": bmark_path}
