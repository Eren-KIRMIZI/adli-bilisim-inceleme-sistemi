"""Unit tests for FileAnalysisService, BrowserForensicsEngine, and MemoryForensicsEngine."""

import os
import sqlite3
from src.file_engine.file_service import FileAnalysisService, create_synthetic_exif_jpeg
from src.browser_engine.browser_service import BrowserForensicsEngine, create_synthetic_browser_databases
from src.memory_engine.memory_service import MemoryForensicsEngine, create_synthetic_memory_dump


def test_file_analysis_exif_spoofing_diff_duplicates(tmp_path):
    jpg_path = str(tmp_path / "photo.jpg")
    create_synthetic_exif_jpeg(jpg_path)

    info = FileAnalysisService.analyze(jpg_path)
    assert info["signature_type"] == "JPEG"
    assert info["extension_mismatch"] is False
    assert info["exif"]["Make"] == "Canon"
    assert info["exif"]["Model"] == "Canon EOS R5"

    # Extension spoofing: PE executable named as .jpg
    spoof = tmp_path / "invoice.jpg"
    spoof.write_bytes(b"MZ" + b"\x00" * 100)
    spoof_info = FileAnalysisService.analyze(str(spoof))
    assert spoof_info["extension_mismatch"] is True

    # Diff check
    diff_same = FileAnalysisService.compare_files(jpg_path, jpg_path)
    assert diff_same["identical"] is True
    assert diff_same["first_diff_offset"] is None

    # Duplicate scan
    dup_copy = tmp_path / "invoice_copy.jpg"
    dup_copy.write_bytes(b"MZ" + b"\x00" * 100)
    scan = FileAnalysisService.scan_directory_duplicates(str(tmp_path))
    assert scan["duplicate_groups"] == 1
    assert scan["total_scanned"] == 3


def test_browser_forensics_chrome_and_redacted_cookies(tmp_path):
    paths = create_synthetic_browser_databases(str(tmp_path / "br"))
    eng = BrowserForensicsEngine()

    res = eng.parse_sqlite_artifact(paths["history"], browser_hint="Google Chrome")
    assert len(res["history"]) == 3
    assert len(res["downloads"]) == 1
    assert len(res["searches"]) >= 1

    bmarks = eng.parse_chromium_bookmarks_json(paths["bookmarks"])
    assert len(bmarks) == 2

    # Cookie privacy redaction check
    cookie_db = str(tmp_path / "cookies.sqlite")
    con = sqlite3.connect(cookie_db)
    con.execute("CREATE TABLE cookies (host_key TEXT, name TEXT, encrypted_value BLOB, creation_utc INTEGER, expires_utc INTEGER)")
    con.execute("INSERT INTO cookies VALUES ('.example.com', 'SESSION_SECRET', X'DEADBEEF', 13370000000000000, 13400000000000000)")
    con.commit()
    con.close()

    cres = eng.parse_sqlite_artifact(cookie_db)
    assert len(cres["cookies"]) == 1
    assert "GİZLİ" in cres["cookies"][0]["value_status"]
    assert "DEADBEEF" not in str(cres["cookies"][0])


def test_memory_forensics_dump_and_unsupported_honesty(tmp_path):
    dmp = str(tmp_path / "mem.dmp")
    create_synthetic_memory_dump(dmp)

    eng = MemoryForensicsEngine()
    res = eng.inspect_memory_dump(dmp)
    assert "PAGEDU64" in res["format"]
    assert len(res["kdbg_offsets"]) == 1
    assert len(res["pe_modules"]) == 1
    assert any("198.51.100.42" in i["value"] for i in res["iocs"])

    # Unsupported / random binary must warn explicitly and NOT fabricate processes
    unk = tmp_path / "unknown.ram"
    unk.write_bytes(b"\xAA\xBB\xCC\xDD" * 512)
    ures = eng.inspect_memory_dump(str(unk))
    assert "Bilinmeyen" in ures["format"]
    assert len(ures["warnings"]) >= 1
    assert len(ures["pe_modules"]) == 0
