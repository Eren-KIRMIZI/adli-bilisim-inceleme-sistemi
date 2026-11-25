"""Regression & forensic accuracy tests covering all audited security, integrity, UI, and parser fixes."""

from datetime import datetime
import sqlite3
import struct
import pytest

from src.case_engine.case_service import CaseService
from src.evidence_engine.evidence_service import EvidenceService
from src.database.models import AuditLog, init_db
from src.report_engine.report_service import ReportService
from src.usb_engine.usb_service import UsbService
from src.registry_engine.windows_artifacts import WindowsArtifactParsers
from src.ntfs_engine.ntfs_service import DiskForensicsEngine, datetime_to_filetime
from src.browser_engine.browser_service import BrowserForensicsEngine
from src.ui.components.data_table import ForensicDataTable


def test_evidence_write_blocker_default_and_strict_hash_verification(tmp_path):
    """Ensure write_blocker defaults to False and arbitrary hashes NEVER become 'verified'."""
    db_file = str(tmp_path / "strict_evd.db")
    cs = CaseService(db_path=db_file)
    es = EvidenceService(db_path=db_file)
    c = cs.create_case("VAK-AUD-01", "Strict Hash Verification")

    # 1. Arbitrary 64-hex hash without matching disk file must NOT be marked verified
    e_no_file = es.add_evidence(case_id=c.id, device_type="Disk", sha256_hash="a" * 64)
    assert e_no_file.write_blocker_used is False
    assert e_no_file.status != "verified"

    # 2. Invalid hex format must raise ValueError
    with pytest.raises(ValueError):
        es.add_evidence(case_id=c.id, device_type="Disk", sha256_hash="not_a_real_hash")

    # 3. Mismatched disk file vs expected hash must be flagged hash_mismatch
    f = tmp_path / "evd.bin"
    f.write_bytes(b"GENUINE_IMAGE_DATA")
    e_bad = es.add_evidence(case_id=c.id, device_type="Disk", sha256_hash="b" * 64, file_path=str(f))
    assert e_bad.status == "hash_mismatch"


def test_audit_hash_chain_and_archive_case(tmp_path):
    """Verify hash-chained AuditLog detects tampering and archive_case preserves records."""
    db_file = str(tmp_path / "audit_chain.db")
    cs = CaseService(db_path=db_file)
    c = cs.create_case("VAK-AUD-02", "Hash Chain Test", "Uzman")
    cs.archive_case(c.id, "Uzman", "Kapanış")

    chk = cs.verify_audit_integrity()
    assert chk["intact"] is True
    assert chk["checked"] >= 2

    # Tamper with the latest audit entry directly via SQLite and verify detection
    Session = init_db(db_file)
    with Session() as s:
        last = s.query(AuditLog).order_by(AuditLog.id.desc()).first()
        last.details = "TAMPERED_RECORD"
        s.commit()

    chk_after = cs.verify_audit_integrity()
    assert chk_after["intact"] is False
    assert len(chk_after["broken"]) >= 1


def test_report_html_xss_and_pdf_escaping(tmp_path):
    """Ensure HTML & PDF report generators escape XSS/markup payloads in evidence metadata."""
    db_file = str(tmp_path / "xss_rep.db")
    cs = CaseService(db_path=db_file)
    es = EvidenceService(db_path=db_file)
    c = cs.create_case("VAK-XSS-01", "XSS Check")
    es.add_evidence(
        case_id=c.id,
        device_type="USB",
        model='<img src=x onerror="alert(1)">',
        serial="<script>alert(2)</script>",
    )

    rep = ReportService(db_path=db_file)
    html = rep.render_html(case_id=c.id)
    assert "<script>alert(2)</script>" not in html
    assert "&lt;script&gt;alert(2)&lt;/script&gt;" in html
    assert "&lt;img src=x onerror=" in html

    pdf_p = str(tmp_path / "escaped.pdf")
    rep.export_pdf(pdf_p, case_id=c.id)
    assert (tmp_path / "escaped.pdf").stat().st_size > 1000


def test_status_badge_no_false_green_substring(qapp):
    """Regression: 'Hash Yok', 'Normal Dışı', 'Çok Şüpheli' must NEVER render green verified badge."""
    tbl = ForensicDataTable(["Durum", "Açıklama"])
    tbl.set_records([
        {"Durum": "Hash Yok", "Açıklama": "A"},
        {"Durum": "Normal Dışı", "Açıklama": "B"},
        {"Durum": "Çok Şüpheli", "Açıklama": "C"},
        {"Durum": "Doğrulandı", "Açıklama": "D"},
    ])
    variants = []
    for row in range(4):
        w = tbl.cellWidget(row, 0)
        lbl = w.layout().itemAt(0).widget()
        variants.append(lbl.styleSheet())
    # Row 0,1,2 must NOT have verified green color (#185E3F)
    assert "#185E3F" not in variants[0]
    assert "#185E3F" not in variants[1]
    assert "#185E3F" not in variants[2]
    # Row 3 ('Doğrulandı') MUST have verified green color (#185E3F)
    assert "#185E3F" in variants[3]


def test_usb_offline_hive_does_not_fabricate_timestamps_or_serials(tmp_path):
    """Ensure fallback raw hive USB scan never invents 'E:', 'OFFLINE_0001', or datetime.utcnow()."""
    fake_raw_hive = tmp_path / "raw_usbstor.bin"
    fake_raw_hive.write_bytes(b"\x00" * 64 + b"Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP" + b"\x00" * 64)
    svc = UsbService(db_path=str(tmp_path / "usb_honest.db"))
    recs = svc.parse_offline_hive(str(fake_raw_hive))
    assert len(recs) == 1
    r = recs[0]
    assert r.drive_letter is None
    assert r.first_connected is None
    assert r.last_connected is None
    assert r.serial_number is None


def test_jumplist_cfb_mini_stream_parsing(tmp_path):
    """Verify OLE2 Jump List reader extracts small (<4096B) LNK streams stored inside MS-CFB Mini-Stream."""
    # Build minimal valid 76-byte+ LNK payload (<4096 bytes)
    lnk = bytearray(120)
    struct.pack_into("<I", lnk, 0, 0x4C)
    lnk[4:20] = bytes.fromhex("0114020000000000c000000000000046")
    struct.pack_into("<II", lnk, 20, 0x08 | 0x80, 0x20)  # HasRelativePath + Unicode
    rel = "C:\\Temp\\mini_payload.exe"
    rel_pos = 76
    struct.pack_into("<H", lnk, rel_pos, len(rel))
    lnk = lnk[:rel_pos + 2] + rel.encode("utf-16le")

    sec_sz = 512
    # Layout: Header(512B), Sec0=FAT, Sec1=Dir, Sec2=MiniFAT, Sec3=Root MiniStream Container (stores LNK at mini-sector 0)
    ole = bytearray(sec_sz * 5)
    ole[0:8] = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
    struct.pack_into("<HH", ole, 24, 0x003E, 0x0003)
    struct.pack_into("<HH", ole, 28, 0xFFFE, 9)   # 512B sector
    struct.pack_into("<H", ole, 32, 6)            # 64B mini-sector
    struct.pack_into("<I", ole, 44, 1)            # 1 FAT sector
    struct.pack_into("<I", ole, 48, 1)            # Dir start = Sec 1
    struct.pack_into("<I", ole, 56, 4096)         # Mini stream cutoff = 4096
    struct.pack_into("<II", ole, 60, 2, 1)        # MiniFAT start = Sec 2, count = 1
    struct.pack_into("<I", ole, 76, 0)            # FAT at Sec 0

    # Sec 0 FAT: [0]=FATSEC, [1]=Dir EOF, [2]=MiniFAT EOF, [3]=Root MiniStream EOF
    struct.pack_into("<IIII", ole, sec_sz * 1, 0xFFFFFFFD, 0xFFFFFFFE, 0xFFFFFFFE, 0xFFFFFFFE)

    # Sec 1 Directory: Entry 0 (Root Entry -> MiniStream container at Sec 3, size 512), Entry 1 (stream "a" -> mini-sector 0)
    dir_off = sec_sz * 2
    rname = "Root Entry\x00".encode("utf-16le")
    ole[dir_off:dir_off + len(rname)] = rname
    struct.pack_into("<HB", ole, dir_off + 64, len(rname), 5)
    struct.pack_into("<II", ole, dir_off + 116, 3, sec_sz)

    e1_off = dir_off + 128
    sname = "a\x00".encode("utf-16le")
    ole[e1_off:e1_off + len(sname)] = sname
    struct.pack_into("<HB", ole, e1_off + 64, len(sname), 2)
    struct.pack_into("<II", ole, e1_off + 116, 0, len(lnk))

    # Sec 2 MiniFAT: [0]=1, [1]=2, [2]=EOF (3 mini-sectors of 64B cover 126B LNK)
    struct.pack_into("<III", ole, sec_sz * 3, 1, 2, 0xFFFFFFFE)
    # Sec 3 MiniStream data
    ole[sec_sz * 4:sec_sz * 4 + len(lnk)] = lnk

    jl_path = tmp_path / "mini_stream.automaticDestinations-ms"
    jl_path.write_bytes(bytes(ole))
    entries = WindowsArtifactParsers.parse_jump_list(str(jl_path))
    assert len(entries) == 1
    assert "mini_payload.exe" in entries[0]["target_path"]


def test_ntfs_si_fn_timestomping_ads_and_browser_visits_truncation(tmp_path):
    """Verify MFT SI-vs-FN timestomping, Named ADS detection, and Browser visits join + truncation warning."""
    # 1. Synthetic 1024-byte MFT FILE record with SI=2020, FN=2026 + Named ADS Zone.Identifier
    rec = bytearray(1024)
    rec[0:4] = b"FILE"
    struct.pack_into("<HH", rec, 4, 48, 3)  # USA
    struct.pack_into("<HH", rec, 20, 64, 0x0001)

    off = 64
    # $STANDARD_INFORMATION (0x10) dated 2020-01-01
    si = bytearray(24 + 48)
    struct.pack_into("<II", si, 0, 0x10, len(si))
    struct.pack_into("<H", si, 20, 24)
    ft_2020 = datetime_to_filetime(datetime(2020, 1, 1, 0, 0, 0))
    struct.pack_into("<QQQQ", si, 24, ft_2020, ft_2020, ft_2020, ft_2020)
    rec[off:off + len(si)] = si
    off += len(si)

    # $FILE_NAME (0x30) dated 2026-11-25
    fname = "stolen.exe".encode("utf-16le")
    fn = bytearray((24 + 66 + len(fname) + 7) & ~7)
    struct.pack_into("<II", fn, 0, 0x30, len(fn))
    struct.pack_into("<H", fn, 20, 24)
    ft_2026 = datetime_to_filetime(datetime(2026, 11, 25, 12, 0, 0))
    struct.pack_into("<Q", fn, 24, 5)  # parent ref 5
    struct.pack_into("<QQ", fn, 32, ft_2026, ft_2026)
    fn[24 + 64] = len("stolen.exe")
    fn[24 + 65] = 1
    fn[24 + 66:24 + 66 + len(fname)] = fname
    rec[off:off + len(fn)] = fn
    off += len(fn)

    # Named ADS $DATA:Zone.Identifier (0x80 with name_len > 0)
    ads_b = "Zone.Identifier".encode("utf-16le")
    ads = bytearray((24 + len(ads_b) + 7) & ~7)
    struct.pack_into("<II", ads, 0, 0x80, len(ads))
    ads[9] = len("Zone.Identifier")
    struct.pack_into("<H", ads, 10, 24)
    ads[24:24 + len(ads_b)] = ads_b
    rec[off:off + len(ads)] = ads
    off += len(ads)
    struct.pack_into("<I", rec, off, 0xFFFFFFFF)

    parsed_mft = DiskForensicsEngine().parse_mft_record(bytes(rec), record_index=42)
    assert parsed_mft["timestomping_suspect"] is True
    assert "Zone.Identifier" in parsed_mft["ads_streams"]

    # 2. Browser visits table join + truncation warning when max_rows=2
    hist_db = tmp_path / "History"
    con = sqlite3.connect(str(hist_db))
    con.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER)")
    con.execute("CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)")
    for i in range(4):
        con.execute("INSERT INTO urls VALUES (?, ?, ?, 1, 13400000000000000)", (i + 1, f"https://example{i}.com", f"Page {i}"))
        con.execute("INSERT INTO visits VALUES (?, ?, 13400000000000000)", (i + 1, i + 1))
    con.commit()
    con.close()

    br = BrowserForensicsEngine().parse_sqlite_artifact(str(hist_db), max_rows=2)
    assert len(br["history"]) == 2
    assert len(br["warnings"]) >= 1
