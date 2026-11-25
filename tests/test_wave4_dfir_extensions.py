"""Automated tests for Dalga 4 DFIR extensions: Super-Timeline, Multi-Module Reports, BitLocker, ShellBags BagMRU, EML, PCAP, HashSet/YARA UI."""

from datetime import datetime
import struct

from src.ntfs_engine.ntfs_service import DiskForensicsEngine
from src.registry_engine.hive_parser import RegistryHiveParser
from src.timeline_engine.timeline_service import TimelineService
from src.report_engine.report_service import ReportService
from src.database.models import init_db, ForensicArtifact
from src.file_engine.threat_scanner import HashSetService
from src.email_network_engine import (
    EmailForensicsService,
    NetworkForensicsService,
    create_synthetic_eml_file,
    create_synthetic_pcap_file,
)


def test_bitlocker_fve_volume_detection(tmp_path):
    """Verify BitLocker (-FVE-FS-) encrypted volumes trigger explicit status and warning."""
    img = bytearray(64 * 512)
    img[0:3] = b"\xeb\x58\x90"
    img[3:11] = b"-FVE-FS-"
    p = tmp_path / "bitlocker_vol.raw"
    p.write_bytes(bytes(img))

    res = DiskForensicsEngine().inspect_image(str(p))
    assert "BitLocker" in res["format"]
    assert res["partitions"][0]["vbr_info"]["encrypted"] is True
    assert any("-FVE-FS-" in w for w in res["warnings"])


def test_shellbags_bagmru_recursive_extraction():
    """Verify BagMRU tree reconstruction using parse_shellbag_item."""
    dos_d = ((2026 - 1980) << 9) | (11 << 5) | 25
    dos_t = (15 << 11) | (20 << 5) | 0

    def make_dir_item(name: str) -> bytes:
        nb = name.encode("ascii") + b"\x00\x00"
        b = bytearray(14 + len(nb))
        struct.pack_into("<H", b, 0, len(b))
        b[2] = 0x31
        struct.pack_into("<HH", b, 8, dos_d, dos_t)
        b[14:] = nb
        return bytes(b)

    tree = {
        "name": "ROOT",
        "path": "\\ROOT",
        "values": [],
        "children": [
            {
                "name": "BagMRU",
                "path": "\\ROOT\\BagMRU",
                "last_written": datetime(2026, 11, 25, 15, 20),
                "values": [{"name": "0", "raw_bytes": make_dir_item("C_Drive")}],
                "children": [
                    {
                        "name": "0",
                        "path": "\\ROOT\\BagMRU\\0",
                        "last_written": datetime(2026, 11, 25, 15, 21),
                        "values": [{"name": "1", "raw_bytes": make_dir_item("ExfilFolder")}],
                        "children": [],
                    }
                ],
            }
        ],
    }

    sbs = RegistryHiveParser.extract_shellbags_from_root(tree)
    assert len(sbs) == 2
    assert any(sb["full_path"] == "C_Drive > ExfilFolder" for sb in sbs)


def test_super_timeline_and_multimodule_report(tmp_path):
    """Verify Super-Timeline ingests ForensicArtifact + MFT/EVTX/EML and appears in HTML & PDF reports."""
    db_file = str(tmp_path / "dfir_wave4.db")
    tl = TimelineService(db_path=db_file)
    Session = init_db(db_file)
    with Session() as s:
        s.add(ForensicArtifact(
            case_id=1,
            artifact_type="YARA_HIT",
            source_path="C:\\temp\\dropper.ps1",
            source_location="Dosya Analizi",
            extracted_data="PowerShell_EncodedCommand tespit edildi",
            original_timestamp="2026-11-20T19:42:00Z",
            normalized_timestamp=datetime(2026, 11, 20, 19, 42, 0),
            parser_name="YaraStyleScanner",
            parser_version="1.0",
            confidence=95,
        ))
        s.commit()

    tl.ingest_mft_records([
        {"filename": "dropper.ps1", "full_path": "C:\\temp\\dropper.ps1", "record_index": 88, "si_created": datetime(2026, 11, 20, 19, 40, 0)}
    ])
    tl.ingest_evtx_events([
        {"event_id": 4688, "timestamp": datetime(2026, 11, 20, 19, 41, 0), "description": "Yeni süreç", "details": "powershell.exe"}
    ])
    events = tl.collect_case_timeline(case_id=1)
    assert any("YARA_HIT" in e["event_type"] for e in events)
    assert any("MFT Oluşturulma" in e["event_type"] for e in events)
    assert any("EVTX Event 4688" in e["event_type"] for e in events)

    rep = ReportService(db_path=db_file)
    html = rep.render_html(case_id=1)
    assert "PowerShell_EncodedCommand" in html
    assert "Çoklu Modül Artefakt" in html
    pdf_out = str(tmp_path / "multimod.pdf")
    rep.export_pdf(pdf_out, case_id=1)
    assert (tmp_path / "multimod.pdf").stat().st_size > 1000


def test_eml_pcap_hosts_and_hashset_import_ui(qapp, tmp_path):
    """Verify RFC 5322 .eml, libpcap .pcap, hosts parser, HashSet CSV import & FileAnalysis/WindowsForensics UI tabs."""
    from src.ui.pages.file_analysis_page import FileAnalysisPage
    from src.ui.pages.windows_forensics.windows_forensics_page import WindowsForensicsPage

    eml_p = str(tmp_path / "phish.eml")
    create_synthetic_eml_file(eml_p)
    eml_res = EmailForensicsService.parse_eml(eml_p)
    assert "evil-c2.example" in eml_res["from"]
    assert any("c2-drop.example" in u for u in eml_res["urls"])
    assert len(eml_res["attachments"]) == 1
    assert eml_res["attachments"][0]["filename"] == "fatura_ek.zip"

    pcap_p = str(tmp_path / "cap.pcap")
    create_synthetic_pcap_file(pcap_p)
    pcap_res = NetworkForensicsService.parse_pcap(pcap_p)
    assert pcap_res["packet_count"] == 2
    assert any(q["domain"] == "exfil.evil-c2.example" for q in pcap_res["dns_queries"])
    assert any("stage2.bin" in h["ioc"] for h in pcap_res["http_iocs"])

    hosts_p = tmp_path / "hosts"
    hosts_p.write_text("127.0.0.1 localhost\n185.220.101.44 update.microsoft.com\n", encoding="utf-8")
    hosts_rows = NetworkForensicsService.read_hosts_file(str(hosts_p))
    assert len(hosts_rows) == 2

    hs_csv = tmp_path / "iocs.csv"
    hs_csv.write_text(f"{'d' * 64},Dropper_IOC\n", encoding="utf-8")
    hs = HashSetService(db_path=str(tmp_path / "hs_import.db"))
    assert hs.import_hash_file(str(hs_csv), category="known_bad") == 1
    assert hs.stats()["known_bad"] == 1

    fpage = FileAnalysisPage(hashset_db_path=str(tmp_path / "ui_hs_w4.db"))
    fpage.load_eml(eml_p)
    assert "evil-c2.example" in fpage.eml_detail.toPlainText()
    assert fpage.eml_att_table.rowCount() == 1

    mal_dir = tmp_path / "yara_dir"
    mal_dir.mkdir()
    (mal_dir / "mimikatz_note.txt").write_bytes(b"sekurlsa::logonpasswords")
    fpage.scan_yara_folder(str(mal_dir))
    assert fpage.yara_table.rowCount() >= 1

    wpage = WindowsForensicsPage()
    wpage.load_pcap(pcap_p)
    assert wpage.net_table.rowCount() >= 4
