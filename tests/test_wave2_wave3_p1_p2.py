"""Automated verification tests for Wave 2 (P1) and Wave 3 (P2) DFIR capabilities."""

import json
import os
import struct
from src.ntfs_engine.ntfs_service import DiskForensicsEngine, create_synthetic_ntfs_image
from src.ntfs_engine.ewf_reader import create_synthetic_e01_image, EwfImageStream
from src.registry_engine.windows_artifacts import WindowsArtifactParsers, create_synthetic_windows_artifacts
from src.core.triage_collector import TriageCollector
from src.memory_engine.memory_service import MemoryForensicsEngine, create_synthetic_memory_dump
from src.file_engine.threat_scanner import YaraStyleScanner, HashSetService


def test_p1_e01_ewf_compression_and_ntfs_inspection(tmp_path):
    """Verify pure-Python EnCase EWF (.E01) chunk decompression + end-to-end NTFS MFT inspection."""
    raw_path = str(tmp_path / "src_ntfs.img")
    e01_path = str(tmp_path / "evidence_disk.E01")
    create_synthetic_ntfs_image(raw_path)
    create_synthetic_e01_image(raw_path, e01_path)

    with EwfImageStream(e01_path) as stream:
        assert stream.size > 0
        stream.seek(510)
        assert stream.read(2) == b"\x55\xAA"
        stream.seek(128 * 512)
        vbr_head = stream.read(11)
        assert vbr_head[:3] == b"\xeb\x52\x90"
        assert vbr_head[3:11] == b"NTFS    "

    res = DiskForensicsEngine().inspect_image(e01_path)
    assert "E01" in res["format"]
    assert len(res["partitions"]) >= 1
    assert res["partitions"][0]["filesystem"] == "NTFS"
    assert res["partitions"][0]["vbr_info"]["oem_id"] == "NTFS"
    names = {r["filename"] for r in res["mft_records"]}
    assert len(names) >= 5


def test_p1_prefetch_8ts_jumplist_and_shellbags(tmp_path):
    """Verify 8-timestamp Prefetch, OLE2 Jump List, and ShellBag binary decoding."""
    arts = create_synthetic_windows_artifacts(str(tmp_path / "win_arts"))

    pf = WindowsArtifactParsers.parse_prefetch(arts["pf"])
    assert len(pf["last_run_times"]) == 3
    assert len(pf["loaded_files"]) >= 2
    assert any("NTDLL" in f or "EXFIL" in f for f in pf["loaded_files"])

    jl = WindowsArtifactParsers.parse_jump_list(arts["jumplist"])
    assert len(jl) == 1
    assert jl[0]["artifact_type"] == "Jump List (LNK)"
    assert "musteri_listesi.zip" in jl[0]["target_path"]

    # Synthetic Directory ShellBag item (type 0x31 + size + flags + DOS date/time + name)
    dos_date = ((2026 - 1980) << 9) | (11 << 5) | 24
    dos_time = (14 << 11) | (30 << 5) | 5
    name_bytes = b"USB_Backup_2026\x00\x00"
    item = bytearray(14 + len(name_bytes))
    struct.pack_into("<H", item, 0, len(item))
    item[2] = 0x31
    struct.pack_into("<HH", item, 8, dos_date, dos_time)
    item[14:] = name_bytes
    sb = WindowsArtifactParsers.parse_shellbag_item(bytes(item))
    assert "USB_Backup_2026" in sb["name"]
    assert sb["modified_dos"] == "2026-11-24 14:30:10"


def test_p1_triage_collector_manifest(tmp_path):
    """Verify KAPE-style TriageCollector copies working files read-only and generates SHA-256 manifest."""
    src_dir = tmp_path / "src_triage"
    out_dir = tmp_path / "out_triage"
    src_dir.mkdir()
    sample = src_dir / "EVTX_Security.evtx"
    sample.write_bytes(b"ElfFile\x00TEST_TRIAGE_DATA")
    (src_dir / "ignore.tmp").write_bytes(b"skip")

    manifest = TriageCollector.collect_from_directory(
        str(src_dir), str(out_dir), extensions=(".evtx",), max_files=10
    )
    assert manifest["collected_count"] == 1
    assert os.path.isfile(manifest["manifest_path"])
    saved = json.loads(open(manifest["manifest_path"], "r", encoding="utf-8").read())
    assert saved["files"][0]["sha256"]


def test_p2_memory_proc_heuristic_and_yara_hashset(tmp_path):
    """Verify Memory Proc Pool heuristic extraction, Volatility3 check, YaraStyleScanner, and HashSetService."""
    dmp = str(tmp_path / "mem_p2.dmp")
    create_synthetic_memory_dump(dmp)
    res = MemoryForensicsEngine().inspect_memory_dump(dmp)
    assert len(res["eprocess_candidates"]) >= 1
    assert any(c["image_name"] == "beacon_svc.exe" for c in res["eprocess_candidates"])
    assert "Heuristiği" in res["eprocess_candidates"][0]["confidence"]
    assert "available" in res["volatility3"]

    scanner = YaraStyleScanner()
    mal_bytes = b"cmd.exe /c powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA=="
    hits = scanner.scan_bytes(mal_bytes)
    assert any(h["rule"] == "PowerShell_EncodedCommand" for h in hits)
    assert scanner.scan_bytes(b"Ordinary non-malicious ASCII text document.") == []

    hs_db = str(tmp_path / "hashsets.db")
    hs = HashSetService(db_path=hs_db)
    hs.add_hashes([
        {"sha256": "a" * 64, "category": "known_bad", "label": "BeaconPayload", "source": "UnitTest"},
        {"sha256": "b" * 64, "category": "known_good", "label": "NSRL_Notepad", "source": "NSRL"},
    ])
    bad = hs.lookup("A" * 64)
    assert bad is not None and bad["category"] == "known_bad"
    good = hs.lookup("b" * 64)
    assert good is not None and good["category"] == "known_good"
    assert hs.lookup("c" * 64) is None


def test_p2_file_analysis_page_yara_ui(qapp, tmp_path):
    """Verify FileAnalysisPage integrates YaraStyleScanner & HashSetService in UI output."""
    from src.ui.pages.file_analysis_page import FileAnalysisPage

    suspicious = tmp_path / "payload.ps1"
    suspicious.write_bytes(b"powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==")
    page = FileAnalysisPage(hashset_db_path=str(tmp_path / "ui_hs.db"))
    page.analyze_file(str(suspicious))
    txt = page.meta_view.toPlainText()
    assert "PowerShell_EncodedCommand" in txt
    assert "HASH SET" in txt
