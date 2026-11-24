"""Wave 1 P0 unit tests: NTFS Data Runs, Full Paths, $UsnJrnl:$J, Streaming Carving, BinXML EVTX, Registry Big Data/UserAssist/ShimCache."""

import struct
from datetime import datetime
from src.ntfs_engine.ntfs_service import (
    DiskForensicsEngine,
    create_synthetic_ntfs_image,
    create_synthetic_usn_journal,
    decode_data_runs,
    datetime_to_filetime,
)
from src.eventlog_engine.evtx_service import EventLogService, create_synthetic_evtx_file
from src.registry_engine.hive_parser import RegistryHiveParser


def test_ntfs_data_runs_fragmented_mft_and_full_paths(tmp_path):
    # Test raw runlist decoder including sparse run
    runs = decode_data_runs(bytes([0x11, 0x02, 0x04, 0x01, 0x03, 0x11, 0x01, 0x08, 0x00]))
    assert runs == [(4, 2), (None, 3), (12, 1)]

    img = str(tmp_path / "frag_ntfs.dd")
    create_synthetic_ntfs_image(img)
    res = DiskForensicsEngine().inspect_image(img)

    by_name = {r["filename"]: r for r in res["mft_records"]}
    # Records from fragment 2 (cluster 12) MUST be reached via $MFT Data Runs!
    assert "musteri_export.xlsx" in by_name
    assert "silinen_kanit.jpg" in by_name
    assert by_name["silinen_kanit.jpg"]["is_deleted"] is True

    # Full directory path reconstruction via parent MFT record 6 ("Users")
    assert by_name["gizli_rapor.pdf"]["full_path"] == r"\Users\gizli_rapor.pdf"
    # Non-resident file preview & signature detection
    assert by_name["gizli_rapor.pdf"]["is_resident"] is False
    assert by_name["gizli_rapor.pdf"]["signature_type"] == "PDF"


def test_usn_journal_v2_and_streaming_carving(tmp_path):
    usn_path = str(tmp_path / "usn_j.bin")
    create_synthetic_usn_journal(usn_path)
    recs = DiskForensicsEngine().parse_usn_journal(usn_path)
    assert len(recs) == 3
    assert recs[0]["filename"] == "rclone.exe"
    assert "FILE_CREATE" in recs[0]["reasons"]
    assert "FILE_DELETE" in recs[2]["reasons"]

    img = str(tmp_path / "stream.dd")
    create_synthetic_ntfs_image(img)
    prog = []
    carved = DiskForensicsEngine().carve_signatures_streaming(img, chunk_size=32768, progress_callback=prog.append)
    assert prog[-1] == 100
    assert any(c["type"] == "PDF" for c in carved)
    assert any(c["type"] == "JPEG" for c in carved)


def test_structural_binxml_evtx_decoding(tmp_path):
    evtx_path = str(tmp_path / "binxml.evtx")
    create_synthetic_evtx_file(evtx_path)
    res = EventLogService().parse_evtx_file(evtx_path)
    assert len(res["events"]) == 5
    ev_4688 = [e for e in res["events"] if e["event_id"] == 4688][0]
    assert "MehmetS" in ev_4688["details"]
    assert "powershell.exe" in ev_4688["details"]
    assert len(ev_4688["event_data"]) >= 3


def test_registry_userassist_and_shimcache_parsers():
    # UserAssist ROT13 + 72-byte binary entry
    encoded = RegistryHiveParser.decode_rot13(r"P:\Hfref\NuzrgX\CbjreFuryy.rkr")
    assert encoded == r"C:\Users\AhmetK\PowerShell.exe"

    ua_raw = bytearray(72)
    struct.pack_into("<III", ua_raw, 4, 14, 5, 12500)
    struct.pack_into("<Q", ua_raw, 60, datetime_to_filetime(datetime(2026, 11, 20, 19, 45)))
    parsed_ua = RegistryHiveParser.parse_userassist_value(r"P:\Grfg.rkr", bytes(ua_raw))
    assert parsed_ua["decoded_path"] == r"C:\Test.exe"
    assert parsed_ua["run_count"] == 14
    assert parsed_ua["last_executed"] is not None

    # ShimCache Win10 '10ts' entry
    path_b = r"C:\Users\Public\exfil.exe".encode("utf-16le")
    entry_body = struct.pack("<IH", 0, len(path_b)) + path_b + struct.pack("<Q", datetime_to_filetime(datetime(2026, 11, 20, 18, 0)))
    # Entry layout: '10ts'(4) + 4B unk + entry_len(4) + path_len(2) + path + filetime(8)
    ent_payload = struct.pack("<H", len(path_b)) + path_b + struct.pack("<Q", datetime_to_filetime(datetime(2026, 11, 20, 18, 0)))
    blob = bytearray(0x34)
    struct.pack_into("<I", blob, 0, 0x34)
    blob.extend(b"10ts" + b"\x00\x00\x00\x00" + struct.pack("<I", len(ent_payload)) + ent_payload)

    sc_entries = RegistryHiveParser.parse_shimcache(bytes(blob))
    assert len(sc_entries) == 1
    assert sc_entries[0]["path"] == r"C:\Users\Public\exfil.exe"
    assert sc_entries[0]["last_modified"] is not None
