"""Comprehensive tests for v3.0 DFIR Gap Closures (Filesystems, Containers, BitLocker/VSS, SRUM/BAM/Sigma, PCAPNG/PST, Mobile/Cloud, FTS5, Bookmarks, STIX2)."""

import json
import os
import struct
import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from src.ntfs_engine.ntfs_service import DiskForensicsEngine, create_synthetic_ntfs_image
from src.ntfs_engine.container_streams import (
    LogicalContainerParser,
    create_synthetic_vhd_from_raw,
    create_synthetic_qcow2_from_raw,
    create_synthetic_aff4_from_raw,
    create_synthetic_ad1,
)
from src.ntfs_engine.filesystem_parsers import (
    create_synthetic_fat32_image,
    create_synthetic_exfat_image,
    create_synthetic_ext4_image,
    create_synthetic_apfs_image,
)
from src.ntfs_engine.bitlocker_vss_logfile import (
    BitLockerService,
    VssParser,
    NtfsLogFileParser,
    create_synthetic_vss_and_logfile,
)
from src.registry_engine.ese_srum_parser import EseDatabaseParser, create_synthetic_srum_ese
from src.registry_engine.extended_windows_artifacts import (
    ExtendedWindowsArtifacts,
    create_synthetic_extended_windows_bundle,
)
from src.registry_engine.hive_parser import RegistryHiveParser
from src.eventlog_engine.evtx_service import EventLogService, create_synthetic_evtx_file
from src.eventlog_engine.sigma_engine import SigmaRuleEngine
from src.file_engine.threat_scanner import YaraStyleScanner
from src.email_network_engine.email_network_service import (
    EmailForensicsService,
    NetworkForensicsService,
    create_synthetic_pcapng_file,
    create_synthetic_mbox_and_pst,
)
from src.mobile_cloud_engine.mobile_cloud_service import (
    MobileCloudForensicsService,
    create_synthetic_mobile_cloud_bundle,
)
from src.core.fts_index import ForensicFtsIndex
from src.core.bookmark_service import BookmarkService
from src.core.benchmark_service import BenchmarkService
from src.core.triage_collector import TriageCollector
from src.core.orchestrator import AnalysisOrchestrator
from src.report_engine.report_service import ReportService


def test_fat32_exfat_ext4_apfs_and_containers(tmp_path):
    eng = DiskForensicsEngine()

    fat32_res = eng.inspect_image(create_synthetic_fat32_image(str(tmp_path / "usb.fat32")))
    assert fat32_res["partitions"][0]["filesystem"] == "FAT32"
    assert any(r["is_deleted"] for r in fat32_res["mft_records"])
    assert any("RAPOR.TXT" in r["filename"] for r in fat32_res["mft_records"])

    exfat_res = eng.inspect_image(create_synthetic_exfat_image(str(tmp_path / "usb.exfat")))
    assert exfat_res["partitions"][0]["filesystem"] == "exFAT"
    assert any(r["is_deleted"] and "silinen_usb.ps1" in r["filename"] for r in exfat_res["mft_records"])

    ext4_res = eng.inspect_image(create_synthetic_ext4_image(str(tmp_path / "lin.ext4")))
    assert ext4_res["partitions"][0]["filesystem"] == "ext4"
    assert any(r["filename"] == "auth.log" for r in ext4_res["mft_records"])

    apfs_res = eng.inspect_image(create_synthetic_apfs_image(str(tmp_path / "mac.apfs")))
    assert apfs_res["partitions"][0]["filesystem"] == "APFS"
    assert any("Macintosh HD" in r["filename"] for r in apfs_res["mft_records"])

    # Virtual & Forensic Containers wrapping NTFS image
    raw_ntfs = create_synthetic_ntfs_image(str(tmp_path / "base.dd"))
    for fn, builder in [
        ("disk.vhd", create_synthetic_vhd_from_raw),
        ("disk.qcow2", create_synthetic_qcow2_from_raw),
        ("disk.aff4", create_synthetic_aff4_from_raw),
    ]:
        c_path = builder(raw_ntfs, str(tmp_path / fn))
        c_res = eng.inspect_image(c_path)
        assert len(c_res["mft_records"]) >= 5

    ad1_res = eng.inspect_image(create_synthetic_ad1(str(tmp_path / "logical.ad1")))
    assert len(ad1_res["mft_records"]) == 2


def test_bitlocker_fvek_decryption_vss_and_logfile(tmp_path):
    # Encrypt a synthetic NTFS partition volume sector-by-sector with AES-XTS and verify decryption restores NTFS
    raw_ntfs = create_synthetic_ntfs_image(str(tmp_path / "plain.dd"))
    ins_plain = DiskForensicsEngine().inspect_image(raw_ntfs)
    part_off = ins_plain["partitions"][0]["start_offset"]
    plain_bytes = open(raw_ntfs, "rb").read()[part_off:]
    fvek = b"\x42" * 32 + b"\x99" * 32
    enc_buf = bytearray()
    for sec_idx in range(len(plain_bytes) // 512):
        blk = plain_bytes[sec_idx * 512:(sec_idx + 1) * 512]
        if sec_idx == 0:
            hdr = bytearray(blk)
            hdr[3:11] = b"-FVE-FS-"
            enc_buf.extend(hdr)
        else:
            tweak = struct.pack("<Q", sec_idx) + b"\x00" * 8
            enc = Cipher(algorithms.AES(fvek), modes.XTS(tweak)).encryptor()
            enc_buf.extend(enc.update(blk) + enc.finalize())

    enc_path = str(tmp_path / "bitlocker.dd")
    open(enc_path, "wb").write(bytes(enc_buf))

    fve_info = BitLockerService.inspect_fve_header(enc_path)
    assert fve_info["signature"] == "-FVE-FS-"

    dec_path = str(tmp_path / "decrypted.dd")
    BitLockerService.decrypt_volume_with_fvek(enc_path, dec_path, fvek)
    dec_res = DiskForensicsEngine().inspect_image(dec_path)
    assert len(dec_res["mft_records"]) >= 5

    bundle = create_synthetic_vss_and_logfile(str(tmp_path / "vss_log"))
    snaps = VssParser.scan_vss_snapshots(bundle["vss_image"])
    assert len(snaps) == 1 and snaps[0]["record_type"] == "VSS Store Header"

    lf = NtfsLogFileParser.parse_logfile(bundle["logfile"])
    assert len(lf["restarts"]) == 1
    assert len(lf["records"]) >= 1 and lf["records"][0]["lsn"] == 100520


def test_srum_ese_extended_windows_sigma_and_yara(tmp_path):
    srum_path = create_synthetic_srum_ese(str(tmp_path / "SRUDB.dat"))
    srum = EseDatabaseParser.parse_ese(srum_path)
    assert len(srum["records"]) == 3
    assert any("rclone.exe" in r["app_or_user"] for r in srum["records"])

    ext_bundle = create_synthetic_extended_windows_bundle(str(tmp_path / "ext_win"))
    acts = ExtendedWindowsArtifacts.parse_activities_cache(ext_bundle["activities_db"])
    assert len(acts) == 1 and "rclone.exe" in acts[0]["application"]

    task = ExtendedWindowsArtifacts.parse_scheduled_task_xml(ext_bundle["task_xml"])
    assert task["suspicious"] is True and "powershell.exe" in task["commands"][0]

    wmi = ExtendedWindowsArtifacts.scan_wmi_objects_data(ext_bundle["wmi_objects"])
    assert len(wmi) >= 3

    # Offline BAM extraction via simulated hive dict
    fake_hive = {
        "root": {
            "name": "ROOT",
            "path": "ROOT",
            "values": [],
            "children": [{
                "name": "S-1-5-21-1001",
                "path": r"ROOT\ControlSet001\Services\bam\State\UserSettings\S-1-5-21-1001",
                "values": [{"name": r"\Device\HarddiskVolume3\Tools\rclone.exe", "raw_bytes": struct.pack("<Q", 134181301200000000)}],
                "children": [],
            }],
        }
    }
    bam_rows = ExtendedWindowsArtifacts.parse_bam_dam_from_hive(fake_hive)
    assert len(bam_rows) == 1 and "rclone.exe" in bam_rows[0]["executable"]

    # Sigma Rule Engine over EVTX
    evtx_path = create_synthetic_evtx_file(str(tmp_path / "sec.evtx"))
    evtx = EventLogService().parse_evtx_file(evtx_path)
    sigma_hits = SigmaRuleEngine().scan_events(evtx["events"])
    assert len(sigma_hits) >= 1

    # YARA Scanner (yara-python or fallback)
    scanner = YaraStyleScanner()
    hits = scanner.scan_bytes(b"powershell.exe -WindowStyle Hidden -EncodedCommand SQBuAHYAbwBrAGUAQQBiAGMA")
    assert len(hits) >= 1


def test_pcapng_mbox_pst_mobile_cloud_fts5_bookmarks_stix(tmp_path):
    pcapng = NetworkForensicsService.parse_pcap(create_synthetic_pcapng_file(str(tmp_path / "cap.pcapng")))
    assert pcapng["version"] == "PCAPNG 1.0"
    assert any("ngc2.evil-c2.example" in d["domain"] for d in pcapng["dns_queries"])

    epaths = create_synthetic_mbox_and_pst(str(tmp_path / "mail"))
    mbox = EmailForensicsService.parse_mbox(epaths["mbox"])
    assert mbox["message_count"] == 1
    pst = EmailForensicsService.parse_pst_ost(epaths["pst"])
    assert any("evil-c2.example" in e for e in pst["extracted_emails"])

    mc = create_synthetic_mobile_cloud_bundle(str(tmp_path / "mc"))
    wa = MobileCloudForensicsService.parse_mobile_sqlite(mc["whatsapp_db"])
    assert wa["record_count"] == 2
    pl = MobileCloudForensicsService.parse_ios_plist(mc["ios_plist"])
    assert pl["record_count"] >= 4
    m365 = MobileCloudForensicsService.parse_cloud_audit_or_sync(mc["m365_audit"])
    assert m365["record_count"] == 2

    # FTS5 Search
    fts = ForensicFtsIndex(db_path=str(tmp_path / "fts.db"))
    doc_dir = tmp_path / "docs"
    doc_dir.mkdir()
    (doc_dir / "note.txt").write_text("exfiltration via rclone remote_exfil:drop completed", encoding="utf-8")
    assert fts.index_directory(str(doc_dir)) == 1
    assert len(fts.search("rclone")) == 1

    # Bookmarks + Report + STIX2 + CSV + Remote Triage + CFReDS Benchmark
    db_file = str(tmp_path / "v3.db")
    bm_svc = BookmarkService(db_path=db_file)
    bm_svc.add_bookmark(1, "Kritik IOC", "YARA", "rclone_payload.exe", analyst_note="Dogrulandi")
    html = ReportService(db_path=db_file).render_html(case_id=1)
    assert "rclone_payload.exe" in html and "Kritik IOC" in html

    orch = AnalysisOrchestrator(db_path=db_file)
    stix_p = orch.export_stix2_bundle(1, str(tmp_path / "bundle.stix.json"), extra_iocs=[{"type": "domain-name", "value": "evil-c2.example"}])
    stix_doc = json.loads(open(stix_p, encoding="utf-8").read())
    assert stix_doc["type"] == "bundle" and len(stix_doc["objects"]) >= 1

    csv_p = AnalysisOrchestrator.export_csv([{"time": "2026-03-15", "event": "rclone"}], str(tmp_path / "tl.csv"))
    assert os.path.isfile(csv_p)

    ps1_p = TriageCollector.export_remote_triage_script(str(tmp_path / "remote_triage.ps1"))
    assert os.path.isfile(ps1_p) and "SRUDB.dat" in open(ps1_p, encoding="utf-8").read()

    cf = BenchmarkService.run_cfreds_reference_suite()
    assert cf["accuracy_pct"] == 100.0
