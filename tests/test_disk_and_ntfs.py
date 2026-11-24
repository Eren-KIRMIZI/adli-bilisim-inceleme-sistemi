"""Unit tests for DiskForensicsEngine (MBR, NTFS VBR, MFT, File Carving, E01 warnings)."""

import struct
import uuid
import pytest
from src.ntfs_engine.ntfs_service import DiskForensicsEngine, create_synthetic_ntfs_image, detect_signature


def test_synthetic_ntfs_image_inspection(tmp_path):
    img_path = str(tmp_path / "synth_disk.dd")
    create_synthetic_ntfs_image(img_path)

    engine = DiskForensicsEngine()
    res = engine.inspect_image(img_path)

    assert res["format"] == "RAW Disk Image (.dd/.raw)"
    assert len(res["partitions"]) == 1
    p = res["partitions"][0]
    assert p["scheme"] == "MBR"
    assert p["filesystem"] == "NTFS"
    assert p["start_lba"] == 128

    mft = res["mft_records"]
    assert len(mft) >= 6
    names = {r["filename"]: r for r in mft}

    assert "gizli_rapor.pdf" in names
    assert names["gizli_rapor.pdf"]["is_deleted"] is False
    assert names["gizli_rapor.pdf"]["signature_type"] == "PDF"

    # Deleted file check
    assert "silinen_kanit.jpg" in names
    assert names["silinen_kanit.jpg"]["is_deleted"] is True
    assert names["silinen_kanit.jpg"]["signature_type"] == "JPEG"
    assert names["silinen_kanit.jpg"]["created"] is not None


def test_file_carving_signatures(tmp_path):
    img_path = str(tmp_path / "carve_disk.dd")
    create_synthetic_ntfs_image(img_path)
    engine = DiskForensicsEngine()
    carved = engine.carve_signatures(img_path)

    types = {c["type"] for c in carved}
    assert "PDF" in types
    assert "JPEG" in types
    assert "ZIP / DOCX / XLSX" in types


def test_gpt_partition_parsing(tmp_path):
    gpt_path = str(tmp_path / "gpt_disk.dd")
    buf = bytearray(4096)
    # Protective MBR (0xEE)
    buf[446:462] = struct.pack("<B3sB3sII", 0x00, b"\x00\x00\x00", 0xEE, b"\x00\x00\x00", 1, 100)
    buf[510:512] = b"\x55\xAA"
    # GPT Header at LBA 1 (512)
    buf[512:520] = b"EFI PART"
    struct.pack_into("<Q", buf, 512 + 72, 2)    # entries start LBA 2 (offset 1024)
    struct.pack_into("<II", buf, 512 + 80, 1, 128)
    # Entry 0 at 1024
    guid = uuid.UUID("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7").bytes_le
    buf[1024:1040] = guid
    struct.pack_into("<QQ", buf, 1024 + 32, 34, 99)
    pname = "Basic data partition".encode("utf-16le")
    buf[1024 + 56:1024 + 56 + len(pname)] = pname

    with open(gpt_path, "wb") as f:
        f.write(buf)

    parts = DiskForensicsEngine().parse_partition_table(gpt_path)
    assert len(parts) == 1
    assert parts[0]["scheme"] == "GPT"
    assert parts[0]["type_name"] == "Basic data partition"
    assert parts[0]["start_lba"] == 34


def test_e01_header_detection_warning(tmp_path):
    e01 = tmp_path / "test.e01"
    e01.write_bytes(b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 1024)
    res = DiskForensicsEngine().inspect_image(str(e01))
    assert "E01" in res["format"]
    assert len(res["warnings"]) >= 1


def test_detect_signature_helper():
    assert detect_signature(b"%PDF-1.5")[0] == "PDF"
    assert detect_signature(b"\xFF\xD8\xFF\xE0")[0] == "JPEG"
    assert detect_signature(b"\x00\x01\x02\x03")[0] == "Bilinmeyen / Ham Veri"
