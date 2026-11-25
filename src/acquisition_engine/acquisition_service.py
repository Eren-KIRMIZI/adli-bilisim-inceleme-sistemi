"""Forensic Field Acquisition Engine: Read-Only Raw (.dd) / Split (.001) Imaging & Dual Hashing.

Strict forensic integrity:
- Sources are opened read-only ('rb').
- Raw block devices (\\\\.\\PhysicalDriveN, \\\\.\\E:) require Administrator elevation on Windows;
  permission denials are reported explicitly without fabricating data.
- Single-pass streaming SHA-256 & SHA-512 + post-acquisition destination read-back verification.
"""

import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import hashlib
import json
import os
import time
from typing import Any, Callable, Dict, List, Optional

from src.core.privilege_service import PrivilegeService


DRIVE_TYPES = {
    0: "Bilinmeyen",
    1: "Kök Dizin Yok",
    2: "Çıkarılabilir Medya (USB)",
    3: "Sabit Yerel Disk",
    4: "Ağ Sürücüsü",
    5: "Optik Sürücü (CD/DVD)",
    6: "RAM Disk",
}


class AcquisitionService:
    """Read-only forensic raw image acquirer with optional split output and verified manifest."""

    @staticmethod
    def list_storage_targets() -> List[Dict[str, Any]]:
        """Enumerate logical Windows volumes & physical drive handles cleanly."""
        targets: List[Dict[str, Any]] = []
        is_admin = PrivilegeService.is_admin()

        if os.name == "nt" and hasattr(ctypes, "windll"):
            k32 = ctypes.windll.kernel32
            bitmask = k32.GetLogicalDrives()
            for i in range(26):
                if not (bitmask & (1 << i)):
                    continue
                letter = chr(ord("A") + i)
                root = f"{letter}:\\"
                dtype_code = k32.GetDriveTypeW(root)
                dtype = DRIVE_TYPES.get(dtype_code, "Diğer")

                vol_name = ctypes.create_unicode_buffer(261)
                fs_name = ctypes.create_unicode_buffer(261)
                serial_no = wintypes.DWORD(0)
                k32.GetVolumeInformationW(
                    root, vol_name, 260, ctypes.byref(serial_no), None, None, fs_name, 260
                )

                free_bytes = ctypes.c_ulonglong(0)
                total_bytes = ctypes.c_ulonglong(0)
                avail_bytes = ctypes.c_ulonglong(0)
                k32.GetDiskFreeSpaceExW(
                    root, ctypes.byref(avail_bytes), ctypes.byref(total_bytes), ctypes.byref(free_bytes)
                )
                gb = total_bytes.value / (1024 ** 3) if total_bytes.value else 0.0
                raw_handle = f"\\\\.\\{letter}:"
                targets.append({
                    "Hedef": raw_handle,
                    "Etiket": vol_name.value or "(Etiketsiz)",
                    "Tür": dtype,
                    "Dosya Sistemi": fs_name.value or "-",
                    "Kapasite": f"{gb:.1f} GB" if gb else "-",
                    "Erişim": "Salt-Okunur Hazır (Admin)" if is_admin else "Ham Blok İçin UAC Gerekli",
                    "Seri (Volume)": f"{serial_no.value:08X}",
                })

            # PhysicalDrive0..3 probe (honest handle test)
            for idx in range(4):
                phys = f"\\\\.\\PhysicalDrive{idx}"
                access = "Salt-Okunur Açılabilir (Admin)" if is_admin else "Yönetici Yetkisi Gerekli"
                if is_admin:
                    try:
                        with open(phys, "rb") as pf:
                            pf.read(512)
                        access = "Doğrulandı • Salt-Okunur Hazır"
                    except OSError as exc:
                        access = f"Erişim Yok ({exc.errno or exc})"
                        if idx > 0 and exc.errno == 2:
                            continue
                targets.append({
                    "Hedef": phys,
                    "Etiket": f"Fiziksel Disk #{idx}",
                    "Tür": "Fiziksel Blok Aygıtı",
                    "Dosya Sistemi": "RAW Sector Stream",
                    "Kapasite": "-",
                    "Erişim": access,
                    "Seri (Volume)": "-",
                })
        else:
            targets.append({
                "Hedef": "/dev/sda (Sadece Linux Root)",
                "Etiket": "Sistem Diski",
                "Tür": "Blok Aygıtı",
                "Dosya Sistemi": "-",
                "Kapasite": "-",
                "Erişim": "Root Gerekli",
                "Seri (Volume)": "-",
            })
        return targets

    @staticmethod
    def acquire_raw_image(
        source_path: str,
        output_path: str,
        chunk_size: int = 1024 * 1024,
        split_mb: int = 0,
        max_bytes: Optional[int] = None,
        write_blocker_verified: bool = False,
        write_blocker_model: str = "",
        operator: str = "Adli Bilişim Uzmanı",
        case_number: str = "VAK-2026-084",
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> Dict[str, Any]:
        """Acquire a raw (.dd) or split (.001/.002) forensic image strictly read-only with hash verification."""
        if not source_path:
            raise ValueError("Kaynak dosya veya aygıt yolu belirtilmelidir.")

        is_raw_device = source_path.startswith("\\\\.\\") or source_path.startswith("/dev/")
        if not is_raw_device and not os.path.isfile(source_path):
            raise FileNotFoundError(f"Kaynak bulunamadı: {source_path}")

        src_size = 0 if is_raw_device else os.path.getsize(source_path)
        limit = min(src_size, max_bytes) if (src_size and max_bytes) else (max_bytes or src_size)

        os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
        split_bytes = int(split_mb) * 1024 * 1024 if split_mb and split_mb > 0 else 0

        h256 = hashlib.sha256()
        h512 = hashlib.sha512()
        total_written = 0
        segment_paths: List[str] = []
        t0 = time.perf_counter()

        try:
            with open(source_path, "rb") as src:
                if split_bytes == 0:
                    segment_paths.append(output_path)
                    with open(output_path, "wb") as dst:
                        while True:
                            to_read = chunk_size
                            if limit:
                                rem = limit - total_written
                                if rem <= 0:
                                    break
                                to_read = min(chunk_size, rem)
                            buf = src.read(to_read)
                            if not buf:
                                break
                            dst.write(buf)
                            h256.update(buf)
                            h512.update(buf)
                            total_written += len(buf)
                            if progress_callback:
                                progress_callback(total_written, limit or total_written)
                else:
                    part_idx = 1
                    cur_part_bytes = 0
                    cur_path = f"{output_path}.{part_idx:03d}"
                    segment_paths.append(cur_path)
                    dst = open(cur_path, "wb")
                    try:
                        while True:
                            to_read = chunk_size
                            if limit:
                                rem = limit - total_written
                                if rem <= 0:
                                    break
                                to_read = min(chunk_size, rem)
                            buf = src.read(to_read)
                            if not buf:
                                break
                            if cur_part_bytes > 0 and cur_part_bytes + len(buf) > split_bytes:
                                dst.close()
                                part_idx += 1
                                cur_part_bytes = 0
                                cur_path = f"{output_path}.{part_idx:03d}"
                                segment_paths.append(cur_path)
                                dst = open(cur_path, "wb")
                            dst.write(buf)
                            cur_part_bytes += len(buf)
                            h256.update(buf)
                            h512.update(buf)
                            total_written += len(buf)
                            if progress_callback:
                                progress_callback(total_written, limit or total_written)
                    finally:
                        dst.close()
        except PermissionError as exc:
            raise PermissionError(
                f"Ham kaynak okunamadı (Yönetici / Yazma Engelleyici Yetkisi Gerekli): {source_path} -> {exc}"
            ) from exc

        # Post-acquisition read-back verification across written segment(s)
        vh256 = hashlib.sha256()
        for sp in segment_paths:
            with open(sp, "rb") as vf:
                while True:
                    chunk = vf.read(65536)
                    if not chunk:
                        break
                    vh256.update(chunk)

        src_sha256 = h256.hexdigest()
        src_sha512 = h512.hexdigest()
        verify_sha256 = vh256.hexdigest()
        verified = src_sha256 == verify_sha256
        elapsed = max(0.001, time.perf_counter() - t0)
        mb_per_sec = (total_written / (1024 * 1024)) / elapsed

        manifest = {
            "schema": "adli-bilisim-acquisition/v1",
            "case_number": case_number,
            "acquired_at_utc": datetime.now(timezone.utc).isoformat(),
            "operator": operator,
            "source": source_path,
            "segments": segment_paths,
            "segment_count": len(segment_paths),
            "bytes_acquired": total_written,
            "write_blocker_verified": bool(write_blocker_verified),
            "write_blocker_model": write_blocker_model.strip() or "Belirtilmedi",
            "source_sha256": src_sha256,
            "source_sha512": src_sha512,
            "destination_sha256": verify_sha256,
            "post_verification_matched": verified,
            "elapsed_sec": round(elapsed, 4),
            "throughput_mb_s": round(mb_per_sec, 2),
        }
        manifest_path = output_path + ".acquisition.json"
        with open(manifest_path, "w", encoding="utf-8") as mf:
            json.dump(manifest, mf, indent=2, ensure_ascii=False)
        manifest["manifest_path"] = manifest_path
        return manifest
