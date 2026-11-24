"""Original File Analysis engine: signatures, extension spoofing, entropy, EXIF, diff, duplicates."""

import hashlib
import math
import mimetypes
import os
import struct
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from src.integrity_engine.integrity_service import IntegrityService
from src.ntfs_engine.ntfs_service import detect_signature

EXIF_TAGS = {
    0x010F: "Make",
    0x0110: "Model",
    0x0112: "Orientation",
    0x0131: "Software",
    0x0132: "DateTime",
    0x8769: "ExifIFDPointer",
    0x8825: "GPSInfoIFDPointer",
    0x9003: "DateTimeOriginal",
    0x9004: "DateTimeDigitized",
    0xA002: "PixelXDimension",
    0xA003: "PixelYDimension",
}


class FileAnalysisService:
    """Comprehensive read-only file forensic analyzer."""

    @staticmethod
    def shannon_entropy(data: bytes) -> float:
        """Calculate Shannon entropy (0.0 to 8.0 bits per byte)."""
        if not data:
            return 0.0
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        length = len(data)
        entropy = 0.0
        for c in counts:
            if c:
                p = c / length
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    @staticmethod
    def extract_jpeg_exif(data: bytes) -> Dict[str, Any]:
        """Pure-Python JPEG APP1 EXIF/TIFF IFD parser."""
        if len(data) < 12 or data[:2] != b"\xFF\xD8":
            return {}
        pos = 2
        while pos + 4 <= len(data):
            if data[pos] != 0xFF:
                break
            marker = data[pos + 1]
            if marker in (0xD8, 0xD9, 0x00):
                pos += 2
                continue
            if marker == 0xDA:  # Start of Scan
                break
            seg_len = struct.unpack(">H", data[pos + 2:pos + 4])[0]
            seg_data = data[pos + 4:pos + 2 + seg_len]
            if marker == 0xE1 and seg_data.startswith(b"Exif\x00\x00"):
                return FileAnalysisService._parse_tiff_ifd(seg_data[6:])
            pos += 2 + seg_len
        return {}

    @staticmethod
    def _parse_tiff_ifd(tiff: bytes) -> Dict[str, Any]:
        if len(tiff) < 8:
            return {}
        endian_mark = tiff[:2]
        endian = "<" if endian_mark == b"II" else (">" if endian_mark == b"MM" else None)
        if not endian:
            return {}
        magic = struct.unpack(endian + "H", tiff[2:4])[0]
        if magic != 42:
            return {}
        ifd0_off = struct.unpack(endian + "I", tiff[4:8])[0]
        result: Dict[str, Any] = {}

        def read_ifd(offset: int):
            if offset <= 0 or offset + 2 > len(tiff):
                return
            count = struct.unpack(endian + "H", tiff[offset:offset + 2])[0]
            for i in range(min(count, 100)):
                ent_off = offset + 2 + i * 12
                if ent_off + 12 > len(tiff):
                    break
                tag, typ, cnt, val_or_off = struct.unpack(endian + "HHII", tiff[ent_off:ent_off + 12])
                tag_name = EXIF_TAGS.get(tag, f"Tag_0x{tag:04X}")
                if tag in (0x8769, 0x8825):
                    read_ifd(val_or_off)
                    continue
                if typ == 2:  # ASCII string
                    if cnt <= 4:
                        raw = tiff[ent_off + 8:ent_off + 8 + cnt]
                    elif val_or_off + cnt <= len(tiff):
                        raw = tiff[val_or_off:val_or_off + cnt]
                    else:
                        continue
                    result[tag_name] = raw.decode("ascii", errors="replace").rstrip("\x00").strip()
                elif typ == 3 and cnt == 1:  # SHORT
                    result[tag_name] = struct.unpack(endian + "H", tiff[ent_off + 8:ent_off + 10])[0]
                elif typ == 4 and cnt == 1:  # LONG
                    result[tag_name] = val_or_off

        read_ifd(ifd0_off)
        return result

    @staticmethod
    def analyze(path: str) -> Dict[str, Any]:
        """Perform comprehensive read-only forensic inspection of a single file."""
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Dosya bulunamadı: {path}")

        st = os.stat(path)
        with open(path, "rb") as f:
            head = f.read(min(st.st_size, 1024 * 1024))

        sig_type, sig_conf = detect_signature(head)
        ext = os.path.splitext(path)[1].lower()
        ext_mismatch = FileAnalysisService._check_extension_mismatch(ext, sig_type)

        hashes = IntegrityService.compute_dual_hashes(path)
        md5_val = hashlib.md5(head if st.st_size <= 1024 * 1024 else open(path, "rb").read()).hexdigest()
        entropy = FileAnalysisService.shannon_entropy(head)
        exif = FileAnalysisService.extract_jpeg_exif(head) if head.startswith(b"\xFF\xD8") else {}

        return {
            "path": path,
            "name": os.path.basename(path),
            "extension": ext or "(Yok)",
            "size": st.st_size,
            "mime": mimetypes.guess_type(path)[0] or "application/octet-stream",
            "signature_type": sig_type,
            "signature_confidence": sig_conf,
            "extension_mismatch": ext_mismatch,
            "entropy": entropy,
            "entropy_note": "Yüksek entropi (Şifreli/Sıkıştırılmış olabilir)" if entropy >= 7.2 else "Normal",
            "sha256": hashes["sha256"],
            "sha512": hashes["sha512"],
            "md5": md5_val,
            "created_utc": datetime.fromtimestamp(st.st_ctime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "modified_utc": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "accessed_utc": datetime.fromtimestamp(st.st_atime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "exif": exif,
            "preview_bytes": head[:65536],
        }

    @staticmethod
    def _check_extension_mismatch(ext: str, sig_type: str) -> bool:
        expected_map = {
            ".jpg": "JPEG", ".jpeg": "JPEG",
            ".png": "PNG",
            ".pdf": "PDF",
            ".zip": "ZIP", ".docx": "ZIP", ".xlsx": "ZIP",
            ".exe": "PE Executable", ".dll": "PE Executable",
            ".db": "SQLite", ".sqlite": "SQLite",
            ".evtx": "EVTX",
        }
        if ext in expected_map and sig_type != "Bilinmeyen / Ham Veri":
            return expected_map[ext].lower() not in sig_type.lower()
        return False

    @staticmethod
    def compare_files(path_a: str, path_b: str) -> Dict[str, Any]:
        """Compare two files byte-by-byte and cryptographically."""
        info_a = FileAnalysisService.analyze(path_a)
        info_b = FileAnalysisService.analyze(path_b)
        identical = info_a["sha256"] == info_b["sha256"]
        first_diff_offset: Optional[int] = None

        if not identical:
            with open(path_a, "rb") as fa, open(path_b, "rb") as fb:
                offset = 0
                while True:
                    ca = fa.read(65536)
                    cb = fb.read(65536)
                    if not ca and not cb:
                        break
                    min_len = min(len(ca), len(cb))
                    for i in range(min_len):
                        if ca[i] != cb[i]:
                            first_diff_offset = offset + i
                            break
                    if first_diff_offset is not None:
                        break
                    if len(ca) != len(cb):
                        first_diff_offset = offset + min_len
                        break
                    offset += min_len

        return {
            "file_a": info_a,
            "file_b": info_b,
            "identical": identical,
            "size_diff": info_a["size"] - info_b["size"],
            "first_diff_offset": first_diff_offset,
        }

    @staticmethod
    def scan_directory_duplicates(folder_path: str, max_files: int = 1000) -> Dict[str, Any]:
        """Scan folder read-only for duplicate hashes and extension spoofing anomalies."""
        if not os.path.isdir(folder_path):
            raise NotADirectoryError(f"Klasör bulunamadı: {folder_path}")

        hash_groups: Dict[str, List[str]] = defaultdict(list)
        records: List[Dict[str, Any]] = []
        scanned = 0

        for root, _, files in os.walk(folder_path):
            for fname in files:
                if scanned >= max_files:
                    break
                fpath = os.path.join(root, fname)
                try:
                    st = os.stat(fpath)
                    sha = IntegrityService.hash_file(fpath, "sha256")
                    with open(fpath, "rb") as f:
                        head = f.read(64)
                    sig, _ = detect_signature(head)
                    ext = os.path.splitext(fname)[1].lower()
                    mismatch = FileAnalysisService._check_extension_mismatch(ext, sig)
                    hash_groups[sha].append(fpath)
                    records.append({
                        "path": fpath,
                        "name": fname,
                        "size": st.st_size,
                        "sha256": sha,
                        "signature": sig,
                        "mismatch": mismatch,
                    })
                    scanned += 1
                except Exception:
                    continue

        dup_hashes = {h for h, paths in hash_groups.items() if len(paths) > 1}
        for r in records:
            r["is_duplicate"] = r["sha256"] in dup_hashes

        return {
            "folder": folder_path,
            "total_scanned": scanned,
            "duplicate_groups": len(dup_hashes),
            "records": records,
        }


def create_synthetic_exif_jpeg(output_path: str) -> str:
    """Create a minimal valid JPEG containing forensic EXIF APP1 metadata for testing."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    # Little-endian TIFF IFD0 with 3 tags: Make, Model, DateTimeOriginal
    make_b = b"Canon\x00"
    model_b = b"Canon EOS R5\x00"
    dt_b = b"2026:11:18 14:22:10\x00"

    ifd0_offset = 8
    num_entries = 3
    data_start = ifd0_offset + 2 + num_entries * 12 + 4

    make_off = data_start
    model_off = make_off + len(make_b)
    dt_off = model_off + len(model_b)

    tiff = bytearray(dt_off + len(dt_b))
    tiff[0:2] = b"II"
    struct.pack_into("<HI", tiff, 2, 42, ifd0_offset)
    struct.pack_into("<H", tiff, ifd0_offset, num_entries)

    entries = [
        (0x010F, 2, len(make_b), make_off),
        (0x0110, 2, len(model_b), model_off),
        (0x9003, 2, len(dt_b), dt_off),
    ]
    for idx, (tag, typ, cnt, val_off) in enumerate(entries):
        struct.pack_into("<HHII", tiff, ifd0_offset + 2 + idx * 12, tag, typ, cnt, val_off)

    tiff[make_off:make_off + len(make_b)] = make_b
    tiff[model_off:model_off + len(model_b)] = model_b
    tiff[dt_off:dt_off + len(dt_b)] = dt_b

    app1_payload = b"Exif\x00\x00" + bytes(tiff)
    app1_seg = b"\xFF\xE1" + struct.pack(">H", len(app1_payload) + 2) + app1_payload
    jpeg = b"\xFF\xD8" + app1_seg + b"\xFF\xD9"
    with open(output_path, "wb") as f:
        f.write(jpeg)
    return output_path
