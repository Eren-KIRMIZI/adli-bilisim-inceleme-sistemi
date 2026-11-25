"""BitLocker (-FVE-FS-) Recovery Decryption, Volume Shadow Copy (VSS), and NTFS $LogFile Parsers."""

from datetime import datetime, timedelta, timezone
import hashlib
import os
import re
import struct
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM


def _filetime_to_iso(ft: int) -> Optional[str]:
    if not ft or ft < 116444736000000000:
        return None
    try:
        dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ft // 10)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except OverflowError:
        return None


class BitLockerService:
    """BitLocker FVE header/metadata parser & AES-CBC/XTS decryption via FVEK or 48-digit recovery key."""

    @staticmethod
    def recovery_password_to_intermediate_key(recovery_password: str, salt: bytes) -> bytes:
        """Convert a 48-digit BitLocker recovery password + 16-byte salt into stretched 32-byte key."""
        groups = re.findall(r"\d{6}", recovery_password or "")
        if len(groups) != 8:
            raise ValueError("BitLocker kurtarma parolası 8 adet 6 haneli gruptan (toplam 48 rakam) oluşmalıdır.")
        raw_16 = bytearray()
        for g in groups:
            val = int(g)
            if val % 11 != 0 or val >= 65536 * 11:
                raise ValueError(f"Geçersiz BitLocker kurtarma grubu (11'in katı olmalı): {g}")
            raw_16.extend(struct.pack("<H", val // 11))

        # Step 1: SHA-256(16-byte recovery key)
        key_hash = hashlib.sha256(bytes(raw_16)).digest()
        # Step 2: 0x100000 rounds of SHA-256(updated_hash || prev_hash || salt || counter_le64)
        # Compact deterministic key stretching (compatible with synthetic & standard FVE salt flow)
        buf = bytearray(key_hash + key_hash + salt[:16].ljust(16, b"\x00") + b"\x00" * 8)
        cur = key_hash
        for cnt in range(1048576):
            buf[0:32] = cur
            struct.pack_into("<Q", buf, 80, cnt)
            cur = hashlib.sha256(buf).digest()
        return cur

    @staticmethod
    def inspect_fve_header(image_path: str, part_offset: int = 0) -> Dict[str, Any]:
        with open(image_path, "rb") as f:
            f.seek(part_offset)
            vbr = f.read(512)
            if len(vbr) < 512 or vbr[3:11] != b"-FVE-FS-":
                raise ValueError("BitLocker '-FVE-FS-' birim imzası bulunamadı.")
            bps = struct.unpack("<H", vbr[11:13])[0] or 512
            spc = vbr[13] or 8
            fve_guid = vbr[160:176].hex()
            meta_offsets = [
                struct.unpack("<Q", vbr[176:184])[0],
                struct.unpack("<Q", vbr[184:192])[0],
                struct.unpack("<Q", vbr[192:200])[0],
            ]
            # Fallback custom offset @ 120 for compact volumes
            if not any(meta_offsets):
                meta_offsets = [4096]
            meta_off = next((m for m in meta_offsets if m > 0), 4096)
            f.seek(part_offset + meta_off)
            meta = f.read(4096)

        has_fve_meta = meta[0:8] == b"-FVE-FS-"
        protectors: List[str] = []
        if b"FVE_VMK" in meta:
            protectors.append("VMK/Kurtarma Anahtarı")
        if b"TPM" in meta:
            protectors.append("TPM Koruyucu")
        return {
            "signature": "-FVE-FS-",
            "bytes_per_sector": bps,
            "sectors_per_cluster": spc,
            "volume_guid": fve_guid,
            "metadata_offset": meta_off,
            "metadata_valid": has_fve_meta,
            "protectors": protectors or ["Kurtarma Parolası / FVEK Bekleniyor"],
        }

    @staticmethod
    def decrypt_volume_with_fvek(
        encrypted_path: str,
        output_path: str,
        fvek_bytes: bytes,
        part_offset: int = 0,
        sector_size: int = 512,
        mode: str = "xts",
    ) -> str:
        """Decrypt raw BitLocker sectors using a 32-byte (CBC) or 64-byte (XTS) FVEK to a read-only copy."""
        if mode == "xts" and len(fvek_bytes) not in (32, 64):
            raise ValueError("AES-XTS için 32 veya 64 baytlık FVEK gerekir.")
        if mode == "cbc" and len(fvek_bytes) not in (16, 32):
            raise ValueError("AES-CBC için 16 veya 32 baytlık FVEK gerekir.")

        total_sz = os.path.getsize(encrypted_path)
        os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
        with open(encrypted_path, "rb") as src, open(output_path, "wb") as dst:
            src.seek(part_offset)
            sec_idx = 0
            while src.tell() < total_sz:
                blk = src.read(sector_size)
                if not blk:
                    break
                if len(blk) < sector_size:
                    dst.write(blk)
                    break
                if sec_idx == 0 and blk[3:11] == b"-FVE-FS-":
                    # Restore NTFS OEM ID header in decrypted working copy if marker present
                    dec = bytearray(blk)
                    dec[3:11] = b"NTFS    "
                    dst.write(bytes(dec))
                else:
                    tweak = struct.pack("<Q", sec_idx) + b"\x00" * 8
                    if mode == "xts":
                        key = fvek_bytes if len(fvek_bytes) == 64 else (fvek_bytes + fvek_bytes)
                        cipher = Cipher(algorithms.AES(key), modes.XTS(tweak))
                    else:
                        iv = Cipher(algorithms.AES(fvek_bytes), modes.ECB()).encryptor().update(tweak)
                        cipher = Cipher(algorithms.AES(fvek_bytes), modes.CBC(iv))
                    decryptor = cipher.decryptor()
                    dst.write(decryptor.update(blk) + decryptor.finalize())
                sec_idx += 1
        return output_path

    @staticmethod
    def unwrap_fvek_with_recovery_password(
        recovery_password: str,
        salt: bytes,
        nonce: bytes,
        wrapped_fvek: bytes,
    ) -> bytes:
        """Derive intermediate key from 48-digit recovery password and unwrap AES-CCM protected FVEK."""
        inter_key = BitLockerService.recovery_password_to_intermediate_key(recovery_password, salt)
        return AESCCM(inter_key, tag_length=16).decrypt(nonce[:12], wrapped_fvek, None)


class VssParser:
    """Volume Shadow Copy Service (VSS) Catalog & Store Header scanner/parser."""

    VSS_GUID_BYTES = bytes.fromhex("6b87083876c1484eb7ae04046e6cc752")  # {3808876b-c176-4e48-b7ae-04046e6cc752}

    @classmethod
    def scan_vss_snapshots(cls, image_path: str, max_scan_mb: int = 32) -> List[Dict[str, Any]]:
        if not os.path.isfile(image_path):
            raise FileNotFoundError(image_path)
        limit = min(os.path.getsize(image_path), max_scan_mb * 1024 * 1024)
        with open(image_path, "rb") as f:
            data = f.read(limit)

        snapshots: List[Dict[str, Any]] = []
        pos = 0
        while True:
            idx = data.find(cls.VSS_GUID_BYTES, pos)
            if idx < 0:
                break
            pos = idx + 16
            if idx + 128 > len(data):
                continue
            ver, rec_type = struct.unpack("<II", data[idx + 16:idx + 24])
            # Store Header (rec_type == 4) or Catalog Block (rec_type == 2)
            cur_off = struct.unpack("<Q", data[idx + 24:idx + 32])[0]
            vol_sz = struct.unpack("<Q", data[idx + 40:idx + 48])[0]
            ts_ft = struct.unpack("<Q", data[idx + 48:idx + 56])[0]
            snapshots.append({
                "offset": idx,
                "offset_hex": f"0x{idx:08X}",
                "version": ver,
                "record_type": {1: "VSS Volume Header", 2: "VSS Catalog", 3: "VSS Block List", 4: "VSS Store Header"}.get(rec_type, f"Type {rec_type}"),
                "store_offset": cur_off,
                "volume_size": vol_sz,
                "created_utc": _filetime_to_iso(ts_ft),
            })
        return snapshots


class NtfsLogFileParser:
    """NTFS $LogFile (RSTR Restart Area & RCRD Log Record Page) parser."""

    OP_CODES = {
        0x00: "Noop",
        0x01: "CompensationLogRecord",
        0x02: "InitializeFileRecordSegment",
        0x03: "DeallocateFileRecordSegment",
        0x04: "WriteEndOfFileRecordSegment",
        0x05: "CreateAttribute",
        0x06: "DeleteAttribute",
        0x07: "UpdateResidentValue",
        0x08: "UpdateNonResidentValue",
        0x0B: "AddIndexEntryAllocation",
        0x0C: "DeleteIndexEntryAllocation",
        0x0F: "SetNewAttributeSizes",
    }

    @classmethod
    def parse_logfile(cls, logfile_path: str, max_records: int = 2000) -> Dict[str, Any]:
        if not os.path.isfile(logfile_path):
            raise FileNotFoundError(logfile_path)
        with open(logfile_path, "rb") as f:
            raw = f.read(min(os.path.getsize(logfile_path), 16 * 1024 * 1024))

        page_size = 4096
        restarts: List[Dict[str, Any]] = []
        records: List[Dict[str, Any]] = []

        for page_off in range(0, len(raw) - 63, page_size):
            page = raw[page_off:page_off + page_size]
            sig = page[0:4]
            if sig == b"RSTR":
                usa_off, usa_cnt = struct.unpack("<HH", page[4:8])
                chk_lsn = struct.unpack("<Q", page[8:16])[0]
                sys_page_sz, log_page_sz = struct.unpack("<II", page[32:40])
                restarts.append({
                    "offset": f"0x{page_off:08X}",
                    "chkdsk_lsn": chk_lsn,
                    "system_page_size": sys_page_sz,
                    "log_page_size": log_page_sz,
                    "usa_count": usa_cnt,
                })
            elif sig == b"RCRD" and len(records) < max_records:
                last_lsn = struct.unpack("<Q", page[8:16])[0]
                next_rec_off = struct.unpack("<H", page[42:44])[0] or 64
                # Walk LFS record headers inside RCRD page starting @ 64
                pos = 64
                while pos + 48 <= min(len(page), next_rec_off if next_rec_off > 64 else len(page)) and len(records) < max_records:
                    this_lsn, prev_lsn, undo_lsn = struct.unpack("<QQQ", page[pos:pos + 24])
                    client_len, client_id, rec_type, tx_id = struct.unpack("<IIII", page[pos + 24:pos + 40])
                    if this_lsn == 0 or client_len == 0 or pos + 48 + client_len > len(page):
                        break
                    redo_op = struct.unpack("<H", page[pos + 48:pos + 50])[0] if pos + 50 <= len(page) else 0
                    undo_op = struct.unpack("<H", page[pos + 50:pos + 52])[0] if pos + 52 <= len(page) else 0
                    records.append({
                        "page_offset": f"0x{page_off:08X}",
                        "lsn": this_lsn,
                        "prev_lsn": prev_lsn,
                        "transaction_id": tx_id,
                        "redo_op": cls.OP_CODES.get(redo_op, f"0x{redo_op:02X}"),
                        "undo_op": cls.OP_CODES.get(undo_op, f"0x{undo_op:02X}"),
                        "client_data_len": client_len,
                        "page_last_lsn": last_lsn,
                    })
                    pos += 48 + ((client_len + 7) & ~7)

        return {"restarts": restarts, "records": records}


def create_synthetic_vss_and_logfile(output_dir: str) -> Dict[str, str]:
    """Generate synthetic VSS snapshot store image and NTFS $LogFile binary for testing."""
    os.makedirs(output_dir, exist_ok=True)
    vss_path = os.path.join(output_dir, "synthetic_vss.img")
    vss = bytearray(8192)
    off = 1024
    vss[off:off + 16] = VssParser.VSS_GUID_BYTES
    struct.pack_into("<IIQQQ", vss, off + 16, 1, 4, 4096, 1024 * 1024, 134181300000000000)
    with open(vss_path, "wb") as f:
        f.write(bytes(vss))

    log_path = os.path.join(output_dir, "$LogFile")
    lf = bytearray(4096 * 3)
    # Page 0: RSTR
    lf[0:4] = b"RSTR"
    struct.pack_into("<HHQ", lf, 4, 48, 9, 100500)
    struct.pack_into("<II", lf, 32, 4096, 4096)
    # Page 2: RCRD
    p2 = 4096 * 2
    lf[p2:p2 + 4] = b"RCRD"
    struct.pack_into("<Q", lf, p2 + 8, 100520)
    struct.pack_into("<H", lf, p2 + 42, 64 + 48 + 16)
    r = p2 + 64
    struct.pack_into("<QQQIIII", lf, r, 100520, 100500, 0, 16, 1, 1, 77)
    struct.pack_into("<HH", lf, r + 48, 0x03, 0x02)  # DeallocateFileRecordSegment / Initialize
    with open(log_path, "wb") as f:
        f.write(bytes(lf))

    return {"vss_image": vss_path, "logfile": log_path}
