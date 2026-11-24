"""Original parsers for Windows LNK shortcuts, Prefetch (.pf), and Recycle Bin ($I) artifacts."""

import ctypes
import os
import struct
from datetime import datetime
from typing import Any, Dict, List, Optional

from src.ntfs_engine.ntfs_service import filetime_to_datetime, datetime_to_filetime


class WindowsArtifactParsers:
    """Pure-Python binary parsers for LNK, Prefetch, and Recycle Bin $I artifacts."""

    @staticmethod
    def parse_lnk(path: str) -> Dict[str, Any]:
        """Parse a Windows Shell Link (.lnk) binary file per MS-SHLLINK specification."""
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        with open(path, "rb") as f:
            data = f.read()

        if len(data) < 76:
            raise ValueError("LNK dosyası minimum 76 baytlık başlık boyutundan küçük.")

        hdr_size = struct.unpack("<I", data[0:4])[0]
        clsid = data[4:20]
        expected_clsid = bytes.fromhex("0114020000000000c000000000000046")
        if hdr_size != 0x4C or clsid != expected_clsid:
            raise ValueError("Geçerli Windows LNK (MS-SHLLINK) imzası bulunamadı.")

        link_flags = struct.unpack("<I", data[20:24])[0]
        file_attrs = struct.unpack("<I", data[24:28])[0]
        c_ft, a_ft, w_ft = struct.unpack("<QQQ", data[28:52])
        file_size = struct.unpack("<I", data[52:56])[0]

        pos = 76
        # Skip LinkTargetIDList if flag 0x01 set
        if (link_flags & 0x01) and pos + 2 <= len(data):
            id_list_size = struct.unpack("<H", data[pos:pos + 2])[0]
            pos += 2 + id_list_size

        local_base_path = ""
        # Parse LinkInfo if flag 0x02 set
        if (link_flags & 0x02) and pos + 28 <= len(data):
            info_size = struct.unpack("<I", data[pos:pos + 4])[0]
            info_hdr_size = struct.unpack("<I", data[pos + 4:pos + 8])[0]
            info_flags = struct.unpack("<I", data[pos + 8:pos + 12])[0]
            if (info_flags & 0x01) and pos + 20 <= len(data):
                local_off = struct.unpack("<I", data[pos + 16:pos + 20])[0]
                if pos + local_off < len(data):
                    end_nul = data.find(b"\x00", pos + local_off)
                    if end_nul != -1:
                        local_base_path = data[pos + local_off:end_nul].decode("mbcs", errors="replace")
            pos += info_size

        # Parse StringData sections if present
        is_unicode = bool(link_flags & 0x80)
        string_fields = {}
        for flag_bit, fname in [(0x04, "Name"), (0x08, "RelativePath"), (0x10, "WorkingDir"), (0x20, "Arguments")]:
            if (link_flags & flag_bit) and pos + 2 <= len(data):
                char_cnt = struct.unpack("<H", data[pos:pos + 2])[0]
                pos += 2
                byte_cnt = char_cnt * 2 if is_unicode else char_cnt
                if pos + byte_cnt <= len(data):
                    raw_s = data[pos:pos + byte_cnt]
                    string_fields[fname] = raw_s.decode("utf-16le" if is_unicode else "mbcs", errors="replace")
                    pos += byte_cnt

        return {
            "artifact_type": "LNK Kısayolu",
            "filename": os.path.basename(path),
            "target_path": local_base_path or string_fields.get("RelativePath") or "(Belirtilmemiş)",
            "working_dir": string_fields.get("WorkingDir", "-"),
            "arguments": string_fields.get("Arguments", "-"),
            "target_file_size": file_size,
            "target_created": filetime_to_datetime(c_ft),
            "target_accessed": filetime_to_datetime(a_ft),
            "target_modified": filetime_to_datetime(w_ft),
            "file_attributes": f"0x{file_attrs:08X}",
            "raw_bytes": data[:2048],
        }

    @staticmethod
    def parse_prefetch(path: str) -> Dict[str, Any]:
        """Parse a Windows Prefetch (.pf) file (uncompressed SCCA or Win10/11 MAM)."""
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        with open(path, "rb") as f:
            data = f.read()

        warnings: List[str] = []
        if data[:3] == b"MAM":
            decompressed = WindowsArtifactParsers._decompress_mam(data)
            if decompressed is None:
                return {
                    "artifact_type": "Prefetch (.pf)",
                    "filename": os.path.basename(path),
                    "executable": "(MAM Sıkıştırılmış)",
                    "version": "Win10/11 MAM",
                    "run_count": None,
                    "last_run": None,
                    "warnings": ["MAM (Xpress Huffman) sıkıştırması çözülemedi; tahmin yapılmadı."],
                    "raw_bytes": data[:2048],
                }
            data = decompressed

        if len(data) < 100 or data[4:8] != b"SCCA":
            raise ValueError("Geçerli Windows Prefetch ('SCCA') imzası bulunamadı.")

        version = struct.unpack("<I", data[0:4])[0]
        exe_name = data[16:76].decode("utf-16le", errors="ignore").split("\x00")[0]
        pf_hash = struct.unpack("<I", data[76:80])[0]

        run_count: Optional[int] = None
        last_run: Optional[datetime] = None

        if version == 17 and len(data) >= 152:  # XP
            last_run = filetime_to_datetime(struct.unpack("<Q", data[120:128])[0])
            run_count = struct.unpack("<I", data[144:148])[0]
        elif version == 23 and len(data) >= 156:  # Vista/Win7
            last_run = filetime_to_datetime(struct.unpack("<Q", data[128:136])[0])
            run_count = struct.unpack("<I", data[152:156])[0]
        elif version in (26, 30) and len(data) >= 212:  # Win8/10/11
            last_run = filetime_to_datetime(struct.unpack("<Q", data[128:136])[0])
            run_count = struct.unpack("<I", data[208:212])[0]
        else:
            warnings.append(f"Prefetch sürüm {version} için çalıştırma sayacı alanı eksik/kısa.")

        return {
            "artifact_type": "Prefetch (.pf)",
            "filename": os.path.basename(path),
            "executable": exe_name or "(Bilinmiyor)",
            "prefetch_hash": f"0x{pf_hash:08X}",
            "version": version,
            "run_count": run_count,
            "last_run": last_run,
            "warnings": warnings,
            "raw_bytes": data[:2048],
        }

    @staticmethod
    def _decompress_mam(data: bytes) -> Optional[bytes]:
        """Attempt native Windows ntdll RtlDecompressBufferEx decompression for Win10/11 Prefetch."""
        if len(data) < 8 or not hasattr(ctypes, "windll"):
            return None
        try:
            uncompressed_size = struct.unpack("<I", data[4:8])[0]
            if uncompressed_size == 0 or uncompressed_size > 16 * 1024 * 1024:
                return None
            ntdll = ctypes.windll.ntdll
            ws_size = ctypes.c_ulong()
            frag_size = ctypes.c_ulong()
            # 4 = COMPRESSION_FORMAT_XPRESS_HUFF
            status = ntdll.RtlGetCompressionWorkSpaceSize(4, ctypes.byref(ws_size), ctypes.byref(frag_size))
            if status != 0:
                return None
            ws = ctypes.create_string_buffer(ws_size.value)
            out_buf = ctypes.create_string_buffer(uncompressed_size)
            final_size = ctypes.c_ulong()
            comp_slice = data[8:]
            status = ntdll.RtlDecompressBufferEx(
                4,
                out_buf,
                uncompressed_size,
                comp_slice,
                len(comp_slice),
                ctypes.byref(final_size),
                ws,
            )
            if status == 0:
                return out_buf.raw[:final_size.value]
        except Exception:
            return None
        return None

    @staticmethod
    def parse_recycle_bin_i(path: str) -> Dict[str, Any]:
        """Parse Windows Recycle Bin $I metadata file (Version 1 Win7 / Version 2 Win10+)."""
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        with open(path, "rb") as f:
            data = f.read()

        if len(data) < 28:
            raise ValueError("$I Geri Dönüşüm Kutusu dosyası geçersiz boyutta.")

        version = struct.unpack("<Q", data[0:8])[0]
        orig_size = struct.unpack("<Q", data[8:16])[0]
        deleted_at = filetime_to_datetime(struct.unpack("<Q", data[16:24])[0])

        if version == 1:
            orig_path = data[24:544].decode("utf-16le", errors="ignore").split("\x00")[0]
        elif version == 2:
            path_chars = struct.unpack("<I", data[24:28])[0]
            orig_path = data[28:28 + path_chars * 2].decode("utf-16le", errors="ignore").rstrip("\x00")
        else:
            raise ValueError(f"Desteklenmeyen $I sürümü: {version}")

        return {
            "artifact_type": "Geri Dönüşüm Kutusu ($I)",
            "filename": os.path.basename(path),
            "version": version,
            "original_size": orig_size,
            "deleted_at": deleted_at,
            "original_path": orig_path or "(Eksik Yol)",
            "raw_bytes": data[:2048],
        }


def create_synthetic_windows_artifacts(output_dir: str) -> Dict[str, str]:
    """Generate authentic synthetic .lnk, .pf, and $I files for offline forensic validation."""
    os.makedirs(output_dir, exist_ok=True)
    paths: Dict[str, str] = {}

    # 1. Synthetic .lnk
    lnk_path = os.path.join(output_dir, "gizli_arsiv.lnk")
    lnk = bytearray(76)
    struct.pack_into("<I", lnk, 0, 0x4C)
    lnk[4:20] = bytes.fromhex("0114020000000000c000000000000046")
    # LinkFlags: HasLinkInfo(0x02) | HasWorkingDir(0x10) | IsUnicode(0x80)
    struct.pack_into("<I", lnk, 20, 0x02 | 0x10 | 0x80)
    struct.pack_into("<I", lnk, 24, 0x20)
    ft_c = datetime_to_filetime(datetime(2026, 11, 19, 10, 15))
    ft_w = datetime_to_filetime(datetime(2026, 11, 19, 10, 20))
    struct.pack_into("<QQQ", lnk, 28, ft_c, ft_w, ft_w)
    struct.pack_into("<I", lnk, 52, 1048576)
    target_b = b"E:\\Exfil\\musteri_listesi.zip\x00"
    info_hdr = bytearray(28 + len(target_b))
    struct.pack_into("<IIIII", info_hdr, 0, len(info_hdr), 28, 0x01, 0, 28)
    info_hdr[28:] = target_b
    wdir = "E:\\Exfil"
    wdir_b = struct.pack("<H", len(wdir)) + wdir.encode("utf-16le")
    with open(lnk_path, "wb") as f:
        f.write(bytes(lnk) + bytes(info_hdr) + wdir_b)
    paths["lnk"] = lnk_path

    # 2. Synthetic uncompressed Prefetch (.pf v26)
    pf_path = os.path.join(output_dir, "POWERSHELL.EXE-A1B2C3D4.pf")
    pf = bytearray(256)
    struct.pack_into("<I", pf, 0, 26)
    pf[4:8] = b"SCCA"
    exe_b = "POWERSHELL.EXE".encode("utf-16le")
    pf[16:16 + len(exe_b)] = exe_b
    struct.pack_into("<I", pf, 76, 0xA1B2C3D4)
    struct.pack_into("<Q", pf, 128, datetime_to_filetime(datetime(2026, 11, 20, 19, 41, 3)))
    struct.pack_into("<I", pf, 208, 7)  # run count = 7
    with open(pf_path, "wb") as f:
        f.write(pf)
    paths["pf"] = pf_path

    # 3. Synthetic Recycle Bin $I (Version 2)
    i_path = os.path.join(output_dir, "$I99XABC.xlsx")
    orig_p = "C:\\Users\\AhmetK\\Desktop\\gizli_maas_tablosu.xlsx"
    orig_b = orig_p.encode("utf-16le")
    ibuf = bytearray(28 + len(orig_b))
    struct.pack_into("<QQQ", ibuf, 0, 2, 245760, datetime_to_filetime(datetime(2026, 11, 20, 21, 10, 0)))
    struct.pack_into("<I", ibuf, 24, len(orig_p))
    ibuf[28:] = orig_b
    with open(i_path, "wb") as f:
        f.write(ibuf)
    paths["recycle"] = i_path

    return paths
