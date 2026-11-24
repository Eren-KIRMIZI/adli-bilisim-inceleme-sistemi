"""Original parsers for Windows LNK, Prefetch (8 timestamps + loaded files), Jump Lists (OLE2), ShellBags, and Recycle Bin ($I)."""

import ctypes
import os
import struct
from datetime import datetime
from typing import Any, Dict, List, Optional

from src.ntfs_engine.ntfs_service import filetime_to_datetime, datetime_to_filetime


def _dos_datetime_to_str(dos_date: int, dos_time: int) -> Optional[str]:
    if dos_date == 0 and dos_time == 0:
        return None
    try:
        year = ((dos_date >> 9) & 0x7F) + 1980
        month = (dos_date >> 5) & 0x0F
        day = dos_date & 0x1F
        hour = (dos_time >> 11) & 0x1F
        minute = (dos_time >> 5) & 0x3F
        sec = (dos_time & 0x1F) * 2
        return f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{sec:02d}"
    except Exception:
        return None


class WindowsArtifactParsers:
    """Pure-Python binary parsers for LNK, Prefetch, Jump Lists, ShellBags, and Recycle Bin $I."""

    @staticmethod
    def parse_lnk(path: str) -> Dict[str, Any]:
        """Parse a Windows Shell Link (.lnk) file from disk."""
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        with open(path, "rb") as f:
            data = f.read()
        return WindowsArtifactParsers.parse_lnk_bytes(data, filename=os.path.basename(path))

    @staticmethod
    def parse_lnk_bytes(data: bytes, filename: str = "stream.lnk") -> Dict[str, Any]:
        """Parse a Windows Shell Link (.lnk) binary buffer per MS-SHLLINK specification."""
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
        if (link_flags & 0x01) and pos + 2 <= len(data):
            id_list_size = struct.unpack("<H", data[pos:pos + 2])[0]
            pos += 2 + id_list_size

        local_base_path = ""
        if (link_flags & 0x02) and pos + 28 <= len(data):
            info_size = struct.unpack("<I", data[pos:pos + 4])[0]
            info_flags = struct.unpack("<I", data[pos + 8:pos + 12])[0]
            if (info_flags & 0x01) and pos + 20 <= len(data):
                local_off = struct.unpack("<I", data[pos + 16:pos + 20])[0]
                if pos + local_off < len(data):
                    end_nul = data.find(b"\x00", pos + local_off)
                    if end_nul != -1:
                        local_base_path = data[pos + local_off:end_nul].decode("mbcs", errors="replace")
            pos += info_size

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
            "filename": filename,
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
        """Parse Windows Prefetch (.pf): up to 8 last execution times, loaded file paths, and run count."""
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
                    "last_run_times": [],
                    "loaded_files": [],
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
        last_run_times: List[datetime] = []
        loaded_files: List[str] = []

        # Extract filename strings section (offset +96, size +100 in File Information block)
        if len(data) >= 108:
            fn_off = struct.unpack("<I", data[100:104])[0]
            fn_size = struct.unpack("<I", data[104:108])[0]
            if 84 <= fn_off < len(data) and fn_off + fn_size <= len(data) and fn_size > 0:
                raw_fn = data[fn_off:fn_off + fn_size].decode("utf-16le", errors="ignore")
                loaded_files = [s for s in raw_fn.split("\x00") if s.strip()][:200]

        if version == 17 and len(data) >= 152:
            dt = filetime_to_datetime(struct.unpack("<Q", data[120:128])[0])
            if dt:
                last_run_times.append(dt)
            run_count = struct.unpack("<I", data[144:148])[0]
        elif version == 23 and len(data) >= 156:
            dt = filetime_to_datetime(struct.unpack("<Q", data[128:136])[0])
            if dt:
                last_run_times.append(dt)
            run_count = struct.unpack("<I", data[152:156])[0]
        elif version in (26, 30) and len(data) >= 212:
            # Extract all 8 execution timestamps (8 x 8 bytes starting at +128)
            for idx in range(8):
                ft = struct.unpack("<Q", data[128 + idx * 8:136 + idx * 8])[0]
                dt = filetime_to_datetime(ft)
                if dt:
                    last_run_times.append(dt)
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
            "last_run": last_run_times[0] if last_run_times else None,
            "last_run_times": last_run_times,
            "loaded_files": loaded_files,
            "warnings": warnings,
            "raw_bytes": data[:2048],
        }

    @staticmethod
    def _decompress_mam(data: bytes) -> Optional[bytes]:
        if len(data) < 8 or not hasattr(ctypes, "windll"):
            return None
        try:
            uncompressed_size = struct.unpack("<I", data[4:8])[0]
            if uncompressed_size == 0 or uncompressed_size > 16 * 1024 * 1024:
                return None
            ntdll = ctypes.windll.ntdll
            ws_size = ctypes.c_ulong()
            frag_size = ctypes.c_ulong()
            if ntdll.RtlGetCompressionWorkSpaceSize(4, ctypes.byref(ws_size), ctypes.byref(frag_size)) != 0:
                return None
            ws = ctypes.create_string_buffer(ws_size.value)
            out_buf = ctypes.create_string_buffer(uncompressed_size)
            final_size = ctypes.c_ulong()
            comp_slice = data[8:]
            status = ntdll.RtlDecompressBufferEx(
                4, out_buf, uncompressed_size, comp_slice, len(comp_slice), ctypes.byref(final_size), ws
            )
            if status == 0:
                return out_buf.raw[:final_size.value]
        except Exception:
            return None
        return None

    @staticmethod
    def parse_jump_list(path: str) -> List[Dict[str, Any]]:
        """Parse an OLE2 / MS-CFB .automaticDestinations-ms Jump List and extract embedded LNK targets."""
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        with open(path, "rb") as f:
            data = f.read()

        if len(data) < 512 or data[:8] != b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1":
            raise ValueError("Geçerli MS-CFB (OLE2) Jump List başlığı bulunamadı.")

        sector_shift = struct.unpack("<H", data[30:32])[0]
        sector_size = 1 << sector_shift
        first_dir_sector = struct.unpack("<I", data[48:52])[0]

        # Collect FAT sectors from DIFAT[0..108] in header
        fat_sectors = []
        for i in range(109):
            sid = struct.unpack("<I", data[76 + i * 4:80 + i * 4])[0]
            if sid < 0xFFFFFFFA:
                fat_sectors.append(sid)

        fat: List[int] = []
        for fsid in fat_sectors:
            off = (fsid + 1) * sector_size
            if off + sector_size <= len(data):
                for j in range(0, sector_size, 4):
                    fat.append(struct.unpack("<I", data[off + j:off + j + 4])[0])

        def read_chain(start_sid: int, size_limit: int) -> bytes:
            out = bytearray()
            sid = start_sid
            visited = set()
            while sid < 0xFFFFFFFA and sid not in visited and len(out) < size_limit:
                visited.add(sid)
                off = (sid + 1) * sector_size
                if off + sector_size > len(data):
                    break
                out.extend(data[off:off + sector_size])
                sid = fat[sid] if sid < len(fat) else 0xFFFFFFFE
            return bytes(out[:size_limit])

        dir_bytes = read_chain(first_dir_sector, 1024 * 1024)
        entries: List[Dict[str, Any]] = []

        for d_off in range(0, len(dir_bytes), 128):
            ent = dir_bytes[d_off:d_off + 128]
            if len(ent) < 128:
                break
            name_len = struct.unpack("<H", ent[64:66])[0]
            obj_type = ent[66]
            if obj_type != 2 or name_len < 2:  # 2 = stream
                continue
            sname = ent[:name_len].decode("utf-16le", errors="ignore").rstrip("\x00")
            start_sid = struct.unpack("<I", ent[116:120])[0]
            stream_size = struct.unpack("<I", ent[120:124])[0]
            if stream_size < 76:
                continue
            stream_data = read_chain(start_sid, stream_size)
            if stream_data[:4] == b"\x4c\x00\x00\x00":
                try:
                    lnk = WindowsArtifactParsers.parse_lnk_bytes(stream_data, filename=f"{os.path.basename(path)}::{sname}")
                    lnk["artifact_type"] = "Jump List (LNK)"
                    lnk["stream_name"] = sname
                    entries.append(lnk)
                except Exception:
                    continue
        return entries

    @staticmethod
    def parse_shellbag_item(raw_bytes: bytes) -> Dict[str, Any]:
        """Decode a Windows ShellBag / Shell Item binary entry (Drive Letter, Folder/File + BEEF0004)."""
        if len(raw_bytes) < 4:
            return {"artifact_type": "ShellBag", "name": "(Bozuk)", "modified_dos": None}

        item_size = struct.unpack("<H", raw_bytes[0:2])[0]
        item_type = raw_bytes[2] if len(raw_bytes) > 2 else 0

        if item_type == 0x2F and len(raw_bytes) >= 6:  # Drive Letter
            drive = raw_bytes[3:6].split(b"\x00", 1)[0].decode("ascii", "replace")
            return {"artifact_type": "ShellBag (Sürücü)", "name": drive, "modified_dos": None}

        if item_type in (0x31, 0x32, 0x35, 0x36) and len(raw_bytes) >= 14:  # Directory / File item
            dos_d, dos_t = struct.unpack("<HH", raw_bytes[8:12])
            mod_str = _dos_datetime_to_str(dos_d, dos_t)
            short_end = raw_bytes.find(b"\x00", 14)
            short_name = raw_bytes[14:short_end].decode("ascii", "replace") if short_end != -1 else ""
            long_name = ""
            beef_idx = raw_bytes.find(b"\x04\x00\xEF\xBE")
            if beef_idx != -1 and beef_idx + 42 < len(raw_bytes):
                # In BEEF0004 block, long name UTF-16LE follows fixed header (~42 bytes from signature start)
                cand = raw_bytes[beef_idx + 42:]
                nul = cand.find(b"\x00\x00")
                if nul != -1:
                    if nul % 2 != 0:
                        nul += 1
                    long_name = cand[:nul].decode("utf-16le", errors="ignore").rstrip("\x00")
            return {
                "artifact_type": "ShellBag (Klasör/Dosya)",
                "name": long_name or short_name or "(Bilinmiyor)",
                "modified_dos": mod_str,
            }

        return {
            "artifact_type": f"ShellBag (Tip 0x{item_type:02X})",
            "name": raw_bytes[3:min(item_size, 32)].decode("ascii", "ignore").strip("\x00") or f"Type_0x{item_type:02X}",
            "modified_dos": None,
        }

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
    """Generate authentic synthetic .lnk, 8-timestamp .pf, .automaticDestinations-ms JumpList, and $I files."""
    os.makedirs(output_dir, exist_ok=True)
    paths: Dict[str, str] = {}

    # 1. Synthetic .lnk
    lnk_path = os.path.join(output_dir, "gizli_arsiv.lnk")
    lnk = bytearray(76)
    struct.pack_into("<I", lnk, 0, 0x4C)
    lnk[4:20] = bytes.fromhex("0114020000000000c000000000000046")
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
    lnk_bytes = bytes(lnk) + bytes(info_hdr) + wdir_b
    with open(lnk_path, "wb") as f:
        f.write(lnk_bytes)
    paths["lnk"] = lnk_path

    # 2. Synthetic Prefetch (.pf v30 with 3 timestamps + loaded DLL/EXE file strings)
    pf_path = os.path.join(output_dir, "POWERSHELL.EXE-A1B2C3D4.pf")
    loaded_str = "\\VOLUME{01d}\\WINDOWS\\SYSTEM32\\NTDLL.DLL\x00\\VOLUME{01d}\\USERS\\PUBLIC\\EXFIL.PS1\x00".encode("utf-16le")
    pf = bytearray(256 + len(loaded_str))
    struct.pack_into("<I", pf, 0, 30)
    pf[4:8] = b"SCCA"
    exe_b = "POWERSHELL.EXE".encode("utf-16le")
    pf[16:16 + len(exe_b)] = exe_b
    struct.pack_into("<I", pf, 76, 0xA1B2C3D4)
    struct.pack_into("<II", pf, 100, 256, len(loaded_str))
    struct.pack_into("<Q", pf, 128, datetime_to_filetime(datetime(2026, 11, 20, 19, 41, 3)))
    struct.pack_into("<Q", pf, 136, datetime_to_filetime(datetime(2026, 11, 20, 18, 10, 0)))
    struct.pack_into("<Q", pf, 144, datetime_to_filetime(datetime(2026, 11, 19, 9, 5, 0)))
    struct.pack_into("<I", pf, 208, 7)
    pf[256:] = loaded_str
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

    # 4. Synthetic OLE2 Jump List (.automaticDestinations-ms) embedding lnk_bytes
    jl_path = os.path.join(output_dir, "sample.automaticDestinations-ms")
    sec_sz = 512
    # Header + Sector 0 (FAT) + Sector 1 (Directory) + Sector 2 (LNK stream)
    ole = bytearray(sec_sz * 4)
    ole[0:8] = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
    struct.pack_into("<HH", ole, 24, 0x003E, 0x0003)
    struct.pack_into("<HH", ole, 28, 0xFFFE, 9)  # 512B sector
    struct.pack_into("<I", ole, 44, 1)           # 1 FAT sector
    struct.pack_into("<I", ole, 48, 1)           # first dir sector = 1
    struct.pack_into("<I", ole, 76, 0)           # FAT at sector 0
    # FAT sector 0: [0]=FFFFFFFD (FAT), [1]=FFFFFFFE (Dir EOF), [2]=FFFFFFFE (Stream EOF)
    struct.pack_into("<III", ole, sec_sz, 0xFFFFFFFD, 0xFFFFFFFE, 0xFFFFFFFE)
    # Directory entry 0 (Root Entry) + Directory entry 1 (stream "1" at sector 2)
    dir_off = sec_sz * 2
    root_name = "Root Entry\x00".encode("utf-16le")
    ole[dir_off:dir_off + len(root_name)] = root_name
    struct.pack_into("<HB", ole, dir_off + 64, len(root_name), 5)
    ent1_off = dir_off + 128
    s1_name = "1\x00".encode("utf-16le")
    ole[ent1_off:ent1_off + len(s1_name)] = s1_name
    struct.pack_into("<HB", ole, ent1_off + 64, len(s1_name), 2)
    struct.pack_into("<II", ole, ent1_off + 116, 2, len(lnk_bytes))
    # Stream data at sector 2
    ole[sec_sz * 3:sec_sz * 3 + len(lnk_bytes)] = lnk_bytes
    with open(jl_path, "wb") as f:
        f.write(ole)
    paths["jumplist"] = jl_path

    return paths
