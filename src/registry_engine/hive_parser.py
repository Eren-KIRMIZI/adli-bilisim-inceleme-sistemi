"""Original Windows Registry Hive ('regf') binary parser and live read-only triage reader."""

import os
import struct
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.ntfs_engine.ntfs_service import filetime_to_datetime, datetime_to_filetime

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False

REG_TYPES = {
    0: "REG_NONE",
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    5: "REG_DWORD_BIG_ENDIAN",
    6: "REG_LINK",
    7: "REG_MULTI_SZ",
    11: "REG_QWORD",
}


class RegistryHiveParser:
    """Pure-Python binary parser for Windows Registry Hive ('regf') files and live winreg."""

    PARSER_NAME = "AdliBilisim-Original-RegistryHive-Parser"
    PARSER_VERSION = "1.0.0"

    def parse_hive_file(self, path: str, max_nodes: int = 5000) -> Dict[str, Any]:
        """Parse an offline Windows Registry Hive ('regf') file in strict read-only mode."""
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Registry kovanı bulunamadı: {path}")

        with open(path, "rb") as f:
            data = f.read()

        if len(data) < 4096 or data[:4] != b"regf":
            raise ValueError("Geçerli Windows Registry Hive ('regf') başlığı bulunamadı.")

        last_write = filetime_to_datetime(struct.unpack("<Q", data[12:20])[0])
        root_cell_rel = struct.unpack("<I", data[36:40])[0]
        hive_name = data[48:112].decode("utf-16le", errors="ignore").rstrip("\x00")
        hbin_base = 4096

        visited = set()
        node_counter = [0]

        def read_cell(rel_offset: int) -> bytes:
            if rel_offset in (0, 0xFFFFFFFF):
                return b""
            abs_off = hbin_base + rel_offset
            if abs_off + 4 > len(data):
                return b""
            cell_size = abs(struct.unpack("<i", data[abs_off:abs_off + 4])[0])
            if cell_size < 4 or abs_off + cell_size > len(data):
                return b""
            return data[abs_off + 4:abs_off + cell_size]

        def decode_vk(rel_off: int) -> Optional[Dict[str, Any]]:
            cell = read_cell(rel_off)
            if len(cell) < 20 or cell[:2] != b"vk":
                return None
            name_len = struct.unpack("<H", cell[2:4])[0]
            data_len_raw = struct.unpack("<I", cell[4:8])[0]
            data_off_raw = struct.unpack("<I", cell[8:12])[0]
            val_type = struct.unpack("<I", cell[12:16])[0]
            flags = struct.unpack("<H", cell[16:18])[0]

            if name_len == 0:
                val_name = "(Default)"
            elif len(cell) >= 20 + name_len:
                raw_name = cell[20:20 + name_len]
                val_name = raw_name.decode("ascii" if (flags & 0x01) else "utf-16le", errors="replace")
            else:
                val_name = "<Bozuk İsim>"

            is_inline = bool(data_len_raw & 0x80000000)
            real_len = data_len_raw & 0x7FFFFFFF
            if is_inline:
                raw_val = struct.pack("<I", data_off_raw)[:real_len]
            else:
                raw_val = read_cell(data_off_raw)[:real_len]

            parsed_val = self._format_reg_value(val_type, raw_val)
            return {
                "name": val_name,
                "type": REG_TYPES.get(val_type, f"TYPE_{val_type}"),
                "value": parsed_val,
                "raw_bytes": raw_val,
            }

        def collect_subkeys(list_rel: int) -> List[int]:
            cell = read_cell(list_rel)
            if len(cell) < 4:
                return []
            sig = cell[:2]
            count = struct.unpack("<H", cell[2:4])[0]
            out: List[int] = []
            if sig in (b"lf", b"lh"):
                for i in range(count):
                    pos = 4 + i * 8
                    if pos + 4 <= len(cell):
                        out.append(struct.unpack("<I", cell[pos:pos + 4])[0])
            elif sig == b"li":
                for i in range(count):
                    pos = 4 + i * 4
                    if pos + 4 <= len(cell):
                        out.append(struct.unpack("<I", cell[pos:pos + 4])[0])
            elif sig == b"ri":
                for i in range(count):
                    pos = 4 + i * 4
                    if pos + 4 <= len(cell):
                        out.extend(collect_subkeys(struct.unpack("<I", cell[pos:pos + 4])[0]))
            return out

        def parse_nk(rel_off: int, parent_path: str = "") -> Optional[Dict[str, Any]]:
            if rel_off in visited or node_counter[0] >= max_nodes:
                return None
            visited.add(rel_off)
            cell = read_cell(rel_off)
            if len(cell) < 76 or cell[:2] != b"nk":
                return None

            node_counter[0] += 1
            flags = struct.unpack("<H", cell[2:4])[0]
            ts = filetime_to_datetime(struct.unpack("<Q", cell[4:12])[0])
            subkey_count = struct.unpack("<I", cell[20:24])[0]
            subkey_list_off = struct.unpack("<I", cell[28:32])[0]
            val_count = struct.unpack("<I", cell[36:40])[0]
            val_list_off = struct.unpack("<I", cell[40:44])[0]
            name_len = struct.unpack("<H", cell[72:74])[0]

            if len(cell) >= 76 + name_len:
                raw_kname = cell[76:76 + name_len]
                kname = raw_kname.decode("ascii" if (flags & 0x20) else "utf-16le", errors="replace")
            else:
                kname = "<Adsız>"

            full_path = f"{parent_path}\\{kname}" if parent_path else kname

            values: List[Dict[str, Any]] = []
            if val_count > 0 and val_list_off != 0xFFFFFFFF:
                vlist_cell = read_cell(val_list_off)
                for i in range(min(val_count, len(vlist_cell) // 4)):
                    vk_off = struct.unpack("<I", vlist_cell[i * 4:(i + 1) * 4])[0]
                    vk = decode_vk(vk_off)
                    if vk:
                        values.append(vk)

            children: List[Dict[str, Any]] = []
            if subkey_count > 0 and subkey_list_off != 0xFFFFFFFF:
                for sk_off in collect_subkeys(subkey_list_off):
                    child = parse_nk(sk_off, full_path)
                    if child:
                        children.append(child)

            return {
                "name": kname,
                "path": full_path,
                "last_written": ts,
                "values": values,
                "children": children,
            }

        root_node = parse_nk(root_cell_rel)
        return {
            "path": path,
            "filename": os.path.basename(path),
            "hive_name": hive_name or os.path.basename(path),
            "last_written": last_write,
            "root": root_node,
            "total_keys_parsed": node_counter[0],
        }

    def _format_reg_value(self, val_type: int, raw: bytes) -> str:
        if val_type in (1, 2):  # REG_SZ, REG_EXPAND_SZ
            return raw.decode("utf-16le", errors="replace").rstrip("\x00")
        if val_type == 4 and len(raw) >= 4:  # REG_DWORD
            val = struct.unpack("<I", raw[:4])[0]
            return f"{val} (0x{val:08X})"
        if val_type == 11 and len(raw) >= 8:  # REG_QWORD
            val = struct.unpack("<Q", raw[:8])[0]
            return f"{val} (0x{val:016X})"
        if val_type == 7:  # REG_MULTI_SZ
            txt = raw.decode("utf-16le", errors="replace")
            return " | ".join(s for s in txt.split("\x00") if s)
        return raw[:64].hex(" ").upper() if raw else "(Boş)"

    def read_live_windows_triage(self) -> Dict[str, Any]:
        """Collect read-only Windows forensic artifacts from the live Registry (Run, Services, Profiles, TypedPaths)."""
        if not HAS_WINREG:
            return {"supported": False, "reason": "winreg yalnızca Windows platformunda desteklenir.", "categories": {}}

        categories: Dict[str, List[Dict[str, Any]]] = {
            "Başlangıç Programları (Run/RunOnce)": [],
            "Windows Servisleri (Services)": [],
            "Kullanıcı Profilleri (ProfileList)": [],
            "Son Yazılan Yollar (TypedPaths)": [],
        }

        # 1. Autorun keys
        run_targets = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
        ]
        for hive, subkey, hname in run_targets:
            try:
                with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as k:
                    n_vals = winreg.QueryInfoKey(k)[1]
                    for i in range(n_vals):
                        vname, vdata, vtype = winreg.EnumValue(k, i)
                        categories["Başlangıç Programları (Run/RunOnce)"].append({
                            "Kategori": "Başlangıç (Autorun)",
                            "Ad": vname,
                            "Değer / Yol": str(vdata),
                            "Kaynak": f"{hname}\\{subkey}",
                            "Durum": "İnceleniyor" if any(x in str(vdata).lower() for x in ["appdata", "temp", "powershell", "cmd"]) else "Normal",
                        })
            except Exception:
                pass

        # 2. Services (bounded to 150 entries for fast interactive display)
        try:
            svc_root = r"SYSTEM\CurrentControlSet\Services"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, svc_root, 0, winreg.KEY_READ) as sk:
                total_svcs = winreg.QueryInfoKey(sk)[0]
                for i in range(min(total_svcs, 150)):
                    sname = winreg.EnumKey(sk, i)
                    try:
                        with winreg.OpenKey(sk, sname, 0, winreg.KEY_READ) as one:
                            img = ""
                            start_mode = ""
                            try:
                                img, _ = winreg.QueryValueEx(one, "ImagePath")
                            except Exception:
                                pass
                            try:
                                st, _ = winreg.QueryValueEx(one, "Start")
                                start_mode = {0: "Boot", 1: "System", 2: "Auto", 3: "Manual", 4: "Disabled"}.get(st, str(st))
                            except Exception:
                                pass
                            if img:
                                categories["Windows Servisleri (Services)"].append({
                                    "Kategori": f"Servis ({start_mode or '-'})",
                                    "Ad": sname,
                                    "Değer / Yol": str(img),
                                    "Kaynak": f"HKLM\\{svc_root}\\{sname}",
                                    "Durum": "Normal",
                                })
                    except Exception:
                        continue
        except Exception:
            pass

        # 3. User Profiles (SIDs)
        try:
            prof_root = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, prof_root, 0, winreg.KEY_READ) as pk:
                for i in range(winreg.QueryInfoKey(pk)[0]):
                    sid = winreg.EnumKey(pk, i)
                    try:
                        with winreg.OpenKey(pk, sid, 0, winreg.KEY_READ) as one:
                            pdir, _ = winreg.QueryValueEx(one, "ProfileImagePath")
                            categories["Kullanıcı Profilleri (ProfileList)"].append({
                                "Kategori": "Kullanıcı Hesabı",
                                "Ad": sid,
                                "Değer / Yol": str(pdir),
                                "Kaynak": f"HKLM\\{prof_root}\\{sid}",
                                "Durum": "Doğrulandı",
                            })
                    except Exception:
                        continue
        except Exception:
            pass

        # 4. TypedPaths
        try:
            tp_root = r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, tp_root, 0, winreg.KEY_READ) as tk:
                for i in range(winreg.QueryInfoKey(tk)[1]):
                    vname, vdata, _ = winreg.EnumValue(tk, i)
                    categories["Son Yazılan Yollar (TypedPaths)"].append({
                        "Kategori": "Kullanıcı Aktivitesi",
                        "Ad": vname,
                        "Değer / Yol": str(vdata),
                        "Kaynak": f"HKCU\\{tp_root}",
                        "Durum": "Normal",
                    })
        except Exception:
            pass

        return {"supported": True, "categories": categories}


def create_synthetic_registry_hive(output_path: str) -> str:
    """Build a valid minimal Windows Registry Hive ('regf') binary file for testing & demonstration."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    buf = bytearray(8192)  # 4KB regf header + 4KB hbin

    # regf header
    buf[0:4] = b"regf"
    now_ft = datetime_to_filetime(datetime(2026, 11, 20, 15, 0, 0))
    struct.pack_into("<II", buf, 4, 1, 1)         # seq1, seq2
    struct.pack_into("<Q", buf, 12, now_ft)       # last write
    struct.pack_into("<II", buf, 20, 1, 5)        # major=1, minor=5
    struct.pack_into("<I", buf, 36, 0x20)         # root cell offset (after 32-byte hbin header)
    struct.pack_into("<I", buf, 40, 4096)         # hbin data size
    hive_title = "SYSTEM_FORENSIC_TEST".encode("utf-16le")
    buf[48:48 + len(hive_title)] = hive_title

    # hbin header at 4096
    hbin = 4096
    buf[hbin:hbin + 4] = b"hbin"
    struct.pack_into("<II", buf, hbin + 4, 0, 4096)

    def write_cell(rel_off: int, payload: bytes):
        abs_off = hbin + rel_off
        cell_len = (4 + len(payload) + 7) & ~7
        struct.pack_into("<i", buf, abs_off, -cell_len)  # negative = allocated
        buf[abs_off + 4:abs_off + 4 + len(payload)] = payload
        return cell_len

    def make_nk(name: str, subkey_list_off: int, subkey_cnt: int, val_list_off: int, val_cnt: int) -> bytes:
        name_b = name.encode("ascii")
        nk = bytearray(76 + len(name_b))
        nk[0:2] = b"nk"
        struct.pack_into("<H", nk, 2, 0x20)  # ASCII name flag
        struct.pack_into("<Q", nk, 4, now_ft)
        struct.pack_into("<I", nk, 20, subkey_cnt)
        struct.pack_into("<I", nk, 28, subkey_list_off)
        struct.pack_into("<I", nk, 36, val_cnt)
        struct.pack_into("<I", nk, 40, val_list_off)
        struct.pack_into("<H", nk, 72, len(name_b))
        nk[76:] = name_b
        return bytes(nk)

    def make_vk(name: str, val_type: int, val_data: bytes, data_rel_off: int) -> bytes:
        name_b = name.encode("ascii")
        vk = bytearray(20 + len(name_b))
        vk[0:2] = b"vk"
        struct.pack_into("<H", vk, 2, len(name_b))
        if len(val_data) <= 4:
            struct.pack_into("<I", vk, 4, len(val_data) | 0x80000000)
            padded = val_data.ljust(4, b"\x00")
            vk[8:12] = padded
        else:
            struct.pack_into("<I", vk, 4, len(val_data))
            struct.pack_into("<I", vk, 8, data_rel_off)
        struct.pack_into("<I", vk, 12, val_type)
        struct.pack_into("<H", vk, 16, 0x01)
        vk[20:] = name_b
        return bytes(vk)

    # Allocate cells sequentially from 0x100 upward (root stays at 0x20, lh list at 0x90)
    cursor = 0x100
    comp_val = "WIN-FORENSIC-01\x00".encode("utf-16le")
    comp_val_off = cursor
    cursor += write_cell(comp_val_off, comp_val)

    comp_vk_off = cursor
    cursor += write_cell(comp_vk_off, make_vk("ComputerName", 1, comp_val, comp_val_off))

    comp_vlist_off = cursor
    cursor += write_cell(comp_vlist_off, struct.pack("<I", comp_vk_off))

    ccs_nk_off = cursor
    cursor += write_cell(ccs_nk_off, make_nk("CurrentControlSet", 0xFFFFFFFF, 0, comp_vlist_off, 1))

    updater_val = (r"C:\Users\Public\updater.exe" + "\x00").encode("utf-16le")
    updater_val_off = cursor
    cursor += write_cell(updater_val_off, updater_val)

    updater_vk_off = cursor
    cursor += write_cell(updater_vk_off, make_vk("SuspiciousUpdater", 1, updater_val, updater_val_off))

    updater_vlist_off = cursor
    cursor += write_cell(updater_vlist_off, struct.pack("<I", updater_vk_off))

    run_nk_off = cursor
    cursor += write_cell(run_nk_off, make_nk("AutorunEntries", 0xFFFFFFFF, 0, updater_vlist_off, 1))

    lh = b"lh" + struct.pack("<H", 2) + struct.pack("<II", ccs_nk_off, 1) + struct.pack("<II", run_nk_off, 2)
    write_cell(0x90, lh)
    write_cell(0x20, make_nk("ROOT_HIVE", 0x90, 2, 0xFFFFFFFF, 0))

    with open(output_path, "wb") as f:
        f.write(buf)
    return output_path
