"""Memory Forensics Engine: Dump header/KDBG inspection, PE/IOC & Proc pool heuristic, Volatility 3 check, live snapshot.

Strict forensic honesty: Pool-tag EPROCESS candidates and raw strings are explicitly flagged
with heuristic confidence and never presented as full PDB-verified process trees.
"""

import ctypes
from ctypes import wintypes
import importlib.util
import os
import re
import shutil
import struct
from datetime import datetime
from typing import Any, Dict, List

IS_WINDOWS = os.name == "nt" and hasattr(ctypes, "windll")


class MemoryForensicsEngine:
    """Original RAM dump inspector and live Windows volatile process triage."""

    PARSER_NAME = "AdliBilisim-Original-Memory-Engine"
    PARSER_VERSION = "2.0.0"

    @staticmethod
    def detect_volatility3() -> Dict[str, Any]:
        """Check whether optional Volatility 3 CLI or Python package is installed."""
        cli = shutil.which("vol") or shutil.which("vol3")
        pkg = importlib.util.find_spec("volatility3") is not None
        return {"available": bool(cli or pkg), "cli_path": cli, "python_pkg": pkg}

    def inspect_memory_dump(self, dump_path: str, max_scan_mb: int = 32) -> Dict[str, Any]:
        """Inspect a RAM dump file read-only without fabricating unverified structures."""
        if not os.path.isfile(dump_path):
            raise FileNotFoundError(f"RAM imajı bulunamadı: {dump_path}")

        size = os.path.getsize(dump_path)
        warnings: List[str] = []
        with open(dump_path, "rb") as f:
            head = f.read(min(size, 4096))

        fmt, arch, hdr_details = self._detect_dump_format(head)

        if fmt == "Bilinmeyen / Desteklenmeyen Format":
            warnings.append(
                "Bilinen bellek döküm başlığı (PAGEDU64/PAGEDUMP/ELF/HIBR/LiME) tespit edilmedi; "
                "RAW bellek olarak yalnızca doğrulanabilir KDBG, PE başlıkları, Proc pool adayları ve IOC kalıntıları taranmaktadır."
            )
        else:
            warnings.append(
                "Tam çekirdek sembol tablosu (PDB) olmadan kesin EPROCESS ağacı türetilmez; "
                "doğrulanan başlıklar, KDBG işaretçileri, PE modülleri ve düşük/orta güvenilirlikli Proc havuz adayları listelenmiştir."
            )

        scan_limit = min(size, max_scan_mb * 1024 * 1024)
        pe_modules: List[Dict[str, Any]] = []
        iocs: List[Dict[str, Any]] = []
        kdbg_blocks: List[Dict[str, Any]] = []
        eprocess_candidates: List[Dict[str, Any]] = []

        with open(dump_path, "rb") as f:
            data = f.read(scan_limit)

        # 1. Scan for KDBG kernel debug blocks & parse pointers if large enough
        pos = 0
        while len(kdbg_blocks) < 10:
            idx = data.find(b"KDBG", pos)
            if idx == -1:
                break
            info = {"offset_hex": f"0x{idx:08X}"}
            if idx >= 16 and idx + 80 <= len(data):
                # In _DBGKD_DEBUG_DATA_HEADER64, OwnerTag 'KDBG' is at +16 (size at +20)
                ps_loaded = struct.unpack("<Q", data[idx + 56:idx + 64])[0] if idx + 64 <= len(data) else 0
                ps_active = struct.unpack("<Q", data[idx + 64:idx + 72])[0] if idx + 72 <= len(data) else 0
                info["ps_loaded_modules_ptr"] = f"0x{ps_loaded:016X}"
                info["ps_active_process_ptr"] = f"0x{ps_active:016X}"
            kdbg_blocks.append(info)
            pos = idx + 4

        # 2. Scan for Windows 'Proc' pool tag heuristic + nearby ImageFileName (.exe)
        pos = 0
        seen_proc = set()
        while len(eprocess_candidates) < 150:
            idx = data.find(b"Proc", pos)
            if idx == -1:
                break
            window = data[idx:min(len(data), idx + 1536)]
            m = re.search(rb"([a-zA-Z0-9_\-]{2,20}\.exe)\x00", window)
            if m:
                name = m.group(1).decode("ascii", "replace")
                key = (idx, name)
                if key not in seen_proc:
                    seen_proc.add(key)
                    eprocess_candidates.append({
                        "offset_hex": f"0x{idx:08X}",
                        "image_name": name,
                        "confidence": "Orta (Proc Pool Heuristiği — PDB Doğrulamasız)",
                    })
            pos = idx + 4

        # 3. Scan for in-memory PE headers (MZ ... PE\x00\x00)
        pos = 0
        while len(pe_modules) < 200:
            idx = data.find(b"MZ", pos)
            if idx == -1:
                break
            if idx + 0x40 <= len(data):
                e_lfanew = struct.unpack("<I", data[idx + 0x3C:idx + 0x40])[0]
                if 0x40 <= e_lfanew <= 0x400 and idx + e_lfanew + 6 <= len(data):
                    if data[idx + e_lfanew:idx + e_lfanew + 4] == b"PE\x00\x00":
                        machine = struct.unpack("<H", data[idx + e_lfanew + 4:idx + e_lfanew + 6])[0]
                        pe_arch = "x64 (AMD64)" if machine == 0x8664 else ("x86 (I386)" if machine == 0x014C else f"0x{machine:04X}")
                        pe_modules.append({
                            "offset_hex": f"0x{idx:08X}",
                            "arch": pe_arch,
                            "type": "In-Memory PE Image (MZ/PE)",
                            "preview": data[idx:idx + 256],
                        })
            pos = idx + 2

        # 4. Scan for IPv4 & HTTP/HTTPS URL strings in memory
        for m in re.finditer(rb"https?://[a-zA-Z0-9\.\-_:/\?=&%]{6,120}", data):
            if len(iocs) >= 150:
                break
            iocs.append({
                "kind": "URL Kalıntısı",
                "value": m.group(0).decode("ascii", "replace"),
                "offset_hex": f"0x{m.start():08X}",
            })
        for m in re.finditer(rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", data):
            if len(iocs) >= 200:
                break
            ip = m.group(0).decode("ascii")
            if not ip.startswith("0.") and ip != "127.0.0.1":
                iocs.append({
                    "kind": "IPv4 Adresi",
                    "value": ip,
                    "offset_hex": f"0x{m.start():08X}",
                })

        return {
            "path": dump_path,
            "filename": os.path.basename(dump_path),
            "size_bytes": size,
            "format": fmt,
            "architecture": arch,
            "header_details": hdr_details,
            "kdbg_offsets": [k["offset_hex"] for k in kdbg_blocks],
            "kdbg_blocks": kdbg_blocks,
            "eprocess_candidates": eprocess_candidates,
            "pe_modules": pe_modules,
            "iocs": iocs,
            "volatility3": self.detect_volatility3(),
            "warnings": warnings,
            "header_bytes": head,
        }

    def _detect_dump_format(self, head: bytes):
        if head.startswith(b"PAGEDU64"):
            return "Windows 64-bit Crash Dump (PAGEDU64)", "x64", {"Signature": "PAGEDU64"}
        if head.startswith(b"PAGEDUMP"):
            return "Windows 32-bit Crash Dump (PAGEDUMP)", "x86", {"Signature": "PAGEDUMP"}
        if head.startswith(b"HIBR") or head.startswith(b"hibr"):
            return "Windows Hibernation File (hiberfil.sys)", "x86/x64", {"Signature": "HIBR"}
        if head.startswith(b"\x7fELF"):
            return "ELF Core / Memory Dump", "ELF", {"Signature": "0x7F ELF"}
        if head.startswith(b"EMiL"):
            return "LiME Linux Memory Image", "Linux", {"Signature": "EMiL"}
        return "Bilinmeyen / Desteklenmeyen Format", "Belirsiz (RAW)", {}

    def capture_live_windows_processes(self) -> Dict[str, Any]:
        """Collect read-only live volatile process list (PID, PPID, Name, Threads) via Windows Toolhelp32 API."""
        if not IS_WINDOWS:
            return {"supported": False, "reason": "Canlı bellek süreç görünümü yalnızca Windows üzerinde desteklenir.", "processes": []}

        TH32CS_SNAPPROCESS = 0x00000002

        class PROCESSENTRY32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", wintypes.WCHAR * 260),
            ]

        kernel32 = ctypes.windll.kernel32
        snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snap == ctypes.c_void_p(-1).value:
            return {"supported": False, "reason": "CreateToolhelp32Snapshot çağrısı başarısız.", "processes": []}

        processes: List[Dict[str, Any]] = []
        try:
            pe = PROCESSENTRY32W()
            pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            ok = kernel32.Process32FirstW(snap, ctypes.byref(pe))
            while ok:
                processes.append({
                    "pid": int(pe.th32ProcessID),
                    "ppid": int(pe.th32ParentProcessID),
                    "name": pe.szExeFile,
                    "threads": int(pe.cntThreads),
                    "priority": int(pe.pcPriClassBase),
                })
                ok = kernel32.Process32NextW(snap, ctypes.byref(pe))
        finally:
            kernel32.CloseHandle(snap)

        return {"supported": True, "captured_at": datetime.utcnow(), "processes": processes}


def create_synthetic_memory_dump(output_path: str) -> str:
    """Create a controlled synthetic Windows PAGEDU64 dump containing KDBG, Proc pool candidate, PE & IOC artifacts."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    buf = bytearray(32768)
    buf[0:8] = b"PAGEDU64"
    buf[4096:4100] = b"KDBG"

    # Embed synthetic PE header at 0x2000
    pe_off = 0x2000
    buf[pe_off:pe_off + 2] = b"MZ"
    struct.pack_into("<I", buf, pe_off + 0x3C, 0x80)
    buf[pe_off + 0x80:pe_off + 0x84] = b"PE\x00\x00"
    struct.pack_into("<H", buf, pe_off + 0x84, 0x8664)

    # Embed synthetic Proc pool tag + ImageFileName
    buf[0x2800:0x2804] = b"Proc"
    buf[0x2900:0x2910] = b"beacon_svc.exe\x00\x00"

    # Embed IOC strings at 0x3000
    iocs = b"http://198.51.100.42:8080/beacon.bin\x00C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\x00192.168.1.50\x00"
    buf[0x3000:0x3000 + len(iocs)] = iocs

    with open(output_path, "wb") as f:
        f.write(buf)
    return output_path
