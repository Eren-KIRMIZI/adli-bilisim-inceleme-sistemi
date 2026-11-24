"""Original Windows Event Log (EVTX) binary parser and forensic event analyzer."""

import os
import re
import struct
from datetime import datetime
from typing import Any, Dict, List, Optional

from src.ntfs_engine.ntfs_service import filetime_to_datetime, datetime_to_filetime

CRITICAL_EVENT_DESCRIPTIONS = {
    1102: ("Denetim Günlüğü Temizlendi (Audit Log Cleared)", "Kritik"),
    4624: ("Başarılı Oturum Açma (Successful Logon)", "Normal"),
    4625: ("Başarısız Oturum Açma (Failed Logon)", "Uyarı"),
    4648: ("Açık Kimlik Bilgisi ile Oturum Açma", "Uyarı"),
    4672: ("Özel Yetkili Oturum Atandı (Admin Logon)", "İnceleniyor"),
    4688: ("Yeni Süreç Oluşturuldu (Process Creation)", "İnceleniyor"),
    4720: ("Yeni Kullanıcı Hesabı Oluşturuldu", "Uyarı"),
    7045: ("Sisteme Yeni Servis Kuruldu", "Uyarı"),
}


class EventLogService:
    """Original binary parser for Microsoft EVTX ('ElfFile') log containers."""

    PARSER_NAME = "AdliBilisim-Original-EVTX-Parser"
    PARSER_VERSION = "1.0.0"

    def parse_evtx_file(self, path: str, max_records: int = 2000) -> Dict[str, Any]:
        """Parse an EVTX file in strict read-only binary mode."""
        if not os.path.isfile(path):
            raise FileNotFoundError(f"EVTX dosyası bulunamadı: {path}")

        with open(path, "rb") as f:
            data = f.read()

        if len(data) < 4096 or data[:8] != b"ElfFile\x00":
            raise ValueError("Geçerli Windows Event Log ('ElfFile') başlığı bulunamadı.")

        oldest_chunk, current_chunk, next_rec_id = struct.unpack("<QQQ", data[8:32])
        num_chunks = struct.unpack("<H", data[42:44])[0]
        warnings: List[str] = []
        events: List[Dict[str, Any]] = []

        # Walk 64KB chunks starting at offset 4096
        pos = 4096
        while pos + 512 <= len(data) and len(events) < max_records:
            if data[pos:pos + 8] != b"ElfChnk\x00":
                pos += 65536
                continue

            free_space_off = struct.unpack("<I", data[pos + 48:pos + 52])[0]
            chunk_end = min(len(data), pos + (free_space_off if 512 <= free_space_off <= 65536 else 65536))
            rec_off = pos + 512

            while rec_off + 24 <= chunk_end and len(events) < max_records:
                if data[rec_off:rec_off + 4] != b"\x2a\x2a\x00\x00":
                    break
                rec_size = struct.unpack("<I", data[rec_off + 4:rec_off + 8])[0]
                if rec_size < 28 or rec_off + rec_size > chunk_end:
                    warnings.append(f"Chunk 0x{pos:X} içinde bozuk/eksik olay kaydı boyutu atlandı.")
                    break

                rec_id = struct.unpack("<Q", data[rec_off + 8:rec_off + 16])[0]
                written_ft = struct.unpack("<Q", data[rec_off + 16:rec_off + 24])[0]
                ts = filetime_to_datetime(written_ft)
                binxml_payload = data[rec_off + 24:rec_off + rec_size - 4]

                # Extract readable strings and EventID clues from BinXML tokens
                strings = self._extract_binxml_strings(binxml_payload)
                event_id = self._infer_event_id(binxml_payload, strings)
                desc, severity = CRITICAL_EVENT_DESCRIPTIONS.get(
                    event_id, ("Windows Olay Kaydı", "Normal")
                )

                events.append({
                    "record_id": rec_id,
                    "event_id": event_id,
                    "timestamp": ts,
                    "description": desc,
                    "severity": severity,
                    "details": " | ".join(strings[:8]) if strings else "(BinXML içeriği çözümlenemedi)",
                    "source_offset": f"0x{rec_off:08X}",
                    "raw_bytes": data[rec_off:rec_off + min(rec_size, 2048)],
                })
                rec_off += rec_size

            pos += 65536

        return {
            "path": path,
            "filename": os.path.basename(path),
            "chunk_count": num_chunks,
            "next_record_id": next_rec_id,
            "events": events,
            "warnings": warnings,
        }

    def _extract_binxml_strings(self, payload: bytes) -> List[str]:
        """Extract UTF-16LE and ASCII text tokens embedded inside BinXML records."""
        found: List[str] = []
        # UTF-16LE sequences of >=4 printable ASCII chars
        for m in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}", payload):
            s = m.group(0).decode("utf-16le", errors="ignore").strip()
            if s and s not in found:
                found.append(s)
        return found

    def _infer_event_id(self, payload: bytes, strings: List[str]) -> Optional[int]:
        for s in strings:
            m = re.match(r"EventID=(\d{3,5})", s)
            if m:
                return int(m.group(1))
        # Also search uint16 known critical event IDs preceded by BinXML uint16 value type (0x06)
        for eid in CRITICAL_EVENT_DESCRIPTIONS:
            marker = b"\x06" + struct.pack("<H", eid)
            if marker in payload:
                return eid
        return None


def create_synthetic_evtx_file(output_path: str) -> str:
    """Generate a valid synthetic EVTX ('ElfFile') sample containing realistic DFIR security events."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    # 4096 file header + 65536 chunk
    buf = bytearray(4096 + 65536)
    buf[0:8] = b"ElfFile\x00"
    struct.pack_into("<QQQ", buf, 8, 0, 0, 6)
    struct.pack_into("<IHH", buf, 32, 128, 3, 1)
    struct.pack_into("<H", buf, 42, 1)  # 1 chunk

    chunk = 4096
    buf[chunk:chunk + 8] = b"ElfChnk\x00"
    struct.pack_into("<QQQQ", buf, chunk + 8, 1, 5, 1, 5)

    sample_events = [
        (1, 4624, datetime(2026, 11, 20, 8, 55, 12), ["Microsoft-Windows-Security-Auditing", "AhmetK", "LogonType=2", "Workstation=FINANS-PC04"]),
        (2, 4688, datetime(2026, 11, 20, 19, 41, 3), ["Security", "MehmetS", "powershell.exe -EncodedCommand ZQBjAGgAbwA=", "Parent=cmd.exe"]),
        (3, 7045, datetime(2026, 11, 20, 19, 41, 18), ["Service Control Manager", "ServiceName=RemoteExecHelper", "ImagePath=C:\\Users\\Public\\svchost_upd.exe"]),
        (4, 4625, datetime(2026, 11, 20, 21, 12, 44), ["Security", "Administrator", "Status=0xC000006D", "SourceIP=192.168.10.45"]),
        (5, 1102, datetime(2026, 11, 20, 21, 18, 5), ["Microsoft-Windows-Eventlog", "MehmetS", "The audit log was cleared"]),
    ]

    rec_pos = chunk + 512
    for rid, eid, dt, tokens in sample_events:
        # Encode EventID marker + UTF-16LE strings
        body = b"\x06" + struct.pack("<H", eid) + f"EventID={eid}".encode("utf-16le") + b"\x00\x00"
        for tok in tokens:
            body += tok.encode("utf-16le") + b"\x00\x00"
        # Pad to 4-byte boundary
        while len(body) % 4 != 0:
            body += b"\x00"
        rec_size = 24 + len(body) + 4
        struct.pack_into("<IIQQ", buf, rec_pos, 0x00002A2A, rec_size, rid, datetime_to_filetime(dt))
        buf[rec_pos + 24:rec_pos + 24 + len(body)] = body
        struct.pack_into("<I", buf, rec_pos + rec_size - 4, rec_size)
        rec_pos += rec_size

    struct.pack_into("<I", buf, chunk + 48, rec_pos - chunk)  # free space offset
    with open(output_path, "wb") as f:
        f.write(buf)
    return output_path
