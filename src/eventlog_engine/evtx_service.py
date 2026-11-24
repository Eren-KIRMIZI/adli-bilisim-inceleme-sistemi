"""Original Windows Event Log (EVTX) binary parser with structural BinXML decoding."""

import os
import re
import struct
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

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


def _decode_sid(raw: bytes) -> str:
    """Decode binary Windows SID into S-1-5-... notation."""
    if len(raw) < 8:
        return raw.hex()
    rev = raw[0]
    sub_cnt = raw[1]
    auth = int.from_bytes(raw[2:8], "big")
    subs = []
    for i in range(sub_cnt):
        off = 8 + i * 4
        if off + 4 <= len(raw):
            subs.append(str(struct.unpack("<I", raw[off:off + 4])[0]))
    return f"S-{rev}-{auth}" + (("-" + "-".join(subs)) if subs else "")


class BinXmlDecoder:
    """Pure-Python decoder for Microsoft BinXML chunks, templates, and substitution arrays."""

    @staticmethod
    def read_name(chunk_data: bytes, name_offset: int) -> str:
        """Read a BinXML Name entry stored inside the 64KB EVTX chunk."""
        if name_offset <= 0 or name_offset + 8 > len(chunk_data):
            return ""
        char_len = struct.unpack("<H", chunk_data[name_offset + 6:name_offset + 8])[0]
        end = name_offset + 8 + char_len * 2
        if end > len(chunk_data):
            return ""
        return chunk_data[name_offset + 8:end].decode("utf-16le", errors="replace").rstrip("\x00")

    @staticmethod
    def decode_value(val_type: int, raw: bytes) -> Any:
        if val_type == 0x00:
            return None
        if val_type == 0x01:  # Unicode string
            return raw.decode("utf-16le", errors="replace").rstrip("\x00")
        if val_type == 0x02:  # ANSI string
            return raw.decode("ascii", errors="replace").rstrip("\x00")
        if val_type in (0x03, 0x04) and len(raw) >= 1:
            return struct.unpack("<b" if val_type == 0x03 else "<B", raw[:1])[0]
        if val_type in (0x05, 0x06) and len(raw) >= 2:
            return struct.unpack("<h" if val_type == 0x05 else "<H", raw[:2])[0]
        if val_type in (0x07, 0x08) and len(raw) >= 4:
            return struct.unpack("<i" if val_type == 0x07 else "<I", raw[:4])[0]
        if val_type in (0x09, 0x0A) and len(raw) >= 8:
            return struct.unpack("<q" if val_type == 0x09 else "<Q", raw[:8])[0]
        if val_type == 0x0D and len(raw) >= 4:  # Bool32
            return bool(struct.unpack("<I", raw[:4])[0])
        if val_type == 0x0F and len(raw) >= 16:  # GUID
            return str(uuid.UUID(bytes_le=raw[:16]))
        if val_type == 0x11 and len(raw) >= 8:  # FILETIME
            dt = filetime_to_datetime(struct.unpack("<Q", raw[:8])[0])
            return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else raw.hex()
        if val_type == 0x13 and len(raw) >= 8:  # SID
            return _decode_sid(raw)
        if val_type == 0x14 and len(raw) >= 4:
            return f"0x{struct.unpack('<I', raw[:4])[0]:08X}"
        if val_type == 0x15 and len(raw) >= 8:
            return f"0x{struct.unpack('<Q', raw[:8])[0]:016X}"
        if val_type == 0x0E:
            return raw.hex()
        return raw.decode("utf-16le", errors="ignore").rstrip("\x00") or raw.hex()

    @classmethod
    def decode_record(cls, chunk_data: bytes, rec_rel_off: int, rec_size: int) -> Dict[str, Any]:
        """Extract structured fields and substitution values from a BinXML event record."""
        payload_start = rec_rel_off + 24
        payload_end = rec_rel_off + rec_size - 4
        payload = chunk_data[payload_start:payload_end]

        extracted_kv: Dict[str, Any] = {}
        substitutions: List[Any] = []
        element_names: List[str] = []

        # Scan for TemplateInstance (0x0C) / SubstitutionArray inside BinXML payload
        pos = 0
        while pos < len(payload):
            tok = payload[pos]
            base_tok = tok & 0x0F
            if tok == 0x0C and pos + 10 <= len(payload):
                # TemplateInstance: tok(1) + unknown(1) + template_id(4) + template_def_offset(4)
                tmpl_off = struct.unpack("<I", payload[pos + 6:pos + 10])[0]
                sub_pos = pos + 10
                # If template definition follows inline (chunk-relative offset), jump past template header
                if rec_rel_off + 24 <= tmpl_off < rec_rel_off + rec_size:
                    # TemplateDef header is 24 bytes at tmpl_off in chunk (relative to payload start = rec_rel_off + 24)
                    t_rel = tmpl_off - (rec_rel_off + 24)
                    if t_rel + 24 <= len(payload):
                        tmpl_data_size = struct.unpack("<I", payload[t_rel + 20:t_rel + 24])[0]
                        # Collect element names embedded in template
                        element_names.extend(cls._scan_template_names(chunk_data, payload[t_rel + 24:t_rel + 24 + tmpl_data_size]))
                        sub_pos = t_rel + 24 + tmpl_data_size
                if sub_pos + 4 <= len(payload):
                    subs = cls._read_substitution_array(payload, sub_pos)
                    if subs:
                        substitutions.extend(subs)
                        break
            elif tok == 0x01 or tok == 0x41:
                # OpenStartElement: dep_id(2) + data_size(4) + name_off(4)
                if pos + 11 <= len(payload):
                    name_off = struct.unpack("<I", payload[pos + 7:pos + 11])[0]
                    ename = cls.read_name(chunk_data, name_off)
                    if ename:
                        element_names.append(ename)
                    pos += 11
                    continue
            elif tok == 0x05 and pos + 4 <= len(payload):
                # ValueText: val_type(1) + char_len(2) + utf16
                vtype = payload[pos + 1]
                if vtype == 0x01:
                    clen = struct.unpack("<H", payload[pos + 2:pos + 4])[0]
                    if pos + 4 + clen * 2 <= len(payload):
                        val_s = payload[pos + 4:pos + 4 + clen * 2].decode("utf-16le", errors="replace")
                        if element_names:
                            extracted_kv[element_names[-1]] = val_s
                        pos += 4 + clen * 2
                        continue
            pos += 1

        # Map positional substitutions or Key=Value strings
        for idx, val in enumerate(substitutions):
            if val is not None and str(val).strip() != "":
                extracted_kv[f"Param_{idx}"] = val

        return {
            "elements": element_names,
            "substitutions": substitutions,
            "event_data": extracted_kv,
        }

    @classmethod
    def _scan_template_names(cls, chunk_data: bytes, tmpl_bytes: bytes) -> List[str]:
        names: List[str] = []
        p = 0
        while p + 11 <= len(tmpl_bytes):
            if tmpl_bytes[p] in (0x01, 0x41):
                noff = struct.unpack("<I", tmpl_bytes[p + 7:p + 11])[0]
                n = cls.read_name(chunk_data, noff)
                if n:
                    names.append(n)
            p += 1
        return names

    @classmethod
    def _read_substitution_array(cls, payload: bytes, start: int) -> List[Any]:
        if start + 4 > len(payload):
            return []
        num_subs = struct.unpack("<I", payload[start:start + 4])[0]
        if num_subs == 0 or num_subs > 128:
            return []
        meta_start = start + 4
        meta_end = meta_start + num_subs * 4
        if meta_end > len(payload):
            return []

        specs: List[Tuple[int, int]] = []
        for i in range(num_subs):
            sz, vtype = struct.unpack("<HBB", payload[meta_start + i * 4:meta_start + (i + 1) * 4])[:2]
            specs.append((sz, vtype))

        data_pos = meta_end
        out: List[Any] = []
        for sz, vtype in specs:
            if data_pos + sz > len(payload):
                break
            raw = payload[data_pos:data_pos + sz]
            out.append(cls.decode_value(vtype, raw))
            data_pos += sz
        return out


class EventLogService:
    """Original binary parser for Microsoft EVTX ('ElfFile') log containers."""

    PARSER_NAME = "AdliBilisim-Original-EVTX-Parser"
    PARSER_VERSION = "2.0.0"

    def parse_evtx_file(self, path: str, max_records: int = 5000) -> Dict[str, Any]:
        """Parse an EVTX file in strict read-only binary mode with structural BinXML decoding."""
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

        pos = 4096
        while pos + 512 <= len(data) and len(events) < max_records:
            if data[pos:pos + 8] != b"ElfChnk\x00":
                pos += 65536
                continue

            chunk_data = data[pos:pos + 65536]
            free_space_off = struct.unpack("<I", chunk_data[48:52])[0]
            chunk_end = min(len(chunk_data), free_space_off if 512 <= free_space_off <= 65536 else len(chunk_data))
            rec_off = 512

            while rec_off + 24 <= chunk_end and len(events) < max_records:
                if chunk_data[rec_off:rec_off + 4] != b"\x2a\x2a\x00\x00":
                    break
                rec_size = struct.unpack("<I", chunk_data[rec_off + 4:rec_off + 8])[0]
                if rec_size < 28 or rec_off + rec_size > chunk_end:
                    warnings.append(f"Chunk 0x{pos:X} içinde bozuk/eksik olay kaydı boyutu atlandı.")
                    break

                rec_id = struct.unpack("<Q", chunk_data[rec_off + 8:rec_off + 16])[0]
                written_ft = struct.unpack("<Q", chunk_data[rec_off + 16:rec_off + 24])[0]
                ts = filetime_to_datetime(written_ft)
                binxml_payload = chunk_data[rec_off + 24:rec_off + rec_size - 4]

                decoded = BinXmlDecoder.decode_record(chunk_data, rec_off, rec_size)
                strings = self._extract_binxml_strings(binxml_payload)
                event_id = self._infer_event_id(binxml_payload, strings, decoded["event_data"])
                desc, severity = CRITICAL_EVENT_DESCRIPTIONS.get(event_id, ("Windows Olay Kaydı", "Normal"))

                merged_details = []
                for k, v in decoded["event_data"].items():
                    merged_details.append(f"{k}={v}")
                for s in strings:
                    if s not in " ".join(merged_details):
                        merged_details.append(s)

                events.append({
                    "record_id": rec_id,
                    "event_id": event_id,
                    "timestamp": ts,
                    "description": desc,
                    "severity": severity,
                    "event_data": decoded["event_data"],
                    "details": " | ".join(merged_details[:12]) if merged_details else "(BinXML içeriği çözümlenemedi)",
                    "source_offset": f"0x{pos + rec_off:08X}",
                    "raw_bytes": chunk_data[rec_off:rec_off + min(rec_size, 2048)],
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
        found: List[str] = []
        for m in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}", payload):
            s = m.group(0).decode("utf-16le", errors="ignore").strip()
            if s and s not in found:
                found.append(s)
        return found

    def _infer_event_id(self, payload: bytes, strings: List[str], event_data: Dict[str, Any]) -> Optional[int]:
        if "EventID" in event_data:
            try:
                return int(event_data["EventID"])
            except Exception:
                pass
        for v in event_data.values():
            if isinstance(v, int) and v in CRITICAL_EVENT_DESCRIPTIONS:
                return v
        for s in strings:
            m = re.match(r"EventID=(\d{3,5})", s)
            if m:
                return int(m.group(1))
        for eid in CRITICAL_EVENT_DESCRIPTIONS:
            marker = b"\x06" + struct.pack("<H", eid)
            if marker in payload:
                return eid
        return None


def create_synthetic_evtx_file(output_path: str) -> str:
    """Generate a valid synthetic EVTX ('ElfFile') sample using structural BinXML TemplateInstance + SubstitutionArray."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    buf = bytearray(4096 + 65536)
    buf[0:8] = b"ElfFile\x00"
    struct.pack_into("<QQQ", buf, 8, 0, 0, 6)
    struct.pack_into("<IHH", buf, 32, 128, 3, 1)
    struct.pack_into("<H", buf, 42, 1)

    chunk = 4096
    buf[chunk:chunk + 8] = b"ElfChnk\x00"
    struct.pack_into("<QQQQ", buf, chunk + 8, 1, 5, 1, 5)

    sample_events = [
        (1, 4624, datetime(2026, 11, 20, 8, 55, 12), [
            (0x06, struct.pack("<H", 4624)),
            (0x01, "Microsoft-Windows-Security-Auditing".encode("utf-16le")),
            (0x01, "AhmetK".encode("utf-16le")),
            (0x01, "FINANS-PC04".encode("utf-16le")),
        ]),
        (2, 4688, datetime(2026, 11, 20, 19, 41, 3), [
            (0x06, struct.pack("<H", 4688)),
            (0x01, "MehmetS".encode("utf-16le")),
            (0x01, "powershell.exe -EncodedCommand ZQBjAGgAbwA=".encode("utf-16le")),
            (0x01, "cmd.exe".encode("utf-16le")),
        ]),
        (3, 7045, datetime(2026, 11, 20, 19, 41, 18), [
            (0x06, struct.pack("<H", 7045)),
            (0x01, "RemoteExecHelper".encode("utf-16le")),
            (0x01, r"C:\Users\Public\svchost_upd.exe".encode("utf-16le")),
        ]),
        (4, 4625, datetime(2026, 11, 20, 21, 12, 44), [
            (0x06, struct.pack("<H", 4625)),
            (0x01, "Administrator".encode("utf-16le")),
            (0x01, "192.168.10.45".encode("utf-16le")),
            (0x14, struct.pack("<I", 0xC000006D)),
        ]),
        (5, 1102, datetime(2026, 11, 20, 21, 18, 5), [
            (0x06, struct.pack("<H", 1102)),
            (0x01, "MehmetS".encode("utf-16le")),
            (0x01, "The audit log was cleared".encode("utf-16le")),
        ]),
    ]

    rec_pos = chunk + 512
    for rid, eid, dt, subs in sample_events:
        # Build BinXML Fragment + TemplateInstance (0x0C) with inline TemplateDef + SubstitutionArray
        rel_rec = rec_pos - chunk
        tmpl_def_rel = rel_rec + 24 + 10
        hdr = bytearray([0x0F, 0x01, 0x01, 0x00])  # BinXML fragment header (4 bytes)
        # Wait: place TemplateInstance right at payload[0] for crisp parsing:
        tmpl_def_rel = rel_rec + 24 + 10
        inst_hdr = struct.pack("<BBII", 0x0C, 0x01, eid, tmpl_def_rel)
        tmpl_def = bytearray(24)  # minimal empty template def (size=0)
        sub_count = struct.pack("<I", len(subs))
        sub_specs = b"".join(struct.pack("<HBB", len(val_b), vtype, 0) for vtype, val_b in subs)
        sub_data = b"".join(val_b for _, val_b in subs)

        body = inst_hdr + bytes(tmpl_def) + sub_count + sub_specs + sub_data
        while len(body) % 4 != 0:
            body += b"\x00"
        rec_size = 24 + len(body) + 4
        struct.pack_into("<IIQQ", buf, rec_pos, 0x00002A2A, rec_size, rid, datetime_to_filetime(dt))
        buf[rec_pos + 24:rec_pos + 24 + len(body)] = body
        struct.pack_into("<I", buf, rec_pos + rec_size - 4, rec_size)
        rec_pos += rec_size

    struct.pack_into("<I", buf, chunk + 48, rec_pos - chunk)
    with open(output_path, "wb") as f:
        f.write(buf)
    return output_path
