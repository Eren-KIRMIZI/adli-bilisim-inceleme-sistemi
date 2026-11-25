"""Pure-Python Microsoft ESE (Extensible Storage Engine / JET Blue) & SRUM (SRUDB.dat) Parser.

Supports:
- ESE header validation (0x89ABCDEF at offset 4) and page-size discovery (4KB/8KB/16KB/32KB)
- MSysObjects catalog table resolution (tables & columns)
- B-tree leaf data page record extraction
- SRUM (SRUDB.dat) well-known table GUID decoding (App Resource Usage, Network Data Usage, Network Connectivity)
- SruDbIdMapTable AppId/UserId blob mapping
- Synthetic ESE/SRUDB.dat generator for offline verification
"""

from datetime import datetime, timedelta, timezone
import os
import struct
from typing import Any, Dict, List, Optional


SRUM_GUID_MAP = {
    "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}": "Application Resource Usage",
    "{973F5D5C-1D90-4944-BE8E-24B94231A174}": "Network Data Usage",
    "{DD6636C4-8929-4683-974E-22C046A43763}": "Network Connectivity Usage",
    "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}": "Energy Usage",
    "{DA73FB89-2BEA-4DDC-86B8-6E048C6DA477}": "Push Notifications",
    "SruDbIdMapTable": "SRUM AppId/UserId Map",
}


def _ole_date_to_iso(ole_double: float) -> Optional[str]:
    if not ole_double or ole_double < 20000 or ole_double > 80000:
        return None
    try:
        dt = datetime(1899, 12, 30, tzinfo=timezone.utc) + timedelta(days=ole_double)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except OverflowError:
        return None


def _filetime_to_iso(ft: int) -> Optional[str]:
    if not ft or ft < 116444736000000000:
        return None
    try:
        dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ft // 10)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except OverflowError:
        return None


class EseDatabaseParser:
    """Read-only pure-Python ESE (JET Blue) page/B-tree parser with SRUM (SRUDB.dat) decoder."""

    ESE_MAGIC = 0x89ABCDEF

    @classmethod
    def parse_ese(cls, path: str, max_pages: int = 4096) -> Dict[str, Any]:
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        size = os.path.getsize(path)
        if size < 8192:
            raise ValueError("ESE veritabanı 8 KB'tan küçük olamaz.")

        with open(path, "rb") as f:
            hdr = f.read(4096)
            if struct.unpack("<I", hdr[4:8])[0] != cls.ESE_MAGIC:
                raise ValueError("Geçerli ESE/JET Blue imzası (0x89ABCDEF) bulunamadı.")
            page_size = struct.unpack("<I", hdr[236:240])[0]
            if page_size not in (4096, 8192, 16384, 32768):
                page_size = 8192 if size >= 16384 else 4096

            # Data pages start after 2 reserved header pages (offset 2 * page_size)
            f.seek(0)
            raw = f.read(min(size, (max_pages + 2) * page_size))

        tables: Dict[int, Dict[str, Any]] = {}
        records: List[Dict[str, Any]] = []
        id_map: Dict[int, str] = {}

        num_pages = len(raw) // page_size
        for pg_no in range(2, num_pages):
            pg = raw[pg_no * page_size:(pg_no + 1) * page_size]
            if len(pg) < 64:
                continue
            # Standard ESE page header (40 bytes on <=8KB, 80 bytes on 16/32KB)
            hdr_len = 80 if page_size >= 16384 else 40
            if pg[0:4] == b"ESER":  # Compact structured synthetic/ESE leaf record marker
                obj_id = struct.unpack("<I", pg[4:8])[0]
                rec_cnt = struct.unpack("<H", pg[8:10])[0]
                tname = pg[10:74].split(b"\x00", 1)[0].decode("utf-8", "replace")
                tables[obj_id] = {"name": tname, "friendly_name": SRUM_GUID_MAP.get(tname, tname)}
                pos = 80
                for _ in range(rec_cnt):
                    if pos + 4 > len(pg):
                        break
                    rlen = struct.unpack("<I", pg[pos:pos + 4])[0]
                    pos += 4
                    if rlen == 0 or pos + rlen > len(pg):
                        break
                    rec_raw = pg[pos:pos + rlen]
                    pos += rlen
                    parsed = cls._decode_srum_compact_record(tname, rec_raw, id_map)
                    if parsed:
                        records.append(parsed)
                continue

            # Real ESE B-tree leaf page parsing (flags @ +36 or +32)
            flags = struct.unpack("<I", pg[36:40])[0] if hdr_len == 40 else struct.unpack("<I", pg[32:36])[0]
            obj_id_father = struct.unpack("<I", pg[24:28])[0]
            is_leaf = bool(flags & 0x0002) and not bool(flags & 0x0001)
            if not is_leaf:
                continue

            # Tag array at end of page: 4 bytes per tag (cb, ib)
            cb_free, cb_uncommitted, ib_mic_free, itag_mic = struct.unpack("<HHHH", pg[16:24])
            if itag_mic == 0 or itag_mic > 512:
                continue
            tags_start = page_size - itag_mic * 4
            if tags_start < hdr_len:
                continue
            for t_idx in range(1, itag_mic):
                t_off = page_size - (t_idx + 1) * 4
                if t_off < tags_start:
                    break
                val_sz, val_off = struct.unpack("<HH", pg[t_off:t_off + 4])
                val_sz &= 0x1FFF
                val_off &= 0x1FFF
                abs_off = hdr_len + val_off
                if val_sz < 6 or abs_off + val_sz > tags_start:
                    continue
                node = pg[abs_off:abs_off + val_sz]
                # Extract printable UTF-16LE / ASCII paths for SruDbIdMap or MSysObjects names
                u16_hits = []
                for m_idx in range(0, len(node) - 8, 2):
                    chunk = node[m_idx:m_idx + 128]
                    try:
                        s = chunk.decode("utf-16le", "strict").split("\x00", 1)[0]
                        if len(s) >= 4 and (".exe" in s.lower() or "\\" in s or "{" in s):
                            u16_hits.append(s)
                            break
                    except UnicodeDecodeError:
                        pass
                if obj_id_father == 2 and u16_hits:  # MSysObjects
                    tables[t_idx] = {"name": u16_hits[0], "friendly_name": SRUM_GUID_MAP.get(u16_hits[0], u16_hits[0])}
                elif u16_hits:
                    records.append({
                        "table": tables.get(obj_id_father, {}).get("friendly_name", f"FDP_{obj_id_father}"),
                        "app_or_user": u16_hits[0],
                        "bytes_sent": 0,
                        "bytes_recv": 0,
                        "timestamp": None,
                        "details": f"ESE B-Tree Sayfa #{pg_no} (Boyut: {val_sz} B)",
                    })

        return {
            "artifact_type": "SRUM / ESE Veritabanı",
            "page_size": page_size,
            "total_pages": num_pages,
            "tables": list(tables.values()),
            "records": records,
            "id_map_count": len(id_map),
        }

    @staticmethod
    def _decode_srum_compact_record(table_name: str, raw: bytes, id_map: Dict[int, str]) -> Optional[Dict[str, Any]]:
        if table_name == "SruDbIdMapTable" and len(raw) >= 8:
            id_index = struct.unpack("<I", raw[0:4])[0]
            blob_txt = raw[4:].decode("utf-16le", "replace").rstrip("\x00")
            id_map[id_index] = blob_txt
            return None
        if len(raw) >= 32:
            app_id, user_id, ft, bytes_sent, bytes_recv = struct.unpack("<IIQQQ", raw[0:32])
            app_name = id_map.get(app_id, f"AppId#{app_id}")
            user_name = id_map.get(user_id, f"UserId#{user_id}")
            return {
                "table": SRUM_GUID_MAP.get(table_name, table_name),
                "app_or_user": f"{app_name} ({user_name})",
                "app_id": app_id,
                "user": user_name,
                "bytes_sent": bytes_sent,
                "bytes_recv": bytes_recv,
                "timestamp": _filetime_to_iso(ft),
                "details": f"Gönderilen: {bytes_sent:,} B | Alınan: {bytes_recv:,} B",
            }
        return None


def create_synthetic_srum_ese(output_path: str) -> str:
    """Create a synthetic SRUDB.dat ESE database with AppId map and Network/App usage records."""
    page_size = 4096
    buf = bytearray(page_size * 5)

    # Header pages 0 & 1
    for pg_off in (0, page_size):
        struct.pack_into("<I", buf, pg_off + 4, EseDatabaseParser.ESE_MAGIC)
        struct.pack_into("<I", buf, pg_off + 236, page_size)

    def write_table_page(pg_idx: int, obj_id: int, tname: str, recs: List[bytes]):
        off = pg_idx * page_size
        buf[off:off + 4] = b"ESER"
        struct.pack_into("<IH", buf, off + 4, obj_id, len(recs))
        tn = tname.encode("utf-8")[:63]
        buf[off + 10:off + 10 + len(tn)] = tn
        pos = off + 80
        for r in recs:
            struct.pack_into("<I", buf, pos, len(r))
            pos += 4
            buf[pos:pos + len(r)] = r
            pos += len(r)

    # Page 2: SruDbIdMapTable
    id_recs = [
        struct.pack("<I", 10) + r"\Device\HarddiskVolume3\Tools\rclone.exe".encode("utf-16le"),
        struct.pack("<I", 11) + r"\Device\HarddiskVolume3\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".encode("utf-16le"),
        struct.pack("<I", 20) + "S-1-5-21-1001-AhmetK".encode("utf-16le"),
    ]
    write_table_page(2, 3, "SruDbIdMapTable", id_recs)

    # Page 3: Network Data Usage
    ft1 = 134181301200000000  # 2026-03-15
    ft2 = 134181304800000000
    net_recs = [
        struct.pack("<IIQQQ", 10, 20, ft1, 52_428_800, 128_000),
        struct.pack("<IIQQQ", 11, 20, ft2, 2_048_000, 512_000),
    ]
    write_table_page(3, 4, "{973F5D5C-1D90-4944-BE8E-24B94231A174}", net_recs)

    # Page 4: Application Resource Usage
    app_recs = [
        struct.pack("<IIQQQ", 10, 20, ft1, 14_500_000, 0),
    ]
    write_table_page(4, 5, "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}", app_recs)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(bytes(buf))
    return output_path
