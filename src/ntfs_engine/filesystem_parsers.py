"""Pure-Python Filesystem Parsers for FAT32, exFAT, Linux ext4, and Apple APFS.

Designed for read-only forensic inspection of USB flash drives, SD cards, Linux images,
and Apple containers without external GPL/native drivers.
"""

from datetime import datetime, timedelta, timezone
import os
import struct
from typing import Any, Dict, List, Optional


def _dos_dt_to_iso(dos_date: int, dos_time: int) -> Optional[str]:
    if not dos_date:
        return None
    year = ((dos_date >> 9) & 0x7F) + 1980
    month = (dos_date >> 5) & 0x0F
    day = dos_date & 0x1F
    hour = (dos_time >> 11) & 0x1F
    minute = (dos_time >> 5) & 0x3F
    sec = (dos_time & 0x1F) * 2
    try:
        return datetime(year, month, day, hour, minute, min(sec, 59), tzinfo=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except ValueError:
        return None


def _unix_to_iso(ts: int) -> Optional[str]:
    if not ts or ts <= 0:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OSError, OverflowError, ValueError):
        return None


def _apfs_ns_to_iso(ns: int) -> Optional[str]:
    if not ns or ns <= 0:
        return None
    try:
        return datetime.fromtimestamp(ns / 1_000_000_000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OSError, OverflowError, ValueError):
        return None


class FatExfatParser:
    """Read-only FAT32 & exFAT directory tree parser (active + deleted entries + LFN)."""

    @staticmethod
    def parse_fat32(stream, part_offset: int, max_entries: int = 10000) -> Dict[str, Any]:
        stream.seek(part_offset)
        vbr = stream.read(512)
        if len(vbr) < 512:
            return {"vbr_info": {}, "records": []}
        bps = struct.unpack("<H", vbr[11:13])[0] or 512
        spc = vbr[13] or 1
        reserved_sec = struct.unpack("<H", vbr[14:16])[0]
        num_fats = vbr[16] or 2
        fat_sz_32 = struct.unpack("<I", vbr[36:40])[0]
        root_cluster = struct.unpack("<I", vbr[44:48])[0] or 2
        vol_label = vbr[71:82].decode("ascii", "replace").strip()

        fat_offset = part_offset + reserved_sec * bps
        data_offset = part_offset + (reserved_sec + num_fats * fat_sz_32) * bps
        bpc = bps * spc

        def next_cluster(clus: int) -> Optional[int]:
            stream.seek(fat_offset + clus * 4)
            raw = stream.read(4)
            if len(raw) < 4:
                return None
            val = struct.unpack("<I", raw)[0] & 0x0FFFFFFF
            if val >= 0x0FFFFFF8 or val < 2:
                return None
            return val

        def read_cluster_chain(start_clus: int, max_clusters: int = 256) -> bytes:
            buf = bytearray()
            cur: Optional[int] = start_clus
            seen = set()
            while cur and cur not in seen and len(seen) < max_clusters:
                seen.add(cur)
                stream.seek(data_offset + (cur - 2) * bpc)
                buf.extend(stream.read(bpc))
                cur = next_cluster(cur)
            return bytes(buf)

        records: List[Dict[str, Any]] = []
        queue: List[tuple] = [(root_cluster, "/")]
        visited_dirs = set()

        while queue and len(records) < max_entries:
            dir_clus, dir_path = queue.pop(0)
            if dir_clus in visited_dirs:
                continue
            visited_dirs.add(dir_clus)
            dir_bytes = read_cluster_chain(dir_clus)
            lfn_parts: Dict[int, str] = {}

            for off in range(0, len(dir_bytes) - 31, 32):
                ent = dir_bytes[off:off + 32]
                first_b = ent[0]
                if first_b == 0x00:
                    break
                attr = ent[11]
                if attr == 0x0F:
                    # LFN entry
                    seq = first_b & 0x1F
                    chars = ent[1:11] + ent[14:26] + ent[28:32]
                    txt = chars.decode("utf-16le", "ignore").split("\x00", 1)[0].rstrip("\uffff")
                    lfn_parts[seq] = txt
                    continue

                is_deleted = (first_b == 0xE5)
                if attr & 0x08:  # Volume ID
                    lfn_parts.clear()
                    continue

                raw_name = bytearray(ent[0:8])
                if is_deleted:
                    raw_name[0] = ord("_")
                short_name = bytes(raw_name).decode("ascii", "replace").strip()
                short_ext = ent[8:11].decode("ascii", "replace").strip()
                sfn = f"{short_name}.{short_ext}" if short_ext else short_name
                if sfn in (".", ".."):
                    lfn_parts.clear()
                    continue

                if lfn_parts:
                    fname = "".join(lfn_parts[k] for k in sorted(lfn_parts.keys()))
                else:
                    fname = sfn
                lfn_parts.clear()

                clus_hi = struct.unpack("<H", ent[20:22])[0]
                clus_lo = struct.unpack("<H", ent[26:28])[0]
                first_clus = (clus_hi << 16) | clus_lo
                ctime = _dos_dt_to_iso(struct.unpack("<H", ent[16:18])[0], struct.unpack("<H", ent[14:16])[0])
                atime = _dos_dt_to_iso(struct.unpack("<H", ent[18:20])[0], 0)
                mtime = _dos_dt_to_iso(struct.unpack("<H", ent[24:26])[0], struct.unpack("<H", ent[22:24])[0])
                fsize = struct.unpack("<I", ent[28:32])[0]
                is_dir = bool(attr & 0x10)
                full_p = (dir_path.rstrip("/") + "/" + fname) if dir_path != "/" else f"/{fname}"

                preview = b""
                if not is_dir and first_clus >= 2:
                    stream.seek(data_offset + (first_clus - 2) * bpc)
                    preview = stream.read(min(fsize or 256, 256))

                records.append({
                    "record_index": len(records) + 1,
                    "partition": 1,
                    "filename": fname,
                    "full_path": full_p,
                    "parent_ref": dir_clus,
                    "in_use": not is_deleted,
                    "is_deleted": is_deleted,
                    "is_dir": is_dir,
                    "size": fsize,
                    "created": ctime,
                    "modified": mtime,
                    "accessed": atime,
                    "signature": "Dizin" if is_dir else "FAT32 Dosya",
                    "sig_confidence": "FAT32 BPB",
                    "raw_preview": preview,
                    "fixup_ok": True,
                    "timestomping_suspect": False,
                    "ads_streams": [],
                })
                if is_dir and first_clus >= 2 and not is_deleted:
                    queue.append((first_clus, full_p))

        return {
            "vbr_info": {
                "filesystem": "FAT32",
                "volume_label": vol_label,
                "bytes_per_sector": bps,
                "sectors_per_cluster": spc,
                "root_cluster": root_cluster,
            },
            "records": records,
        }

    @staticmethod
    def parse_exfat(stream, part_offset: int, max_entries: int = 10000) -> Dict[str, Any]:
        stream.seek(part_offset)
        vbr = stream.read(512)
        if len(vbr) < 512 or vbr[3:11] != b"EXFAT   ":
            return {"vbr_info": {}, "records": []}
        fat_off_sec = struct.unpack("<I", vbr[80:84])[0]
        clus_heap_sec = struct.unpack("<I", vbr[88:92])[0]
        root_clus = struct.unpack("<I", vbr[96:100])[0] or 4
        bps_shift = vbr[108]
        spc_shift = vbr[109]
        bps = 1 << min(bps_shift, 12)
        spc = 1 << min(spc_shift, 16)
        bpc = bps * spc
        heap_offset = part_offset + clus_heap_sec * bps

        stream.seek(heap_offset + (root_clus - 2) * bpc)
        root_bytes = stream.read(bpc * 4)

        records: List[Dict[str, Any]] = []
        i = 0
        while i + 32 <= len(root_bytes) and len(records) < max_entries:
            ent = root_bytes[i:i + 32]
            etype = ent[0]
            if etype == 0x00:
                break
            if etype in (0x85, 0x05):  # File Directory Entry (0x85 active, 0x05 deleted)
                is_deleted = (etype == 0x05)
                sec_cnt = ent[1]
                f_attr = struct.unpack("<H", ent[4:6])[0]
                is_dir = bool(f_attr & 0x10)
                c_dos = struct.unpack("<I", ent[8:12])[0]
                m_dos = struct.unpack("<I", ent[12:16])[0]
                a_dos = struct.unpack("<I", ent[16:20])[0]
                ctime = _dos_dt_to_iso((c_dos >> 16) & 0xFFFF, c_dos & 0xFFFF)
                mtime = _dos_dt_to_iso((m_dos >> 16) & 0xFFFF, m_dos & 0xFFFF)
                atime = _dos_dt_to_iso((a_dos >> 16) & 0xFFFF, a_dos & 0xFFFF)

                stream_ext_size = 0
                first_clus = 0
                name_parts: List[str] = []
                for s_idx in range(1, sec_cnt + 1):
                    if i + s_idx * 32 + 32 > len(root_bytes):
                        break
                    sub = root_bytes[i + s_idx * 32:i + (s_idx + 1) * 32]
                    stype = sub[0]
                    if stype in (0xC0, 0x40):  # Stream Extension
                        first_clus = struct.unpack("<I", sub[20:24])[0]
                        stream_ext_size = struct.unpack("<Q", sub[24:32])[0]
                    elif stype in (0xC1, 0x41):  # File Name
                        name_parts.append(sub[2:32].decode("utf-16le", "ignore").rstrip("\x00"))
                fname = "".join(name_parts) or f"exfat_entry_{i // 32}"
                preview = b""
                if not is_dir and first_clus >= 2:
                    stream.seek(heap_offset + (first_clus - 2) * bpc)
                    preview = stream.read(min(stream_ext_size or 256, 256))

                records.append({
                    "record_index": len(records) + 1,
                    "partition": 1,
                    "filename": fname,
                    "full_path": f"/{fname}",
                    "parent_ref": root_clus,
                    "in_use": not is_deleted,
                    "is_deleted": is_deleted,
                    "is_dir": is_dir,
                    "size": stream_ext_size,
                    "created": ctime,
                    "modified": mtime,
                    "accessed": atime,
                    "signature": "Dizin" if is_dir else "exFAT Dosya",
                    "sig_confidence": "exFAT EntrySet",
                    "raw_preview": preview,
                    "fixup_ok": True,
                    "timestomping_suspect": False,
                    "ads_streams": [],
                })
                i += (sec_cnt + 1) * 32
                continue
            i += 32

        return {
            "vbr_info": {
                "filesystem": "exFAT",
                "bytes_per_sector": bps,
                "sectors_per_cluster": spc,
                "fat_offset_sectors": fat_off_sec,
                "cluster_heap_sector": clus_heap_sec,
                "root_cluster": root_clus,
            },
            "records": records,
        }


class Ext4ApfsParser:
    """Read-only Linux ext2/ext3/ext4 & Apple APFS (NXSB/APSB) forensic metadata parsers."""

    @staticmethod
    def parse_ext4(stream, part_offset: int, max_entries: int = 5000) -> Dict[str, Any]:
        stream.seek(part_offset + 1024)
        sb = stream.read(1024)
        if len(sb) < 256 or struct.unpack("<H", sb[56:58])[0] != 0xEF53:
            return {"vbr_info": {}, "records": []}

        inodes_count, blocks_count = struct.unpack("<II", sb[0:8])
        log_block_size = struct.unpack("<I", sb[24:28])[0]
        block_size = 1024 << min(log_block_size, 6)
        inodes_per_group = struct.unpack("<I", sb[40:44])[0] or 1
        inode_size = struct.unpack("<H", sb[88:90])[0] or 128
        vol_name = sb[120:136].split(b"\x00", 1)[0].decode("utf-8", "replace")

        # Group descriptor table starts at block after superblock
        bgdt_off = part_offset + (2048 if block_size == 1024 else block_size)
        stream.seek(bgdt_off)
        bgd = stream.read(64)
        inode_table_blk = struct.unpack("<I", bgd[8:12])[0]
        inode_table_off = part_offset + inode_table_blk * block_size

        def read_inode(ino: int) -> Optional[Dict[str, Any]]:
            if ino < 1 or ino > inodes_count:
                return None
            idx = ino - 1
            stream.seek(inode_table_off + idx * inode_size)
            raw = stream.read(inode_size)
            if len(raw) < 128:
                return None
            i_mode, _, i_size_lo, i_atime, i_ctime, i_mtime, i_dtime = struct.unpack("<HHIIIII", raw[0:24])
            # Direct blocks at offset 40..100 (or extents if i_flags & 0x80000)
            i_flags = struct.unpack("<I", raw[32:36])[0]
            blocks = list(struct.unpack("<12I", raw[40:88]))
            return {
                "inode": ino,
                "mode": i_mode,
                "is_dir": (i_mode & 0xF000) == 0x4000,
                "is_deleted": i_dtime != 0 or i_mode == 0,
                "size": i_size_lo,
                "atime": _unix_to_iso(i_atime),
                "ctime": _unix_to_iso(i_ctime),
                "mtime": _unix_to_iso(i_mtime),
                "flags": i_flags,
                "blocks": blocks,
                "raw_i_block": raw[40:100],
            }

        records: List[Dict[str, Any]] = []
        root_ino = read_inode(2)
        if root_ino:
            dir_blocks = []
            if root_ino["flags"] & 0x80000 and root_ino["raw_i_block"][0:2] == b"\x0a\xf3":
                # Extent header: entries count at +2, first extent leaf block lo at +12+8
                ee_cnt = struct.unpack("<H", root_ino["raw_i_block"][2:4])[0]
                if ee_cnt > 0:
                    start_blk = struct.unpack("<I", root_ino["raw_i_block"][20:24])[0]
                    dir_blocks.append(start_blk)
            else:
                dir_blocks = [b for b in root_ino["blocks"] if b > 0]

            for blk in dir_blocks:
                stream.seek(part_offset + blk * block_size)
                ddata = stream.read(block_size)
                pos = 0
                while pos + 8 <= len(ddata) and len(records) < max_entries:
                    d_ino, rec_len, name_len, file_type = struct.unpack("<IHBB", ddata[pos:pos + 8])
                    if rec_len < 8 or pos + rec_len > len(ddata):
                        break
                    fname = ddata[pos + 8:pos + 8 + name_len].decode("utf-8", "replace")
                    if fname and fname not in (".", "..") and d_ino > 0:
                        meta = read_inode(d_ino)
                        preview = b""
                        if meta and not meta["is_dir"] and meta["blocks"] and meta["blocks"][0] > 0:
                            if not (meta["flags"] & 0x80000):
                                stream.seek(part_offset + meta["blocks"][0] * block_size)
                                preview = stream.read(min(meta["size"] or 256, 256))
                        records.append({
                            "record_index": d_ino,
                            "partition": 1,
                            "filename": fname,
                            "full_path": f"/{fname}",
                            "parent_ref": 2,
                            "in_use": not (meta["is_deleted"] if meta else False),
                            "is_deleted": meta["is_deleted"] if meta else False,
                            "is_dir": (file_type == 2) or (meta["is_dir"] if meta else False),
                            "size": meta["size"] if meta else 0,
                            "created": meta["ctime"] if meta else None,
                            "modified": meta["mtime"] if meta else None,
                            "accessed": meta["atime"] if meta else None,
                            "signature": "Dizin" if file_type == 2 else "ext4 Inode",
                            "sig_confidence": "ext4 Superblock",
                            "raw_preview": preview,
                            "fixup_ok": True,
                            "timestomping_suspect": False,
                            "ads_streams": [],
                        })
                    pos += rec_len

        return {
            "vbr_info": {
                "filesystem": "Linux ext4",
                "volume_label": vol_name or "(Etiketsiz)",
                "block_size": block_size,
                "inodes_count": inodes_count,
                "blocks_count": blocks_count,
                "inodes_per_group": inodes_per_group,
            },
            "records": records,
        }

    @staticmethod
    def parse_apfs(stream, part_offset: int) -> Dict[str, Any]:
        stream.seek(part_offset)
        nxsb = stream.read(4096)
        if len(nxsb) < 256 or nxsb[32:36] != b"NXSB":
            return {"vbr_info": {}, "records": []}
        block_size = struct.unpack("<I", nxsb[36:40])[0] or 4096
        block_count = struct.unpack("<Q", nxsb[40:48])[0]
        container_uuid = nxsb[72:88].hex()

        # Scan first 64 blocks for APSB (APFS Volume Superblock)
        volumes: List[Dict[str, Any]] = []
        for blk_idx in range(1, min(64, max(2, block_count))):
            stream.seek(part_offset + blk_idx * block_size)
            blk = stream.read(block_size)
            if len(blk) >= 720 and blk[32:36] == b"APSB":
                fs_flags = struct.unpack("<Q", blk[48:56])[0]
                vol_name = blk[704:704 + 64].split(b"\x00", 1)[0].decode("utf-8", "replace")
                num_files = struct.unpack("<Q", blk[128:136])[0]
                last_mod_ns = struct.unpack("<Q", blk[264:272])[0]
                encrypted = not bool(fs_flags & 0x1)  # APFS_FS_UNENCRYPTED = 0x1
                volumes.append({
                    "record_index": blk_idx,
                    "partition": 1,
                    "filename": vol_name or f"APFS_Volume_{blk_idx}",
                    "full_path": f"/APFS/{vol_name or blk_idx}",
                    "parent_ref": 0,
                    "in_use": True,
                    "is_deleted": False,
                    "is_dir": True,
                    "size": num_files,
                    "created": None,
                    "modified": _apfs_ns_to_iso(last_mod_ns),
                    "accessed": None,
                    "signature": f"APFS Volume ({'Şifreli/FileVault' if encrypted else 'Şifresiz'})",
                    "sig_confidence": "APSB Magic",
                    "raw_preview": blk[:256],
                    "fixup_ok": True,
                    "timestomping_suspect": False,
                    "ads_streams": [],
                })

        return {
            "vbr_info": {
                "filesystem": "Apple APFS (NXSB)",
                "block_size": block_size,
                "block_count": block_count,
                "container_uuid": container_uuid,
                "volumes_detected": len(volumes),
            },
            "records": volumes,
        }


# ---------------------------------------------------------------------------
# Synthetic Filesystem Image Builders (for Offline Tests & Demos)
# ---------------------------------------------------------------------------

def create_synthetic_fat32_image(output_path: str) -> str:
    """Build a synthetic FAT32 volume with active LFN and deleted 0xE5 file entries."""
    bps = 512
    spc = 2  # 1024 bytes per cluster
    reserved = 32
    fat_sz = 8
    num_fats = 2
    total_sec = 256
    img = bytearray(total_sec * bps)

    # VBR
    img[0:3] = b"\xeb\x58\x90"
    img[3:11] = b"MSDOS5.0"
    struct.pack_into("<H", img, 11, bps)
    img[13] = spc
    struct.pack_into("<H", img, 14, reserved)
    img[16] = num_fats
    struct.pack_into("<I", img, 32, total_sec)
    struct.pack_into("<I", img, 36, fat_sz)
    struct.pack_into("<I", img, 44, 2)  # root cluster 2
    img[71:82] = b"USB_KANIT  "
    img[82:90] = b"FAT32   "
    img[510:512] = b"\x55\xaa"

    fat_off = reserved * bps
    data_off = (reserved + num_fats * fat_sz) * bps
    for clus, val in [(0, 0x0FFFFFF8), (1, 0x0FFFFFFF), (2, 0x0FFFFFFF), (3, 0x0FFFFFFF), (4, 0x0FFFFFFF)]:
        struct.pack_into("<I", img, fat_off + clus * 4, val)

    # Root dir at cluster 2: entry 0 active "RAPOR.TXT", entry 1 deleted "_IZ.LOG"
    root_off = data_off
    dos_date = ((2026 - 1980) << 9) | (3 << 5) | 15
    dos_time = (10 << 11) | (15 << 5)

    p1 = b"FAT32_ACTIVE_EVIDENCE_DATA"
    struct.pack_into("<8s3sB", img, root_off, b"RAPOR   ", b"TXT", 0x20)
    struct.pack_into("<HHHH", img, root_off + 14, dos_time, dos_date, dos_date, 0)
    struct.pack_into("<HHHI", img, root_off + 22, dos_time, dos_date, 3, len(p1))
    img[data_off + (3 - 2) * (bps * spc):data_off + (3 - 2) * (bps * spc) + len(p1)] = p1

    p2 = b"FAT32_DELETED_EVIDENCE_DATA"
    e2 = root_off + 32
    struct.pack_into("<8s3sB", img, e2, b"\xe5IZ     ", b"LOG", 0x20)
    struct.pack_into("<HHHH", img, e2 + 14, dos_time, dos_date, dos_date, 0)
    struct.pack_into("<HHHI", img, e2 + 22, dos_time, dos_date, 4, len(p2))
    img[data_off + (4 - 2) * (bps * spc):data_off + (4 - 2) * (bps * spc) + len(p2)] = p2

    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(bytes(img))
    return output_path


def create_synthetic_exfat_image(output_path: str) -> str:
    """Build a synthetic exFAT volume with active and deleted directory entry sets."""
    bps = 512
    spc = 2
    heap_sec = 64
    img = bytearray(128 * bps)
    img[3:11] = b"EXFAT   "
    struct.pack_into("<I", img, 80, 24)
    struct.pack_into("<I", img, 88, heap_sec)
    struct.pack_into("<I", img, 96, 4)  # root cluster 4
    img[108] = 9   # 512 B/sec
    img[109] = 1   # 2 sec/cluster
    img[510:512] = b"\x55\xaa"

    heap_off = heap_sec * bps
    bpc = bps * spc
    root_off = heap_off + (4 - 2) * bpc
    dos_dt = (((2026 - 1980) << 9) | (3 << 5) | 15) << 16 | ((11 << 11) | (20 << 5))

    def write_entry_set(off: int, active: bool, fname: str, clus: int, payload: bytes):
        img[off] = 0x85 if active else 0x05
        img[off + 1] = 2  # 2 secondary entries (Stream + FileName)
        struct.pack_into("<III", img, off + 8, dos_dt, dos_dt, dos_dt)
        s_off = off + 32
        img[s_off] = 0xC0 if active else 0x40
        struct.pack_into("<IQ", img, s_off + 20, clus, len(payload))
        n_off = off + 64
        img[n_off] = 0xC1 if active else 0x41
        enc = fname.encode("utf-16le")[:30]
        img[n_off + 2:n_off + 2 + len(enc)] = enc
        c_off = heap_off + (clus - 2) * bpc
        img[c_off:c_off + len(payload)] = payload

    write_entry_set(root_off, True, "exfat_kanit.txt", 5, b"EXFAT_ACTIVE_RECORD")
    write_entry_set(root_off + 96, False, "silinen_usb.ps1", 6, b"EXFAT_DELETED_SCRIPT")

    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(bytes(img))
    return output_path


def create_synthetic_ext4_image(output_path: str) -> str:
    """Build a synthetic ext4 filesystem with superblock (0xEF53), inode table, and root directory."""
    blk_sz = 1024
    img = bytearray(64 * blk_sz)
    sb_off = 1024
    struct.pack_into("<II", img, sb_off, 16, 64)  # inodes, blocks
    struct.pack_into("<I", img, sb_off + 24, 0)   # 1024B blocks
    struct.pack_into("<I", img, sb_off + 40, 16)
    struct.pack_into("<H", img, sb_off + 56, 0xEF53)
    struct.pack_into("<H", img, sb_off + 88, 128)
    img[sb_off + 120:sb_off + 129] = b"LINUX_USB"

    # BGD at block 2 (offset 2048): inode table at block 5
    struct.pack_into("<I", img, 2048 + 8, 5)
    itbl_off = 5 * blk_sz

    # Inode 2 (root dir) -> data block 10
    r_off = itbl_off + 1 * 128
    struct.pack_into("<HHIIIII", img, r_off, 0x41ED, 0, blk_sz, 1773570000, 1773570000, 1773570000, 0)
    struct.pack_into("<I", img, r_off + 40, 10)

    # Inode 12 (file) -> data block 11
    f_off = itbl_off + 11 * 128
    payload = b"EXT4_FORENSIC_PAYLOAD"
    struct.pack_into("<HHIIIII", img, f_off, 0x81A4, 0, len(payload), 1773570100, 1773570100, 1773570100, 0)
    struct.pack_into("<I", img, f_off + 40, 11)
    img[11 * blk_sz:11 * blk_sz + len(payload)] = payload

    # Dir entry in block 10
    d_off = 10 * blk_sz
    name = b"auth.log"
    struct.pack_into("<IHBB", img, d_off, 12, blk_sz, len(name), 1)
    img[d_off + 8:d_off + 8 + len(name)] = name

    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(bytes(img))
    return output_path


def create_synthetic_apfs_image(output_path: str) -> str:
    """Build a synthetic APFS container (NXSB) with an APSB volume block."""
    blk_sz = 4096
    img = bytearray(8 * blk_sz)
    img[32:36] = b"NXSB"
    struct.pack_into("<I", img, 36, blk_sz)
    struct.pack_into("<Q", img, 40, 8)
    img[72:88] = b"\x11\x22\x33\x44" * 4

    v_off = 2 * blk_sz
    img[v_off + 32:v_off + 36] = b"APSB"
    struct.pack_into("<Q", img, v_off + 48, 0x1)  # unencrypted
    struct.pack_into("<Q", img, v_off + 128, 42)
    struct.pack_into("<Q", img, v_off + 264, 1773570000 * 1_000_000_000)
    img[v_off + 704:v_off + 716] = b"Macintosh HD"

    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(bytes(img))
    return output_path
