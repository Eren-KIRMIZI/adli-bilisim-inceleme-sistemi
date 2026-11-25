"""Pure-Python EnCase E01 (EWF) Segment Reader & Stream Wrapper.

Supports reading zlib-compressed and uncompressed EWF (.E01/.E02...) forensic images
in strict read-only mode without external C/GPL libraries.
"""

import os
import struct
import zlib
from typing import Dict, List, Optional, Tuple

EWF_SIGNATURE = b"EVF\x09\x0d\x0a\xff\x00"


class EwfImageStream:
    """Read-only random-access binary stream over EnCase EWF (.E01) segment files."""

    def __init__(self, first_segment_path: str):
        if not os.path.isfile(first_segment_path):
            raise FileNotFoundError(first_segment_path)

        self.segment_paths = self._discover_segments(first_segment_path)
        self.chunk_size = 32768
        self.bytes_per_sector = 512
        self.total_sectors = 0
        self.total_size = 0
        self.warnings: List[str] = []
        # List of (segment_file_path, file_offset, is_compressed)
        self.chunks: List[Tuple[str, int, bool]] = []
        self._pos = 0
        self._cache_idx: Optional[int] = None
        self._cache_data: bytes = b""

        self._index_all_segments()

    def _discover_segments(self, first_path: str) -> List[str]:
        base, ext = os.path.splitext(first_path)
        if not ext.lower().startswith(".e0"):
            return [first_path]
        segments = [first_path]
        idx = 2
        while idx < 999:
            cand = f"{base}.E{idx:02d}"
            cand_low = f"{base}.e{idx:02d}"
            if os.path.isfile(cand):
                segments.append(cand)
            elif os.path.isfile(cand_low):
                segments.append(cand_low)
            else:
                break
            idx += 1
        return segments

    def _index_all_segments(self) -> None:
        for seg_path in self.segment_paths:
            with open(seg_path, "rb") as f:
                hdr = f.read(13)
                if len(hdr) < 13 or hdr[:8] != EWF_SIGNATURE:
                    raise ValueError(f"Geçersiz EWF/E01 imzası: {seg_path}")

                pos = 13
                file_len = os.path.getsize(seg_path)
                sectors_base_offset = 0

                while pos + 76 <= file_len:
                    f.seek(pos)
                    sec_hdr = f.read(76)
                    if len(sec_hdr) < 76:
                        break
                    sec_type = sec_hdr[0:16].split(b"\x00", 1)[0].decode("ascii", "replace")
                    next_off = struct.unpack("<Q", sec_hdr[16:24])[0]
                    sec_size = struct.unpack("<Q", sec_hdr[24:32])[0]
                    stored_adler = struct.unpack("<I", sec_hdr[72:76])[0]
                    calc_adler = zlib.adler32(sec_hdr[:72]) & 0xFFFFFFFF
                    if stored_adler and stored_adler != calc_adler:
                        self.warnings.append(
                            f"EWF bölüm ('{sec_type}') Adler-32 sağlama toplamı uyuşmazlığı @ 0x{pos:X}"
                        )

                    if sec_type == "volume" and pos + 76 + 32 <= file_len:
                        vol = f.read(32)
                        chunk_cnt, spc, bps, tot_sec = struct.unpack("<IIII", vol[4:20])
                        if bps:
                            self.bytes_per_sector = bps
                        if spc and bps:
                            self.chunk_size = spc * bps
                        if tot_sec:
                            self.total_sectors = tot_sec
                            self.total_size = tot_sec * self.bytes_per_sector

                    elif sec_type == "sectors":
                        sectors_base_offset = pos + 76

                    elif sec_type in ("table", "table2") and pos + 76 + 24 <= file_len:
                        tbl_hdr = f.read(24)
                        entry_cnt = struct.unpack("<I", tbl_hdr[0:4])[0]
                        table_base = struct.unpack("<Q", tbl_hdr[8:16])[0]
                        raw_entries = f.read(entry_cnt * 4)
                        if sec_type == "table":
                            # table2 mirrors table; only index primary 'table' entries
                            for i in range(min(entry_cnt, len(raw_entries) // 4)):
                                raw_off = struct.unpack("<I", raw_entries[i * 4:(i + 1) * 4])[0]
                                is_comp = bool(raw_off & 0x80000000)
                                rel_off = raw_off & 0x7FFFFFFF
                                abs_off = (table_base + rel_off) if table_base else (sectors_base_offset + rel_off)
                                self.chunks.append((seg_path, abs_off, is_comp))

                    elif sec_type in ("done", "next"):
                        break

                    if next_off <= pos:
                        break
                    pos = next_off

        if self.total_size == 0 and self.chunks:
            self.total_size = len(self.chunks) * self.chunk_size

    def _read_chunk(self, idx: int) -> bytes:
        if self._cache_idx == idx:
            return self._cache_data
        if idx < 0 or idx >= len(self.chunks):
            return b""
        seg_path, abs_off, is_comp = self.chunks[idx]
        next_off = self.chunks[idx + 1][1] if (idx + 1 < len(self.chunks) and self.chunks[idx + 1][0] == seg_path) else None
        read_len = max(self.chunk_size + 1024, (next_off - abs_off) if (next_off and next_off > abs_off) else (self.chunk_size + 1024))

        with open(seg_path, "rb") as f:
            f.seek(abs_off)
            raw = f.read(read_len)

        if is_comp:
            try:
                data = zlib.decompress(raw)
            except zlib.error:
                data = zlib.decompressobj().decompress(raw)
        else:
            data = raw[:self.chunk_size]

        self._cache_idx = idx
        self._cache_data = data
        return data

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if whence == os.SEEK_SET:
            self._pos = max(0, offset)
        elif whence == os.SEEK_CUR:
            self._pos = max(0, self._pos + offset)
        elif whence == os.SEEK_END:
            self._pos = max(0, self.total_size + offset)
        return self._pos

    def tell(self) -> int:
        return self._pos

    def read(self, size: int = -1) -> bytes:
        if self._pos >= self.total_size:
            return b""
        if size < 0 or self._pos + size > self.total_size:
            size = self.total_size - self._pos

        out = bytearray()
        remaining = size
        while remaining > 0 and self._pos < self.total_size:
            chunk_idx = self._pos // self.chunk_size
            in_chunk_off = self._pos % self.chunk_size
            chunk_data = self._read_chunk(chunk_idx)
            if not chunk_data:
                break
            take = min(remaining, len(chunk_data) - in_chunk_off)
            if take <= 0:
                break
            out.extend(chunk_data[in_chunk_off:in_chunk_off + take])
            self._pos += take
            remaining -= take
        return bytes(out)

    @property
    def size(self) -> int:
        return self.total_size

    def close(self) -> None:
        self._cache_data = b""
        self._cache_idx = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


def create_synthetic_e01_image(raw_image_path: str, e01_output_path: str, chunk_size: int = 32768) -> str:
    """Wrap any raw disk image into a valid zlib-compressed EWF (.E01) container for testing."""
    with open(raw_image_path, "rb") as f:
        raw = f.read()

    os.makedirs(os.path.dirname(e01_output_path) or ".", exist_ok=True)
    bps = 512
    spc = chunk_size // bps
    num_chunks = (len(raw) + chunk_size - 1) // chunk_size
    tot_sectors = (len(raw) + bps - 1) // bps

    def make_sec_hdr(sec_type: str, next_off: int, sec_size: int) -> bytes:
        hdr = bytearray(76)
        tb = sec_type.encode("ascii")[:16]
        hdr[:len(tb)] = tb
        struct.pack_into("<QQ", hdr, 16, next_off, sec_size)
        struct.pack_into("<I", hdr, 72, zlib.adler32(hdr[:72]))
        return bytes(hdr)

    out = bytearray()
    # 13-byte EVF file header
    out.extend(EWF_SIGNATURE + struct.pack("<BHH", 1, 1, 0))

    # volume section (76 + 1052 bytes)
    vol_off = len(out)
    vol_body = bytearray(1052)
    struct.pack_into("<IIII", vol_body, 4, num_chunks, spc, bps, tot_sectors)
    vol_next = vol_off + 76 + len(vol_body)
    out.extend(make_sec_hdr("volume", vol_next, 76 + len(vol_body)))
    out.extend(vol_body)

    # sectors section
    sec_off = len(out)
    compressed_chunks = []
    for i in range(num_chunks):
        chunk = raw[i * chunk_size:(i + 1) * chunk_size].ljust(chunk_size, b"\x00")
        comp = zlib.compress(chunk)
        compressed_chunks.append(comp)
    sectors_payload = b"".join(compressed_chunks)
    tbl_off = sec_off + 76 + len(sectors_payload)
    out.extend(make_sec_hdr("sectors", tbl_off, 76 + len(sectors_payload)))
    out.extend(sectors_payload)

    # table section
    tbl_hdr = bytearray(24)
    struct.pack_into("<I", tbl_hdr, 0, num_chunks)
    struct.pack_into("<Q", tbl_hdr, 8, sec_off + 76)
    entries = bytearray()
    cur_rel = 0
    for comp in compressed_chunks:
        entries.extend(struct.pack("<I", cur_rel | 0x80000000))
        cur_rel += len(comp)
    done_off = tbl_off + 76 + len(tbl_hdr) + len(entries)
    out.extend(make_sec_hdr("table", done_off, 76 + len(tbl_hdr) + len(entries)))
    out.extend(tbl_hdr)
    out.extend(entries)

    # done section
    out.extend(make_sec_hdr("done", done_off, 76))

    with open(e01_output_path, "wb") as f:
        f.write(out)
    return e01_output_path
