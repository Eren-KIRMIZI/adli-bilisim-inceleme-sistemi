import struct, os

class RegistryEngine:
    def read_strings(self, path, min_len=4):
        out = []
        with open(path, "rb") as f:
            data = f.read()
        cur = bytearray()
        for b in data:
            if 32 <= b < 127:
                cur.append(b)
            else:
                if len(cur) >= min_len:
                    out.append(cur.decode("ascii", "replace"))
                cur = bytearray()
        if len(cur) >= min_len:
            out.append(cur.decode("ascii", "replace"))
        return out

class EventLogEngine:
    def read_text(self, path):
        try:
            with open(path, "rb") as f:
                return f.read(2000).decode("utf-8", "replace")
        except Exception as e:
            return str(e)

class UsbEngine:
    def find_usb_strings(self, path):
        re_ = RegistryEngine()
        strs = re_.read_strings(path)
        return [s for s in strs if "USB" in s.upper() or "VID_" in s.upper()]

class NtfsEngine:
    def read_raw(self, path, limit=1024):
        with open(path, "rb") as f:
            return f.read(limit)

class BrowserEngine:
    def read_sqlite_tables(self, path):
        import sqlite3
        try:
            con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            cur = con.cursor()
            tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            con.close()
            return tables
        except Exception as e:
            return [str(e)]

class MemoryEngine:
    def basic_info(self, path):
        st = os.stat(path)
        return {"size": st.st_size, "note": "Basic memory dump info (placeholder)"}

class CorrelationEngine:
    def link(self, a, b, rel):
        return {"from": a, "to": b, "relation": rel}
