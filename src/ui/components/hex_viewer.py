from PySide6.QtWidgets import QTextEdit

class HexViewer(QTextEdit):
    def __init__(self):
        super().__init__(); self.setReadOnly(True); self.setFontFamily("Consolas")
    def load_file(self, path, max_bytes=4096):
        with open(path, "rb") as f:
            data = f.read(max_bytes)
        lines = []
        for off in range(0, len(data), 16):
            chunk = data[off:off+16]
            hexpart = " ".join(f"{b:02X}" for b in chunk)
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{off:08X}  {hexpart:<47}  {asc}")
        self.setPlainText("\n".join(lines))
