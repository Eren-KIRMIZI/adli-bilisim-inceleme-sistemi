"""Forensic Hexadecimal Viewer component with byte grouping and checksum calculations."""

import hashlib
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QPlainTextEdit, QMessageBox, QApplication
)
from PySide6.QtGui import QFont, QTextCursor


class ForensicHexViewer(QWidget):
    """Forensic standard Hexadecimal & ASCII inspector."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_data = b""
        self._base_offset = 0

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)

        lbl = QLabel("Offset:")
        lbl.setObjectName("mutedLabel")
        toolbar.addWidget(lbl)

        self.jump_input = QLineEdit()
        self.jump_input.setPlaceholderText("0x0000")
        self.jump_input.setFixedWidth(100)
        self.jump_input.setStyleSheet("font-family: Consolas; font-size: 11px; padding: 3px 6px;")
        toolbar.addWidget(self.jump_input)

        jump_btn = QPushButton("Git")
        jump_btn.setFixedWidth(48)
        jump_btn.clicked.connect(self._jump_to_offset)
        toolbar.addWidget(jump_btn)

        toolbar.addStretch()

        self.size_badge = QLabel("0 Bayt")
        self.size_badge.setObjectName("monoLabel")
        toolbar.addWidget(self.size_badge)

        self.sha_badge = QLabel("SHA-256: -")
        self.sha_badge.setObjectName("topbarBadge")
        toolbar.addWidget(self.sha_badge)

        copy_btn = QPushButton("Hex Kopyala")
        copy_btn.clicked.connect(self._copy_hex)
        toolbar.addWidget(copy_btn)

        layout.addLayout(toolbar)

        self.text_edit = QPlainTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setFont(QFont("Consolas", 10))
        layout.addWidget(self.text_edit)

    def load_bytes(self, data: bytes, base_offset: int = 0):
        self._current_data = data
        self._base_offset = base_offset

        sha = hashlib.sha256(data).hexdigest() if data else "-"
        self.size_badge.setText(f"{len(data):,} Bayt")
        self.sha_badge.setText(f"SHA256: {sha[:12]}...")
        self.sha_badge.setToolTip(f"Tam SHA-256: {sha}")

        if not data:
            self.text_edit.setPlainText("İncelenecek bayt verisi yok.")
            return

        lines = [
            "OFFSET    00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F   ASCII DEĞERİ",
            "--------  -----------------------  -----------------------   ----------------",
        ]

        for off in range(0, min(len(data), 65536), 16):
            chunk = data[off:off + 16]
            hex_p1 = " ".join(f"{b:02X}" for b in chunk[:8])
            hex_p2 = " ".join(f"{b:02X}" for b in chunk[8:])
            hex_full = f"{hex_p1:<23}  {hex_p2:<23}"
            ascii_repr = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{base_offset + off:08X}  {hex_full}  |{ascii_repr}|")

        if len(data) > 65536:
            lines.append(f"\n[... Performans için ilk 64 KB gösteriliyor. Toplam: {len(data):,} bayt ...]")

        self.text_edit.setPlainText("\n".join(lines))

    def load_file(self, path: str, max_bytes: int = 65536):
        try:
            with open(path, "rb") as f:
                data = f.read(max_bytes)
            self.load_bytes(data)
        except Exception as e:
            self.text_edit.setPlainText(f"Dosya okuma hatası: {e}")

    def _jump_to_offset(self):
        text = self.jump_input.text().strip()
        if not text:
            return
        try:
            val = int(text, 16) if text.startswith("0x") else int(text)
            line_idx = (val // 16) + 2
            cursor = self.text_edit.textCursor()
            cursor.movePosition(QTextCursor.Start)
            for _ in range(line_idx):
                cursor.movePosition(QTextCursor.Down)
            self.text_edit.setTextCursor(cursor)
        except Exception:
            QMessageBox.warning(self, "Geçersiz Offset", "Lütfen geçerli bir onaltılık (0x100) veya onluk sayı girin.")

    def _copy_hex(self):
        if self._current_data:
            hex_str = " ".join(f"{b:02X}" for b in self._current_data[:2048])
            QApplication.clipboard().setText(hex_str)
            QMessageBox.information(self, "Kopyalandı", "Hexadecimal bayt dizisi panoya kopyalandı.")
