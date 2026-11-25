"""Capture crisp screenshots of the USB Cryptographic Login Screen (Waiting & Verified states) without real secrets."""

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from PySide6.QtWidgets import QApplication
from src.core.usb_auth_service import UsbCryptoAuthService
from src.ui.pages.usb_login_window import UsbLoginDialog


def main() -> None:
    out_dir = Path("docs/screenshots")
    out_dir.mkdir(parents=True, exist_ok=True)
    app = QApplication.instance() or QApplication(sys.argv)
    app.setStyle("Fusion")

    with tempfile.TemporaryDirectory() as td:
        usb_dir = os.path.join(td, "KeyUSB")
        os.makedirs(usb_dir, exist_ok=True)
        cfg_file = os.path.join(td, "usb_auth.json")
        db_file = os.path.join(td, "login_demo.db")

        svc = UsbCryptoAuthService(config_path=cfg_file, db_path=db_file, custom_usb_roots=[usb_dir])
        svc.provision_usb_key(usb_dir, "ShowcaseDemoPass99!")
        meta_p = os.path.join(usb_dir, ".forensic_key", "usb_key_info.json")
        meta = json.loads(Path(meta_p).read_text(encoding="utf-8"))
        meta["drive_letter"] = "D:"
        meta["label"] = "Key"
        meta["capacity_gb"] = "28.9 GB"
        Path(meta_p).write_text(json.dumps(meta), encoding="utf-8")

        # State 1: Waiting for USB key
        dlg_wait = UsbLoginDialog(db_path=db_file, auth_config_path=cfg_file, custom_usb_roots=[], auto_poll=False)
        dlg_wait.resize(1060, 640)
        dlg_wait.show()
        for _ in range(5):
            app.processEvents()
        dlg_wait.grab().save(str(out_dir / "00_usb_login_waiting.png"))
        print("Captured 00_usb_login_waiting.png")
        dlg_wait.close()

        # State 2: Digital Signature Verified + Personal Password prompt
        dlg_ok = UsbLoginDialog(db_path=db_file, auth_config_path=cfg_file, custom_usb_roots=[usb_dir], auto_poll=False)
        dlg_ok.resize(1060, 640)
        dlg_ok.pwd_input.setText("DemoMaskedOnly")
        dlg_ok.show()
        for _ in range(5):
            app.processEvents()
        dlg_ok.grab().save(str(out_dir / "00b_usb_login_verified.png"))
        print("Captured 00b_usb_login_verified.png")
        dlg_ok.close()


if __name__ == "__main__":
    main()
