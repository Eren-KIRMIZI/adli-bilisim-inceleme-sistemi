import ctypes
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PySide6.QtWidgets import QApplication, QDialog
from src.ui.pages.usb_login_window import UsbLoginDialog
from src.ui.shell.main_window import MainWindow
from src.ui.styles.icons import get_app_icon


def main():
    # Ensure Windows 11 taskbar uses our custom .ico instead of grouping under python.exe
    if os.name == "nt" and hasattr(ctypes, "windll"):
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("AdliBilisim.DFIR.Suite.1.0")
        except Exception:
            pass

    app = QApplication(sys.argv)
    # Force Fusion style so QSS design tokens render deterministically on Windows 11
    app.setStyle("Fusion")
    app.setWindowIcon(get_app_icon())

    # Two-Factor USB Cryptographic Authentication Gate
    login = UsbLoginDialog(db_path="data/forensics.db", auth_config_path="data/usb_auth.json")
    if login.exec() != QDialog.Accepted or not login.auth_result:
        sys.exit(0)

    w = MainWindow(usb_auth_session=login.auth_result)
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
