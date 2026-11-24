import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PySide6.QtWidgets import QApplication
from src.ui.shell.main_window import MainWindow


def main():
    app = QApplication(sys.argv)
    # Force Fusion style so QSS design tokens render deterministically on Windows 11
    app.setStyle("Fusion")
    w = MainWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
