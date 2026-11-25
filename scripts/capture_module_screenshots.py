"""Capture crisp native Windows dark-mode screenshots of all 14 forensic modules into docs/screenshots/."""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from PySide6.QtWidgets import QApplication
from src.ui.shell.main_window import MainWindow
from src.core.case_workspace import prepare_suspect_case_workspace
from src.database.models import init_db, Case, ForensicArtifact
from src.database.seed import seed_database_if_empty

SCREENSHOT_FILES = [
    (0, "01_dashboard.png"),
    (1, "02_cases.png"),
    (2, "03_evidence.png"),
    (3, "04_integrity.png"),
    (4, "05_disk_forensics.png"),
    (5, "06_windows_forensics.png"),
    (6, "07_usb_analysis.png"),
    (7, "08_browser_forensics.png"),
    (8, "09_memory_forensics.png"),
    (9, "10_file_analysis.png"),
    (10, "11_timeline.png"),
    (11, "12_relations.png"),
    (12, "13_reports.png"),
    (13, "14_settings.png"),
]


def main() -> None:
    out_dir = Path("docs/screenshots")
    out_dir.mkdir(parents=True, exist_ok=True)

    app = QApplication.instance() or QApplication(sys.argv)
    app.setStyle("Fusion")

    with tempfile.TemporaryDirectory() as td:
        db_file = os.path.join(td, "showcase.db")
        seed_database_if_empty(db_file)
        # Add realistic multi-module findings to DB so Dashboard/Timeline/Relations/Reports reflect VAK-2026-084 deeply
        Session = init_db(db_file)
        with Session() as s:
            from datetime import datetime
            import json
            c = s.query(Case).filter(Case.case_number == "VAK-2026-084").first()
            cid = c.id if c else 1
            s.add_all([
                ForensicArtifact(
                    case_id=cid,
                    artifact_type="Extension Spoofing + YARA",
                    source_path="examples/suspect_pc_case/tatil_fatura_ek.jpg",
                    source_location="Dosya & YARA Analizi",
                    extracted_data=json.dumps({"file": "tatil_fatura_ek.jpg", "rules": ["PowerShell_EncodedCommand", "Suspicious_Exfil_Tools"]}),
                    original_timestamp="2026-03-15T09:24:12Z",
                    normalized_timestamp=datetime(2026, 3, 15, 9, 24, 12),
                    parser_name="FileAnalysisService+YaraStyleScanner",
                    parser_version="1.0.0",
                    confidence=100,
                    warnings="JPEG uzantısı altında Windows PE/MZ ikilisi tespit edildi.",
                ),
                ForensicArtifact(
                    case_id=cid,
                    artifact_type="Memory IOC & EPROCESS",
                    source_path="examples/suspect_pc_case/suspect_memory.dmp",
                    source_location="RAM Bellek Analizi",
                    extracted_data=json.dumps({"ip": "185.220.101.42"}),
                    original_timestamp="2026-03-15T10:05:40Z",
                    normalized_timestamp=datetime(2026, 3, 15, 10, 5, 40),
                    parser_name="MemoryForensicsEngine",
                    parser_version="1.0.0",
                    confidence=90,
                ),
            ])
            s.commit()

        prepare_suspect_case_workspace("examples/suspect_pc_case")

        win = MainWindow(db_path=db_file, data_dir="data")
        win.resize(1440, 880)
        win.show()
        for _ in range(5):
            app.processEvents()

        # Select first row on Disk table so Hex Viewer highlights real MFT bytes cleanly
        if hasattr(win.disk_page, "table") and win.disk_page.table.rowCount() > 0:
            win.disk_page.table.selectRow(0)

        for idx, fname in SCREENSHOT_FILES:
            win.sidebar.select_page(idx)
            for _ in range(6):
                app.processEvents()
            pix = win.grab()
            pix.save(str(out_dir / fname))
            print(f"Captured {fname} ({pix.width()}x{pix.height()})")

        win.close()


if __name__ == "__main__":
    main()
