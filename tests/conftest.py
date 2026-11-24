"""Shared pytest configuration ensuring clean PySide6 teardown on Windows."""

import gc
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    yield app
    for w in list(app.topLevelWidgets()):
        try:
            w.close()
            w.deleteLater()
        except Exception:
            pass
    app.processEvents()
    gc.collect()
    app.quit()
