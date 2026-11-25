"""Shared non-blocking QThread workers for cryptographic hashing and forensic I/O engines."""

from PySide6.QtCore import QThread, Signal
from src.integrity_engine.integrity_service import IntegrityService


class HashWorker(QThread):
    """Background worker computing SHA-256 and SHA-512 without blocking the UI thread."""
    progress = Signal(int)
    finished_result = Signal(dict)
    failed = Signal(str)

    def __init__(self, file_path: str, parent=None):
        super().__init__(parent)
        self.file_path = file_path
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def run(self):
        try:
            res = IntegrityService.compute_dual_hashes(
                self.file_path,
                progress_callback=self.progress.emit,
                cancel_check=lambda: self._cancelled,
            )
            self.finished_result.emit(res)
        except Exception as e:
            self.failed.emit(str(e))


class FunctionWorker(QThread):
    """Generic QThread wrapper running a callable off the main GUI thread."""
    finished_result = Signal(object)
    failed = Signal(str)

    def __init__(self, fn, *args, parent=None, **kwargs):
        super().__init__(parent)
        self._fn = fn
        self._args = args
        self._kwargs = kwargs

    def run(self):
        try:
            res = self._fn(*self._args, **self._kwargs)
            self.finished_result.emit(res)
        except Exception as e:
            self.failed.emit(str(e))
