"""Deprecated compatibility facade delegating directly to the production forensic engines."""

from src.registry_engine.hive_parser import RegistryHiveParser
from src.eventlog_engine.evtx_service import EventLogService
from src.usb_engine.usb_service import UsbService
from src.ntfs_engine.ntfs_service import DiskForensicsEngine
from src.browser_engine.browser_service import BrowserForensicsEngine
from src.memory_engine.memory_service import MemoryForensicsEngine
from src.correlation_engine.correlation_service import CorrelationService

__all__ = [
    "RegistryHiveParser",
    "EventLogService",
    "UsbService",
    "DiskForensicsEngine",
    "BrowserForensicsEngine",
    "MemoryForensicsEngine",
    "CorrelationService",
]
