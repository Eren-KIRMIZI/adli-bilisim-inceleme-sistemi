"""Pure-Python Email (.eml) & Network (.pcap / Hosts / Live Triage) Forensics Engine."""

from .email_network_service import (
    EmailForensicsService,
    NetworkForensicsService,
    create_synthetic_eml_file,
    create_synthetic_pcap_file,
)

__all__ = [
    "EmailForensicsService",
    "NetworkForensicsService",
    "create_synthetic_eml_file",
    "create_synthetic_pcap_file",
]
