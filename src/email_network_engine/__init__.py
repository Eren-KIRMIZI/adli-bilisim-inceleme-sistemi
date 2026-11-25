"""Pure-Python Email (.eml, .mbox, .pst/.ost) & Network (.pcap, .pcapng, Hosts, Live Triage) Forensics Engine."""

from .email_network_service import (
    EmailForensicsService,
    NetworkForensicsService,
    create_synthetic_eml_file,
    create_synthetic_pcap_file,
    create_synthetic_pcapng_file,
    create_synthetic_mbox_and_pst,
)

__all__ = [
    "EmailForensicsService",
    "NetworkForensicsService",
    "create_synthetic_eml_file",
    "create_synthetic_pcap_file",
    "create_synthetic_pcapng_file",
    "create_synthetic_mbox_and_pst",
]
