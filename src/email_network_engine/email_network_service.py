"""Original pure-Python Email (RFC 5322 .eml) and Network (libpcap .pcap / Hosts) Forensic Parsers."""

from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
import hashlib
import os
import re
import socket
import struct
import subprocess
from typing import Any, Dict, List, Optional

from src.file_engine.file_service import detect_signature


class EmailForensicsService:
    """Read-only RFC 5322 (.eml) parser extracting headers, relay hops, auth flags, URLs, and attachments."""

    @staticmethod
    def parse_eml(path: str) -> Dict[str, Any]:
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        with open(path, "rb") as f:
            raw = f.read()

        msg = BytesParser(policy=policy.default).parsebytes(raw)
        date_raw = msg.get("Date", "")
        date_utc: Optional[datetime] = None
        if date_raw:
            try:
                dt = parsedate_to_datetime(date_raw)
                if dt.tzinfo is not None:
                    date_utc = dt.astimezone(timezone.utc).replace(tzinfo=None)
                else:
                    date_utc = dt
            except Exception:
                date_utc = None

        received_hops = [str(h) for h in msg.get_all("Received", [])]
        auth_results = [str(h) for h in msg.get_all("Authentication-Results", [])]

        body_texts: List[str] = []
        attachments: List[Dict[str, Any]] = []
        if msg.is_multipart():
            for part in msg.walk():
                cdisp = part.get_content_disposition()
                fname = part.get_filename()
                ctype = part.get_content_type()
                if cdisp == "attachment" or fname:
                    payload = part.get_payload(decode=True) or b""
                    sig, conf = detect_signature(payload[:32])
                    attachments.append({
                        "filename": fname or "ek_dosya",
                        "content_type": ctype,
                        "size": len(payload),
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "signature": f"{sig} ({conf})",
                    })
                elif ctype in ("text/plain", "text/html"):
                    try:
                        body_texts.append(part.get_content())
                    except Exception:
                        pass
        else:
            try:
                body_texts.append(msg.get_content())
            except Exception:
                pass

        combined_body = "\n".join(str(b) for b in body_texts)
        urls = sorted(set(re.findall(r"https?://[^\s<>\"'()]+", combined_body)))[:100]

        return {
            "artifact_type": "E-posta (.eml)",
            "filename": os.path.basename(path),
            "from": str(msg.get("From", "-")),
            "to": str(msg.get("To", "-")),
            "cc": str(msg.get("Cc", "-")),
            "subject": str(msg.get("Subject", "-")),
            "message_id": str(msg.get("Message-ID", "-")),
            "return_path": str(msg.get("Return-Path", "-")),
            "date_raw": str(date_raw or "-"),
            "date_utc": date_utc,
            "received_hops": received_hops,
            "auth_results": auth_results,
            "urls": urls,
            "attachments": attachments,
            "body_preview": combined_body[:1500],
            "raw_bytes": raw[:2048],
        }


class NetworkForensicsService:
    """Pure-Python libpcap (.pcap) packet/DNS/HTTP IOC extractor + Windows hosts & live network triage."""

    PCAP_MAGICS = {
        b"\xd4\xc3\xb2\xa1": "<",  # little-endian microsec
        b"\xa1\xb2\xc3\xd4": ">",  # big-endian microsec
        b"\x4d\x3c\xb2\xa1": "<",  # little-endian nanosec
        b"\xa1\xb2\x3c\x4d": ">",  # big-endian nanosec
    }

    @classmethod
    def parse_pcap(cls, path: str, max_packets: int = 5000) -> Dict[str, Any]:
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        with open(path, "rb") as f:
            raw = f.read(min(os.path.getsize(path), 32 * 1024 * 1024))

        if len(raw) < 24 or raw[:4] not in cls.PCAP_MAGICS:
            raise ValueError("Geçerli libpcap (.pcap) başlık imzası (0xA1B2C3D4) bulunamadı.")

        endian = cls.PCAP_MAGICS[raw[:4]]
        is_nano = raw[:4] in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        ver_maj, ver_min, _, _, snaplen, network = struct.unpack(f"{endian}HHIIII", raw[4:24])

        pos = 24
        packets: List[Dict[str, Any]] = []
        dns_queries: List[Dict[str, Any]] = []
        http_iocs: List[Dict[str, Any]] = []

        while pos + 16 <= len(raw) and len(packets) < max_packets:
            ts_sec, ts_sub, incl_len, orig_len = struct.unpack(f"{endian}IIII", raw[pos:pos + 16])
            pos += 16
            if incl_len == 0 or pos + incl_len > len(raw):
                break
            pkt = raw[pos:pos + incl_len]
            pos += incl_len

            dt = datetime.utcfromtimestamp(ts_sec) if ts_sec > 0 else None
            src_ip, dst_ip, proto_name, src_port, dst_port = "-", "-", f"LinkType({network})", "-", "-"

            # Ethernet II (linktype 1) + IPv4 (0x0800)
            if network == 1 and len(pkt) >= 34 and struct.unpack(">H", pkt[12:14])[0] == 0x0800:
                ip_hdr = pkt[14:]
                ihl = (ip_hdr[0] & 0x0F) * 4
                proto = ip_hdr[9]
                src_ip = socket.inet_ntoa(ip_hdr[12:16])
                dst_ip = socket.inet_ntoa(ip_hdr[16:20])
                l4 = ip_hdr[ihl:] if len(ip_hdr) >= ihl else b""
                if proto == 6 and len(l4) >= 20:
                    proto_name = "TCP"
                    src_port, dst_port = struct.unpack(">HH", l4[0:4])
                    doff = ((l4[12] >> 4) & 0x0F) * 4
                    app = l4[doff:]
                    for m in re.finditer(rb"(?:GET|POST|PUT|HEAD)\s+([^\r\n ]+)|Host:\s*([^\r\n]+)", app):
                        val = (m.group(1) or m.group(2) or b"").decode("ascii", "replace")
                        http_iocs.append({
                            "timestamp": dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "-",
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "ioc": val,
                        })
                elif proto == 17 and len(l4) >= 8:
                    proto_name = "UDP"
                    src_port, dst_port = struct.unpack(">HH", l4[0:4])
                    if src_port == 53 or dst_port == 53:
                        proto_name = "DNS (UDP/53)"
                        dns_q = cls._parse_dns_qname(l4[8:])
                        if dns_q:
                            dns_queries.append({
                                "timestamp": dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "-",
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "domain": dns_q,
                            })
                elif proto == 1:
                    proto_name = "ICMP"
                else:
                    proto_name = f"IPProto({proto})"

            packets.append({
                "index": len(packets) + 1,
                "timestamp": dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "-",
                "protocol": proto_name,
                "src": f"{src_ip}:{src_port}" if src_port != "-" else src_ip,
                "dst": f"{dst_ip}:{dst_port}" if dst_port != "-" else dst_ip,
                "length": orig_len,
                "_raw": pkt[:512],
            })

        return {
            "filename": os.path.basename(path),
            "version": f"{ver_maj}.{ver_min}" + (" (ns)" if is_nano else " (us)"),
            "snaplen": snaplen,
            "packet_count": len(packets),
            "packets": packets,
            "dns_queries": dns_queries,
            "http_iocs": http_iocs,
            "header_bytes": raw[:1024],
        }

    @staticmethod
    def _parse_dns_qname(dns_payload: bytes) -> Optional[str]:
        if len(dns_payload) < 17:
            return None
        qdcount = struct.unpack(">H", dns_payload[4:6])[0]
        if qdcount == 0:
            return None
        pos = 12
        labels: List[str] = []
        while pos < len(dns_payload):
            ln = dns_payload[pos]
            pos += 1
            if ln == 0:
                break
            if (ln & 0xC0) or pos + ln > len(dns_payload):
                return None
            labels.append(dns_payload[pos:pos + ln].decode("ascii", "replace"))
            pos += ln
        return ".".join(labels) if labels else None

    @staticmethod
    def read_hosts_file(hosts_path: Optional[str] = None) -> List[Dict[str, str]]:
        """Read-only parser for Windows/Linux hosts mapping file (detects suspicious domain overrides)."""
        target = hosts_path or os.path.join(
            os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers", "etc", "hosts"
        )
        entries: List[Dict[str, str]] = []
        if not os.path.isfile(target):
            return entries
        try:
            with open(target, "r", encoding="utf-8", errors="replace") as f:
                for lineno, line in enumerate(f, 1):
                    clean = line.split("#", 1)[0].strip()
                    if not clean:
                        continue
                    parts = clean.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        for dom in parts[1:]:
                            entries.append({
                                "line": str(lineno),
                                "ip": ip,
                                "domain": dom,
                                "source": target,
                            })
        except Exception:
            pass
        return entries

    @staticmethod
    def capture_live_connections(max_rows: int = 120) -> List[Dict[str, str]]:
        """Read-only snapshot of active TCP/UDP endpoints via netstat -ano (Windows/POSIX)."""
        rows: List[Dict[str, str]] = []
        try:
            proc = subprocess.run(
                ["netstat", "-ano"], capture_output=True, text=True, timeout=6, check=False
            )
            for line in proc.stdout.splitlines():
                parts = line.strip().split()
                if parts and parts[0] in ("TCP", "UDP") and len(parts) >= 4:
                    proto = parts[0]
                    local = parts[1]
                    remote = parts[2]
                    state = parts[3] if proto == "TCP" and len(parts) >= 5 else "-"
                    pid = parts[-1]
                    rows.append({
                        "protocol": proto,
                        "local": local,
                        "remote": remote,
                        "state": state,
                        "pid": pid,
                    })
                    if len(rows) >= max_rows:
                        break
        except Exception:
            pass
        return rows


def create_synthetic_eml_file(output_path: str) -> str:
    """Create a synthetic RFC 5322 .eml phishing/exfil evidence sample with an embedded attachment."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    eml_content = (
        "From: attacker@evil-c2.example\r\n"
        "To: ahmet.k@sirket.example\r\n"
        "Subject: Acil Fatura Onayi - Q4 Exfil\r\n"
        "Date: Fri, 20 Nov 2026 19:35:00 +0000\r\n"
        "Message-ID: <20261120193500.99@evil-c2.example>\r\n"
        "Authentication-Results: mx.sirket.example; spf=fail smtp.mailfrom=evil-c2.example; dkim=none\r\n"
        "Received: from [185.220.101.44] by mx.sirket.example with ESMTP; Fri, 20 Nov 2026 19:35:00 +0000\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/mixed; boundary=\"FORENSIC_BOUNDARY_01\"\r\n"
        "\r\n"
        "--FORENSIC_BOUNDARY_01\r\n"
        "Content-Type: text/plain; charset=\"utf-8\"\r\n"
        "\r\n"
        "Merhaba, odeme dekontunu https://c2-drop.example/invoice?id=44 adresinden dogrulayin.\r\n"
        "--FORENSIC_BOUNDARY_01\r\n"
        "Content-Type: application/zip; name=\"fatura_ek.zip\"\r\n"
        "Content-Disposition: attachment; filename=\"fatura_ek.zip\"\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "\r\n"
        "UEsDBAoAAAAAAP//AAAAAAAAAAAAAAAA\r\n"
        "--FORENSIC_BOUNDARY_01--\r\n"
    ).encode("utf-8")
    with open(output_path, "wb") as f:
        f.write(eml_content)
    return output_path


def create_synthetic_pcap_file(output_path: str) -> str:
    """Create a minimal valid libpcap (.pcap) file containing DNS (UDP/53) + HTTP (TCP/80) packets."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    buf = bytearray()
    # Global header: magic, 2.4, tz=0, sigfigs=0, snaplen=65535, Ethernet=1
    buf.extend(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

    def wrap_eth_ip(src_ip: str, dst_ip: str, proto: int, l4_payload: bytes) -> bytes:
        eth = b"\xaa\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44\x55\x66\x08\x00"
        tot_len = 20 + len(l4_payload)
        ip_hdr = struct.pack(
            ">BBHHHBBH4s4s",
            0x45, 0, tot_len, 1, 0, 64, proto, 0,
            socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
        )
        return eth + ip_hdr + l4_payload

    # Packet 1: DNS query for exfil.evil-c2.example
    qname = b"\x05exfil\x07evil-c2\x07example\x00"
    dns_body = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 1, 1)
    udp = struct.pack(">HHHH", 51234, 53, 8 + len(dns_body), 0) + dns_body
    p1 = wrap_eth_ip("192.168.1.50", "8.8.8.8", 17, udp)
    buf.extend(struct.pack("<IIII", 1795203300, 0, len(p1), len(p1)))
    buf.extend(p1)

    # Packet 2: HTTP GET /stage2.bin to 185.220.101.44:80
    http_body = b"GET /stage2.bin HTTP/1.1\r\nHost: c2-drop.example\r\n\r\n"
    tcp = struct.pack(">HHIIHHHH", 51235, 80, 1, 0, (5 << 12) | 0x18, 8192, 0, 0) + http_body
    p2 = wrap_eth_ip("192.168.1.50", "185.220.101.44", 6, tcp)
    buf.extend(struct.pack("<IIII", 1795203315, 0, len(p2), len(p2)))
    buf.extend(p2)

    with open(output_path, "wb") as f:
        f.write(buf)
    return output_path
