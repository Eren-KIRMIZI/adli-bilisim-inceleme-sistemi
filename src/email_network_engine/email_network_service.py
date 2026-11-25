"""Original pure-Python Email (.eml, .mbox, .pst/.ost PFF) and Network (.pcap, .pcapng, Hosts) Forensic Parsers."""

from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
import hashlib
import mailbox
import os
import re
import socket
import struct
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from src.file_engine.file_service import detect_signature


class EmailForensicsService:
    """Read-only RFC 5322 (.eml), Unix .mbox, and Outlook PFF (.pst/.ost) forensic parser."""

    @staticmethod
    def _parse_email_message(msg, raw_len: int = 0) -> Dict[str, Any]:
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
        }

    @classmethod
    def parse_eml(cls, path: str) -> Dict[str, Any]:
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        with open(path, "rb") as f:
            raw = f.read()
        msg = BytesParser(policy=policy.default).parsebytes(raw)
        parsed = cls._parse_email_message(msg, len(raw))
        parsed["artifact_type"] = "E-posta (.eml)"
        parsed["filename"] = os.path.basename(path)
        parsed["raw_bytes"] = raw[:2048]
        return parsed

    @classmethod
    def parse_mbox(cls, path: str, max_messages: int = 500) -> Dict[str, Any]:
        """Parse Unix/Thunderbird .mbox archive containing multiple RFC 5322 messages."""
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        mbox = mailbox.mbox(path, factory=lambda f: BytesParser(policy=policy.default).parse(f))
        messages: List[Dict[str, Any]] = []
        try:
            for idx, msg in enumerate(mbox):
                if idx >= max_messages:
                    break
                item = cls._parse_email_message(msg)
                item["index"] = idx + 1
                messages.append(item)
        finally:
            mbox.close()

        with open(path, "rb") as f:
            head = f.read(2048)

        return {
            "artifact_type": "E-posta Kutusu (.mbox)",
            "filename": os.path.basename(path),
            "message_count": len(messages),
            "messages": messages,
            "from": messages[0]["from"] if messages else "-",
            "to": messages[0]["to"] if messages else "-",
            "subject": f"{len(messages)} ileti (.mbox arşivi)",
            "date_raw": messages[0]["date_raw"] if messages else "-",
            "date_utc": messages[0]["date_utc"] if messages else None,
            "received_hops": messages[0]["received_hops"] if messages else [],
            "auth_results": messages[0]["auth_results"] if messages else [],
            "urls": sorted({u for m in messages for u in m.get("urls", [])})[:100],
            "attachments": [a for m in messages for a in m.get("attachments", [])][:100],
            "body_preview": "\n---\n".join(f"[{m['index']}] {m['from']} -> {m['subject']}\n{m['body_preview'][:300]}" for m in messages[:5]),
            "raw_bytes": head,
        }

    @classmethod
    def parse_pst_ost(cls, path: str, max_scan_mb: int = 32) -> Dict[str, Any]:
        """Pure-Python Microsoft Outlook PFF (.pst/.ost '!BDN') forensic header & message extractor."""
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        with open(path, "rb") as f:
            raw = f.read(min(os.path.getsize(path), max_scan_mb * 1024 * 1024))
        if len(raw) < 512 or raw[0:4] != b"!BDN":
            raise ValueError("Geçerli Outlook PFF (.pst/.ost '!BDN') imzası bulunamadı.")

        ver_client = struct.unpack("<H", raw[10:12])[0]
        is_unicode = ver_client >= 23
        crypt_method = raw[513] if len(raw) > 513 else 0
        # Permute-decode simple PFF encoding (method 1) if needed, and extract ASCII/UTF-16LE email metadata/subjects
        decoded_ascii = raw.decode("ascii", "replace")
        emails = sorted(set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", decoded_ascii)))[:100]
        urls = sorted(set(re.findall(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", decoded_ascii)))[:100]

        subjects: List[str] = []
        for m in re.finditer(rb"Subject:\s*([^\r\n\x00]{3,140})", raw):
            subjects.append(m.group(1).decode("utf-8", "replace"))
        for m in re.finditer(rb"(?:[\x20-\x7e]\x00){6,100}", raw):
            txt = m.group(0).decode("utf-16le", "ignore").strip()
            if ("@" in txt or "http" in txt or "Fatura" in txt or "Exfil" in txt or "Subject" in txt) and txt not in subjects:
                subjects.append(txt)

        return {
            "artifact_type": f"Outlook PFF ({'Unicode' if is_unicode else 'ANSI'} .pst/.ost)",
            "filename": os.path.basename(path),
            "version_client": ver_client,
            "encryption_method": {0: "Şifresiz", 1: "Permute (Basit)", 2: "Cyclic"}.get(crypt_method, f"Kod {crypt_method}"),
            "from": emails[0] if emails else "-",
            "to": ", ".join(emails[1:4]) if len(emails) > 1 else "-",
            "subject": subjects[0] if subjects else f"PFF Verisi ({len(emails)} e-posta adresi)",
            "date_raw": "-",
            "date_utc": None,
            "received_hops": [],
            "auth_results": [],
            "urls": urls,
            "attachments": [],
            "extracted_emails": emails,
            "extracted_subjects": subjects[:50],
            "body_preview": "Bulunan E-postalar: " + ", ".join(emails[:10]) + "\nKonu/Metin Kalıntıları:\n" + "\n".join(subjects[:15]),
            "raw_bytes": raw[:2048],
        }


class NetworkForensicsService:
    """Pure-Python libpcap (.pcap) & PCAPNG (.pcapng) extractor + Windows hosts & live netstat triage."""

    PCAP_MAGICS = {
        b"\xd4\xc3\xb2\xa1": "<",
        b"\xa1\xb2\xc3\xd4": ">",
        b"\x4d\x3c\xb2\xa1": "<",
        b"\xa1\xb2\x3c\x4d": ">",
    }

    @classmethod
    def _decode_eth_ipv4(cls, pkt: bytes, dt: Optional[datetime], linktype: int,
                         dns_queries: List[Dict[str, Any]], http_iocs: List[Dict[str, Any]]) -> Tuple[str, str, str, str, str]:
        src_ip, dst_ip, proto_name, src_port, dst_port = "-", "-", f"LinkType({linktype})", "-", "-"
        if linktype == 1 and len(pkt) >= 34 and struct.unpack(">H", pkt[12:14])[0] == 0x0800:
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
        return src_ip, dst_ip, proto_name, str(src_port), str(dst_port)

    @classmethod
    def parse_pcap(cls, path: str, max_packets: int = 5000) -> Dict[str, Any]:
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        with open(path, "rb") as f:
            raw = f.read(min(os.path.getsize(path), 32 * 1024 * 1024))

        if len(raw) >= 12 and raw[:4] == b"\x0a\x0d\x0d\x0a":
            return cls._parse_pcapng_bytes(raw, path, max_packets=max_packets)

        if len(raw) < 24 or raw[:4] not in cls.PCAP_MAGICS:
            raise ValueError("Geçerli libpcap (.pcap) veya PCAPNG (.pcapng) başlık imzası bulunamadı.")

        endian = cls.PCAP_MAGICS[raw[:4]]
        is_nano = raw[:4] in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        ver_maj, ver_min, _, _, snaplen, network = struct.unpack(f"{endian}HHIIII", raw[4:24])

        pos = 24
        packets: List[Dict[str, Any]] = []
        dns_queries: List[Dict[str, Any]] = []
        http_iocs: List[Dict[str, Any]] = []

        while pos + 16 <= len(raw) and len(packets) < max_packets:
            ts_sec, _, incl_len, orig_len = struct.unpack(f"{endian}IIII", raw[pos:pos + 16])
            pos += 16
            if incl_len == 0 or pos + incl_len > len(raw):
                break
            pkt = raw[pos:pos + incl_len]
            pos += incl_len

            dt = datetime.utcfromtimestamp(ts_sec) if ts_sec > 0 else None
            src_ip, dst_ip, proto_name, src_port, dst_port = cls._decode_eth_ipv4(
                pkt, dt, network, dns_queries, http_iocs
            )
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
            "version": f"PCAP {ver_maj}.{ver_min}" + (" (ns)" if is_nano else " (us)"),
            "snaplen": snaplen,
            "packet_count": len(packets),
            "packets": packets,
            "dns_queries": dns_queries,
            "http_iocs": http_iocs,
            "header_bytes": raw[:1024],
        }

    @classmethod
    def _parse_pcapng_bytes(cls, raw: bytes, path: str, max_packets: int = 5000) -> Dict[str, Any]:
        """Pure-Python PCAPNG (Section Header Block / Interface Description Block / Enhanced Packet Block)."""
        pos = 0
        endian = "<"
        interfaces: List[int] = []
        packets: List[Dict[str, Any]] = []
        dns_queries: List[Dict[str, Any]] = []
        http_iocs: List[Dict[str, Any]] = []

        while pos + 12 <= len(raw) and len(packets) < max_packets:
            btype = struct.unpack(f"{endian}I", raw[pos:pos + 4])[0]
            if btype == 0x0A0D0D0A and pos + 12 <= len(raw):
                magic_bom = raw[pos + 8:pos + 12]
                endian = "<" if magic_bom == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack(f"{endian}I", raw[pos + 4:pos + 8])[0]
            if blen < 12 or pos + blen > len(raw):
                break
            body = raw[pos + 8:pos + blen - 4]

            if btype == 0x00000001 and len(body) >= 8:  # IDB
                linktype = struct.unpack(f"{endian}H", body[0:2])[0]
                interfaces.append(linktype)
            elif btype == 0x00000006 and len(body) >= 20:  # EPB
                iface_id, ts_hi, ts_lo, cap_len, orig_len = struct.unpack(f"{endian}IIIII", body[0:20])
                linktype = interfaces[iface_id] if iface_id < len(interfaces) else 1
                ts_us = ((ts_hi << 32) | ts_lo)
                dt = datetime.utcfromtimestamp(ts_us / 1_000_000) if ts_us > 0 else None
                pkt = body[20:20 + cap_len]
                src_ip, dst_ip, proto_name, src_port, dst_port = cls._decode_eth_ipv4(
                    pkt, dt, linktype, dns_queries, http_iocs
                )
                packets.append({
                    "index": len(packets) + 1,
                    "timestamp": dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "-",
                    "protocol": proto_name,
                    "src": f"{src_ip}:{src_port}" if src_port != "-" else src_ip,
                    "dst": f"{dst_ip}:{dst_port}" if dst_port != "-" else dst_ip,
                    "length": orig_len,
                    "_raw": pkt[:512],
                })
            pos += blen

        return {
            "filename": os.path.basename(path),
            "version": "PCAPNG 1.0",
            "snaplen": 65535,
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
                            entries.append({"line": str(lineno), "ip": ip, "domain": dom, "source": target})
        except Exception:
            pass
        return entries

    @staticmethod
    def capture_live_connections(max_rows: int = 120) -> List[Dict[str, str]]:
        rows: List[Dict[str, str]] = []
        try:
            proc = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=6, check=False)
            for line in proc.stdout.splitlines():
                parts = line.strip().split()
                if parts and parts[0] in ("TCP", "UDP") and len(parts) >= 4:
                    proto = parts[0]
                    rows.append({
                        "protocol": proto,
                        "local": parts[1],
                        "remote": parts[2],
                        "state": parts[3] if proto == "TCP" and len(parts) >= 5 else "-",
                        "pid": parts[-1],
                    })
                    if len(rows) >= max_rows:
                        break
        except Exception:
            pass
        return rows


def create_synthetic_eml_file(output_path: str) -> str:
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
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    buf = bytearray()
    buf.extend(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

    def wrap_eth_ip(src_ip: str, dst_ip: str, proto: int, l4_payload: bytes) -> bytes:
        eth = b"\xaa\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44\x55\x66\x08\x00"
        tot_len = 20 + len(l4_payload)
        ip_hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, tot_len, 1, 0, 64, proto, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
        return eth + ip_hdr + l4_payload

    qname = b"\x05exfil\x07evil-c2\x07example\x00"
    dns_body = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 1, 1)
    udp = struct.pack(">HHHH", 51234, 53, 8 + len(dns_body), 0) + dns_body
    p1 = wrap_eth_ip("192.168.1.50", "8.8.8.8", 17, udp)
    buf.extend(struct.pack("<IIII", 1795203300, 0, len(p1), len(p1)))
    buf.extend(p1)

    http_body = b"GET /stage2.bin HTTP/1.1\r\nHost: c2-drop.example\r\n\r\n"
    tcp = struct.pack(">HHIIHHHH", 51235, 80, 1, 0, (5 << 12) | 0x18, 8192, 0, 0) + http_body
    p2 = wrap_eth_ip("192.168.1.50", "185.220.101.44", 6, tcp)
    buf.extend(struct.pack("<IIII", 1795203315, 0, len(p2), len(p2)))
    buf.extend(p2)

    with open(output_path, "wb") as f:
        f.write(buf)
    return output_path


def create_synthetic_pcapng_file(output_path: str) -> str:
    """Create a valid synthetic PCAPNG (.pcapng) file with SHB + IDB + EPB DNS/HTTP packets."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    def pad4(b: bytes) -> bytes:
        rem = len(b) % 4
        return b + (b"\x00" * ((4 - rem) % 4))

    def block(btype: int, body: bytes) -> bytes:
        blen = 12 + len(body)
        return struct.pack("<II", btype, blen) + body + struct.pack("<I", blen)

    shb = block(0x0A0D0D0A, struct.pack("<IHHiQ", 0x1A2B3C4D, 1, 0, -1, 0)[:16])
    # Reconstruct exact SHB body: BOM(4) + maj(2) + min(2) + section_len(8)
    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = block(0x00000001, struct.pack("<HHI", 1, 0, 65535))

    eth = b"\xaa\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44\x55\x66\x08\x00"
    qname = b"\x04ngc2\x07evil-c2\x07example\x00"
    dns_body = struct.pack(">HHHHHH", 0x5678, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 1, 1)
    udp = struct.pack(">HHHH", 53000, 53, 8 + len(dns_body), 0) + dns_body
    ip_hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 2, 0, 64, 17, 0, socket.inet_aton("10.0.0.15"), socket.inet_aton("1.1.1.1"))
    pkt = eth + ip_hdr + udp
    ts_us = 1795203400 * 1_000_000
    epb_body = struct.pack("<IIIII", 0, ts_us >> 32, ts_us & 0xFFFFFFFF, len(pkt), len(pkt)) + pad4(pkt)
    epb = block(0x00000006, epb_body)

    with open(output_path, "wb") as f:
        f.write(shb + idb + epb)
    return output_path


def create_synthetic_mbox_and_pst(output_dir: str) -> Dict[str, str]:
    """Generate synthetic .mbox and .pst ('!BDN') files for offline tests."""
    os.makedirs(output_dir, exist_ok=True)
    mbox_path = os.path.join(output_dir, "suspect_archive.mbox")
    with open(mbox_path, "w", encoding="utf-8") as f:
        f.write(
            "From attacker@evil-c2.example Fri Nov 20 19:35:00 2026\n"
            "From: attacker@evil-c2.example\n"
            "To: ahmet.k@sirket.example\n"
            "Subject: MBOX Exfil Talimati\n"
            "Date: Fri, 20 Nov 2026 19:35:00 +0000\n\n"
            "Dosyayi https://c2-drop.example/mbox_drop adresine yukleyin.\n\n"
        )

    pst_path = os.path.join(output_dir, "outlook_archive.pst")
    pst = bytearray(4096)
    pst[0:4] = b"!BDN"
    struct.pack_into("<H", pst, 10, 23)  # Unicode PFF
    msg_blob = (
        b"Subject: Outlook PST Gizli Maas Listesi\r\n"
        b"From: ahmet.k@sirket.example -> exfil@evil-c2.example\r\n"
        b"https://c2-drop.example/pst_upload\x00"
    )
    pst[1024:1024 + len(msg_blob)] = msg_blob
    with open(pst_path, "wb") as f:
        f.write(bytes(pst))
    return {"mbox": mbox_path, "pst": pst_path}
