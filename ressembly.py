# core/decoder.py
"""
Decoder module
- Prend des paquets Scapy et retourne une structure python (dict)
  contenant métadonnées utiles pour l'UI et le reassembly.
- Tente d'utiliser dpkt si installé pour parsing HTTP/DNS plus propre.
- Fournit helpers: parse_http_from_bytes, extract_tls_sni, hex_dump, protocol_summary.

Usage:
    from scapy.all import sniff
    from core.decoder import parse_packet

    def cb(pkt):
        info = parse_packet(pkt)
        print(info['summary'])
"""

from typing import Dict, Any, Optional, Tuple
import binascii
import struct

# Try imports; dpkt optional
try:
    import dpkt
    DPktAvailable = True
except Exception:
    dpkt = None
    DPktAvailable = False

# Scapy imports (assume scapy is installed since capture uses it)
from scapy.all import IP, IPv6, TCP, UDP, ICMP, Ether, ARP, Raw
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello  # scapy TLS layers if available

# ---------- Helpers ----------

def hex_dump(data: bytes, width: int = 16) -> str:
    """Return a simple hex+ascii dump as a string."""
    if not data:
        return ""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asciipart = "".join((chr(b) if 32 <= b < 127 else ".") for b in chunk)
        lines.append(f"{i:08x}  {hexpart:<{width*3}}  {asciipart}")
    return "\n".join(lines)

def _safe_getattr(obj, attr, default=None):
    try:
        return getattr(obj, attr)
    except Exception:
        return default

# ---------- Protocol parsers ----------

def parse_http_from_bytes(data: bytes) -> Optional[Dict[str, Any]]:
    """
    Try to extract a basic HTTP request/response from raw bytes.
    Returns dict with method/status, headers, body if found.
    Uses dpkt if available for cleaner parsing.
    """
    if not data:
        return None
    try:
        # Try dpkt
        if DPktAvailable:
            try:
                # dpkt can parse requests or responses heuristically
                try:
                    req = dpkt.http.Request(data)
                    headers = {k: v for k, v in req.headers.items()}
                    return {"type": "request", "method": req.method, "uri": req.uri, "version": req.version,
                            "headers": headers, "body": req.body}
                except (dpkt.NeedData, dpkt.UnpackError):
                    pass
                try:
                    resp = dpkt.http.Response(data)
                    headers = {k: v for k, v in resp.headers.items()}
                    return {"type": "response", "status": resp.status, "reason": resp.reason,
                            "version": resp.version, "headers": headers, "body": resp.body}
                except (dpkt.NeedData, dpkt.UnpackError):
                    pass
            except Exception:
                pass

        # Fallback: crude ASCII checks
        txt = None
        try:
            txt = data.decode("utf-8", errors="ignore")
        except Exception:
            txt = None
        if not txt:
            return None
        lines = txt.splitlines()
        if not lines:
            return None
        first = lines[0].strip()
        # HTTP Request
        if first.split(" ")[0] in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"):
            parts = first.split(" ")
            method = parts[0]
            uri = parts[1] if len(parts) > 1 else ""
            headers = {}
            body = b""
            i = 1
            while i < len(lines):
                line = lines[i]
                if line == "":
                    # remainder is body
                    body = "\n".join(lines[i+1:]).encode("utf-8", errors="ignore")
                    break
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip()] = v.strip()
                i += 1
            return {"type": "request", "method": method, "uri": uri, "headers": headers, "body": body}
        # HTTP Response
        if first.startswith("HTTP/"):
            parts = first.split(" ", 2)
            version = parts[0]
            status = parts[1] if len(parts) > 1 else ""
            reason = parts[2] if len(parts) > 2 else ""
            headers = {}
            body = b""
            i = 1
            while i < len(lines):
                line = lines[i]
                if line == "":
                    body = "\n".join(lines[i+1:]).encode("utf-8", errors="ignore")
                    break
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip()] = v.strip()
                i += 1
            return {"type": "response", "status": status, "reason": reason, "headers": headers, "body": body}
    except Exception:
        return None
    return None

def parse_dns_from_scapy(pkt) -> Optional[Dict[str, Any]]:
    """Parse DNS content from a Scapy packet (if present)."""
    try:
        if DNS in pkt:
            dns = pkt[DNS]
            out = {"id": dns.id, "qr": dns.qr, "opcode": dns.opcode, "rcode": dns.rcode, "qdcount": dns.qdcount,
                   "ancount": dns.ancount, "nscount": dns.nscount, "arcount": dns.arcount, "questions": [], "answers": []}
            # questions
            for i in range(dns.qdcount):
                try:
                    q = dns.qd[i] if dns.qdcount > 1 else dns.qd
                    out["questions"].append({"qname": q.qname.decode() if isinstance(q.qname, bytes) else str(q.qname),
                                             "qtype": q.qtype, "qclass": q.qclass})
                except Exception:
                    pass
            # answers
            for i in range(dns.ancount):
                try:
                    a = dns.an[i] if dns.ancount > 1 else dns.an
                    out["answers"].append({"rrname": getattr(a, "rrname", None),
                                           "type": getattr(a, "type", None),
                                           "rdata": getattr(a, "rdata", None)})
                except Exception:
                    pass
            return out
    except Exception:
        return None
    return None

def extract_tls_sni_from_bytes(data: bytes) -> Optional[str]:
    """
    Attempt to extract SNI from TLS ClientHello bytes.
    This is a heuristic parser (reads TLS record + handshake structures) and not full TLS implementation.
    Returns server name or None.
    """
    if not data or len(data) < 5:
        return None
    try:
        # TLS record header: ContentType(1) Version(2) Length(2)
        rec_type = data[0]
        if rec_type != 22:  # Handshake
            return None
        # handshake starts at offset 5
        # Find ClientHello (handshake type 1)
        # We'll search for the SNI extension pattern: 00 00 (extension type 0x0000? actually 0x0000 is SNI)
        # Safer approach: scan for 0x00 0x00 0x00 <len> ... but we'll do a more tolerant regex-less scan.
        # Navigate handshake:
        # Skip record header
        ptr = 5
        if ptr >= len(data):
            return None
        # handshake type
        hs_type = data[5]
        if hs_type != 1:  # ClientHello
            return None
        # Skip handshake header (1 byte type + 3 bytes length)
        ptr = 5 + 4
        # Skip client version (2), random(32)
        ptr += 2 + 32
        if ptr >= len(data):
            return None
        # Session ID
        sid_len = data[ptr]
        ptr += 1 + sid_len
        if ptr >= len(data):
            return None
        # Cipher suites
        if ptr + 2 > len(data):
            return None
        cs_len = struct.unpack("!H", data[ptr:ptr+2])[0]
        ptr += 2 + cs_len
        if ptr >= len(data):
            return None
        # Compression methods
        if ptr + 1 > len(data):
            return None
        comp_len = data[ptr]
        ptr += 1 + comp_len
        if ptr >= len(data):
            return None
        # Extensions length
        if ptr + 2 > len(data):
            return None
        ext_len = struct.unpack("!H", data[ptr:ptr+2])[0]
        ptr += 2
        end_ext = ptr + ext_len
        # Walk extensions
        while ptr + 4 <= end_ext and ptr + 4 <= len(data):
            ext_type = struct.unpack("!H", data[ptr:ptr+2])[0]
            ext_len = struct.unpack("!H", data[ptr+2:ptr+4])[0]
            ptr += 4
            if ext_type == 0x0000:  # SNI
                # SNI structure: list_length(2) name_type(1) name_len(2) name_bytes
                if ptr + 2 > len(data): return None
                list_len = struct.unpack("!H", data[ptr:ptr+2])[0]
                ptr += 2
                # read first name
                if ptr + 3 > len(data): return None
                name_type = data[ptr]
                name_len = struct.unpack("!H", data[ptr+1:ptr+3])[0]
                ptr += 3
                if ptr + name_len > len(data): return None
                sni = data[ptr:ptr+name_len].decode("utf-8", errors="ignore")
                return sni
            else:
                ptr += ext_len
        return None
    except Exception:
        return None

# ---------- Main packet parsing entrypoint ----------

def parse_packet(pkt) -> Dict[str, Any]:
    """
    Parse a scapy packet and return a dictionary with keys:
      - 'summary': short text summary
      - 'eth': {src,dst,type} if present
      - 'ip': {...} IPv4/IPv6 info
      - 'transport': {proto, sport, dport}
      - 'protocol': top-level protocol string
      - 'length': int
      - 'time': pkt.time (if available)
      - 'payload_bytes': raw payload bytes (if any)
      - 'http': dict or None
      - 'dns': dict or None
      - 'tls_sni': str or None
      - 'hex': hex dump of payload
    """
    info: Dict[str, Any] = {
        "summary": "",
        "eth": None,
        "ip": None,
        "transport": None,
        "protocol": None,
        "length": None,
        "time": _safe_getattr(pkt, "time", None),
        "payload_bytes": b"",
        "http": None,
        "dns": None,
        "tls_sni": None,
        "hex": ""
    }

    try:
        # Ethernet
        if Ether in pkt:
            eth = pkt[Ether]
            info["eth"] = {"src": _safe_getattr(eth, "src", None), "dst": _safe_getattr(eth, "dst", None),
                           "type": _safe_getattr(eth, "type", None)}

        # IPv4 / IPv6
        ip_layer = None
        if IP in pkt:
            ip_layer = pkt[IP]
            info["ip"] = {"version": 4, "src": ip_layer.src, "dst": ip_layer.dst}
        elif IPv6 in pkt:
            ip_layer = pkt[IPv6]
            info["ip"] = {"version": 6, "src": ip_layer.src, "dst": ip_layer.dst}

        # Transport
        transport = None
        payload_bytes = b""
        proto_name = None
        sport = None; dport = None

        if TCP in pkt:
            tcp = pkt[TCP]
            transport = {"proto": "TCP", "sport": tcp.sport, "dport": tcp.dport, "flags": tcp.flags}
            proto_name = "TCP"
            sport = tcp.sport; dport = tcp.dport
            if Raw in pkt:
                payload_bytes = bytes(pkt[Raw].load)
        elif UDP in pkt:
            udp = pkt[UDP]
            transport = {"proto": "UDP", "sport": udp.sport, "dport": udp.dport}
            proto_name = "UDP"
            sport = udp.sport; dport = udp.dport
            if Raw in pkt:
                payload_bytes = bytes(pkt[Raw].load)
        elif ICMP in pkt:
            proto_name = "ICMP"
            # include raw bytes of icmp
            if Raw in pkt:
                payload_bytes = bytes(pkt[Raw].load)
        elif ARP in pkt:
            proto_name = "ARP"
        else:
            # fallback: try Raw
            if Raw in pkt:
                payload_bytes = bytes(pkt[Raw].load)

        info["transport"] = transport
        info["payload_bytes"] = payload_bytes
        info["protocol"] = proto_name or "OTHER"
        info["length"] = len(payload_bytes) if payload_bytes else _safe_getattr(pkt, "len", None)

        # Try to parse DNS if UDP/TCP and DNS layer present
        try:
            dns_info = parse_dns_from_scapy(pkt)
            if dns_info:
                info["dns"] = dns_info
        except Exception:
            pass

        # Try HTTP parsing if payload looks like HTTP or port 80/8080 etc.
        try:
            # Quick heuristic: port 80/8080 or payload starting with HTTP methods/HTTP/
            if payload_bytes:
                if (sport in (80, 8080, 8000) or dport in (80, 8080, 8000) or
                        payload_bytes.startswith(b"GET ") or payload_bytes.startswith(b"POST ") or payload_bytes.startswith(b"HTTP/")):
                    info["http"] = parse_http_from_bytes(payload_bytes)
        except Exception:
            pass

        # TLS SNI extraction heuristic (client hello)
        try:
            if payload_bytes and (sport == 443 or dport == 443 or proto_name == "TCP"):
                sni = extract_tls_sni_from_bytes(payload_bytes)
                if sni:
                    info["tls_sni"] = sni
        except Exception:
            pass

        # Basic summary
        parts = []
        if info["ip"]:
            parts.append(f"{info['ip'].get('src')} -> {info['ip'].get('dst')}")
        if transport:
            parts.append(f"{transport.get('proto')}:{transport.get('sport')}->{transport.get('dport')}")
        if info.get("http"):
            http = info["http"]
            if http.get("type") == "request":
                parts.append(f"HTTP {http.get('method')} {http.get('uri')}")
            else:
                parts.append(f"HTTP {http.get('status')}")
        elif info.get("dns"):
            parts.append("DNS")
        elif info.get("tls_sni"):
            parts.append(f"TLS SNI: {info.get('tls_sni')}")
        else:
            if proto_name:
                parts.append(proto_name)

        info["summary"] = " | ".join([p for p in parts if p])

        # hex dump preview (first 512 bytes)
        info["hex"] = hex_dump(payload_bytes[:512])

    except Exception as e:
        # Minimal fallback summary on error
        info["summary"] = f"Error parsing packet: {e}"

    return info
