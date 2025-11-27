# core/decoder.py
"""
Decoder module
- Fournit decode_packet(pkt) -> dict avec métadonnées et infos lisibles
- Heuristiques pour HTTP, DNS, TLS SNI extraction
- Hooks simples pour appeler des parseurs externes (core.protocols.*)
"""

from typing import Optional, Dict, Any
import time
import re

from scapy.all import (
    Ether, IP, IPv6, TCP, UDP, ICMP, Raw, ARP,
    DNS, DNSQR, DNSRR
)

# Try to import optional protocol parsers if present
try:
    from core.protocols import http as http_parser  # type: ignore
except Exception:
    http_parser = None  # optional

try:
    from core import tls_decrypt as tls_decryptor  # type: ignore
except Exception:
    tls_decryptor = None

_TLS_SNI_RE = re.compile(
    # Very small, tolerant regex to find SNI in TLS ClientHello bytes.
    b'\x00\x16\x03[\x00-\x03].{1,2000}?\x00\x00\x00'  # record/header-ish then extension area
)

def safe_get_pkt_len(pkt) -> int:
    try:
        return len(bytes(pkt))
    except Exception:
        try:
            return int(getattr(pkt, "len", 0))
        except Exception:
            return 0


def extract_sni_from_tls_bytes(data: bytes) -> Optional[str]:
    """
    Try to extract SNI (Server Name Indication) from a TLS ClientHello raw bytes.
    This is heuristic and not perfect; better decryption should use tls_decryptor with SSLKEYLOG.
    """
    if not data or len(data) < 5:
        return None
    try:
        # look for 0x00 0x00 (name length) pattern or 'server_name' bytes - quick heuristic
        # Better approach: parse TLS handshake properly. For speed we do regex search for typical SNI layout.
        # Search for substring 0x00 (extension type name) 0x00 <len> <name...>
        # We'll attempt a more permissive search:
        # Find b'\x00\x00' followed by non-null bytes up to 255 length
        m = re.search(b'\x00\x00\x00[\x00-\xff]{1,255}', data)
        if m:
            candidate = m.group(0)
            # drop the first 3 bytes (two zeros + length) and strip zeros
            s = candidate[3:].split(b'\x00')[0]
            try:
                return s.decode('utf-8', errors='ignore')
            except Exception:
                return None

        # Fallback: search for ascii hostnames in the blob (e.g., example.com)
        ascii_hits = re.findall(b'([a-z0-9\\-]+\\.(?:com|net|org|io|local|dev|lan|edu|gov))', data, flags=re.IGNORECASE)
        if ascii_hits:
            try:
                return ascii_hits[0].decode('utf-8', errors='ignore')
            except Exception:
                return None
    except Exception:
        return None
    return None


def parse_http_from_payload(payload: bytes) -> Optional[Dict[str, Any]]:
    """
    Heuristic HTTP parser (for plaintext HTTP payloads).
    Returns dict with method, path, headers (dict), first_line (string), body (bytes)
    """
    if not payload:
        return None
    try:
        txt = payload.decode('utf-8', errors='ignore')
    except Exception:
        return None

    lines = txt.splitlines()
    if not lines:
        return None

    first = lines[0].strip()
    if not (first.startswith("GET") or first.startswith("POST") or first.startswith("PUT")
            or first.startswith("HTTP/") or first.startswith("HEAD") or first.startswith("OPTIONS")
            or first.startswith("DELETE") or first.startswith("PATCH")):
        return None

    headers = {}
    body = b""
    # find blank line separator
    try:
        sep_index = txt.index("\r\n\r\n")
        header_block = txt[:sep_index]
        body_raw = payload[sep_index + 4:]
    except ValueError:
        # try only \n\n
        try:
            sep_index = txt.index("\n\n")
            header_block = txt[:sep_index]
            body_raw = payload[sep_index + 2:]
        except ValueError:
            header_block = txt
            body_raw = b""

    for i, ln in enumerate(header_block.splitlines()[1:]):
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip()] = v.strip()

    method = None
    path = None
    proto = None
    parts = first.split()
    if len(parts) >= 1:
        method = parts[0]
    if len(parts) >= 2:
        path = parts[1]
    if len(parts) >= 3:
        proto = parts[2]

    return {
        "first_line": first,
        "method": method,
        "path": path,
        "proto": proto,
        "headers": headers,
        "body": body_raw
    }


def parse_dns(pkt) -> Optional[Dict[str, Any]]:
    """
    Parse DNS layer using Scapy DNS fields if present.
    """
    try:
        if DNS not in pkt:
            return None
        dns = pkt[DNS]
        qname = None
        qtype = None
        answers = []
        if hasattr(dns, "qd") and dns.qd is not None:
            q = dns.qd
            if isinstance(q, DNSQR):
                qname = q.qname.decode() if isinstance(q.qname, bytes) else str(q.qname)
                qtype = q.qtype
        # answers parsing
        if hasattr(dns, "an") and dns.an is not None:
            # scapy can chain multiple answers
            ans = dns.an
            # if it's a list-like
            try:
                for rr in ans:
                    rname = getattr(rr, "rrname", None)
                    rdata = getattr(rr, "rdata", None)
                    answers.append((rname.decode() if isinstance(rname, bytes) else rname, rdata))
            except TypeError:
                # single answer
                rname = getattr(ans, "rrname", None)
                rdata = getattr(ans, "rdata", None)
                answers.append((rname, rdata))
        return {"qname": qname, "qtype": qtype, "answers": answers}
    except Exception:
        return None


def decode_packet(pkt) -> Dict[str, Any]:
    """
    Decode a Scapy packet into a structured dictionary:
    {
        'timestamp': float,
        'len': int,
        'layers': [...],
        'eth': {...} optional,
        'ip': {...} optional,
        'tcp': {...} optional,
        'udp': {...} optional,
        'icmp': {...} optional,
        'proto': 'TCP'|'UDP'|'ICMP'|'ARP'|'OTHER',
        'info': human readable short summary,
        'payload': bytes,
        'http': dict or None,
        'dns': dict or None,
        'sni': str or None
    }
    """
    out: Dict[str, Any] = {}
    out['timestamp'] = getattr(pkt, 'time', time.time())
    out['len'] = safe_get_pkt_len(pkt)
    out['layers'] = []

    # default values
    out['eth'] = None
    out['ip'] = None
    out['tcp'] = None
    out['udp'] = None
    out['icmp'] = None
    out['arp'] = None
    out['proto'] = 'OTHER'
    out['info'] = ''
    out['payload'] = b''
    out['http'] = None
    out['dns'] = None
    out['sni'] = None

    try:
        # Ethernet
        if Ether in pkt:
            eth = pkt[Ether]
            out['layers'].append('Ethernet')
            out['eth'] = {
                'src': eth.src,
                'dst': eth.dst,
                'type': eth.type
            }

        # ARP
        if ARP in pkt:
            a = pkt[ARP]
            out['layers'].append('ARP')
            out['arp'] = {'psrc': a.psrc, 'pdst': a.pdst, 'op': a.op}
            out['proto'] = 'ARP'
            out['info'] = f"ARP {a.op} {a.psrc} -> {a.pdst}"
            return out  # ARP has no IP/TCP

        # IPv4 / IPv6
        if IP in pkt or IPv6 in pkt:
            ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]
            out['layers'].append('IP')
            out['ip'] = {
                'src': ip_layer.src,
                'dst': ip_layer.dst,
                'ttl': getattr(ip_layer, 'ttl', None)
            }

            # ICMP
            if ICMP in pkt:
                out['layers'].append('ICMP')
                ic = pkt[ICMP]
                out['icmp'] = {'type': ic.type, 'code': ic.code}
                out['proto'] = 'ICMP'
                out['info'] = f"ICMP {ip_layer.src} -> {ip_layer.dst} type={ic.type}"
                out['payload'] = bytes(ic.payload) if Raw in ic else b''
                return out

            # TCP
            if TCP in pkt:
                tcp = pkt[TCP]
                out['layers'].append('TCP')
                out['tcp'] = {
                    'sport': tcp.sport,
                    'dport': tcp.dport,
                    'flags': str(tcp.sprintf('%TCP.flags%')),
                    'seq': getattr(tcp, 'seq', None),
                    'ack': getattr(tcp, 'ack', None)
                }
                out['proto'] = 'TCP'
                # payload bytes
                payload = bytes(tcp.payload) if Raw in tcp else b''
                out['payload'] = payload

                # basic info summary
                out['info'] = f"TCP {ip_layer.src}:{tcp.sport} -> {ip_layer.dst}:{tcp.dport} flags={out['tcp']['flags']} len={len(payload)}"

                # Try to detect HTTP (plaintext)
                http = parse_http_from_payload(payload)
                if http:
                    out['http'] = http
                    out['info'] = f"HTTP {http.get('method')} {http.get('path')}"

                # Try to detect DNS over TCP (rare) via port heuristic
                if tcp.sport == 53 or tcp.dport == 53:
                    # attempt DNS parse
                    dns = parse_dns(pkt)
                    if dns:
                        out['dns'] = dns
                        out['info'] = f"DNS {dns.get('qname')}"

                # Try to find SNI for TLS ClientHello in payload
                sni = extract_sni_from_tls_bytes(payload)
                if sni:
                    out['sni'] = sni
                    out['info'] = f"{out['info']} (SNI:{sni})"

                # if optional tls_decryptor is available, try to use it (non-blocking)
                if tls_decryptor is not None:
                    try:
                        dec = tls_decryptor.try_decrypt_tcp_packet(pkt)
                        if dec is not None:
                            # dec expected: {'plain': b'...', 'http': {...} }
                            out['payload'] = dec.get('plain', out['payload'])
                            if 'http' in dec:
                                out['http'] = dec['http']
                                out['info'] = f"HTTP (decrypted) {out['http'].get('method')} {out['http'].get('path')}"
                    except Exception:
                        # don't crash decoder if tls_decryptor fails
                        pass

                # parse TLS metadata (record version) if available in scapy TLS layer (rare)
                # else we'll leave it to pyshark in GUI TLS worker for real decryption

                return out

            # UDP
            if UDP in pkt:
                udp = pkt[UDP]
                out['layers'].append('UDP')
                out['udp'] = {'sport': udp.sport, 'dport': udp.dport}
                out['proto'] = 'UDP'
                payload = bytes(udp.payload) if Raw in udp else b''
                out['payload'] = payload
                out['info'] = f"UDP {ip_layer.src}:{udp.sport} -> {ip_layer.dst}:{udp.dport} len={len(payload)}"

                # DNS UDP
                dns = parse_dns(pkt)
                if dns:
                    out['dns'] = dns
                    out['info'] = f"DNS {dns.get('qname')}"

                # QUIC (over UDP, heuristic: port 443 & long header)
                # Quick heuristic: if dport==443 and payload resembles QUIC (header/first byte)
                if udp.dport == 443 or udp.sport == 443:
                    # mark as QUIC candidate
                    out['info'] += " (QUIC?)"

                return out

    except Exception as e:
        # catch-all to avoid crashing the caller
        out['info'] = f"Decode error: {e}"

    return out


# If run directly, quick demo using a pcap file given as argument
if __name__ == "__main__":
    import sys
    from scapy.all import rdpcap
    if len(sys.argv) < 2:
        print("Usage: python decoder.py <file.pcap>")
        sys.exit(1)

    pcap = sys.argv[1]
    pkts = rdpcap(pcap)
    for i, p in enumerate(pkts[:50], 1):
        d = decode_packet(p)
        t = time.strftime('%H:%M:%S', time.localtime(d['timestamp']))
        print(f"{i:4} {t} {d.get('proto')} {d.get('info')}")
