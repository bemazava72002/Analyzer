# # flow_reconstructor.py (version C)
# from collections import defaultdict, namedtuple
# import time
# from scapy.all import IP, TCP, UDP, Raw

# FlowKey = namedtuple("FlowKey", ["proto","src","sport","dst","dport"])

# class FlowReconstructor:
#     def __init__(self):
#         self.flows = defaultdict(list)
#         self.last_seen = {}

#     def add_segment(self, key, seq, payload):
#         self.flows[key].append((seq, payload))
#         self.last_seen[key] = time.time()

#     def add_packet(self, pkt):
#         proto = None
#         if TCP in pkt: proto='TCP'
#         elif UDP in pkt: proto='UDP'
#         elif IP in pkt: proto='IP'
#         else: return None

#         ip = pkt[IP]
#         sport, dport = (0,0)
#         if TCP in pkt or UDP in pkt: sport=pkt.sport; dport=pkt.dport
#         key = FlowKey(proto, ip.src, sport, ip.dst, dport)

#         payload = bytes(pkt[Raw].load) if Raw in pkt else b""
#         seq = getattr(pkt[TCP], "seq", 0) if TCP in pkt else 0
#         if payload:
#             self.add_segment(key, seq, payload)
#         return key

#     def get_reassembled(self, key):
#         segments = self.flows.get(key, [])
#         if not segments: return b""
#         if key.proto=='TCP':
#             segments_sorted = sorted(segments, key=lambda x:x[0])
#             out=bytearray(); expected=None
#             for seq,payload in segments_sorted:
#                 if expected is None: out.extend(payload); expected=seq+len(payload)
#                 else:
#                     if seq>=expected: out.extend(payload); expected=seq+len(payload)
#                     else:
#                         overlap=expected-seq
#                         if overlap<len(payload): out.extend(payload[overlap:]); expected=seq+len(payload)
#             return bytes(out)
#         else:
#             return b"".join(p for _,p in segments)

#     def extract_http_info(self,key):
#         payload=self.get_reassembled(key)
#         try:
#             text=payload.decode("utf-8",errors="ignore")
#             lines=text.splitlines()
#             headers=[line for line in lines if line.startswith(("GET","POST","HTTP/"))]
#             return "\n".join(headers[:10])  # première dizaine de lignes HTTP
#         except:
#             return ""

#     def detect_sni(self,key):
#         payload=self.get_reassembled(key)
#         if not payload: return None
#         # TLS handshake SNI: chercher 00 16 ... SNI
#         try:
#             import re
#             sni = re.search(b'\x00\x16.*\x00\x00\x00(.*?)\x00',payload)
#             if sni: return sni.group(1).decode(errors="ignore")
#         except: return None
#         return None

#     def flows_summary(self):
#         return [(k, sum(len(p) for _,p in segs), self.last_seen.get(k)) for k,segs in self.flows.items()]

# backend/flow_reconstructor.py
# from scapy.all import IP, TCP, Raw, UDP
# flow_reconstructor_adv.py
from scapy.all import IP, TCP, UDP, Raw
from collections import defaultdict, namedtuple

FlowKey = namedtuple("FlowKey", ["src", "sport", "dst", "dport", "proto"])

class FlowReconstructorAdv:
    """Reconstruit les flux TCP/UDP et reassemble les payloads."""

    def __init__(self):
        self.flows = defaultdict(list)  # key: FlowKey -> [(seq, payload)]

    def add_packet(self, pkt):
        if IP in pkt:
            ip = pkt[IP]
            if TCP in pkt:
                tcp = pkt[TCP]
                key = FlowKey(ip.src, tcp.sport, ip.dst, tcp.dport, "TCP")
                payload = bytes(tcp.payload) if Raw in tcp else b""
                self.flows[key].append((tcp.seq, payload))
                self.flows[key].sort(key=lambda x: x[0])
                return key
            elif UDP in pkt:
                udp = pkt[UDP]
                key = FlowKey(ip.src, udp.sport, ip.dst, udp.dport, "UDP")
                payload = bytes(udp.payload) if Raw in udp else b""
                self.flows[key].append((0, payload))
                return key

    def get_reassembled(self, key):
        if key not in self.flows:
            return b""
        return b"".join([p for seq, p in self.flows[key]])

    def flows_summary(self):
        summary = []
        for k, lst in self.flows.items():
            total_bytes = sum(len(p) for seq, p in lst)
            summary.append((k, total_bytes, len(lst)))
        return summary
