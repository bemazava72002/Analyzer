# core/tcp_reassembly.py
from collections import defaultdict, OrderedDict
import threading

class TCPReassembly:
    """
    Reassemble TCP streams based on sequence numbers.
    Handles:
      - out-of-order packets
      - retransmissions
      - overlapping segments
      - stream gaps
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.streams = defaultdict(lambda: {
            "segments": OrderedDict(),
            "base_seq": None,
        })

    def _flow_id(self, pkt):
        """Returns a unique flow id (5-tuple)"""
        return (
            pkt[0][1].src,
            pkt[0][2].sport,
            pkt[0][1].dst,
            pkt[0][2].dport,
            "TCP"
        )

    def add_packet(self, pkt):
        """Add a TCP packet into a stream"""
        if "TCP" not in pkt:
            return None

        if "Raw" not in pkt:
            return None

        flow = self._flow_id(pkt)

        seq = pkt["TCP"].seq
        payload = bytes(pkt["Raw"].load)

        with self.lock:
            stream = self.streams[flow]

            # base sequence number
            if stream["base_seq"] is None:
                stream["base_seq"] = seq

            rel_seq = seq - stream["base_seq"]

            # retransmission or duplicate?
            if rel_seq in stream["segments"]:
                # If retransmission has bigger data, update
                if len(payload) > len(stream["segments"][rel_seq]):
                    stream["segments"][rel_seq] = payload
            else:
                # Normal new segment
                stream["segments"][rel_seq] = payload

        return flow

    def get_stream(self, flow):
        """Returns the fully reassembled TCP byte stream"""
        with self.lock:
            if flow not in self.streams:
                return b""

            segments = self.streams[flow]["segments"]
            output = bytearray()

            # reassemble by sorted sequence
            for seq in sorted(segments.keys()):
                seg = segments[seq]

                end = seq + len(seg)
                if len(output) < seq:
                    # missing segment → gap (Wireshark shows it too)
                    gap_size = seq - len(output)
                    output.extend(b"\x00" * gap_size)

                if end > len(output):
                    output.extend(seg[len(output)-seq:])

            return bytes(output)
