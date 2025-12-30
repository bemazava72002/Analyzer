# # capture_backend.py (version C)
# import threading
# from scapy.all import sniff, rdpcap, PcapWriter, IP, TCP, UDP, Raw
# from scapy.error import Scapy_Exception

# class PacketCapture:
#     def __init__(self, iface=None, bpf_filter=None, promisc=True, autosave_path=None, max_bytes=None):
#         self.iface = iface
#         self.bpf_filter = bpf_filter
#         self.promisc = promisc
#         self.running = False
#         self._thread = None
#         self._packet_cb = None
#         self._err_cb = None
#         self.autosave_path = autosave_path
#         self.max_bytes = max_bytes
#         self._autosave = None
#         self._saved_bytes = 0

#     def start_live(self, packet_callback, error_callback=None):
#         self._packet_cb = packet_callback
#         self._err_cb = error_callback
#         self.running = True
#         if self.autosave_path:
#             self._autosave = PcapWriter(self.autosave_path, append=True, sync=True)
#             self._saved_bytes = 0
#         self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
#         self._thread.start()

#     def stop(self):
#         self.running = False
#         if self._autosave:
#             try: self._autosave.close()
#             except Exception: pass

#     def read_pcap(self, path, packet_callback, error_callback=None):
#         self._packet_cb = packet_callback
#         self._err_cb = error_callback
#         try:
#             pkts = rdpcap(path)
#             for pkt in pkts:
#                 if self._packet_cb: self._packet_cb(pkt)
#         except Exception as e:
#             if self._err_cb: self._err_cb(f"Failed to read pcap: {e}")

#     def _sniff_loop(self):
#         from scapy.all import sniff
#         try:
#             def prn(pkt):
#                 if not self.running: return False
#                 if self._packet_cb: self._packet_cb(pkt)
#                 if self._autosave:
#                     try:
#                         self._autosave.write(pkt)
#                         self._saved_bytes += len(bytes(pkt))
#                         if self.max_bytes and self._saved_bytes >= self.max_bytes:
#                             self.running = False
#                             return False
#                     except Exception:
#                         if self._err_cb: self._err_cb("Autosave error while writing packet.")
#             sniff(iface=self.iface if self.iface else None,
#                   filter=self.bpf_filter if self.bpf_filter else None,
#                   prn=prn, store=0, promisc=self.promisc,
#                   stop_filter=lambda x: not self.running)
#         except Scapy_Exception as e:
#             if self._err_cb: self._err_cb(f"Scapy filter error: {e}")
#         except Exception as e:
#             if self._err_cb: self._err_cb(f"Capture init error: {e}")


# backend/capture_backend.py
# 
# capture_backend.py



import threading
from scapy.all import sniff, rdpcap, PcapWriter, get_if_list
from scapy.error import Scapy_Exception

class PacketCapture:
    """Capture de paquets live ou depuis fichier pcap, avec auto-save."""

    def __init__(self, iface=None, bpf_filter=None, promisc=True, autosave_path=None, max_bytes=None):
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.promisc = promisc
        self.running = False
        self._thread = None
        self._packet_cb = None
        self._err_cb = None
        self.autosave_path = autosave_path
        self.max_bytes = max_bytes
        self._saved_bytes = 0
        self._autosave = None

    def start_live(self, packet_callback, error_callback=None):
        self._packet_cb = packet_callback
        self._err_cb = error_callback
        self.running = True
        if self.autosave_path:
            self._autosave = PcapWriter(self.autosave_path, append=True, sync=True)
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False
        if self._autosave:
            try:
                self._autosave.close()
            except:
                pass

    def _sniff_loop(self):
        try:
            if self.iface and self.iface not in get_if_list():
                raise ValueError(f"Interface '{self.iface}' not found.")

            def prn(pkt):
                if not self.running:
                    return False
                if self._packet_cb:
                    self._packet_cb(pkt)
                if self._autosave:
                    try:
                        self._autosave.write(pkt)
                        self._saved_bytes += len(bytes(pkt))
                        if self.max_bytes and self._saved_bytes >= self.max_bytes:
                            self.running = False
                            return False
                    except Exception:
                        if self._err_cb:
                            self._err_cb("Autosave error writing packet.")
                return None

            sniff(iface=self.iface, filter=self.bpf_filter, prn=prn, store=0, promisc=self.promisc,
                  stop_filter=lambda x: not self.running)
        except Scapy_Exception as e:
            if self._err_cb:
                self._err_cb(f"Scapy error: {e}")
        except Exception as e:
            if self._err_cb:
                self._err_cb(str(e))

    def read_pcap(self, path, packet_callback, error_callback=None):
        self._packet_cb = packet_callback
        self._err_cb = error_callback
        try:
            pkts = rdpcap(path)
            for pkt in pkts:
                self._packet_cb(pkt)
        except Exception as e:
            if self._err_cb:
                self._err_cb(f"Failed to read pcap: {e}")
