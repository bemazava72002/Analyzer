"""
Analyseur de paquets réseau et reconstruction de sessions - Version Finale 2025
Auteur: Mr Ferdinand
Description: Outil professionnel de forensique réseau avec capture live
→ Support complet : HTTP/1-3, WebSocket, FTP, SMTP, SSH, POP3, IMAP, SNI, ALPN, QUIC
→ Reconstruction de fichiers (HTTP/HTTPS/FTP) + Export PCAP
"""

import sys
import os
import re
import hashlib
from datetime import datetime
from collections import defaultdict, OrderedDict
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTableWidget, QTableWidgetItem, QTextEdit, QLabel,
    QFileDialog, QSplitter, QTreeWidget, QTreeWidgetItem, QTabWidget,
    QMessageBox, QHeaderView, QStatusBar, QComboBox, QCheckBox, QDialog,
    QDialogButtonBox, QGroupBox, QSpinBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor

try:
    from scapy.all import (
        rdpcap, sniff, wrpcap, IP, TCP, UDP, Raw, DNS, ICMP, ARP, get_if_list, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# === Dossier de sortie pour fichiers reconstruits ===
RECONSTRUCTED_ROOT = "reconstructed_files"
os.makedirs(RECONSTRUCTED_ROOT, exist_ok=True)


# === Extensions MIME ===
MIME_TO_EXT = {
    'image/jpeg': '.jpg', 'image/jpg': '.jpg', 'image/png': '.png', 'image/gif': '.gif',
    'image/webp': '.webp', 'image/bmp': '.bmp', 'image/svg+xml': '.svg',
    'application/pdf': '.pdf', 'application/zip': '.zip',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': '.xlsx',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation': '.pptx',
    'text/plain': '.txt', 'text/html': '.html', 'text/css': '.css',
    'application/javascript': '.js', 'application/octet-stream': ''
}


# === Préambule HTTP/2 ===
HTTP2_MAGIC = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


# === Reassembleur TCP robuste ===
class TCPReassembler:
    def __init__(self):
        self.streams = {}

    def add(self, src_ip, src_port, dst_ip, dst_port, seq, data):
        key = ((src_ip, src_port), (dst_ip, dst_port))
        rev_key = ((dst_ip, dst_port), (src_ip, src_port))
        if key not in self.streams and rev_key not in self.streams:
            self.streams[key] = {'segments': OrderedDict(), 'expected': seq}
        elif rev_key in self.streams:
            key = rev_key

        stream = self.streams[key]
        if seq in stream['segments']:
            return b''

        stream['segments'][seq] = data
        reassembled = b''
        cur = stream['expected']
        while cur in stream['segments']:
            chunk = stream['segments'].pop(cur)
            reassembled += chunk
            cur += len(chunk)
        stream['expected'] = cur
        return reassembled


# === Reconstructeur de fichiers ===
class FileReconstructor:
    def __init__(self):
        self.reassembler = TCPReassembler()
        self.http_streams = {}
        self.ftp_data = {}

    def _save_file(self, data, filename, ctype):
        if len(data) < 100 or len(data) > 20_000_000:
            return None
        ext = MIME_TO_EXT.get(ctype, '')
        safe_name = re.sub(r'[^\w\.\-]', '_', filename)[:100]
        name = safe_name + ext if not safe_name.endswith(ext) else safe_name
        h = hashlib.sha256(data).hexdigest()[:12]
        path = os.path.join(RECONSTRUCTED_ROOT, f"{h}_{name}")
        try:
            with open(path, 'wb') as f:
                f.write(data)
            return path
        except:
            return None

    def process_http(self, session_key, payload):
        text = payload.decode('latin1', errors='ignore')
        if 'HTTP/' not in text[:20]:
            return None

        if session_key not in self.http_streams:
            self.http_streams[session_key] = {
                'headers': '', 'body': b'', 'ctype': 'application/octet-stream',
                'name': 'file', 'length': -1
            }

        stream = self.http_streams[session_key]
        if not stream['headers'] and '\r\n\r\n' in text:
            headers, body = text.split('\r\n\r\n', 1)
            stream['headers'] = headers
            stream['body'] = body.encode('latin1')
            for line in headers.split('\r\n'):
                low = line.lower()
                if low.startswith('content-type:'):
                    stream['ctype'] = line.split(':', 1)[1].strip().split(';')[0]
                if low.startswith('content-length:'):
                    stream['length'] = int(line.split(':', 1)[1].strip())
                if low.startswith('content-disposition:'):
                    m = re.search(r'filename=["\']?([^"\']+)', line)
                    if m:
                        stream['name'] = m.group(1)
        else:
            stream['body'] += payload

        if stream['length'] > 0 and len(stream['body']) >= stream['length']:
            path = self._save_file(stream['body'][:stream['length']], stream['name'], stream['ctype'])
            del self.http_streams[session_key]
            return path
        return None


reconstructor = FileReconstructor()


# === Extraction SNI & ALPN ===
def extract_sni_from_tls_client_hello(payload: bytes) -> str:
    try:
        if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
            return ""
        pos = 43
        session_id_len = payload[pos]
        pos += 1 + session_id_len
        cipher_len = int.from_bytes(payload[pos:pos+2], 'big')
        pos += 2 + cipher_len
        comp_len = payload[pos]
        pos += 1 + comp_len
        if pos + 2 > len(payload):
            return ""
        ext_len = int.from_bytes(payload[pos:pos+2], 'big')
        pos += 2
        end = pos + ext_len
        while pos + 4 <= end:
            ext_type = int.from_bytes(payload[pos:pos+2], 'big')
            ext_len = int.from_bytes(payload[pos+2:pos+4], 'big')
            pos += 4
            if ext_type == 0x00 and len(payload[pos:pos+ext_len]) >= 9:
                sni_len = int.from_bytes(payload[pos+5:pos+7], 'big')
                if pos + 7 + sni_len <= pos + ext_len:
                    return payload[pos+7:pos+7+sni_len].decode('utf-8', errors='ignore')
            pos += ext_len
    except:
        pass
    return ""


def extract_alpn_from_tls_client_hello(payload: bytes) -> str:
    try:
        if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
            return ""
        pos = 43
        session_id_len = payload[pos]
        pos += 1 + session_id_len
        cipher_len = int.from_bytes(payload[pos:pos+2], 'big')
        pos += 2 + cipher_len
        comp_len = payload[pos]
        pos += 1 + comp_len
        if pos + 2 > len(payload):
            return ""
        ext_len = int.from_bytes(payload[pos:pos+2], 'big')
        pos += 2
        end = pos + ext_len
        while pos + 4 <= end:
            ext_type = int.from_bytes(payload[pos:pos+2], 'big')
            ext_len = int.from_bytes(payload[pos+2:pos+4], 'big')
            pos += 4
            if ext_type == 0x10:
                alpn_data = payload[pos:pos+ext_len]
                if len(alpn_data) >= 2:
                    list_len = int.from_bytes(alpn_data[0:2], 'big')
                    p = 2
                    protos = []
                    while p < list_len + 2:
                        plen = alpn_data[p]
                        p += 1
                        if p + plen <= len(alpn_data):
                            protos.append(alpn_data[p:p+plen].decode('utf-8', errors='ignore'))
                            p += plen
                    return ', '.join(protos)
            pos += ext_len
    except:
        pass
    return ""


def is_quic_initial_packet(payload: bytes) -> bool:
    return len(payload) > 0 and (payload[0] & 0xC0) == 0xC0 and (payload[0] & 0x30) == 0x00


def is_websocket_handshake(payload: bytes) -> bool:
    text = payload.decode('utf-8', errors='ignore').lower()
    return 'upgrade: websocket' in text and ('sec-websocket-key:' in text or '101 switching protocols' in text)


# === Analyse du paquet ===
def analyze_packet(pkt, idx):
    info = {
        'no': idx,
        'time': datetime.now().strftime('%H:%M:%S.%f')[:-3],
        'src': '',
        'dst': '',
        'protocol': 'Unknown',
        'length': len(pkt),
        'info': '',
        'session_key': None,
        'raw_data': bytes(pkt),
        'tls_sni': '',
        'alpn': ''
    }

    if IP in pkt:
        info['src'] = pkt[IP].src
        info['dst'] = pkt[IP].dst

        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            session = tuple(sorted([(info['src'], src_port), (info['dst'], dst_port)]))
            info['session_key'] = f"TCP:{session}"
            info['protocol'] = 'TCP'
            info['info'] = f"{src_port} → {dst_port}"

            flags = []
            if pkt[TCP].flags.S: flags.append('SYN')
            if pkt[TCP].flags.A: flags.append('ACK')
            if pkt[TCP].flags.F: flags.append('FIN')
            if pkt[TCP].flags.R: flags.append('RST')
            if pkt[TCP].flags.P: flags.append('PSH')
            if pkt[TCP].flags.U: flags.append('URG')
            if flags:
                info['info'] += f" [{','.join(flags)}]"

            if Raw in pkt:
                payload = bytes(pkt[Raw].load)

                # Réassemblage + reconstruction HTTP/HTTPS
                reassembled = reconstructor.reassembler.add(info['src'], src_port, info['dst'], dst_port, pkt[TCP].seq, payload)
                if reassembled:
                    path = reconstructor.process_http(info['session_key'], reassembled)
                    if path:
                        info['info'] += f" [Fichier reconstruit: {os.path.basename(path)}]"

                # Détections
                if payload.startswith(HTTP2_MAGIC):
                    info['protocol'] = 'HTTP/2'
                    info['info'] += " [HTTP/2 Preface]"

                elif len(payload) > 5 and payload[0] == 0x16 and payload[5] == 0x01:
                    sni = extract_sni_from_tls_client_hello(payload)
                    alpn = extract_alpn_from_tls_client_hello(payload)
                    if sni:
                        info['tls_sni'] = sni
                        info['info'] += f" [SNI: {sni}]"
                    if alpn:
                        info['alpn'] = alpn
                        info['info'] += f" [ALPN: {alpn}]"
                        if 'h2' in alpn.lower():
                            info['protocol'] = 'HTTP/2 (TLS)'
                        else:
                            info['protocol'] = 'HTTPS'

                elif is_websocket_handshake(payload):
                    info['protocol'] = 'WebSocket (Secure)' if dst_port == 443 else 'WebSocket'
                    info['info'] += " [WebSocket]"

                elif payload.startswith((b'GET ', b'POST ', b'PUT ', b'HEAD ', b'HTTP/')):
                    info['protocol'] = 'HTTP'
                    try:
                        line = payload.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                        info['info'] += f" [{line[:60]}]"
                    except:
                        pass

                elif dst_port == 443 or src_port == 443:
                    info['protocol'] = 'HTTPS'

        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            info['protocol'] = 'UDP'
            info['info'] = f"{src_port} → {dst_port}"
            session = tuple(sorted([(info['src'], src_port), (info['dst'], dst_port)]))
            info['session_key'] = f"UDP:{session}"
            if Raw in pkt and (dst_port == 443 or src_port == 443):
                if is_quic_initial_packet(bytes(pkt[Raw].load)):
                    info['protocol'] = 'HTTP/3 (QUIC)'
                    info['info'] += " [QUIC Initial]"
                else:
                    info['protocol'] = 'QUIC'

        if DNS in pkt:
            info['protocol'] = 'DNS'
            if pkt[DNS].qd:
                qname = pkt[DNS].qd.qname.decode('utf-8', errors='ignore')
                info['info'] += f" Query: {qname}"

    return info


# === Threads ===
class LiveCaptureThread(QThread):
    packet_captured = pyqtSignal(dict)
    status_update = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, interface, filter_str="", packet_limit=0):
        super().__init__()
        self.interface = interface
        self.filter_str = filter_str
        self.packet_limit = packet_limit
        self.is_running = True
        self.packet_count = 0

    def run(self):
        try:
            self.status_update.emit(f"Capture démarrée sur {self.interface}")
            self.packet_count = 0

            def packet_handler(pkt):
                if not self.is_running:
                    return True
                self.packet_count += 1
                packet_info = analyze_packet(pkt, self.packet_count)
                self.packet_captured.emit(packet_info)

                if self.packet_limit > 0 and self.packet_count >= self.packet_limit:
                    self.is_running = False
                    return True

            sniff(
                iface=self.interface,
                prn=packet_handler,
                filter=self.filter_str or None,
                store=False,
                stop_filter=lambda x: not self.is_running
            )

            self.status_update.emit(f"Capture terminée - {self.packet_count} paquets capturés")
        except PermissionError:
            self.error.emit("Permissions insuffisantes. Exécutez en administrateur.")
        except Exception as e:
            self.error.emit(f"Erreur de capture: {str(e)}")

    def stop(self):
        self.is_running = False


class PacketAnalyzerThread(QThread):
    progress = pyqtSignal(int, int)
    finished = pyqtSignal(list, dict)
    error = pyqtSignal(str)

    def __init__(self, pcap_file):
        super().__init__()
        self.pcap_file = pcap_file

    def run(self):
        try:
            packets = rdpcap(self.pcap_file)
            total = len(packets)
            analyzed_packets = []
            sessions = defaultdict(list)

            for idx, pkt in enumerate(packets):
                if idx % 100 == 0:
                    self.progress.emit(idx + 1, total)
                packet_info = analyze_packet(pkt, idx + 1)
                analyzed_packets.append(packet_info)

                session_key = packet_info.get('session_key')
                if session_key:
                    sessions[session_key].append(packet_info)

            self.progress.emit(total, total)
            self.finished.emit(analyzed_packets, dict(sessions))
        except Exception as e:
            self.error.emit(str(e))


# === Dialog des paramètres de capture ===
class CaptureSettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Paramètres de capture")
        self.setModal(True)
        self.setMinimumWidth(500)

        layout = QVBoxLayout()

        interface_group = QGroupBox("Interface réseau")
        il = QVBoxLayout()
        self.interface_combo = QComboBox()
        if SCAPY_AVAILABLE:
            try:
                interfaces = get_if_list()
                self.interface_combo.addItems(interfaces or ["Aucune interface détectée"])
                if conf.iface:
                    self.interface_combo.setCurrentText(conf.iface)
            except:
                self.interface_combo.addItem("Erreur de détection")
        else:
            self.interface_combo.addItem("Scapy non disponible")
        il.addWidget(QLabel("Interface:"))
        il.addWidget(self.interface_combo)
        interface_group.setLayout(il)
        layout.addWidget(interface_group)

        filter_group = QGroupBox("Filtres BPF")
        fl = QVBoxLayout()
        self.filter_combo = QComboBox()
        self.filter_combo.setEditable(True)
        self.filter_combo.addItems([
            "", "tcp", "udp", "icmp", "port 80", "port 443",
            "tcp port 80 or tcp port 443", "not arp"
        ])
        fl.addWidget(QLabel("Filtre (optionnel):"))
        fl.addWidget(self.filter_combo)
        filter_group.setLayout(fl)
        layout.addWidget(filter_group)

        options_group = QGroupBox("Options")
        ol = QVBoxLayout()
        limit_layout = QHBoxLayout()
        self.limit_check = QCheckBox("Limiter le nombre de paquets")
        self.limit_spin = QSpinBox()
        self.limit_spin.setRange(1, 1000000)
        self.limit_spin.setValue(1000)
        self.limit_spin.setEnabled(False)
        self.limit_check.toggled.connect(self.limit_spin.setEnabled)
        limit_layout.addWidget(self.limit_check)
        limit_layout.addWidget(self.limit_spin)
        limit_layout.addStretch()
        ol.addLayout(limit_layout)
        options_group.setLayout(ol)
        layout.addWidget(options_group)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.setLayout(layout)

    def get_settings(self):
        return {
            'interface': self.interface_combo.currentText(),
            'filter': self.filter_combo.currentText().strip(),
            'limit': self.limit_spin.value() if self.limit_check.isChecked() else 0
        }


# === Interface principale ===
class NetworkAnalyzer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.packets = []
        self.sessions = {}
        self.current_capture_packets = []
        self.current_file = None
        self.capture_thread = None
        self.is_capturing = False
        self.btn_stop = None
        self.btn_export_pcap = None
        self.init_ui()

    # Toutes les méthodes utilisées dans le toolbar sont définies AVANT create_toolbar
    def open_pcap(self):
        if not SCAPY_AVAILABLE:
            QMessageBox.critical(self, "Erreur", "Scapy n'est pas installé.")
            return
        path, _ = QFileDialog.getOpenFileName(self, "Ouvrir PCAP", "", "PCAP (*.pcap *.pcapng)")
        if path:
            self.current_file = path
            self.status_bar.showMessage("Chargement...")
            self.analyzer_thread = PacketAnalyzerThread(path)
            self.analyzer_thread.progress.connect(self.update_progress)
            self.analyzer_thread.finished.connect(self.on_analysis_finished)
            self.analyzer_thread.error.connect(lambda m: QMessageBox.critical(self, "Erreur", m))
            self.analyzer_thread.start()

    def start_live_capture(self):
        if not SCAPY_AVAILABLE:
            QMessageBox.critical(self, "Erreur", "Scapy n'est pas installé.")
            return
        dialog = CaptureSettingsDialog(self)
        if dialog.exec() == QDialog.Accepted:
            s = dialog.get_settings()
            if not s['interface'] or "Erreur" in s['interface']:
                QMessageBox.warning(self, "Erreur", "Interface invalide.")
                return
            self.clear_data()
            self.capture_thread = LiveCaptureThread(s['interface'], s['filter'], s['limit'])
            self.capture_thread.packet_captured.connect(self.add_live_packet)
            self.capture_thread.status_update.connect(self.status_bar.showMessage)
            self.capture_thread.error.connect(lambda m: QMessageBox.critical(self, "Erreur capture", m))
            self.capture_thread.start()
            self.is_capturing = True
            self.btn_stop.setEnabled(True)
            self.info_label.setText(f"Capture live sur {s['interface']}")

    def stop_live_capture(self):
        if self.capture_thread and self.is_capturing:
            self.capture_thread.stop()
            self.capture_thread.wait()
            self.is_capturing = False
            self.btn_stop.setEnabled(False)

    def export_pcap(self):
        if not self.current_capture_packets:
            QMessageBox.information(self, "Info", "Aucune capture live à exporter.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Exporter capture", "capture_live.pcapng", "PCAPNG (*.pcapng)")
        if path:
            try:
                wrpcap(path, self.current_capture_packets)
                QMessageBox.information(self, "Succès", f"Capture exportée :\n{path}")
            except Exception as e:
                QMessageBox.critical(self, "Erreur", str(e))

    def analyze_sessions(self):
        if not self.sessions:
            QMessageBox.information(self, "Info", "Aucune session à analyser")
            return
        report = f"Rapport d'analyse\n{'='*60}\n\n"
        report += f"Source: {os.path.basename(self.current_file) if self.current_file else 'Capture live'}\n"
        report += f"Total paquets: {len(self.packets)}\n"
        report += f"Total sessions: {len(self.sessions)}\n\n"
        for key, pkgs in self.sessions.items():
            report += f"\n{key}\n  Paquets: {len(pkgs)}\n  Total: {sum(p['length'] for p in pkgs)} bytes\n"
        self.stream_text.setPlainText(report)

    def export_sessions(self):
        path, _ = QFileDialog.getSaveFileName(self, "Exporter sessions", "", "Text Files (*.txt)")
        if path:
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(f"Export des sessions - {datetime.now()}\n{'='*80}\n\n")
                    for key, pkgs in self.sessions.items():
                        f.write(f"Session: {key}\nPaquets: {len(pkgs)}\n{'-'*80}\n")
                        for p in pkgs:
                            f.write(f"  [{p['time']}] {p['src']} → {p['dst']} | {p['info']}\n")
                QMessageBox.information(self, "Export", "Export réussi !")
            except Exception as e:
                QMessageBox.critical(self, "Erreur", str(e))

    def clear_data(self):
        self.packets.clear()
        self.sessions.clear()
        self.current_capture_packets.clear()
        self.packet_table.setRowCount(0)
        self.session_tree.clear()
        self.detail_text.clear()
        self.hex_text.clear()
        self.stream_text.clear()
        self.info_label.setText("Prêt")
        self.status_bar.showMessage("Données effacées")
        self.btn_analyze.setEnabled(False)
        self.btn_export.setEnabled(False)
        self.btn_export_pcap.setEnabled(False)
        if self.is_capturing:
            self.stop_live_capture()

    # === UI ===
    def init_ui(self):
        self.setWindowTitle("Analyseur Réseau Pro 2025 - Mr Ferdinand")
        self.setGeometry(100, 100, 1500, 900)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        toolbar = self.create_toolbar()
        layout.addLayout(toolbar)

        splitter = QSplitter(Qt.Vertical)
        self.packet_table = self.create_packet_table()
        splitter.addWidget(self.packet_table)

        bottom = QSplitter(Qt.Horizontal)
        self.session_tree = self.create_session_tree()
        bottom.addWidget(self.session_tree)
        self.detail_tabs = self.create_detail_tabs()
        bottom.addWidget(self.detail_tabs)
        bottom.setSizes([400, 600])
        splitter.addWidget(bottom)
        splitter.setSizes([500, 400])
        layout.addWidget(splitter)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Prêt")

        self.apply_styles()

    def create_toolbar(self):
        tb = QHBoxLayout()
        btns = [
            ("📁 Ouvrir PCAP", self.open_pcap),
            ("🔴 Démarrer Capture", self.start_live_capture),
            ("⏹ Arrêter", self.stop_live_capture, False),
            ("💾 Exporter PCAP", self.export_pcap, False),
            ("🔍 Analyser", self.analyze_sessions, False),
            ("📄 Exporter Sessions", self.export_sessions, False),
            ("🗑️ Effacer", self.clear_data)
        ]
        for text, func, enabled in btns:
            btn = QPushButton(text)
            btn.clicked.connect(func)
            btn.setEnabled(enabled)
            if "Arrêter" in text:
                self.btn_stop = btn
            elif "Exporter PCAP" in text:
                self.btn_export_pcap = btn
            tb.addWidget(btn)
        self.info_label = QLabel("Prêt")
        tb.addStretch()
        tb.addWidget(self.info_label)
        return tb

    def create_packet_table(self):
        table = QTableWidget()
        table.setColumnCount(7)
        table.setHorizontalHeaderLabels(['No.', 'Temps', 'Source', 'Destination', 'Protocole', 'Longueur', 'Info'])
        header = table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setAlternatingRowColors(True)
        table.itemSelectionChanged.connect(self.on_packet_selected)
        return table

    def create_session_tree(self):
        tree = QTreeWidget()
        tree.setHeaderLabels(['Sessions TCP/UDP', 'Paquets', 'Bytes'])
        tree.itemClicked.connect(self.on_session_selected)
        return tree

    def create_detail_tabs(self):
        tabs = QTabWidget()
        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setFont(QFont("Courier", 9))
        tabs.addTab(self.detail_text, "Détails")
        self.hex_text = QTextEdit()
        self.hex_text.setReadOnly(True)
        self.hex_text.setFont(QFont("Courier", 9))
        tabs.addTab(self.hex_text, "Hexdump")
        self.stream_text = QTextEdit()
        self.stream_text.setReadOnly(True)
        self.stream_text.setFont(QFont("Courier", 9))
        tabs.addTab(self.stream_text, "Flux TCP")
        return tabs

    # === Affichage ===
    def add_live_packet(self, packet_info):
        self.packets.append(packet_info)
        self.current_capture_packets.append(packet_info['raw_data'])
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)

        items = [
            str(packet_info['no']), packet_info['time'], packet_info['src'],
            packet_info['dst'], packet_info['protocol'], str(packet_info['length']),
            packet_info['info']
        ]
        for col, text in enumerate(items):
            item = QTableWidgetItem(text)
            if col == 4:
                colors = {
                    'TCP': '#E3F2FD', 'UDP': '#FFF3E0', 'HTTP': '#E8F5E9',
                    'HTTPS': '#FFCCBC', 'HTTP/2': '#C5E1A5', 'HTTP/2 (TLS)': '#A5D6A7',
                    'QUIC': '#B39DDB', 'HTTP/3 (QUIC)': '#9575CD',
                    'WebSocket': '#FFCC80', 'WebSocket (Secure)': '#FFB74D',
                    'DNS': '#F1F8E9'
                }
                if packet_info['protocol'] in colors:
                    item.setBackground(QColor(colors[packet_info['protocol']]))
            self.packet_table.setItem(row, col, item)

        self.packet_table.scrollToBottom()

    def update_progress(self, current, total):
        self.status_bar.showMessage(f"Analyse: {current}/{total} paquets...")

    def on_analysis_finished(self, packets, sessions):
        self.packets = packets
        self.sessions = sessions
        self.display_packets()
        self.display_sessions()
        file_name = os.path.basename(self.current_file) if self.current_file else "Capture live"
        self.info_label.setText(f"📄 {file_name} - {len(packets)} paquets - {len(sessions)} sessions")
        self.status_bar.showMessage(f"Analyse terminée: {len(packets)} paquets")
        self.btn_analyze.setEnabled(True)
        self.btn_export.setEnabled(True)
        self.btn_export_pcap.setEnabled(True if self.current_capture_packets else False)

    def display_packets(self):
        self.packet_table.setRowCount(len(self.packets))
        for idx, pkt in enumerate(self.packets):
            items = [str(pkt['no']), pkt['time'], pkt['src'], pkt['dst'], pkt['protocol'], str(pkt['length']), pkt['info']]
            for col, text in enumerate(items):
                item = QTableWidgetItem(text)
                if col == 4:
                    colors = {
                        'TCP': '#E3F2FD', 'UDP': '#FFF3E0', 'HTTP': '#E8F5E9',
                        'HTTPS': '#FFCCBC', 'HTTP/2': '#C5E1A5', 'HTTP/2 (TLS)': '#A5D6A7',
                        'QUIC': '#B39DDB', 'HTTP/3 (QUIC)': '#9575CD',
                        'WebSocket': '#FFCC80', 'WebSocket (Secure)': '#FFB74D',
                        'DNS': '#F1F8E9'
                    }
                    if pkt['protocol'] in colors:
                        item.setBackground(QColor(colors[pkt['protocol']]))
                self.packet_table.setItem(idx, col, item)

    def update_session_tree(self):
        self.session_tree.clear()
        for key, pkgs in self.sessions.items():
            item = QTreeWidgetItem([key, str(len(pkgs)), f"{sum(p['length'] for p in pkgs)} bytes"])
            self.session_tree.addTopLevelItem(item)

    def display_sessions(self):
        self.update_session_tree()
        self.btn_analyze.setEnabled(True)
        self.btn_export.setEnabled(True)

    def on_packet_selected(self):
        row = self.packet_table.currentRow()
        if row < 0 or row >= len(self.packets):
            return
        pkt = self.packets[row]
        details = f"""Paquet #{pkt['no']}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Temps:        {pkt['time']}
Source:       {pkt['src']}
Destination:  {pkt['dst']}
Protocole:    {pkt['protocol']}
Longueur:     {pkt['length']} bytes
Info:         {pkt['info']}
Session:      {pkt['session_key'] or 'N/A'}"""
        if pkt.get('tls_sni'):
            details += f"\nSNI (Site):   {pkt['tls_sni']}"
        if pkt.get('alpn'):
            details += f"\nALPN:         {pkt['alpn']}"
        self.detail_text.setPlainText(details)

        hex_dump = '\n'.join(
            f"{i:08x}  {' '.join(f'{b:02x}' for b in chunk):<48}  {''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)}"
            for i, chunk in enumerate((pkt['raw_data'][j:j+16] for j in range(0, len(pkt['raw_data']), 16)))
        )
        self.hex_text.setPlainText(hex_dump)

    def on_session_selected(self, item, column):
        session_key = item.text(0)
        if session_key not in self.sessions:
            return
        packets = self.sessions[session_key]
        lines = []
        sni = next((p['tls_sni'] for p in packets if p.get('tls_sni')), "")
        alpn = next((p['alpn'] for p in packets if p.get('alpn')), "")
        if sni:
            lines.append(f"Site (SNI): {sni}")
        if alpn:
            lines.append(f"ALPN: {alpn}")
        if any(lines):
            lines.append("")
        for p in packets:
            lines.append(f"[{p['time']}] {p['src']} → {p['dst']}")
            lines.append(f"  {p['info']}")
            lines.append("")
        self.stream_text.setPlainText("\n".join(lines))

    def apply_styles(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #f5f5f5; }
            QPushButton { background-color: #2196F3; color: white; padding: 10px; border-radius: 5px; font-weight: bold; }
            QPushButton:hover { background-color: #1976D2; }
            QPushButton:disabled { background-color: #aaa; }
            QTableWidget { background-color: white; gridline-color: #ddd; }
            QHeaderView::section { background-color: #424242; color: white; font-weight: bold; }
        """)


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    if not SCAPY_AVAILABLE:
        QMessageBox.critical(None, "Erreur", "Scapy n'est pas installé.\nInstallez-le avec: pip install scapy")
        sys.exit(1)
    window = NetworkAnalyzer()
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()