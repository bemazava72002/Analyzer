"""
Analyseur de paquets réseau et reconstruction de sessions
Auteur: Mr Ferdinand
Description: Application professionnelle pour l'analyse forensique réseau avec capture live
→ Détection avancée : HTTP/1-3, WebSocket, FTP, SMTP, SSH, POP3, IMAP, SNI, ALPN, QUIC
"""

import sys
import os
from datetime import datetime
from collections import defaultdict
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
        rdpcap, sniff, IP, TCP, UDP, Raw, DNS, ICMP, ARP, get_if_list, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# Préambule HTTP/2
HTTP2_MAGIC = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


# --- Extraction SNI et ALPN ---
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
        extensions_len = int.from_bytes(payload[pos:pos+2], 'big')
        pos += 2
        end = pos + extensions_len
        while pos + 4 <= end:
            ext_type = int.from_bytes(payload[pos:pos+2], 'big')
            ext_len = int.from_bytes(payload[pos+2:pos+4], 'big')
            pos += 4
            if ext_type == 0x00:
                sni_data = payload[pos:pos+ext_len]
                if len(sni_data) >= 5:
                    name_len = int.from_bytes(sni_data[3:5], 'big')
                    if 5 + name_len <= len(sni_data):
                        return sni_data[5:5+name_len].decode('utf-8', errors='ignore')
            pos += ext_len
    except Exception:
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
        extensions_len = int.from_bytes(payload[pos:pos+2], 'big')
        pos += 2
        end = pos + extensions_len
        while pos + 4 <= end:
            ext_type = int.from_bytes(payload[pos:pos+2], 'big')
            ext_len = int.from_bytes(payload[pos+2:pos+4], 'big')
            pos += 4
            if ext_type == 0x10:
                alpn_data = payload[pos:pos+ext_len]
                if len(alpn_data) < 2:
                    continue
                list_len = int.from_bytes(alpn_data[0:2], 'big')
                alpn_pos = 2
                protocols = []
                while alpn_pos < list_len + 2 and alpn_pos < len(alpn_data):
                    proto_len = alpn_data[alpn_pos]
                    alpn_pos += 1
                    if alpn_pos + proto_len <= len(alpn_data):
                        proto = alpn_data[alpn_pos:alpn_pos + proto_len].decode('utf-8', errors='ignore')
                        protocols.append(proto)
                        alpn_pos += proto_len
                return ', '.join(protocols) if protocols else ""
            pos += ext_len
    except Exception:
        pass
    return ""


def is_quic_initial_packet(payload: bytes) -> bool:
    try:
        if len(payload) < 1:
            return False
        header_byte = payload[0]
        return (header_byte & 0xC0) == 0xC0 and (header_byte & 0x30) == 0x00
    except:
        return False


# --- Détections protocoles ---
def is_websocket_handshake(payload: bytes) -> tuple[bool, str]:
    try:
        text = payload.decode('utf-8', errors='ignore').lower()
        if 'upgrade: websocket' in text and 'sec-websocket-key:' in text:
            return True, 'client'
        if '101 switching protocols' in text and 'upgrade: websocket' in text:
            return True, 'server'
        return False, ''
    except:
        return False, ''


def detect_ftp_command(payload: bytes) -> str:
    try:
        cmd = payload.decode('ascii', errors='ignore').strip().upper()
        if cmd.startswith(('USER ', 'PASS ', 'RETR ', 'STOR ', 'LIST', 'PWD', 'CWD ', 'TYPE ', 'QUIT')):
            if cmd.startswith('PASS '):
                return "PASS ****"
            return cmd.split('\r\n')[0]
        return ""
    except:
        return ""


def detect_smtp_command(payload: bytes) -> str:
    try:
        cmd = payload.decode('ascii', errors='ignore').strip().upper()
        if cmd.startswith(('HELO ', 'EHLO ', 'MAIL FROM:', 'RCPT TO:', 'DATA', 'QUIT', 'AUTH ')):
            return cmd.split('\r\n')[0]
        return ""
    except:
        return ""


def detect_ssh_version(payload: bytes) -> str:
    try:
        text = payload.decode('ascii', errors='ignore')
        if text.startswith('SSH-'):
            return text.split('\r\n')[0].strip()
        return ""
    except:
        return ""


def detect_pop3_command(payload: bytes) -> str:
    try:
        cmd = payload.decode('ascii', errors='ignore').strip().upper()
        if cmd.startswith(('USER ', 'PASS ', 'LIST', 'RETR ', 'DELE ', 'UIDL ', 'QUIT', 'CAPA', 'STAT')):
            if cmd.startswith('PASS '):
                return "PASS ****"
            return cmd.split('\r\n')[0]
        return ""
    except:
        return ""


def detect_imap_command(payload: bytes) -> str:
    try:
        text = payload.decode('ascii', errors='ignore').strip()
        lines = text.split('\r\n')
        for line in lines:
            if line.upper().startswith(('A001 LOGIN', 'LOGIN ', 'SELECT ', 'FETCH ', 'SEARCH ', 'LIST ', 'CAPABILITY', 'LOGOUT')):
                parts = line.split(' ', 2)
                tag = parts[0]
                cmd = parts[1] if len(parts) > 1 else ""
                if cmd.upper() == 'LOGIN':
                    return f"{tag} LOGIN user ****"
                return f"{tag} {cmd} ..."
        return ""
    except:
        return ""


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
        'alpn': '',
        'is_websocket': False,
        'ftp_cmd': '',
        'smtp_cmd': '',
        'ssh_version': '',
        'pop3_cmd': '',
        'imap_cmd': ''
    }

    if ARP in pkt:
        info['protocol'] = 'ARP'
        info['src'] = pkt[ARP].psrc
        info['dst'] = pkt[ARP].pdst
        info['info'] = f"Who has {pkt[ARP].pdst}? Tell {pkt[ARP].psrc}" if pkt[ARP].op == 1 else f"{pkt[ARP].psrc} is at {pkt[ARP].hwsrc}"
        return info

    if IP in pkt:
        info['src'] = pkt[IP].src
        info['dst'] = pkt[IP].dst

        if ICMP in pkt:
            info['protocol'] = 'ICMP'
            icmp_types = {0: 'Echo Reply', 3: 'Dest Unreachable', 8: 'Echo Request', 11: 'Time Exceeded'}
            info['info'] = icmp_types.get(pkt[ICMP].type, f"Type {pkt[ICMP].type}")
            return info

        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            info['protocol'] = 'TCP'
            info['info'] = f"{src_port} → {dst_port}"

            flags = [f for f, c in [('SYN', pkt[TCP].flags.S), ('ACK', pkt[TCP].flags.A),
                                   ('FIN', pkt[TCP].flags.F), ('RST', pkt[TCP].flags.R),
                                   ('PSH', pkt[TCP].flags.P), ('URG', pkt[TCP].flags.U)] if c]
            if flags:
                info['info'] += f" [{','.join(flags)}]"

            session = tuple(sorted([(info['src'], src_port), (info['dst'], dst_port)]))
            info['session_key'] = f"TCP:{session}"

            if Raw in pkt:
                payload = bytes(pkt[Raw].load)

                # POP3 / POP3S
                if dst_port in (110, 995) or src_port in (110, 995):
                    pop3_cmd = detect_pop3_command(payload)
                    if pop3_cmd:
                        info['pop3_cmd'] = pop3_cmd
                        info['protocol'] = 'POP3' + ('S' if dst_port == 995 or src_port == 995 else '')
                        info['info'] += f" [{pop3_cmd}]"

                # IMAP / IMAPS
                elif dst_port in (143, 993) or src_port in (143, 993):
                    imap_cmd = detect_imap_command(payload)
                    if imap_cmd:
                        info['imap_cmd'] = imap_cmd
                        info['protocol'] = 'IMAP' + ('S' if dst_port == 993 or src_port == 993 else '')
                        info['info'] += f" [{imap_cmd}]"

                # FTP
                elif dst_port in (21, 20) or src_port in (21, 20):
                    ftp_cmd = detect_ftp_command(payload)
                    if ftp_cmd:
                        info['ftp_cmd'] = ftp_cmd
                        info['protocol'] = 'FTP'
                        info['info'] += f" [{ftp_cmd}]"

                # SMTP / SMTPS
                elif dst_port in (25, 587, 465) or src_port in (25, 587, 465):
                    smtp_cmd = detect_smtp_command(payload)
                    if smtp_cmd:
                        info['smtp_cmd'] = smtp_cmd
                        info['protocol'] = 'SMTP' + ('S' if dst_port == 465 or src_port == 465 else '')
                        info['info'] += f" [{smtp_cmd}]"

                # SSH
                elif dst_port == 22 or src_port == 22:
                    ssh_ver = detect_ssh_version(payload)
                    if ssh_ver:
                        info['ssh_version'] = ssh_ver
                        info['protocol'] = 'SSH'
                        info['info'] += f" [{ssh_ver}]"

                # WebSocket
                elif is_websocket_handshake(payload)[0]:
                    info['is_websocket'] = True
                    secure = (dst_port == 443 or src_port == 443)
                    info['protocol'] = 'WebSocket (Secure)' if secure else 'WebSocket'
                    info['info'] += " [WebSocket Handshake]"

                # HTTP/1.1
                elif payload.startswith((b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ', b'HTTP/')):
                    info['protocol'] = 'HTTP'
                    try:
                        first_line = payload.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                        info['info'] += f" [{first_line[:60]}]"
                    except:
                        info['info'] += " [HTTP]"

                # HTTP/2
                elif payload.startswith(HTTP2_MAGIC):
                    info['protocol'] = 'HTTP/2'
                    info['info'] += " [HTTP/2 Preface]"

                # TLS
                elif len(payload) > 5 and payload[0] == 0x16 and payload[5] == 0x01:
                    sni = extract_sni_from_tls_client_hello(payload)
                    if sni:
                        info['tls_sni'] = sni
                        info['info'] += f" [SNI: {sni}]"
                    alpn = extract_alpn_from_tls_client_hello(payload)
                    if alpn:
                        info['alpn'] = alpn
                        info['info'] += f" [ALPN: {alpn}]"
                        if 'h2' in alpn.lower():
                            info['protocol'] = 'HTTP/2 (ALPN)'
                        elif 'http/1.1' in alpn.lower():
                            info['protocol'] = 'HTTPS (HTTP/1.1)'
                    elif dst_port == 443 or src_port == 443:
                        info['protocol'] = 'HTTPS'

                elif dst_port == 443 or src_port == 443:
                    info['protocol'] = 'HTTPS'

        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            info['protocol'] = 'UDP'
            info['info'] = f"{src_port} → {dst_port}"

            session = tuple(sorted([(info['src'], src_port), (info['dst'], dst_port)]))
            info['session_key'] = f"UDP:{session}"

            if Raw in pkt:
                payload = bytes(pkt[Raw].load)
                if (dst_port == 443 or src_port == 443):
                    if is_quic_initial_packet(payload):
                        info['protocol'] = 'HTTP/3 (QUIC)'
                        info['info'] += " [QUIC Initial]"
                    else:
                        info['protocol'] = 'QUIC'
                        info['info'] += " [QUIC Data]"

            if DNS in pkt:
                info['protocol'] = 'DNS'
                if pkt[DNS].qd:
                    qname = pkt[DNS].qd.qname.decode('utf-8', errors='ignore')
                    info['info'] += f" Query: {qname}"

    return info


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
        il.addWidget(QLabel("Interface:"))
        il.addWidget(self.interface_combo)
        interface_group.setLayout(il)
        layout.addWidget(interface_group)

        filter_group = QGroupBox("Filtres BPF")
        fl = QVBoxLayout()
        self.filter_combo = QComboBox()
        self.filter_combo.setEditable(True)
        self.filter_combo.addItems(["", "tcp", "udp", "icmp", "port 80", "port 443", "tcp port 80 or tcp port 443", "not arp"])
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


class NetworkAnalyzer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.packets = []
        self.sessions = {}
        self.websocket_sessions = set()
        self.ftp_sessions = set()
        self.smtp_sessions = set()
        self.ssh_sessions = set()
        self.pop3_sessions = set()
        self.imap_sessions = set()
        self.current_file = None
        self.capture_thread = None
        self.is_capturing = False
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Analyseur Réseau Avancé - Mr Ferdinand")
        self.setGeometry(100, 100, 1400, 800)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(5, 5, 5, 5)

        toolbar = self.create_toolbar()
        main_layout.addLayout(toolbar)

        main_splitter = QSplitter(Qt.Vertical)
        self.packet_table = self.create_packet_table()
        main_splitter.addWidget(self.packet_table)

        bottom_splitter = QSplitter(Qt.Horizontal)
        self.session_tree = self.create_session_tree()
        bottom_splitter.addWidget(self.session_tree)
        self.detail_tabs = self.create_detail_tabs()
        bottom_splitter.addWidget(self.detail_tabs)
        bottom_splitter.setSizes([400, 600])

        main_splitter.addWidget(bottom_splitter)
        main_splitter.setSizes([400, 400])
        main_layout.addWidget(main_splitter)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Prêt - Chargez un PCAP ou démarrez une capture live")

        self.apply_styles()

    def create_toolbar(self):
        toolbar = QHBoxLayout()
        self.btn_open = QPushButton("📁 Ouvrir PCAP")
        self.btn_open.clicked.connect(self.open_pcap)
        self.btn_capture = QPushButton("🔴 Démarrer Capture Live")
        self.btn_capture.clicked.connect(self.start_live_capture)
        self.btn_stop = QPushButton("⏹ Arrêter Capture")
        self.btn_stop.clicked.connect(self.stop_live_capture)
        self.btn_stop.setEnabled(False)
        self.btn_analyze = QPushButton("🔍 Analyser Sessions")
        self.btn_analyze.clicked.connect(self.analyze_sessions)
        self.btn_analyze.setEnabled(False)
        self.btn_export = QPushButton("💾 Exporter")
        self.btn_export.clicked.connect(self.export_sessions)
        self.btn_export.setEnabled(False)
        self.btn_clear = QPushButton("🗑️ Effacer")
        self.btn_clear.clicked.connect(self.clear_data)
        self.info_label = QLabel("Aucun fichier chargé - Aucune capture")
        self.info_label.setStyleSheet("color: #666; font-size: 11px;")

        toolbar.addWidget(self.btn_open)
        toolbar.addWidget(self.btn_capture)
        toolbar.addWidget(self.btn_stop)
        toolbar.addWidget(self.btn_analyze)
        toolbar.addWidget(self.btn_export)
        toolbar.addWidget(self.btn_clear)
        toolbar.addStretch()
        toolbar.addWidget(self.info_label)
        return toolbar

    def create_packet_table(self):
        table = QTableWidget()
        table.setColumnCount(7)
        table.setHorizontalHeaderLabels(['No.', 'Temps', 'Source', 'Destination', 'Protocole', 'Longueur', 'Info'])
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.Stretch)
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

    def open_pcap(self):
        if not SCAPY_AVAILABLE:
            QMessageBox.critical(self, "Erreur", "Scapy n'est pas installé.")
            return
        file_path, _ = QFileDialog.getOpenFileName(self, "Ouvrir PCAP", "", "PCAP Files (*.pcap *.pcapng)")
        if file_path:
            self.current_file = file_path
            self.status_bar.showMessage("Chargement du fichier...")
            self.analyzer_thread = PacketAnalyzerThread(file_path)
            self.analyzer_thread.progress.connect(self.update_progress)
            self.analyzer_thread.finished.connect(self.on_analysis_finished)
            self.analyzer_thread.error.connect(self.on_analysis_error)
            self.analyzer_thread.start()

    def start_live_capture(self):
        if not SCAPY_AVAILABLE:
            QMessageBox.critical(self, "Erreur", "Scapy n'est pas installé.")
            return
        dialog = CaptureSettingsDialog(self)
        if dialog.exec() == QDialog.Accepted:
            settings = dialog.get_settings()
            interface = settings['interface']
            if not interface or "Erreur" in interface:
                QMessageBox.warning(self, "Erreur", "Interface invalide.")
                return
            self.clear_data()
            self.capture_thread = LiveCaptureThread(
                interface=interface,
                filter_str=settings['filter'],
                packet_limit=settings['limit']
            )
            self.capture_thread.packet_captured.connect(self.add_live_packet)
            self.capture_thread.status_update.connect(self.status_bar.showMessage)
            self.capture_thread.error.connect(lambda msg: QMessageBox.critical(self, "Erreur capture", msg))
            self.capture_thread.start()
            self.is_capturing = True
            self.btn_capture.setEnabled(False)
            self.btn_stop.setEnabled(True)
            self.info_label.setText(f"Capture live sur {interface}")

    def stop_live_capture(self):
        if self.capture_thread and self.is_capturing:
            self.capture_thread.stop()
            self.capture_thread.wait()
            self.is_capturing = False
            self.btn_capture.setEnabled(True)
            self.btn_stop.setEnabled(False)

    def add_live_packet(self, packet_info):
        self.packets.append(packet_info)
        row = len(self.packets) - 1
        self.packet_table.insertRow(row)
        self.packet_table.setItem(row, 0, QTableWidgetItem(str(packet_info['no'])))
        self.packet_table.setItem(row, 1, QTableWidgetItem(packet_info['time']))
        self.packet_table.setItem(row, 2, QTableWidgetItem(packet_info['src']))
        self.packet_table.setItem(row, 3, QTableWidgetItem(packet_info['dst']))

        proto_item = QTableWidgetItem(packet_info['protocol'])
        colors = {
            'TCP': '#E3F2FD', 'UDP': '#FFF3E0', 'HTTP': '#E8F5E9',
            'HTTPS': '#FFCCBC', 'HTTP/2': '#C5E1A5', 'HTTP/2 (ALPN)': '#A5D6A7',
            'HTTPS (HTTP/1.1)': '#FFAB91', 'QUIC': '#B39DDB', 'HTTP/3 (QUIC)': '#9575CD',
            'WebSocket': '#FFCC80', 'WebSocket (Secure)': '#FFB74D',
            'FTP': '#FFCDD2', 'SMTP': '#D1C4E9', 'SMTPS': '#B39DDB',
            'SSH': '#C8E6C9', 'POP3': '#F8BBD0', 'POP3S': '#F06292',
            'IMAP': '#E1BEE7', 'IMAPS': '#AB47BC',
            'DNS': '#F1F8E9', 'ICMP': '#FFEBEE', 'ARP': '#FFFDE7'
        }
        if packet_info['protocol'] in colors:
            proto_item.setBackground(QColor(colors[packet_info['protocol']]))
        self.packet_table.setItem(row, 4, proto_item)

        self.packet_table.setItem(row, 5, QTableWidgetItem(str(packet_info['length'])))
        self.packet_table.setItem(row, 6, QTableWidgetItem(packet_info['info']))

        session_key = packet_info.get('session_key')
        if session_key:
            self.sessions.setdefault(session_key, []).append(packet_info)

            # Marquage des sessions
            if packet_info.get('ftp_cmd'): self.ftp_sessions.add(session_key)
            if packet_info.get('smtp_cmd'): self.smtp_sessions.add(session_key)
            if packet_info.get('ssh_version'): self.ssh_sessions.add(session_key)
            if packet_info.get('pop3_cmd'): self.pop3_sessions.add(session_key)
            if packet_info.get('imap_cmd'): self.imap_sessions.add(session_key)
            if packet_info.get('is_websocket'): self.websocket_sessions.add(session_key)

            # Propagation du protocole dans la session
            if session_key in self.pop3_sessions:
                packet_info['protocol'] = 'POP3' + ('S' if '995' in session_key else '')
            if session_key in self.imap_sessions:
                packet_info['protocol'] = 'IMAP' + ('S' if '993' in session_key else '')
            if session_key in self.ftp_sessions:
                packet_info['protocol'] = 'FTP'
            if session_key in self.smtp_sessions:
                packet_info['protocol'] = 'SMTP' + ('S' if '465' in session_key else '')
            if session_key in self.ssh_sessions:
                packet_info['protocol'] = 'SSH'
            if session_key in self.websocket_sessions:
                packet_info['protocol'] = 'WebSocket (Secure)' if '443' in session_key else 'WebSocket'

            self.update_session_tree()

        self.packet_table.scrollToBottom()

    def update_progress(self, current, total):
        self.status_bar.showMessage(f"Analyse fichier: {current}/{total} paquets...")

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

    def on_analysis_error(self, msg):
        QMessageBox.critical(self, "Erreur", msg)
        self.status_bar.showMessage("Erreur lors du chargement")

    def display_packets(self):
        self.packet_table.setRowCount(0)
        for pkt in self.packets:
            row = self.packet_table.rowCount()
            self.packet_table.insertRow(row)
            self.packet_table.setItem(row, 0, QTableWidgetItem(str(pkt['no'])))
            self.packet_table.setItem(row, 1, QTableWidgetItem(pkt['time']))
            self.packet_table.setItem(row, 2, QTableWidgetItem(pkt['src']))
            self.packet_table.setItem(row, 3, QTableWidgetItem(pkt['dst']))

            proto_item = QTableWidgetItem(pkt['protocol'])
            colors = {
                'TCP': '#E3F2FD', 'UDP': '#FFF3E0', 'HTTP': '#E8F5E9',
                'HTTPS': '#FFCCBC', 'HTTP/2': '#C5E1A5', 'HTTP/2 (ALPN)': '#A5D6A7',
                'HTTPS (HTTP/1.1)': '#FFAB91', 'QUIC': '#B39DDB', 'HTTP/3 (QUIC)': '#9575CD',
                'WebSocket': '#FFCC80', 'WebSocket (Secure)': '#FFB74D',
                'FTP': '#FFCDD2', 'SMTP': '#D1C4E9', 'SMTPS': '#B39DDB',
                'SSH': '#C8E6C9', 'POP3': '#F8BBD0', 'POP3S': '#F06292',
                'IMAP': '#E1BEE7', 'IMAPS': '#AB47BC',
                'DNS': '#F1F8E9', 'ICMP': '#FFEBEE', 'ARP': '#FFFDE7'
            }
            if pkt['protocol'] in colors:
                proto_item.setBackground(QColor(colors[pkt['protocol']]))
            self.packet_table.setItem(row, 4, proto_item)

            self.packet_table.setItem(row, 5, QTableWidgetItem(str(pkt['length'])))
            self.packet_table.setItem(row, 6, QTableWidgetItem(pkt['info']))

    def update_session_tree(self):
        self.session_tree.clear()
        for session_key, packets in self.sessions.items():
            total_bytes = sum(p['length'] for p in packets)
            item = QTreeWidgetItem([session_key, str(len(packets)), f"{total_bytes} bytes"])
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

        hex_dump = self.create_hexdump(pkt['raw_data'])
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
        if session_key in self.pop3_sessions:
            lines.append("Protocole email: POP3" + ("S" if '995' in session_key else ""))
        if session_key in self.imap_sessions:
            lines.append("Protocole email: IMAP" + ("S" if '993' in session_key else ""))
        if session_key in self.ftp_sessions:
            lines.append("Protocole: FTP")
        if session_key in self.smtp_sessions:
            lines.append("Protocole: SMTP" + ("S" if '465' in session_key else ""))
        if session_key in self.ssh_sessions:
            lines.append("Protocole: SSH")
        if session_key in self.websocket_sessions:
            lines.append("Connexion: WebSocket" + (" sécurisée (wss)" if '443' in session_key else ""))
        if "QUIC" in session_key:
            lines.append("Transport: QUIC (HTTP/3)")
        if any(lines):
            lines.append("")
        for p in packets:
            lines.append(f"[{p['time']}] {p['src']} → {p['dst']}")
            lines.append(f"  {p['info']}")
            lines.append("")
        self.stream_text.setPlainText("\n".join(lines))

    def create_hexdump(self, data):
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f"{i:08x}  {hex_part:<48}  {ascii_part}")
        return '\n'.join(lines)

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
        file_path, _ = QFileDialog.getSaveFileName(self, "Exporter sessions", "", "Text Files (*.txt)")
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(f"Export des sessions - {datetime.now()}\n{'='*80}\n\n")
                    for key, pkgs in self.sessions.items():
                        f.write(f"Session: {key}\nPaquets: {len(pkgs)}\n{'-'*80}\n")
                        for p in pkgs:
                            f.write(f"  [{p['time']}] {p['src']} → {p['dst']} | {p['info']}\n")
                QMessageBox.information(self, "Export", "Export réussi !")
            except Exception as e:
                QMessageBox.critical(self, "Erreur", str(e))

    def clear_data(self):
        self.packets = []
        self.sessions = {}
        self.websocket_sessions.clear()
        self.ftp_sessions.clear()
        self.smtp_sessions.clear()
        self.ssh_sessions.clear()
        self.pop3_sessions.clear()
        self.imap_sessions.clear()
        self.packet_table.setRowCount(0)
        self.session_tree.clear()
        self.detail_text.clear()
        self.hex_text.clear()
        self.stream_text.clear()
        self.info_label.setText("Aucun fichier chargé - Aucune capture")
        self.status_bar.showMessage("Données effacées")
        self.btn_analyze.setEnabled(False)
        self.btn_export.setEnabled(False)
        if self.is_capturing:
            self.stop_live_capture()

    def apply_styles(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #f5f5f5; }
            QPushButton { background-color: #2196F3; color: white; border: none; padding: 8px 16px; border-radius: 4px; font-weight: bold; }
            QPushButton:hover { background-color: #1976D2; }
            QPushButton:disabled { background-color: #BDBDBD; }
            QTableWidget { background-color: white; alternate-background-color: #f9f9f9; border: 1px solid #ddd; }
            QHeaderView::section { background-color: #424242; color: white; padding: 6px; font-weight: bold; }
        """)


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    if not SCAPY_AVAILABLE:
        QMessageBox.warning(None, "Module manquant", "Scapy n'est pas installé.\nInstallez-le avec: pip install scapy")
    window = NetworkAnalyzer()
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()