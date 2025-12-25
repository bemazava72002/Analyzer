"""
Analyseur de paquets réseau et reconstruction de sessions
Auteur: Mr Ferdinand
Description: Application professionnelle pour l'analyse forensique réseau
"""

import sys
import os
from datetime import datetime
from collections import defaultdict
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTableWidget, QTableWidgetItem, QTextEdit, QLabel,
    QFileDialog, QSplitter, QTreeWidget, QTreeWidgetItem, QTabWidget,
    QMessageBox, QHeaderView, QStatusBar
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor

try:
    from scapy.all import rdpcap, IP, TCP, UDP, Raw, DNS
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class PacketAnalyzerThread(QThread):
    """Thread pour l'analyse des paquets sans bloquer l'interface"""
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
                    self.progress.emit(idx, total)
                
                packet_info = self.analyze_packet(pkt, idx)
                analyzed_packets.append(packet_info)
                
                # Regroupement par session
                session_key = packet_info.get('session_key')
                if session_key:
                    sessions[session_key].append(packet_info)
            
            self.progress.emit(total, total)
            self.finished.emit(analyzed_packets, dict(sessions))
            
        except Exception as e:
            self.error.emit(str(e))

    def analyze_packet(self, pkt, idx):
        """Analyse détaillée d'un paquet"""
        info = {
            'no': idx + 1,
            'time': datetime.now().strftime('%H:%M:%S.%f')[:-3],
            'src': '',
            'dst': '',
            'protocol': '',
            'length': len(pkt),
            'info': '',
            'session_key': None,
            'raw_data': bytes(pkt)
        }
        
        # Analyse couche IP
        if IP in pkt:
            info['src'] = pkt[IP].src
            info['dst'] = pkt[IP].dst
            info['protocol'] = pkt[IP].proto
            
            # Analyse TCP
            if TCP in pkt:
                info['protocol'] = 'TCP'
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                info['info'] = f"{src_port} → {dst_port}"
                
                # Flags TCP
                flags = []
                if pkt[TCP].flags.S: flags.append('SYN')
                if pkt[TCP].flags.A: flags.append('ACK')
                if pkt[TCP].flags.F: flags.append('FIN')
                if pkt[TCP].flags.R: flags.append('RST')
                if pkt[TCP].flags.P: flags.append('PSH')
                
                if flags:
                    info['info'] += f" [{','.join(flags)}]"
                
                # Clé de session (bidirectionnelle)
                session = tuple(sorted([
                    (info['src'], src_port),
                    (info['dst'], dst_port)
                ]))
                info['session_key'] = f"TCP:{session}"
                
                # Détection HTTP
                if Raw in pkt:
                    payload = bytes(pkt[Raw].load)
                    if payload.startswith(b'HTTP') or payload.startswith(b'GET') or payload.startswith(b'POST'):
                        info['protocol'] = 'HTTP'
                        info['info'] += ' [HTTP]'
            
            # Analyse UDP
            elif UDP in pkt:
                info['protocol'] = 'UDP'
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                info['info'] = f"{src_port} → {dst_port}"
                
                session = tuple(sorted([
                    (info['src'], src_port),
                    (info['dst'], dst_port)
                ]))
                info['session_key'] = f"UDP:{session}"
                
                # Détection DNS
                if DNS in pkt:
                    info['protocol'] = 'DNS'
                    if pkt[DNS].qd:
                        info['info'] += f" Query: {pkt[DNS].qd.qname.decode()}"
        
        return info


class NetworkAnalyzer(QMainWindow):
    """Interface principale de l'analyseur réseau"""
    
    def __init__(self):
        super().__init__()
        self.packets = []
        self.sessions = {}
        self.current_file = None
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle("Analyseur de Paquets Réseau - Mr Ferdinand")
        self.setGeometry(100, 100, 1400, 800)
        
        # Widget central
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(5, 5, 5, 5)
        
        # Barre d'outils
        toolbar = self.create_toolbar()
        main_layout.addLayout(toolbar)
        
        # Splitter principal (horizontal)
        main_splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Table des paquets
        self.packet_table = self.create_packet_table()
        main_splitter.addWidget(self.packet_table)
        
        # Splitter inférieur
        bottom_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Arbre de sessions
        self.session_tree = self.create_session_tree()
        bottom_splitter.addWidget(self.session_tree)
        
        # Onglets de détails
        self.detail_tabs = self.create_detail_tabs()
        bottom_splitter.addWidget(self.detail_tabs)
        
        bottom_splitter.setSizes([400, 600])
        main_splitter.addWidget(bottom_splitter)
        main_splitter.setSizes([400, 400])
        
        main_layout.addWidget(main_splitter)
        
        # Barre de statut
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Prêt - Veuillez charger un fichier PCAP")
        
        self.apply_styles()
        
    def create_toolbar(self):
        """Création de la barre d'outils"""
        toolbar = QHBoxLayout()
        
        self.btn_open = QPushButton("📁 Ouvrir PCAP")
        self.btn_open.clicked.connect(self.open_pcap)
        self.btn_open.setFixedHeight(35)
        
        self.btn_analyze = QPushButton("🔍 Analyser Sessions")
        self.btn_analyze.clicked.connect(self.analyze_sessions)
        self.btn_analyze.setEnabled(False)
        self.btn_analyze.setFixedHeight(35)
        
        self.btn_export = QPushButton("💾 Exporter")
        self.btn_export.clicked.connect(self.export_sessions)
        self.btn_export.setEnabled(False)
        self.btn_export.setFixedHeight(35)
        
        self.btn_clear = QPushButton("🗑️ Effacer")
        self.btn_clear.clicked.connect(self.clear_data)
        self.btn_clear.setFixedHeight(35)
        
        self.info_label = QLabel("Aucun fichier chargé")
        self.info_label.setStyleSheet("color: #666; font-size: 11px;")
        
        toolbar.addWidget(self.btn_open)
        toolbar.addWidget(self.btn_analyze)
        toolbar.addWidget(self.btn_export)
        toolbar.addWidget(self.btn_clear)
        toolbar.addStretch()
        toolbar.addWidget(self.info_label)
        
        return toolbar
    
    def create_packet_table(self):
        """Création de la table des paquets"""
        table = QTableWidget()
        table.setColumnCount(7)
        table.setHorizontalHeaderLabels([
            'No.', 'Temps', 'Source', 'Destination', 'Protocole', 'Longueur', 'Info'
        ])
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.itemSelectionChanged.connect(self.on_packet_selected)
        
        return table
    
    def create_session_tree(self):
        """Création de l'arbre des sessions"""
        tree = QTreeWidget()
        tree.setHeaderLabels(['Sessions TCP/UDP', 'Paquets', 'Bytes'])
        tree.itemClicked.connect(self.on_session_selected)
        return tree
    
    def create_detail_tabs(self):
        """Création des onglets de détails"""
        tabs = QTabWidget()
        
        # Onglet Détails du paquet
        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setFont(QFont("Courier", 9))
        tabs.addTab(self.detail_text, "Détails")
        
        # Onglet Hexdump
        self.hex_text = QTextEdit()
        self.hex_text.setReadOnly(True)
        self.hex_text.setFont(QFont("Courier", 9))
        tabs.addTab(self.hex_text, "Hexdump")
        
        # Onglet Reconstruction
        self.stream_text = QTextEdit()
        self.stream_text.setReadOnly(True)
        self.stream_text.setFont(QFont("Courier", 9))
        tabs.addTab(self.stream_text, "Flux TCP")
        
        return tabs
    
    def open_pcap(self):
        """Ouverture et chargement d'un fichier PCAP"""
        if not SCAPY_AVAILABLE:
            QMessageBox.critical(self, "Erreur", 
                "Scapy n'est pas installé.\nInstallez-le avec: pip install scapy")
            return
        
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Ouvrir un fichier PCAP", "", "PCAP Files (*.pcap *.pcapng);;All Files (*)"
        )
        
        if file_path:
            self.current_file = file_path
            self.status_bar.showMessage("Chargement en cours...")
            
            # Lancement du thread d'analyse
            self.analyzer_thread = PacketAnalyzerThread(file_path)
            self.analyzer_thread.progress.connect(self.update_progress)
            self.analyzer_thread.finished.connect(self.on_analysis_finished)
            self.analyzer_thread.error.connect(self.on_analysis_error)
            self.analyzer_thread.start()
            
            self.btn_open.setEnabled(False)
    
    def update_progress(self, current, total):
        """Mise à jour de la progression"""
        self.status_bar.showMessage(f"Analyse: {current}/{total} paquets...")
    
    def on_analysis_finished(self, packets, sessions):
        """Traitement après analyse"""
        self.packets = packets
        self.sessions = sessions
        
        self.display_packets()
        self.display_sessions()
        
        file_name = os.path.basename(self.current_file)
        self.info_label.setText(f"📄 {file_name} - {len(packets)} paquets - {len(sessions)} sessions")
        self.status_bar.showMessage(f"Analyse terminée: {len(packets)} paquets chargés")
        
        self.btn_open.setEnabled(True)
        self.btn_analyze.setEnabled(True)
        self.btn_export.setEnabled(True)
    
    def on_analysis_error(self, error_msg):
        """Gestion des erreurs"""
        QMessageBox.critical(self, "Erreur d'analyse", f"Impossible d'analyser le fichier:\n{error_msg}")
        self.btn_open.setEnabled(True)
        self.status_bar.showMessage("Erreur lors de l'analyse")
    
    def display_packets(self):
        """Affichage des paquets dans la table"""
        self.packet_table.setRowCount(len(self.packets))
        
        for idx, pkt in enumerate(self.packets):
            self.packet_table.setItem(idx, 0, QTableWidgetItem(str(pkt['no'])))
            self.packet_table.setItem(idx, 1, QTableWidgetItem(pkt['time']))
            self.packet_table.setItem(idx, 2, QTableWidgetItem(pkt['src']))
            self.packet_table.setItem(idx, 3, QTableWidgetItem(pkt['dst']))
            
            protocol_item = QTableWidgetItem(pkt['protocol'])
            if pkt['protocol'] == 'TCP':
                protocol_item.setBackground(QColor('#E3F2FD'))
            elif pkt['protocol'] == 'UDP':
                protocol_item.setBackground(QColor('#FFF3E0'))
            elif pkt['protocol'] == 'HTTP':
                protocol_item.setBackground(QColor('#E8F5E9'))
            
            self.packet_table.setItem(idx, 4, protocol_item)
            self.packet_table.setItem(idx, 5, QTableWidgetItem(str(pkt['length'])))
            self.packet_table.setItem(idx, 6, QTableWidgetItem(pkt['info']))
    
    def display_sessions(self):
        """Affichage des sessions dans l'arbre"""
        self.session_tree.clear()
        
        for session_key, packets in self.sessions.items():
            total_bytes = sum(p['length'] for p in packets)
            
            item = QTreeWidgetItem([
                session_key,
                str(len(packets)),
                f"{total_bytes} bytes"
            ])
            
            self.session_tree.addTopLevelItem(item)
    
    def on_packet_selected(self):
        """Affichage des détails d'un paquet sélectionné"""
        selected = self.packet_table.selectedItems()
        if not selected:
            return
        
        row = self.packet_table.currentRow()
        if row < 0 or row >= len(self.packets):
            return
        
        pkt = self.packets[row]
        
        # Détails textuels
        details = f"""Paquet #{pkt['no']}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Temps:        {pkt['time']}
Source:       {pkt['src']}
Destination:  {pkt['dst']}
Protocole:    {pkt['protocol']}
Longueur:     {pkt['length']} bytes
Info:         {pkt['info']}
Session:      {pkt['session_key'] or 'N/A'}
"""
        self.detail_text.setPlainText(details)
        
        # Hexdump
        raw_data = pkt['raw_data']
        hex_dump = self.create_hexdump(raw_data)
        self.hex_text.setPlainText(hex_dump)
    
    def on_session_selected(self, item, column):
        """Reconstruction du flux TCP d'une session"""
        session_key = item.text(0)
        
        if session_key not in self.sessions:
            return
        
        packets = self.sessions[session_key]
        
        # Reconstruction du flux
        stream_data = []
        for pkt in packets:
            stream_data.append(f"[{pkt['time']}] {pkt['src']} → {pkt['dst']}")
            stream_data.append(f"  {pkt['info']}")
            stream_data.append("")
        
        self.stream_text.setPlainText("\n".join(stream_data))
    
    def create_hexdump(self, data):
        """Création d'un hexdump formaté"""
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f"{i:08x}  {hex_part:<48}  {ascii_part}")
        
        return '\n'.join(lines)
    
    def analyze_sessions(self):
        """Analyse approfondie des sessions"""
        if not self.sessions:
            QMessageBox.information(self, "Info", "Aucune session à analyser")
            return
        
        report = f"Rapport d'analyse\n{'='*60}\n\n"
        report += f"Fichier: {os.path.basename(self.current_file)}\n"
        report += f"Total paquets: {len(self.packets)}\n"
        report += f"Total sessions: {len(self.sessions)}\n\n"
        
        for session_key, packets in self.sessions.items():
            report += f"\n{session_key}\n"
            report += f"  Paquets: {len(packets)}\n"
            report += f"  Total: {sum(p['length'] for p in packets)} bytes\n"
        
        self.stream_text.setPlainText(report)
        QMessageBox.information(self, "Analyse", f"{len(self.sessions)} sessions analysées")
    
    def export_sessions(self):
        """Export des sessions vers un fichier"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Exporter les sessions", "", "Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(f"Export des sessions - {datetime.now()}\n")
                    f.write("="*80 + "\n\n")
                    
                    for session_key, packets in self.sessions.items():
                        f.write(f"\nSession: {session_key}\n")
                        f.write(f"Nombre de paquets: {len(packets)}\n")
                        f.write("-"*80 + "\n")
                        
                        for pkt in packets:
                            f.write(f"  [{pkt['time']}] {pkt['src']} → {pkt['dst']} | {pkt['info']}\n")
                
                QMessageBox.information(self, "Export", "Sessions exportées avec succès!")
            except Exception as e:
                QMessageBox.critical(self, "Erreur", f"Erreur lors de l'export:\n{str(e)}")
    
    def clear_data(self):
        """Effacement de toutes les données"""
        self.packets = []
        self.sessions = {}
        self.packet_table.setRowCount(0)
        self.session_tree.clear()
        self.detail_text.clear()
        self.hex_text.clear()
        self.stream_text.clear()
        self.info_label.setText("Aucun fichier chargé")
        self.status_bar.showMessage("Données effacées")
        self.btn_analyze.setEnabled(False)
        self.btn_export.setEnabled(False)
    
    def apply_styles(self):
        """Application des styles CSS"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f5f5;
            }
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QPushButton:disabled {
                background-color: #BDBDBD;
            }
            QTableWidget {
                background-color: white;
                alternate-background-color: #f9f9f9;
                border: 1px solid #ddd;
                gridline-color: #e0e0e0;
            }
            QTableWidget::item:selected {
                background-color: #BBDEFB;
                color: black;
            }
            QHeaderView::section {
                background-color: #424242;
                color: white;
                padding: 6px;
                border: none;
                font-weight: bold;
            }
            QTreeWidget {
                background-color: white;
                border: 1px solid #ddd;
            }
            QTextEdit {
                background-color: white;
                border: 1px solid #ddd;
            }
            QTabWidget::pane {
                border: 1px solid #ddd;
                background-color: white;
            }
            QTabBar::tab {
                background-color: #e0e0e0;
                padding: 8px 16px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: white;
            }
        """)


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    if not SCAPY_AVAILABLE:
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.setWindowTitle("Module manquant")
        msg.setText("Scapy n'est pas installé")
        msg.setInformativeText("Pour utiliser cette application, installez Scapy:\n\npip install scapy")
        msg.exec()
    
    window = NetworkAnalyzer()
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()