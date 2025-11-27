# 
# main_window.py
import sys
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from capture_backend import PacketCapture
from flow_reconstructor import FlowReconstructorAdv, FlowKey
from scapy.all import get_if_list, IP, TCP, UDP, Raw

class CaptureWorker(QObject):
    packet_received = pyqtSignal(object)
    error = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, iface=None, bpf=None, autosave=None, max_bytes=None):
        super().__init__()
        self._pcap = PacketCapture(iface, bpf, autosave, max_bytes)

    def start_live(self):
        self._pcap.start_live(self._on_packet, error_callback=self._on_error)

    def stop(self):
        self._pcap.stop()
        self.finished.emit()

    def read_pcap(self, path):
        self._pcap.read_pcap(path, self._on_packet, error_callback=self._on_error)
        self.finished.emit()

    def _on_packet(self, pkt):
        self.packet_received.emit(pkt)

    def _on_error(self, msg):
        self.error.emit(str(msg))

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Packet Analyzer")
        self.setMinimumSize(1200, 750)
        self.reconstructor = FlowReconstructorAdv()
        self.total_packets = 0
        self.total_bytes = 0
        self.capture_thread = None
        self.capture_worker = None
        self._setup_ui()
        self._connect_signals()
        self._refresh_timer = QTimer()
        self._refresh_timer.timeout.connect(self._refresh_stats)
        self._refresh_timer.start(1000)

    def _setup_ui(self):
        layout = QVBoxLayout()
        controls = QHBoxLayout()
        self.open_pcap_btn = QPushButton("Open .pcap")
        self.start_live_btn = QPushButton("Start Live")
        self.stop_live_btn = QPushButton("Stop")
        self.stop_live_btn.setEnabled(False)
        self.iface_combo = QComboBox(); self.iface_combo.setEditable(True)
        for ifn in get_if_list(): self.iface_combo.addItem(ifn)
        self.bpf_input = QLineEdit(); self.bpf_input.setPlaceholderText("BPF filter")
        self.autosave_input = QLineEdit(); self.autosave_input.setPlaceholderText("Auto-save path")
        for w in [self.open_pcap_btn,self.start_live_btn,self.stop_live_btn,
                  QLabel("Interface:"),self.iface_combo,QLabel("Filter:"),self.bpf_input,
                  QLabel("Auto-save:"),self.autosave_input]:
            controls.addWidget(w)
        layout.addLayout(controls)

        splitter = QSplitter(Qt.Horizontal)
        left = QWidget(); left_layout = QVBoxLayout(left)
        self.flows_table = QTableWidget(0,5)
        self.flows_table.setHorizontalHeaderLabels(["Src","Sport","Dst","Dport","Bytes"])
        for w in [QLabel("Flows"),self.flows_table]:
            left_layout.addWidget(w)
        self.refresh_btn = QPushButton("Refresh list")
        self.export_flow_btn = QPushButton("Export Flow")
        left_layout.addWidget(self.refresh_btn)
        left_layout.addWidget(self.export_flow_btn)
        splitter.addWidget(left)

        right = QWidget(); right_layout = QVBoxLayout(right)
        self.payload_view = QTextEdit(); self.payload_view.setReadOnly(True)
        right_layout.addWidget(QLabel("Payload / Reconstructed"))
        right_layout.addWidget(self.payload_view)
        self.extract_http_btn = QPushButton("Extract HTTP")
        self.reconstruct_btn = QPushButton("Reconstruct Flow")
        right_layout.addWidget(self.extract_http_btn)
        right_layout.addWidget(self.reconstruct_btn)
        stats_layout = QHBoxLayout()
        self.pkt_count_label = QLabel("Packets: 0")
        self.bytes_label = QLabel("Bytes: 0")
        self.flows_label = QLabel("Flows: 0")
        for w in [self.pkt_count_label,self.bytes_label,self.flows_label]: stats_layout.addWidget(w)
        right_layout.addLayout(stats_layout)
        splitter.addWidget(right)
        splitter.setStretchFactor(0,3)
        splitter.setStretchFactor(1,4)
        layout.addWidget(splitter)

        container = QWidget(); container.setLayout(layout)
        self.setCentralWidget(container)

    def _connect_signals(self):
        self.open_pcap_btn.clicked.connect(self.open_pcap)
        self.start_live_btn.clicked.connect(self.start_live_capture)
        self.stop_live_btn.clicked.connect(self.stop_capture)
        self.refresh_btn.clicked.connect(self.refresh_flows_table)
        self.flows_table.cellClicked.connect(self.on_flow_selected)
        self.export_flow_btn.clicked.connect(self.export_selected_payload)
        self.extract_http_btn.clicked.connect(self.extract_http_from_payload)
        self.reconstruct_btn.clicked.connect(self.reconstruct_selected_flow)

    # --- Capture/PCAP ---
    def open_pcap(self):
        path,_ = QFileDialog.getOpenFileName(self,"Open pcap","","PCAP files (*.pcap *.pcapng)")
        if not path: return
        self._start_worker_read_pcap(path)

    def start_live_capture(self):
        iface = self.iface_combo.currentText().strip()
        bpf = self.bpf_input.text().strip() or None
        autosave = self.autosave_input.text().strip() or None
        self._start_worker_live(iface,bpf,autosave)

    def stop_capture(self):
        if self.capture_worker: self.capture_worker.stop()
        self.start_live_btn.setEnabled(True)
        self.stop_live_btn.setEnabled(False)

    def _start_worker_live(self, iface, bpf, autosave):
        if self.capture_thread and self.capture_thread.isRunning():
            QMessageBox.warning(self,"Capture","A capture is already running."); return
        self.capture_thread = QThread()
        self.capture_worker = CaptureWorker(iface,bpf,autosave)
        self.capture_worker.moveToThread(self.capture_thread)
        self.capture_worker.packet_received.connect(self.on_packet_received)
        self.capture_worker.error.connect(self.on_capture_error)
        self.capture_thread.started.connect(self.capture_worker.start_live)
        self.capture_worker.finished.connect(self.capture_thread.quit)
        self.capture_thread.start()
        self.start_live_btn.setEnabled(False)
        self.stop_live_btn.setEnabled(True)

    def _start_worker_read_pcap(self,path):
        self.capture_thread = QThread()
        self.capture_worker = CaptureWorker()
        self.capture_worker.moveToThread(self.capture_thread)
        self.capture_worker.packet_received.connect(self.on_packet_received)
        self.capture_worker.error.connect(self.on_capture_error)
        self.capture_thread.started.connect(lambda: self.capture_worker.read_pcap(path))
        self.capture_worker.finished.connect(self.capture_thread.quit)
        self.capture_thread.start()

    def on_capture_error(self,msg):
        QMessageBox.critical(self,"Capture error",msg)
        self.stop_capture()

    # --- Packet handling ---
    def on_packet_received(self,pkt):
        self.total_packets += 1
        try: self.total_bytes += len(bytes(pkt))
        except: pass
        key = self.reconstructor.add_packet(pkt)
        if key: self._update_or_insert_flow_row(key)

    def _update_or_insert_flow_row(self,key):
        for r in range(self.flows_table.rowCount()):
            it0 = self.flows_table.item(r,0)
            it1 = self.flows_table.item(r,1)
            it2 = self.flows_table.item(r,2)
            it3 = self.flows_table.item(r,3)
            if it0 and it0.text()==key.src and it1.text()==str(key.sport) and it2.text()==key.dst and it3.text()==str(key.dport):
                size = self.reconstructor.get_reassembled(key)
                self.flows_table.setItem(r,4,QTableWidgetItem(str(len(size))))
                return
        r = self.flows_table.rowCount()
        self.flows_table.insertRow(r)
        self.flows_table.setItem(r,0,QTableWidgetItem(key.src))
        self.flows_table.setItem(r,1,QTableWidgetItem(str(key.sport)))
        self.flows_table.setItem(r,2,QTableWidgetItem(key.dst))
        self.flows_table.setItem(r,3,QTableWidgetItem(str(key.dport)))
        size = self.reconstructor.get_reassembled(key)
        self.flows_table.setItem(r,4,QTableWidgetItem(str(len(size))))

    # --- GUI actions ---
    def reconstruct_selected_flow(self):
        sel = self.flows_table.currentRow()
        if sel<0: QMessageBox.warning(self,"Reconstruct","No flow selected."); return
        src = self.flows_table.item(sel,0).text()
        sport=int(self.flows_table.item(sel,1).text())
        dst=self.flows_table.item(sel,2).text()
        dport=int(self.flows_table.item(sel,3).text())
        key = FlowKey(src,sport,dst,dport,"TCP")
        payload=self.reconstructor.get_reassembled(key)
        try: self.payload_view.setPlainText(payload.decode("utf-8",errors="replace"))
        except: self.payload_view.setPlainText(payload.hex())

    def refresh_flows_table(self):
        self.flows_table.setRowCount(0)
        for key,total_bytes,_ in self.reconstructor.flows_summary():
            r=self.flows_table.rowCount()
            self.flows_table.insertRow(r)
            self.flows_table.setItem(r,0,QTableWidgetItem(key.src))
            self.flows_table.setItem(r,1,QTableWidgetItem(str(key.sport)))
            self.flows_table.setItem(r,2,QTableWidgetItem(key.dst))
            self.flows_table.setItem(r,3,QTableWidgetItem(str(key.dport)))
            self.flows_table.setItem(r,4,QTableWidgetItem(str(total_bytes)))

    def on_flow_selected(self,row,col):
        src=self.flows_table.item(row,0).text()
        sport=int(self.flows_table.item(row,1).text())
        dst=self.flows_table.item(row,2).text()
        dport=int(self.flows_table.item(row,3).text())
        key=FlowKey(src,sport,dst,dport,"TCP")
        payload=self.reconstructor.get_reassembled(key)
        try: self.payload_view.setPlainText(payload.decode("utf-8",errors="replace"))
        except: self.payload_view.setPlainText(payload.hex())

    def export_selected_payload(self):
        sel=self.flows_table.currentRow()
        if sel<0: QMessageBox.warning(self,"Export","No flow selected."); return
        src=self.flows_table.item(sel,0).text()
        sport=int(self.flows_table.item(sel,1).text())
        dst=self.flows_table.item(sel,2).text()
        dport=int(self.flows_table.item(sel,3).text())
        key=FlowKey(src,sport,dst,dport,"TCP")
        payload=self.reconstructor.get_reassembled(key)
        path,_=QFileDialog.getSaveFileName(self,"Save payload",f"flow_{src}_{sport}_{dst}_{dport}.bin")
        if not path: return
        with open(path,"wb") as f: f.write(payload)
        QMessageBox.information(self,"Export",f"Saved {path}")

    def extract_http_from_payload(self):
        text=self.payload_view.toPlainText()
        if not text: QMessageBox.information(self,"HTTP extract","No payload."); return
        lines=[l for l in text.splitlines() if l.startswith(("GET","POST")) or "HTTP/" in l]
        QMessageBox.information(self,"HTTP extract","\n".join(lines[:40]) if lines else "No HTTP content found.")

    def _refresh_stats(self):
        self.pkt_count_label.setText(f"Packets: {self.total_packets}")
        self.bytes_label.setText(f"Bytes: {self.total_bytes}")
        self.flows_label.setText(f"Flows: {len(self.reconstructor.flows)}")

if __name__=="__main__":
    app=QApplication(sys.argv)
    win=MainWindow()
    win.show()
    sys.exit(app.exec_())
