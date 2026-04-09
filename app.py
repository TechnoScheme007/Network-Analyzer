"""Network Analyzer — PySide6 desktop GUI."""
from __future__ import annotations

import sys
from pathlib import Path
from datetime import datetime

from PySide6.QtCore import Qt, Signal, QObject, Slot, QTimer
from PySide6.QtGui import QAction, QFont, QColor, QIcon, QKeySequence
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QStatusBar,
    QTableWidget,
    QTableWidgetItem,
    QToolBar,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from capture import CaptureEngine, DecodedPacket, get_interfaces, hex_dump

# ── Protocol colours ──────────────────────────────────────────

PROTOCOL_COLORS: dict[str, str] = {
    "TCP": "#c8e6c9",
    "UDP": "#bbdefb",
    "ICMP": "#e1bee7",
    "DNS": "#b2ebf2",
    "ARP": "#fff9c4",
    "HTTP": "#a5d6a7",
    "OTHER": "#ffffff",
}

DARK_PROTOCOL_COLORS: dict[str, str] = {
    "TCP": "#1b5e20",
    "UDP": "#0d47a1",
    "ICMP": "#4a148c",
    "DNS": "#006064",
    "ARP": "#f57f17",
    "HTTP": "#2e7d32",
    "OTHER": "#212121",
}

COLUMNS = ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"]


# ── Signal bridge (thread → GUI) ─────────────────────────────

class PacketSignal(QObject):
    new_packet = Signal(object)
    limit_reached = Signal()


# ── Main window ──────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Network Analyzer")
        self.setMinimumSize(1100, 700)
        self.resize(1400, 850)

        self.engine = CaptureEngine()
        self._signal = PacketSignal()
        self._signal.new_packet.connect(self._on_packet_arrived)
        self._signal.limit_reached.connect(self._on_limit_reached)
        self._selected_idx: int = -1

        self._build_menu()
        self._build_toolbar()
        self._build_body()
        self._build_statusbar()

        # Periodic status refresh while capturing
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh_status)
        self._timer.start(500)

    # ── Menu bar ──────────────────────────────────────────────

    def _build_menu(self) -> None:
        menu = self.menuBar()

        file_menu = menu.addMenu("&File")
        export_act = QAction("&Export PCAP...", self)
        export_act.setShortcut(QKeySequence("Ctrl+E"))
        export_act.triggered.connect(self._export_pcap)
        file_menu.addAction(export_act)
        file_menu.addSeparator()
        quit_act = QAction("&Quit", self)
        quit_act.setShortcut(QKeySequence("Ctrl+Q"))
        quit_act.triggered.connect(self.close)
        file_menu.addAction(quit_act)

        capture_menu = menu.addMenu("&Capture")
        start_act = QAction("&Start", self)
        start_act.setShortcut(QKeySequence("F5"))
        start_act.triggered.connect(self._start_capture)
        capture_menu.addAction(start_act)
        stop_act = QAction("S&top", self)
        stop_act.setShortcut(QKeySequence("F6"))
        stop_act.triggered.connect(self._stop_capture)
        capture_menu.addAction(stop_act)
        capture_menu.addSeparator()
        clear_act = QAction("&Clear", self)
        clear_act.setShortcut(QKeySequence("Ctrl+K"))
        clear_act.triggered.connect(self._clear)
        capture_menu.addAction(clear_act)

        help_menu = menu.addMenu("&Help")
        about_act = QAction("&About", self)
        about_act.triggered.connect(self._show_about)
        help_menu.addAction(about_act)

    # ── Toolbar ───────────────────────────────────────────────

    def _build_toolbar(self) -> None:
        tb = QToolBar("Capture Controls")
        tb.setMovable(False)
        tb.setIconSize(tb.iconSize())
        self.addToolBar(tb)

        tb.addWidget(QLabel("  Interface: "))
        self._iface_combo = QComboBox()
        self._iface_combo.setMinimumWidth(320)
        interfaces = get_interfaces()
        for iface_id, label, _ip in interfaces:
            self._iface_combo.addItem(label, userData=iface_id)
        # First item is already the active interface (sorted by get_interfaces)
        if interfaces:
            self._iface_combo.setCurrentIndex(0)
        tb.addWidget(self._iface_combo)

        tb.addSeparator()

        tb.addWidget(QLabel("  Filter: "))
        self._filter_input = QLineEdit()
        self._filter_input.setPlaceholderText("BPF filter, e.g.  tcp port 80   host 1.2.3.4")
        self._filter_input.setMinimumWidth(280)
        self._filter_input.returnPressed.connect(self._start_capture)
        tb.addWidget(self._filter_input)

        tb.addSeparator()

        self._start_btn = QPushButton("  Start  ")
        self._start_btn.setStyleSheet(
            "QPushButton { background-color: #4caf50; color: white; font-weight: bold; "
            "padding: 4px 14px; border-radius: 3px; }"
            "QPushButton:hover { background-color: #388e3c; }"
            "QPushButton:disabled { background-color: #a5d6a7; }"
        )
        self._start_btn.clicked.connect(self._start_capture)
        tb.addWidget(self._start_btn)

        self._stop_btn = QPushButton("  Stop  ")
        self._stop_btn.setEnabled(False)
        self._stop_btn.setStyleSheet(
            "QPushButton { background-color: #f44336; color: white; font-weight: bold; "
            "padding: 4px 14px; border-radius: 3px; }"
            "QPushButton:hover { background-color: #d32f2f; }"
            "QPushButton:disabled { background-color: #ef9a9a; }"
        )
        self._stop_btn.clicked.connect(self._stop_capture)
        tb.addWidget(self._stop_btn)

        self._clear_btn = QPushButton("  Clear  ")
        self._clear_btn.setStyleSheet(
            "QPushButton { padding: 4px 14px; border-radius: 3px; }"
        )
        self._clear_btn.clicked.connect(self._clear)
        tb.addWidget(self._clear_btn)

        self._export_btn = QPushButton("  Export PCAP  ")
        self._export_btn.setStyleSheet(
            "QPushButton { background-color: #1976d2; color: white; font-weight: bold; "
            "padding: 4px 14px; border-radius: 3px; }"
            "QPushButton:hover { background-color: #1565c0; }"
        )
        self._export_btn.clicked.connect(self._export_pcap)
        tb.addWidget(self._export_btn)

        tb.addSeparator()

        tb.addWidget(QLabel("  Max packets: "))
        self._limit_spin = QSpinBox()
        self._limit_spin.setRange(50, 100000)
        self._limit_spin.setSingleStep(100)
        self._limit_spin.setValue(CaptureEngine.DEFAULT_MAX_PACKETS)
        self._limit_spin.setToolTip("Capture auto-stops when this limit is reached")
        self._limit_spin.setMinimumWidth(90)
        tb.addWidget(self._limit_spin)

    # ── Central body ──────────────────────────────────────────

    def _build_body(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(4, 4, 4, 4)

        # Vertical splitter: packet table | (details + hex)
        vsplit = QSplitter(Qt.Orientation.Vertical)

        # ── Packet table ──
        self._table = QTableWidget(0, len(COLUMNS))
        self._table.setHorizontalHeaderLabels(COLUMNS)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.setSortingEnabled(False)
        self._table.setFont(QFont("Consolas", 9))
        header = self._table.horizontalHeader()
        for i in range(len(COLUMNS) - 1):
            header.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(len(COLUMNS) - 1, QHeaderView.ResizeMode.Stretch)
        self._table.currentCellChanged.connect(self._on_row_changed)
        vsplit.addWidget(self._table)

        # ── Bottom half: detail tree + hex dump ──
        hsplit = QSplitter(Qt.Orientation.Horizontal)

        self._detail_tree = QTreeWidget()
        self._detail_tree.setHeaderLabels(["Field", "Value"])
        self._detail_tree.setFont(QFont("Consolas", 9))
        self._detail_tree.setAlternatingRowColors(True)
        self._detail_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._detail_tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        # Placeholder for empty state
        placeholder = QTreeWidgetItem(["Click a packet above to inspect", ""])
        placeholder.setForeground(0, QColor("#999999"))
        self._detail_tree.addTopLevelItem(placeholder)
        hsplit.addWidget(self._detail_tree)

        self._hex_view = QPlainTextEdit()
        self._hex_view.setReadOnly(True)
        self._hex_view.setFont(QFont("Consolas", 9))
        self._hex_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self._hex_view.setPlaceholderText("Click a packet above to see its hex dump")
        self._hex_view.setStyleSheet(
            "QPlainTextEdit { background-color: #1e1e1e; color: #4ec9b0; }"
        )
        hsplit.addWidget(self._hex_view)

        hsplit.setSizes([500, 500])
        vsplit.addWidget(hsplit)
        vsplit.setSizes([400, 300])

        layout.addWidget(vsplit)

    # ── Status bar ────────────────────────────────────────────

    def _build_statusbar(self) -> None:
        sb = QStatusBar()
        self.setStatusBar(sb)
        self._status_label = QLabel("Ready")
        sb.addPermanentWidget(self._status_label)

    def _refresh_status(self) -> None:
        count = len(self.engine.packets)
        limit = self.engine.max_packets
        state = "Capturing..." if self.engine.running else "Stopped"
        iface = self._iface_combo.currentText() or "---"
        backend = f"   |   Backend: {self.engine.backend}" if self.engine.backend else ""
        self._status_label.setText(
            f"  Packets: {count}/{limit}   |   {state}   |   {iface}{backend}  "
        )

    # ── Capture actions ───────────────────────────────────────

    def _start_capture(self) -> None:
        if self.engine.running:
            return
        iface = self._iface_combo.currentData()
        if not iface:
            QMessageBox.warning(self, "No Interface", "Select a network interface first.")
            return

        bpf = self._filter_input.text().strip()
        self.engine.max_packets = self._limit_spin.value()
        self.engine.on_limit_reached = lambda: self._signal.limit_reached.emit()

        try:
            self.engine.start(
                iface,
                bpf_filter=bpf,
                callback=lambda pkt: self._signal.new_packet.emit(pkt),
            )
        except Exception as e:
            msg = str(e)
            if "pcap" in msg.lower() or "npcap" in msg.lower() or "winpcap" in msg.lower():
                msg = (
                    "Could not open the network interface.\n\n"
                    "Make sure:\n"
                    "  1. Npcap is installed (https://npcap.com/)\n"
                    '  2. "WinPcap API-compatible Mode" was enabled during install\n'
                    "  3. You are running as Administrator\n\n"
                    f"Details: {e}"
                )
            elif "filter" in msg.lower() or "bpf" in msg.lower() or "syntax" in msg.lower():
                msg = (
                    f"Invalid BPF filter: {bpf}\n\n"
                    "Examples of valid filters:\n"
                    "  tcp port 80\n"
                    "  host 192.168.1.1\n"
                    "  udp and not port 53\n\n"
                    f"Details: {e}"
                )
            QMessageBox.critical(self, "Capture Error", msg)
            return

        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._iface_combo.setEnabled(False)
        self._filter_input.setEnabled(False)
        self._limit_spin.setEnabled(False)

    def _stop_capture(self) -> None:
        self.engine.stop()
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._iface_combo.setEnabled(True)
        self._filter_input.setEnabled(True)
        self._limit_spin.setEnabled(True)

    @Slot()
    def _on_limit_reached(self) -> None:
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._iface_combo.setEnabled(True)
        self._filter_input.setEnabled(True)
        self._limit_spin.setEnabled(True)
        self.statusBar().showMessage(
            f"Capture auto-stopped: {self.engine.max_packets} packet limit reached", 5000
        )

    def _clear(self) -> None:
        if self.engine.running:
            self._stop_capture()
        self.engine.packets.clear()
        self.engine._counter = 0
        self._table.setRowCount(0)
        self._detail_tree.clear()
        self._hex_view.clear()
        self._selected_idx = -1

    def _export_pcap(self) -> None:
        if not self.engine.packets:
            QMessageBox.information(self, "Export", "No packets to export.")
            return
        default_name = f"capture_{datetime.now():%Y%m%d_%H%M%S}.pcap"
        path, _ = QFileDialog.getSaveFileName(
            self, "Export PCAP", default_name, "PCAP Files (*.pcap);;All Files (*)"
        )
        if not path:
            return
        try:
            count = self.engine.export_pcap(path)
            QMessageBox.information(self, "Export", f"Exported {count} packets to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def _show_about(self) -> None:
        QMessageBox.about(
            self,
            "About Network Analyzer",
            "<h2>Network Analyzer</h2>"
            "<p>A lightweight Wireshark-like packet capture tool.</p>"
            "<p>Decodes Ethernet, IPv4/IPv6, TCP, UDP, ICMP, ARP, DNS, HTTP.</p>"
            "<p>Built with <b>Scapy</b> + <b>PySide6</b>.</p>",
        )

    # ── Packet arrival (thread-safe via signal) ───────────────

    @Slot(object)
    def _on_packet_arrived(self, pkt: DecodedPacket) -> None:
        row = self._table.rowCount()
        self._table.insertRow(row)
        bg = QColor(PROTOCOL_COLORS.get(pkt.protocol, "#ffffff"))

        values = [
            str(pkt.number),
            f"{pkt.timestamp:.3f}",
            pkt.src_ip,
            pkt.dst_ip,
            pkt.protocol,
            str(pkt.length),
            pkt.info[:120],
        ]
        for col, text in enumerate(values):
            item = QTableWidgetItem(text)
            item.setBackground(bg)
            self._table.setItem(row, col, item)

        # Auto-select first packet so detail panels aren't empty
        if row == 0:
            self._table.selectRow(0)

        # Auto-scroll if user is near the bottom
        scrollbar = self._table.verticalScrollBar()
        if scrollbar.value() >= scrollbar.maximum() - 3:
            self._table.scrollToBottom()

    # ── Row selection → detail + hex ──────────────────────────

    def _on_row_changed(self, row: int, _col: int, _prev_row: int, _prev_col: int) -> None:
        if row < 0 or row >= len(self.engine.packets):
            return
        self._selected_idx = row
        pkt = self.engine.packets[row]
        self._show_details(pkt)
        self._show_hex(pkt)

    def _show_details(self, pkt: DecodedPacket) -> None:
        self._detail_tree.clear()
        for layer_name, fields in pkt.layers:
            layer_item = QTreeWidgetItem([layer_name, ""])
            layer_item.setExpanded(True)
            font = layer_item.font(0)
            font.setBold(True)
            layer_item.setFont(0, font)
            for key, value in fields.items():
                child = QTreeWidgetItem([str(key), str(value)])
                layer_item.addChild(child)
            self._detail_tree.addTopLevelItem(layer_item)

    def _show_hex(self, pkt: DecodedPacket) -> None:
        self._hex_view.setPlainText(hex_dump(pkt.raw_bytes))

    # ── Window close ──────────────────────────────────────────

    def closeEvent(self, event) -> None:
        self.engine.stop()
        event.accept()
