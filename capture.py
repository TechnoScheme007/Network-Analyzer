"""Packet capture and decoding engine.

Two backends:
  1. Raw sockets (Windows built-in) — no external dependencies, captures IP-level packets
  2. Scapy (optional)             — Ethernet frames, ARP, full BPF filters

Automatically picks the best available backend.
"""
from __future__ import annotations

import platform
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

# ── Optional scapy import ─────────────────────────────────────

try:
    from scapy.all import (
        ARP,
        DNS,
        ICMP,
        IP,
        TCP,
        UDP,
        AsyncSniffer,
        Ether,
        IPv6,
        Raw,
        conf,
        get_if_list,
        wrpcap,
    )

    conf.verb = 0

    def _scapy_has_pcap() -> bool:
        """Check whether scapy can actually open interfaces (Npcap present)."""
        try:
            return bool(getattr(conf, "use_pcap", False) or getattr(conf, "use_npcap", False))
        except Exception:
            return False

    HAS_SCAPY = True
    HAS_PCAP = _scapy_has_pcap()
except ImportError:
    HAS_SCAPY = False
    HAS_PCAP = False

SYSTEM = platform.system()

# ── ICMP / HTTP constants ─────────────────────────────────────

ICMP_TYPES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    4: "Source Quench",
    5: "Redirect",
    8: "Echo Request",
    9: "Router Advertisement",
    10: "Router Solicitation",
    11: "Time Exceeded",
    13: "Timestamp Request",
    14: "Timestamp Reply",
}

HTTP_METHODS = [b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"PATCH ", b"OPTIONS ", b"HTTP/"]


# ── Data classes ──────────────────────────────────────────────

@dataclass
class DecodedPacket:
    """A captured packet with decoded protocol layers."""

    number: int
    timestamp: float
    src_mac: str
    dst_mac: str
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: Optional[int]
    dst_port: Optional[int]
    length: int
    info: str
    layers: list[tuple[str, dict[str, Any]]]
    raw_bytes: bytes
    scapy_pkt: Any  # None when using raw-socket backend


# ── Hex dump ──────────────────────────────────────────────────

def hex_dump(data: bytes) -> str:
    """Format raw bytes as a hex dump with ASCII sidebar."""
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset : offset + 16]
        hex_parts: list[str] = []
        for i, b in enumerate(chunk):
            if i == 8:
                hex_parts.append("")
            hex_parts.append(f"{b:02x}")
        hex_str = " ".join(hex_parts)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:04x}  {hex_str:<50s} {ascii_str}")
    return "\n".join(lines)


# ── Interface discovery ───────────────────────────────────────

def get_default_ip() -> str:
    """Detect the machine's primary outbound IP address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return ""


def get_interfaces() -> list[tuple[str, str, str]]:
    """Return [(iface_id, display_label, ip), ...].

    Active interface (matching default gateway) is sorted first.
    Uses scapy if available, otherwise falls back to socket-based discovery.
    """
    default_ip = get_default_ip()

    if HAS_SCAPY:
        result = _get_scapy_interfaces(default_ip)
        if result:
            return result

    return _get_socket_interfaces(default_ip)


def _get_scapy_interfaces(default_ip: str) -> list[tuple[str, str, str]]:
    try:
        ifaces = conf.ifaces
        result: list[tuple[str, str, str]] = []
        for iface in ifaces.values():
            name = getattr(iface, "name", str(iface))
            desc = getattr(iface, "description", name)
            ip = getattr(iface, "ip", "")
            label = str(desc)
            if ip:
                label += f" ({ip})"
            result.append((name, label, ip))
        if default_ip:
            result.sort(key=lambda item: item[2] != default_ip)
        return result
    except Exception:
        return []


def _get_socket_interfaces(default_ip: str) -> list[tuple[str, str, str]]:
    ips: list[str] = []

    # Gather all local IPv4 addresses
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip not in ips and ip != "127.0.0.1":
                ips.append(ip)
    except Exception:
        pass

    if default_ip and default_ip not in ips:
        ips.insert(0, default_ip)

    result = [(ip, f"Network Interface ({ip})", ip) for ip in ips]

    # Active interface first
    if default_ip:
        result.sort(key=lambda x: x[2] != default_ip)

    return result if result else [("127.0.0.1", "Loopback (127.0.0.1)", "127.0.0.1")]


# ── Simple filter compiler (raw-socket mode) ─────────────────
#
#   Supports:  tcp  udp  icmp
#              host 1.2.3.4 / src host … / dst host …
#              port 80      / src port … / dst port …
#              combined with 'and'
# ──────────────────────────────────────────────────────────────


def _proto_match(num: int):
    return lambda proto=0, **_: proto == num


def _host_match(addr: str, direction: str | None = None):
    if direction == "src":
        return lambda src_ip="", **_: src_ip == addr
    if direction == "dst":
        return lambda dst_ip="", **_: dst_ip == addr
    return lambda src_ip="", dst_ip="", **_: src_ip == addr or dst_ip == addr


def _port_match(port: int, direction: str | None = None):
    if direction == "src":
        return lambda src_port=0, **_: src_port == port
    if direction == "dst":
        return lambda dst_port=0, **_: dst_port == port
    return lambda src_port=0, dst_port=0, **_: src_port == port or dst_port == port


def compile_filter(filter_str: str):
    """Compile a BPF-like filter string into a Python predicate."""
    if not filter_str.strip():
        return lambda **_: True

    tokens = filter_str.lower().split()
    conditions: list[Callable[..., bool]] = []
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t in ("and", "&&"):
            pass
        elif t == "tcp":
            conditions.append(_proto_match(6))
        elif t == "udp":
            conditions.append(_proto_match(17))
        elif t == "icmp":
            conditions.append(_proto_match(1))
        elif t in ("src", "dst") and i + 2 < len(tokens):
            direction = t
            kind = tokens[i + 1]
            value = tokens[i + 2]
            if kind == "host":
                conditions.append(_host_match(value, direction))
            elif kind == "port":
                conditions.append(_port_match(int(value), direction))
            i += 2
        elif t == "host" and i + 1 < len(tokens):
            conditions.append(_host_match(tokens[i + 1]))
            i += 1
        elif t == "port" and i + 1 < len(tokens):
            conditions.append(_port_match(int(tokens[i + 1])))
            i += 1
        i += 1

    if not conditions:
        return lambda **_: True
    return lambda **kw: all(c(**kw) for c in conditions)


# ── PCAP writer (no scapy needed) ────────────────────────────

PCAP_MAGIC = 0xA1B2C3D4
PCAP_LINKTYPE_RAW_IP = 101  # DLT_RAW
PCAP_LINKTYPE_ETHERNET = 1


def write_pcap_file(filepath: str, packets: list[tuple[float, bytes]], linktype: int = PCAP_LINKTYPE_RAW_IP) -> int:
    """Write packets to a .pcap file using the standard format."""
    with open(filepath, "wb") as f:
        f.write(
            struct.pack(
                "<IHHiIII",
                PCAP_MAGIC,
                2, 4,      # version
                0, 0,      # timezone, sigfigs
                65535,      # snaplen
                linktype,
            )
        )
        for ts, data in packets:
            ts_sec = int(ts)
            ts_usec = int((ts - ts_sec) * 1_000_000)
            length = len(data)
            f.write(struct.pack("<IIII", ts_sec, ts_usec, length, length))
            f.write(data)
    return len(packets)


# ── DNS mini-parser (raw-socket mode) ─────────────────────────

def _try_parse_dns(data: bytes) -> str | None:
    """Parse a DNS header and return a human-readable summary."""
    if len(data) < 12:
        return None
    try:
        flags = struct.unpack("!H", data[2:4])[0]
        qr = (flags >> 15) & 1
        an_count = struct.unpack("!H", data[6:8])[0]

        # Parse first question name
        offset = 12
        labels: list[str] = []
        while offset < len(data) and data[offset] != 0:
            length = data[offset]
            if length > 63:
                break
            offset += 1
            if offset + length > len(data):
                break
            labels.append(data[offset : offset + length].decode(errors="replace"))
            offset += length
        qname = ".".join(labels) if labels else "?"

        if qr == 0:
            return f"Query: {qname}"
        return f"Response: {an_count} answer(s)"
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════
#  Capture Engine
# ══════════════════════════════════════════════════════════════

class CaptureEngine:
    """Manages packet capture.  Automatically selects the best backend."""

    DEFAULT_MAX_PACKETS = 500

    def __init__(self) -> None:
        self.packets: list[DecodedPacket] = []
        self.running = False
        self.backend = ""  # "scapy" or "raw"
        self.max_packets: int = self.DEFAULT_MAX_PACKETS
        self.on_limit_reached: Callable[[], None] | None = None
        self._counter = 0
        self._start_time = 0.0
        self._abs_start_time = 0.0
        self._callback: Callable[[DecodedPacket], None] | None = None
        # scapy backend
        self._sniffer: Any = None
        # raw-socket backend
        self._raw_sock: socket.socket | None = None
        self._raw_thread: threading.Thread | None = None
        self._raw_filter: Callable[..., bool] | None = None

    # ── Public API ────────────────────────────────────────────

    def start(
        self,
        interface: str,
        bpf_filter: str = "",
        callback: Callable[[DecodedPacket], None] | None = None,
    ) -> str:
        """Start capturing.  Returns the backend name used ("scapy" or "raw")."""
        if self.running:
            return self.backend

        self.packets.clear()
        self._counter = 0
        self._start_time = time.time()
        self._abs_start_time = time.time()
        self._callback = callback
        self.running = True

        # Try scapy first (if available and pcap driver is present)
        if HAS_SCAPY and HAS_PCAP:
            try:
                self._start_scapy(interface, bpf_filter)
                self.backend = "scapy"
                return self.backend
            except Exception:
                pass  # fall through to raw sockets

        # Raw-socket fallback
        if SYSTEM == "Windows":
            ip = self._resolve_to_ip(interface)
            self._start_raw_win(ip, bpf_filter)
            self.backend = "raw"
            return self.backend

        if SYSTEM == "Linux":
            self._start_raw_linux(interface, bpf_filter)
            self.backend = "raw"
            return self.backend

        self.running = False
        raise RuntimeError(
            "No capture backend available.\n"
            "Install scapy + libpcap, or run on Windows/Linux for raw-socket capture."
        )

    def stop(self) -> None:
        self.running = False
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None
        if self._raw_sock is not None:
            try:
                self._raw_sock.close()
            except Exception:
                pass
            self._raw_sock = None
        if self._raw_thread is not None:
            self._raw_thread.join(timeout=3)
            self._raw_thread = None

    def export_pcap(self, filepath: str, indices: list[int] | None = None) -> int:
        """Export captured packets to a .pcap file."""
        selected = [self.packets[i] for i in indices] if indices else self.packets

        # Prefer scapy writer when we have scapy packets
        if HAS_SCAPY and selected and selected[0].scapy_pkt is not None:
            wrpcap(filepath, [p.scapy_pkt for p in selected])
            return len(selected)

        # Manual writer (raw-socket packets → DLT_RAW / Raw IP)
        raw_data = [(self._abs_start_time + p.timestamp, p.raw_bytes) for p in selected]
        return write_pcap_file(filepath, raw_data, PCAP_LINKTYPE_RAW_IP)

    # ── Scapy backend ────────────────────────────────────────

    def _start_scapy(self, interface: str, bpf_filter: str) -> None:
        kwargs: dict[str, Any] = {
            "iface": interface,
            "prn": self._on_scapy_pkt,
            "store": False,
        }
        if bpf_filter.strip():
            kwargs["filter"] = bpf_filter.strip()
        self._sniffer = AsyncSniffer(**kwargs)
        self._sniffer.start()

    def _check_limit(self) -> None:
        """Stop capture if packet limit reached."""
        if self.max_packets > 0 and len(self.packets) >= self.max_packets:
            self.stop()
            if self.on_limit_reached:
                self.on_limit_reached()

    def _on_scapy_pkt(self, pkt: Any) -> None:
        if not self.running:
            return
        self._counter += 1
        try:
            decoded = self._decode_scapy(pkt, self._counter)
            self.packets.append(decoded)
            if self._callback:
                self._callback(decoded)
            self._check_limit()
        except Exception:
            pass

    def _decode_scapy(self, pkt: Any, number: int) -> DecodedPacket:
        ts = float(pkt.time) - self._start_time
        raw = bytes(pkt)
        layers: list[tuple[str, dict[str, Any]]] = []
        src_mac = dst_mac = src_ip = dst_ip = ""
        protocol = "OTHER"
        src_port: int | None = None
        dst_port: int | None = None
        info = ""

        if pkt.haslayer(Ether):
            eth = pkt[Ether]
            src_mac, dst_mac = eth.src, eth.dst
            layers.append(("Ethernet", {"Source MAC": eth.src, "Destination MAC": eth.dst, "EtherType": f"0x{eth.type:04x}"}))

        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            protocol, src_ip, dst_ip = "ARP", arp.psrc, arp.pdst
            info = f"Who has {arp.pdst}? Tell {arp.psrc}" if arp.op == 1 else f"{arp.psrc} is at {arp.hwsrc}"
            layers.append(("ARP", {"Operation": "Request" if arp.op == 1 else "Reply", "Sender MAC": arp.hwsrc, "Sender IP": arp.psrc, "Target MAC": arp.hwdst, "Target IP": arp.pdst}))

        if pkt.haslayer(IP):
            ip = pkt[IP]
            src_ip, dst_ip = ip.src, ip.dst
            layers.append(("IPv4", {"Version": ip.version, "Header Length": f"{ip.ihl * 4} bytes", "TTL": ip.ttl, "Protocol": ip.proto, "Source": ip.src, "Destination": ip.dst, "Total Length": ip.len, "Identification": ip.id, "Flags": str(ip.flags), "Checksum": f"0x{ip.chksum:04x}" if ip.chksum else "N/A"}))
        elif pkt.haslayer(IPv6):
            ip6 = pkt[IPv6]
            src_ip, dst_ip = ip6.src, ip6.dst
            layers.append(("IPv6", {"Source": ip6.src, "Destination": ip6.dst, "Traffic Class": ip6.tc, "Flow Label": ip6.fl, "Payload Length": ip6.plen, "Next Header": ip6.nh, "Hop Limit": ip6.hlim}))

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            protocol, src_port, dst_port = "TCP", tcp.sport, tcp.dport
            flags = str(tcp.flags)
            info = f"{tcp.sport} -> {tcp.dport} [{flags}] Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window}"
            layers.append(("TCP", {"Source Port": tcp.sport, "Destination Port": tcp.dport, "Sequence Number": tcp.seq, "Acknowledgment": tcp.ack, "Flags": flags, "Window Size": tcp.window, "Checksum": f"0x{tcp.chksum:04x}" if tcp.chksum else "N/A", "Urgent Pointer": tcp.urgptr}))
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            protocol, src_port, dst_port = "UDP", udp.sport, udp.dport
            info = f"{udp.sport} -> {udp.dport} Len={udp.len}"
            layers.append(("UDP", {"Source Port": udp.sport, "Destination Port": udp.dport, "Length": udp.len, "Checksum": f"0x{udp.chksum:04x}" if udp.chksum else "N/A"}))
        elif pkt.haslayer(ICMP):
            ic = pkt[ICMP]
            protocol = "ICMP"
            tn = ICMP_TYPES.get(ic.type, f"Type {ic.type}")
            info = f"{tn} (type={ic.type}, code={ic.code})"
            fields: dict[str, Any] = {"Type": f"{ic.type} ({tn})", "Code": ic.code, "Checksum": f"0x{ic.chksum:04x}" if ic.chksum else "N/A"}
            if hasattr(ic, "id") and ic.id is not None:
                fields["Identifier"] = ic.id
            if hasattr(ic, "seq") and ic.seq is not None:
                fields["Sequence"] = ic.seq
            layers.append(("ICMP", fields))

        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            protocol = "DNS"
            if dns.qr == 0 and dns.qd:
                info = f"Query: {dns.qd.qname.decode(errors='replace').rstrip('.')}"
            elif dns.qr == 1:
                info = f"Response: {dns.ancount} answer(s)"
            layers.append(("DNS", {"Type": "Response" if dns.qr else "Query", "Opcode": dns.opcode, "Questions": dns.qdcount, "Answers": dns.ancount}))

        if pkt.haslayer(Raw) and protocol == "TCP":
            payload = pkt[Raw].load
            for method in HTTP_METHODS:
                if payload.startswith(method):
                    protocol = "HTTP"
                    try:
                        info = payload.split(b"\r\n")[0].decode(errors="replace")
                    except Exception:
                        info = payload[:80].decode(errors="replace")
                    break

        if pkt.haslayer(Raw):
            layers.append(("Payload", {"Length": f"{len(pkt[Raw].load)} bytes"}))

        if not info:
            info = pkt.summary()

        return DecodedPacket(number=number, timestamp=ts, src_mac=src_mac, dst_mac=dst_mac, src_ip=src_ip or src_mac, dst_ip=dst_ip or dst_mac, protocol=protocol, src_port=src_port, dst_port=dst_port, length=len(raw), info=info, layers=layers, raw_bytes=raw, scapy_pkt=pkt)

    # ── Raw-socket backend (Windows) ──────────────────────────

    def _resolve_to_ip(self, interface: str) -> str:
        """Convert an interface identifier to an IP address for binding."""
        try:
            socket.inet_aton(interface)
            return interface
        except OSError:
            pass
        if HAS_SCAPY:
            try:
                iface_obj = conf.ifaces.dev_from_name(interface)
                ip = getattr(iface_obj, "ip", "")
                if ip:
                    return ip
            except Exception:
                pass
        return get_default_ip() or "0.0.0.0"

    def _start_raw_win(self, bind_ip: str, bpf_filter: str) -> None:
        self._raw_filter = compile_filter(bpf_filter)
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sock.bind((bind_ip, 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        sock.settimeout(0.5)
        self._raw_sock = sock
        self._raw_thread = threading.Thread(target=self._raw_loop_win, daemon=True)
        self._raw_thread.start()

    def _raw_loop_win(self) -> None:
        sock = self._raw_sock
        try:
            while self.running and sock is not None:
                try:
                    data, _ = sock.recvfrom(65535)
                    self._process_raw_packet(data)
                except socket.timeout:
                    continue
                except OSError:
                    break
        finally:
            try:
                if sock:
                    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                    sock.close()
            except Exception:
                pass

    # ── Raw-socket backend (Linux) ────────────────────────────

    def _start_raw_linux(self, interface: str, bpf_filter: str) -> None:
        self._raw_filter = compile_filter(bpf_filter)
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        if interface and interface != "any":
            sock.bind((interface, 0))
        sock.settimeout(0.5)
        self._raw_sock = sock
        self._raw_thread = threading.Thread(target=self._raw_loop_linux, daemon=True)
        self._raw_thread.start()

    def _raw_loop_linux(self) -> None:
        sock = self._raw_sock
        try:
            while self.running and sock is not None:
                try:
                    data, _ = sock.recvfrom(65535)
                    # Linux AF_PACKET gives full Ethernet frame
                    if len(data) >= 14:
                        ethertype = struct.unpack("!H", data[12:14])[0]
                        if ethertype == 0x0800:  # IPv4
                            self._process_raw_packet(data[14:], eth_header=data[:14])
                except socket.timeout:
                    continue
                except OSError:
                    break
        finally:
            try:
                if sock:
                    sock.close()
            except Exception:
                pass

    # ── Raw packet processing ─────────────────────────────────

    def _process_raw_packet(self, ip_data: bytes, eth_header: bytes | None = None) -> None:
        if len(ip_data) < 20:
            return

        version = (ip_data[0] >> 4) & 0xF
        if version != 4:
            return

        ihl = (ip_data[0] & 0xF) * 4
        if len(ip_data) < ihl:
            return

        proto_num = ip_data[9]
        src_ip = socket.inet_ntoa(ip_data[12:16])
        dst_ip = socket.inet_ntoa(ip_data[16:20])
        payload = ip_data[ihl:]

        # Parse ports for filtering
        src_port = dst_port = 0
        if proto_num in (6, 17) and len(payload) >= 4:
            src_port, dst_port = struct.unpack("!HH", payload[:4])

        # Apply filter
        if self._raw_filter and not self._raw_filter(
            proto=proto_num, src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port,
        ):
            return

        if not self.running:
            return
        self._counter += 1
        decoded = self._decode_raw(ip_data, self._counter, eth_header)
        if decoded:
            self.packets.append(decoded)
            if self._callback:
                self._callback(decoded)
            self._check_limit()

    def _decode_raw(self, ip_data: bytes, number: int, eth_header: bytes | None = None) -> DecodedPacket | None:
        ts = time.time() - self._start_time
        layers: list[tuple[str, dict[str, Any]]] = []

        src_mac = dst_mac = ""
        src_ip = dst_ip = ""
        protocol = "OTHER"
        proto_num = 0
        src_port: int | None = None
        dst_port: int | None = None
        info = ""

        full_raw = (eth_header or b"") + ip_data

        # ── Ethernet (Linux only) ──
        if eth_header and len(eth_header) >= 14:
            dst_mac = ":".join(f"{b:02x}" for b in eth_header[0:6])
            src_mac = ":".join(f"{b:02x}" for b in eth_header[6:12])
            ethertype = struct.unpack("!H", eth_header[12:14])[0]
            layers.append(("Ethernet", {"Source MAC": src_mac, "Destination MAC": dst_mac, "EtherType": f"0x{ethertype:04x}"}))

        # ── IPv4 ──
        ihl = (ip_data[0] & 0xF) * 4
        total_length = struct.unpack("!H", ip_data[2:4])[0]
        identification = struct.unpack("!H", ip_data[4:6])[0]
        flags_offset = struct.unpack("!H", ip_data[6:8])[0]
        ttl = ip_data[8]
        proto_num = ip_data[9]
        checksum = struct.unpack("!H", ip_data[10:12])[0]
        src_ip = socket.inet_ntoa(ip_data[12:16])
        dst_ip = socket.inet_ntoa(ip_data[16:20])

        ip_flags_list = []
        if (flags_offset >> 14) & 1:
            ip_flags_list.append("DF")
        if (flags_offset >> 13) & 1:
            ip_flags_list.append("MF")

        layers.append(("IPv4", {
            "Version": 4,
            "Header Length": f"{ihl} bytes",
            "TTL": ttl,
            "Protocol": proto_num,
            "Source": src_ip,
            "Destination": dst_ip,
            "Total Length": total_length,
            "Identification": identification,
            "Flags": ", ".join(ip_flags_list) if ip_flags_list else "none",
            "Checksum": f"0x{checksum:04x}",
        }))

        payload = ip_data[ihl:]

        # ── TCP ──
        if proto_num == 6 and len(payload) >= 20:
            protocol = "TCP"
            sp, dp, seq, ack, off_flags, win, tcp_chk, urg = struct.unpack("!HHIIHHHH", payload[:20])
            src_port, dst_port = sp, dp
            data_offset = (off_flags >> 12) * 4
            flags = off_flags & 0x3F
            flag_chars = []
            if flags & 0x20: flag_chars.append("U")
            if flags & 0x10: flag_chars.append("A")
            if flags & 0x08: flag_chars.append("P")
            if flags & 0x04: flag_chars.append("R")
            if flags & 0x02: flag_chars.append("S")
            if flags & 0x01: flag_chars.append("F")
            flag_str = "".join(flag_chars) or "none"
            info = f"{sp} -> {dp} [{flag_str}] Seq={seq} Ack={ack} Win={win}"
            layers.append(("TCP", {"Source Port": sp, "Destination Port": dp, "Sequence Number": seq, "Acknowledgment": ack, "Flags": flag_str, "Window Size": win, "Checksum": f"0x{tcp_chk:04x}", "Urgent Pointer": urg}))

            tcp_payload = payload[data_offset:] if data_offset <= len(payload) else b""
            if tcp_payload:
                layers.append(("Payload", {"Length": f"{len(tcp_payload)} bytes"}))
                for method in HTTP_METHODS:
                    if tcp_payload.startswith(method):
                        protocol = "HTTP"
                        try:
                            info = tcp_payload.split(b"\r\n")[0].decode(errors="replace")
                        except Exception:
                            info = tcp_payload[:80].decode(errors="replace")
                        break
                if protocol != "HTTP" and (sp == 53 or dp == 53) and len(tcp_payload) > 14:
                    dns_info = _try_parse_dns(tcp_payload[2:])
                    if dns_info:
                        protocol, info = "DNS", dns_info

        # ── UDP ──
        elif proto_num == 17 and len(payload) >= 8:
            protocol = "UDP"
            sp, dp, udp_len, udp_chk = struct.unpack("!HHHH", payload[:8])
            src_port, dst_port = sp, dp
            info = f"{sp} -> {dp} Len={udp_len}"
            layers.append(("UDP", {"Source Port": sp, "Destination Port": dp, "Length": udp_len, "Checksum": f"0x{udp_chk:04x}"}))

            udp_payload = payload[8:]
            if udp_payload:
                layers.append(("Payload", {"Length": f"{len(udp_payload)} bytes"}))
                if (sp == 53 or dp == 53) and len(udp_payload) >= 12:
                    dns_info = _try_parse_dns(udp_payload)
                    if dns_info:
                        protocol, info = "DNS", dns_info

        # ── ICMP ──
        elif proto_num == 1 and len(payload) >= 8:
            protocol = "ICMP"
            icmp_type, icmp_code, icmp_chk, icmp_id, icmp_seq = struct.unpack("!BBHHH", payload[:8])
            tn = ICMP_TYPES.get(icmp_type, f"Type {icmp_type}")
            info = f"{tn} (type={icmp_type}, code={icmp_code})"
            layers.append(("ICMP", {"Type": f"{icmp_type} ({tn})", "Code": icmp_code, "Checksum": f"0x{icmp_chk:04x}", "Identifier": icmp_id, "Sequence": icmp_seq}))

        if not info:
            info = f"Protocol {proto_num}, {len(ip_data)} bytes"

        return DecodedPacket(
            number=number, timestamp=ts, src_mac=src_mac, dst_mac=dst_mac,
            src_ip=src_ip, dst_ip=dst_ip, protocol=protocol,
            src_port=src_port, dst_port=dst_port, length=len(full_raw),
            info=info, layers=layers, raw_bytes=full_raw, scapy_pkt=None,
        )
