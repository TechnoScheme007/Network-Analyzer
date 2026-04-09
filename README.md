# Network Analyzer

A lightweight, open-source packet capture and analysis tool with a native desktop GUI. Built entirely in Python, it provides real-time network traffic inspection with protocol decoding, filtering, hex dump viewing, and PCAP export — no third-party capture drivers required on Windows.

---

## Features

- **Live Packet Capture** — real-time capture on any network interface
- **Protocol Decoding** — full layer-by-layer breakdown of Ethernet, IPv4/IPv6, TCP, UDP, ICMP, ARP, DNS, and HTTP
- **Filtering** — BPF-style filter syntax to isolate specific traffic (`tcp port 443`, `host 10.0.0.1`, etc.)
- **Packet Detail Inspector** — expandable tree view showing every field in every protocol layer
- **Hex Dump View** — raw packet bytes displayed in classic offset + hex + ASCII format
- **PCAP Export** — save captured packets to standard `.pcap` files, compatible with Wireshark and tcpdump
- **Configurable Packet Limit** — auto-stops capture at a user-defined threshold (default: 500) to prevent memory issues
- **Color-Coded Protocols** — each protocol type is highlighted with a distinct row color for quick visual scanning
- **Zero External Drivers** — works out of the box on Windows using raw sockets; optionally supports Scapy + Npcap for enhanced capture
- **Auto-Detects Active Interface** — automatically selects the network interface with the default gateway IP

## Screenshots

<!-- Add screenshots of your running application here -->
<!-- ![Main Window](screenshots/main.png) -->

## Architecture

```
network-analyzer/
    main.py             Entry point — privilege check, dependency check, app launch
    capture.py          Capture engine — dual backend (raw sockets / Scapy), protocol
                        decoders, filter compiler, hex dump formatter, PCAP writer
    app.py              Desktop GUI — PySide6 (Qt) window with packet table,
                        detail tree, hex dump panel, toolbar controls
    requirements.txt    Python dependencies
```

### Capture Backends

The application automatically selects the best available capture backend:

| | Raw Sockets (default) | Scapy + Npcap (optional) |
|---|---|---|
| **Extra installs** | None | `pip install scapy` + [Npcap](https://npcap.com/) |
| **Protocols captured** | IPv4, TCP, UDP, ICMP, DNS, HTTP | + Ethernet frames, ARP, IPv6 |
| **Filter engine** | Built-in Python filter compiler | Full Berkeley Packet Filter (BPF) |
| **PCAP export** | Built-in writer (DLT_RAW) | Via Scapy (DLT_EN10MB) |
| **Platform** | Windows, Linux | Windows, Linux, macOS |

The raw socket backend requires no external capture libraries. On Windows, it uses `SIO_RCVALL` to receive all IP traffic on the bound interface. If Scapy and Npcap are installed, the engine upgrades to the Scapy backend automatically for richer protocol support.

## Requirements

- **Python 3.10+**
- **PySide6** (Qt for Python) — installed via `pip`
- **Administrator / root privileges** — required for raw packet capture on all platforms

### Optional (Enhanced Capture)

- **[Scapy](https://scapy.net/)** — `pip install scapy`
- **[Npcap](https://npcap.com/)** (Windows only) — check *"WinPcap API-compatible Mode"* during installation

## Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/network-analyzer.git
cd network-analyzer

# Install dependencies
pip install -r requirements.txt
```

## Usage

> **Important:** This tool must be run with elevated privileges to capture network packets.

### Windows

Right-click **Command Prompt**, **PowerShell**, or **Windows Terminal** and select **Run as Administrator**:

```
python main.py
```

### Linux

```bash
sudo python main.py
```

### macOS

Requires Scapy + libpcap (included with macOS):

```bash
pip install scapy
sudo python main.py
```

## Quick Start

1. Launch the application with administrator/root privileges
2. The active network interface is pre-selected in the **Interface** dropdown
3. *(Optional)* Enter a filter expression in the **Filter** field
4. Click **Start** to begin capturing
5. Click any packet row to inspect its decoded layers and hex dump
6. Click **Stop** when finished
7. Click **Export PCAP** to save the capture to a `.pcap` file

## Filter Syntax

The built-in filter engine supports standard BPF-style expressions:

| Filter | Description |
|---|---|
| `tcp` | All TCP packets |
| `udp` | All UDP packets |
| `icmp` | All ICMP packets |
| `tcp port 443` | HTTPS traffic |
| `udp port 53` | DNS queries |
| `host 192.168.1.1` | All traffic to/from a specific IP |
| `src host 10.0.0.1` | Traffic originating from a specific IP |
| `dst port 80` | Traffic destined to port 80 |
| `tcp port 443 and host 10.0.0.1` | Combined filter with `and` |

> **Note:** When using the Scapy backend, the full BPF syntax is supported, including `net`, `not`, `or`, and more complex expressions.

## Keyboard Shortcuts

| Key | Action |
|---|---|
| `F5` | Start capture |
| `F6` | Stop capture |
| `Ctrl+E` | Export captured packets to `.pcap` |
| `Ctrl+K` | Clear all captured packets |
| `Ctrl+Q` | Quit the application |
| `Up / Down` | Navigate the packet list |

## Decoded Protocols

Each captured packet is decoded into its constituent layers with full field extraction:

| Layer | Fields Decoded |
|---|---|
| **Ethernet** | Source/Destination MAC, EtherType |
| **IPv4** | Source/Destination IP, TTL, Protocol, Flags, Header Length, Checksum |
| **IPv6** | Source/Destination IP, Traffic Class, Flow Label, Hop Limit |
| **TCP** | Source/Destination Port, Seq/Ack Numbers, Flags (SYN, ACK, FIN, etc.), Window Size |
| **UDP** | Source/Destination Port, Length, Checksum |
| **ICMP** | Type (Echo Request/Reply, Dest Unreachable, etc.), Code, Identifier, Sequence |
| **ARP** | Operation (Request/Reply), Sender/Target MAC and IP |
| **DNS** | Query/Response, Question Name, Answer Count |
| **HTTP** | Method, URI, and first line of request/response (detected from TCP payload) |

## Troubleshooting

| Problem | Solution |
|---|---|
| *"Administrator privileges required"* | Right-click your terminal and select **Run as Administrator** (Windows) or use `sudo` (Linux/macOS) |
| No packets captured | Verify you selected the correct interface (look for your IP address in the dropdown) |
| Filter shows no results | Most web traffic uses port **443** (HTTPS), not port 80. Try `tcp port 443` instead of `tcp port 80` |
| *"Capture Error"* on Start | If using Scapy backend, ensure Npcap is installed with WinPcap compatibility mode |
| Application won't launch | Run `pip install -r requirements.txt` to install PySide6 |

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
