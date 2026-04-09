#!/usr/bin/env python3
"""Network Analyzer - Lightweight packet capture and analysis tool.

Requires administrator/root privileges to capture packets.
Works without Npcap on Windows using raw sockets.
Optionally uses Scapy + Npcap for enhanced capture (Ethernet, ARP, BPF filters).
"""
import platform
import sys


def check_privileges() -> None:
    """Exit with a clear message if not running with admin/root."""
    if platform.system() == "Windows":
        import ctypes

        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("=" * 60)
            print("  ERROR: Administrator privileges required.")
            print()
            print("  Right-click your terminal or IDE and")
            print("  select 'Run as Administrator', then retry.")
            print("=" * 60)
            sys.exit(1)
    else:
        import os

        if os.getuid() != 0:
            print("ERROR: Root privileges required.")
            print("Run with:  sudo python main.py")
            sys.exit(1)


def check_dependencies() -> None:
    """Verify PySide6 is installed.  Scapy is optional."""
    try:
        import PySide6  # noqa: F401
    except ImportError:
        print("ERROR: PySide6 is not installed.")
        print("Run:  pip install -r requirements.txt")
        sys.exit(1)


def main() -> None:
    check_privileges()
    check_dependencies()

    from PySide6.QtWidgets import QApplication

    from app import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("Network Analyzer")
    app.setStyle("Fusion")

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
