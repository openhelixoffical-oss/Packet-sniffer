"""
pcap_export.py
saves captured packets to a .pcap file you can open in wireshark
"""

try:
    from scapy.all import wrpcap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class PcapWriter:
    """Collects raw packets and writes them to a pcap file on demand."""

    def __init__(self, max_packets: int = 5000):
        self.max_packets = max_packets
        self._packets = []

    def add(self, pkt):
        if len(self._packets) < self.max_packets:
            self._packets.append(pkt)

    def save(self, filename: str) -> int:
        if not SCAPY_AVAILABLE:
            raise RuntimeError("scapy not installed")
        wrpcap(filename, self._packets)
        return len(self._packets)
