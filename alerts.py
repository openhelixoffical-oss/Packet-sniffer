"""
capture.py
captures live packets off the network and pulls out the useful fields
needs admin/root to open a raw socket
"""

import time
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Callable, List, Dict
from collections import deque

try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# common port -> protocol name, makes the output readable
PORT_NAMES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 80: "http", 110: "pop3",
    123: "ntp", 137: "netbios", 138: "netbios", 139: "netbios",
    143: "imap", 161: "snmp", 179: "bgp", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 514: "syslog", 587: "smtp",
    631: "ipp", 636: "ldaps", 853: "dns-tls", 873: "rsync",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1900: "upnp",
    3306: "mysql", 3389: "rdp", 5060: "sip", 5353: "mdns",
    5432: "postgres", 5900: "vnc", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 27017: "mongodb",
}


@dataclass
class Packet:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    proto: str           # tcp, udp, icmp, arp etc
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    length: int = 0
    info: str = ""       # extra detail, e.g. dns query name, tcp flags
    flagged: bool = False
    flag_reason: str = ""

    def service_name(self) -> str:
        """Guess the service based on the lower of src/dst port."""
        for port in (self.dst_port, self.src_port):
            if port and port in PORT_NAMES:
                return PORT_NAMES[port]
        return ""

    def direction_str(self) -> str:
        if self.src_port and self.dst_port:
            return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}"
        return f"{self.src_ip} -> {self.dst_ip}"


class PacketCapture:
    """
    Runs a live capture in a background thread.
    Keeps a rolling buffer of recent packets and running stats.
    """

    def __init__(self, iface: Optional[str] = None, bpf_filter: Optional[str] = None,
                 buffer_size: int = 500, alert_engine=None):
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.buffer_size = buffer_size
        self.alert_engine = alert_engine

        self.packets: deque = deque(maxlen=buffer_size)
        self.lock = threading.Lock()

        self._running = False
        self._thread: Optional[threading.Thread] = None

        # running stats
        self.total_packets = 0
        self.total_bytes = 0
        self.proto_counts: Dict[str, int] = {}
        self.talkers: Dict[str, int] = {}      # ip -> byte count
        self.dns_queries: Dict[str, int] = {}  # hostname -> count
        self.port_counts: Dict[int, int] = {}  # dst port -> count
        self.start_time: Optional[datetime] = None

        self.on_packet: Optional[Callable] = None

    def _parse_packet(self, pkt) -> Optional[Packet]:
        ts = datetime.now()
        length = len(pkt)

        src_ip = dst_ip = None
        proto = "other"
        src_port = dst_port = None
        info = ""

        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
        elif pkt.haslayer(ARP):
            proto = "arp"
            src_ip = pkt[ARP].psrc
            dst_ip = pkt[ARP].pdst
            op = "who-has" if pkt[ARP].op == 1 else "is-at"
            info = f"{op} {dst_ip}"
            return Packet(timestamp=ts, src_ip=src_ip, dst_ip=dst_ip,
                          proto=proto, length=length, info=info)
        else:
            return None

        if pkt.haslayer(TCP):
            proto = "tcp"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            flags = pkt[TCP].flags
            flag_str = self._tcp_flags_str(flags)
            if flag_str:
                info = flag_str

        elif pkt.haslayer(UDP):
            proto = "udp"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

            # DNS query?
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                try:
                    qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                    info = f"dns query: {qname}"
                    with self.lock:
                        self.dns_queries[qname] = self.dns_queries.get(qname, 0) + 1
                except Exception:
                    pass

        elif pkt.haslayer(ICMP):
            proto = "icmp"
            icmp_type = pkt[ICMP].type
            type_names = {0: "echo-reply", 8: "echo-request", 3: "unreachable",
                          11: "time-exceeded", 5: "redirect"}
            info = type_names.get(icmp_type, f"type {icmp_type}")

        return Packet(
            timestamp=ts, src_ip=src_ip, dst_ip=dst_ip, proto=proto,
            src_port=src_port, dst_port=dst_port, length=length, info=info,
        )

    def _tcp_flags_str(self, flags) -> str:
        names = []
        if flags & 0x02: names.append("SYN")
        if flags & 0x10: names.append("ACK")
        if flags & 0x01: names.append("FIN")
        if flags & 0x04: names.append("RST")
        if flags & 0x08: names.append("PSH")
        if flags & 0x20: names.append("URG")
        return ",".join(names)

    def _handle_packet(self, pkt):
        if self.alert_engine:
            try:
                self.alert_engine.check_packet(pkt)
            except Exception:
                pass

        parsed = self._parse_packet(pkt)
        if parsed is None:
            return

        with self.lock:
            self.total_packets += 1
            self.total_bytes += parsed.length
            self.proto_counts[parsed.proto] = self.proto_counts.get(parsed.proto, 0) + 1

            if parsed.src_ip:
                self.talkers[parsed.src_ip] = self.talkers.get(parsed.src_ip, 0) + parsed.length
            if parsed.dst_ip:
                self.talkers[parsed.dst_ip] = self.talkers.get(parsed.dst_ip, 0) + parsed.length

            if parsed.dst_port:
                self.port_counts[parsed.dst_port] = self.port_counts.get(parsed.dst_port, 0) + 1

            self.packets.append(parsed)

        if self.on_packet:
            self.on_packet(parsed)

    def _run(self):
        if not SCAPY_AVAILABLE:
            return
        conf.verb = 0
        try:
            sniff(
                iface=self.iface,
                filter=self.bpf_filter,
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except Exception as e:
            print(f"  capture error: {e}")
            print("  tip: run as administrator and make sure npcap is installed")

    def start(self):
        if not SCAPY_AVAILABLE:
            raise RuntimeError("scapy is not installed")
        self._running = True
        self.start_time = datetime.now()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def get_recent(self, n: int = 30) -> List[Packet]:
        with self.lock:
            return list(self.packets)[-n:]

    def get_stats(self) -> Dict:
        with self.lock:
            elapsed = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
            return {
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "proto_counts": dict(self.proto_counts),
                "top_talkers": sorted(self.talkers.items(), key=lambda x: x[1], reverse=True)[:10],
                "top_ports": sorted(self.port_counts.items(), key=lambda x: x[1], reverse=True)[:10],
                "top_dns": sorted(self.dns_queries.items(), key=lambda x: x[1], reverse=True)[:10],
                "elapsed_seconds": elapsed,
                "packets_per_sec": self.total_packets / elapsed if elapsed > 0 else 0,
            }
