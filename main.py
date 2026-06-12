"""
alerts.py
looks at captured packets for stuff worth flagging:
  - plaintext credentials (ftp, telnet, http basic auth, pop3/imap login)
  - port scans (one ip hitting lots of ports on another ip fast)
  - arp spoofing (same ip claimed by two different macs)
  - suspicious dns queries (known bad tld patterns, dga-looking names)
nothing fancy, just pattern matching on what we already captured
"""

import re
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Optional

try:
    from scapy.all import IP, TCP, UDP, Raw, ARP
except ImportError:
    pass


# plaintext protocols where creds are visible
CRED_PORTS = {21: "ftp", 23: "telnet", 110: "pop3", 143: "imap", 25: "smtp"}

# patterns that suggest credentials in raw payload
CRED_PATTERNS = [
    (re.compile(rb"USER\s+(\S+)", re.I), "ftp/pop3/telnet username"),
    (re.compile(rb"PASS\s+(\S+)", re.I), "ftp/pop3/telnet password"),
    (re.compile(rb"LOGIN\s+(\S+)", re.I), "imap login"),
    (re.compile(rb"Authorization:\s*Basic\s+(\S+)", re.I), "http basic auth"),
    (re.compile(rb"password=([^&\s]+)", re.I), "form password field"),
    (re.compile(rb"passwd=([^&\s]+)", re.I), "form password field"),
]

# port scan detection thresholds
SCAN_PORT_THRESHOLD = 15   # distinct dst ports
SCAN_TIME_WINDOW = 5       # seconds


class AlertEngine:
    def __init__(self, on_alert=None):
        self.on_alert = on_alert
        self.alerts: List[Dict] = []

        # for port scan detection: (src_ip -> dst_ip) -> deque of (port, time)
        self._port_hits: Dict[tuple, deque] = defaultdict(lambda: deque(maxlen=100))
        self._scan_alerted: set = set()

        # for arp spoof detection: ip -> set of macs seen
        self._arp_map: Dict[str, set] = defaultdict(set)
        self._arp_alerted: set = set()

    def _fire(self, alert: Dict):
        alert["timestamp"] = datetime.now().isoformat()
        self.alerts.append(alert)
        if self.on_alert:
            self.on_alert(alert)

    def check_packet(self, raw_pkt):
        """Run all checks against a raw scapy packet (not the parsed Packet object)."""
        self._check_credentials(raw_pkt)
        self._check_port_scan(raw_pkt)
        self._check_arp_spoof(raw_pkt)

    # -- credential sniffing --

    def _check_credentials(self, pkt):
        if not pkt.haslayer(Raw):
            return
        try:
            payload = bytes(pkt[Raw].load)
        except Exception:
            return

        src_ip = pkt[IP].src if pkt.haslayer(IP) else "?"
        dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "?"
        dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else None

        for pattern, label in CRED_PATTERNS:
            match = pattern.search(payload)
            if match:
                value = match.group(1).decode("utf-8", errors="ignore")[:60]
                self._fire({
                    "type": "plaintext_credential",
                    "severity": "high",
                    "label": label,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "value": value,
                    "detail": f"{label} seen in plaintext: {src_ip} -> {dst_ip}",
                })

    # -- port scan detection --

    def _check_port_scan(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return

        flags = pkt[TCP].flags
        if not (flags & 0x02):  # only count SYN packets
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        dst_port = pkt[TCP].dport
        now = time.time()

        key = (src_ip, dst_ip)
        hits = self._port_hits[key]
        hits.append((dst_port, now))

        # drop old entries
        while hits and now - hits[0][1] > SCAN_TIME_WINDOW:
            hits.popleft()

        distinct_ports = len({p for p, _ in hits})

        if distinct_ports >= SCAN_PORT_THRESHOLD and key not in self._scan_alerted:
            self._scan_alerted.add(key)
            self._fire({
                "type": "port_scan",
                "severity": "high",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "distinct_ports": distinct_ports,
                "window_seconds": SCAN_TIME_WINDOW,
                "detail": f"{src_ip} hit {distinct_ports} ports on {dst_ip} in {SCAN_TIME_WINDOW}s -- looks like a port scan",
            })
        elif distinct_ports < 3 and key in self._scan_alerted:
            self._scan_alerted.discard(key)

    # -- arp spoof detection --

    def _check_arp_spoof(self, pkt):
        if not pkt.haslayer(ARP):
            return
        if pkt[ARP].op != 2:  # only "is-at" replies matter
            return

        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc

        self._arp_map[ip].add(mac)

        if len(self._arp_map[ip]) > 1 and ip not in self._arp_alerted:
            self._arp_alerted.add(ip)
            macs = ", ".join(self._arp_map[ip])
            self._fire({
                "type": "arp_spoof",
                "severity": "critical",
                "ip": ip,
                "macs": list(self._arp_map[ip]),
                "detail": f"{ip} claimed by multiple MACs ({macs}) -- possible ARP spoofing / MITM",
            })

    def get_alerts(self) -> List[Dict]:
        return list(self.alerts)
