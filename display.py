"""
demo.py
fake traffic generator for demo mode -- no admin/npcap needed
plays out a loop of staged "attack scenarios" so the dashboard always has
something happening. useful for showing off the tool or testing the ui
without waiting around for real suspicious traffic.

scenarios included:
  - port scan
  - ssh brute force
  - plaintext ftp login caught
  - arp spoofing / mitm
  - dns tunneling / beaconing
  - sql injection attempt
  - malware c2 callback
"""

import random
import threading
import time
from datetime import datetime
from collections import deque
from typing import Optional, Callable, List, Dict

from .capture import Packet, PORT_NAMES


# fake but plausible-looking ips for the demo
LOCAL_IPS = ["192.168.1.10", "192.168.1.22", "192.168.1.34", "192.168.1.50"]
ROUTER_IP = "192.168.1.1"
EXTERNAL_IPS = ["45.33.32.156", "104.131.6.18", "198.199.64.217", "23.249.162.161",
                "8.8.8.8", "1.1.1.1", "151.101.1.69", "104.21.10.7"]
ATTACKER_IP = "192.168.1.66"  # the "bad" device for most scenarios

SUSPICIOUS_DOMAINS = [
    "a8f3e9c1b2d4.evil-c2.net",
    "update-check.malware-cdn.ru",
    "x7k2p9.dyndns-tunnel.org",
    "telemetry.suspicious-host.biz",
]

NORMAL_DOMAINS = [
    "www.google.com", "api.github.com", "cdn.cloudflare.com",
    "graph.facebook.com", "www.netflix.com", "outlook.office365.com",
]


def _now():
    return datetime.now()


class DemoCapture:
    """
    Mimics PacketCapture's interface but generates fake packets and alerts
    by cycling through scripted attack scenarios.
    """

    def __init__(self, buffer_size: int = 500, speed: float = 1.0):
        self.buffer_size = buffer_size
        self.speed = speed  # multiplier, higher = faster scenarios

        self.packets: deque = deque(maxlen=buffer_size)
        self.lock = threading.Lock()

        self._running = False
        self._thread: Optional[threading.Thread] = None

        self.total_packets = 0
        self.total_bytes = 0
        self.proto_counts: Dict[str, int] = {}
        self.talkers: Dict[str, int] = {}
        self.dns_queries: Dict[str, int] = {}
        self.port_counts: Dict[int, int] = {}
        self.start_time: Optional[datetime] = None

        self.alerts: List[Dict] = []

        self._scenarios = [
            self._scenario_normal_traffic,
            self._scenario_port_scan,
            self._scenario_ssh_bruteforce,
            self._scenario_ftp_plaintext,
            self._scenario_arp_spoof,
            self._scenario_dns_tunnel,
            self._scenario_sql_injection,
            self._scenario_c2_beacon,
        ]

    # -- internal helpers --

    def _add_packet(self, proto, src_ip, dst_ip, src_port=None, dst_port=None,
                     length=None, info="", flagged=False):
        if length is None:
            length = random.randint(60, 1500)

        pkt = Packet(
            timestamp=_now(), src_ip=src_ip, dst_ip=dst_ip, proto=proto,
            src_port=src_port, dst_port=dst_port, length=length, info=info,
            flagged=flagged,
        )

        with self.lock:
            self.total_packets += 1
            self.total_bytes += length
            self.proto_counts[proto] = self.proto_counts.get(proto, 0) + 1
            self.talkers[src_ip] = self.talkers.get(src_ip, 0) + length
            self.talkers[dst_ip] = self.talkers.get(dst_ip, 0) + length
            if dst_port:
                self.port_counts[dst_port] = self.port_counts.get(dst_port, 0) + 1
            self.packets.append(pkt)

        return pkt

    def _fire_alert(self, severity, detail, **extra):
        alert = {
            "timestamp": _now().isoformat(),
            "severity": severity,
            "detail": detail,
        }
        alert.update(extra)
        with self.lock:
            self.alerts.append(alert)

    def _sleep(self, base):
        time.sleep(base / max(self.speed, 0.1))

    # -- scenarios --

    def _scenario_normal_traffic(self):
        """Just some boring everyday packets."""
        for _ in range(random.randint(4, 8)):
            ip = random.choice(LOCAL_IPS)
            ext = random.choice(EXTERNAL_IPS)
            proto = random.choice(["tcp", "tcp", "udp"])

            if proto == "tcp":
                port = random.choice([443, 443, 443, 80, 22])
                self._add_packet("tcp", ip, ext, src_port=random.randint(40000, 60000),
                                 dst_port=port, info=random.choice(["", "ACK", "PSH,ACK"]))
            else:
                domain = random.choice(NORMAL_DOMAINS)
                self._add_packet("udp", ip, ROUTER_IP, src_port=random.randint(40000, 60000),
                                 dst_port=53, length=random.randint(60, 120),
                                 info=f"dns query: {domain}")
                with self.lock:
                    self.dns_queries[domain] = self.dns_queries.get(domain, 0) + 1

            self._sleep(0.3)

    def _scenario_port_scan(self):
        """Attacker IP rapidly hits many ports on a local device."""
        target = random.choice([ip for ip in LOCAL_IPS if ip != ATTACKER_IP])
        ports = random.sample(range(20, 1000), 18)

        for port in ports:
            self._add_packet("tcp", ATTACKER_IP, target,
                             src_port=random.randint(40000, 60000), dst_port=port,
                             length=60, info="SYN", flagged=True)
            self._sleep(0.08)

        self._fire_alert(
            "high",
            f"{ATTACKER_IP} hit {len(ports)} ports on {target} in under 5s -- looks like a port scan",
            type="port_scan", src_ip=ATTACKER_IP, dst_ip=target,
        )

    def _scenario_ssh_bruteforce(self):
        """Repeated SSH connection attempts with auth failures."""
        target = random.choice([ip for ip in LOCAL_IPS if ip != ATTACKER_IP])
        usernames = ["root", "admin", "ubuntu", "pi", "user", "test"]

        for i in range(10):
            user = random.choice(usernames)
            self._add_packet("tcp", ATTACKER_IP, target,
                             src_port=random.randint(40000, 60000), dst_port=22,
                             length=random.randint(80, 200),
                             info=f"ssh auth attempt (user: {user})", flagged=True)
            self._sleep(0.15)

        self._fire_alert(
            "high",
            f"{ATTACKER_IP} made 10 ssh login attempts against {target} in a few seconds -- brute force",
            type="bruteforce", src_ip=ATTACKER_IP, dst_ip=target, service="ssh",
        )

    def _scenario_ftp_plaintext(self):
        """A device logs into FTP with creds visible in plaintext."""
        client = random.choice([ip for ip in LOCAL_IPS])
        server = random.choice(EXTERNAL_IPS)
        username = random.choice(["backup-user", "ftpadmin", "guest"])
        password = random.choice(["hunter2", "letmein123", "P@ssw0rd!"])

        self._add_packet("tcp", client, server, src_port=random.randint(40000, 60000),
                         dst_port=21, length=72, info="USER " + username)
        self._sleep(0.3)
        self._add_packet("tcp", client, server, src_port=random.randint(40000, 60000),
                         dst_port=21, length=72, info="PASS " + password, flagged=True)

        self._fire_alert(
            "high",
            f"ftp/pop3/telnet password seen in plaintext: {client} -> {server} (PASS {password})",
            type="plaintext_credential", src_ip=client, dst_ip=server, label="ftp password",
        )

    def _scenario_arp_spoof(self):
        """Attacker claims to be the router via ARP."""
        victim = random.choice([ip for ip in LOCAL_IPS if ip != ATTACKER_IP])
        real_mac = "b8:27:eb:4a:9c:21"
        fake_mac = "de:ad:be:ef:13:37"

        self._add_packet("arp", ROUTER_IP, victim, length=42,
                         info=f"is-at {real_mac}")
        self._sleep(0.4)
        self._add_packet("arp", ROUTER_IP, victim, length=42,
                         info=f"is-at {fake_mac}", flagged=True)

        self._fire_alert(
            "critical",
            f"{ROUTER_IP} claimed by multiple MACs ({real_mac}, {fake_mac}) -- possible ARP spoofing / MITM",
            type="arp_spoof", ip=ROUTER_IP, macs=[real_mac, fake_mac],
        )

    def _scenario_dns_tunnel(self):
        """Lots of weird DNS queries to a sketchy domain -- classic c2/tunneling."""
        infected = random.choice(LOCAL_IPS)
        domain = random.choice(SUSPICIOUS_DOMAINS)

        for _ in range(8):
            subdomain = "".join(random.choices("abcdef0123456789", k=12))
            full = f"{subdomain}.{domain}"
            self._add_packet("udp", infected, ROUTER_IP, src_port=random.randint(40000, 60000),
                             dst_port=53, length=random.randint(90, 180),
                             info=f"dns query: {full}", flagged=True)
            with self.lock:
                self.dns_queries[full] = self.dns_queries.get(full, 0) + 1
            self._sleep(0.2)

        self._fire_alert(
            "medium",
            f"{infected} made repeated dns queries with random-looking subdomains to {domain} -- possible dns tunneling / c2",
            type="dns_tunnel", src_ip=infected, domain=domain,
        )

    def _scenario_sql_injection(self):
        """HTTP request with an obvious sqli payload."""
        attacker = ATTACKER_IP
        webserver = random.choice(LOCAL_IPS)
        payload = "id=1' OR '1'='1' UNION SELECT username,password FROM users--"

        self._add_packet("tcp", attacker, webserver,
                         src_port=random.randint(40000, 60000), dst_port=80,
                         length=len(payload) + 120,
                         info=f"GET /product.php?{payload[:50]}...", flagged=True)

        self._fire_alert(
            "critical",
            f"sql injection payload detected from {attacker} to {webserver}: {payload[:60]}...",
            type="sql_injection", src_ip=attacker, dst_ip=webserver,
        )

    def _scenario_c2_beacon(self):
        """A local device 'phones home' to a known bad ip at regular intervals."""
        infected = random.choice(LOCAL_IPS)
        c2_ip = "23.249.162.161"

        for _ in range(4):
            self._add_packet("tcp", infected, c2_ip,
                             src_port=random.randint(40000, 60000), dst_port=443,
                             length=random.randint(200, 400),
                             info="PSH,ACK  (encrypted beacon)", flagged=True)
            self._sleep(0.4)

        self._fire_alert(
            "high",
            f"{infected} sent repeated small encrypted packets to {c2_ip}, a known mirai c2 ip -- possible malware beacon",
            type="c2_beacon", src_ip=infected, dst_ip=c2_ip,
        )

    # -- main loop --

    def _run(self):
        # start with some normal traffic so the table isnt empty
        self._scenario_normal_traffic()

        weights = [40, 12, 12, 12, 8, 8, 8, 8]  # normal traffic is most common

        while self._running:
            scenario = random.choices(self._scenarios, weights=weights, k=1)[0]
            try:
                scenario()
            except Exception:
                pass
            self._sleep(random.uniform(1.5, 3.0))

    def start(self):
        self._running = True
        self.start_time = _now()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def get_recent(self, n=30):
        with self.lock:
            return list(self.packets)[-n:]

    def get_stats(self):
        with self.lock:
            elapsed = (_now() - self.start_time).total_seconds() if self.start_time else 0
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


class DemoAlertEngine:
    """Wraps the alerts list generated by DemoCapture so display.py can use the same interface."""

    def __init__(self, demo_capture: DemoCapture):
        self.demo_capture = demo_capture

    def get_alerts(self):
        with self.demo_capture.lock:
            return list(self.demo_capture.alerts)
