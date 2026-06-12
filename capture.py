"""
display.py
terminal output for the sniffer -- live table of packets, stats panel, alerts
"""

import time
from datetime import datetime

try:
    from rich.console import Console, Group
    from rich.table import Table
    from rich.live import Live
    from rich.text import Text
    from rich.panel import Panel
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


PROTO_COLORS = {
    "tcp": "cyan",
    "udp": "magenta",
    "icmp": "yellow",
    "arp": "blue",
    "other": "dim",
}


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


class Display:
    def __init__(self):
        if RICH_AVAILABLE:
            self.console = Console()

    def banner(self):
        if RICH_AVAILABLE:
            self.console.print()
            self.console.print("  [bold white]packet-sniffer[/bold white]  [dim]// made by brad[/dim]")
            self.console.print("  [dim]live network traffic viewer + basic threat detection[/dim]")
            self.console.print()
        else:
            print("\n  packet-sniffer -- made by brad\n")

    def print_info(self, msg):
        if RICH_AVAILABLE:
            self.console.print(msg)
        else:
            print(msg)

    def _packet_table(self, packets, max_rows=25):
        table = Table(
            box=box.SIMPLE_HEAD,
            header_style="bold",
            border_style="dim",
            expand=True,
            padding=(0, 1),
            show_lines=False,
        )
        table.add_column("time", style="dim", width=10)
        table.add_column("proto", width=6)
        table.add_column("source", min_width=20)
        table.add_column("destination", min_width=20)
        table.add_column("len", justify="right", width=6)
        table.add_column("service", width=10)
        table.add_column("info", min_width=20)

        for p in packets[-max_rows:]:
            color = PROTO_COLORS.get(p.proto, "white")
            proto = f"[{color}]{p.proto}[/{color}]"

            src = p.src_ip
            dst = p.dst_ip
            if p.src_port:
                src += f":{p.src_port}"
            if p.dst_port:
                dst += f":{p.dst_port}"

            row_style = "on dark_red" if p.flagged else ""

            table.add_row(
                p.timestamp.strftime("%H:%M:%S"),
                proto,
                src,
                dst,
                str(p.length),
                p.service_name() or "",
                p.info,
                style=row_style,
            )

        return table

    def _stats_panel(self, stats):
        lines = []
        lines.append(f"packets: {stats['total_packets']}   "
                      f"bytes: {_fmt_bytes(stats['total_bytes'])}   "
                      f"rate: {stats['packets_per_sec']:.1f}/s   "
                      f"elapsed: {int(stats['elapsed_seconds'])}s")

        protos = stats["proto_counts"]
        if protos:
            proto_str = "  ".join(f"{k}:{v}" for k, v in sorted(protos.items(), key=lambda x: -x[1]))
            lines.append(f"protocols  --  {proto_str}")

        talkers = stats["top_talkers"][:5]
        if talkers:
            talker_str = "  ".join(f"{ip} ({_fmt_bytes(b)})" for ip, b in talkers)
            lines.append(f"top talkers  --  {talker_str}")

        ports = stats["top_ports"][:6]
        if ports:
            from .capture import PORT_NAMES
            port_str = "  ".join(
                f"{p}({PORT_NAMES.get(p,'?')}):{c}" for p, c in ports
            )
            lines.append(f"top ports  --  {port_str}")

        return "\n".join(f"  {l}" for l in lines)

    def _alerts_panel(self, alerts, max_alerts=6):
        if not alerts:
            return "  [dim]no alerts yet[/dim]"

        severity_colors = {"critical": "red", "high": "yellow", "medium": "cyan", "low": "dim"}
        lines = []
        for a in alerts[-max_alerts:]:
            sev = a.get("severity", "low")
            color = severity_colors.get(sev, "white")
            ts = a["timestamp"][11:19]
            lines.append(f"  [{color}]{sev.upper()}[/{color}]  [dim]{ts}[/dim]  {a['detail']}")
        return "\n".join(lines)

    def live_view(self, capture, alert_engine, refresh=2):
        """Run the live dashboard. Blocks until ctrl+c."""
        if not RICH_AVAILABLE:
            raise RuntimeError("rich is required for live view")

        header = Text.from_markup(
            "  [bold white]packet-sniffer[/bold white]  [dim]// made by brad[/dim]  "
            "[dim](ctrl+c to stop)[/dim]"
        )

        def make_renderable():
            packets = capture.get_recent(25)
            stats = capture.get_stats()
            alerts = alert_engine.get_alerts() if alert_engine else []

            table = self._packet_table(packets)
            stats_text = Text.from_markup(self._stats_panel(stats))
            alerts_text = Text.from_markup(self._alerts_panel(alerts))

            stats_panel = Panel(stats_text, title="[dim]stats[/dim]", title_align="left",
                                 border_style="dim", box=box.SIMPLE)
            alerts_panel = Panel(alerts_text, title="[dim]alerts[/dim]", title_align="left",
                                  border_style="dim", box=box.SIMPLE)

            return Group(header, table, stats_panel, alerts_panel)

        with Live(make_renderable(), console=self.console, refresh_per_second=refresh) as live:
            try:
                while True:
                    time.sleep(1 / refresh)
                    live.update(make_renderable())
            except KeyboardInterrupt:
                pass

    def print_summary(self, capture, alert_engine):
        """Print final stats after stopping."""
        stats = capture.get_stats()
        alerts = alert_engine.get_alerts() if alert_engine else []

        self.print_info("\n  [bold]capture summary[/bold]")
        self.print_info(self._stats_panel(stats))

        dns = stats.get("top_dns", [])
        if dns:
            self.print_info("\n  [bold]top dns lookups[/bold]")
            for name, count in dns:
                self.print_info(f"    {name}  ({count}x)")

        if alerts:
            self.print_info(f"\n  [bold]alerts ({len(alerts)} total)[/bold]")
            for a in alerts:
                sev = a.get("severity", "low")
                self.print_info(f"    [{sev}] {a['detail']}")
        else:
            self.print_info("\n  no alerts triggered")

        self.print_info("")
