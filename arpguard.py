import argparse
import os
import signal
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.database import ForensicDatabase
from core.healer import ARPHealer
from core.sniffer import ARPSnifferEngine

console = Console()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ARPGuard - Real-Time Layer-2 ARP Spoofing Detector & Active Healer"
    )
    parser.add_argument(
        "-i",
        "--interface",
        required=True,
        help="Network interface to monitor (e.g., eth0, wlan0, enp3s0)",
    )
    parser.add_argument(
        "-g",
        "--gateway",
        default=None,
        help="Default Gateway IPv4 address to lock on startup",
    )
    parser.add_argument(
        "-m",
        "--mitigate",
        action="store_true",
        help="Actively heal poisoned ARP caches via corrective broadcasts",
    )
    parser.add_argument(
        "-t",
        "--threshold",
        type=int,
        default=25,
        help="Max ARP replies per 5s before storm alert (default: 25)",
    )
    parser.add_argument(
        "--db",
        default="arpguard_audit.db",
        help="Path to SQLite forensic database file",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if os.geteuid() != 0:
        console.print(
            "[bold red][!] Error: ARPGuard requires root privileges (CAP_NET_RAW). Run with sudo.[/bold red]"
        )
        sys.exit(1)

    db = ForensicDatabase(db_path=args.db)
    healer = ARPHealer(interface=args.interface)
    sniffer = ARPSnifferEngine(
        interface=args.interface,
        db=db,
        healer=healer,
        gateway_ip=args.gateway,
        mitigate=args.mitigate,
        storm_threshold=args.threshold,
    )

    def shutdown_handler(sig, frame):
        console.print(
            "\n[bold cyan][*] Stopping ARPGuard. Session Summary:[/bold cyan]"
        )
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Metric")
        table.add_column("Count", justify="right")
        table.add_row("ARP Frames Inspected", str(sniffer.stats["packets_inspected"]))
        table.add_row("Trusted Hosts Baselines", str(len(sniffer.arp_table)))
        table.add_row(
            "Security Alerts Triggered", str(sniffer.stats["alerts_triggered"])
        )
        table.add_row("Active Mitigations Dispatched", str(healer.mitigations_sent))
        console.print(table)
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown_handler)

    console.print(
        Panel.fit(
            f"[bold cyan]ARPGuard Layer-2 IDS Active[/bold cyan]\n"
            f"Interface: [bold]{args.interface}[/bold] | "
            f"Active Mitigation: [bold]{'ENABLED' if args.mitigate else 'DISABLED'}[/bold] | "
            f"Audit DB: [bold]{args.db}[/bold]",
            border_style="cyan",
        )
    )

    sniffer.run()


if __name__ == "__main__":
    main()
