import time
from collections import defaultdict, deque
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from scapy.all import ARP, Ether, conf, sniff, srp

from core.database import ForensicDatabase
from core.healer import ARPHealer

console = Console()
conf.verb = 0


class ARPSnifferEngine:
    """Core Layer-2 packet inspection and active probing engine."""

    def __init__(
        self,
        interface: str,
        db: ForensicDatabase,
        healer: ARPHealer,
        gateway_ip: str | None = None,
        mitigate: bool = False,
        storm_threshold: int = 25,
    ):
        self.interface = interface
        self.db = db
        self.healer = healer
        self.gateway_ip = gateway_ip
        self.mitigate = mitigate
        self.storm_threshold = storm_threshold

        self.arp_table: dict[str, str] = {}  # IP -> Verified Legitimate MAC
        self.reply_timestamps: dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.stats = {
            "packets_inspected": 0,
            "alerts_triggered": 0,
        }

        if self.gateway_ip:
            self._bootstrap_gateway()

    def _bootstrap_gateway(self) -> None:
        """Actively resolve and pin the default gateway's MAC address on startup."""
        console.print(
            f"[cyan][*] Probing gateway {self.gateway_ip} on interface '{self.interface}'...[/cyan]"
        )
        real_mac = self.active_mac_probe(self.gateway_ip)
        if real_mac:
            self.arp_table[self.gateway_ip] = real_mac
            self.db.upsert_trusted_host(self.gateway_ip, real_mac, is_gateway=1)
            console.print(
                f"[green][+] Gateway locked: {self.gateway_ip} -> {real_mac}[/green]"
            )
        else:
            console.print(
                f"[yellow][!] Warning: Could not resolve gateway {self.gateway_ip} at startup.[/yellow]"
            )

    def active_mac_probe(self, ip_address: str) -> str | None:
        """Dispatch a broadcast Ethernet + ARP Who-Has request to verify true hardware MAC."""
        try:
            arp_req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address)
            answered, _ = srp(
                arp_req, timeout=1.2, retry=1, iface=self.interface, verbose=False
            )
            if answered:
                return answered[0][1].hwsrc.lower()
        except Exception:
            pass
        return None

    def inspect_packet(self, packet) -> None:
        """Callback invoked for every captured Layer-2 ARP frame."""
        if not packet.haslayer(ARP):
            return

        self.stats["packets_inspected"] += 1
        arp = packet[ARP]
        src_ip = arp.psrc
        src_mac = arp.hwsrc.lower()
        eth_src_mac = packet[Ether].src.lower() if packet.haslayer(Ether) else src_mac

        # Ignore incomplete DHCP/ACD ARP probes (0.0.0.0) or loopback
        if src_ip == "0.0.0.0" or src_mac == "00:00:00:00:00:00":
            return

        # Heuristic 1: Outer Ethernet Frame Header vs Inner ARP Payload MAC Mismatch
        if eth_src_mac != src_mac:
            self._trigger_incident(
                alert_type="HEADER_MAC_MISMATCH",
                ip=src_ip,
                real_mac=eth_src_mac,
                fake_mac=src_mac,
                severity="HIGH",
            )

        # Process ARP Replies (op == 2: 'is-at')
        if arp.op == 2:
            now = time.time()
            window = self.reply_timestamps[src_mac]
            window.append(now)

            # Heuristic 2: Gratuitous ARP Storm / Flood Detection (sliding 5s window)
            recent_count = sum(1 for ts in window if now - ts <= 5.0)
            if recent_count >= self.storm_threshold:
                self._trigger_incident(
                    alert_type="UNSOLICITED_ARP_STORM",
                    ip=src_ip,
                    real_mac=self.arp_table.get(src_ip, "UNKNOWN"),
                    fake_mac=src_mac,
                    severity="MEDIUM",
                )
                window.clear()

            # Heuristic 3: Stateful Baseline & Active Cross-Verification
            if src_ip in self.arp_table:
                recorded_mac = self.arp_table[src_ip]
                if recorded_mac != src_mac:
                    # Out-of-band check: verify if true host still responds
                    probed_mac = self.active_mac_probe(src_ip) or recorded_mac
                    if probed_mac != src_mac:
                        self._trigger_incident(
                            alert_type="ARP_CACHE_POISONING",
                            ip=src_ip,
                            real_mac=probed_mac,
                            fake_mac=src_mac,
                            severity="CRITICAL",
                        )
                        return
            else:
                # First observation: actively verify before adding to baseline
                verified_mac = self.active_mac_probe(src_ip) or src_mac
                self.arp_table[src_ip] = verified_mac
                self.db.upsert_trusted_host(src_ip, verified_mac)
                if verified_mac != src_mac:
                    self._trigger_incident(
                        alert_type="SPOOFED_FIRST_CONTACT",
                        ip=src_ip,
                        real_mac=verified_mac,
                        fake_mac=src_mac,
                        severity="CRITICAL",
                    )

    def _trigger_incident(
        self,
        alert_type: str,
        ip: str,
        real_mac: str,
        fake_mac: str,
        severity: str,
    ) -> None:
        self.stats["alerts_triggered"] += 1
        healed = False

        if self.mitigate and real_mac != "UNKNOWN":
            healed = self.healer.heal_cache(ip, real_mac)

        self.db.log_incident(alert_type, ip, real_mac, fake_mac, severity, healed)

        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        mitigation_tag = (
            "[bold green]HEALED[/bold green]"
            if healed
            else "[yellow]LOGGED ONLY[/yellow]"
        )

        console.print(
            Panel(
                f"[bold red]Alert Type:[/bold red] {alert_type} ({severity})\n"
                f"[bold white]Target IP:[/bold white]  {ip}\n"
                f"[bold green]True MAC:[/bold green]   {real_mac}\n"
                f"[bold yellow]Spoof MAC:[/bold yellow]  {fake_mac}\n"
                f"[bold cyan]Action:[/bold cyan]     {mitigation_tag} | Timestamp: {timestamp}",
                title="[bold red]SECURITY INCIDENT DETECTED[/bold red]",
                border_style="red",
            )
        )

    def run(self) -> None:
        """Start blocking BPF packet capture loop."""
        sniff(iface=self.interface, filter="arp", prn=self.inspect_packet, store=False)
