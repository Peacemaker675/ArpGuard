from rich.console import Console
from scapy.all import ARP, Ether, sendp

console = Console()


class ARPHealer:
    """Synthesizes and dispatches corrective Layer-2 ARP frames to restore poisoned caches."""

    def __init__(self, interface: str, burst_count: int = 3):
        self.interface = interface
        self.burst_count = burst_count
        self.mitigations_sent = 0

    def heal_cache(self, target_ip: str, legitimate_mac: str) -> bool:
        """
        Broadcast corrective gratuitous ARP replies (op=2: 'is-at') so all hosts on
        the subnet immediately overwrite the attacker's forged MAC with the true MAC.
        """
        try:
            corrective_frame = Ether(src=legitimate_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=2,
                psrc=target_ip,
                hwsrc=legitimate_mac,
                pdst="255.255.255.255",
                hwdst="ff:ff:ff:ff:ff:ff",
            )
            sendp(
                corrective_frame,
                iface=self.interface,
                count=self.burst_count,
                inter=0.02,
                verbose=False,
            )
            self.mitigations_sent += 1
            return True
        except Exception as exc:
            console.print(
                f"[red][!] Healer failed to dispatch corrective ARP burst: {exc}[/red]"
            )
            return False
