# 🛡️ ARPGuard: Real-Time Layer-2 ARP Spoofing Detector & Active Mitigation Engine

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
![Scapy](https://img.shields.io/badge/Scapy-2.5%2B-orange?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey?style=flat-square)
![SQLite](https://img.shields.io/badge/Database-SQLite3-003B57?style=flat-square&logo=sqlite)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

**ARPGuard** is a real-time Layer-2 Intrusion Detection and Active Prevention System (IDS/IPS) designed to detect, log, and neutralize **Address Resolution Protocol (ARP) Cache Poisoning** and **Local Area Network (LAN) Man-in-the-Middle (MitM)** attacks.

Unlike traditional passive ARP monitors that suffer from high false-positive rates during routine DHCP lease renewals and cannot stop ongoing interception, ARPGuard pairs **kernel-level Berkeley Packet Filtering (BPF)** with **out-of-band active wire verification (`srp`)** and **automated gratuitous ARP cache healing**.

---

## ✨ Key Features

* **⚡ Kernel-Level BPF Filtering:** Captures raw Layer-2 Ethernet frames using `filter="arp"` in kernel space so high-volume TCP/UDP traffic never crosses into Python user space.
* **🔍 Multi-Heuristic Detection Pipeline:**
  1. **Header Integrity Check (`HIGH`):** Compares the outer IEEE 802.3 Ethernet source MAC (`Ether.src`) against the inner RFC 826 ARP sender hardware address (`ARP.hwsrc`).
  2. **Sliding-Window Storm Detection (`MEDIUM`):** Tracks unsolicited ARP reply rates per MAC using $O(1)$ bounded `deque` buffers to detect rapid poisoning floods (`arpspoof`, `ettercap`, `bettercap`).
  3. **Active Out-of-Band Wire Verification (`CRITICAL`):** Whenever a conflicting MAC-to-IP binding is observed, ARPGuard dispatches an independent Layer-2 broadcast query (`srp`) to verify whether the legitimate NIC is still active on the wire—eliminating DHCP churn false positives.
* **🩹 Automated Gratuitous ARP Cache Healing (`--mitigate`):** Synthesizes and broadcasts $3\times$ corrective `is-at` ARP bursts (`op=2`) at $20\text{ ms}$ intervals to immediately restore poisoned ARP caches across the subnet.
* **🗄️ Tamper-Evident SQLite3 Forensic Logging:** Persists verified host baselines (`trusted_hosts`) and detailed attack logs (`security_incidents`) with mutex thread synchronization.
* **🖥️ Rich CLI Telemetry & Lab Simulator:** Displays real-time color-coded incident panels and includes a built-in, safe packet simulator (`simulator/arp_spoof_sim.py`) to test all three attack vectors.

---

## 📂 Project Architecture

```text
arpguard/
├── arpguard.py          # Main CLI entrypoint & orchestrator
├── core/
│   ├── __init__.py      # Core package initializer
│   ├── sniffer.py       # Layer-2 BPF packet capture & active srp() verifier
│   ├── healer.py        # Corrective gratuitous ARP cache restoration engine
│   └── database.py      # Thread-safe SQLite3 forensic logger & baseline registry
├── simulator/
│   └── arp_spoof_sim.py # Controlled ARP poisoning/mismatch/storm lab simulator
├── requirements.txt     # Python dependencies (scapy, rich)
└── arpguard_audit.db    # Auto-generated SQLite3 forensic database
```

---

## 🚀 Getting Started on Linux (Ubuntu / Linux Mint / Debian / Arch)

### 1. Prerequisites
Ensure `python3`, `venv`, and `libpcap` are installed on your system:
```bash
# Debian / Ubuntu / Linux Mint
sudo apt update && sudo apt install -y python3 python3-venv libpcap0.8 sqlite3 iproute2
```

### 2. Clone & Set Up Virtual Environment
```bash
git clone [https://github.com/yourusername/arpguard.git](https://github.com/yourusername/arpguard.git)
cd arpguard

python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

### 3. Find Your Network Interface & Gateway IP
Run `ip route` to identify your active interface and default gateway:
```bash
ip route show default
# Example output: default via 10.39.7.203 dev enxd63046d04f70 proto dhcp src 10.39.7.219
```
* Here, the interface is `enxd63046d04f70` (or `wlan0` / `eth0`) and the gateway IP is `10.39.7.203`.

### 4. Run ARPGuard (Terminal 1)
Because capturing raw Layer-2 sockets and injecting Ethernet frames requires `CAP_NET_RAW` privileges, run the virtual environment's Python binary with `sudo`:
```bash
sudo .venv/bin/python arpguard.py -i enxd63046d04f70 -g 10.39.7.203 --mitigate
```

---

## 🪟 Getting Started on Windows (Windows 10 / 11)

On Windows, raw Layer-2 packet capture and frame injection require the **Npcap** driver (the Windows port of `libpcap`).

### 1. Prerequisites
1. **Install Python 3.10+:** Download from [python.org](https://www.python.org/downloads/windows/) and ensure **"Add python.exe to PATH"** is checked.
2. **Install Npcap (Required for Scapy on Windows):**
   * Download and install [Npcap](https://npcap.com/#download).
   * **Important:** During installation, check **"Install Npcap in WinPcap API-compatible Mode"**.

### 2. Set Up Virtual Environment (PowerShell as Administrator)
Open **PowerShell** or **Windows Terminal** as **Administrator** (`Right-click -> Run as administrator`):
```powershell
git clone [https://github.com/yourusername/arpguard.git](https://github.com/yourusername/arpguard.git)
cd arpguard

python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
```

> **Note for Windows Compatibility:** If you are running `arpguard.py` and `arp_spoof_sim.py` on native Windows (outside WSL), replace the Unix-only `os.geteuid() != 0` privilege check in both files with a cross-platform check:
> ```python
> import ctypes, os
> is_admin = (os.geteuid() == 0) if hasattr(os, "geteuid") else (ctypes.windll.shell32.IsUserAnAdmin() != 0)
> ```

### 3. Find Your Windows Network Interface & Gateway IP
In PowerShell, list your active network adapter name and Default Gateway:
```powershell
Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4DefaultGateway
```
* Note the `InterfaceAlias` (e.g., `"Wi-Fi"` or `"Ethernet"`) and the `NextHop` gateway IP (e.g., `192.168.1.1`).
* Alternatively, inspect Scapy's recognized Windows interface names directly:
  ```powershell
  .\.venv\Scripts\python -c "from scapy.all import show_interfaces; show_interfaces()"
  ```

### 4. Run ARPGuard on Windows (Administrator PowerShell)
```powershell
.\.venv\Scripts\python arpguard.py -i "Wi-Fi" -g 192.168.1.1 --mitigate
```

---

## 🧪 Testing with the Built-In Attack Simulator

You can safely test all three detection heuristics (`poison`, `mismatch`, and `storm`) by opening a **second privileged terminal** and running `simulator/arp_spoof_sim.py`.

### On Linux (Terminal 2):
```bash
# 1. Test ARP Cache Poisoning (CRITICAL) + Active Cache Healing
sudo .venv/bin/python simulator/arp_spoof_sim.py -i enxd63046d04f70 -t 10.39.7.203 --mode poison

# 2. Test Ethernet vs. ARP Header Mismatch (HIGH)
sudo .venv/bin/python simulator/arp_spoof_sim.py -i enxd63046d04f70 -t 10.39.7.203 --mode mismatch

# 3. Test Unsolicited Gratuitous ARP Storm (MEDIUM)
sudo .venv/bin/python simulator/arp_spoof_sim.py -i enxd63046d04f70 -t 10.39.7.203 --mode storm
```

### On Windows (Administrator PowerShell - Terminal 2):
```powershell
# 1. Test ARP Cache Poisoning (CRITICAL)
.\.venv\Scripts\python simulator\arp_spoof_sim.py -i "Wi-Fi" -t 192.168.1.1 --mode poison

# 2. Test Header Mismatch (HIGH)
.\.venv\Scripts\python simulator\arp_spoof_sim.py -i "Wi-Fi" -t 192.168.1.1 --mode mismatch

# 3. Test Gratuitous ARP Storm (MEDIUM)
.\.venv\Scripts\python simulator\arp_spoof_sim.py -i "Wi-Fi" -t 192.168.1.1 --mode storm
```

---

## ⚙️ Command-Line Options

### `arpguard.py`
| Flag | Long Flag | Required | Default | Description |
| :--- | :--- | :---: | :---: | :--- |
| `-i` | `--interface` | **Yes** | — | Network interface to monitor (e.g., `eth0`, `wlan0`, `"Wi-Fi"`) |
| `-g` | `--gateway` | No | `None` | Default Gateway IPv4 address to actively probe and lock at startup |
| `-m` | `--mitigate` | No | `False` | Broadcast corrective $3\times$ gratuitous ARP replies to heal poisoned caches |
| `-t` | `--threshold` | No | `25` | Maximum ARP replies permitted per MAC within a 5s window before storm alert |
| — | `--db` | No | `arpguard_audit.db` | File path for the SQLite3 forensic audit database |

### `simulator/arp_spoof_sim.py`
| Flag | Long Flag | Required | Default | Description |
| :--- | :--- | :---: | :---: | :--- |
| `-i` | `--interface` | **Yes** | — | Network interface used to inject test frames |
| `-t` | `--target-ip` | **Yes** | — | Target IPv4 address to impersonate (typically the Gateway IP) |
| `-f` | `--fake-mac` | No | `08:00:27:de:ad:be` | Spoofed attacker hardware MAC address |
| — | `--mode` | No | `poison` | Heuristic to trigger: `poison`, `mismatch`, or `storm` |
| `-c` | `--count` | No | `5` | Number of spoofed frames to transmit (`30` minimum in `storm` mode) |

---

## 🔍 Auditing the Forensic SQLite Database

All baseline bindings and detected attacks are stored in `arpguard_audit.db`. Query them directly via the `sqlite3` CLI or Python:

```bash
# View verified baseline hosts
sqlite3 -header -box arpguard_audit.db "SELECT * FROM trusted_hosts;"

# View logged security incidents
sqlite3 -header -box arpguard_audit.db \
  "SELECT incident_id, timestamp, alert_type, target_ip, legitimate_mac, attacker_mac, severity, mitigated FROM security_incidents;"
```

**Sample Output:**
```text
┌─────────────┬────────────────────────────┬───────────────────────┬─────────────┬───────────────────┬───────────────────┬──────────┬───────────┐
│ incident_id │ timestamp                  │ alert_type            │ target_ip   │ legitimate_mac    │ attacker_mac      │ severity │ mitigated │
├─────────────┼────────────────────────────┼───────────────────────┼─────────────┼───────────────────┼───────────────────┼──────────┼───────────┤
│ 1           │ 2026-11-15T15:18:04.219104 │ ARP_CACHE_POISONING   │ 10.39.7.203 │ d6:30:46:d0:4f:70 │ 08:00:27:de:ad:be │ CRITICAL │ 1         │
│ 2           │ 2026-11-15T15:18:14.892411 │ HEADER_MAC_MISMATCH   │ 10.39.7.203 │ 02:11:22:33:44:55 │ 08:00:27:de:ad:be │ HIGH     │ 1         │
│ 3           │ 2026-11-15T15:18:21.105832 │ UNSOLICITED_ARP_STORM │ 10.39.7.203 │ d6:30:46:d0:4f:70 │ 08:00:27:de:ad:be │ MEDIUM   │ 1         │
└─────────────┴────────────────────────────┴───────────────────────┴─────────────┴───────────────────┴───────────────────┴──────────┴───────────┘
```

---

## ⚠️ Disclaimer

This software and its companion simulator are developed strictly for **educational purposes, academic research, and authorized network defense auditing**. Only run the simulator on networks or virtual testbeds (`veth` / lab VLANs) that you own or have explicit permission to test.
