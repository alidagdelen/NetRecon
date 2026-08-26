# 🛡️ NetRecon v3.0

> Advanced Network Reconnaissance & MITM DNS Sniffer Tool for Linux

**NetRecon** is a powerful Python-based network utility designed for local network reconnaissance, active host discovery, and real-time DNS query interception using ARP Spoofing (MITM) techniques.

---

## 🚀 Features

* **Advanced Host Discovery:** Fast multi-threaded ping sweep to scan and list active devices on any subnet.
* **Smart Gateway Detection:** Automatically detects your default router/gateway IP address.
* **ARP Spoofing Engine (MITM):** Seamlessly redirects traffic from target devices through your machine for monitoring.
* **Universal & Targeted DNS Sniffing:** Intercepts and logs plaintext DNS queries (`udp port 53`) across local network devices in real-time.
* **Clean Exit & Restoration:** Automatically restores original network ARP tables and disables IP forwarding upon exit.

---

## 📋 Requirements & Environment

* **OS:** Tested and verified on **BlackArch Linux** / Kali Linux
* **Python:** Python 3.x
* **Dependencies:** `scapy`

---

## ⚙️ Installation

1. Clone or download the repository to your local machine.
2. Ensure Python and Scapy are installed on your system (BlackArch usually comes with Scapy pre-installed, or you can install via pacman/pip if needed):
   ```bash
   sudo pacman -S python-scapy
