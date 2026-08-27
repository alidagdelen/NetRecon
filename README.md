# 🛡️ NetRecon v3.6

> Advanced Network Reconnaissance, Port Scanner & Social Media MITM Sniffer Tool for Linux

**NetRecon** is a powerful Python-based network utility designed for local network reconnaissance, active host discovery, real-time port scanning, and live DNS query interception using ARP Spoofing (MITM) techniques.

---

## 🚀 Features

* **Advanced Host Discovery:** Fast multi-threaded ping sweep to scan and list active devices on any subnet.
* **Smart Gateway & IP Detection:** Automatically detects your local IP, subnet, and default router/gateway.
* **Quick Port Scanner:** Optional fast TCP port check on target devices to discover open services (HTTP, HTTPS, SSH, etc.).
* **Social Media Alert System:** Real-time keyword filtering that highlights social media traffic (Instagram, TikTok, Twitter, Facebook, etc.) in high-visibility alert colors.
* **ARP Spoofing Engine (MITM):** Seamlessly redirects traffic from target devices through your machine for monitoring.
* **Interactive Main Menu Loop:** Runs continuously; once a sniffing session or timeout completes, it automatically restores the network and returns you to the menu to pick a new target without restarting the script.
* **Robust Error Handling:** Built-in fault tolerance that prompts you dynamically if a target goes offline or fails to respond.
* **Clean Exit & Restoration:** Automatically restores original network ARP tables, disables IP forwarding, and exits safely.

---

## 📋 Requirements & Environment

* **OS:** Tested and verified on **BlackArch Linux** / Kali Linux / Arch Linux
* **Python:** Python 3.x
* **Dependencies:** `scapy`

---

## ⚙️ Installation

1. Clone or download the repository to your local machine.
2. Ensure Python and Scapy are installed on your system (BlackArch/Kali usually come with Scapy pre-installed, or install via package manager):
   ```bash
   sudo pacman -S python-scapy
   # or via pip: sudo pip install scapy
