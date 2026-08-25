import ipaddress
import sys
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor


def print_banner():
    print("=" * 50)
    print("                 NetRecon v1.0.0                 ")
    print("          Advanced Local Network Recon Tool      ")
    print("=" * 50)


def generate_ips(network_str):
    try:
        network = ipaddress.ip_network(network_str, strict=False)

        print(f"\n[+] Subnet verified successfully: {network}")
        print(f"[+] Network Address: {network.network_address}")
        print(f"[+] Broadcast Address: {network.broadcast_address}")
        print(f"[+] Total IP addresses: {network.num_addresses}")

        host_list = list(network.hosts())
        print(f"[+] Usable host IP count: {len(host_list)}")

        ip_list = [str(ip) for ip in host_list]
        return ip_list

    except ValueError as e:
        print(f"[-] Error: Invalid IP or subnet provided -> {e}")
        return []


def ping_host(ip_str, timeout_ms=800):
    system_name = platform.system().lower()

    if system_name == "windows":
        command = ["ping", "-n", "1", "-w", str(timeout_ms), ip_str]
    else:
        timeout_s = max(1, timeout_ms // 1000)
        command = ["ping", "-c", "1", "-W", str(timeout_s), ip_str]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0
    except Exception as e:
        print(f"[-] Error pinging {ip_str}: {e}")
        return False


def scan_network(ip_list, max_workers=50):
    print("\n" + "=" * 40)
    print("           SCANNING NETWORK HOSTS           ")
    print("=" * 40)

    active_hosts = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(ping_host, ip): ip for ip in ip_list}
        for future in future_to_ip:
            ip = future_to_ip[future]
            try:
                if future.result():
                    active_hosts.append(ip)
                    print(f"[+] Host is active: {ip}")
                else:
                    print(f"[-] Host is inactive: {ip}")
            except Exception as e:
                print(f"[-] Error scanning {ip}: {e}")

    print("=" * 40)
    print(f"[+] Scan complete. Active hosts found: {len(active_hosts)}")
    return active_hosts


def main():
    print_banner()
    try:
        user_input = input(
            "\n[*] Enter an IP address or subnet (e.g., 192.168.1.0/24): "
        ).strip()

        ip_list = generate_ips(user_input)
        if not ip_list:
            sys.exit(1)

        choice = input(
            "\n[*] Run automatic network scan? (y = auto scan / n = manual IP): "
        ).strip().lower()

        if choice == "y":
            active_hosts = scan_network(ip_list)
        elif choice == "n":
            manual_ip = input("[*] Enter the IP to scan: ").strip()
            if manual_ip not in ip_list:
                print("[-] This IP is not in the given subnet, trying anyway...")
            is_active = ping_host(manual_ip)
            active_hosts = [manual_ip] if is_active else []
            status = "ACTIVE" if is_active else "NOT ACTIVE"
            print(f"[+] {manual_ip} -> {status}")
        else:
            print("[-] Invalid choice, must enter 'y' or 'n'.")
            sys.exit(1)

        print(f"\n[+] Active hosts ready for next step: {active_hosts}")

    except KeyboardInterrupt:
        print("\n\n[-] User interrupted the program (Ctrl+C). Exiting safely...")
        sys.exit(0)


if __name__ == "__main__":
    main()