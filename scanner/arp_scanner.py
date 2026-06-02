import json
import os
import sys
from pathlib import Path

from scapy.all import ARP, Ether, srp

from config.constants import IFACE, SUBNET, BASELINE_FILE


def require_root():
    if os.geteuid() != 0:
        sys.exit("Error: run this script with sudo because Scapy needs raw socket access.")


def scan_subnet(
    subnet: str,
    iface: str,
    timeout: float = 5.0,
    retries: int = 3,
) -> dict[str, str]:
    """
    Sends ARP who-has requests across the subnet and returns:
    {
        "ip": "mac"
    }
    """
    ip_mac_map = {}

    for attempt in range(retries):
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)

        answered, unanswered = srp(
            packet,
            timeout=timeout,
            iface=iface,
            verbose=0,
            inter=0.01,
        )

        for _, received in answered:
            ip_mac_map[received.psrc] = received.hwsrc.lower()

    return ip_mac_map


def save_baseline(ip_mac_map: dict[str, str], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as file:
        json.dump(ip_mac_map, file, indent=2)

    print(f"[+] Baseline saved to {path}")


def main():
    require_root()

    print(f"[*] Scanning subnet: {SUBNET}")
    print(f"[*] Interface: {IFACE}")

    results = scan_subnet(SUBNET, IFACE)

    if not results:
        print("[!] No hosts discovered. Check subnet, interface, and VM network mode.")
    else:
        print("[+] Hosts discovered:")
        for ip, mac in sorted(results.items()):
            print(f"    {ip:<15} {mac}")

    save_baseline(results, BASELINE_FILE)


if __name__ == "__main__":
    main()
