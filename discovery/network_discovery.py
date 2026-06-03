from __future__ import annotations

import os
import socket
import argparse
import sys
import subprocess
from pathlib import Path


HOSTNAME_LOOKUP_TIMEOUT = 1.0

class NetworkScanError(RuntimeError):
    pass


class NetworkScanPermissionError(NetworkScanError):
    pass


def resolve_hostname(ip: str) -> str:
    for resolver in (
        _resolve_hostname_getent,
        _resolve_hostname_avahi,
        _resolve_hostname_netbios,
        _resolve_hostname_reverse_dns,
    ):
        hostname = resolver(ip)
        if hostname:
            return hostname
    return "Unknown"


def _clean_hostname(value: str | None, ip: str) -> str | None:
    if not value:
        return None
    hostname = value.strip().rstrip(".")
    if not hostname or hostname == ip or hostname.lower() == "unknown":
        return None
    return hostname


def _run_lookup_command(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=HOSTNAME_LOOKUP_TIMEOUT,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""
    return result.stdout


def _resolve_hostname_getent(ip: str) -> str | None:
    output = _run_lookup_command(["getent", "hosts", ip])
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            return _clean_hostname(parts[1], ip)
    return None


def _resolve_hostname_avahi(ip: str) -> str | None:
    output = _run_lookup_command(["avahi-resolve-address", ip])
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            return _clean_hostname(parts[-1], ip)
    return None


def _resolve_hostname_netbios(ip: str) -> str | None:
    output = _run_lookup_command(["nmblookup", "-A", ip])
    for line in output.splitlines():
        if "<00>" not in line or "GROUP" in line:
            continue
        hostname = _clean_hostname(line.split("<00>", 1)[0], ip)
        if hostname:
            return hostname
    return None


def _resolve_hostname_reverse_dns(ip: str) -> str | None:
    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(HOSTNAME_LOOKUP_TIMEOUT)
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(previous_timeout)
    return _clean_hostname(hostname, ip)


def scan_subnet(subnet: str, iface: str) -> list[dict[str, str]]:
    """
    Scan the local subnet using ARP requests.

    Returns a list of {"ip": "...", "mac": "...", "hostname": "..."} dictionaries.
    """
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise NetworkScanPermissionError("ARP scanning requires root privileges. Run the app using sudo.")

    try:
        from scanner.arp_scanner import scan_subnet as arp_scan_subnet

        ip_mac_map = arp_scan_subnet(subnet, iface)
    except PermissionError as exc:
        raise NetworkScanPermissionError("ARP scanning requires root privileges. Run the app using sudo.") from exc
    except Exception as exc:
        raise NetworkScanError(f"Could not scan subnet: {exc}") from exc

    return [
        {
            "ip": ip,
            "mac": mac,
            "hostname": resolve_hostname(ip),
        }
        for ip, mac in sorted(ip_mac_map.items(), key=lambda item: _ip_sort_key(item[0]))
    ]


def _ip_sort_key(ip: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in ip.split("."))
    except ValueError:
        return (999, 999, 999, 999)


def main() -> None:
    # Allows running this file directly:
    # sudo python3 discovery/network_discovery.py
    project_root = Path(__file__).resolve().parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    parser = argparse.ArgumentParser(description="Test network discovery scan.")
    parser.add_argument("--subnet", help="Subnet CIDR, e.g. 192.168.11.0/24")
    parser.add_argument("--iface", help="Network interface, e.g. wlp69s0")
    args = parser.parse_args()

    subnet = args.subnet
    iface = args.iface

    if not subnet or not iface:
        from config.runtime_config import RuntimeConfig

        config = RuntimeConfig.from_defaults()
        subnet = subnet or config.subnet
        iface = iface or config.iface

    print(f"[*] Scanning subnet: {subnet}")
    print(f"[*] Interface: {iface}")

    try:
        devices = scan_subnet(subnet, iface)
    except NetworkScanPermissionError as exc:
        print(f"[!] Permission error: {exc}")
        return
    except NetworkScanError as exc:
        print(f"[!] Scan error: {exc}")
        return

    if not devices:
        print("[!] No devices found.")
        return

    print("[+] Devices found:")
    for device in devices:
        print(
            f"    {device['ip']:<16}"
            f"{device['mac']:<20}"
            f"{device.get('hostname', 'Unknown')}"
        )


if __name__ == "__main__":
    main()
