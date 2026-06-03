from __future__ import annotations

import argparse
import signal
import threading

from offensive.arp_spoofer import run_spoofer


def main() -> None:
    parser = argparse.ArgumentParser(description="ARP spoofer terminal runner")
    parser.add_argument("--iface", required=True)
    parser.add_argument("--victim-ip", required=True)
    parser.add_argument("--server-ip", required=True)
    parser.add_argument("--spoof-interval", type=int, default=2)

    args = parser.parse_args()

    stop_event = threading.Event()

    def handle_stop(signum, frame):
        print("\n[*] Stop requested. Restoring ARP tables...")
        stop_event.set()

    signal.signal(signal.SIGINT, handle_stop)
    signal.signal(signal.SIGTERM, handle_stop)


    run_spoofer(
        iface=args.iface,
        victim_ip=args.victim_ip,
        server_ip=args.server_ip,
        spoof_interval=args.spoof_interval,
        stop_event=stop_event,
        ready_event=None,
    )


if __name__ == "__main__":
    main()