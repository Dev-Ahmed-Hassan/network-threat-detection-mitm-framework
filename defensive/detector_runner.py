from __future__ import annotations

import argparse
import os
import signal
import sys
from pathlib import Path

from config.constants import ALERT_LOG_FILE, BASELINE_FILE, DETECTOR_HEALTH_FILE, IFACE
from defensive.arp_detector import ARPDetector


def require_root() -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        sys.exit("Error: run this script with sudo because packet sniffing needs raw socket access.")


def main() -> None:
    parser = argparse.ArgumentParser(description="ARP baseline detector runner")
    parser.add_argument("--iface", default=IFACE)
    parser.add_argument("--baseline-path", type=Path, default=BASELINE_FILE)
    parser.add_argument("--alert-log", type=Path, default=ALERT_LOG_FILE)
    parser.add_argument("--current-alert-log", type=Path, default=ALERT_LOG_FILE)
    parser.add_argument("--health-file", type=Path, default=DETECTOR_HEALTH_FILE)
    parser.add_argument("--current-health-file", type=Path, default=DETECTOR_HEALTH_FILE)
    parser.add_argument("--gateway-ip")
    parser.add_argument(
        "--protected-ip",
        action="append",
        default=[],
        help="Protect only this IP. May be passed multiple times. Omit to protect the full baseline.",
    )
    args = parser.parse_args()

    require_root()

    def handle_stop(signum, frame):
        print("\n[*] Stop requested. Exiting ARP detector...")
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, handle_stop)
    signal.signal(signal.SIGTERM, handle_stop)

    try:
        detector = ARPDetector(
            iface=args.iface,
            baseline_path=args.baseline_path,
            alert_log_path=args.alert_log,
            current_alert_log_path=args.current_alert_log,
            health_path=args.health_file,
            current_health_path=args.current_health_file,
            protected_ips=set(args.protected_ip),
            gateway_ip=args.gateway_ip,
        )
        detector.start()
    except KeyboardInterrupt:
        print("[*] ARP detector stopped.")


if __name__ == "__main__":
    main()
