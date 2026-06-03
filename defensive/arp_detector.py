from __future__ import annotations

import json
import os
import sys
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import ARP, sniff

from config.constants import (
    ALERT_LOG_FILE,
    ARP_DETECTION_COOLDOWN,
    BASELINE_FILE,
    DETECTOR_HEALTH_FILE,
    IFACE,
    PROTECTED_IP,
    PROTECTED_NAME,
)
from defensive.baseline_manager import BaselineManager
from defensive.detector_health import write_health


@dataclass
class Alert:
    timestamp: str
    severity: str
    event: str
    source_ip: str
    expected_mac: str | None
    observed_mac: str
    rule: str
    asset: str = "Baseline Host"
    details: str = ""

    def print_alert(self) -> None:
        print()
        print("=" * 70)
        print(f"[{self.severity}] {self.event}")
        print(f"Time:         {self.timestamp}")
        print(f"Asset:        {self.asset}")
        print(f"Source IP:    {self.source_ip}")
        print(f"Expected MAC: {self.expected_mac}")
        print(f"Observed MAC: {self.observed_mac}")
        print(f"Rule:         {self.rule}")
        if self.details:
            print(f"Details:      {self.details}")
        print("Meaning:      Possible ARP spoofing / MITM activity")
        print("=" * 70)
        print()


class ARPDetector:
    def __init__(
        self,
        *,
        iface: str = IFACE,
        baseline_path: Path = BASELINE_FILE,
        alert_log_path: Path = ALERT_LOG_FILE,
        current_alert_log_path: Path | None = ALERT_LOG_FILE,
        health_path: Path = DETECTOR_HEALTH_FILE,
        current_health_path: Path | None = DETECTOR_HEALTH_FILE,
        protected_ips: set[str] | None = None,
        protected_name: str = PROTECTED_NAME,
        gateway_ip: str | None = None,
        cooldown: int = ARP_DETECTION_COOLDOWN,
        high_frequency_window: int = 10,
        high_frequency_threshold: int = 25,
    ):
        self.iface = iface
        self.baseline_path = Path(baseline_path)
        self.alert_log_path = Path(alert_log_path)
        self.current_alert_log_path = Path(current_alert_log_path) if current_alert_log_path else None
        self.health_path = Path(health_path)
        self.current_health_path = Path(current_health_path) if current_health_path else None
        self.protected_ips = set(protected_ips or [])
        self.protected_name = protected_name
        self.gateway_ip = gateway_ip
        self.cooldown = cooldown
        self.high_frequency_window = high_frequency_window
        self.high_frequency_threshold = high_frequency_threshold

        self.baseline = BaselineManager(self.baseline_path)
        self.full_baseline_table = self.baseline.all_entries()
        self.baseline_table = self._filtered_baseline()
        self.last_alert_times: dict[tuple[str, str, str], float] = {}
        self.observed_ip_to_mac: dict[str, str] = {}
        self.observed_mac_to_ips: dict[str, set[str]] = {}
        self.packet_times_by_ip: dict[str, list[float]] = {}
        self.unknown_ips_seen: set[str] = set()
        self.started_at = datetime.now(timezone.utc).isoformat()

        if not self.baseline_table:
            raise RuntimeError(
                f"No protected hosts found in baseline {self.baseline_path}. "
                "Rebuild the baseline or select valid protected IPs."
            )

    def _filtered_baseline(self) -> dict[str, str]:
        if not self.protected_ips:
            return self.full_baseline_table
        return {ip: mac for ip, mac in self.full_baseline_table.items() if ip in self.protected_ips}

    def should_suppress_alert(self, rule: str, source_ip: str, observed_mac: str) -> bool:
        now = time.time()
        key = (rule, source_ip, observed_mac)
        last_alert_time = self.last_alert_times.get(key, 0)
        if now - last_alert_time < self.cooldown:
            return True

        self.last_alert_times[key] = now
        return False

    def inspect_packet(self, packet) -> None:
        if not packet.haslayer(ARP):
            return

        arp = packet[ARP]
        source_ip = str(arp.psrc)
        observed_mac = str(arp.hwsrc).lower()

        self._record_observation(source_ip, observed_mac)
        self._check_new_device(source_ip, observed_mac)
        self._check_known_ip_mac_mismatch(source_ip, observed_mac)
        self._check_duplicate_mac(source_ip, observed_mac)
        self._check_high_frequency(source_ip, observed_mac)

    def _record_observation(self, source_ip: str, observed_mac: str) -> None:
        self.observed_ip_to_mac[source_ip] = observed_mac
        self.observed_mac_to_ips.setdefault(observed_mac, set()).add(source_ip)

    def _check_known_ip_mac_mismatch(self, source_ip: str, observed_mac: str) -> None:
        expected_mac = self.baseline_table.get(source_ip)
        if not expected_mac or observed_mac == expected_mac:
            return

        event = "Known IP MAC Mismatch Detected"
        rule = "rule_known_ip_mac_mismatch"
        if self.gateway_ip and source_ip == self.gateway_ip:
            event = "Gateway MAC Mismatch Detected"
            rule = "rule_gateway_mac_mismatch"

        self.emit_alert(
            severity="CRITICAL",
            event=event,
            source_ip=source_ip,
            expected_mac=expected_mac,
            observed_mac=observed_mac,
            rule=rule,
            asset=self._asset_label(source_ip),
        )

    def _check_new_device(self, source_ip: str, observed_mac: str) -> None:
        if source_ip in self.full_baseline_table or source_ip in self.unknown_ips_seen:
            return

        self.unknown_ips_seen.add(source_ip)
        self.emit_alert(
            severity="INFO",
            event="New Device Observed Outside Baseline",
            source_ip=source_ip,
            expected_mac=None,
            observed_mac=observed_mac,
            rule="rule_new_device_observed",
            asset="Unknown Host",
        )

    def _check_duplicate_mac(self, source_ip: str, observed_mac: str) -> None:
        claimed_ips = self.observed_mac_to_ips.get(observed_mac, set())
        protected_claims = sorted(ip for ip in claimed_ips if ip in self.baseline_table)
        if len(protected_claims) < 2:
            return

        self.emit_alert(
            severity="WARNING",
            event="One MAC Address Claiming Multiple Protected IPs",
            source_ip=source_ip,
            expected_mac=self.baseline_table.get(source_ip),
            observed_mac=observed_mac,
            rule="rule_duplicate_mac_multiple_ips",
            asset=self._asset_label(source_ip),
            details=f"Claimed protected IPs: {', '.join(protected_claims)}",
        )

    def _check_high_frequency(self, source_ip: str, observed_mac: str) -> None:
        now = time.time()
        cutoff = now - self.high_frequency_window
        times = [stamp for stamp in self.packet_times_by_ip.get(source_ip, []) if stamp >= cutoff]
        times.append(now)
        self.packet_times_by_ip[source_ip] = times

        if len(times) < self.high_frequency_threshold:
            return

        self.emit_alert(
            severity="WARNING",
            event="High-Frequency ARP Activity Detected",
            source_ip=source_ip,
            expected_mac=self.baseline_table.get(source_ip),
            observed_mac=observed_mac,
            rule="rule_high_frequency_arp",
            asset=self._asset_label(source_ip),
            details=(
                f"{len(times)} ARP packets observed in "
                f"{self.high_frequency_window} seconds"
            ),
        )

    def emit_alert(
        self,
        *,
        severity: str,
        event: str,
        source_ip: str,
        expected_mac: str | None,
        observed_mac: str,
        rule: str,
        asset: str,
        details: str = "",
    ) -> None:
        if self.should_suppress_alert(rule, source_ip, observed_mac):
            return

        alert = Alert(
            timestamp=datetime.now(timezone.utc).isoformat(),
            severity=severity,
            event=event,
            source_ip=source_ip,
            expected_mac=expected_mac,
            observed_mac=observed_mac,
            rule=rule,
            asset=asset,
            details=details,
        )
        alert.print_alert()
        self.log_alert(alert)

    def log_alert(self, alert: Alert) -> None:
        line = json.dumps(asdict(alert), sort_keys=True) + "\n"
        self._append_alert_line(self.alert_log_path, line)
        if self.current_alert_log_path and self.current_alert_log_path != self.alert_log_path:
            self._append_alert_line(self.current_alert_log_path, line)

    @staticmethod
    def _append_alert_line(path: Path, line: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as file:
            file.write(line)

    def _asset_label(self, source_ip: str) -> str:
        if source_ip == PROTECTED_IP:
            return self.protected_name
        if self.gateway_ip and source_ip == self.gateway_ip:
            return "Default Gateway"
        return "Baseline Host"

    def start(self) -> None:
        print("[+] ARP baseline detector started")
        print(f"[*] Interface:       {self.iface}")
        print(f"[*] Baseline file:   {self.baseline_path}")
        print(f"[*] Alert log:       {self.alert_log_path}")
        print(f"[*] Health file:     {self.health_path}")
        print(f"[*] Protected hosts: {len(self.baseline_table)}")
        print("[*] Monitoring ARP traffic...")
        print()

        self._start_health_heartbeat()

        sniff(
            iface=self.iface,
            filter="arp",
            prn=self.inspect_packet,
            store=False,
        )

    def _start_health_heartbeat(self) -> None:
        def heartbeat() -> None:
            while True:
                write_health(
                    path=self.health_path,
                    current_path=self.current_health_path,
                    status="running",
                    iface=self.iface,
                    baseline_path=self.baseline_path,
                    protected_hosts=len(self.baseline_table),
                    started_at=self.started_at,
                )
                time.sleep(2)

        thread = threading.Thread(target=heartbeat, name="detector-health", daemon=True)
        thread.start()


def require_root() -> None:
    if os.geteuid() != 0:
        sys.exit("Error: run this script with sudo because packet sniffing needs raw socket access.")


def main() -> None:
    require_root()
    detector = ARPDetector()
    detector.start()


if __name__ == "__main__":
    main()
