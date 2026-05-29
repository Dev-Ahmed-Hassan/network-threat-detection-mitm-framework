from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass


@dataclass
class BaselineComparison:
    new_ips: list[str]
    missing_ips: list[str]
    changed_ips: list[str]
    duplicate_macs: dict[str, list[str]]
    gateway_changed: bool

    def has_changes(self) -> bool:
        return any(
            [
                self.new_ips,
                self.missing_ips,
                self.changed_ips,
                self.duplicate_macs,
                self.gateway_changed,
            ]
        )


def compare_baseline(
    baseline: dict[str, str],
    current: dict[str, str],
    *,
    gateway_ip: str | None = None,
) -> BaselineComparison:
    baseline_ips = set(baseline)
    current_ips = set(current)
    changed_ips = sorted(
        ip for ip in baseline_ips & current_ips if baseline[ip].lower() != current[ip].lower()
    )

    mac_to_ips: dict[str, list[str]] = defaultdict(list)
    for ip, mac in current.items():
        mac_to_ips[mac.lower()].append(ip)

    duplicate_macs = {
        mac: sorted(ips, key=ip_sort_key)
        for mac, ips in mac_to_ips.items()
        if len(ips) > 1
    }

    return BaselineComparison(
        new_ips=sorted(current_ips - baseline_ips, key=ip_sort_key),
        missing_ips=sorted(baseline_ips - current_ips, key=ip_sort_key),
        changed_ips=sorted(changed_ips, key=ip_sort_key),
        duplicate_macs=duplicate_macs,
        gateway_changed=bool(gateway_ip and gateway_ip in changed_ips),
    )


def ip_sort_key(ip: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in ip.split("."))
    except ValueError:
        return (999, 999, 999, 999)
