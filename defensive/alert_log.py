from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from config.constants import ALERT_LOG_FILE


def read_alerts(path: Path = ALERT_LOG_FILE) -> list[dict]:
    if not path.exists():
        return []

    alerts = []
    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return alerts


def filter_alerts(alerts: list[dict], severity: str = "ALL") -> list[dict]:
    if severity == "ALL":
        return alerts
    return [alert for alert in alerts if alert.get("severity") == severity]


def alert_counts(alerts: list[dict]) -> Counter:
    return Counter(str(alert.get("severity", "UNKNOWN")) for alert in alerts)
