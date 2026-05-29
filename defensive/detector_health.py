from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from config.constants import DETECTOR_HEALTH_FILE


def write_health(
    *,
    path: Path = DETECTOR_HEALTH_FILE,
    current_path: Path | None = DETECTOR_HEALTH_FILE,
    status: str,
    iface: str,
    baseline_path: Path,
    protected_hosts: int,
    started_at: str,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "status": status,
        "pid": os.getpid(),
        "iface": iface,
        "baseline_path": str(baseline_path),
        "protected_hosts": protected_hosts,
        "started_at": started_at,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    _write_health_file(path, payload)
    if current_path and current_path != path:
        _write_health_file(current_path, payload)


def _write_health_file(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2, sort_keys=True)


def read_health(path: Path = DETECTOR_HEALTH_FILE) -> dict | None:
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError):
        return None


def heartbeat_age_seconds(health: dict | None) -> int | None:
    if not health or not health.get("updated_at"):
        return None
    try:
        from datetime import datetime

        updated_at = datetime.fromisoformat(str(health["updated_at"]))
        return max(0, int(time.time() - updated_at.timestamp()))
    except ValueError:
        return None
