from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from config.constants import BASELINE_DIR, BASELINE_FILE


def save_current_and_archive(
    ip_mac_map: dict[str, str],
    *,
    current_path: Path = BASELINE_FILE,
    baseline_dir: Path = BASELINE_DIR,
) -> Path:
    baseline_dir.mkdir(parents=True, exist_ok=True)
    current_path.parent.mkdir(parents=True, exist_ok=True)

    normalized = {ip: mac.lower() for ip, mac in sorted(ip_mac_map.items())}
    with open(current_path, "w", encoding="utf-8") as file:
        json.dump(normalized, file, indent=2)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    archive_path = baseline_dir / f"baseline_{timestamp}.json"
    with open(archive_path, "w", encoding="utf-8") as file:
        json.dump(normalized, file, indent=2)

    return archive_path


def list_baseline_archives(baseline_dir: Path = BASELINE_DIR) -> list[Path]:
    if not baseline_dir.exists():
        return []
    return sorted(baseline_dir.glob("baseline_*.json"))
