from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from config.constants import (
    ALERT_LOG_FILE,
    DETECTOR_HEALTH_FILE,
    SESSION_LOG_DIR,
)


def create_log_session() -> dict[str, Path]:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    session_dir = SESSION_LOG_DIR / f"session_{timestamp}"
    session_dir.mkdir(parents=True, exist_ok=True)

    paths = {
        "session_dir": session_dir,
        "alert_log": session_dir / "alerts.jsonl",
        "health_file": session_dir / "detector_health.json",
    }
    write_current_session(paths)
    reset_current_files()
    return paths


def write_current_session(paths: dict[str, Path]) -> None:
    ALERT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    payload = {key: str(value) for key, value in paths.items()}
    with open(ALERT_LOG_FILE.parent / "current_session.json", "w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2, sort_keys=True)


def reset_current_files() -> None:
    ALERT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    ALERT_LOG_FILE.write_text("", encoding="utf-8")
    if DETECTOR_HEALTH_FILE.exists():
        DETECTOR_HEALTH_FILE.unlink()


def current_session_paths() -> dict[str, Path] | None:
    path = ALERT_LOG_FILE.parent / "current_session.json"
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as file:
            data = json.load(file)
    except (OSError, json.JSONDecodeError):
        return None

    return {key: Path(value) for key, value in data.items()}
