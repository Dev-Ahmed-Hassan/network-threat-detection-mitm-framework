from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from config.constants import ALERT_LOG_FILE, BASELINE_FILE, DETECTOR_HEALTH_FILE
from config.runtime_config import RuntimeConfig
from defensive.baseline_manager import BaselineManager
from defensive.log_session import create_log_session


class DefenseStartError(RuntimeError):
    pass


@dataclass
class TaskStatus:
    name: str
    running: bool
    started_at: float | None
    last_error: str | None


class ManagedProcessTask:
    def __init__(self, name: str):
        self.name = name
        self._process: subprocess.Popen | None = None
        self._started_at: float | None = None
        self._last_error: str | None = None

    def start(self, command: list[str], cwd: Path) -> None:
        if self.is_running():
            raise DefenseStartError(f"{self.name} is already running.")

        term_command = _wrap_with_terminal(command)
        if not term_command:
            raise DefenseStartError(f"No supported terminal emulator found for {self.name} window.")

        self._last_error = None
        try:
            self._process = subprocess.Popen(term_command, cwd=str(cwd))
        except OSError as exc:
            raise DefenseStartError(f"Could not launch {self.name} window: {exc}") from exc

        time.sleep(0.25)
        if self._process.poll() is not None:
            code = self._process.returncode
            self._last_error = f"{self.name} window exited immediately (code {code})."
            self._process = None
            raise DefenseStartError(self._last_error)

        self._started_at = time.time()

    def stop(self) -> None:
        if not self._process:
            return
        if self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=3)
        self._process = None
        self._started_at = None

    def is_running(self) -> bool:
        return bool(self._process and self._process.poll() is None)

    def status(self) -> TaskStatus:
        if self._process and self._process.poll() is not None:
            code = self._process.returncode
            self._last_error = f"{self.name} window closed (code {code})."
            self._process = None
            self._started_at = None
        return TaskStatus(
            name=self.name,
            running=self.is_running(),
            started_at=self._started_at,
            last_error=self._last_error,
        )


class DefenseSession:
    def __init__(self, project_root: Path):
        self.arp_detector = ManagedProcessTask("ARP Detector")
        self.selected_protected_ips: set[str] = set()
        self.monitor_mode = "full baseline"
        self.current_session_dir: Path | None = None
        self._project_root = project_root

    def start_full_baseline_monitor(self, config: RuntimeConfig) -> None:
        self._start_detector(config, protected_ips=set(), mode="full baseline")

    def start_selected_monitor(self, config: RuntimeConfig) -> None:
        if not self.selected_protected_ips:
            raise DefenseStartError("No selected protected IPs. Select devices first.")
        self._start_detector(
            config,
            protected_ips=self.selected_protected_ips,
            mode=f"selected hosts ({len(self.selected_protected_ips)})",
        )

    def stop_arp_detector(self) -> None:
        self.arp_detector.stop()

    def stop_all(self) -> None:
        self.stop_arp_detector()

    def statuses(self) -> list[TaskStatus]:
        return [self.arp_detector.status()]

    def any_running(self) -> bool:
        return any(status.running for status in self.statuses())

    def _start_detector(self, config: RuntimeConfig, protected_ips: set[str], mode: str) -> None:
        self._ensure_root()
        self._ensure_monitor_ready(config, protected_ips)
        session_paths = create_log_session()
        self.current_session_dir = session_paths["session_dir"]
        self.arp_detector.start(
            self._detector_command(config, protected_ips, session_paths),
            self._project_root,
        )
        self.monitor_mode = mode

    @staticmethod
    def _detector_command(
        config: RuntimeConfig,
        protected_ips: set[str],
        session_paths: dict[str, Path],
    ) -> list[str]:
        command = [
            sys.executable,
            "-u",
            "-m",
            "defensive.detector_runner",
            "--iface",
            config.iface or "",
            "--baseline-path",
            str(BASELINE_FILE),
            "--alert-log",
            str(session_paths["alert_log"]),
            "--current-alert-log",
            str(ALERT_LOG_FILE),
            "--health-file",
            str(session_paths["health_file"]),
            "--current-health-file",
            str(DETECTOR_HEALTH_FILE),
        ]
        if config.gateway_ip:
            command.extend(["--gateway-ip", config.gateway_ip])
        for ip in sorted(protected_ips, key=ip_sort_key):
            command.extend(["--protected-ip", ip])
        return command

    @staticmethod
    def _ensure_root() -> None:
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            raise DefenseStartError("Defense options require sudo/root privileges.")

    @staticmethod
    def _ensure_monitor_ready(config: RuntimeConfig, protected_ips: set[str]) -> None:
        if not config.iface:
            raise DefenseStartError("Interface is missing. Auto-detect or edit defense configuration.")
        try:
            baseline = BaselineManager()
        except FileNotFoundError as exc:
            raise DefenseStartError(str(exc)) from exc

        entries = baseline.all_entries()
        if not entries:
            raise DefenseStartError("Baseline is empty. Rebuild the baseline first.")

        missing = sorted(ip for ip in protected_ips if ip not in entries)
        if missing:
            raise DefenseStartError(f"Selected IPs are missing from baseline: {', '.join(missing)}")


def ip_sort_key(ip: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in ip.split("."))
    except ValueError:
        return (999, 999, 999, 999)


def _wrap_with_terminal(command: list[str]) -> list[str] | None:
    if shutil.which("gnome-terminal"):
        return ["gnome-terminal", "--", *command]
    if shutil.which("konsole"):
        return ["konsole", "-e", *command]
    if shutil.which("xterm"):
        return ["xterm", "-e", *command]
    if shutil.which("x-terminal-emulator"):
        quoted = " ".join(shlex.quote(part) for part in command)
        return ["x-terminal-emulator", "-e", quoted]
    return None
