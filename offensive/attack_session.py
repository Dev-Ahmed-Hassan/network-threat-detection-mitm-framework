from __future__ import annotations

import contextlib
import os
import shlex
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from config.runtime_config import RuntimeConfig


class AttackStartError(RuntimeError):
    pass


@dataclass
class TaskStatus:
    name: str
    running: bool
    started_at: float | None
    last_error: str | None


class ManagedThreadTask:
    def __init__(self, name: str, target):
        self.name = name
        self._target = target
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._ready_event = threading.Event()
        self._started_at: float | None = None
        self._last_error: str | None = None

    def start(self, config: RuntimeConfig) -> None:
        if self.is_running():
            raise AttackStartError(f"{self.name} is already running.")

        self._stop_event = threading.Event()
        self._ready_event = threading.Event()
        self._last_error = None
        self._thread = threading.Thread(
            target=self._run,
            args=(config.snapshot(), self._stop_event, self._ready_event),
            name=f"attack-{self.name.lower()}",
            daemon=True,
        )
        self._thread.start()

        if not self._ready_event.wait(timeout=4):
            time.sleep(0.1)
            if self._last_error:
                self._cleanup_if_dead()
                raise AttackStartError(f"{self.name} failed to start: {self._last_error}")
            if not self.is_running():
                self._cleanup_if_dead()
                raise AttackStartError(f"{self.name} exited before becoming ready.")
            raise AttackStartError(f"{self.name} did not become ready in time.")

        self._started_at = time.time()

    def stop(self, timeout: float = 8.0) -> None:
        if not self._thread:
            return
        self._stop_event.set()
        self._thread.join(timeout=timeout)
        self._cleanup_if_dead()

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def status(self) -> TaskStatus:
        self._cleanup_if_dead()
        return TaskStatus(
            name=self.name,
            running=self.is_running(),
            started_at=self._started_at,
            last_error=self._last_error,
        )

    def _cleanup_if_dead(self) -> None:
        if self._thread and not self._thread.is_alive():
            self._thread = None
            self._started_at = None

    def _run(
        self,
        config: RuntimeConfig,
        stop_event: threading.Event,
        ready_event: threading.Event,
    ) -> None:
        try:
            with open(os.devnull, "w", encoding="utf-8") as null_out:
                with contextlib.redirect_stdout(null_out), contextlib.redirect_stderr(null_out):
                    self._target(config, stop_event, ready_event)
        except BaseException as exc:
            self._last_error = str(exc)
        finally:
            self._started_at = None


class ManagedProcessTask:
    def __init__(self, name: str):
        self.name = name
        self._process: subprocess.Popen | None = None
        self._started_at: float | None = None
        self._last_error: str | None = None
        

    def start(self, command: list[str], cwd: Path) -> None:
        if self.is_running():
            raise AttackStartError(f"{self.name} is already running.")

        self._last_error = None
        term_command = _wrap_with_terminal(command)
        if not term_command:
            raise AttackStartError(f"No supported terminal emulator found for {self.name} window.")

        try:
            self._process = subprocess.Popen(term_command, cwd=str(cwd))
        except OSError as exc:
            raise AttackStartError(f"Could not launch {self.name} window: {exc}") from exc

        time.sleep(0.25)
        if self._process.poll() is not None:
            code = self._process.returncode
            self._last_error = f"{self.name} window exited immediately (code {code})."
            self._process = None
            raise AttackStartError(self._last_error)

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


class AttackSession:
    def __init__(self):
        self.spoofer = ManagedProcessTask("Spoofer")
        self.interceptor = ManagedProcessTask("Interceptor")
        self._project_root = Path(__file__).resolve().parent.parent
        self._spoofer_config: RuntimeConfig | None = None

    def start_spoofer(self, config: RuntimeConfig) -> None:
        self._ensure_ready(config)
        self._ensure_root()

        snapshot = config.snapshot()
        self.spoofer.start(self._spoofer_command(snapshot), self._project_root)
        self._spoofer_config = snapshot

    def start_interceptor(self, config: RuntimeConfig, output_mode: str = "demo") -> None:
        self._ensure_ready(config)
        self._ensure_root()
        self.interceptor.start(
            self._interceptor_command(config, output_mode),
            self._project_root,
        )

    def start_full_mitm(self, config: RuntimeConfig, output_mode: str = "demo") -> None:
        self._ensure_ready(config)
        self._ensure_root()

        started_spoofer_here = False

        if not self.spoofer.is_running():
            snapshot = config.snapshot()
            self.spoofer.start(self._spoofer_command(snapshot), self._project_root)
            self._spoofer_config = snapshot
            started_spoofer_here = True

        if not self.interceptor.is_running():
            try:
                self.interceptor.start(
                    self._interceptor_command(config, output_mode),
                    self._project_root,
                )
            except AttackStartError:
                if started_spoofer_here:
                    self.stop_spoofer()
                raise

    def stop_spoofer(self) -> None:
        restore_config = self._spoofer_config

        self.spoofer.stop()

        if restore_config is not None:
            self._restore_arp_tables(restore_config)
            self._spoofer_config = None

    def stop_interceptor(self) -> None:
        self.interceptor.stop()

    def stop_all(self) -> None:
        self.interceptor.stop()
        self.stop_spoofer()

    def statuses(self) -> list[TaskStatus]:
        return [self.spoofer.status(), self.interceptor.status()]

    def any_running(self) -> bool:
        return any(status.running for status in self.statuses())

    def _spoofer_command(self, config: RuntimeConfig) -> list[str]:
        return [
            sys.executable,
            "-u",
            "-m",
            "offensive.spoofer_runner",
            "--iface",
            config.iface,
            "--victim-ip",
            config.victim_ip,
            "--server-ip",
            config.server_ip,
            "--spoof-interval",
            str(config.spoof_interval),
        ]
    def _interceptor_command(self, config: RuntimeConfig, output_mode: str = "demo") -> list[str]:
        if output_mode not in {"demo", "debug"}:
            raise AttackStartError(f"Invalid interceptor output mode: {output_mode}")

        return [
            sys.executable,
            "-u",
            "-m",
            "offensive.interceptor",
            "--output",
            output_mode,
            "--transport",
            config.transport_mode,
            "--iface",
            config.iface,
            "--victim-ip",
            config.victim_ip,
            "--server-ip",
            config.server_ip,
            "--backend-port",
            str(config.backend_port),
        ]
    

    @staticmethod
    def _ensure_ready(config: RuntimeConfig) -> None:
        if not config.is_ready():
            raise AttackStartError("Final configuration is not ready.")

    @staticmethod
    def _ensure_root() -> None:
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            raise AttackStartError("Attack options require sudo/root privileges.")

    @staticmethod
    def _restore_arp_tables(config: RuntimeConfig) -> None:
        from offensive.arp_spoofer import get_mac, restore_runtime

        print("[*] Attempting ARP table restore from attack session...")

        victim_mac = get_mac(config.victim_ip, config.iface)
        server_mac = get_mac(config.server_ip, config.iface)

        if not victim_mac:
            print(f"[WARN] Could not resolve victim MAC for restore: {config.victim_ip}")
            return

        if not server_mac:
            print(f"[WARN] Could not resolve server MAC for restore: {config.server_ip}")
            return

        restore_runtime(
            iface=config.iface,
            victim_ip=config.victim_ip,
            server_ip=config.server_ip,
            victim_mac=victim_mac,
            server_mac=server_mac,
            count=8,
        )

    @staticmethod
    def _run_spoofer(
        config: RuntimeConfig,
        stop_event: threading.Event,
        ready_event: threading.Event,
    ) -> None:
        from offensive.arp_spoofer import run_spoofer

        run_spoofer(
            iface=config.iface,
            victim_ip=config.victim_ip,
            server_ip=config.server_ip,
            spoof_interval=config.spoof_interval,
            stop_event=stop_event,
            ready_event=ready_event,
        )


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
