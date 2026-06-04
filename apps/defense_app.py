from __future__ import annotations

import os
import sys
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config.constants import (  # noqa: E402
    ALERT_LOG_FILE,
    BASELINE_FILE,
    DETECTOR_HEALTH_FILE,
    PROTECTED_IP,
    PROTECTED_NAME,
)
from config.runtime_config import RuntimeConfig, validate_cidr  # noqa: E402
from defensive.alert_log import alert_counts, filter_alerts, read_alerts  # noqa: E402
from defensive.arp_table import ARPTableError, read_local_arp_table  # noqa: E402
from defensive.baseline_compare import compare_baseline  # noqa: E402
from defensive.baseline_manager import BaselineManager  # noqa: E402
from defensive.baseline_store import list_baseline_archives, save_current_and_archive  # noqa: E402
from defensive.defense_session import DefenseSession, DefenseStartError, TaskStatus  # noqa: E402
from defensive.detector_health import heartbeat_age_seconds, read_health  # noqa: E402
from defensive.log_session import current_session_paths  # noqa: E402
from discovery.interface_discovery import (  # noqa: E402
    InterfaceDetectionError,
    auto_detect_network,
)


class C:
    RESET = "\033[0m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[97m"


def color(text: str, style: str) -> str:
    return f"{style}{text}{C.RESET}"


def clear_screen() -> None:
    print("\033[2J\033[H", end="")


def pause(message: str = "Press Enter to continue...") -> None:
    input(color(message, C.DIM))


def press_any_key() -> None:
    print(color("Press any key to enter the console...", C.DIM), end="", flush=True)
    try:
        import termios
        import tty

        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    except Exception:
        input()


def splash() -> None:
    clear_screen()
    print(color("============================================================", C.GREEN))
    print(color("     __  __ ___ _____ __  __      ____       __               ", C.CYAN))
    print(color("    |  \\/  |_ _|_   _|  \\/  |    |  _ \\  ___/ _| ___ _ __  ___ ___", C.CYAN))
    print(color("    | |\\/| || |  | | | |\\/| |    | | | |/ _ \\ |_ / _ \\ '_ \\/ __/ _ \\", C.CYAN))
    print(color("    | |  | || |  | | | |  | |    | |_| |  __/  _|  __/ | | \\__ \\  __/", C.CYAN))
    print(color("    |_|  |_|___| |_| |_|  |_|    |____/ \\___|_|  \\___|_| |_|___/\\___|", C.CYAN))
    print()
    print(color("                  MITM DEFENSE MONITOR", C.BOLD + C.WHITE))
    print(color("              Defensive Lab Console / Phase 1", C.GREEN))
    print(color("============================================================", C.GREEN))
    print()
    press_any_key()


def print_banner(title: str) -> None:
    print(color("=" * 60, C.GREEN))
    print(color(title.center(60), C.BOLD + C.WHITE))
    print(color("=" * 60, C.GREEN))


def print_config(config: RuntimeConfig, title: str = "CURRENT DEFENSE CONFIGURATION") -> None:
    print_banner(title)
    print()
    rows = [
        ("Interface", config.iface or "Not selected"),
        ("Subnet", config.subnet or "Not selected"),
        ("Gateway", config.gateway_ip or "Not detected"),
        ("This Machine", config.attacker_ip or "Not detected"),
        ("Default Asset", PROTECTED_NAME),
        ("Default Asset IP", PROTECTED_IP),
        ("Baseline File", str(BASELINE_FILE)),
        ("Alert Log", str(ALERT_LOG_FILE)),
    ]
    for label, value in rows:
        rendered = value if not value.startswith("Not ") else color(value, C.YELLOW)
        print(f"{color(label + ':', C.CYAN):<26} {rendered}")
    print()


def option_prompt(max_choice: int) -> str:
    choice = input(color("Select option > ", C.GREEN)).strip().lower()
    valid_choices = {str(number) for number in range(1, max_choice + 1)}
    if choice not in valid_choices:
        print(color("Invalid option.", C.RED))
        pause()
        return ""
    return choice


def read_value(prompt: str) -> str:
    return input(color(prompt, C.CYAN)).strip()


def require_root_message() -> bool:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print(color("This action requires sudo/root privileges.", C.RED))
        return False
    return True


def auto_detect(config: RuntimeConfig, interactive: bool = True) -> bool:
    try:
        detected = auto_detect_network()
    except InterfaceDetectionError as exc:
        print(color(f"[WARN] {exc}", C.YELLOW))
        if interactive:
            print(color("You can enter the values manually from the edit menu.", C.DIM))
            pause()
        return False

    config.merge_detected(**detected)
    print(color("[OK] Auto-detected network info:", C.GREEN))
    print(f"  Interface:    {detected.get('iface') or 'Unknown'}")
    print(f"  This Machine: {detected.get('attacker_ip') or 'Unknown'}")
    print(f"  Subnet:       {detected.get('subnet') or 'Unknown'}")
    print(f"  Gateway:      {detected.get('gateway_ip') or 'Unknown'}")
    if interactive:
        pause()
    return True


def edit_config_menu(config: RuntimeConfig) -> None:
    while True:
        clear_screen()
        print_config(config, "EDIT DEFENSE CONFIGURATION")
        print(color("1.", C.GREEN), "Change interface")
        print(color("2.", C.GREEN), "Change subnet")
        print(color("3.", C.GREEN), "Back")
        print()

        choice = option_prompt(3)
        if not choice:
            continue
        if choice == "1":
            edit_interface(config)
        elif choice == "2":
            edit_subnet(config)
        elif choice == "3":
            return


def edit_interface(config: RuntimeConfig) -> None:
    value = read_value("Interface: ")
    if not value:
        print(color("Interface should not be empty.", C.RED))
    else:
        config.iface = value
        print(color("[OK] Interface updated.", C.GREEN))
    pause()


def edit_subnet(config: RuntimeConfig) -> None:
    value = read_value("Subnet CIDR: ")
    if validate_cidr(value):
        config.subnet = value
        print(color("[OK] Subnet updated.", C.GREEN))
    else:
        print(color("Enter a valid CIDR subnet, for example 192.168.1.0/24.", C.RED))
    pause()


def scan_network(config: RuntimeConfig) -> dict[str, str] | None:
    if not config.iface or not config.subnet:
        print(color("Interface and subnet are required before scanning.", C.RED))
        return None

    if not validate_cidr(config.subnet):
        print(color("Subnet is invalid. Edit defense configuration first.", C.RED))
        return None

    if not require_root_message():
        return None

    print(color(f"Scanning {config.subnet} on {config.iface}...", C.GREEN))
    try:
        from scanner.arp_scanner import scan_subnet

        return scan_subnet(config.subnet, config.iface)
    except Exception as exc:
        print(color(f"Scan failed: {exc}", C.RED))
        return None


def save_baseline_snapshot(ip_mac_map: dict[str, str]) -> None:
    archive_path = save_current_and_archive(ip_mac_map)
    print(f"[+] Baseline saved to {BASELINE_FILE}")
    print(f"[+] Baseline archived to {archive_path}")


def create_baseline_snapshot(config: RuntimeConfig, interactive: bool = True) -> dict[str, str] | None:
    ip_mac_map = scan_network(config)
    if not ip_mac_map:
        print(color("No hosts discovered. Baseline was not updated.", C.YELLOW))
        if interactive:
            pause()
        return None

    save_baseline_snapshot(ip_mac_map)
    print()
    print(color("[OK] Full baseline snapshot saved.", C.GREEN))
    print_baseline_entries(ip_mac_map)

    if interactive:
        pause()
    return ip_mac_map


def scan_and_select_protected_devices(config: RuntimeConfig, session: DefenseSession) -> None:
    clear_screen()
    print_config(config, "SCAN AND SELECT PROTECTED DEVICES")
    ip_mac_map = scan_network(config)
    if not ip_mac_map:
        print(color("No hosts discovered. Baseline was not updated.", C.YELLOW))
        pause()
        return

    save_baseline_snapshot(ip_mac_map)
    devices = entries_to_devices(ip_mac_map)

    while True:
        clear_screen()
        print_banner("DEVICES FOUND")
        print()
        print_devices(devices, config)
        print(color("Protection mode:", C.BOLD + C.WHITE))
        print(color("1.", C.GREEN), "Protect all discovered devices")
        print(color("2.", C.GREEN), "Select specific devices")
        print(color("3.", C.GREEN), "Protect gateway only")
        print(color("4.", C.GREEN), "Protect default server only")
        print(color("5.", C.GREEN), "Back")
        print()

        choice = option_prompt(5)
        if not choice:
            continue
        if choice == "1":
            session.selected_protected_ips = set(ip_mac_map)
            print(color(f"[OK] Selected all {len(session.selected_protected_ips)} discovered devices.", C.GREEN))
            pause()
            return
        if choice == "2":
            selected = select_devices(devices)
            if selected:
                session.selected_protected_ips = {device["ip"] for device in selected}
                print(color(f"[OK] Selected {len(selected)} protected devices.", C.GREEN))
            pause()
            return
        if choice == "3":
            if config.gateway_ip and config.gateway_ip in ip_mac_map:
                session.selected_protected_ips = {config.gateway_ip}
                print(color(f"[OK] Selected gateway {config.gateway_ip}.", C.GREEN))
            else:
                print(color("Gateway was not found in the scan results.", C.RED))
            pause()
            return
        if choice == "4":
            if PROTECTED_IP in ip_mac_map:
                session.selected_protected_ips = {PROTECTED_IP}
                print(color(f"[OK] Selected default server {PROTECTED_IP}.", C.GREEN))
            else:
                print(color(f"Default server {PROTECTED_IP} was not found in the scan results.", C.RED))
            pause()
            return
        if choice == "5":
            return


def select_protected_from_baseline(session: DefenseSession) -> None:
    clear_screen()
    print_banner("SELECT FROM BASELINE")
    print()
    try:
        entries = BaselineManager().all_entries()
    except FileNotFoundError as exc:
        print(color(str(exc), C.RED))
        pause()
        return

    devices = entries_to_devices(entries)
    print_devices(devices, RuntimeConfig.from_defaults())
    selected = select_devices(devices)
    if selected:
        session.selected_protected_ips = {device["ip"] for device in selected}
        print(color(f"[OK] Selected {len(selected)} protected devices.", C.GREEN))
    pause()


def select_devices(devices: list[dict[str, str]]) -> list[dict[str, str]]:
    value = read_value("Select device numbers, ranges, or 'all' (example: 1,3-5): ").lower()
    if value == "all":
        return devices

    indexes: set[int] = set()
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            try:
                start = int(start_text)
                end = int(end_text)
            except ValueError:
                print(color("Invalid range.", C.RED))
                return []
            indexes.update(range(start, end + 1))
            continue
        try:
            indexes.add(int(part))
        except ValueError:
            print(color("Enter numbers, ranges, or 'all'.", C.RED))
            return []

    if not indexes:
        print(color("No devices selected.", C.YELLOW))
        return []

    if any(index < 1 or index > len(devices) for index in indexes):
        print(color("One or more device numbers are out of range.", C.RED))
        return []

    return [devices[index - 1] for index in sorted(indexes)]


def show_baseline() -> None:
    clear_screen()
    print_banner("SAVED BASELINE")
    print()
    try:
        entries = BaselineManager().all_entries()
    except FileNotFoundError as exc:
        print(color(str(exc), C.RED))
        pause()
        return

    if not entries:
        print(color("Baseline file exists, but it does not contain any hosts.", C.YELLOW))
    else:
        print_baseline_entries(entries)

    print()
    print(color(f"Total protected by full-baseline mode: {len(entries)}", C.CYAN))
    print(color(f"Archived baselines: {len(list_baseline_archives())}", C.CYAN))
    pause()


def show_baseline_archives() -> None:
    clear_screen()
    print_banner("BASELINE ARCHIVES")
    print()
    archives = list_baseline_archives()
    if not archives:
        print(color("No archived baselines found yet.", C.YELLOW))
    else:
        for index, path in enumerate(archives, start=1):
            print(f"{color(f'[{index}]', C.GREEN):<8} {path.name}")
    pause()


def compare_current_scan_to_baseline(config: RuntimeConfig) -> None:
    clear_screen()
    print_config(config, "COMPARE CURRENT SCAN TO BASELINE")
    try:
        baseline = BaselineManager().all_entries()
    except FileNotFoundError as exc:
        print(color(str(exc), C.RED))
        pause()
        return

    current = scan_network(config)
    if current is None:
        pause()
        return

    comparison = compare_baseline(baseline, current, gateway_ip=config.gateway_ip)

    print()
    print(color("Comparison:", C.BOLD + C.WHITE))
    print(f"{color('New devices:', C.CYAN):<24} {len(comparison.new_ips)}")
    print(f"{color('Missing devices:', C.CYAN):<24} {len(comparison.missing_ips)}")
    print(f"{color('MAC changes:', C.CYAN):<24} {len(comparison.changed_ips)}")
    print(f"{color('Duplicate MACs:', C.CYAN):<24} {len(comparison.duplicate_macs)}")
    print(f"{color('Gateway changed:', C.CYAN):<24} {'yes' if comparison.gateway_changed else 'no'}")
    print()

    if comparison.changed_ips:
        print(color("MAC changes", C.RED))
        for ip in comparison.changed_ips:
            print(f"  {ip:<17} baseline={baseline[ip]} current={current[ip]}")
        print()

    if comparison.duplicate_macs:
        print(color("Duplicate MACs in current scan", C.RED))
        for mac, ips in comparison.duplicate_macs.items():
            print(f"  {mac:<20} {', '.join(ips)}")
        print()

    if comparison.new_ips:
        print(color("New devices", C.YELLOW))
        for ip in comparison.new_ips:
            print(f"  {ip:<17} {current[ip]}")
        print()

    if comparison.missing_ips:
        print(color("Missing devices", C.YELLOW))
        for ip in comparison.missing_ips:
            print(f"  {ip:<17} {baseline[ip]}")
        print()

    if not comparison.has_changes():
        print(color("[OK] Current scan matches the saved baseline.", C.GREEN))

    pause()


def show_local_arp_table() -> None:
    clear_screen()
    print_banner("LOCAL ARP TABLE")
    print()
    try:
        entries = read_local_arp_table()
    except ARPTableError as exc:
        print(color(str(exc), C.RED))
        pause()
        return

    if not entries:
        print(color("No neighbor entries found.", C.YELLOW))
    else:
        print(color("IP Address        Interface       MAC Address          State", C.BOLD + C.WHITE))
        print(color("-" * 72, C.DIM))
        for entry in entries:
            print(
                f"{entry['ip']:<17} "
                f"{entry['iface']:<15} "
                f"{entry['mac']:<20} "
                f"{entry['state']}"
            )
    print()
    print(color("Note: this is this machine's neighbor cache, not the full network baseline.", C.DIM))
    pause()


def show_recent_alerts(limit: int = 20, severity: str = "ALL") -> None:
    clear_screen()
    print_banner(f"RECENT ALERTS / {severity}")
    print()
    alerts = filter_alerts(read_alerts(), severity)
    if not ALERT_LOG_FILE.exists():
        print(color(f"No alert log found yet: {ALERT_LOG_FILE}", C.YELLOW))
        pause()
        return

    if not alerts:
        print(color(f"No {severity.lower()} alerts found.", C.YELLOW))
        pause()
        return

    print(color("Time                         Severity   Source IP        Rule", C.BOLD + C.WHITE))
    print(color("-" * 88, C.DIM))
    for alert in alerts[-limit:]:
        timestamp = str(alert.get("timestamp", ""))[:24]
        severity = str(alert.get("severity", ""))
        source_ip = str(alert.get("source_ip", ""))
        rule = str(alert.get("rule", ""))
        print(f"{timestamp:<28} {severity:<10} {source_ip:<16} {rule}")
        details = alert.get("details")
        if details:
            print(color(f"  {details}", C.DIM))
    pause()


def alert_filter_menu() -> None:
    while True:
        clear_screen()
        print_banner("ALERT FILTER")
        print()
        print(color("1.", C.GREEN), "Show all alerts")
        print(color("2.", C.GREEN), "Show CRITICAL alerts")
        print(color("3.", C.GREEN), "Show WARNING alerts")
        print(color("4.", C.GREEN), "Show INFO alerts")
        print(color("5.", C.GREEN), "Back")
        print()

        choice = option_prompt(5)
        if not choice:
            continue
        if choice == "1":
            show_recent_alerts(severity="ALL")
        elif choice == "2":
            show_recent_alerts(severity="CRITICAL")
        elif choice == "3":
            show_recent_alerts(severity="WARNING")
        elif choice == "4":
            show_recent_alerts(severity="INFO")
        elif choice == "5":
            return


def print_baseline_entries(entries: dict[str, str]) -> None:
    print(color("IP Address        MAC Address", C.BOLD + C.WHITE))
    print(color("-" * 38, C.DIM))
    for ip, mac in sorted(entries.items(), key=lambda item: ip_sort_key(item[0])):
        marker = color(" default-server", C.MAGENTA) if ip == PROTECTED_IP else ""
        print(f"{ip:<17} {mac}{marker}")


def print_devices(devices: list[dict[str, str]], config: RuntimeConfig) -> None:
    print(color("No.   IP Address        MAC Address          Label", C.BOLD + C.WHITE))
    print(color("-" * 72, C.DIM))
    for index, device in enumerate(devices, start=1):
        label = device_label(device["ip"], config)
        print(f"{index:<5} {device['ip']:<17} {device['mac']:<20} {label}")
    print()


def entries_to_devices(entries: dict[str, str]) -> list[dict[str, str]]:
    return [
        {"ip": ip, "mac": mac}
        for ip, mac in sorted(entries.items(), key=lambda item: ip_sort_key(item[0]))
    ]


def device_label(ip: str, config: RuntimeConfig) -> str:
    labels = []
    if ip == config.gateway_ip:
        labels.append("Gateway")
    if ip == config.attacker_ip:
        labels.append("This Machine")
    if ip == PROTECTED_IP:
        labels.append("Default Server")
    return ", ".join(labels) if labels else "Baseline Host"


def show_validation(config: RuntimeConfig, session: DefenseSession) -> None:
    try:
        entries = BaselineManager().all_entries()
    except FileNotFoundError:
        entries = {}

    selected_missing = sorted(ip for ip in session.selected_protected_ips if ip not in entries)
    checks = [
        ("OK" if config.iface else "ERROR", "Interface selected"),
        ("OK" if config.subnet and validate_cidr(config.subnet) else "ERROR", "Subnet is valid"),
        ("OK" if entries else "ERROR", "Baseline contains protected hosts"),
        ("OK" if not selected_missing else "ERROR", "Selected hosts exist in baseline"),
    ]

    print(color("Status:", C.BOLD + C.WHITE))
    for status, message in checks:
        style = C.GREEN if status == "OK" else C.RED
        print(f"{color(f'[{status}]', style):<18} {message}")
    print(f"{color('Selected hosts:', C.CYAN):<26} {len(session.selected_protected_ips)}")
    if selected_missing:
        print(color(f"Missing selected IPs: {', '.join(selected_missing)}", C.RED))


def build_incident_summary(alerts: list[dict]) -> dict | None:
    security_alerts = [
        alert
        for alert in alerts
        if alert.get("severity") in {"CRITICAL", "WARNING"}
    ]
    if not security_alerts:
        return None

    severity_rank = {"INFO": 1, "WARNING": 2, "CRITICAL": 3}
    highest = max(
        security_alerts,
        key=lambda alert: severity_rank.get(str(alert.get("severity")), 0),
    )
    suspected_macs = sorted(
        {
            str(alert.get("observed_mac"))
            for alert in security_alerts
            if alert.get("observed_mac")
        }
    )
    affected_ips = sorted(
        {
            str(alert.get("source_ip"))
            for alert in security_alerts
            if alert.get("source_ip")
        },
        key=ip_sort_key,
    )
    timestamps = sorted(
        str(alert.get("timestamp"))
        for alert in security_alerts
        if alert.get("timestamp")
    )

    return {
        "highest_severity": highest.get("severity", "UNKNOWN"),
        "event": highest.get("event", "Security incident"),
        "suspected_macs": suspected_macs,
        "affected_ips": affected_ips,
        "first_seen": timestamps[0] if timestamps else "Unknown",
        "last_seen": timestamps[-1] if timestamps else "Unknown",
        "alert_count": len(security_alerts),
    }


def print_incident_summary(alerts: list[dict]) -> None:
    summary = build_incident_summary(alerts)
    print()
    print(color("Incident Summary:", C.BOLD + C.WHITE))

    if not summary:
        print(color("[OK] No active warning or critical ARP incidents in current alerts.", C.GREEN))
        return

    severity = str(summary["highest_severity"])
    severity_style = C.RED if severity == "CRITICAL" else C.YELLOW
    suspected_macs = ", ".join(summary["suspected_macs"]) or "Unknown"
    affected_ips = ", ".join(summary["affected_ips"]) or "Unknown"

    print(f"{color('Highest severity:', C.CYAN):<24} {color(severity, severity_style)}")
    print(f"{color('Primary event:', C.CYAN):<24} {summary['event']}")
    print(f"{color('Suspected MAC:', C.CYAN):<24} {suspected_macs}")
    print(f"{color('Affected IPs:', C.CYAN):<24} {affected_ips}")
    print(f"{color('First seen:', C.CYAN):<24} {str(summary['first_seen'])[:24]}")
    print(f"{color('Last seen:', C.CYAN):<24} {str(summary['last_seen'])[:24]}")
    print(f"{color('Related alerts:', C.CYAN):<24} {summary['alert_count']}")
    print(color("Action: verify affected hosts, stop suspicious MITM activity, then compare or rebuild baseline.", C.YELLOW))


def show_dashboard(config: RuntimeConfig, session: DefenseSession) -> None:
    clear_screen()
    print_config(config, "DEFENSE DASHBOARD")

    try:
        baseline_count = len(BaselineManager().all_entries())
    except FileNotFoundError:
        baseline_count = 0

    alerts = read_alerts()
    counts = alert_counts(alerts)
    health = read_health()
    current_session = current_session_paths()
    heartbeat_age = heartbeat_age_seconds(health)
    health_text = "No heartbeat"
    if heartbeat_age is not None:
        health_text = f"{heartbeat_age}s ago"

    show_defense_status(session)
    print(color("Summary:", C.BOLD + C.WHITE))
    print(f"{color('Baseline hosts:', C.CYAN):<24} {baseline_count}")
    print(f"{color('Selected hosts:', C.CYAN):<24} {len(session.selected_protected_ips)}")
    print(f"{color('Alert total:', C.CYAN):<24} {len(alerts)}")
    print(f"{color('Critical alerts:', C.CYAN):<24} {counts.get('CRITICAL', 0)}")
    print(f"{color('Warning alerts:', C.CYAN):<24} {counts.get('WARNING', 0)}")
    print(f"{color('Info alerts:', C.CYAN):<24} {counts.get('INFO', 0)}")
    print(f"{color('Health heartbeat:', C.CYAN):<24} {health_text}")
    if current_session:
        print(f"{color('Log session:', C.CYAN):<24} {current_session['session_dir']}")
    if health:
        print(f"{color('Detector iface:', C.CYAN):<24} {health.get('iface', 'Unknown')}")
        print(f"{color('Detector hosts:', C.CYAN):<24} {health.get('protected_hosts', 'Unknown')}")
    print_incident_summary(alerts)
    pause()


def monitor_control_menu(config: RuntimeConfig, session: DefenseSession) -> None:
    notice: tuple[str, str] | None = None

    while True:
        clear_screen()
        print_config(config, "MONITOR CONTROL")
        show_defense_status(session)
        show_validation(config, session)
        print()

        if notice:
            style = C.GREEN if notice[0] == "OK" else C.RED
            print(color(f"[{notice[0]}] {notice[1]}", style))
            print()
            notice = None

        print(color("Options:", C.BOLD + C.WHITE))
        print(color("1.", C.GREEN), "Start full baseline monitor")
        print(color("2.", C.GREEN), "Start selected-host monitor")
        print(color("3.", C.GREEN), "Stop ARP detector")
        print(color("4.", C.GREEN), "Back")
        print(color("x.", C.RED), "PANIC STOP")
        print()

        choice = input(color("Select option > ", C.GREEN)).strip().lower()

        if choice == "1":
            notice = start_defense_action(
                lambda: session.start_full_baseline_monitor(config),
                "Full baseline monitor started.",
            )
        elif choice == "2":
            notice = start_defense_action(
                lambda: session.start_selected_monitor(config),
                "Selected-host monitor started.",
            )
        elif choice == "3":
            session.stop_arp_detector()
            notice = ("OK", "ARP detector stop requested.")
        elif choice == "4":
            return
        elif choice == "x":
            session.stop_all()
            notice = ("PANIC STOP", "All defense modules stopped.")
        else:
            notice = ("ERROR", "Invalid option.")


def start_defense_action(action, success_message: str) -> tuple[str, str]:
    try:
        action()
    except DefenseStartError as exc:
        return ("ERROR", str(exc))
    return ("OK", success_message)


def show_defense_status(session: DefenseSession) -> None:
    print(color("Module Status:", C.BOLD + C.WHITE))
    for status in session.statuses():
        print(render_task_status(status))
    print(f"{color('Monitor mode:', C.CYAN):<24} {session.monitor_mode}")
    print()


def render_task_status(status: TaskStatus) -> str:
    state = color("RUNNING", C.GREEN) if status.running else color("STOPPED", C.DIM)
    uptime = ""
    if status.running and status.started_at:
        uptime = f" uptime={format_duration(status.started_at)}"
    error = f" last_error={status.last_error}" if status.last_error else ""
    return f"{color(status.name + ':', C.CYAN):<24} {state}{uptime}{error}"


def format_duration(started_at: float) -> str:
    elapsed = max(0, int(time.time() - started_at))
    minutes, seconds = divmod(elapsed, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h{minutes:02d}m{seconds:02d}s"
    if minutes:
        return f"{minutes}m{seconds:02d}s"
    return f"{seconds}s"


def setup_baseline_menu(config: RuntimeConfig, session: DefenseSession) -> None:
    while True:
        clear_screen()
        print_config(config, "SETUP / BASELINE")
        print(color("Options:", C.BOLD + C.WHITE))
        print(color("1.", C.GREEN), "Auto-detect network info")
        print(color("2.", C.GREEN), "Edit interface and subnet")
        print(color("3.", C.GREEN), "Build full baseline")
        print(color("4.", C.GREEN), "Show saved baseline")
        print(color("5.", C.GREEN), "Show baseline archives")
        print(color("6.", C.GREEN), "Back")
        print()

        choice = option_prompt(6)
        if not choice:
            continue
        if choice == "1":
            clear_screen()
            auto_detect(config, interactive=True)
        elif choice == "2":
            edit_config_menu(config)
        elif choice == "3":
            clear_screen()
            print_config(config, "FULL BASELINE SNAPSHOT")
            ip_mac_map = create_baseline_snapshot(config, interactive=True)
            if ip_mac_map:
                session.selected_protected_ips = set(ip_mac_map)
        elif choice == "4":
            show_baseline()
        elif choice == "5":
            show_baseline_archives()
        elif choice == "6":
            return


def protected_hosts_menu(config: RuntimeConfig, session: DefenseSession) -> None:
    while True:
        clear_screen()
        print_config(config, "PROTECTED HOSTS")
        show_validation(config, session)
        print()
        print(color("Options:", C.BOLD + C.WHITE))
        print(color("1.", C.GREEN), "Scan subnet and choose protected devices")
        print(color("2.", C.GREEN), "Select protected devices from baseline")
        print(color("3.", C.GREEN), "Protect all baseline hosts")
        print(color("4.", C.GREEN), "Back")
        print()

        choice = option_prompt(4)
        if not choice:
            continue
        if choice == "1":
            scan_and_select_protected_devices(config, session)
        elif choice == "2":
            select_protected_from_baseline(session)
        elif choice == "3":
            try:
                entries = BaselineManager().all_entries()
            except FileNotFoundError as exc:
                print(color(str(exc), C.RED))
            else:
                session.selected_protected_ips = set(entries)
                print(color(f"[OK] Selected all {len(entries)} baseline hosts.", C.GREEN))
            pause()
        elif choice == "4":
            return


def investigation_menu(config: RuntimeConfig) -> None:
    while True:
        clear_screen()
        print_config(config, "INVESTIGATION")
        print(color("Options:", C.BOLD + C.WHITE))
        print(color("1.", C.GREEN), "Show alerts by severity")
        print(color("2.", C.GREEN), "Compare current scan to baseline")
        print(color("3.", C.GREEN), "Show local ARP table")
        print(color("4.", C.GREEN), "Back")
        print()

        choice = option_prompt(4)
        if not choice:
            continue
        if choice == "1":
            alert_filter_menu()
        elif choice == "2":
            compare_current_scan_to_baseline(config)
        elif choice == "3":
            show_local_arp_table()
        elif choice == "4":
            return


def reports_logs_menu() -> None:
    while True:
        clear_screen()
        print_banner("REPORTS / LOGS")
        print()
        current_session = current_session_paths()
        rows = [
            ("Current alert log", str(ALERT_LOG_FILE)),
            ("Current health file", str(DETECTOR_HEALTH_FILE)),
            ("Baseline file", str(BASELINE_FILE)),
        ]
        if current_session:
            rows.insert(0, ("Session directory", str(current_session["session_dir"])))

        for label, value in rows:
            print(f"{color(label + ':', C.CYAN):<24} {value}")
        print()
        print(color("Options:", C.BOLD + C.WHITE))
        print(color("1.", C.GREEN), "Show alerts by severity")
        print(color("2.", C.GREEN), "Show baseline archives")
        print(color("3.", C.GREEN), "Back")
        print()

        choice = option_prompt(3)
        if not choice:
            continue
        if choice == "1":
            alert_filter_menu()
        elif choice == "2":
            show_baseline_archives()
        elif choice == "3":
            return


def main_menu(config: RuntimeConfig, session: DefenseSession) -> None:
    while True:
        clear_screen()
        print_config(config)
        print(color("Options:", C.BOLD + C.WHITE))
        print(color("1.", C.GREEN), "Dashboard")
        print(color("2.", C.GREEN), "Setup / Baseline")
        print(color("3.", C.GREEN), "Protected Hosts")
        print(color("4.", C.GREEN), "Monitor Control")
        print(color("5.", C.GREEN), "Investigation")
        print(color("6.", C.GREEN), "Reports / Logs")
        print(color("7.", C.GREEN), "Exit")
        print()

        choice = option_prompt(7)
        if not choice:
            continue
        if choice == "1":
            show_dashboard(config, session)
        elif choice == "2":
            setup_baseline_menu(config, session)
        elif choice == "3":
            protected_hosts_menu(config, session)
        elif choice == "4":
            monitor_control_menu(config, session)
        elif choice == "5":
            investigation_menu(config)
        elif choice == "6":
            reports_logs_menu()
        elif choice == "7":
            if session.any_running():
                session.stop_all()
            print(color("Exiting defense console.", C.DIM))
            return


def ip_sort_key(ip: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in ip.split("."))
    except ValueError:
        return (999, 999, 999, 999)


def main() -> None:
    os.environ.setdefault("SCAPY_SUPPRESS_NO_DEFAULT_ROUTE_WARNING", "1")
    config = RuntimeConfig.from_defaults()
    session = DefenseSession(PROJECT_ROOT)

    try:
        splash()
        clear_screen()
        auto_detect(config, interactive=False)
        print()
        ip_mac_map = create_baseline_snapshot(config, interactive=False)
        if ip_mac_map:
            session.selected_protected_ips = set(ip_mac_map)
        print()
        pause("Press Enter to open the defense console...")
        main_menu(config, session)
    except KeyboardInterrupt:
        print()
        print(color("[PANIC STOP] Keyboard interrupt received. Cleaning up...", C.RED))
    finally:
        session.stop_all()


if __name__ == "__main__":
    main()
