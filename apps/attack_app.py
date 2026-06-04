from __future__ import annotations

import os
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config.runtime_config import (  # noqa: E402
    RuntimeConfig,
    validate_cidr,
    validate_ip,
    validate_port,
)
from discovery.interface_discovery import (  # noqa: E402
    InterfaceDetectionError,
    auto_detect_network,
)
from discovery.network_discovery import (  # noqa: E402
    NetworkScanError,
    NetworkScanPermissionError,
    scan_subnet,
)
from offensive.attack_session import AttackSession, AttackStartError, TaskStatus  # noqa: E402


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


# Debugging Logic... =============================

def debug(message: str) -> None:
    if os.environ.get("DEBUG_SCAN") == "1":
        print(color(f"[DEBUG] {message}", C.DIM))
              
def scan_and_select_targets(config: RuntimeConfig, scanner=scan_subnet) -> None:
    """
    Debug-friendly version.

    Usage:
      DEBUG_SCAN=1 python your_console_file.py

    The optional `scanner` argument lets you inject a fake scanner for testing.
    The existing menu can still call this as scan_and_select_targets(config).
    """
    clear_screen()
    print_config(config, "SUBNET SCAN")

    debug(f"config.iface={config.iface!r}")
    debug(f"config.subnet={config.subnet!r}")
    debug(f"config.attacker_ip={config.attacker_ip!r}")
    debug(f"config.gateway_ip={config.gateway_ip!r}")
    debug(f"config.victim_ip={config.victim_ip!r}")
    debug(f"config.server_ip={config.server_ip!r}")

    if not config.subnet or not validate_cidr(config.subnet):
        print(color("Subnet is missing or invalid. Edit runtime configuration first.", C.RED))
        pause()
        return

    if not config.iface:
        print(color("Interface is missing. Edit runtime configuration first.", C.RED))
        pause()
        return

    print(color(f"Scanning {config.subnet} on {config.iface}...", C.GREEN))

    try:
        devices = scanner(config.subnet, config.iface)
    except NetworkScanPermissionError as exc:
        print(color(str(exc), C.RED))
        debug("NetworkScanPermissionError was raised.")
        pause()
        return
    except NetworkScanError as exc:
        print(color(str(exc), C.RED))
        debug("NetworkScanError was raised.")
        pause()
        return
    except Exception as exc:
        print(color(f"Unexpected scan error: {exc}", C.RED))
        debug(f"Unexpected exception type={type(exc).__name__}")
        import traceback
        traceback.print_exc()
        pause()
        return

    debug(f"scanner returned type={type(devices).__name__}")
    debug(f"scanner returned value={devices!r}")

    if not devices:
        print(color("No devices found on subnet.", C.YELLOW))
        print(color("Check interface, subnet, permissions, or network connection.", C.DIM))
        pause()
        return

    valid_devices = normalize_devices(devices)
    debug(f"normalized devices={valid_devices!r}")

    if not valid_devices:
        print(color("Devices were returned, but none had usable ip/mac fields.", C.RED))
        print(color("Check what scan_subnet() returns.", C.DIM))
        pause()
        return

    clear_screen()
    show_devices(valid_devices, config)

    victim = select_device(valid_devices, "Select victim device number: ")
    debug(f"victim selected={victim!r}")

    if victim is None:
        pause()
        return

    server = select_device(valid_devices, "Select server device number: ")
    debug(f"server selected={server!r}")

    if server is None:
        pause()
        return

    victim_ip = victim["ip"]
    server_ip = server["ip"]

    if victim_ip == server_ip:
        print(color("Victim and server must be different devices.", C.RED))
    elif victim_ip == config.attacker_ip or server_ip == config.attacker_ip:
        print(color("Do not select this machine as victim or server.", C.RED))
    else:
        config.victim_ip = victim_ip
        config.server_ip = server_ip

        print()
        print(color(f"Victim selected: {config.victim_ip}", C.GREEN))
        print(color(f"Server selected: {config.server_ip}", C.GREEN))

        debug(f"final config.victim_ip={config.victim_ip!r}")
        debug(f"final config.server_ip={config.server_ip!r}")

    pause()


def normalize_devices(devices: list[dict[str, str]]) -> list[dict[str, str]]:
    normalized = []

    for index, device in enumerate(devices, start=1):
        if not isinstance(device, dict):
            debug(f"Skipping device #{index}: not a dict: {device!r}")
            continue

        ip = device.get("ip") or device.get("IP") or device.get("addr")
        mac = device.get("mac") or device.get("MAC") or device.get("hwsrc")
        hostname = (
            device.get("hostname")
            or device.get("host")
            or device.get("name")
            or "Unknown"
        )

        if not ip:
            debug(f"Skipping device #{index}: missing IP field: {device!r}")
            continue

        if not mac:
            debug(f"Device #{index} missing MAC field, using Unknown: {device!r}")
            mac = "Unknown"

        normalized.append({
            "ip": str(ip),
            "mac": str(mac),
            "hostname": str(hostname),
        })

    return normalized



def device_label(ip: str, config: RuntimeConfig) -> str:
    labels = []

    if ip == config.gateway_ip:
        labels.append("Gateway")

    if ip == config.attacker_ip:
        labels.append("This Machine")

    if ip == config.victim_ip:
        labels.append("Selected Victim")

    if ip == config.server_ip:
        labels.append("Selected Server")

    return ", ".join(labels) if labels else "Unknown Host"


def label_color(label: str) -> str:
    if "This Machine" in label:
        return C.CYAN

    if "Gateway" in label:
        return C.MAGENTA

    if "Selected" in label:
        return C.GREEN

    return C.DIM


def select_device(devices: list[dict[str, str]], prompt: str) -> dict[str, str] | None:
    value = input(color(prompt, C.CYAN)).strip()
    debug(f"raw user selection input={value!r}")

    try:
        index = int(value)
    except ValueError:
        print(color("Enter a device number from the list.", C.RED))
        return None

    if not 1 <= index <= len(devices):
        print(color("Device number is out of range.", C.RED))
        debug(f"selection index={index}, valid range=1..{len(devices)}")
        return None

    selected = devices[index - 1]
    debug(f"selected device={selected!r}")

    return selected

##################################################################################  



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
    print(color("     __  __ ___ _____ __  __      _   _   _             _   ", C.CYAN))
    print(color("    |  \\/  |_ _|_   _|  \\/  |    / \\ | |_| |_ __ _  ___| | __", C.CYAN))
    print(color("    | |\\/| || |  | | | |\\/| |   / _ \\| __| __/ _` |/ __| |/ /", C.CYAN))
    print(color("    | |  | || |  | | | |  | |  / ___ \\ |_| || (_| | (__|   < ", C.CYAN))
    print(color("    |_|  |_|___| |_| |_|  |_| /_/   \\_\\__|\\__\\__,_|\\___|_|\\_\\", C.CYAN))
    print()
    print(color("                  MITM ATTACK SIMULATION", C.BOLD + C.WHITE))
    print(color("              Offensive Lab Console / Phase 1", C.GREEN))
    print(color("============================================================", C.GREEN))
    print()
    press_any_key()


def print_banner(title: str) -> None:
    print(color("=" * 60, C.GREEN))
    print(color(title.center(60), C.BOLD + C.WHITE))
    print(color("=" * 60, C.GREEN))


def print_config(config: RuntimeConfig, title: str = "CURRENT RUNTIME CONFIGURATION") -> None:
    print_banner(title)
    print()
    for label, value in config.as_rows():
        rendered = value if not value.startswith("Not ") else color(value, C.YELLOW)
        print(f"{color(label + ':', C.CYAN):<26} {rendered}")
    print()


def option_prompt(max_choice: int) -> str:
    choice = input(color("Select option > ", C.GREEN)).strip()
    if choice not in {str(number) for number in range(1, max_choice + 1)}:
        print(color("Invalid option.", C.RED))
        pause()
        return ""
    return choice


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
    print(f"  Interface:   {detected.get('iface') or 'Unknown'}")
    print(f"  Attacker IP: {detected.get('attacker_ip') or 'Unknown'}")
    print(f"  Subnet:      {detected.get('subnet') or 'Unknown'}")
    print(f"  Gateway:     {detected.get('gateway_ip') or 'Unknown'}")
    if interactive:
        pause()
    return True


def edit_config_menu(config: RuntimeConfig) -> None:
    while True:
        clear_screen()
        print_config(config, "EDIT RUNTIME CONFIGURATION")
        print(color("1.", C.GREEN), "Change interface")
        print(color("2.", C.GREEN), "Change attacker IP")
        print(color("3.", C.GREEN), "Change subnet")
        print(color("4.", C.GREEN), "Change victim IP")
        print(color("5.", C.GREEN), "Change server IP")
        print(color("6.", C.GREEN), "Change backend port")
        print(color("7.", C.GREEN), "Change transport mode")
        print(color("8.", C.GREEN), "Back")
        print()

        choice = option_prompt(8)
        if not choice:
            continue
        if choice == "8":
            return

        handlers = {
            "1": edit_interface,
            "2": edit_attacker_ip,
            "3": edit_subnet,
            "4": edit_victim_ip,
            "5": edit_server_ip,
            "6": edit_backend_port,
            "7": edit_transport_mode,
        }
        handlers[choice](config)


def read_value(prompt: str) -> str:
    return input(color(prompt, C.CYAN)).strip()


def edit_interface(config: RuntimeConfig) -> None:
    value = read_value("Interface: ")
    if not value:
        print(color("Interface should not be empty.", C.RED))
    else:
        config.iface = value
        print(color("[OK] Interface updated.", C.GREEN))
    pause()


def edit_attacker_ip(config: RuntimeConfig) -> None:
    value = read_value("Attacker IP: ")
    if validate_ip(value):
        config.attacker_ip = value
        print(color("[OK] Attacker IP updated.", C.GREEN))
    else:
        print(color("Enter a valid IPv4 address.", C.RED))
    pause()


def edit_subnet(config: RuntimeConfig) -> None:
    value = read_value("Subnet CIDR: ")
    if validate_cidr(value):
        config.subnet = value
        print(color("[OK] Subnet updated.", C.GREEN))
    else:
        print(color("Enter a valid CIDR subnet, for example 192.168.1.0/24.", C.RED))
    pause()


def edit_victim_ip(config: RuntimeConfig) -> None:
    value = read_value("Victim IP: ")
    if not validate_ip(value):
        print(color("Enter a valid IPv4 address.", C.RED))
    elif value == config.attacker_ip:
        print(color("Victim IP should not be the attacker IP.", C.RED))
    elif value == config.server_ip:
        print(color("Victim IP and Server IP should not be the same.", C.RED))
    else:
        config.victim_ip = value
        print(color("[OK] Victim IP updated.", C.GREEN))
    pause()


def edit_server_ip(config: RuntimeConfig) -> None:
    value = read_value("Server IP: ")
    if not validate_ip(value):
        print(color("Enter a valid IPv4 address.", C.RED))
    elif value == config.attacker_ip:
        print(color("Server IP should not be the attacker IP.", C.RED))
    elif value == config.victim_ip:
        print(color("Server IP and Victim IP should not be the same.", C.RED))
    else:
        config.server_ip = value
        print(color("[OK] Server IP updated.", C.GREEN))
    pause()


def edit_backend_port(config: RuntimeConfig) -> None:
    value = read_value("Backend port: ")
    if validate_port(value):
        config.backend_port = int(value)
        print(color("[OK] Backend port updated.", C.GREEN))
    else:
        print(color("Backend port must be an integer from 1 to 65535.", C.RED))
    pause()


def edit_transport_mode(config: RuntimeConfig) -> None:
    value = read_value("Transport mode [http/https]: ").lower()
    if value in {"http", "https"}:
        config.transport_mode = value
        print(color("[OK] Transport mode updated.", C.GREEN))
    else:
        print(color("Transport mode should be either http or https.", C.RED))
    pause()

# # DEBUG101
# def scan_and_select_targets(config: RuntimeConfig) -> None:
#     clear_screen()
#     print_config(config, "SUBNET SCAN")

#     if not config.subnet or not validate_cidr(config.subnet):
#         print(color("Subnet is missing or invalid. Edit runtime configuration first.", C.RED))
#         pause()
#         return
#     if not config.iface:
#         print(color("Interface is missing. Edit runtime configuration first.", C.RED))
#         pause()
#         return

#     print(color(f"Scanning {config.subnet} on {config.iface}...", C.GREEN))
#     try:
#         devices = scan_subnet(config.subnet, config.iface)
#     except NetworkScanPermissionError as exc:
#         print(color(str(exc), C.RED))
#         pause()
#         return
#     except NetworkScanError as exc:
#         print(color(str(exc), C.RED))
#         pause()
#         return

#     if not devices:
#         print(color("No devices found on subnet.", C.YELLOW))
#         print(color("Check interface, subnet, permissions, or network connection.", C.DIM))
#         pause()
#         return

#     clear_screen()
#     show_devices(devices, config)
#     victim = select_device(devices, "Select victim device number: ")
#     if victim is None:
#         pause()
#         return

#     server = select_device(devices, "Select server device number: ")
#     if server is None:
#         pause()
#         return

#     if victim["ip"] == server["ip"]:
#         print(color("Victim and server must be different devices.", C.RED))
#     elif victim["ip"] == config.attacker_ip or server["ip"] == config.attacker_ip:
#         print(color("Do not select this machine as victim or server.", C.RED))
#     else:
#         config.victim_ip = victim["ip"]
#         config.server_ip = server["ip"]
#         print()
#         print(color(f"Victim selected: {config.victim_ip}", C.GREEN))
#         print(color(f"Server selected: {config.server_ip}", C.GREEN))

#     pause()


def show_devices(devices: list[dict[str, str]], config: RuntimeConfig) -> None:
    print_banner("DEVICES FOUND")
    print()
    print(color("No.        IP Address        MAC Address            Hostname                    Label", C.BOLD + C.WHITE))
    print(color("-" * 86, C.DIM))

    for index, device in enumerate(devices, start=1):
        ip = device.get("ip", "Missing IP")
        mac = device.get("mac", "Missing MAC")
        hostname = fit_cell(device.get("hostname", "Unknown"), 26)

        label = device_label(ip, config)

        print(
            f"{color(f'[{index}]', C.GREEN):<12}"
            f"{ip:<18}"
            f"{mac:<22}"
            f"{hostname:<28}"
            f"{color(label, label_color(label))}"
        )

    print()


def fit_cell(value: str, width: int) -> str:
    text = str(value)
    if len(text) <= width:
        return text
    return text[: max(0, width - 1)] + "~"

#DEBUG101
# def device_label(ip: str, config: RuntimeConfig) -> str:
#     labels = []
#     if ip == config.gateway_ip:
#         labels.append("Gateway")
#     if ip == config.attacker_ip:
#         labels.append("This Machine")
#     if ip == config.victim_ip:
#         labels.append("Selected Victim")
#     if ip == config.server_ip:
#         labels.append("Selected Server")
#     return ", ".join(labels) if labels else "Unknown Host"


# def label_color(label: str) -> str:
#     if "This Machine" in label:
#         return C.CYAN
#     if "Gateway" in label:
#         return C.MAGENTA
#     if "Selected" in label:
#         return C.GREEN
#     return C.DIM


# def select_device(devices: list[dict[str, str]], prompt: str) -> dict[str, str] | None:
#     value = input(color(prompt, C.CYAN)).strip()
#     try:
#         index = int(value)
#     except ValueError:
#         print(color("Enter a device number from the list.", C.RED))
#         return None
#     if not 1 <= index <= len(devices):
#         print(color("Device number is out of range.", C.RED))
#         return None
#     return devices[index - 1]


def show_validation(config: RuntimeConfig, final: bool = True) -> None:
    checks = config.validate(final=final)
    print(color("Status:", C.BOLD + C.WHITE))
    for status, message in checks:
        style = C.GREEN if status == "OK" else C.RED
        print(f"{color(f'[{status}]', style):<18} {message}")
    if final and config.is_ready():
        print(f"{color('[OK]', C.GREEN):<18} Ready for attack options")


def final_summary(config: RuntimeConfig) -> bool:
    clear_screen()
    print_config(config, "FINAL ATTACK CONFIGURATION")
    show_validation(config, final=True)
    print()
    return config.is_ready()


def continue_to_attack_options(config: RuntimeConfig, session: AttackSession) -> None:
    ready = final_summary(config)
    if ready:
        pause("Press Enter to open attack options...")
        attack_options_menu(config, session)
    else:
        print(color("Resolve the errors above before continuing to attack options.", C.RED))
        pause()

def select_interceptor_output_mode() -> str | None:
        print()
        print(color("Interceptor output mode:", C.BOLD + C.WHITE))
        print(color("1.", C.GREEN), "Demo mode - cautious, security findings only")
        print(color("2.", C.GREEN), "Debug mode - verbose packet details")
        print()

        choice = input(color("Select mode > ", C.GREEN)).strip()

        if choice == "1":
            return "demo"

        if choice == "2":
            return "debug"

        print(color("Invalid interceptor mode.", C.RED))
        pause()
        return None

def attack_options_menu(config: RuntimeConfig, session: AttackSession) -> None:
    notice: tuple[str, str] | None = None

    while True:
        clear_screen()
        print_config(config, "ATTACK OPTIONS")
        show_attack_status(session)
        if notice:
            style = C.GREEN if notice[0] == "OK" else C.RED
            print(color(f"[{notice[0]}] {notice[1]}", style))
            print()
            notice = None
        print(color("Options:", C.BOLD + C.WHITE))
        print(color("1.", C.GREEN), "Start ARP spoofer only (new console window)")
        print(color("2.", C.GREEN), "Start interceptor only (new console window)")
        print(color("3.", C.GREEN), "Start full MITM demo (spoofer + interceptor windows)")
        print(color("4.", C.GREEN), "Stop ARP spoof")
        print(color("5.", C.GREEN), "Stop interceptor")
        print(color("6.", C.GREEN), "Stop all and restore")
        print(color("7.", C.GREEN), "Back to main menu")
        print(color("x.", C.RED), "PANIC STOP")
        print()

        choice = input(color("Select option > ", C.GREEN)).strip().lower()

        if choice == "1":
            notice = start_attack_action(session.start_spoofer, config, "ARP spoofer started.")
        elif choice == "2":
            output_mode = select_interceptor_output_mode()
            if output_mode:
                notice = start_attack_action(
                    lambda cfg: session.start_interceptor(cfg, output_mode=output_mode),
                    config,
                    f"Interceptor window launched in {output_mode} mode.",
                )
        elif choice == "3":
            output_mode = select_interceptor_output_mode()
            if output_mode:
                notice = start_attack_action(
                    lambda cfg: session.start_full_mitm(cfg, output_mode=output_mode),
                    config,
                    f"Full MITM started with interceptor in {output_mode} mode.",
                )
        elif choice == "4":
            session.stop_spoofer()
            notice = ("OK", "Spoofer stop requested.")
        elif choice == "5":
            session.stop_interceptor()
            notice = ("OK", "Interceptor stop requested.")
        elif choice == "6":
            session.stop_all()
            notice = ("OK", "All attack modules stopped.")
        elif choice == "7":
            return
        elif choice == "x":
            session.stop_all()
            notice = ("PANIC STOP", "All attack modules stopped and cleanup requested.")
        else:
            notice = ("ERROR", "Invalid option.")

def start_attack_action(action, config: RuntimeConfig, success_message: str) -> tuple[str, str]:
    try:
        action(config)
    except AttackStartError as exc:
        return ("ERROR", str(exc))
    return ("OK", success_message)


def show_attack_status(session: AttackSession) -> None:
    print(color("Module Status:", C.BOLD + C.WHITE))
    for status in session.statuses():
        print(render_task_status(status))
    print()


def render_task_status(status: TaskStatus) -> str:
    state = color("RUNNING", C.GREEN) if status.running else color("STOPPED", C.DIM)
    uptime = ""
    if status.running and status.started_at:
        uptime = f" uptime={format_duration(status.started_at)}"
    error = f" last_error={status.last_error}" if status.last_error else ""
    return f"{color(status.name + ':', C.CYAN):<24} {state}{uptime}{error}"


def format_duration(started_at: float) -> str:
    import time

    elapsed = max(0, int(time.time() - started_at))
    minutes, seconds = divmod(elapsed, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h{minutes:02d}m{seconds:02d}s"
    if minutes:
        return f"{minutes}m{seconds:02d}s"
    return f"{seconds}s"


def main_menu(config: RuntimeConfig, session: AttackSession) -> None:
    while True:
        clear_screen()
        print_config(config)
        print(color("Options:", C.BOLD + C.WHITE))
        print(color("1.", C.GREEN), "Auto-detect network info")
        print(color("2.", C.GREEN), "Edit runtime configuration manually")
        print(color("3.", C.GREEN), "Scan subnet and select targets")
        print(color("4.", C.GREEN), "Show current configuration")
        print(color("5.", C.GREEN), "Continue to attack options")
        print(color("6.", C.GREEN), "Exit")
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
            #DEBUG101
            #scan_and_select_targets(config)
            scan_and_select_targets(config)
        elif choice == "4":
            clear_screen()
            print_config(config)
            show_validation(config, final=False)
            pause()
        elif choice == "5":
            continue_to_attack_options(config, session)
        elif choice == "6":
            if session.any_running():
                session.stop_all()
            print(color("Exiting attacker console.", C.DIM))
            return


def main() -> None:
    os.environ.setdefault("SCAPY_SUPPRESS_NO_DEFAULT_ROUTE_WARNING", "1")
    config = RuntimeConfig.from_defaults()
    session = AttackSession()
    try:
        splash()
        clear_screen()
        auto_detect(config, interactive=False)
        pause()
        main_menu(config, session)
    except KeyboardInterrupt:
        print()
        print(color("[PANIC STOP] Keyboard interrupt received. Cleaning up...", C.RED))
    finally:
        session.stop_all()


if __name__ == "__main__":
    main()
