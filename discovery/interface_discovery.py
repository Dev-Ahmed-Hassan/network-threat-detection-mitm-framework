from __future__ import annotations

import json
import subprocess
from ipaddress import IPv4Interface


class InterfaceDetectionError(RuntimeError):
    pass


def _run_ip_command(args: list[str]) -> str:
    try:
        result = subprocess.run(
            ["ip", *args],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise InterfaceDetectionError("Linux 'ip' command was not found.") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or exc.stdout.strip() or "unknown error"
        raise InterfaceDetectionError(detail) from exc

    return result.stdout


def detect_default_route() -> dict[str, str | None]:
    output = _run_ip_command(["route", "show", "default"])
    for line in output.splitlines():
        parts = line.split()
        if not parts or parts[0] != "default":
            continue
        route = {"iface": None, "gateway_ip": None}
        if "dev" in parts:
            route["iface"] = parts[parts.index("dev") + 1]
        if "via" in parts:
            route["gateway_ip"] = parts[parts.index("via") + 1]
        if route["iface"]:
            return route
    raise InterfaceDetectionError("Could not find a default network route.")


def detect_default_interface() -> str:
    route = detect_default_route()
    iface = route.get("iface")
    if not iface:
        raise InterfaceDetectionError("Default route did not include an interface.")
    return iface


def detect_default_gateway() -> str | None:
    return detect_default_route().get("gateway_ip")


def _interface_addresses(interface: str) -> list[dict]:
    output = _run_ip_command(["-j", "addr", "show", "dev", interface])
    data = json.loads(output)
    if not data:
        raise InterfaceDetectionError(f"Interface {interface!r} was not found.")
    return data[0].get("addr_info", [])


def detect_attacker_ip(interface: str) -> str:
    for address in _interface_addresses(interface):
        if address.get("family") == "inet" and address.get("local"):
            return address["local"]
    raise InterfaceDetectionError(f"No IPv4 address found on {interface!r}.")


def detect_subnet(interface: str) -> str:
    for address in _interface_addresses(interface):
        if address.get("family") != "inet":
            continue
        local = address.get("local")
        prefixlen = address.get("prefixlen")
        if local and prefixlen is not None:
            return str(IPv4Interface(f"{local}/{prefixlen}").network)
    raise InterfaceDetectionError(f"No IPv4 subnet found on {interface!r}.")


def auto_detect_network() -> dict[str, str | None]:
    route = detect_default_route()
    iface = route.get("iface")
    if not iface:
        raise InterfaceDetectionError("Could not auto-detect active interface.")
    return {
        "iface": iface,
        "attacker_ip": detect_attacker_ip(iface),
        "subnet": detect_subnet(iface),
        "gateway_ip": route.get("gateway_ip"),
    }
