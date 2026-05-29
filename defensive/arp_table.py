from __future__ import annotations

import subprocess


class ARPTableError(RuntimeError):
    pass


def read_local_arp_table() -> list[dict[str, str]]:
    try:
        result = subprocess.run(
            ["ip", "neigh", "show"],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise ARPTableError("Linux 'ip' command was not found.") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or exc.stdout.strip() or "unknown error"
        raise ARPTableError(f"Could not read ARP table: {detail}") from exc

    lines = [line for line in result.stdout.splitlines() if line.strip()]
    return parse_ip_neigh(lines)


def parse_ip_neigh(lines: list[str]) -> list[dict[str, str]]:
    entries = []
    for line in lines:
        parts = line.split()
        entry = {"ip": parts[0], "iface": "Unknown", "mac": "Unknown", "state": parts[-1]}
        if "dev" in parts and parts.index("dev") + 1 < len(parts):
            entry["iface"] = parts[parts.index("dev") + 1]
        if "lladdr" in parts and parts.index("lladdr") + 1 < len(parts):
            entry["mac"] = parts[parts.index("lladdr") + 1]
        entries.append(entry)
    return entries
