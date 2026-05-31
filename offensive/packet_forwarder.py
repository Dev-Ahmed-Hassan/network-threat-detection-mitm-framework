import os
import sys
from pathlib import Path

IP_FORWARD_PATH = Path("/proc/sys/net/ipv4/ip_forward")


def require_root():
    if os.geteuid() != 0:
        sys.exit("Error: run with sudo. IP forwarding requires root privileges.")


def get_forwarding_value() -> str:
    return IP_FORWARD_PATH.read_text(encoding="utf-8").strip()


def set_forwarding_value(value: str) -> None:
    IP_FORWARD_PATH.write_text(value, encoding="utf-8")


def enable_forwarding() -> str:
    """
    Enables Linux IPv4 forwarding.

    Returns the original value so it can be restored later.
    """
    require_root()

    original_value = get_forwarding_value()

    if original_value != "1":
        set_forwarding_value("1")
        print("[+] IP forwarding enabled")
    else:
        print("[*] IP forwarding was already enabled")

    return original_value


def restore_forwarding(original_value: str) -> None:
    """
    Restores IPv4 forwarding to the value that existed before the demo.
    """
    require_root()

    set_forwarding_value(original_value)
    print(f"[+] IP forwarding restored to {original_value}")


def main():
    require_root()

    original = enable_forwarding()

    try:
        input("[*] Press Enter to restore forwarding and exit...")
    finally:
        restore_forwarding(original)


if __name__ == "__main__":
    main()
