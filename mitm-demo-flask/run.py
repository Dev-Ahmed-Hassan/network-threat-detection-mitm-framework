import argparse
from pathlib import Path

from app import create_app

BASE_DIR = Path(__file__).resolve().parent
CERT_FILE = BASE_DIR / "certs" / "cert.pem"
KEY_FILE = BASE_DIR / "certs" / "key.pem"


def parse_args():
    parser = argparse.ArgumentParser(description="Run MITM demo app")
    parser.add_argument(
        "--mode",
        choices=["http", "https_no_hsts", "https_hsts"],
        default="http",
        help="Transport mode",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument(
        "--downgrade-http-port",
        type=int,
        default=5000,
        help="HTTP port used by /downgrade-demo redirects in HTTPS no-HSTS mode.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    app = create_app(mode=args.mode, downgrade_http_port=args.downgrade_http_port)

    if args.mode == "http":
        app.run(host=args.host, port=args.port, debug=True)
        return

    if not CERT_FILE.exists() or not KEY_FILE.exists():
        raise FileNotFoundError(
            "HTTPS mode requires certs/cert.pem and certs/key.pem files."
        )

    app.run(
        host=args.host,
        port=args.port,
        debug=True,
        ssl_context=(str(CERT_FILE), str(KEY_FILE)),
    )


if __name__ == "__main__":
    main()
