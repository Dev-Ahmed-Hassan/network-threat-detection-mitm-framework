import json
from pathlib import Path

from config.constants import BASELINE_FILE


class BaselineManager:
    def __init__(self, path: Path = BASELINE_FILE):
        self.path = Path(path)
        self._table = self._load()

    def _load(self) -> dict[str, str]:
        if not self.path.exists():
            raise FileNotFoundError(
                f"Baseline file not found: {self.path}. Build a baseline from the defense app first."
            )

        with open(self.path, "r", encoding="utf-8") as file:
            data = json.load(file)

        return {ip: mac.lower() for ip, mac in data.items()}

    def get_expected_mac(self, ip: str) -> str | None:
        mac = self._table.get(ip)
        return mac.lower() if mac else None

    def all_entries(self) -> dict[str, str]:
        return dict(self._table)


def main():
    baseline = BaselineManager()
    print("[+] Loaded baseline:")
    for ip, mac in sorted(baseline.all_entries().items()):
        print(f"    {ip:<15} {mac}")


if __name__ == "__main__":
    main()
